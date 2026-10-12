//! Where the connector may connect (decision 0013, section 3).
//!
//! Every address is checked when the connector connects, and the checked address is the one
//! connected to:
//!
//! - **An IP literal** in the server's URL is checked when the connector is built, since it
//!   never changes ([`UpstreamError::DestinationRefused`](crate::UpstreamError)).
//! - **A DNS name** is resolved once for each connection, by a [`CheckedResolver`]. It drops
//!   every refused address from the answer and hands the rest to the TCP connector, which
//!   connects only to those: nothing resolves the name again between the check and the
//!   connection, so a second DNS answer cannot replace the one checked. An answer with no
//!   address left is a refusal: nothing is connected to, a warning names the server, and the
//!   call is an error with the [`DESTINATION_REFUSED`](crate::outcome::DESTINATION_REFUSED)
//!   sentence.
//!
//! [`refusal`] says which addresses are refused:
//!
//! - **Always:** loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), link-local
//!   (`169.254.0.0/16`, which holds the cloud metadata address `169.254.169.254`, and
//!   `fe80::/10`), multicast (`224.0.0.0/4`, `ff00::/8`) and the broadcast address. An IPv6
//!   address that carries an IPv4 one, in the IPv4-mapped (`::ffff:a.b.c.d`) or
//!   IPv4-compatible (`::a.b.c.d`) form, is judged as that IPv4 address.
//! - **Unless the server's destination is [`Destination::InCluster`]:** the private ranges
//!   (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) and carrier-grade NAT
//!   (`100.64.0.0/10`). A Service in the cluster has such an address, so the demos rely on it.
//!
//! Loopback is allowed only when the connector is told [`Loopback::Allowed`], which exists only
//! in a development build, one with this crate's `test-support` feature, for the tests' local
//! servers. The release build cannot name it.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use gateway_core::ConnectorName;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use thiserror::Error;
use tower_service::Service;

/// The class of a server's destination, as its registry entry names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// A Service inside the cluster. It may be reached over plain `http`, and at a private or
    /// carrier-grade NAT address.
    InCluster,
    /// Anywhere else: over `https` only, and never at a private address.
    Public,
}

/// Whether a connector may reach a loopback address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loopback {
    /// Loopback is refused like every other address that is always refused. The only choice
    /// in a release build.
    Refused,
    /// Loopback is allowed, for the tests' local servers. Only a development build, one with
    /// the `test-support` feature, has this variant.
    #[cfg(feature = "test-support")]
    Allowed,
}

impl Loopback {
    /// What a connector is built with unless told otherwise: [`Loopback::Allowed`] in a
    /// development build and [`Loopback::Refused`] in a release build.
    pub const fn of_this_build() -> Self {
        #[cfg(feature = "test-support")]
        {
            Loopback::Allowed
        }
        #[cfg(not(feature = "test-support"))]
        {
            Loopback::Refused
        }
    }
}

/// Why an address is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A loopback address.
    Loopback,
    /// An unspecified address, or one in `0.0.0.0/8`.
    Unspecified,
    /// A link-local address, such as the cloud metadata address `169.254.169.254`.
    LinkLocal,
    /// A multicast address.
    Multicast,
    /// The IPv4 broadcast address.
    Broadcast,
    /// A private or carrier-grade NAT address, for a server whose destination is not
    /// `in_cluster`.
    Private,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::Loopback => "a loopback address",
            Refusal::Unspecified => "an unspecified address",
            Refusal::LinkLocal => "a link-local address",
            Refusal::Multicast => "a multicast address",
            Refusal::Broadcast => "the broadcast address",
            Refusal::Private => {
                "a private address, which only a server whose destination is in_cluster may use"
            }
        })
    }
}

/// Why the connector would not connect to `address`, for a server whose destination is
/// `destination`, or `None` if it may. See the [module documentation](self).
pub fn refusal(address: IpAddr, destination: Destination, loopback: Loopback) -> Option<Refusal> {
    let refused = match address {
        IpAddr::V4(v4) => class_v4(v4),
        IpAddr::V6(v6) => class_v6(v6),
    }?;
    match refused {
        Refusal::Loopback if loopback != Loopback::Refused => None,
        Refusal::Private if destination == Destination::InCluster => None,
        refused => Some(refused),
    }
}

fn class_v4(address: Ipv4Addr) -> Option<Refusal> {
    let [first, second, ..] = address.octets();
    if address.is_loopback() {
        Some(Refusal::Loopback)
    } else if first == 0 {
        Some(Refusal::Unspecified)
    } else if address.is_link_local() {
        Some(Refusal::LinkLocal)
    } else if address.is_multicast() {
        Some(Refusal::Multicast)
    } else if address.is_broadcast() {
        Some(Refusal::Broadcast)
    } else if address.is_private() || (first == 100 && second & 0xc0 == 64) {
        Some(Refusal::Private)
    } else {
        None
    }
}

fn class_v6(address: Ipv6Addr) -> Option<Refusal> {
    if address.is_loopback() {
        Some(Refusal::Loopback)
    } else if address.is_unspecified() {
        Some(Refusal::Unspecified)
    } else if let Some(carried) = address.to_ipv4() {
        // The IPv4-mapped and IPv4-compatible forms reach the IPv4 address they carry.
        class_v4(carried)
    } else if address.is_unicast_link_local() {
        Some(Refusal::LinkLocal)
    } else if address.is_multicast() {
        Some(Refusal::Multicast)
    } else if address.is_unique_local() {
        Some(Refusal::Private)
    } else {
        None
    }
}

/// What a server's addresses are checked against.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    /// The server, named in the warning a refusal logs.
    pub(crate) server: ConnectorName,
    pub(crate) destination: Destination,
    pub(crate) loopback: Loopback,
}

impl Policy {
    /// Why `address` is refused, if it is.
    pub(crate) fn refusal(&self, address: IpAddr) -> Option<Refusal> {
        refusal(address, self.destination, self.loopback)
    }

    /// The addresses in `answer`, the resolution of `host`, that may be connected to, in their
    /// order. Each refused address is logged; if none is left, the answer is refused.
    fn admit(
        &self,
        host: &str,
        answer: Vec<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, DestinationRefused> {
        let mut admitted = Vec::with_capacity(answer.len());
        let mut first_refused = None;
        for address in answer {
            match self.refusal(address.ip()) {
                None => admitted.push(address),
                Some(refusal) => {
                    tracing::warn!(
                        event = "destination_refused",
                        connector = %self.server,
                        host,
                        address = %address.ip(),
                        reason = %refusal,
                        "the gateway does not connect to this address of the server's; it was dropped from the server's DNS answer"
                    );
                    first_refused.get_or_insert((address.ip(), refusal));
                }
            }
        }
        match first_refused {
            Some((address, refusal)) if admitted.is_empty() => {
                Err(DestinationRefused { address, refusal })
            }
            _ => Ok(admitted),
        }
    }
}

/// A connection refused for its address. It travels inside the HTTP client's error, where
/// [`refused`] finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("the gateway does not connect to {address}, {refusal}")]
pub(crate) struct DestinationRefused {
    address: IpAddr,
    refusal: Refusal,
}

/// Whether `error`, or anything that caused it, is a [`DestinationRefused`].
pub(crate) fn refused(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error.is::<DestinationRefused>() {
            return true;
        }
        cause = error.source();
    }
    false
}

/// The resolver the TCP connector uses for a server named by DNS: it asks `inner` once, and
/// returns only the addresses [`Policy`] admits. The TCP connector connects to exactly those.
#[derive(Clone)]
pub(crate) struct CheckedResolver<R = GaiResolver> {
    policy: Arc<Policy>,
    inner: R,
}

impl CheckedResolver {
    /// The system resolver, checked against `policy`.
    pub(crate) fn new(policy: Policy) -> Self {
        Self::with(policy, GaiResolver::new())
    }
}

impl<R> CheckedResolver<R> {
    pub(crate) fn with(policy: Policy, inner: R) -> Self {
        Self {
            policy: Arc::new(policy),
            inner,
        }
    }
}

type Resolving =
    Pin<Box<dyn Future<Output = Result<std::vec::IntoIter<SocketAddr>, BoxError>> + Send>>;
type BoxError = Box<dyn Error + Send + Sync>;

impl<R> Service<Name> for CheckedResolver<R>
where
    R: Service<Name> + Clone + Send + 'static,
    R::Response: Iterator<Item = SocketAddr>,
    R::Error: Into<BoxError>,
    R::Future: Send,
{
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = BoxError;
    type Future = Resolving;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let policy = Arc::clone(&self.policy);
        let mut inner = self.inner.clone();
        // `poll_ready` was called on `self.inner`; swap so the ready one is used.
        std::mem::swap(&mut inner, &mut self.inner);
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let answer: Vec<SocketAddr> = inner
                .call(name.clone())
                .await
                .map_err(Into::into)?
                .collect();
            let checked = policy.admit(&host, answer)?;
            Ok(checked.into_iter())
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex;

    use super::*;

    /// A resolver that answers each lookup with the next of its answers, and counts them.
    #[derive(Clone)]
    struct Scripted {
        answers: Arc<Mutex<Vec<Vec<SocketAddr>>>>,
        asked: Arc<Mutex<usize>>,
    }

    impl Service<Name> for Scripted {
        type Response = std::vec::IntoIter<SocketAddr>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _name: Name) -> Self::Future {
            *self.asked.lock().unwrap() += 1;
            let next = self.answers.lock().unwrap().remove(0);
            std::future::ready(Ok(next.into_iter()))
        }
    }

    fn address(text: &str) -> SocketAddr {
        SocketAddr::new(text.parse().unwrap(), 0)
    }

    fn policy() -> Policy {
        Policy {
            server: ConnectorName::new("docs"),
            destination: Destination::Public,
            loopback: Loopback::Refused,
        }
    }

    /// The name is resolved once, and the addresses returned are the checked ones: a second
    /// answer, here the metadata address, is never asked for or used.
    #[tokio::test]
    async fn a_name_is_resolved_once_and_the_checked_answer_is_the_one_returned() {
        let scripted = Scripted {
            answers: Arc::new(Mutex::new(vec![
                vec![address("203.0.113.7")],
                vec![address("169.254.169.254")],
            ])),
            asked: Arc::new(Mutex::new(0)),
        };
        let mut resolver = CheckedResolver::with(policy(), scripted.clone());

        let answer: Vec<SocketAddr> = resolver
            .call("docs.example".parse().unwrap())
            .await
            .unwrap()
            .collect();

        assert_eq!(answer, [address("203.0.113.7")]);
        assert_eq!(*scripted.asked.lock().unwrap(), 1);
    }

    /// Refused addresses are dropped from an answer; an answer with none left is refused.
    #[tokio::test]
    async fn refused_addresses_are_dropped_and_an_answer_of_only_those_is_refused() {
        let scripted = Scripted {
            answers: Arc::new(Mutex::new(vec![
                vec![address("127.0.0.1"), address("203.0.113.7")],
                vec![address("127.0.0.1"), address("::1")],
            ])),
            asked: Arc::new(Mutex::new(0)),
        };
        let mut resolver = CheckedResolver::with(policy(), scripted);
        let name = || "docs.example".parse::<Name>().unwrap();

        let answer: Vec<SocketAddr> = resolver.call(name()).await.unwrap().collect();
        assert_eq!(answer, [address("203.0.113.7")]);

        let error = resolver.call(name()).await.unwrap_err();
        assert!(refused(error.as_ref()), "{error}");
        assert_eq!(
            error.to_string(),
            "the gateway does not connect to 127.0.0.1, a loopback address"
        );
    }
}
