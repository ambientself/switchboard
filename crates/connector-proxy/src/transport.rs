//! The HTTP client every request to one proxied server goes out on: calls, tool lists and
//! probes alike.
//!
//! It is plain HTTP for an `http` URL, which only a server whose destination is `in_cluster`
//! may have, and TLS for an `https` one, trusting only the CA file the deployment names for the
//! server: nothing is compiled in and nothing is read from the operating system. The
//! certificate is verified against the server's identity, the host in its URL. Only HTTP/1.1 is
//! offered.
//!
//! Each address is checked as [`destination`](crate::destination) says: an IP literal when the
//! client is built, and a DNS name each time it is resolved. The legacy client follows no
//! redirect, reads no proxy setting from the environment, and here never retries a request:
//! a call is sent once or not at all. Each connector has a client, and so a pool, of its own.

use std::path::Path;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Uri};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::connector::{Upstream, UpstreamError};
use crate::destination::{CheckedResolver, Destination, Policy};

type Tcp = HttpConnector<CheckedResolver>;

/// The client for one server, with the address it is sent to.
pub(crate) struct Transport {
    pub(crate) endpoint: Uri,
    sender: Sender,
}

enum Sender {
    Plain(Client<Tcp, Full<Bytes>>),
    Tls(Client<HttpsConnector<Tcp>, Full<Bytes>>),
}

impl Transport {
    /// The client for `upstream`'s server. Refuses a URL that is not `http` or `https` with a
    /// host and no user information, plain `http` for a server whose destination is not
    /// `in_cluster`, an IP literal that is refused, an `https` URL with no CA file or one whose
    /// file cannot be used, and a CA file beside an `http` URL.
    pub(crate) fn new(upstream: &Upstream) -> Result<Self, UpstreamError> {
        let connector = &upstream.connector;
        let endpoint = parse_endpoint(&upstream.url).ok_or_else(|| UpstreamError::BadUrl {
            connector: connector.clone(),
            url: upstream.url.clone(),
        })?;
        let host = endpoint.host().unwrap_or_default();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let policy = Policy {
            server: connector.clone(),
            destination: upstream.destination,
            loopback: upstream.loopback,
        };
        // An IP literal is never resolved, so it is checked here, once: it cannot change.
        if let Ok(address) = host.parse()
            && let Some(refusal) = policy.refusal(address)
        {
            return Err(UpstreamError::DestinationRefused {
                connector: connector.clone(),
                address,
                refusal,
            });
        }
        let https = endpoint.scheme_str() == Some("https");
        let sender = match (&upstream.ca_file, https) {
            (Some(_), false) => return Err(UpstreamError::CaFileForHttp(connector.clone())),
            (None, true) => return Err(UpstreamError::NoCaFile(connector.clone())),
            (None, false) => {
                if upstream.destination != Destination::InCluster {
                    return Err(UpstreamError::HttpNotInCluster(connector.clone()));
                }
                // This connector refuses any scheme but `http`.
                Sender::Plain(client(HttpConnector::new_with_resolver(
                    CheckedResolver::new(policy),
                )))
            }
            (Some(ca_file), true) => {
                let identity = ServerName::try_from(host.to_owned())
                    .map_err(|_| UpstreamError::Tls(connector.clone()))?;
                Sender::Tls(tls_client(upstream, ca_file, identity, policy)?)
            }
        };
        Ok(Self { endpoint, sender })
    }

    /// Sends `request`, once.
    pub(crate) fn request(&self, request: Request<Full<Bytes>>) -> ResponseFuture {
        match &self.sender {
            Sender::Plain(client) => client.request(request),
            Sender::Tls(client) => client.request(request),
        }
    }
}

/// The legacy client: it follows no redirect and reads no proxy setting from the environment,
/// and is told never to retry a request, even one it believes the server never saw.
fn client<C>(connector: C) -> Client<C, Full<Bytes>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone,
{
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .retry_canceled_requests(false)
        .build(connector)
}

/// A client that speaks only TLS, offering only HTTP/1.1, trusts only the CAs in `ca_file`,
/// and verifies the certificate against `identity`. Its crypto provider is ring, passed here;
/// the process-wide default provider is neither read nor set.
fn tls_client(
    upstream: &Upstream,
    ca_file: &Path,
    identity: ServerName<'static>,
    policy: Policy,
) -> Result<Client<HttpsConnector<Tcp>, Full<Bytes>>, UpstreamError> {
    let connector = &upstream.connector;
    let roots = trusted(upstream, ca_file)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| UpstreamError::Tls(connector.clone()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // The TCP connector under TLS sees the `https` URL, so it is told not to refuse it; the
    // TLS connector around it refuses every scheme but `https`.
    let mut tcp = HttpConnector::new_with_resolver(CheckedResolver::new(policy));
    tcp.enforce_http(false);
    let tls = HttpsConnector::new(
        tcp,
        config,
        true,
        Arc::new(FixedServerNameResolver::new(identity)),
    );
    Ok(client(tls))
}

/// The certificates in the PEM bundle at `path`, as the only trust anchors.
fn trusted(upstream: &Upstream, path: &Path) -> Result<RootCertStore, UpstreamError> {
    let fault = |fault| UpstreamError::CaFile {
        connector: upstream.connector.clone(),
        path: path.to_owned(),
        fault,
    };
    let bytes = std::fs::read(path).map_err(|_| fault(CaFault::Unreadable))?;
    let mut roots = RootCertStore::empty();
    let mut sections = 0;
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(&bytes) {
        let (kind, der) = section.map_err(|_| fault(CaFault::NotPem))?;
        sections += 1;
        if kind == SectionKind::Certificate {
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| fault(CaFault::BadCertificate))?;
        }
    }
    if sections == 0 {
        return Err(fault(CaFault::NotPem));
    }
    if roots.is_empty() {
        return Err(fault(CaFault::NoCertificate));
    }
    Ok(roots)
}

/// What is wrong with a server's CA file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaFault {
    /// It cannot be read.
    Unreadable,
    /// It is not PEM.
    NotPem,
    /// It holds no certificate.
    NoCertificate,
    /// A certificate in it cannot be used as a trust anchor.
    BadCertificate,
}

impl std::fmt::Display for CaFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CaFault::Unreadable => "cannot be read",
            CaFault::NotPem => "is not PEM",
            CaFault::NoCertificate => "holds no certificate",
            CaFault::BadCertificate => "holds a certificate that cannot be used as a trust anchor",
        })
    }
}

/// `url` as an endpoint, if it is an `http` or `https` URL with a host and no user
/// information.
pub(crate) fn parse_endpoint(url: &str) -> Option<Uri> {
    let endpoint: Uri = url.parse().ok()?;
    let authority = endpoint.authority()?;
    let acceptable = matches!(endpoint.scheme_str(), Some("http" | "https"))
        && !authority.host().is_empty()
        && !authority.as_str().contains('@');
    acceptable.then_some(endpoint)
}
