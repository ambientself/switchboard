//! The key source: its rules, checked once, and the bounded fetch.

use std::fmt;
use std::time::Duration;

use gateway_core::Issuer;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, CONTENT_LENGTH, HeaderMap};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use jsonwebtoken::jwk::JwkSet;
use serde_json::error::Category;
use thiserror::Error;
use url::Url;

/// How long a fetch may take, from connecting to the last byte of the body, unless configured
/// otherwise.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// The largest body accepted, in bytes, unless configured otherwise.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

/// The bounds on each fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchOptions {
    /// How long a fetch may take in all: connecting, the response head and the whole body.
    pub deadline: Duration,
    /// The largest body accepted, in bytes.
    pub max_body_bytes: usize,
}

impl Default for FetchOptions {
    /// [`DEFAULT_DEADLINE`] and [`DEFAULT_MAX_BODY_BYTES`].
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

/// Why a key source was refused. Raised when it is built, so a deployment with a bad keys URL
/// does not start.
///
/// The keys URL itself is never repeated, since one that was refused for carrying a user name
/// or password would repeat the password. Only the part that broke a rule is named.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SourceError {
    /// The issuer is not an `http` or `https` URL with a host and no user name or password, so
    /// it has no origin keys could be fetched from.
    #[error(
        "issuer `{0}` is not an http or https URL with a host, so no keys can be fetched for it"
    )]
    IssuerNotAnOrigin(Issuer),
    /// The keys URL does not parse as a URL.
    #[error("the keys URL for issuer `{0}` is not a URL")]
    NotAUrl(Issuer),
    /// The keys URL carries a user name or password.
    #[error("the keys URL for issuer `{0}` carries a user name or password")]
    UserInfo(Issuer),
    /// The keys URL carries a fragment.
    #[error("the keys URL for issuer `{0}` carries a fragment")]
    Fragment(Issuer),
    /// The keys URL's scheme is not the issuer's.
    #[error("the keys URL for issuer `{issuer}` uses {found}, not the issuer's scheme {expected}")]
    OtherScheme {
        /// The issuer.
        issuer: Issuer,
        /// The issuer's scheme.
        expected: String,
        /// The keys URL's scheme.
        found: String,
    },
    /// The keys URL names another host than the issuer.
    #[error(
        "the keys URL for issuer `{issuer}` names host `{found}`, not the issuer's host `{expected}`"
    )]
    OtherHost {
        /// The issuer.
        issuer: Issuer,
        /// The issuer's host.
        expected: String,
        /// The keys URL's host.
        found: String,
    },
    /// The keys URL names another port than the issuer, explicitly or by its scheme's default.
    #[error(
        "the keys URL for issuer `{issuer}` names port {found}, not the issuer's port {expected}"
    )]
    OtherPort {
        /// The issuer.
        issuer: Issuer,
        /// The issuer's port.
        expected: u16,
        /// The keys URL's port.
        found: u16,
    },
    /// The keys URL is `https`, and this build has no TLS client.
    #[error(
        "the keys URL for issuer `{0}` is https, and this gateway cannot yet fetch keys over TLS"
    )]
    TlsUnavailable(Issuer),
    /// The deadline is zero.
    #[error("the deadline for fetching the keys of issuer `{0}` is zero")]
    ZeroDeadline(Issuer),
    /// The body cap is zero.
    #[error("the body size cap for fetching the keys of issuer `{0}` is zero")]
    ZeroCap(Issuer),
}

/// Where in the body a parse failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// The line, from 1.
    pub line: usize,
    /// The column, from 1.
    pub column: usize,
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {} column {}", self.line, self.column)
    }
}

/// Why a fetch returned no keys. None of these repeats the body: a parse failure gives only
/// where in the body it failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FetchError {
    /// The request could not be sent or its answer could not be read: no connection, or the
    /// exchange failed before a response head arrived.
    #[error("the keys URL could not be reached")]
    Unreachable,
    /// The fetch did not finish within its deadline.
    #[error("fetching the keys took longer than the deadline of {0:?}")]
    Deadline(Duration),
    /// The answer's status is not `200`. A redirect is one of these: it is never followed.
    #[error("the keys URL answered with status {0}, not 200; redirects are not followed")]
    Status(u16),
    /// The body is larger than the cap. It was not read in full.
    #[error("the keys URL answered with a body larger than the cap of {cap} bytes")]
    TooLarge {
        /// The cap, in bytes.
        cap: usize,
    },
    /// The body broke off before its end.
    #[error("the keys URL's answer broke off before its end")]
    BrokenOff,
    /// The body is not JSON.
    #[error("the keys URL's answer is not JSON (at {0})")]
    NotJson(Position),
    /// The body is JSON but not a JWK set.
    #[error("the keys URL's answer is JSON but not a JWK set (at {0})")]
    NotAJwkSet(Position),
}

/// The keys of one issuer, at a URL on the issuer's own origin.
///
/// Built once, at boot, by [`KeySource::new`], which checks the source rules. Each
/// [`fetch`](KeySource::fetch) is one bounded `GET` to that URL and nowhere else. Fetching
/// needs a Tokio runtime.
pub struct KeySource {
    issuer: Issuer,
    uri: Uri,
    deadline: Duration,
    max_body_bytes: usize,
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl fmt::Debug for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySource")
            .field("issuer", &self.issuer)
            .field("uri", &self.uri)
            .field("deadline", &self.deadline)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl KeySource {
    /// The keys of `issuer`, fetched from `keys_url` under `options`. Refuses a URL off the
    /// issuer's origin, one with a user name, password or fragment, an `https` URL (this build
    /// has no TLS client), and a zero deadline or cap.
    pub fn new(
        issuer: &Issuer,
        keys_url: &str,
        options: FetchOptions,
    ) -> Result<Self, SourceError> {
        let origin = Url::parse(issuer.as_str())
            .ok()
            .filter(|origin| {
                matches!(origin.scheme(), "http" | "https")
                    && origin.has_host()
                    && origin.username().is_empty()
                    && origin.password().is_none()
            })
            .ok_or_else(|| SourceError::IssuerNotAnOrigin(issuer.clone()))?;
        let url = Url::parse(keys_url).map_err(|_| SourceError::NotAUrl(issuer.clone()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(SourceError::UserInfo(issuer.clone()));
        }
        if url.fragment().is_some() {
            return Err(SourceError::Fragment(issuer.clone()));
        }
        // The same scheme as the issuer: `https` unless the issuer itself is `http`.
        if url.scheme() != origin.scheme() {
            return Err(SourceError::OtherScheme {
                issuer: issuer.clone(),
                expected: origin.scheme().to_owned(),
                found: url.scheme().to_owned(),
            });
        }
        if url.host() != origin.host() {
            return Err(SourceError::OtherHost {
                issuer: issuer.clone(),
                expected: origin.host_str().unwrap_or_default().to_owned(),
                found: url.host_str().unwrap_or_default().to_owned(),
            });
        }
        let (expected, found) = (origin.port_or_known_default(), url.port_or_known_default());
        if found != expected {
            return Err(SourceError::OtherPort {
                issuer: issuer.clone(),
                expected: expected.unwrap_or_default(),
                found: found.unwrap_or_default(),
            });
        }
        if url.scheme() != "http" {
            return Err(SourceError::TlsUnavailable(issuer.clone()));
        }
        if options.deadline.is_zero() {
            return Err(SourceError::ZeroDeadline(issuer.clone()));
        }
        if options.max_body_bytes == 0 {
            return Err(SourceError::ZeroCap(issuer.clone()));
        }
        let uri: Uri = url
            .as_str()
            .parse()
            .map_err(|_| SourceError::NotAUrl(issuer.clone()))?;
        // The legacy client follows no redirect and reads no proxy setting from the
        // environment, and its connector refuses any scheme but `http`, so a request goes to
        // the URL checked above or nowhere.
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build(HttpConnector::new());
        Ok(Self {
            issuer: issuer.clone(),
            uri,
            deadline: options.deadline,
            max_body_bytes: options.max_body_bytes,
            client,
        })
    }

    /// The issuer whose keys this source fetches.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Fetches the issuer's JWK set: one `GET`, abandoned at the deadline, with the body
    /// refused once it is known to be larger than the cap.
    pub async fn fetch(&self) -> Result<JwkSet, FetchError> {
        let body = match tokio::time::timeout(self.deadline, self.exchange()).await {
            Err(_elapsed) => return Err(FetchError::Deadline(self.deadline)),
            Ok(body) => body?,
        };
        parse(&body)
    }

    /// Sends the request and reads a `200` answer's body, up to the cap.
    async fn exchange(&self) -> Result<Vec<u8>, FetchError> {
        let response = self.send(self.uri.clone()).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        self.read(response).await
    }

    async fn send(&self, uri: Uri) -> Result<Response<Incoming>, FetchError> {
        let request = Request::get(uri)
            .header(ACCEPT, "application/json")
            .body(Empty::new())
            .map_err(|_| FetchError::Unreachable)?;
        self.client
            .request(request)
            .await
            .map_err(|_| FetchError::Unreachable)
    }

    /// Reads the body, refusing as soon as it is known to be larger than the cap: from its
    /// declared length if it has one, and otherwise as it arrives.
    async fn read(&self, response: Response<Incoming>) -> Result<Vec<u8>, FetchError> {
        let too_large = FetchError::TooLarge {
            cap: self.max_body_bytes,
        };
        if declared_length(response.headers())
            .is_some_and(|length| length > self.max_body_bytes as u64)
        {
            return Err(too_large);
        }
        let mut body = response.into_body();
        let mut received = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| FetchError::BrokenOff)?;
            if let Ok(data) = frame.into_data() {
                if received.len() + data.len() > self.max_body_bytes {
                    return Err(too_large);
                }
                received.extend_from_slice(&data);
            }
        }
        Ok(received)
    }
}

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Parses the body as a JWK set. A failure gives where it failed and whether the body was JSON
/// at all, never the body: `serde_json`'s own messages can quote a value from it.
fn parse(body: &[u8]) -> Result<JwkSet, FetchError> {
    serde_json::from_slice(body).map_err(|error| {
        let at = Position {
            line: error.line(),
            column: error.column(),
        };
        match error.classify() {
            Category::Data => FetchError::NotAJwkSet(at),
            Category::Io | Category::Syntax | Category::Eof => FetchError::NotJson(at),
        }
    })
}
