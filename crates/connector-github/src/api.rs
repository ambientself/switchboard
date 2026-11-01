//! GitHub's REST API, read with a token the key custodian issued.
//!
//! The base URL is `https`, with a CA file the deployment names as the only CAs trusted, or,
//! in a development build only (the `loopback` feature), plain `http` to a loopback address,
//! for the tests' fakes. Redirects are not followed, no proxy is read from the environment, and
//! an answer is read up to [`MAX_ANSWER_BYTES`].
//!
//! A request sends the token in an `Authorization` header marked sensitive. No error this
//! module returns holds the token or GitHub's answer: [`ApiError`] keeps the status and whether
//! GitHub said its rate limit was used up, and nothing else of what came back.
//!
//! The same client, built for a job log host the deployment pins, downloads a log: with no
//! token and none of the API's headers, keeping only the end of what it reads. A redirect's
//! target is handed back to the caller, which decides whether a pinned host serves it.

use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, AUTHORIZATION, HeaderValue, LOCATION, USER_AGENT};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{DefaultServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use thiserror::Error;

/// The GitHub REST API version the connector speaks.
pub const API_VERSION: &str = "2022-11-28";

/// The `User-Agent` GitHub requires: the product, nothing about the person running it.
pub const PRODUCT: &str = "switchboard-gateway";

/// The most bytes of one GitHub answer the connector reads. A file is read through the contents
/// API, which serves files up to 1 MB, base64-encoded; this holds one with room to spare.
pub const MAX_ANSWER_BYTES: usize = 2 * 1024 * 1024;

/// Why the API client could not be built.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    /// The URL does not parse, has a path or a query, or is neither `https` nor, in a
    /// development build, plain `http` to a loopback address.
    #[error(
        "the GitHub API URL `{0}` is not an https URL with no path, or, in a development build, \
         an http URL to a loopback address"
    )]
    Url(String),
    /// An `https` URL and no CA file.
    #[error("the GitHub API URL is https, and no CA file is named to trust")]
    NoCaFile,
    /// A CA file beside a plain `http` URL, where nothing would be verified against it.
    #[error("a CA file is named for a plain http GitHub API URL; remove it")]
    CaFileForHttp,
    /// The CA file could not be read or holds no certificate.
    #[error("the CA file `{0}` could not be read, or holds no PEM certificate")]
    CaFile(String),
    /// The TLS configuration could not be built.
    #[error("the TLS client could not be configured")]
    Tls,
}

/// What came of one request. Holds nothing GitHub sent back but the status, whether it said
/// its rate limit was used up, and, on success, the JSON it answered.
#[derive(Debug)]
pub(crate) enum Answered {
    /// A 2xx answer whose body is JSON.
    Json(Value),
    /// A 2xx answer whose body could not be read as JSON.
    Unreadable,
    /// Any other status.
    Status {
        status: StatusCode,
        rate_limited: bool,
    },
    /// No answer: the request could not be sent, or the answer could not be read in full.
    Unreachable,
}

enum Transport {
    #[cfg(feature = "loopback")]
    Plain(Client<HttpConnector, Empty<Bytes>>),
    Tls(Client<HttpsConnector<HttpConnector>, Empty<Bytes>>),
}

/// The client for GitHub's REST API.
pub(crate) struct Api {
    base: String,
    transport: Transport,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// Whether `host` is a loopback address or `localhost`.
#[cfg(feature = "loopback")]
fn loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

impl Api {
    /// A client for the API at `url`, trusting the CAs in `ca_file` for an `https` URL.
    pub(crate) fn new(url: &str, ca_file: Option<&Path>) -> Result<Self, ApiError> {
        let base = url.trim_end_matches('/');
        let bad = || ApiError::Url(url.to_owned());
        let uri: Uri = base.parse().map_err(|_| bad())?;
        let host = uri.host().ok_or_else(bad)?;
        if !(uri.path() == "/" || uri.path().is_empty()) || uri.query().is_some() {
            return Err(bad());
        }
        let transport = match uri.scheme_str() {
            Some("https") => Transport::Tls(tls_client(ca_file.ok_or(ApiError::NoCaFile)?)?),
            #[cfg(feature = "loopback")]
            Some("http") if loopback(host) => {
                if ca_file.is_some() {
                    return Err(ApiError::CaFileForHttp);
                }
                Transport::Plain(client(HttpConnector::new()))
            }
            _ => {
                let _ = host;
                return Err(bad());
            }
        };
        Ok(Self {
            base: base.to_owned(),
            transport,
        })
    }

    /// The base URL: a scheme and an authority, with no path.
    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// `GET {base}{path_and_query}`: with `token` and the API's headers, or, with no token, as
    /// a plain download carrying nothing but the `User-Agent`. The response, or `None` when
    /// there is none.
    async fn send(
        &self,
        path_and_query: &str,
        token: Option<&str>,
    ) -> Option<hyper::Response<Incoming>> {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!("{}{path_and_query}", self.base))
            .header(USER_AGENT, PRODUCT);
        if let Some(token) = token {
            let mut authorization = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
            authorization.set_sensitive(true);
            request = request
                .header(ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", API_VERSION)
                .header(AUTHORIZATION, authorization);
        }
        let request = request.body(Empty::new()).ok()?;
        let response = match &self.transport {
            #[cfg(feature = "loopback")]
            Transport::Plain(client) => client.request(request).await,
            Transport::Tls(client) => client.request(request).await,
        };
        match response {
            Ok(response) => Some(response),
            Err(error) => {
                // hyper's error names the connection's failure, never a header.
                tracing::warn!(%error, "GitHub's API could not be reached");
                None
            }
        }
    }

    /// `GET {base}{path_and_query}` with `token`, for a redirect: where it points is returned,
    /// never followed, and the body of a redirect or a success is not read.
    pub(crate) async fn get_location(&self, path_and_query: &str, token: &str) -> Located {
        let Some(response) = self.send(path_and_query, Some(token)).await else {
            return Located::Answered(Answered::Unreachable);
        };
        let status = response.status();
        if status.is_redirection()
            && let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|location| location.to_str().ok())
        {
            return Located::Redirect(location.to_owned());
        }
        if status.is_success() {
            return Located::Direct(status);
        }
        Located::Answered(Answered::Status {
            status,
            rate_limited: rate_limited(&response),
        })
    }

    /// `GET {base}{path_and_query}` with no credential: at most `max_read` bytes of the body
    /// are read, and the last `keep` of them kept.
    pub(crate) async fn get_tail(
        &self,
        path_and_query: &str,
        keep: usize,
        max_read: usize,
    ) -> Tail {
        let Some(response) = self.send(path_and_query, None).await else {
            return Tail::Unreachable;
        };
        let status = response.status();
        if !status.is_success() {
            return Tail::Status(status);
        }
        let mut body = response.into_body();
        let mut kept: Vec<u8> = Vec::new();
        let mut read = 0;
        let mut stopped = false;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                return Tail::Unreachable;
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            read += data.len();
            kept.extend_from_slice(&data);
            if kept.len() > 2 * keep {
                kept.drain(..kept.len() - keep);
            }
            if read >= max_read {
                stopped = true;
                break;
            }
        }
        if kept.len() > keep {
            kept.drain(..kept.len() - keep);
        }
        Tail::Text {
            cut: read > kept.len(),
            tail: kept,
            stopped,
        }
    }

    /// `GET {base}{path_and_query}` with `token`.
    pub(crate) async fn get(&self, path_and_query: &str, token: &str) -> Answered {
        let Some(response) = self.send(path_and_query, Some(token)).await else {
            return Answered::Unreachable;
        };
        let status = response.status();
        let rate_limited = rate_limited(&response);
        let Ok(body) = Limited::new(response.into_body(), MAX_ANSWER_BYTES)
            .collect()
            .await
        else {
            return Answered::Unreachable;
        };
        if !status.is_success() {
            return Answered::Status {
                status,
                rate_limited,
            };
        }
        match serde_json::from_slice(&body.to_bytes()) {
            Ok(value) => Answered::Json(value),
            Err(_) => Answered::Unreadable,
        }
    }
}

/// Whether GitHub's answer says its rate limit is used up.
fn rate_limited<B>(response: &hyper::Response<B>) -> bool {
    let status = response.status();
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (response
                .headers()
                .get("x-ratelimit-remaining")
                .is_some_and(|remaining| remaining == "0")
                || response.headers().contains_key("retry-after")))
}

/// What came of a request whose answer should be a redirect.
#[derive(Debug)]
pub(crate) enum Located {
    /// A redirect, and where it points: not followed.
    Redirect(String),
    /// A success, whose body was not read.
    Direct(StatusCode),
    /// Any other answer, or none.
    Answered(Answered),
}

/// What came of a download with no credential.
#[derive(Debug)]
pub(crate) enum Tail {
    /// The end of the body.
    Text {
        /// The last bytes read, at most the `keep` asked for.
        tail: Vec<u8>,
        /// Whether more was read than is kept.
        cut: bool,
        /// Whether reading stopped at `max_read`, before the body ended.
        stopped: bool,
    },
    /// An answer that is not a success.
    Status(StatusCode),
    /// No answer, or one that could not be read in full.
    Unreachable,
}

/// The legacy client, which follows no redirect and reads no proxy setting from the
/// environment.
fn client<C>(connector: C) -> Client<C, Empty<Bytes>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone,
{
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .build(connector)
}

/// A client that speaks only TLS, offering only HTTP/1.1, and trusts only the CAs in
/// `ca_file`. Its crypto provider is ring, passed here; the process-wide default is neither
/// read nor set.
fn tls_client(
    ca_file: &Path,
) -> Result<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>, ApiError> {
    let unreadable = || ApiError::CaFile(ca_file.display().to_string());
    let bytes = std::fs::read(ca_file).map_err(|_| unreadable())?;
    let mut roots = RootCertStore::empty();
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(&bytes) {
        let (kind, der) = section.map_err(|_| unreadable())?;
        if kind == SectionKind::Certificate {
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| unreadable())?;
        }
    }
    if roots.is_empty() {
        return Err(unreadable());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ApiError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let mut tcp = HttpConnector::new();
    tcp.enforce_http(false);
    let connector = HttpsConnector::new(
        tcp,
        config,
        true,
        Arc::new(DefaultServerNameResolver::default()),
    );
    Ok(client(connector))
}
