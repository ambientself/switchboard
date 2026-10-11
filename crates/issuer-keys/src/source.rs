//! The key source: its rules, checked once, and the bounded fetch.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use gateway_core::Issuer;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{DefaultServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use jsonwebtoken::jwk::JwkSet;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::{ClientConfig, RootCertStore};
use serde_json::error::Category;
use thiserror::Error;
use url::Url;

/// How long a fetch may take, from connecting to the last byte of the body, unless configured
/// otherwise.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// The largest body accepted, in bytes, unless configured otherwise.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

/// The longest token file read, in bytes, as for a proxied server's credential file. A bearer
/// token is far shorter; a larger file is the wrong file.
pub const MAX_TOKEN_BYTES: u64 = 8 * 1024;

/// The bounds on each fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchOptions {
    /// How long a fetch may take in all: connecting, the TLS handshake, the response head and
    /// the whole body.
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

/// The files a source reads besides its URL. Both belong to an `https` keys URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceFiles {
    /// The PEM bundle of the CAs the keys URL's certificate must chain to, read when the source
    /// is built. These are the only CAs trusted: nothing is compiled in and nothing is read
    /// from the system. Required for an `https` keys URL, and refused beside an `http` one.
    pub ca_file: Option<PathBuf>,
    /// A file holding a bearer token sent with each fetch, to the keys URL only. It is read
    /// again on every fetch, since the kubelet rotates a projected token in place. Refused
    /// beside an `http` keys URL, where the token would cross the network in the clear.
    pub token_file: Option<PathBuf>,
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
    /// The keys URL is `https` and no CA file is given to verify it.
    #[error(
        "the keys URL for issuer `{0}` is https and no CA file is given; name the CA bundle its \
         certificate is verified against"
    )]
    NoCaFile(Issuer),
    /// A CA file is given for an `http` keys URL, which has no certificate to verify.
    #[error("the keys URL for issuer `{0}` is http, so it takes no CA file")]
    CaFileForHttp(Issuer),
    /// A token file is given for an `http` keys URL, which would send the token in the clear.
    #[error(
        "the keys URL for issuer `{0}` is http, so it takes no token file: the token would be \
         sent in the clear"
    )]
    TokenForHttp(Issuer),
    /// The CA file could not be read.
    #[error("the CA file {path} for issuer `{issuer}` could not be read")]
    CaUnreadable {
        /// The issuer.
        issuer: Issuer,
        /// The file.
        path: PathBuf,
    },
    /// The CA file is not PEM.
    #[error("the CA file {path} for issuer `{issuer}` is not PEM")]
    CaNotPem {
        /// The issuer.
        issuer: Issuer,
        /// The file.
        path: PathBuf,
    },
    /// The CA file is PEM and holds no certificate.
    #[error("the CA file {path} for issuer `{issuer}` holds no certificate")]
    CaNoCertificate {
        /// The issuer.
        issuer: Issuer,
        /// The file.
        path: PathBuf,
    },
    /// The CA file holds a certificate that cannot be used as a trust anchor.
    #[error("the CA file {path} for issuer `{issuer}` holds a certificate that does not parse")]
    CaBadCertificate {
        /// The issuer.
        issuer: Issuer,
        /// The file.
        path: PathBuf,
    },
    /// The TLS client could not be built from its settings.
    #[error("the TLS client for the keys of issuer `{0}` could not be built")]
    Tls(Issuer),
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

/// What is wrong with the token file. None of these repeats what the file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TokenFault {
    /// The file could not be read.
    #[error("could not be read")]
    Unreadable,
    /// The file is larger than [`MAX_TOKEN_BYTES`].
    #[error("is larger than {MAX_TOKEN_BYTES} bytes")]
    TooLarge,
    /// The file holds nothing but whitespace.
    #[error("is empty")]
    Empty,
    /// The file holds something a bearer token cannot be: text that is not UTF-8, or a space or
    /// control character inside the token.
    #[error("does not hold one bearer token")]
    NotAToken,
}

/// Why a fetch returned no keys. None of these repeats the body or the token: a parse failure
/// gives only where in the body it failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FetchError {
    /// The token file could not be used, so nothing was sent.
    #[error("the token file for the keys URL {0}, so no request was sent")]
    Token(TokenFault),
    /// The request could not be sent or its answer could not be read: no connection, a TLS
    /// handshake that failed, or an exchange that failed before a response head arrived.
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

/// The client a source sends its request with: plain HTTP for an `http` keys URL, and TLS,
/// trusting only the configured CAs, for an `https` one.
enum Transport {
    Plain(Client<HttpConnector, Empty<Bytes>>),
    Tls(Client<HttpsConnector<HttpConnector>, Empty<Bytes>>),
}

/// The keys of one issuer, at a URL on the issuer's own origin.
///
/// Built once, at boot, by [`KeySource::new`] or [`KeySource::with_files`], which check the
/// source rules. Each [`fetch`](KeySource::fetch) is one bounded `GET` to that URL and nowhere
/// else. Fetching needs a Tokio runtime.
pub struct KeySource {
    issuer: Issuer,
    uri: Uri,
    deadline: Duration,
    max_body_bytes: usize,
    token_file: Option<PathBuf>,
    transport: Transport,
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
    /// The keys of `issuer`, fetched from `keys_url` under `options`, with no CA file and no
    /// token: [`with_files`](KeySource::with_files) with neither file, so an `https` keys URL
    /// is refused.
    pub fn new(
        issuer: &Issuer,
        keys_url: &str,
        options: FetchOptions,
    ) -> Result<Self, SourceError> {
        Self::with_files(issuer, keys_url, &SourceFiles::default(), options)
    }

    /// The keys of `issuer`, fetched from `keys_url` under `options`, reading `files`. Refuses
    /// a URL off the issuer's origin, one with a user name, password or fragment, an `https`
    /// URL with no CA file, a CA or token file beside an `http` URL, a CA file that cannot be
    /// read, is not PEM or holds no certificate, and a zero deadline or cap.
    pub fn with_files(
        issuer: &Issuer,
        keys_url: &str,
        files: &SourceFiles,
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
        // The scheme is the issuer's, so `http` or `https`.
        let transport = if url.scheme() == "https" {
            let Some(ca_file) = &files.ca_file else {
                return Err(SourceError::NoCaFile(issuer.clone()));
            };
            Transport::Tls(tls_client(issuer, ca_file)?)
        } else {
            if files.ca_file.is_some() {
                return Err(SourceError::CaFileForHttp(issuer.clone()));
            }
            if files.token_file.is_some() {
                return Err(SourceError::TokenForHttp(issuer.clone()));
            }
            // This connector refuses any scheme but `http`.
            Transport::Plain(client(HttpConnector::new()))
        };
        Ok(Self {
            issuer: issuer.clone(),
            uri,
            deadline: options.deadline,
            max_body_bytes: options.max_body_bytes,
            token_file: files.token_file.clone(),
            transport,
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

    /// Reads the token, if there is one, sends the request and reads a `200` answer's body, up
    /// to the cap.
    async fn exchange(&self) -> Result<Vec<u8>, FetchError> {
        // Read on every fetch, never kept: the file may have been rotated since the last one.
        let authorization = match &self.token_file {
            Some(path) => Some(bearer(path)?),
            None => None,
        };
        let response = self.send(self.uri.clone(), authorization).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(FetchError::Status(status.as_u16()));
        }
        self.read(response).await
    }

    async fn send(
        &self,
        uri: Uri,
        authorization: Option<HeaderValue>,
    ) -> Result<Response<Incoming>, FetchError> {
        let mut request = Request::get(uri).header(ACCEPT, "application/json");
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        let request = request
            .body(Empty::new())
            .map_err(|_| FetchError::Unreachable)?;
        match &self.transport {
            Transport::Plain(client) => client.request(request).await,
            Transport::Tls(client) => client.request(request).await,
        }
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

/// The legacy client, which follows no redirect and reads no proxy setting from the
/// environment, so a request goes to the URL the source checked or nowhere.
fn client<C>(connector: C) -> Client<C, Empty<Bytes>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone,
{
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .build(connector)
}

/// A client that speaks only TLS, offering only HTTP/1.1, and trusts only the CAs in
/// `ca_file`. Its crypto provider is ring, passed here; the process-wide default provider is
/// neither read nor set. The certificate is verified against the keys URL's host, a DNS name or
/// an IP address.
fn tls_client(
    issuer: &Issuer,
    ca_file: &Path,
) -> Result<Client<HttpsConnector<HttpConnector>, Empty<Bytes>>, SourceError> {
    let roots = trusted(issuer, ca_file)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| SourceError::Tls(issuer.clone()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // The TCP connector under TLS sees the `https` URL, so it is told not to refuse it; the
    // TLS connector around it refuses every scheme but `https`.
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

/// The certificates in the PEM bundle at `path`, as the only trust anchors.
fn trusted(issuer: &Issuer, path: &Path) -> Result<RootCertStore, SourceError> {
    let bytes = std::fs::read(path).map_err(|_| SourceError::CaUnreadable {
        issuer: issuer.clone(),
        path: path.to_owned(),
    })?;
    let not_pem = || SourceError::CaNotPem {
        issuer: issuer.clone(),
        path: path.to_owned(),
    };
    let mut roots = RootCertStore::empty();
    let mut sections = 0;
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(&bytes) {
        let (kind, der) = section.map_err(|_| not_pem())?;
        sections += 1;
        if kind == SectionKind::Certificate {
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| SourceError::CaBadCertificate {
                    issuer: issuer.clone(),
                    path: path.to_owned(),
                })?;
        }
    }
    if sections == 0 {
        return Err(not_pem());
    }
    if roots.is_empty() {
        return Err(SourceError::CaNoCertificate {
            issuer: issuer.clone(),
            path: path.to_owned(),
        });
    }
    Ok(roots)
}

/// The token in `path` as an `Authorization: Bearer` value, marked sensitive. Whitespace around
/// it, such as a trailing newline, is trimmed, as for a proxied server's credential file. No
/// more than one byte past the limit is read.
fn bearer(path: &Path) -> Result<HeaderValue, FetchError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_TOKEN_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| FetchError::Token(TokenFault::Unreadable))?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(FetchError::Token(TokenFault::TooLarge));
    }
    let not_a_token = || FetchError::Token(TokenFault::NotAToken);
    let text = String::from_utf8(bytes).map_err(|_| not_a_token())?;
    let token = text.trim();
    if token.is_empty() {
        return Err(FetchError::Token(TokenFault::Empty));
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(not_a_token());
    }
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| not_a_token())?;
    value.set_sensitive(true);
    Ok(value)
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
