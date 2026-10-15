//! The custodian's side of GitHub's App API: the App JWT, an installation token narrowed to
//! exactly what was asked for, and its revocation.
//!
//! The private key is read once, at start, into an [`AppKey`], which signs App JWTs and does
//! nothing else: its `Debug` shows nothing of it, and nothing returns its bytes. Each token
//! request signs a fresh JWT, issued 60 seconds in the past for clock drift and expiring nine
//! minutes after now, inside GitHub's ten.
//!
//! A token is asked for with `repositories` and `permissions` both set, so GitHub narrows it to
//! them. What GitHub answers is checked: a token that names any other repository, all of
//! them, or a permission beyond what was asked for (other than `metadata: read`, which GitHub
//! adds to every token) is never handed out. It comes back in the `unissued` field of the
//! [`VendorError`], and the server revokes it as it revokes a token at the end of its lifetime
//! (see [`crate::server`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use gateway_registry::Access;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue, USER_AGENT};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{DefaultServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivatePkcs1KeyDer};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;

use crate::clock;
use crate::protocol::{Failure, Secret};

/// The GitHub REST API version the custodian speaks.
pub const API_VERSION: &str = "2022-11-28";

/// The `User-Agent` GitHub requires: the product, nothing about the person running it.
pub const PRODUCT: &str = "switchboard-custodian";

/// How long GitHub's installation tokens last: an hour.
pub const GITHUB_TOKEN_SECONDS: u64 = 3600;

/// The most bytes of GitHub's answer the custodian reads. A token for 500 repositories lists
/// each repository in full, a few kilobytes each.
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

/// The App's private key. Signs App JWTs; shows nothing of itself.
pub struct AppKey(EncodingKey);

impl fmt::Debug for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppKey([redacted])")
    }
}

/// Why the key could not be used.
#[derive(Debug, Error)]
#[error("the App's private key is not an RSA private key in PEM that can sign a JWT")]
pub struct KeyInvalid;

impl AppKey {
    /// The key in `pem`, an RSA private key in PKCS#1 as GitHub issues it, checked by signing
    /// a JWT with it.
    pub fn from_pem(pem: &[u8]) -> Result<Self, KeyInvalid> {
        let der = PrivatePkcs1KeyDer::from_pem_slice(pem).map_err(|_| KeyInvalid)?;
        let key = Self(EncodingKey::from_rsa_der(der.secret_pkcs1_der()));
        key.jwt("check", clock::now()).map_err(|_| KeyInvalid)?;
        Ok(key)
    }

    /// An App JWT for app `app_id` at `now`: RS256, issued 60 seconds before `now`, expiring
    /// nine minutes after it.
    fn jwt(&self, app_id: &str, now: u64) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = json!({
            "iat": now.saturating_sub(60),
            "exp": now + 540,
            "iss": app_id,
        });
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.0)
    }
}

/// Where GitHub's API is, and how the custodian reaches it.
pub struct GitHubConfig<'a> {
    /// The API's base URL: `https://api.github.com`, or plain `http` to a loopback address.
    pub api_url: &'a str,
    /// The CAs to trust for an `https` URL. Required for one.
    pub ca_file: Option<&'a Path>,
    /// The App's ID or client ID, the JWT's issuer.
    pub app_id: &'a str,
    /// The installation tokens are issued for.
    pub installation_id: u64,
    /// How long a call to GitHub may take.
    pub deadline: Duration,
}

/// Why the GitHub client could not be built.
#[derive(Debug, Error)]
pub enum ApiConfigError {
    /// The URL does not parse, or is neither `https` nor `http` to a loopback address.
    #[error(
        "`api_url` `{0}` is not an https URL, or an http URL to a loopback address, with no path"
    )]
    Url(String),
    /// An https URL with no CA file.
    #[error("`api_url` is https, and `ca_file` names no CA file to trust")]
    NoCaFile,
    /// The CA file could not be read or holds no certificate.
    #[error("the CA file `{0}` could not be read, or holds no PEM certificate")]
    CaFile(String),
    /// The TLS configuration could not be built.
    #[error("the TLS client could not be configured")]
    Tls,
}

enum Transport {
    Plain(Client<HttpConnector, Full<Bytes>>),
    Tls(Client<HttpsConnector<HttpConnector>, Full<Bytes>>),
}

/// A token GitHub issued, and when it lapses.
#[derive(Debug)]
pub struct Issued {
    /// The token.
    pub token: Secret,
    /// GitHub's expiry, in seconds since the epoch.
    pub expires_at: u64,
}

/// Why GitHub gave no token.
#[derive(Debug)]
pub struct VendorError {
    /// The kind, as the answer and the counters name it.
    pub failure: Failure,
    /// A sentence for the operator. Never a token or the key.
    pub message: String,
    /// A token GitHub issued that is not handed out, because it is broader than asked for or
    /// has no expiry the custodian can read. It must be revoked.
    pub unissued: Option<Issued>,
}

impl VendorError {
    fn new(failure: Failure, message: impl Into<String>) -> Self {
        Self {
            failure,
            message: message.into(),
            unissued: None,
        }
    }

    /// A failure that leaves `token` issued and not handed out. It lapses at `expires_at`, or
    /// an hour from now if that is sooner or GitHub's answer gave no expiry the custodian can
    /// read.
    fn unissued(
        failure: Failure,
        message: impl Into<String>,
        token: Secret,
        expires_at: Option<u64>,
    ) -> Self {
        let hour = clock::now() + GITHUB_TOKEN_SECONDS;
        Self {
            unissued: Some(Issued {
                token,
                expires_at: expires_at.map_or(hour, |at| at.min(hour)),
            }),
            ..Self::new(failure, message)
        }
    }
}

/// GitHub's answer to a token request: only what the custodian checks.
#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
    #[serde(default)]
    repository_selection: Option<String>,
    #[serde(default)]
    repositories: Option<Vec<RepositoryAnswer>>,
}

#[derive(Deserialize)]
struct RepositoryAnswer {
    full_name: String,
}

/// The client for GitHub's App API.
pub struct GitHubApp {
    base: String,
    transport: Transport,
    app_id: String,
    installation_id: u64,
    key: Arc<AppKey>,
    deadline: Duration,
}

impl fmt::Debug for GitHubApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubApp")
            .field("base", &self.base)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

/// Whether `host` is a loopback address or `localhost`.
fn loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

impl GitHubApp {
    /// A client for `config`, signing with `key`.
    pub fn new(config: &GitHubConfig<'_>, key: AppKey) -> Result<Self, ApiConfigError> {
        let base = config.api_url.trim_end_matches('/');
        let uri: Uri = base
            .parse()
            .map_err(|_| ApiConfigError::Url(config.api_url.to_owned()))?;
        let bad = || ApiConfigError::Url(config.api_url.to_owned());
        let host = uri.host().ok_or_else(bad)?;
        if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
            return Err(bad());
        }
        let transport = match uri.scheme_str() {
            Some("https") => {
                let ca_file = config.ca_file.ok_or(ApiConfigError::NoCaFile)?;
                Transport::Tls(tls_client(ca_file)?)
            }
            Some("http") if loopback(host) => Transport::Plain(client(HttpConnector::new())),
            _ => return Err(bad()),
        };
        Ok(Self {
            base: base.to_owned(),
            transport,
            app_id: config.app_id.to_owned(),
            installation_id: config.installation_id,
            key: Arc::new(key),
            deadline: config.deadline,
        })
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Bytes), VendorError> {
        let failed = |message: &str| VendorError::new(Failure::VendorFailed, message);
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer}"))
            .map_err(|_| failed("the bearer cannot be sent in a header"))?;
        authorization.set_sensitive(true);
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header(ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header(USER_AGENT, PRODUCT)
            .header(AUTHORIZATION, authorization);
        if body.is_some() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|_| failed("the request could not be built"))?;
        let exchange = async {
            let response = match &self.transport {
                Transport::Plain(client) => client.request(request).await,
                Transport::Tls(client) => client.request(request).await,
            }
            .map_err(|error| failed(&format!("GitHub could not be reached: {error}")))?;
            let status = response.status();
            let body = Limited::new(response.into_body(), MAX_ANSWER_BYTES)
                .collect()
                .await
                .map_err(|_| failed("GitHub's answer could not be read, or was too large"))?
                .to_bytes();
            Ok((status, body))
        };
        tokio::time::timeout(self.deadline, exchange)
            .await
            .map_err(|_| {
                VendorError::new(
                    Failure::VendorTimeout,
                    format!("GitHub did not answer within {:?}", self.deadline),
                )
            })?
    }

    /// An installation token for exactly `repositories` (each `owner/name`, all on the
    /// installation's account) and exactly `permissions`.
    pub async fn create_token(
        &self,
        repositories: &[String],
        permissions: &BTreeMap<String, Access>,
    ) -> Result<Issued, VendorError> {
        let names: Vec<&str> = repositories
            .iter()
            .map(|repository| repository.split_once('/').map_or("", |(_, name)| name))
            .collect();
        let levels: BTreeMap<&str, &str> = permissions
            .iter()
            .map(|(name, level)| (name.as_str(), level.as_str()))
            .collect();
        let body = json!({
            "repositories": names,
            "permissions": levels,
        });
        let jwt = self.key.jwt(&self.app_id, clock::now()).map_err(|_| {
            VendorError::new(Failure::VendorFailed, "the App JWT could not be signed")
        })?;
        let path = format!("/app/installations/{}/access_tokens", self.installation_id);
        let (status, body) = self
            .send(
                Method::POST,
                &path,
                &jwt,
                Some(body.to_string().into_bytes()),
            )
            .await?;
        if status != StatusCode::CREATED {
            let failure = if matches!(status.as_u16(), 401 | 403 | 404 | 422) {
                Failure::VendorRefused
            } else {
                Failure::VendorFailed
            };
            return Err(VendorError::new(
                failure,
                format!("GitHub answered {status} to the token request"),
            ));
        }
        let answer: TokenAnswer = serde_json::from_slice(&body).map_err(|_| {
            VendorError::new(
                Failure::VendorFailed,
                "GitHub's token answer could not be read",
            )
        })?;
        let widened = widened(&answer, repositories, permissions);
        let expires_at = clock::parse_utc(&answer.expires_at);
        let token = Secret::new(answer.token);
        if let Some(widened) = widened {
            return Err(VendorError::unissued(
                Failure::Widened,
                widened,
                token,
                expires_at,
            ));
        }
        let Some(expires_at) = expires_at else {
            return Err(VendorError::unissued(
                Failure::VendorFailed,
                "GitHub's token answer has no expiry the custodian can read",
                token,
                None,
            ));
        };
        Ok(Issued { token, expires_at })
    }

    /// Revokes `token` through GitHub's revoke endpoint, once.
    ///
    /// GitHub answers 204 when it revokes the token, and 401 to a token that no longer
    /// authenticates because it was revoked before or has expired. Either way the token no
    /// longer works, which is what revoking is for, so both are `Ok`.
    pub async fn revoke(&self, token: &Secret) -> Result<(), VendorError> {
        let (status, _) = self
            .send(Method::DELETE, "/installation/token", token.expose(), None)
            .await?;
        if status == StatusCode::NO_CONTENT || status == StatusCode::UNAUTHORIZED {
            Ok(())
        } else {
            Err(VendorError::new(
                Failure::VendorFailed,
                format!("GitHub answered {status} to the revocation"),
            ))
        }
    }
}

/// How GitHub's token is broader than what was asked for, if it is.
fn widened(
    answer: &TokenAnswer,
    repositories: &[String],
    permissions: &BTreeMap<String, Access>,
) -> Option<String> {
    if answer.repository_selection.as_deref() != Some("selected") {
        return Some("GitHub issued a token for every repository of the installation".into());
    }
    let asked: BTreeSet<&str> = repositories.iter().map(String::as_str).collect();
    let given: BTreeSet<&str> = answer
        .repositories
        .iter()
        .flatten()
        .map(|repository| repository.full_name.as_str())
        .collect();
    if given != asked {
        return Some("GitHub issued a token for other repositories than asked for".into());
    }
    for (name, level) in &answer.permissions {
        let allowed = match permissions.get(name) {
            Some(Access::Write) => level == "read" || level == "write",
            Some(Access::Read) => level == "read",
            None => name == "metadata" && level == "read",
        };
        if !allowed {
            return Some(format!(
                "GitHub issued a token with `{name}: {level}`, which was not asked for"
            ));
        }
    }
    None
}

/// The legacy client, which follows no redirect and reads no proxy setting from the
/// environment.
fn client<C>(connector: C) -> Client<C, Full<Bytes>>
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
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, ApiConfigError> {
    let unreadable = || ApiConfigError::CaFile(ca_file.display().to_string());
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
        .map_err(|_| ApiConfigError::Tls)?
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
