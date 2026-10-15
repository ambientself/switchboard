//! The client for Otto's resolver interface (decision 0003), and its first question: is this
//! turn current? (decision 0012, "Currency").
//!
//! The interface is proposed to Otto's owners in `docs/resolver-interface.md`, which this
//! module implements and `tests/resolver_doc.rs` holds it to. In short: the gateway sends
//! `POST {base}/v1/currency` with a JSON question naming the turn (its session, execution, turn
//! and epoch, under the grant's own claim names) and a fresh request ID; Otto answers `200`
//! with the question's own object, every member unchanged, and one member added: `answer`,
//! one of `current`, `superseded`, `ended` and `revoked`.
//!
//! [`HttpResolver`] asks it, bounded inside this crate:
//!
//! - **A budget of one second** ([`BUDGET`]) over the whole exchange: reading the token,
//!   connecting, the TLS handshake, the response head and the last byte of the body. It is
//!   fixed by decision 0012, so it is not configured. The token is read on the runtime's
//!   blocking pool, so a read that blocks cannot hold the question past the budget.
//! - **A cap on the answer**, [`MAX_ANSWER_BYTES`], enforced from the declared length if there
//!   is one and otherwise as the body arrives, so an oversized answer is never read in full.
//! - **No cache.** Every question is sent, and every answer is read from its own response.
//! - **No redirect and no proxy.** Any status but `200` is an error; nothing is read from the
//!   environment.
//! - **Only the configured CAs, and a token to the resolver only,** as issuer-keys has them for
//!   an issuer's keys. Plain `http` is accepted only to a loopback address, for a local fake:
//!   over plain `http` anyone on the path could answer `current`.
//!
//! Every failure is a [`ResolverFailure`], and every failure reads as
//! [`CurrencyAnswer::Unconfirmed`], which the core's currency check denies: no answer in time,
//! an error, an unknown version, an answer to another question, and an answer too large or not
//! in the format. Each question's answer, each failure by kind and each question's latency are
//! counted, and [`HttpResolver::counts`] gives them for the gateway to export.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use gateway_core::{BoxFuture, CurrencyAnswer, Delegation, ExecutionId, SessionId, TurnId};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue,
};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{DefaultServerNameResolver, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rand_core::{OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The interface's version: the first part of every question's path, and the `version` of
/// every question and answer.
pub const VERSION: &str = "v1";

/// The currency question's name: the last part of its path, and its `question` member.
pub const CURRENCY: &str = "currency";

/// How long a question may take, from reading the token to the last byte of the answer: one
/// second (decision 0012). No answer within it is unconfirmed.
pub const BUDGET: Duration = Duration::from_secs(1);

/// The largest answer read, in bytes. An honest answer echoes the turn's identifiers, which
/// come from a grant of at most 8192 bytes, so even escaped in full it is far shorter.
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// The longest token file read, in bytes, as for a proxied server's credential file.
pub const MAX_TOKEN_BYTES: u64 = 8 * 1024;

/// The upper bound of each latency bucket but the last, in milliseconds: the audit store's
/// bounds, so the gateway exports the resolver's latency as it does its other histograms.
pub const LATENCY_BOUNDS_MS: [u64; 11] =
    [5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 30_000];

/// How many buckets the latency histogram has: one per bound, and one past the last.
pub const LATENCY_BUCKETS: usize = LATENCY_BOUNDS_MS.len() + 1;

/// The currency question: is this turn current? The turn is named as its grant names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CurrencyQuestion {
    /// The session (the grant's `sid`).
    pub session: SessionId,
    /// The execution (the grant's `eid`).
    pub execution: ExecutionId,
    /// The turn (the grant's `tid`).
    pub turn: TurnId,
    /// The fencing epoch of the control plane that drove the turn (the grant's `epoch`).
    pub epoch: u64,
}

impl CurrencyQuestion {
    /// The question for a verified delegation's turn.
    pub fn of(delegation: &Delegation) -> Self {
        Self {
            session: delegation.session.clone(),
            execution: delegation.execution.clone(),
            turn: delegation.turn.clone(),
            epoch: delegation.epoch,
        }
    }
}

/// What Otto answered, when it answered in the format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// The control plane that drove the turn still holds the lease at the turn's epoch, and
    /// the turn has neither ended nor been revoked.
    Current,
    /// A newer epoch holds the lease.
    Superseded,
    /// The turn has ended.
    Ended,
    /// The turn was revoked.
    Revoked,
}

impl Answer {
    /// Every answer.
    pub const ALL: [Answer; 4] = [
        Answer::Current,
        Answer::Superseded,
        Answer::Ended,
        Answer::Revoked,
    ];

    /// The core's answer for this one.
    pub fn currency(self) -> CurrencyAnswer {
        match self {
            Answer::Current => CurrencyAnswer::Current,
            Answer::Superseded => CurrencyAnswer::Superseded,
            Answer::Ended => CurrencyAnswer::Ended,
            Answer::Revoked => CurrencyAnswer::Revoked,
        }
    }

    /// The answer's name on the wire.
    pub fn as_str(self) -> &'static str {
        self.currency().as_str()
    }
}

/// Why a question has no answer. Each is unconfirmed. None of these repeats the answer's body
/// or the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ResolverFailure {
    /// The token file could not be used, so nothing was sent.
    #[error("the resolver's token file could not be used, so no question was sent")]
    Token,
    /// The question could not be made, such as when no request ID could be drawn, so nothing
    /// was sent.
    #[error("the question could not be made, so it was not sent")]
    NotSent,
    /// No whole answer arrived within the budget.
    #[error("the resolver did not answer within the budget of {BUDGET:?}")]
    Timeout,
    /// The question could not be sent or its answer could not be read: no connection, a TLS
    /// handshake that failed, or an exchange that failed before a response head arrived.
    #[error("the resolver could not be reached")]
    Unreachable,
    /// The answer's status is not `200`. A redirect is one of these: it is never followed.
    #[error("the resolver answered with status {0}, not 200")]
    Status(u16),
    /// The answer is larger than [`MAX_ANSWER_BYTES`]. It was not read in full.
    #[error("the resolver's answer is larger than {MAX_ANSWER_BYTES} bytes")]
    TooLarge,
    /// The answer broke off before its end.
    #[error("the resolver's answer broke off before its end")]
    BrokenOff,
    /// The answer is not a JSON object in the format: not JSON, a member missing, repeated or
    /// unknown, or an answer that is not one of the four.
    #[error("the resolver's answer is not in the format")]
    Malformed,
    /// The answer's `version` is not [`VERSION`].
    #[error("the resolver's answer is of another version than {VERSION}")]
    UnknownVersion,
    /// The answer does not echo the question that was asked: another question, another turn
    /// or epoch, or another request ID.
    #[error("the resolver's answer is to another question")]
    OtherQuestion,
}

impl ResolverFailure {
    /// The label each kind of failure is counted under, in the order the variants are declared.
    pub const LABELS: [&'static str; 10] = [
        "token",
        "not_sent",
        "timeout",
        "unreachable",
        "status",
        "too_large",
        "broken_off",
        "malformed",
        "unknown_version",
        "other_question",
    ];

    /// The label this failure is counted under.
    pub fn label(self) -> &'static str {
        Self::LABELS[self.index()]
    }

    fn index(self) -> usize {
        match self {
            ResolverFailure::Token => 0,
            ResolverFailure::NotSent => 1,
            ResolverFailure::Timeout => 2,
            ResolverFailure::Unreachable => 3,
            ResolverFailure::Status(_) => 4,
            ResolverFailure::TooLarge => 5,
            ResolverFailure::BrokenOff => 6,
            ResolverFailure::Malformed => 7,
            ResolverFailure::UnknownVersion => 8,
            ResolverFailure::OtherQuestion => 9,
        }
    }
}

/// The core's answer for what the resolver gave: its answer, or unconfirmed for every
/// failure.
pub fn currency_answer(result: Result<Answer, ResolverFailure>) -> CurrencyAnswer {
    match result {
        Ok(answer) => answer.currency(),
        Err(_) => CurrencyAnswer::Unconfirmed,
    }
}

/// Something that answers the currency question. The gateway asks through this, so a test can
/// put another in its place.
pub trait Resolver: Send + Sync {
    /// Whether the question's turn is current, asked afresh: every failure is
    /// [`CurrencyAnswer::Unconfirmed`].
    fn currency<'a>(&'a self, question: &'a CurrencyQuestion) -> BoxFuture<'a, CurrencyAnswer>;
}

/// Where the resolver is, and the files that authenticate it and the gateway.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolverConfig {
    /// The interface's base URL. A question goes to `{url}/v1/{question}`. `https`, or plain
    /// `http` to a loopback address only.
    pub url: String,
    /// The PEM bundle of the CAs the resolver's certificate must chain to, read when the client
    /// is built. These are the only CAs trusted. Required for `https`, refused for `http`.
    pub ca_file: Option<PathBuf>,
    /// A file holding the bearer token the gateway sends with each question: a projected
    /// ServiceAccount token whose audience is the resolver. Read when the client is built and
    /// again for every question, since the kubelet rotates it in place. Refused for `http`.
    pub token_file: Option<PathBuf>,
}

/// Why a resolver configuration was refused. The URL itself is never repeated, since one that
/// carries a password would repeat it.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ResolverConfigError {
    /// The URL is not an `http` or `https` URL with a host.
    #[error("the resolver's URL is not an http or https URL with a host")]
    NotAUrl,
    /// The URL carries a user name or password.
    #[error("the resolver's URL carries a user name or password")]
    UserInfo,
    /// The URL carries a query, which the question's path would follow.
    #[error("the resolver's URL carries a query")]
    Query,
    /// The URL is plain `http` to an address that is not loopback, where anyone on the path
    /// could answer.
    #[error("the resolver's URL is plain http to an address that is not loopback; use https")]
    PlainHttp,
    /// The URL is `https` and no CA file is given.
    #[error("the resolver's URL is https and no CA file is given")]
    NoCaFile,
    /// A CA file is given for an `http` URL.
    #[error("the resolver's URL is http, so it takes no CA file")]
    CaFileForHttp,
    /// A token file is given for an `http` URL, which would send the token in the clear.
    #[error("the resolver's URL is http, so it takes no token file")]
    TokenForHttp,
    /// The CA file cannot be used.
    #[error("the resolver's CA file {path} {fault}")]
    CaFile {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        fault: CaFault,
    },
    /// The token file cannot be used.
    #[error("the resolver's token file {path} {fault}")]
    TokenFile {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        fault: TokenFault,
    },
    /// The TLS client could not be built from its settings.
    #[error("the TLS client for the resolver could not be built")]
    Tls,
}

/// What is wrong with the resolver's CA file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CaFault {
    /// It cannot be read.
    #[error("cannot be read")]
    Unreadable,
    /// It is not PEM.
    #[error("is not PEM")]
    NotPem,
    /// It holds no certificate.
    #[error("holds no certificate")]
    NoCertificate,
    /// A certificate in it cannot be used as a trust anchor.
    #[error("holds a certificate that cannot be used as a trust anchor")]
    BadCertificate,
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
    /// The file holds something a bearer token cannot be.
    #[error("does not hold one bearer token")]
    NotAToken,
}

/// The client a resolver's questions go out on: plain HTTP to a loopback address, or TLS
/// trusting only the configured CAs.
enum Transport {
    Plain(Client<HttpConnector, Full<Bytes>>),
    Tls(Client<HttpsConnector<HttpConnector>, Full<Bytes>>),
}

/// The client for Otto's resolver interface over HTTP.
///
/// Built once, at boot, by [`HttpResolver::new`], which checks the configuration. Each
/// question is one `POST`, abandoned at the budget. Asking needs a Tokio runtime.
pub struct HttpResolver {
    currency: Uri,
    token_file: Option<PathBuf>,
    transport: Transport,
    signals: Arc<Signals>,
}

impl fmt::Debug for HttpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResolver")
            .field("currency", &self.currency)
            .field("token_file", &self.token_file)
            .finish_non_exhaustive()
    }
}

impl HttpResolver {
    /// The client for the resolver `config` names. Refuses a URL that is not `http` or `https`
    /// with a host, one with a user name, password or query, plain `http` to an address that
    /// is not loopback, `https` with no CA file, a CA or token file beside `http`, and a CA or
    /// token file that cannot be used.
    pub fn new(config: &ResolverConfig) -> Result<Self, ResolverConfigError> {
        let base: Uri = config
            .url
            .parse()
            .map_err(|_| ResolverConfigError::NotAUrl)?;
        let (Some(scheme), Some(authority)) = (base.scheme_str(), base.authority()) else {
            return Err(ResolverConfigError::NotAUrl);
        };
        if authority.as_str().contains('@') {
            return Err(ResolverConfigError::UserInfo);
        }
        if base.query().is_some() {
            return Err(ResolverConfigError::Query);
        }
        let host = authority.host();
        if host.is_empty() {
            return Err(ResolverConfigError::NotAUrl);
        }
        let path = base.path().trim_end_matches('/');
        let currency: Uri = format!("{scheme}://{authority}{path}/{VERSION}/{CURRENCY}")
            .parse()
            .map_err(|_| ResolverConfigError::NotAUrl)?;
        let transport = match scheme {
            "https" => {
                let Some(ca_file) = &config.ca_file else {
                    return Err(ResolverConfigError::NoCaFile);
                };
                Transport::Tls(tls_client(ca_file)?)
            }
            "http" => {
                let host = host
                    .strip_prefix('[')
                    .and_then(|host| host.strip_suffix(']'))
                    .unwrap_or(host);
                if !host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
                {
                    return Err(ResolverConfigError::PlainHttp);
                }
                if config.ca_file.is_some() {
                    return Err(ResolverConfigError::CaFileForHttp);
                }
                if config.token_file.is_some() {
                    return Err(ResolverConfigError::TokenForHttp);
                }
                // This connector refuses any scheme but `http`.
                Transport::Plain(client(HttpConnector::new()))
            }
            _ => return Err(ResolverConfigError::NotAUrl),
        };
        // Read now as well, so a deployment with a bad token file does not start.
        if let Some(path) = &config.token_file {
            bearer(path).map_err(|fault| ResolverConfigError::TokenFile {
                path: path.clone(),
                fault,
            })?;
        }
        Ok(Self {
            currency,
            token_file: config.token_file.clone(),
            transport,
            signals: Arc::new(Signals::default()),
        })
    }

    /// Asks whether the question's turn is current: one `POST`, abandoned at the budget, its
    /// answer read up to the cap and checked to echo the question. Counted, with its latency.
    pub async fn ask(&self, question: &CurrencyQuestion) -> Result<Answer, ResolverFailure> {
        let started = Instant::now();
        let result = match tokio::time::timeout(BUDGET, self.exchange(question)).await {
            Err(_elapsed) => Err(ResolverFailure::Timeout),
            Ok(result) => result,
        };
        self.signals.record(result, started.elapsed());
        result
    }

    /// What has been counted so far.
    pub fn counts(&self) -> ResolverCounts {
        self.signals.counts()
    }

    /// Reads the token, if there is one, sends the question and reads a `200` answer, up to
    /// the cap.
    async fn exchange(&self, question: &CurrencyQuestion) -> Result<Answer, ResolverFailure> {
        // Read on every question, never kept: the file may have been rotated since the last.
        let authorization = match &self.token_file {
            Some(path) => Some(read_token(path.clone()).await?),
            None => None,
        };
        let request_id = request_id()?;
        let body = serde_json::to_vec(&WireQuestion {
            version: VERSION,
            question: CURRENCY,
            request_id: &request_id,
            sid: question.session.as_str(),
            eid: question.execution.as_str(),
            tid: question.turn.as_str(),
            epoch: question.epoch,
        })
        .map_err(|_| ResolverFailure::NotSent)?;
        let mut request = Request::post(self.currency.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CACHE_CONTROL, "no-store");
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| ResolverFailure::NotSent)?;
        let response = match &self.transport {
            Transport::Plain(client) => client.request(request).await,
            Transport::Tls(client) => client.request(request).await,
        }
        .map_err(|_| ResolverFailure::Unreachable)?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(ResolverFailure::Status(status.as_u16()));
        }
        let body = read(response).await?;
        parse(&body, question, &request_id)
    }
}

impl Resolver for HttpResolver {
    fn currency<'a>(&'a self, question: &'a CurrencyQuestion) -> BoxFuture<'a, CurrencyAnswer> {
        Box::pin(async move { currency_answer(self.ask(question).await) })
    }
}

/// A question as it is sent.
#[derive(Serialize)]
struct WireQuestion<'a> {
    version: &'a str,
    question: &'a str,
    request_id: &'a str,
    sid: &'a str,
    eid: &'a str,
    tid: &'a str,
    epoch: u64,
}

/// Only the version, read first: an answer of another version may have another shape.
#[derive(Deserialize)]
struct Versioned {
    version: String,
}

/// An answer as it must arrive: the question's members, and `answer`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAnswer {
    // Read by `Versioned` first; here only so that it is not an unknown member.
    #[serde(rename = "version")]
    _version: String,
    question: String,
    request_id: String,
    sid: String,
    eid: String,
    tid: String,
    epoch: u64,
    answer: Answer,
}

impl WireAnswer {
    /// Whether this answers the question asked under `request_id`.
    fn echoes(&self, question: &CurrencyQuestion, request_id: &str) -> bool {
        self.question == CURRENCY
            && self.request_id == request_id
            && self.sid == question.session.as_str()
            && self.eid == question.execution.as_str()
            && self.tid == question.turn.as_str()
            && self.epoch == question.epoch
    }
}

/// Reads the answer: its version, then its format, then whether it echoes the question.
fn parse(
    body: &[u8],
    question: &CurrencyQuestion,
    request_id: &str,
) -> Result<Answer, ResolverFailure> {
    let versioned: Versioned =
        serde_json::from_slice(body).map_err(|_| ResolverFailure::Malformed)?;
    if versioned.version != VERSION {
        return Err(ResolverFailure::UnknownVersion);
    }
    let answer: WireAnswer =
        serde_json::from_slice(body).map_err(|_| ResolverFailure::Malformed)?;
    if !answer.echoes(question, request_id) {
        return Err(ResolverFailure::OtherQuestion);
    }
    Ok(answer.answer)
}

/// A fresh request ID: 16 bytes of the operating system's randomness, in lowercase hex.
fn request_id() -> Result<String, ResolverFailure> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ResolverFailure::NotSent)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Reads the body, refusing as soon as it is known to be larger than the cap: from its
/// declared length if it has one, and otherwise as it arrives.
async fn read(response: Response<Incoming>) -> Result<Vec<u8>, ResolverFailure> {
    if declared_length(response.headers()).is_some_and(|length| length > MAX_ANSWER_BYTES as u64) {
        return Err(ResolverFailure::TooLarge);
    }
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ResolverFailure::BrokenOff)?;
        if let Ok(data) = frame.into_data() {
            if received.len() + data.len() > MAX_ANSWER_BYTES {
                return Err(ResolverFailure::TooLarge);
            }
            received.extend_from_slice(&data);
        }
    }
    Ok(received)
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

/// The legacy client, which follows no redirect and reads no proxy setting from the
/// environment. It may resend a question it knows never left on a pooled connection that had
/// closed, which is safe: a question changes nothing.
fn client<C>(connector: C) -> Client<C, Full<Bytes>>
where
    C: hyper_util::client::legacy::connect::Connect + Clone,
{
    Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .build(connector)
}

/// A client that speaks only TLS, offering only HTTP/1.1, and trusts only the CAs in
/// `ca_file`. Its crypto provider is ring, passed here; the process-wide default provider is
/// neither read nor set. The certificate is verified against the URL's host.
fn tls_client(
    ca_file: &Path,
) -> Result<Client<HttpsConnector<HttpConnector>, Full<Bytes>>, ResolverConfigError> {
    let roots = trusted(ca_file).map_err(|fault| ResolverConfigError::CaFile {
        path: ca_file.to_owned(),
        fault,
    })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ResolverConfigError::Tls)?
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
fn trusted(path: &Path) -> Result<RootCertStore, CaFault> {
    let bytes = std::fs::read(path).map_err(|_| CaFault::Unreadable)?;
    let mut roots = RootCertStore::empty();
    let mut sections = 0;
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(&bytes) {
        let (kind, der) = section.map_err(|_| CaFault::NotPem)?;
        sections += 1;
        if kind == SectionKind::Certificate {
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| CaFault::BadCertificate)?;
        }
    }
    if sections == 0 {
        return Err(CaFault::NotPem);
    }
    if roots.is_empty() {
        return Err(CaFault::NoCertificate);
    }
    Ok(roots)
}

/// The token in `path`, read on a thread of the runtime's blocking pool rather than the thread
/// asking. A read that blocks, such as of a FIFO no writer has opened or of a file system that
/// has stopped answering, then holds that pool thread and not a runtime thread, so the budget
/// still ends the question: it is unconfirmed at the budget, and the read is left to finish on
/// its own (#213).
async fn read_token(path: PathBuf) -> Result<HeaderValue, ResolverFailure> {
    tokio::task::spawn_blocking(move || bearer(&path))
        .await
        .map_err(|_| ResolverFailure::Token)?
        .map_err(|_| ResolverFailure::Token)
}

/// The token in `path` as an `Authorization: Bearer` value, marked sensitive. Whitespace around
/// it, such as a trailing newline, is trimmed. No more than one byte past the limit is read.
fn bearer(path: &Path) -> Result<HeaderValue, TokenFault> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_TOKEN_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| TokenFault::Unreadable)?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(TokenFault::TooLarge);
    }
    let text = String::from_utf8(bytes).map_err(|_| TokenFault::NotAToken)?;
    let token = text.trim();
    if token.is_empty() {
        return Err(TokenFault::Empty);
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(TokenFault::NotAToken);
    }
    let mut value =
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| TokenFault::NotAToken)?;
    value.set_sensitive(true);
    Ok(value)
}

/// What a resolver client counts. Every count is an atomic, so asking never waits to count.
#[derive(Debug, Default)]
struct Signals {
    answers: [AtomicU64; 5],
    failures: [AtomicU64; 10],
    latency: [AtomicU64; LATENCY_BUCKETS],
    latency_count: AtomicU64,
    /// The sum of every latency, in nanoseconds.
    latency_sum_nanos: AtomicU64,
}

impl Signals {
    fn record(&self, result: Result<Answer, ResolverFailure>, latency: Duration) {
        if let Err(failure) = result {
            self.failures[failure.index()].fetch_add(1, Ordering::Relaxed);
        }
        let answer = currency_answer(result);
        if let Some(index) = CurrencyAnswer::ALL.iter().position(|each| *each == answer) {
            self.answers[index].fetch_add(1, Ordering::Relaxed);
        }
        let nanos = latency.as_nanos();
        let bucket = LATENCY_BOUNDS_MS
            .iter()
            .position(|bound| nanos <= u128::from(*bound) * 1_000_000)
            .unwrap_or(LATENCY_BOUNDS_MS.len());
        self.latency[bucket].fetch_add(1, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_nanos
            .fetch_add(u64::try_from(nanos).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn counts(&self) -> ResolverCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ResolverCounts {
            answers: std::array::from_fn(|i| read(&self.answers[i])),
            failures: std::array::from_fn(|i| read(&self.failures[i])),
            latency_buckets: std::array::from_fn(|i| read(&self.latency[i])),
            latency_count: read(&self.latency_count),
            latency_sum: Duration::from_nanos(read(&self.latency_sum_nanos)),
        }
    }
}

/// A snapshot of a resolver client's counts, for the gateway to export. Each is read on its
/// own, so one taken while a question is being counted may count it in some and not others.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResolverCounts {
    /// How many questions had each answer, in the order of [`CurrencyAnswer::ALL`]; every
    /// failure is counted as unconfirmed.
    pub answers: [u64; 5],
    /// How many questions failed in each way, in the order of [`ResolverFailure::LABELS`].
    pub failures: [u64; 10],
    /// How many questions took how long, by the buckets of [`LATENCY_BOUNDS_MS`]:
    /// `latency_buckets[i]` counts those above the bound before it, if any, and at most
    /// `LATENCY_BOUNDS_MS[i]`; the last counts those above 30 s. Not cumulative. Every
    /// question is counted, failures included.
    pub latency_buckets: [u64; LATENCY_BUCKETS],
    /// How many latencies were counted: one for each question.
    pub latency_count: u64,
    /// Their sum.
    pub latency_sum: Duration,
}

impl ResolverCounts {
    /// How many questions had `answer`.
    pub fn answered(&self, answer: CurrencyAnswer) -> u64 {
        CurrencyAnswer::ALL
            .iter()
            .position(|each| *each == answer)
            .map_or(0, |index| self.answers[index])
    }

    /// How many questions failed under `label`, one of [`ResolverFailure::LABELS`].
    pub fn failed(&self, label: &str) -> u64 {
        ResolverFailure::LABELS
            .iter()
            .position(|each| *each == label)
            .map_or(0, |index| self.failures[index])
    }

    /// How many timed out: no whole answer within the budget.
    pub fn timeouts(&self) -> u64 {
        self.failed(ResolverFailure::Timeout.label())
    }
}
