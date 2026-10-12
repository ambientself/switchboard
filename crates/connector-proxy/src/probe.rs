//! The probe of a self-built server: does it check its caller? (Decision 0010, "Self-built
//! servers at registration"; decision 0013, section 9.)
//!
//! A probe sends the server three `tools/call` requests naming [`PROBE_TOOL`], a tool that does
//! not exist, so that none of them runs anything:
//!
//! 1. with no `Authorization` header;
//! 2. with `Authorization: Bearer not-a-token`, a malformed credential;
//! 3. with the [`ProbeCredential`]: a valid token for the server's audience for a subject
//!    outside the gateway's identities, or, where there is no issuer, a static dummy.
//!
//! Each call comes to one [`CallVerdict`]:
//!
//! - **Refused**, when the server answered the first two with `401` and a `WWW-Authenticate`
//!   challenge, or the third with `401` or `403`, and the answer carries no JSON-RPC response.
//! - **Open**, when the answer, whatever its status, carries a JSON-RPC result or error: the
//!   server dispatched the call to its tool handling, which shows it does not check its caller.
//! - **Not shown**, for anything else: a connection that failed, the deadline, an answer too
//!   large or broken off, a `401` with no challenge, any other status. A call whose refusal was
//!   not shown is never counted as refused.
//!
//! The server is open if any call is open, and refused only if all three are. Anything else is
//! not shown. The calls go where a tool call goes and are held to the same bounds: each is
//! abandoned at the call deadline and its answer discarded past the answer cap. The three are
//! sent together, so a probe takes no longer than one deadline. No redirect is followed and no
//! proxy is read from the environment. The foreign token is sent on the third call only.

use std::fmt;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::Uri;
use hyper::body::Bytes;
use hyper::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, WWW_AUTHENTICATE,
};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use serde_json::{Value, json};
use thiserror::Error;

use crate::connector::{DEFAULT_DEADLINE, DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION};
use crate::credentials::ProbeCredential;

/// The tool every probe call names. No server has it, so a call that is dispatched runs
/// nothing.
pub const PROBE_TOOL: &str = "switchboard_probe_no_such_tool";

/// The malformed credential the second call presents.
pub const MALFORMED_CREDENTIAL: &str = "not-a-token";

/// One of the probe's three calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeCall {
    /// No `Authorization` header.
    NoCredential,
    /// `Authorization: Bearer not-a-token`.
    MalformedCredential,
    /// The probe credential, a stranger's.
    ForeignToken,
}

impl ProbeCall {
    /// The three calls, in the order decision 0010 lists them.
    pub const ALL: [Self; 3] = [
        Self::NoCredential,
        Self::MalformedCredential,
        Self::ForeignToken,
    ];

    /// As logs and output name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCredential => "no_credential",
            Self::MalformedCredential => "malformed_credential",
            Self::ForeignToken => "foreign_token",
        }
    }

    /// Whether the server must refuse it with `401` and a challenge. Otherwise `401` or `403`
    /// will do.
    fn needs_challenge(self) -> bool {
        self != Self::ForeignToken
    }
}

impl fmt::Display for ProbeCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a call's refusal was not shown. No variant carries the server's text or a credential.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NotShown {
    /// The probe credential could not be read, so the third call was not sent.
    #[error("the probe credential could not be read, so nothing was sent: {0}")]
    Credential(String),
    /// The request could not be built. Nothing was sent.
    #[error("the request could not be built, so nothing was sent")]
    NotSent,
    /// The server could not be connected to, or the exchange failed before an answer began.
    #[error("the server could not be reached")]
    Unreachable,
    /// The server did not answer in full before the deadline.
    #[error("the server did not answer before the deadline")]
    TimedOut,
    /// The answer was larger than the cap, and was discarded unread.
    #[error("the answer was larger than the cap")]
    TooLarge,
    /// The answer stopped before it was complete.
    #[error("the answer stopped before it was complete")]
    BrokenOff,
    /// The server answered `401` with no `WWW-Authenticate` challenge.
    #[error("the server answered 401 with no WWW-Authenticate challenge")]
    NoChallenge,
    /// The server answered with a status that is not a refusal of this call, and no JSON-RPC
    /// response.
    #[error("the server answered with HTTP status {0} and no JSON-RPC response")]
    Status(u16),
}

/// What one call came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallVerdict {
    /// The server refused it before dispatching it.
    Refused,
    /// The server answered it with a JSON-RPC result or error: it was dispatched.
    Open,
    /// Neither was shown.
    NotShown(NotShown),
}

impl fmt::Display for CallVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => f.write_str("refused"),
            Self::Open => f.write_str("open: the call was dispatched"),
            Self::NotShown(reason) => write!(f, "not shown: {reason}"),
        }
    }
}

/// What the whole probe found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFinding {
    /// Every call was refused.
    Refused,
    /// At least one call was dispatched.
    Open,
    /// No call was dispatched, and at least one refusal was not shown.
    NotShown,
}

impl ProbeFinding {
    /// As a probe record and the logs name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Open => "open",
            Self::NotShown => "not_shown",
        }
    }
}

impl fmt::Display for ProbeFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The three calls' verdicts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    calls: Vec<(ProbeCall, CallVerdict)>,
}

impl ProbeReport {
    /// Each call and its verdict, in the order of [`ProbeCall::ALL`].
    pub fn calls(&self) -> &[(ProbeCall, CallVerdict)] {
        &self.calls
    }

    /// The calls the server dispatched.
    pub fn dispatched(&self) -> Vec<ProbeCall> {
        self.calls
            .iter()
            .filter(|(_, verdict)| *verdict == CallVerdict::Open)
            .map(|(call, _)| *call)
            .collect()
    }

    /// What the probe found: open if any call was dispatched, refused only if all three were
    /// refused, and not shown otherwise.
    pub fn finding(&self) -> ProbeFinding {
        if !self.dispatched().is_empty() {
            ProbeFinding::Open
        } else if self.calls.len() == ProbeCall::ALL.len()
            && self
                .calls
                .iter()
                .all(|(_, verdict)| *verdict == CallVerdict::Refused)
        {
            ProbeFinding::Refused
        } else {
            ProbeFinding::NotShown
        }
    }
}

/// The bounds on each probe call: a call's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeBounds {
    /// How long a call may take, from sending it to the last byte of its answer.
    pub deadline: Duration,
    /// The largest answer read, in bytes of HTTP body.
    pub max_response_bytes: usize,
}

impl Default for ProbeBounds {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Why a probe could not begin.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ProbeError {
    /// The URL is not an `http://` URL with a host, or it carries a user name or password.
    #[error("the server's URL must be http:// with a host and no user information: {0}")]
    BadUrl(String),
    /// A bound is zero.
    #[error("the probe's deadline and answer cap must each be more than zero")]
    ZeroBound,
}

/// Probes the server at `url`, an `http://` URL, with its call bounds, presenting `foreign` on
/// the third call (decision 0010, "Self-built servers at registration").
///
/// It sends three `tools/call` requests naming [`PROBE_TOOL`], a tool that does not exist:
/// with no `Authorization`, with `Bearer not-a-token` ([`MALFORMED_CREDENTIAL`]), and with
/// `foreign`. A call is refused when the first two are answered `401` with a
/// `WWW-Authenticate` challenge, or the third `401` or `403`, with no JSON-RPC response in the
/// answer. It is open when the answer, whatever its status, carries a JSON-RPC result or error.
/// Anything else, a connection that failed or a timeout included, is not shown, and is never
/// counted as refused ([`ProbeReport::finding`]). The three are sent together, each bounded as
/// a call is; no redirect is followed and no proxy is read from the environment.
pub async fn probe(
    url: &str,
    bounds: ProbeBounds,
    foreign: &ProbeCredential,
) -> Result<ProbeReport, ProbeError> {
    let endpoint =
        crate::connector::parse_endpoint(url).ok_or_else(|| ProbeError::BadUrl(url.to_owned()))?;
    if bounds.deadline.is_zero() || bounds.max_response_bytes == 0 {
        return Err(ProbeError::ZeroBound);
    }
    Ok(run(&crate::connector::client(), &endpoint, bounds, foreign).await)
}

/// The three calls to `endpoint`, sent together on `client`.
pub(crate) async fn run(
    client: &Client<HttpConnector, Full<Bytes>>,
    endpoint: &Uri,
    bounds: ProbeBounds,
    foreign: &ProbeCredential,
) -> ProbeReport {
    // The stranger's token, read from its file now, for the third call alone.
    let stranger = || {
        foreign
            .secret()
            .map(|secret| secret.bearer().to_owned())
            .map_err(NotShown::Credential)
    };
    let malformed = || Ok(MALFORMED_CREDENTIAL.to_owned());
    let (none, malformed, stranger) = tokio::join!(
        call(client, endpoint, bounds, ProbeCall::NoCredential, None),
        call(
            client,
            endpoint,
            bounds,
            ProbeCall::MalformedCredential,
            Some(malformed())
        ),
        call(
            client,
            endpoint,
            bounds,
            ProbeCall::ForeignToken,
            Some(stranger())
        ),
    );
    ProbeReport {
        calls: vec![
            (ProbeCall::NoCredential, none),
            (ProbeCall::MalformedCredential, malformed),
            (ProbeCall::ForeignToken, stranger),
        ],
    }
}

/// One call, with `bearer` as its credential if it has one.
async fn call(
    client: &Client<HttpConnector, Full<Bytes>>,
    endpoint: &Uri,
    bounds: ProbeBounds,
    which: ProbeCall,
    bearer: Option<Result<String, NotShown>>,
) -> CallVerdict {
    let bearer = match bearer.transpose() {
        Ok(bearer) => bearer,
        Err(not_sent) => return CallVerdict::NotShown(not_sent),
    };
    let Some(request) = request(endpoint, which, bearer.as_deref()) else {
        return CallVerdict::NotShown(NotShown::NotSent);
    };
    match tokio::time::timeout(bounds.deadline, exchange(client, request, bounds)).await {
        Err(_elapsed) => CallVerdict::NotShown(NotShown::TimedOut),
        Ok(Err(not_shown)) => CallVerdict::NotShown(not_shown),
        Ok(Ok(answer)) => judge(which, &answer),
    }
}

/// The request for call `which`, with `bearer` as its credential if it has one.
fn request(endpoint: &Uri, which: ProbeCall, bearer: Option<&str>) -> Option<Request<Full<Bytes>>> {
    let id = match which {
        ProbeCall::NoCredential => 1,
        ProbeCall::MalformedCredential => 2,
        ProbeCall::ForeignToken => 3,
    };
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": PROBE_TOOL, "arguments": {}},
    });
    let mut request = Request::post(endpoint.clone())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .body(Full::new(Bytes::from(body.to_string())))
        .ok()?;
    if let Some(bearer) = bearer {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer}")).ok()?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, authorization);
    }
    Some(request)
}

/// What a call's answer showed: its status, whether it carried a challenge, and its body.
struct Answer {
    status: u16,
    challenged: bool,
    body: Vec<u8>,
}

/// Sends the request and reads the answer, whatever its status, up to the cap.
async fn exchange(
    client: &Client<HttpConnector, Full<Bytes>>,
    request: Request<Full<Bytes>>,
    bounds: ProbeBounds,
) -> Result<Answer, NotShown> {
    let response = client
        .request(request)
        .await
        .map_err(|_| NotShown::Unreachable)?;
    let status = response.status().as_u16();
    let challenged = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .any(|challenge| !challenge.as_bytes().iter().all(u8::is_ascii_whitespace));
    let cap = bounds.max_response_bytes;
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if declared.is_some_and(|declared| declared > cap as u64) {
        return Err(NotShown::TooLarge);
    }
    let mut body = response.into_body();
    let mut read = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| NotShown::BrokenOff)?;
        if let Ok(data) = frame.into_data() {
            if read.len() + data.len() > cap {
                return Err(NotShown::TooLarge);
            }
            read.extend_from_slice(&data);
        }
    }
    Ok(Answer {
        status,
        challenged,
        body: read,
    })
}

/// The verdict on call `which` from its answer.
fn judge(which: ProbeCall, answer: &Answer) -> CallVerdict {
    if carries_rpc_response(&answer.body) {
        return CallVerdict::Open;
    }
    match answer.status {
        401 if which.needs_challenge() && !answer.challenged => {
            CallVerdict::NotShown(NotShown::NoChallenge)
        }
        401 => CallVerdict::Refused,
        403 if !which.needs_challenge() => CallVerdict::Refused,
        other => CallVerdict::NotShown(NotShown::Status(other)),
    }
}

/// Whether `body` carries a JSON-RPC response with a result or an error: as one JSON message,
/// a batch of them, or the `data` of an event in a stream.
fn carries_rpc_response(body: &[u8]) -> bool {
    if let Ok(message) = serde_json::from_slice::<Value>(body) {
        return is_rpc_response(&message);
    }
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .any(|message| is_rpc_response(&message))
}

/// A JSON-RPC response object, or a batch holding one: a `result` or an `error`, beside the
/// `jsonrpc` version or an `id`. An error body that is not JSON-RPC, such as
/// `{"error": "unauthorized"}`, is not one.
fn is_rpc_response(message: &Value) -> bool {
    match message {
        Value::Array(batch) => batch.iter().any(is_rpc_response),
        Value::Object(fields) => {
            (fields.contains_key("result") || fields.contains_key("error"))
                && (fields.contains_key("jsonrpc") || fields.contains_key("id"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, challenged: bool, body: &str) -> Answer {
        Answer {
            status,
            challenged,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_json_rpc_body_is_open_in_any_shape_and_an_oauth_error_is_not() {
        for body in [
            r#"{"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "no tool"}}"#,
            r#"{"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": true}}"#,
            r#"{"id": 1, "result": {}}"#,
            r#"[{"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "x"}}]"#,
            "event: message\ndata: {\"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {}}\n\n",
        ] {
            assert!(carries_rpc_response(body.as_bytes()), "{body}");
        }
        for body in [
            r#"{"error": "unauthorized"}"#,
            r#"{"error": "invalid_token", "error_description": "expired"}"#,
            "",
            "Unauthorized",
            r#"{"jsonrpc": "2.0", "id": 1, "method": "ping"}"#,
        ] {
            assert!(!carries_rpc_response(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn a_403_refuses_only_the_foreign_token() {
        let forbidden = answer(403, false, "");
        assert_eq!(
            judge(ProbeCall::ForeignToken, &forbidden),
            CallVerdict::Refused
        );
        for call in [ProbeCall::NoCredential, ProbeCall::MalformedCredential] {
            assert_eq!(
                judge(call, &forbidden),
                CallVerdict::NotShown(NotShown::Status(403))
            );
        }
        assert_eq!(
            judge(ProbeCall::ForeignToken, &answer(401, false, "")),
            CallVerdict::Refused,
            "the third call needs no challenge"
        );
    }

    #[test]
    fn the_finding_is_refused_only_when_all_three_are() {
        let report = |verdicts: [CallVerdict; 3]| ProbeReport {
            calls: ProbeCall::ALL.into_iter().zip(verdicts).collect(),
        };
        let refused = || CallVerdict::Refused;
        let unshown = || CallVerdict::NotShown(NotShown::Unreachable);
        assert_eq!(
            report([refused(), refused(), refused()]).finding(),
            ProbeFinding::Refused
        );
        assert_eq!(
            report([refused(), refused(), unshown()]).finding(),
            ProbeFinding::NotShown
        );
        let open = report([refused(), unshown(), CallVerdict::Open]);
        assert_eq!(open.finding(), ProbeFinding::Open);
        assert_eq!(open.dispatched(), [ProbeCall::ForeignToken]);
    }
}
