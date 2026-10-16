//! The reach check's call (decision 0011, section 4; decision 0013, section 5, step 3).
//!
//! A proxied entry's reach is a fact outside this repository: an administrator can widen what
//! its credential reaches without touching an approval. So each entry with a `reach_check` in
//! the registry is checked on its drift schedule ([`crate::drift`]) by a call naming a canary
//! resource outside its reach, which the server must refuse.
//!
//! **The call is a gateway call.** The registry holds no vendor credential. [`ReachCaller`]
//! sends the entry's `reach_check` as `tools/call` to this replica's own listener
//! ([`ReachSettings::url`], a surface such as `/mcp/registry-reach`), with the `Host` the
//! listener serves ([`ReachSettings::host`]) and the bearer token of the registry's own
//! workload identity, read from [`ReachSettings::token_file`] on every call. That principal is
//! admitted only to a surface restricted to its own subject. So the check is decided, audited
//! and run with the entry's credential, like any other call, and its row names the registry's
//! principal. It never attempts a write: the registry's loader requires every proxied tool to
//! be `read`.
//!
//! **What the answer means** ([`Verdict`]):
//!
//! - **Held**: a tool result marked `isError` whose text is exactly
//!   [`connector_proxy::outcome::UPSTREAM_REFUSED`]: the server answered `403`, refusing the
//!   canary as outside what the entry's credential may do.
//! - **Mismatch**: a successful tool result. The server answered the canary, so the reach is
//!   wider than recorded.
//! - **Failed**: anything else: a denial by the gateway, an audit failure, an identity failure,
//!   another error, a token that could not be read, an answer that is not one JSON-RPC
//!   response, or none within the entry's call deadline plus [`REACH_ALLOWANCE`]. A failed
//!   check shows nothing about the reach.
//!
//! The token is never logged, and only the verdict and its reason leave this module.
//!
//! **The vendor report** (decision 0011, section 4; #193) is the check's second kind, for a
//! built-in entry whose vendor reports what its credential reaches, as GitHub lists an
//! installation's repositories. [`ReachCaller::report`] sends the entry's `reach_report` tool, a
//! reach-report entry's, with no arguments, the same way, through the same listener as the same
//! principal, so it too is decided and audited like any call, and reads the repositories its
//! result lists ([`Reported`]). [`compare`] compares them with the entry's recorded reach both
//! ways: a repository reported and not recorded, or recorded and not reported, is a mismatch. A
//! result that is an error, or that holds no list of repositories, and anything that fails the
//! canary's call, is a failed check ([`Reported::Failed`]), which shows nothing about the reach.
//! What the credential permits, its permission set, is checked on every token, not by the
//! report: the key custodian refuses a token GitHub issued with any permission beyond those
//! asked for.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use connector_proxy::outcome::UPSTREAM_REFUSED;
use gateway_core::ToolName;
use gateway_mcp::AUDIT_ROW_META;
use gateway_registry::ReachCheck;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST};
use http::{HeaderValue, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::deployment::MAX_SERVER_RESULT_BYTES;

/// How long past the entry's call deadline the reach check waits for the gateway's answer:
/// the gateway's own work on the call, its token check, decision and audit row, comes before
/// and after the deadline that holds the call to the server.
pub const REACH_ALLOWANCE: Duration = Duration::from_secs(5);

/// The room the reach check reads past what the server's result can become. The gateway's
/// answer to the canary is the server's result put in the gateway's own JSON-RPC envelope with
/// `_meta` naming its audit row: a few hundred bytes more. 64 KiB covers that many times over.
pub const REACH_ANSWER_HEADROOM: usize = 64 * 1024;

/// How many times longer the gateway's writing of a server's result can be than the bytes the
/// server sent: 8 (#175).
///
/// The connector holds the server's answer to its `max_result_bytes`, then parses it, and the
/// gateway writes the result's `content` and `structuredContent` out again with `serde_json`,
/// which this workspace builds without `arbitrary_precision`. Those are two separate parts of
/// the answer, and the rest of it is dropped, so it is enough that no part of the JSON grows by
/// more than 8 times:
///
/// - A number inside `u64` or `i64` with neither a fraction nor an exponent, other than `-0`,
///   is kept as an integer and written as sent: JSON allows no leading zero or plus sign.
/// - Any other number is parsed as an `f64` and written in its shortest form, at most 24
///   bytes: a sign, 17 digits, a point, and either a signed exponent of up to three digits
///   (`-2.2250738585072014e-308`) or up to four zeros after `0.`
///   (`-0.000012345678901234567`). Every such number is at least 3 bytes as sent (`1e9`,
///   `0.5`, an integer past `u64`), but `-0`, written `-0.0`, so it grows at most 8 times:
///   `1e9` becomes `1000000000.0`.
/// - A string is written with only `"`, `\` and control characters escaped, each of which the
///   server had to escape too, in as many bytes or more; any other escape it sent is written as
///   the character itself. So a string never grows.
/// - Whitespace is dropped, a repeated key is kept once, and the rest of the structure is
///   written as sent.
pub const REACH_ANSWER_EXPANSION: usize = 8;

/// The largest answer the reach check reads: what the largest `max_result_bytes` a server may
/// have ([`MAX_SERVER_RESULT_BYTES`]) can become when the gateway writes it out again
/// ([`REACH_ANSWER_EXPANSION`]), plus [`REACH_ANSWER_HEADROOM`]. So a widened canary answered
/// near its server's cap is read and judged a mismatch, not failed as too large, whatever
/// numbers it holds. The reader holds only this one local answer, so 8 MiB is acceptable. A
/// refusal is a few hundred bytes; a larger answer than this is a failed check, never a held
/// one.
pub const MAX_REACH_ANSWER_BYTES: usize =
    REACH_ANSWER_EXPANSION * MAX_SERVER_RESULT_BYTES + REACH_ANSWER_HEADROOM;

/// The MCP revision the reach check speaks: the one every caller of the gateway may.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Where the reach check calls, and as whom: the deployment file's `[drift] reach_*` fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachSettings {
    /// The file holding the registry's workload token, read on every check.
    pub token_file: PathBuf,
    /// The replica's own listener and the surface the registry is admitted to, such as
    /// `http://127.0.0.1:8080/mcp/registry-reach`: plain `http` with a host.
    pub url: Uri,
    /// The `Host` the call carries: one of `http.allowed_hosts`.
    pub host: String,
}

/// Why the `[drift] reach_*` fields were refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReachSettingsError {
    /// Some of the three fields are given and some are not.
    #[error(
        "`drift.reach_token_file`, `drift.reach_url` and `drift.reach_host` are given together \
         or not at all"
    )]
    Partial,
    /// The URL is not plain `http` with a host and a path.
    #[error(
        "`drift.reach_url` is `{0}`; it must be an http URL of this gateway's own listener, such as http://127.0.0.1:8080/mcp/registry-reach"
    )]
    NotHttp(String),
    /// The host is not one the listener serves.
    #[error("`drift.reach_host` is `{0}`, which is not one of `http.allowed_hosts`")]
    HostNotAllowed(String),
}

impl ReachSettings {
    /// The settings the three fields give, from the deployment file's directory `base`; `None`
    /// when none is given. Refuses some but not all, a URL that is not plain `http` with a
    /// host, and a host the listener does not serve.
    pub fn from_fields(
        token_file: Option<&Path>,
        url: Option<&str>,
        host: Option<&str>,
        allowed_hosts: &std::collections::BTreeSet<String>,
        base: &Path,
    ) -> Result<Option<Self>, ReachSettingsError> {
        let (token_file, url, host) = match (token_file, url, host) {
            (None, None, None) => return Ok(None),
            (Some(token_file), Some(url), Some(host)) => (token_file, url, host),
            _ => return Err(ReachSettingsError::Partial),
        };
        let parsed: Uri = url
            .parse()
            .map_err(|_| ReachSettingsError::NotHttp(url.to_owned()))?;
        let acceptable = parsed.scheme_str() == Some("http")
            && parsed.authority().is_some_and(|authority| {
                !authority.host().is_empty() && !authority.as_str().contains('@')
            })
            && parsed.path().len() > 1;
        if !acceptable {
            return Err(ReachSettingsError::NotHttp(url.to_owned()));
        }
        if !allowed_hosts.contains(host) {
            return Err(ReachSettingsError::HostNotAllowed(host.to_owned()));
        }
        Ok(Some(Self {
            token_file: base.join(token_file),
            url: parsed,
            host: host.to_owned(),
        }))
    }
}

/// What one reach check came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The server refused the canary: the reach holds.
    Held {
        /// The audit row the gateway wrote for the call, if its answer named one.
        row: Option<String>,
    },
    /// The server answered the canary: the reach is wider than recorded.
    Mismatch {
        /// The audit row the gateway wrote for the call, if its answer named one.
        row: Option<String>,
    },
    /// The check showed nothing about the reach, for this reason.
    Failed(String),
}

/// What one vendor report came to (see the [module documentation](self)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// The report's tool answered with the repositories it lists.
    Listed {
        /// The repositories, each by its full name, `owner/name`.
        repositories: BTreeSet<String>,
        /// The audit row the gateway wrote for the call, if its answer named one.
        row: Option<String>,
    },
    /// The report could not be read, for this reason: it shows nothing about the reach.
    Failed(String),
}

/// How a vendor's report differs from an entry's recorded reach.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Difference {
    /// The repositories the report lists and the reach does not hold: reached, and never
    /// approved.
    pub added: BTreeSet<String>,
    /// The repositories the reach holds and the report does not list: the credential no longer
    /// reaches what was approved, so the approval no longer describes it.
    pub dropped: BTreeSet<String>,
}

impl Difference {
    /// Whether the report and the reach agree.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.dropped.is_empty()
    }
}

/// How `reported` differs from `recorded`, both ways.
pub fn compare(recorded: &BTreeSet<String>, reported: &BTreeSet<String>) -> Difference {
    Difference {
        added: reported.difference(recorded).cloned().collect(),
        dropped: recorded.difference(reported).cloned().collect(),
    }
}

/// Makes the reach check's calls to this replica's own listener. See the [module
/// documentation](self).
pub struct ReachCaller {
    settings: ReachSettings,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl std::fmt::Debug for ReachCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReachCaller")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl ReachCaller {
    /// A caller with `settings`. It follows no redirect and reads no proxy setting from the
    /// environment, so the registry's token goes to the listener named or nowhere.
    pub fn new(settings: ReachSettings) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build_http();
        Self { settings, client }
    }

    /// Where it calls, and as whom.
    pub fn settings(&self) -> &ReachSettings {
        &self.settings
    }

    /// Sends `check` as `tools/call` through the listener, and judges the answer. Gives up
    /// `deadline` (the entry's call deadline) plus [`REACH_ALLOWANCE`] after it starts.
    pub async fn call(&self, check: &ReachCheck, deadline: Duration) -> Verdict {
        match self.send(&check.tool, &check.arguments, deadline).await {
            Ok(body) => judge(&body),
            Err(reason) => Verdict::Failed(reason),
        }
    }

    /// Sends the reach report's `tool`, with no arguments, as `tools/call` through the
    /// listener, and reads the repositories its result lists. Gives up `deadline` (the call
    /// deadline of the report tool's connector) plus [`REACH_ALLOWANCE`] after it starts.
    pub async fn report(&self, tool: &ToolName, deadline: Duration) -> Reported {
        match self.send(tool, &Map::new(), deadline).await {
            Ok(body) => judge_report(&body),
            Err(reason) => Reported::Failed(reason),
        }
    }

    /// Sends `tool` with `arguments` through the listener as the registry, and reads the
    /// answer, or says why there is none to judge.
    async fn send(
        &self,
        tool: &ToolName,
        arguments: &Map<String, Value>,
        deadline: Duration,
    ) -> Result<Vec<u8>, String> {
        let token = match std::fs::read_to_string(&self.settings.token_file) {
            Ok(token) if !token.trim().is_empty() => token.trim().to_owned(),
            Ok(_) => return Err("the registry's token file is empty".to_owned()),
            Err(error) => {
                return Err(format!("could not read the registry's token file: {error}"));
            }
        };
        let Some(request) = self.request(tool, arguments, &token) else {
            return Err("could not build the request".to_owned());
        };
        match tokio::time::timeout(deadline + REACH_ALLOWANCE, self.exchange(request)).await {
            Ok(answer) => answer,
            Err(_elapsed) => Err(format!(
                "no answer within the call deadline plus {} s",
                REACH_ALLOWANCE.as_secs()
            )),
        }
    }

    fn request(
        &self,
        tool: &ToolName,
        arguments: &Map<String, Value>,
        token: &str,
    ) -> Option<Request<Full<Bytes>>> {
        let mut bearer = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
        bearer.set_sensitive(true);
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool.as_str(), "arguments": arguments},
        });
        let mut request = Request::post(self.settings.url.clone())
            .header(HOST, self.settings.host.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .body(Full::new(Bytes::from(body.to_string())))
            .ok()?;
        request.headers_mut().insert(AUTHORIZATION, bearer);
        Some(request)
    }

    /// Sends the request and reads a `200` answer's body, up to [`MAX_REACH_ANSWER_BYTES`].
    async fn exchange(&self, request: Request<Full<Bytes>>) -> Result<Vec<u8>, String> {
        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| format!("could not reach the gateway's listener: {error}"))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => {
                return Err("the gateway did not accept the registry's token (401)".to_owned());
            }
            other => {
                return Err(format!(
                    "the gateway answered with HTTP status {}",
                    other.as_u16()
                ));
            }
        }
        let mut body = response.into_body();
        let mut read = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "the answer was broken off".to_owned())?;
            if let Ok(data) = frame.into_data() {
                if read.len() + data.len() > MAX_REACH_ANSWER_BYTES {
                    return Err("the answer was larger than the reach check reads".to_owned());
                }
                read.extend_from_slice(&data);
            }
        }
        Ok(read)
    }
}

/// The tool result in the gateway's answer `body`, and the audit row its `_meta` names, or why
/// there is none.
fn tool_result(body: &[u8]) -> Result<(Map<String, Value>, Option<String>), String> {
    let Ok(Value::Object(mut answer)) = serde_json::from_slice::<Value>(body) else {
        return Err("the answer is not a JSON-RPC response".to_owned());
    };
    if let Some(error) = answer.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        return Err(format!(
            "the gateway refused the call: {}",
            bounded(message)
        ));
    }
    let Some(Value::Object(result)) = answer.remove("result") else {
        return Err("the answer has neither a result nor an error".to_owned());
    };
    let row = result
        .get("_meta")
        .and_then(|meta| meta.get(AUDIT_ROW_META))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((result, row))
}

/// The text blocks of a tool `result`.
fn texts(result: &Map<String, Value>) -> Vec<&str> {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// The verdict of the gateway's answer `body` to the reach check's call.
fn judge(body: &[u8]) -> Verdict {
    let (result, row) = match tool_result(body) {
        Ok(result) => result,
        Err(reason) => return Verdict::Failed(reason),
    };
    let texts = texts(&result);
    match result.get("isError") {
        Some(Value::Bool(false)) => Verdict::Mismatch { row },
        Some(Value::Bool(true)) if texts == [UPSTREAM_REFUSED] => Verdict::Held { row },
        Some(Value::Bool(true)) => Verdict::Failed(format!(
            "the call failed for another reason: {}",
            bounded(&texts.join(" "))
        )),
        _ => Verdict::Failed("the result is not marked as an error or not".to_owned()),
    }
}

/// What the gateway's answer `body` to the reach report's call reports: the repositories in its
/// result's `structuredContent.repositories`, each a full name, or why it reports nothing.
fn judge_report(body: &[u8]) -> Reported {
    let (result, row) = match tool_result(body) {
        Ok(result) => result,
        Err(reason) => return Reported::Failed(reason),
    };
    match result.get("isError") {
        Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Reported::Failed(format!(
                "the report could not be read: {}",
                bounded(&texts(&result).join(" "))
            ));
        }
        _ => {
            return Reported::Failed("the result is not marked as an error or not".to_owned());
        }
    }
    let listed = result
        .get("structuredContent")
        .and_then(|content| content.get("repositories"))
        .and_then(Value::as_array)
        .and_then(|repositories| {
            repositories
                .iter()
                .map(|repository| repository.as_str().map(str::to_owned))
                .collect::<Option<BTreeSet<String>>>()
        });
    match listed {
        Some(repositories) => Reported::Listed { repositories, row },
        None => Reported::Failed("the result holds no list of repositories".to_owned()),
    }
}

/// `text` cut to 200 characters, for a log line.
fn bounded(text: &str) -> String {
    text.chars()
        .take(200)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The settings for `url` and `host`, with `gateway` the one host served.
    fn settings(url: &str, host: &str) -> Result<Option<ReachSettings>, ReachSettingsError> {
        ReachSettings::from_fields(
            Some(Path::new("token")),
            Some(url),
            Some(host),
            &["gateway".to_owned()].into(),
            Path::new("/etc/switchboard"),
        )
    }

    #[test]
    fn the_three_fields_are_given_together_or_not_at_all() {
        let hosts = ["gateway".to_owned()].into();
        let base = Path::new("/etc");
        assert_eq!(
            ReachSettings::from_fields(None, None, None, &hosts, base),
            Ok(None)
        );
        for (file, url, host) in [
            (Some(Path::new("t")), None, None),
            (None, Some("http://127.0.0.1:8080/mcp/r"), Some("gateway")),
            (
                Some(Path::new("t")),
                Some("http://127.0.0.1:8080/mcp/r"),
                None,
            ),
        ] {
            assert_eq!(
                ReachSettings::from_fields(file, url, host, &hosts, base),
                Err(ReachSettingsError::Partial)
            );
        }
        let given = settings("http://127.0.0.1:8080/mcp/registry-reach", "gateway")
            .unwrap()
            .unwrap();
        assert_eq!(given.token_file, Path::new("/etc/switchboard/token"));
        assert_eq!(given.host, "gateway");
    }

    #[test]
    fn the_url_is_plain_http_with_a_host_and_a_path_and_the_host_is_served() {
        for url in [
            "https://127.0.0.1:8080/mcp/registry-reach",
            "http://127.0.0.1:8080",
            "http://user@127.0.0.1:8080/mcp/registry-reach",
            "/mcp/registry-reach",
            "not a url",
        ] {
            assert_eq!(
                settings(url, "gateway"),
                Err(ReachSettingsError::NotHttp(url.to_owned())),
                "{url}"
            );
        }
        assert_eq!(
            settings("http://127.0.0.1:8080/mcp/registry-reach", "localhost"),
            Err(ReachSettingsError::HostNotAllowed("localhost".to_owned()))
        );
    }

    /// The argument of [`REACH_ANSWER_EXPANSION`], number by number: written again, a number
    /// is at most 24 bytes and at most 8 times as long as sent, and a string never grows.
    #[test]
    fn a_number_written_again_is_at_most_24_bytes_and_8_times_as_long() {
        let written = |sent: &str| serde_json::from_str::<Value>(sent).unwrap().to_string();
        assert_eq!(written("1e9"), "1000000000.0");
        assert_eq!(written("1e15"), "1000000000000000.0");
        assert_eq!(
            written("-2.2250738585072014e-308"),
            "-2.2250738585072014e-308"
        );
        let small = written("-1.2345678901234567e-5");
        assert!(small.starts_with("-0.00001234567890123456"), "{small}");
        assert_eq!(small.len(), 24, "{small}");
        assert_eq!(written("18446744073709551615"), "18446744073709551615");
        assert_eq!(written("18446744073709551616"), "1.8446744073709552e+19");
        assert_eq!(written("-0"), "-0.0");
        let mut longest = 0;
        for exponent in -330..330 {
            for mantissa in ["1", "9", "-1", "1.2345678901234567", "-9.8765432109876543"] {
                let sent = format!("{mantissa}e{exponent}");
                let Ok(value) = serde_json::from_str::<Value>(&sent) else {
                    continue;
                };
                let again = value.to_string();
                assert!(again.len() <= 24, "{sent} is written as {again}");
                assert!(
                    again.len() <= REACH_ANSWER_EXPANSION * sent.len(),
                    "{sent} is written as {again}"
                );
                longest = longest.max(again.len());
            }
        }
        assert_eq!(longest, 24);
        for sent in [r#""a\/bé\u0001\b""#, r#""\"\\\n""#] {
            assert!(written(sent).len() <= sent.len(), "{sent}");
        }
    }

    #[test]
    fn only_the_upstream_refusal_holds_and_only_a_successful_result_is_a_mismatch() {
        let answer =
            |result: Value| json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
        let refused = answer(json!({
            "content": [{"type": "text", "text": UPSTREAM_REFUSED}],
            "isError": true,
            "_meta": {AUDIT_ROW_META: "row-1"},
        }));
        assert_eq!(
            judge(refused.as_bytes()),
            Verdict::Held {
                row: Some("row-1".to_owned())
            }
        );
        let answered =
            answer(json!({"content": [{"type": "text", "text": "plan"}], "isError": false}));
        assert_eq!(judge(answered.as_bytes()), Verdict::Mismatch { row: None });
        for failed in [
            answer(
                json!({"content": [{"type": "text", "text": "This tool's server answered with HTTP status 500."}], "isError": true}),
            ),
            answer(
                json!({"content": [{"type": "text", "text": UPSTREAM_REFUSED}, {"type": "text", "text": "and more"}], "isError": true}),
            ),
            answer(json!({"content": [{"type": "text", "text": UPSTREAM_REFUSED}]})),
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "denied"}})
                .to_string(),
            json!({"jsonrpc": "2.0", "id": 1}).to_string(),
            "not json".to_owned(),
        ] {
            assert!(
                matches!(judge(failed.as_bytes()), Verdict::Failed(_)),
                "{failed}"
            );
        }
    }

    #[test]
    fn a_report_is_compared_with_the_reach_both_ways() {
        let set = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let recorded = set(&["o/atlas", "o/borealis"]);
        assert!(compare(&recorded, &set(&["o/atlas", "o/borealis"])).is_empty());
        assert_eq!(
            compare(&recorded, &set(&["o/atlas", "o/borealis", "o/cosmos"])),
            Difference {
                added: set(&["o/cosmos"]),
                dropped: BTreeSet::new(),
            }
        );
        assert_eq!(
            compare(&recorded, &set(&["o/atlas"])),
            Difference {
                added: BTreeSet::new(),
                dropped: set(&["o/borealis"]),
            }
        );
        assert_eq!(
            compare(&recorded, &set(&["o/atlas", "o/cosmos"])),
            Difference {
                added: set(&["o/cosmos"]),
                dropped: set(&["o/borealis"]),
            }
        );
    }

    #[test]
    fn only_a_successful_result_listing_repositories_is_a_report() {
        let answer =
            |result: Value| json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
        let listed = answer(json!({
            "content": [{"type": "text", "text": "{}"}],
            "structuredContent": {"repositories": ["o/b", "o/a"], "totalCount": 2},
            "isError": false,
            "_meta": {AUDIT_ROW_META: "row-2"},
        }));
        assert_eq!(
            judge_report(listed.as_bytes()),
            Reported::Listed {
                repositories: ["o/a".to_owned(), "o/b".to_owned()].into(),
                row: Some("row-2".to_owned()),
            }
        );
        for failed in [
            answer(
                json!({"content": [{"type": "text", "text": "GitHub answered HTTP 500"}], "isError": true}),
            ),
            answer(json!({"structuredContent": {"repositories": ["o/a"]}, "isError": true})),
            answer(json!({"structuredContent": {"repositories": ["o/a", 7]}, "isError": false})),
            answer(json!({"structuredContent": {}, "isError": false})),
            answer(json!({"structuredContent": {"repositories": ["o/a"]}})),
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "denied"}})
                .to_string(),
            "not json".to_owned(),
        ] {
            assert!(
                matches!(judge_report(failed.as_bytes()), Reported::Failed(_)),
                "{failed}"
            );
        }
    }
}
