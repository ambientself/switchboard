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

use std::path::{Path, PathBuf};
use std::time::Duration;

use connector_proxy::outcome::UPSTREAM_REFUSED;
use gateway_mcp::AUDIT_ROW_META;
use gateway_registry::ReachCheck;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST};
use http::{HeaderValue, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde_json::{Value, json};
use thiserror::Error;

use crate::deployment::MAX_SERVER_RESULT_BYTES;

/// How long past the entry's call deadline the reach check waits for the gateway's answer:
/// the gateway's own work on the call, its token check, decision and audit row, comes before
/// and after the deadline that holds the call to the server.
pub const REACH_ALLOWANCE: Duration = Duration::from_secs(5);

/// The room the reach check reads past the largest answer a server may be allowed. The
/// gateway's answer to the canary is the server's result, which the connector holds to the
/// server's `max_result_bytes`, put in the gateway's own JSON-RPC envelope with `_meta` naming
/// its audit row: a few hundred bytes more. 64 KiB covers that many times over.
pub const REACH_ANSWER_HEADROOM: usize = 64 * 1024;

/// The largest answer the reach check reads: the largest `max_result_bytes` a server may have
/// ([`MAX_SERVER_RESULT_BYTES`]) plus [`REACH_ANSWER_HEADROOM`]. So a widened canary answered
/// near its server's cap is read and judged a mismatch, not failed as too large. A refusal is a
/// few hundred bytes; a larger answer than this is a failed check, never a held one.
pub const MAX_REACH_ANSWER_BYTES: usize = MAX_SERVER_RESULT_BYTES + REACH_ANSWER_HEADROOM;

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
        let token = match std::fs::read_to_string(&self.settings.token_file) {
            Ok(token) if !token.trim().is_empty() => token.trim().to_owned(),
            Ok(_) => return Verdict::Failed("the registry's token file is empty".to_owned()),
            Err(error) => {
                return Verdict::Failed(format!(
                    "could not read the registry's token file: {error}"
                ));
            }
        };
        let Some(request) = self.request(check, &token) else {
            return Verdict::Failed("could not build the request".to_owned());
        };
        match tokio::time::timeout(deadline + REACH_ALLOWANCE, self.exchange(request)).await {
            Ok(Ok(body)) => judge(&body),
            Ok(Err(reason)) => Verdict::Failed(reason),
            Err(_elapsed) => Verdict::Failed(format!(
                "no answer within the call deadline plus {} s",
                REACH_ALLOWANCE.as_secs()
            )),
        }
    }

    fn request(&self, check: &ReachCheck, token: &str) -> Option<Request<Full<Bytes>>> {
        let mut bearer = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
        bearer.set_sensitive(true);
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": check.tool.as_str(), "arguments": check.arguments},
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

/// The verdict of the gateway's answer `body` to the reach check's call.
fn judge(body: &[u8]) -> Verdict {
    let Ok(Value::Object(answer)) = serde_json::from_slice::<Value>(body) else {
        return Verdict::Failed("the answer is not a JSON-RPC response".to_owned());
    };
    if let Some(error) = answer.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("no message");
        return Verdict::Failed(format!(
            "the gateway refused the call: {}",
            bounded(message)
        ));
    }
    let Some(Value::Object(result)) = answer.get("result") else {
        return Verdict::Failed("the answer has neither a result nor an error".to_owned());
    };
    let row = result
        .get("_meta")
        .and_then(|meta| meta.get(AUDIT_ROW_META))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let texts: Vec<&str> = result
        .get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
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
}
