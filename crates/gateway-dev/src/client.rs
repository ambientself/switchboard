//! The scripted client: a short conversation with the gateway in one MCP era, printed as it
//! happens.
//!
//! It is written by hand over plain HTTP, so what it prints is exactly what went over the wire:
//! the method and URL, every header the gateway reads, the body, and the status and body that
//! came back. The bearer token is the one thing it does not print.
//!
//! [`script`] says what is sent in each era:
//!
//! - **legacy** (2025-06-18): `initialize`, `notifications/initialized`, `tools/list`, a read
//!   of the caller's own document and a read of another team's;
//! - **modern** (2026-07-28): `server/discover`, `tools/list` and the same two reads.
//!
//! Each step says what it expects back. [`Client::run`] runs every step, prints each exchange
//! and fails if any answer was not what its step expected.

use std::fmt;
use std::io::Write;

use gateway_mcp::{
    CLIENT_CAPABILITIES_META, DENIAL_CODE, Era, LEGACY, METHOD_HEADER, MODERN, NAME_HEADER,
    PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, TOOL_USE_ID_META,
};
use gateway_testkit::{Caller, DOCUMENT_ARGUMENT, READ_TOOL, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT};
use serde_json::{Map, Value, json};
use thiserror::Error;

/// What a step expects back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// 200 with a JSON-RPC result.
    Result,
    /// 202 with no body: a notification.
    Accepted,
    /// 200 with a tool result whose `isError` is false.
    ToolOk,
    /// 200 with the denial code: a policy denial, a scope refusal or an audit failure.
    Denied,
    /// 401: the caller was not verified.
    Unauthorized,
}

impl Expect {
    /// Whether `status` and `body` are what this expects.
    pub fn met_by(self, status: u16, body: &Value) -> bool {
        let result = status == 200 && body.get("result").is_some() && body.get("error").is_none();
        match self {
            Expect::Result => result,
            Expect::Accepted => status == 202 && body.is_null(),
            Expect::ToolOk => result && body["result"]["isError"] == json!(false),
            Expect::Denied => status == 200 && body["error"]["code"] == json!(DENIAL_CODE),
            Expect::Unauthorized => status == 401,
        }
    }
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Expect::Result => "a result",
            Expect::Accepted => "202 and no body",
            Expect::ToolOk => "a tool result",
            Expect::Denied => "a denial",
            Expect::Unauthorized => "401",
        })
    }
}

/// One request in a script.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    /// What the step shows, in a few words.
    pub title: String,
    /// The era it is sent in.
    pub era: Era,
    /// The JSON-RPC method.
    pub method: String,
    /// The JSON-RPC params, without the era's `_meta`, which [`Client`] adds.
    pub params: Value,
    /// Whether it is a notification, which has no `id`.
    pub notification: bool,
    /// Whether it carries the caller's token.
    pub authenticated: bool,
    /// What it expects back.
    pub expect: Expect,
}

impl Step {
    fn new(era: Era, title: &str, method: &str, params: Value, expect: Expect) -> Self {
        Self {
            title: title.to_owned(),
            era,
            method: method.to_owned(),
            params,
            notification: false,
            authenticated: true,
            expect,
        }
    }
}

/// The name a caller goes by in the tokens file and in the script's output.
pub fn caller_name(caller: Caller) -> &'static str {
    match caller {
        Caller::TeamA => "team_a",
        Caller::TeamB => "team_b",
        Caller::UserInGroupG => "user",
    }
}

/// The caller [`caller_name`] names. A hyphen may stand for the underscore, so `team-a` is
/// team A too.
pub fn caller_named(name: &str) -> Option<Caller> {
    [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG]
        .into_iter()
        .find(|caller| caller_name(*caller) == name.replace('-', "_"))
}

/// The era `name` names: `legacy` or `modern`, or the version itself.
pub fn era_named(name: &str) -> Option<Era> {
    match name {
        "legacy" | LEGACY => Some(Era::Legacy),
        "modern" | MODERN => Some(Era::Modern),
        _ => None,
    }
}

/// A document `caller`'s limits do not reach, which the decision denies by name.
pub fn other_document(caller: Caller) -> &'static str {
    match caller {
        Caller::TeamA => TEAM_B_DOCUMENT,
        Caller::TeamB | Caller::UserInGroupG => TEAM_A_DOCUMENT,
    }
}

/// The script for `caller` in `era`: see the [module documentation](self).
pub fn script(era: Era, caller: Caller) -> Vec<Step> {
    let read = |document: &str| {
        json!({
            "name": READ_TOOL,
            "arguments": {DOCUMENT_ARGUMENT: document},
            "_meta": {TOOL_USE_ID_META: format!("toolu_dev_{}_{}", era_name(era), document)},
        })
    };
    let own = caller.own_document();
    let other = other_document(caller);
    let mut steps = Vec::new();
    match era {
        Era::Legacy => {
            steps.push(Step::new(
                era,
                "initialize, asking for the modern version",
                "initialize",
                json!({
                    "protocolVersion": MODERN,
                    "capabilities": {},
                    "clientInfo": {"name": "switchboard-dev", "version": env!("CARGO_PKG_VERSION")},
                }),
                Expect::Result,
            ));
            let mut initialized = Step::new(
                era,
                "the initialized notification",
                "notifications/initialized",
                json!({}),
                Expect::Accepted,
            );
            initialized.notification = true;
            steps.push(initialized);
        }
        Era::Modern => steps.push(Step::new(
            era,
            "server/discover",
            "server/discover",
            json!({}),
            Expect::Result,
        )),
    }
    steps.push(Step::new(
        era,
        "the tools this caller may call",
        "tools/list",
        json!({}),
        Expect::Result,
    ));
    steps.push(Step::new(
        era,
        &format!("read {own}, which the caller's limits reach"),
        "tools/call",
        read(own),
        Expect::ToolOk,
    ));
    steps.push(Step::new(
        era,
        &format!("read {other}, which they do not"),
        "tools/call",
        read(other),
        Expect::Denied,
    ));
    steps
}

/// A request with no token, which the gateway refuses before it reads the body.
pub fn unauthenticated(era: Era) -> Step {
    let mut step = Step::new(
        era,
        "tools/list with no token",
        "tools/list",
        json!({}),
        Expect::Unauthorized,
    );
    step.authenticated = false;
    step
}

fn era_name(era: Era) -> &'static str {
    match era {
        Era::Legacy => "legacy",
        Era::Modern => "modern",
    }
}

/// One request and what came back.
#[derive(Clone, Debug, PartialEq)]
pub struct Exchange {
    /// The step that was sent.
    pub step: Step,
    /// The JSON-RPC body that was sent.
    pub request: Value,
    /// The HTTP status.
    pub status: u16,
    /// The answer's body: JSON, `null` when empty, or a string when it is not JSON.
    pub body: Value,
}

impl Exchange {
    /// Whether the answer is what the step expected.
    pub fn as_expected(&self) -> bool {
        self.step.expect.met_by(self.status, &self.body)
    }
}

/// Why a script failed.
#[derive(Debug, Error)]
pub enum ScriptError {
    /// A request could not be sent, or its answer not read.
    #[error("`{step}` was not answered: {source}")]
    Transport {
        /// The step's title.
        step: String,
        /// What went wrong.
        source: reqwest::Error,
    },
    /// Answers that were not what their steps expected, by title.
    #[error("{} answer(s) were not as expected: {}", .0.len(), .0.join("; "))]
    Unexpected(Vec<String>),
}

/// A client for one surface, as one caller.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    url: String,
    caller: String,
    token: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("url", &self.url)
            .field("caller", &self.caller)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client that posts to `url` (the endpoint, `.../mcp/<surface>`) as `caller`, presenting
    /// `token`. `caller` is only a name for the output. No proxy is used, whatever the
    /// environment says.
    pub fn new(
        url: impl Into<String>,
        caller: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder().no_proxy().build()?,
            url: url.into(),
            caller: caller.into(),
            token: token.into(),
        })
    }

    /// Sends each step in turn, writing each exchange to `out` as it happens, and fails if any
    /// answer was not what its step expected. Every step is sent, whatever the earlier ones got.
    pub async fn run(
        &self,
        steps: &[Step],
        out: &mut dyn Write,
    ) -> Result<Vec<Exchange>, ScriptError> {
        let mut exchanges = Vec::with_capacity(steps.len());
        let mut unexpected = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let id = i64::try_from(index).unwrap_or(i64::MAX) + 1;
            let exchange = self.send(step, id, out).await?;
            if !exchange.as_expected() {
                let _ = writeln!(out, "!! expected {}", step.expect);
                unexpected.push(step.title.clone());
            }
            exchanges.push(exchange);
        }
        let _ = out.flush();
        if unexpected.is_empty() {
            Ok(exchanges)
        } else {
            Err(ScriptError::Unexpected(unexpected))
        }
    }

    /// Sends one step as request `id`.
    pub async fn send(
        &self,
        step: &Step,
        id: i64,
        out: &mut dyn Write,
    ) -> Result<Exchange, ScriptError> {
        let (body, headers) = request(step, id);
        let _ = writeln!(
            out,
            "\n=== {} ({}), as {}: {}",
            era_name(step.era),
            step.era,
            self.caller,
            step.title
        );
        let _ = writeln!(out, "> POST {}", self.url);
        let mut sent = self.http.post(&self.url).body(body.to_string());
        for (name, value) in &headers {
            let _ = writeln!(out, "> {name}: {value}");
            sent = sent.header(*name, value);
        }
        if step.authenticated {
            let _ = writeln!(
                out,
                "> authorization: Bearer <{}'s token, not shown>",
                self.caller
            );
            sent = sent.bearer_auth(&self.token);
        }
        let _ = writeln!(out, "> {body}");
        let _ = out.flush();

        let failed = |source| ScriptError::Transport {
            step: step.title.clone(),
            source,
        };
        let answer = sent.send().await.map_err(failed)?;
        let status = answer.status();
        let text = answer.text().await.map_err(failed)?;
        let parsed = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        let _ = writeln!(out, "< {status}");
        if !parsed.is_null() {
            let pretty = serde_json::to_string_pretty(&parsed).unwrap_or_default();
            for line in pretty.lines() {
                let _ = writeln!(out, "< {line}");
            }
        }
        let _ = out.flush();
        Ok(Exchange {
            step: step.clone(),
            request: body,
            status: status.as_u16(),
            body: parsed,
        })
    }
}

/// The JSON-RPC body for `step` as request `id`, and the headers it is sent with, but for the
/// token.
fn request(step: &Step, id: i64) -> (Value, Vec<(&'static str, String)>) {
    let mut params = match &step.params {
        Value::Object(params) => params.clone(),
        _ => Map::new(),
    };
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
    ];
    if step.era == Era::Modern {
        let meta = params
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(meta) = meta {
            meta.insert(PROTOCOL_VERSION_META.to_owned(), json!(MODERN));
            meta.insert(CLIENT_CAPABILITIES_META.to_owned(), json!({}));
        }
        headers.push((PROTOCOL_VERSION_HEADER, MODERN.to_owned()));
        headers.push((METHOD_HEADER, step.method.clone()));
        if let Some(name) = params.get("name").and_then(Value::as_str) {
            headers.push((NAME_HEADER, name.to_owned()));
        }
    } else if step.method != "initialize" {
        // After the handshake, a 2025-06-18 client names the version it agreed on.
        headers.push((PROTOCOL_VERSION_HEADER, LEGACY.to_owned()));
    }
    let mut body = Map::new();
    body.insert("jsonrpc".to_owned(), json!("2.0"));
    if !step.notification {
        body.insert("id".to_owned(), json!(id));
    }
    body.insert("method".to_owned(), json!(step.method));
    body.insert("params".to_owned(), Value::Object(params));
    (Value::Object(body), headers)
}
