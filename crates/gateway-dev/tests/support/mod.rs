//! What the tests share: a JSON-RPC POST, a buffer the audit printer can write to, and the
//! end-to-end tests' client, which sends any request a test can describe and reads the whole
//! answer back.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway_dev::FixtureGateway;
use gateway_mcp::{
    CLIENT_CAPABILITIES_META, DENIAL_CODE, Era, METHOD_HEADER, MODERN, NAME_HEADER,
    PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, SESSION_ID_HEADER,
};
use gateway_testkit::{Caller, DOCUMENT_ARGUMENT};
use serde_json::{Value, json};

/// A 2025-06-18 request body.
pub fn legacy(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// Posts `body` to `url` with `token`, if any, and returns the status and the body: JSON, or
/// `null` when it is empty.
pub async fn post(url: &str, token: Option<&str>, body: &Value) -> (u16, Value) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let answer = request.send().await.unwrap();
    // The gateway never starts a session (decision 0007), whatever it answers.
    assert!(
        answer.headers().get("mcp-session-id").is_none(),
        "a session was started: {:?}",
        answer.headers()
    );
    let status = answer.status().as_u16();
    let text = answer.text().await.unwrap();
    let body = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap()
    };
    (status, body)
}

/// A writer whose bytes a test reads back, one JSON value per line.
#[derive(Clone, Default)]
pub struct Lines(Arc<Mutex<Vec<u8>>>);

impl Lines {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    pub fn json(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Write for Lines {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// --- The end-to-end tests' client ------------------------------------------------------------

/// How long a test waits for something that should happen at once.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// The sentence for a call refused because its audit row could not be written. The core keeps
/// it private; this copy is what a caller is promised.
pub const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// An answer as it came over the wire.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub bytes: Vec<u8>,
}

impl Answer {
    /// The body as JSON, or `null` when it is empty.
    pub fn json(&self) -> Value {
        if self.bytes.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&self.bytes)
            .unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&self.bytes)))
    }

    /// The JSON-RPC result of a 200 answer.
    pub fn result(&self) -> Value {
        let body = self.json();
        assert_eq!(self.status, 200, "{body}");
        assert!(body.get("error").is_none(), "{body}");
        body["result"].clone()
    }

    /// The JSON-RPC error's code and message.
    pub fn error(&self) -> (i64, String) {
        let body = self.json();
        let code = body["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("no error code: {body}"));
        let message = body["error"]["message"].as_str().unwrap().to_owned();
        (code, message)
    }

    /// The sentence of a refusal: 200 with the denial code.
    pub fn denial(&self) -> String {
        let (code, message) = self.error();
        assert_eq!((self.status, code), (200, DENIAL_CODE), "{}", self.json());
        message
    }

    /// A tool result: its `isError`, and the whole result.
    pub fn tool_result(&self) -> (bool, Value) {
        let result = self.result();
        let is_error = result["isError"]
            .as_bool()
            .unwrap_or_else(|| panic!("not a tool result: {result}"));
        (is_error, result)
    }

    /// The one value of `name`, if there is one.
    pub fn header(&self, name: &str) -> Option<&str> {
        let mut values = self.headers.get_all(name).iter();
        let value = values.next()?;
        assert!(values.next().is_none(), "two {name} headers");
        Some(value.to_str().unwrap())
    }
}

/// A request a test can change in any one way before it is sent.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A JSON POST of `body` to `url`.
    pub fn post(url: &str, body: &Value) -> Self {
        Self {
            method: "POST".to_owned(),
            url: url.to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }

    /// A 2026-07-28 request: `_meta` carries the version and the client's capabilities, and
    /// the version, the method and, for `tools/call`, the tool's name are mirrored in headers.
    pub fn modern(url: &str, method: &str, mut params: Value) -> Self {
        let meta = params
            .as_object_mut()
            .unwrap()
            .entry("_meta")
            .or_insert_with(|| json!({}));
        meta[PROTOCOL_VERSION_META] = json!(MODERN);
        meta[CLIENT_CAPABILITIES_META] = json!({});
        let name = params["name"].as_str().map(str::to_owned);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut request = Self::post(url, &body)
            .header(PROTOCOL_VERSION_HEADER, MODERN)
            .header(METHOD_HEADER, method);
        if let Some(name) = name {
            request = request.header(NAME_HEADER, &name);
        }
        request
    }

    /// A request in `era`: a 2025-06-18 one as Otto's callers send it, with no version
    /// header, or a 2026-07-28 one.
    pub fn in_era(era: Era, url: &str, method: &str, params: Value) -> Self {
        match era {
            Era::Legacy => Self::post(url, &legacy(method, params)),
            Era::Modern => Self::modern(url, method, params),
        }
    }

    /// Adds a header, after any of the same name.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Removes every header called `name`.
    pub fn without(mut self, name: &str) -> Self {
        self.headers
            .retain(|(header, _)| !header.eq_ignore_ascii_case(name));
        self
    }

    /// Presents `token`.
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", &format!("Bearer {token}"))
    }

    /// Sends `body` in place of the JSON.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Changes the HTTP method.
    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_owned();
        self
    }

    /// Changes the JSON body in place.
    pub fn json(mut self, change: impl FnOnce(&mut Value)) -> Self {
        let mut body: Value = serde_json::from_slice(&self.body).unwrap();
        change(&mut body);
        self.body = body.to_string().into_bytes();
        self
    }

    /// Sends the request on a client of its own and reads the whole answer.
    pub async fn send(self) -> Answer {
        self.send_on(&client()).await
    }

    /// Sends the request on `client` and reads the whole answer. No answer, in any test, may
    /// carry a session.
    pub async fn send_on(self, client: &reqwest::Client) -> Answer {
        let method = reqwest::Method::from_bytes(self.method.as_bytes()).unwrap();
        let mut request = client.request(method, &self.url).body(self.body);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let answer = tokio::time::timeout(PATIENCE, request.send())
            .await
            .expect("an answer in time")
            .unwrap();
        let status = answer.status().as_u16();
        let headers = answer.headers().clone();
        let bytes = answer.bytes().await.unwrap().to_vec();
        let answer = Answer {
            status,
            headers,
            bytes,
        };
        assert!(
            answer.headers.get(SESSION_ID_HEADER).is_none(),
            "an answer carried a session: {answer:?}"
        );
        answer
    }
}

/// An HTTP client that ignores any proxy the environment names.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// The params of a `tools/call`.
pub fn call_params(tool: &str, arguments: Value) -> Value {
    json!({"name": tool, "arguments": arguments})
}

/// The arguments that name `document`.
pub fn document(document: &str) -> Value {
    json!({ DOCUMENT_ARGUMENT: document })
}

/// `caller` calls `tool` with `arguments` on `surface`, in `era`.
pub async fn call(
    gateway: &FixtureGateway,
    caller: Caller,
    era: Era,
    surface: &str,
    tool: &str,
    arguments: Value,
) -> Answer {
    Request::in_era(
        era,
        &gateway.url(surface),
        "tools/call",
        call_params(tool, arguments),
    )
    .bearer(&gateway.token(caller))
    .send()
    .await
}

/// The names `tools/list` gives the holder of `token` on `surface` in `era`, and the whole
/// result.
pub async fn list(
    gateway: &FixtureGateway,
    token: Option<&str>,
    era: Era,
    surface: &str,
) -> (Vec<String>, Value) {
    let mut request = Request::in_era(era, &gateway.url(surface), "tools/list", json!({}));
    if let Some(token) = token {
        request = request.bearer(token);
    }
    let result = request.send().await.result();
    let names = result["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tools: {result}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    (names, result)
}

/// Nothing reached the connector or the credential source, and no row was begun.
pub fn assert_nothing_ran(gateway: &FixtureGateway) {
    assert_eq!(
        gateway.connector().received(),
        Vec::new(),
        "the connector ran"
    );
    assert_eq!(
        gateway.credentials().requests(),
        Vec::new(),
        "a credential was asked for"
    );
    assert_eq!(gateway.store().begin_attempts(), 0, "a row was begun");
}

/// Waits until `done` holds, and fails after [`PATIENCE`].
pub async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {PATIENCE:?} for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
