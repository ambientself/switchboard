//! What the tests share: a JSON-RPC POST, and a buffer the audit printer can write to.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

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
    // The gateway never starts a session (plan #26 section 6, test 7), whatever it answers.
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
