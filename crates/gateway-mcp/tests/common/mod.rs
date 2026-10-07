//! Raw requests for the table and golden tests: a method, headers and a body, as the HTTP layer
//! would hand them over.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use gateway_mcp::{CLIENT_CAPABILITIES_META, MODERN, PROTOCOL_VERSION_META};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Value, json};

/// A raw POST, or another method.
#[derive(Clone, Debug)]
pub struct Raw {
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Raw {
    pub fn post(body: impl Into<Vec<u8>>) -> Self {
        let mut raw = Raw {
            method: Method::POST,
            headers: HeaderMap::new(),
            body: body.into(),
        };
        raw = raw.header("content-type", "application/json");
        raw.header("accept", "application/json, text/event-stream")
    }

    pub fn json(body: &Value) -> Self {
        Raw::post(body.to_string())
    }

    /// A 2026-07-28 request with its `_meta` and every mirrored header, as a conforming client
    /// sends it. `params` may add to or replace parts of it.
    pub fn modern(id: Value, method: &str, params: Value) -> Self {
        let mut all = json!({
            "_meta": {
                PROTOCOL_VERSION_META: MODERN,
                "io.modelcontextprotocol/clientInfo": {"name": "table-client", "version": "1.0.0"},
                CLIENT_CAPABILITIES_META: {},
            }
        });
        merge(&mut all, params);
        let mut raw =
            Raw::json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": all}))
                .header("mcp-protocol-version", MODERN)
                .header("mcp-method", method);
        if let Some(name) = all.get("name").and_then(Value::as_str) {
            raw = raw.header("mcp-name", name);
        }
        raw
    }

    /// A 2025-06-18 request as Otto's callers send it: no protocol header, no `_meta` version.
    pub fn legacy(id: Value, method: &str, params: Value) -> Self {
        Raw::json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
    }

    pub fn notification(method: &str) -> Self {
        Raw::json(&json!({"jsonrpc": "2.0", "method": method}))
    }

    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets a header, replacing any value it had.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        self.headers
            .insert(name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
        self
    }

    /// Adds a header value beside any it had.
    pub fn append(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        self.headers
            .append(name, HeaderValue::from_bytes(value.as_bytes()).unwrap());
        self
    }

    pub fn without(mut self, name: &str) -> Self {
        self.headers.remove(name);
        self
    }

    pub fn parse(&self) -> Result<gateway_mcp::Inbound, gateway_mcp::Rejection> {
        gateway_mcp::parse(&self.method, &self.headers, &self.body)
    }
}

/// Merges `patch` into `target`: objects key by key, anything else replaced. A `null` in the
/// patch removes the key.
pub fn merge(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                if value.is_null() {
                    target.remove(&key);
                } else {
                    merge(target.entry(key).or_insert(Value::Null), value);
                }
            }
        }
        (target, patch) => *target = patch,
    }
}
