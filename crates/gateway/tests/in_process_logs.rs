//! The log events of the gateway-level bound around a connector in the gateway's own process
//! (#217): one `in_process_bound_breached` event for each breach, with the vendor's reference
//! when a side effect the vendor confirmed gave a result over its bound.
//!
//! A test binary of its own, because it installs a log subscriber for its thread: `tracing`
//! caches whether anything listens at each call site, and tests running alongside on other
//! threads, with no subscriber, could make it cache "nothing does".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};

use gateway::path::RequestPath;
use gateway::{BOUND_BREACHED_EVENT, Config, InProcessLimits, Wiring, boot};
use gateway_core::{BoxFuture, Classification, Connector, ToolCall, ToolOutcome, VendorReference};
use gateway_mcp::TOOL_USE_ID_META;
use gateway_testkit::{
    CONNECTOR, Caller, DRAFT_TOOL, Fixture, InMemoryAuditStore, READ_TOOL, SURFACE_ALL,
    TEAM_A_DOCUMENT, fresh_key,
};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};
use support::FixtureResources;

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// The fields of every event logged with `event`.
    fn events(&self, event: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|logged| logged["fields"]["event"] == json!(event))
            .map(|logged| logged["fields"].clone())
            .collect()
    }
}

/// A connector that answers every call at once with a result of 100 characters: a read `ok`,
/// any other tool as the vendor confirmed it, with a reference.
struct Long;

impl Connector for Long {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let read = call.tool().classification == Classification::Read;
        let result = json!({"text": "x".repeat(100)});
        Box::pin(std::future::ready(if read {
            ToolOutcome::Ok(result)
        } else {
            ToolOutcome::Completed(result, VendorReference::new("draft-7"))
        }))
    }
}

async fn call(path: &RequestPath, fixture: &Fixture, tool: &str) {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    let bearer = format!("Bearer {}", fixture.token(Caller::TeamA));
    headers.insert("authorization", HeaderValue::from_str(&bearer).unwrap());
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": Fixture::arguments_naming(TEAM_A_DOCUMENT),
            "_meta": {TOOL_USE_ID_META: fresh_key().as_str()},
        },
    });
    let response = path
        .handle(
            &Method::POST,
            &headers,
            SURFACE_ALL,
            body.to_string().as_bytes(),
        )
        .await;
    assert_eq!(response.status, 200, "{response:?}");
}

/// Each result over its bound is logged once: a read's, and a side effect's the vendor
/// confirmed, whose one event carries the vendor's reference, which reconciliation can find
/// again.
#[tokio::test]
async fn each_breach_is_logged_once_with_a_confirmed_reference() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    // This test's runtime runs every task on this thread.
    let _logging = tracing::subscriber::set_default(subscriber);

    let fixture = Fixture::new().unwrap();
    let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
        .connector(CONNECTOR, Arc::new(Long), Arc::new(FixtureResources))
        .audit_store(Arc::new(InMemoryAuditStore::new()))
        .in_process_limits(
            CONNECTOR,
            InProcessLimits {
                deadline: std::time::Duration::from_secs(5),
                max_result_bytes: 20,
            },
        );
    let config: Config = serde_json::from_value(support::config(&fixture)).unwrap();
    let path = RequestPath::new(boot::check(config, wiring).unwrap());

    call(&path, &fixture, READ_TOOL).await;
    let breaches = captured.events(BOUND_BREACHED_EVENT);
    assert_eq!(breaches.len(), 1, "{breaches:?}");
    assert_eq!(breaches[0]["kind"], json!("oversized"));
    assert_eq!(breaches[0]["outcome"], json!("error"));
    assert_eq!(breaches[0].get("reference"), None, "{breaches:?}");

    call(&path, &fixture, DRAFT_TOOL).await;
    let breaches = captured.events(BOUND_BREACHED_EVENT);
    assert_eq!(
        breaches.len(),
        2,
        "one breach was logged twice: {breaches:?}"
    );
    assert_eq!(breaches[1]["kind"], json!("oversized"));
    assert_eq!(breaches[1]["outcome"], json!("unknown"));
    assert_eq!(breaches[1]["tool"], json!(DRAFT_TOOL));
    assert_eq!(breaches[1]["reference"], json!("draft-7"));
}
