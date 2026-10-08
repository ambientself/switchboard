//! The logs: every request, and every tool call with the time each step took, as JSON.
//!
//! A test binary of its own, because it installs a log subscriber for its thread: `tracing`
//! caches whether anything listens at each call site, and tests running alongside on other
//! threads, with no subscriber, could make it cache "nothing does".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use gateway_testkit::{Caller, READ_TOOL, SURFACE_READ, TEAM_B_DOCUMENT};
use serde_json::{Value, json};

use support::Server;

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

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
    /// Every event logged with `message`, as JSON.
    fn events(&self, message: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["fields"]["message"] == json!(message))
            .collect()
    }
}

#[tokio::test]
async fn each_request_and_each_tool_call_is_logged_with_its_timings() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_span_list(true)
        .with_writer(move || writer.clone())
        .finish();
    // This test's runtime runs every task on this thread, the server's included.
    let _logging = tracing::subscriber::set_default(subscriber);

    let server = Server::start().await;
    let own = json!({"document": Caller::TeamA.own_document()});
    let answer = server
        .call(Caller::TeamA, SURFACE_READ, READ_TOOL, own)
        .send(&server)
        .await;
    assert_eq!(answer.result()["isError"], json!(false));
    let denied = json!({"document": TEAM_B_DOCUMENT});
    let answer = server
        .call(Caller::TeamA, SURFACE_READ, READ_TOOL, denied)
        .send(&server)
        .await;
    answer.denial();

    let ran = captured.events("ran a tool call");
    assert_eq!(ran.len(), 1, "{ran:?}");
    let fields = &ran[0]["fields"];
    assert_eq!(fields["tool"], json!(READ_TOOL));
    assert_eq!(fields["outcome"], json!("ok"));
    // The in-memory store numbers its rows from zero.
    assert_eq!(fields["row"], json!("0"));
    for timing in ["latency_ms", "decide_us", "begin_us", "run_us", "finish_us"] {
        assert!(fields[timing].is_u64(), "{timing}: {fields}");
    }
    let spans: Vec<&str> = ran[0]["spans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|span| span["name"].as_str().unwrap())
        .collect();
    assert_eq!(spans, ["request", "answer"]);

    let denied = captured.events("denied a tool call");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(denied[0]["fields"]["begin_us"].is_u64());

    let answered = captured.events("answered a request");
    assert_eq!(answered.len(), 2);
    for event in answered {
        assert_eq!(event["fields"]["status"], json!(200));
        assert!(event["fields"]["elapsed_us"].is_u64());
    }
}
