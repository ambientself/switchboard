//! The logs: every request, and every tool call with the time each step took, as JSON.
//!
//! A test binary of its own, because it installs a log subscriber for its thread: `tracing`
//! caches whether anything listens at each call site, and tests running alongside on other
//! threads, with no subscriber, could make it cache "nothing does".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gateway::{
    Config, Event, Surface, TELEMETRY_QUEUE, Telemetry, TelemetryCounts, Timeouts, Wiring, boot,
    serve_with_telemetry,
};
use gateway_core::DeploymentName;
use gateway_identity::SigningAlgorithm;
use gateway_mcp::{CLIENT_CAPABILITIES_META, MODERN, PROTOCOL_VERSION_META};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, FakeCredentialSource, Fixture, FixtureConnector,
    InMemoryAuditStore, LocalIssuer, READ_TOOL, SURFACE_READ, TEAM_B_DOCUMENT,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use support::{PATIENCE, Server, legacy};

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
    // The row is the UUIDv7 the gateway made for the call: version 7 in the third group.
    let row = fields["row"].as_str().unwrap();
    let groups: Vec<&str> = row.split('-').collect();
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12]
    );
    assert!(groups[2].starts_with('7'), "{row}");
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
    assert_ne!(
        denied[0]["fields"]["row"],
        json!(row),
        "each call has a row of its own"
    );

    let answered = captured.events("answered a request");
    assert_eq!(answered.len(), 2);
    for event in answered {
        assert_eq!(event["fields"]["status"], json!(200));
        assert!(event["fields"]["elapsed_us"].is_u64());
    }
}

impl Captured {
    /// Every event whose `event` field is `name`, as JSON.
    fn named(&self, name: &str) -> Vec<Value> {
        self.raw()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == json!(name))
            .collect()
    }

    fn raw(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    /// Captures every event logged on this thread until the guard is dropped.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_span_list(true)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
}

/// Decision 0009's telemetry, over loopback: a refused caller, `initialize`, `ping`,
/// `server/discover` and a body that cannot be parsed each give one event naming the surface
/// and the peer, and the counters agree.
#[tokio::test]
async fn each_telemetry_event_names_the_surface_and_the_peer() {
    let captured = Captured::default();
    // This test's runtime runs every task on this thread, the drain's included.
    let _logging = captured.install();
    let mut server = Server::start_with(Timeouts {
        readiness_removal: Duration::ZERO,
        ..Timeouts::default()
    })
    .await;

    // A token from an issuer the gateway does not know, claiming a subject that would forge a
    // log line if it were written as it came.
    let stranger = LocalIssuer::new("https://stranger.test", SigningAlgorithm::Es256).unwrap();
    let now = gateway_identity::Clock::now(&server.fixture.clock);
    let token = stranger
        .user_token("mallory\n\u{1b}[2J", AUDIENCE, &[], now)
        .build();
    server
        .post(SURFACE_READ, &legacy("ping", json!({})))
        .bearer(&token)
        .send(&server)
        .await
        .assert_unauthorized();

    let good = server.token(Caller::TeamA);
    let initialize = legacy(
        "initialize",
        json!({"protocolVersion": MODERN, "capabilities": {}}),
    );
    let answer = server
        .post(SURFACE_READ, &initialize)
        .bearer(&good)
        .send(&server)
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let answer = server
        .post(SURFACE_READ, &legacy("ping", json!({})))
        .bearer(&good)
        .send(&server)
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let discover = json!({"jsonrpc": "2.0", "id": 3, "method": "server/discover", "params": {
        "_meta": {PROTOCOL_VERSION_META: MODERN, CLIENT_CAPABILITIES_META: {}},
    }});
    let answer = server
        .post(SURFACE_READ, &discover)
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", "server/discover")
        .bearer(&good)
        .send(&server)
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let answer = server
        .post(SURFACE_READ, &json!({}))
        .body(b"{not json".to_vec())
        .bearer(&good)
        .send(&server)
        .await;
    assert_eq!(answer.status, 400, "{answer:?}");

    // Shutting down writes every queued event before serving returns.
    server.stop.take().unwrap().send(()).unwrap();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();

    let from_the_peer = |event: &Value| {
        let source: SocketAddr = event["fields"]["source"]
            .as_str()
            .unwrap_or_else(|| panic!("no source: {event}"))
            .parse()
            .unwrap();
        assert_eq!(source.ip(), server.address.ip(), "{event}");
        assert_ne!(
            source, server.address,
            "{event}: the gateway's address, not the peer's"
        );
    };
    let failed = captured.named("identity_failed");
    assert_eq!(failed.len(), 1, "one event per failure: {failed:?}");
    let failed = &failed[0];
    assert_eq!(failed["level"], json!("WARN"));
    let fields = &failed["fields"];
    assert_eq!(fields["deployment"], json!("server-test"));
    assert_eq!(fields["surface"], json!(SURFACE_READ));
    from_the_peer(failed);
    assert_eq!(
        fields["cause"],
        json!("the token's issuer is not configured")
    );
    assert_eq!(fields["claimed_issuer"], json!("https://stranger.test"));
    assert_eq!(fields["claimed_subject"], json!("mallory\\n\\u{1b}[2J"));
    let raw = captured.raw();
    assert!(!raw.contains(&token), "the token reached the log");
    let signature = token.rsplit('.').next().unwrap();
    assert!(
        !raw.contains(signature),
        "part of the token reached the log"
    );

    for name in ["initialize", "ping", "discover", "unparsable_body"] {
        let events = captured.named(name);
        assert_eq!(events.len(), 1, "{name}: {events:?}");
        assert_eq!(
            events[0]["fields"]["surface"],
            json!(SURFACE_READ),
            "{name}"
        );
        from_the_peer(&events[0]);
    }
    assert_eq!(
        captured.named("unparsable_body")[0]["fields"]["rejection"],
        json!("ParseError")
    );

    assert_eq!(
        server.telemetry.counts(),
        TelemetryCounts {
            identity_failed: 1,
            initialize: 1,
            ping: 1,
            discover: 1,
            unparsable: 1,
            dropped: 0,
        }
    );
}

/// Serving returns only once the telemetry queue is closed and every event in it is written.
/// It is served on the test's own task, with a shutdown that has already come, so nothing else
/// runs between its return and the checks after it.
#[tokio::test]
async fn serving_returns_once_the_queued_events_are_written() {
    let captured = Captured::default();
    let _logging = captured.install();
    let fixture = Fixture::new().unwrap();
    let credentials = Arc::new(FakeCredentialSource::new());
    let connector = Arc::new(FixtureConnector::new(credentials));
    let config: Config = serde_json::from_value(support::config(&fixture)).unwrap();
    let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
        .audit_store(Arc::new(InMemoryAuditStore::new()))
        .connector(CONNECTOR, connector, Arc::new(support::FixtureResources));
    let gates = boot::check(config, wiring).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let ping = || Event::Ping {
        deployment: DeploymentName::new("server-test"),
        surface: Some(Surface::new(SURFACE_READ)),
        source: None,
    };
    let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let queued = 20;
    for _ in 0..queued {
        telemetry.emit(ping());
    }
    let timeouts = Timeouts {
        readiness_removal: Duration::ZERO,
        shutdown_grace: Duration::from_millis(10),
        ..Timeouts::default()
    };
    serve_with_telemetry(
        listener,
        gates,
        telemetry.clone(),
        drain,
        async {},
        timeouts,
    )
    .await
    .unwrap();

    assert_eq!(captured.named("ping").len(), queued);
    assert_eq!(telemetry.counts().dropped, 0);
    telemetry.emit(ping());
    assert_eq!(
        telemetry.counts().dropped,
        1,
        "the queue was still open after serving returned"
    );
}
