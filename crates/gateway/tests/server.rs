//! The HTTP endpoint over loopback: the gateway serves the testkit's world on `127.0.0.1:0`, and
//! each test talks to it over a TCP socket with hand-written HTTP/1.1.
//!
//! The request path's own behaviour is tested in `path.rs`. These tests cover what the HTTP
//! layer adds: the host and origin checks, the body limit, identity before the body is read, a
//! task per answer that a disconnect cannot cancel, what a disconnect does to a call (decision
//! 0009), the time limits on a request's head and body, the readiness check, and shutting down.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::{Duration, Instant};

use gateway::{MAX_BODY_BYTES, SHUTTING_DOWN, Timeouts};
use gateway_core::audit::{Completion, DecisionKind, Outcome};
use gateway_core::{AuditRecord, Classification};
use gateway_mcp::{INTERNAL_ERROR, INVALID_REQUEST, LEGACY, MODERN, PARSE_ERROR};
use gateway_testkit::{
    Caller, DRAFT_TOOL, READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{ALLOWED_ORIGIN, Http, PATIENCE, Server, eventually, exchange, legacy, read_answer};

const FORBIDDEN_HOST: &str = "Forbidden: host not allowed";
const FORBIDDEN_ORIGIN: &str = "Forbidden: origin not allowed";

// --- The endpoint answers --------------------------------------------------------------------

#[tokio::test]
async fn a_client_is_answered_and_its_calls_recorded_over_loopback() {
    let server = Server::start().await;
    let token = server.token(Caller::TeamA);

    let initialized = server
        .post(
            SURFACE_READ,
            &legacy(
                "initialize",
                json!({"protocolVersion": MODERN, "capabilities": {}}),
            ),
        )
        .bearer(&token)
        .send(&server)
        .await;
    assert_eq!(initialized.header("content-type"), Some("application/json"));
    assert_eq!(initialized.result()["protocolVersion"], json!(LEGACY));

    let notified = server
        .post(
            SURFACE_READ,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .bearer(&token)
        .send(&server)
        .await;
    assert_eq!(notified.status, 202, "{notified:?}");
    assert!(notified.body.is_empty());

    let listed = server
        .post(SURFACE_READ, &legacy("tools/list", json!({})))
        .bearer(&token)
        .send(&server)
        .await;
    let tools = listed.result()["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&READ_TOOL), "{names:?}");

    // The 2026-07-28 era, over the same endpoint with no session.
    let modern = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {},
    }}});
    let listed = server
        .post(SURFACE_READ, &modern)
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", "tools/list")
        .bearer(&token)
        .send(&server)
        .await;
    assert_eq!(listed.result()["cacheScope"], json!("private"));

    let read = server
        .call(
            Caller::TeamA,
            SURFACE_READ,
            READ_TOOL,
            json!({"document": Caller::TeamA.own_document()}),
        )
        .send(&server)
        .await;
    assert_eq!(read.result()["isError"], json!(false));
    assert_eq!(read.result()["structuredContent"]["tool"], json!(READ_TOOL));

    let denied = server
        .call(
            Caller::TeamA,
            SURFACE_READ,
            READ_TOOL,
            json!({"document": TEAM_B_DOCUMENT}),
        )
        .send(&server)
        .await;
    let sentence = denied.denial();
    assert!(sentence.contains(TEAM_B_DOCUMENT), "{sentence}");

    let rows = server.store.rows();
    assert_eq!(rows.len(), 2, "one row per call, none for anything else");
    assert_eq!(rows[0].decision, DecisionKind::Allow);
    assert_eq!(
        rows[0].completion.as_ref().map(|c| c.outcome.clone()),
        Some(Outcome::Ok)
    );
    assert_eq!(rows[1].decision, DecisionKind::Deny);
    assert_eq!(server.connector.received().len(), 1);
}

#[tokio::test]
async fn a_path_that_is_not_a_surface_is_not_found() {
    let server = Server::start().await;
    let token = server.token(Caller::TeamA);
    for target in [
        "/",
        "/mcp",
        "/mcp/",
        "/other/fixture-read",
        "/mcp/fixture-read/extra",
    ] {
        let mut request = server
            .post(SURFACE_READ, &legacy("ping", json!({})))
            .bearer(&token);
        request.target = target.to_owned();
        assert_eq!(request.send(&server).await.status, 404, "{target}");
    }
    server.assert_nothing_ran();
}

// --- Host and Origin ------------------------------------------------------------------------

#[tokio::test]
async fn a_host_that_is_not_allowed_is_refused_before_identity() {
    let server = Server::start().await;
    let port = server.address.port();
    let ping = || {
        server
            .post(SURFACE_READ, &legacy("ping", json!({})))
            .without("host")
    };

    for host in [
        "evil.example".to_owned(),
        format!("evil.example:{port}"),
        format!("localhost.evil.example:{port}"),
        format!("127.0.0.2:{port}"),
        "localhost:".to_owned(),
        format!("localhost:{port}x"),
        format!("127.0.0.1:{port}:{port}"),
    ] {
        let answer = ping().header("host", &host).send(&server).await;
        answer.assert_forbidden(FORBIDDEN_HOST);
    }
    ping().send(&server).await.assert_forbidden(FORBIDDEN_HOST);
    ping()
        .header("host", &format!("localhost:{port}"))
        .header("host", "evil.example")
        .send(&server)
        .await
        .assert_forbidden(FORBIDDEN_HOST);
    server.assert_nothing_ran();

    // An allowed host, with or without its port and in any case, reaches identity.
    for host in [format!("LocalHost:{port}"), "127.0.0.1".to_owned()] {
        ping()
            .header("host", &host)
            .send(&server)
            .await
            .assert_unauthorized();
    }
}

#[tokio::test]
async fn an_origin_that_is_not_allowed_is_refused_before_identity() {
    let server = Server::start().await;
    let ping = || server.post(SURFACE_READ, &legacy("ping", json!({})));

    for origin in ["http://evil.example", "null", "http://localhost:3001"] {
        let answer = ping().header("origin", origin).send(&server).await;
        answer.assert_forbidden(FORBIDDEN_ORIGIN);
    }
    ping()
        .header("origin", ALLOWED_ORIGIN)
        .header("origin", "http://evil.example")
        .send(&server)
        .await
        .assert_forbidden(FORBIDDEN_ORIGIN);
    server.assert_nothing_ran();

    // An allowed origin reaches identity, and with a token is served.
    ping()
        .header("origin", ALLOWED_ORIGIN)
        .send(&server)
        .await
        .assert_unauthorized();
    let served = ping()
        .header("origin", ALLOWED_ORIGIN)
        .bearer(&server.token(Caller::TeamA))
        .send(&server)
        .await;
    assert_eq!(served.result(), json!({}));
}

#[tokio::test]
async fn a_request_with_no_origin_is_served() {
    let server = Server::start().await;
    let answer = server
        .post(SURFACE_READ, &legacy("ping", json!({})))
        .bearer(&server.token(Caller::TeamB))
        .send(&server)
        .await;
    assert_eq!(answer.result(), json!({}));
}

// --- Transport and size ---------------------------------------------------------------------

#[tokio::test]
async fn what_is_not_a_json_post_is_refused_before_identity() {
    let server = Server::start().await;
    let ping = || server.post(SURFACE_READ, &legacy("ping", json!({})));
    for method in ["GET", "DELETE", "PUT"] {
        let mut request = ping();
        request.method = method.to_owned();
        let answer = request.send(&server).await;
        assert_eq!(answer.status, 405, "{method}: {answer:?}");
        assert_eq!(answer.header("allow"), Some("POST"));
    }
    let answer = ping()
        .without("content-type")
        .header("content-type", "text/plain")
        .send(&server)
        .await;
    assert_eq!(answer.status, 415, "{answer:?}");
    let answer = ping()
        .without("accept")
        .header("accept", "text/event-stream")
        .send(&server)
        .await;
    assert_eq!(answer.status, 406, "{answer:?}");
    server.assert_nothing_ran();
}

#[tokio::test]
async fn a_body_declared_too_large_is_refused_before_identity() {
    let server = Server::start().await;
    let request = server
        .post(SURFACE_READ, &json!({}))
        .header("content-length", &(MAX_BODY_BYTES + 1).to_string());
    // The head only: the body is never sent, and is never waited for.
    let answer = exchange(server.address, &request.head()).await;
    assert_eq!(answer.status, 413, "{answer:?}");
    assert_eq!(answer.error_message(), "Payload too large");
    server.assert_nothing_ran();
}

#[tokio::test]
async fn a_body_of_the_largest_size_is_read() {
    let server = Server::start().await;
    // Exactly the limit, declared and sent: read, and refused only because it is not JSON.
    let answer = server
        .post(SURFACE_READ, &json!({}))
        .bearer(&server.token(Caller::TeamA))
        .body(vec![b'x'; MAX_BODY_BYTES])
        .send(&server)
        .await;
    assert_eq!(answer.status, 400, "{answer:?}");
    assert_eq!(answer.json()["error"]["code"], json!(PARSE_ERROR));
    server.assert_nothing_ran();
}

/// A chunked body: no length is declared, so the limit applies as the body is read.
fn chunked(request: Http, size: usize) -> Vec<u8> {
    let mut bytes = request.header("transfer-encoding", "chunked").head();
    let chunk = 64 * 1024;
    let mut left = size;
    while left > 0 {
        let this = left.min(chunk);
        bytes.extend_from_slice(format!("{this:x}\r\n").as_bytes());
        bytes.extend(std::iter::repeat_n(b'x', this));
        bytes.extend_from_slice(b"\r\n");
        left -= this;
    }
    bytes.extend_from_slice(b"0\r\n\r\n");
    bytes
}

#[tokio::test]
async fn a_body_that_grows_too_large_is_refused() {
    let server = Server::start().await;
    let token = server.token(Caller::TeamA);
    let request = || {
        server
            .post(SURFACE_READ, &json!({}))
            .bearer(&token)
            .body(Vec::new())
    };

    let answer = exchange(server.address, &chunked(request(), MAX_BODY_BYTES + 1)).await;
    assert_eq!(answer.status, 413, "{answer:?}");
    assert_eq!(answer.error_message(), "Payload too large");

    let answer = exchange(server.address, &chunked(request(), MAX_BODY_BYTES)).await;
    assert_eq!(answer.status, 400, "the largest body is read: {answer:?}");
    assert_eq!(answer.json()["error"]["code"], json!(PARSE_ERROR));
    server.assert_nothing_ran();
}

#[tokio::test]
async fn identity_is_checked_before_the_body_is_read() {
    let server = Server::start().await;
    // A body that has started and never finishes. Without a token the answer comes at once.
    let mut bytes = server
        .post(SURFACE_READ, &json!({}))
        .header("transfer-encoding", "chunked")
        .head();
    bytes.extend_from_slice(b"10\r\n{\"jsonrpc\":\"2.0\"");
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    read_answer(&mut stream).await.assert_unauthorized();
    server.assert_nothing_ran();
}

// --- The answer runs on its own task --------------------------------------------------------

/// Sends `request` whole and does not read the answer: the stream, to drop when the client goes
/// away.
async fn send_and_wait(server: &Server, request: Http) -> TcpStream {
    let length = request.body.len().to_string();
    let request = request.header("content-length", &length);
    let mut bytes = request.head();
    bytes.extend_from_slice(&request.body);
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream
}

/// Team A's call to the draft tool, a side effect.
fn propose(server: &Server) -> Http {
    server.call(
        Caller::TeamA,
        SURFACE_ALL,
        DRAFT_TOOL,
        json!({"document": TEAM_A_DOCUMENT, "text": "A proposed change."}),
    )
}

/// Team A's call to the read tool.
fn read(server: &Server) -> Http {
    server.call(
        Caller::TeamA,
        SURFACE_READ,
        READ_TOOL,
        json!({"document": Caller::TeamA.own_document()}),
    )
}

/// How long a test gives the server to notice that a client has gone.
const NOTICE: Duration = Duration::from_millis(200);

fn completion(row: &AuditRecord) -> Option<Outcome> {
    row.completion
        .as_ref()
        .map(|completion| completion.outcome.clone())
}

#[tokio::test]
async fn a_side_effect_completes_its_row_after_its_client_has_gone() {
    let server = Server::start().await;
    let gate = server.connector.hang_next();
    let stream = send_and_wait(&server, propose(&server)).await;
    eventually("the call reaching the connector", || gate.waiting() == 1).await;
    let row = server.store.row(0).unwrap();
    assert_eq!(row.classification, Some(Classification::Propose));
    assert_eq!((row.decision, row.completion), (DecisionKind::Allow, None));

    // The client goes away while the tool is running, and the server notices. Nothing is
    // cancelled: the call is still held, not dropped.
    drop(stream);
    tokio::time::sleep(NOTICE).await;
    assert_eq!(gate.waiting(), 1, "the side effect was cancelled");
    assert_eq!(server.store.row(0).unwrap().completion, None);
    gate.open();
    eventually("the row's completion", || {
        server.store.row(0).unwrap().completion.is_some()
    })
    .await;
    assert_eq!(
        server.store.row(0).unwrap().completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 0
        })
    );
    assert_eq!(server.store.finish_attempts(), 1);
    assert_eq!(server.connector.writes().len(), 1, "the draft was written");
}

#[tokio::test]
async fn a_call_whose_client_goes_during_begin_is_not_run_and_its_row_is_an_error() {
    let server = Server::start().await;
    let gate = server.store.hold_begins();
    let stream = send_and_wait(&server, propose(&server)).await;
    eventually("begin reaching the store", || gate.waiting() == 1).await;

    drop(stream);
    tokio::time::sleep(NOTICE).await;
    gate.open();
    eventually("the row's completion", || {
        server
            .store
            .row(0)
            .is_some_and(|row| row.completion.is_some())
    })
    .await;
    let row = server.store.row(0).unwrap();
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Error,
            latency_ms: 0
        })
    );
    assert!(
        server.connector.received().is_empty(),
        "the connector was called for a client that had gone"
    );
    assert!(server.connector.writes().is_empty());
    assert_eq!(server.store.finish_attempts(), 1);
}

#[tokio::test]
async fn a_read_whose_client_goes_is_cancelled_and_its_row_is_an_error() {
    let server = Server::start().await;
    let gate = server.connector.hang_next();
    let stream = send_and_wait(&server, read(&server)).await;
    eventually("the call reaching the connector", || gate.waiting() == 1).await;

    // The gate is never opened: the read is cancelled, and its future dropped.
    drop(stream);
    eventually("the row's completion", || {
        server.store.row(0).unwrap().completion.is_some()
    })
    .await;
    assert_eq!(
        completion(&server.store.row(0).unwrap()),
        Some(Outcome::Error)
    );
    assert_eq!(gate.waiting(), 0, "the read's future was not dropped");
    assert_eq!(server.connector.received().len(), 1);
    assert_eq!(server.store.finish_attempts(), 1);
}

#[tokio::test]
async fn a_read_whose_client_stays_is_answered() {
    let server = Server::start().await;
    let gate = server.connector.hang_next();
    let mut stream = send_and_wait(&server, read(&server)).await;
    eventually("the call reaching the connector", || gate.waiting() == 1).await;
    tokio::time::sleep(NOTICE).await;
    gate.open();
    let answer = read_answer(&mut stream).await;
    assert_eq!(answer.result()["isError"], json!(false), "{answer:?}");
    assert_eq!(completion(&server.store.row(0).unwrap()), Some(Outcome::Ok));
}

// --- The readiness check --------------------------------------------------------------------

/// A kubelet's probe: a GET from the pod's IP, with no token and no Origin.
fn probe() -> Http {
    Http::new("GET", "/readyz").header("host", "10.244.0.7:8080")
}

#[tokio::test]
async fn the_readiness_check_is_ready_for_any_host_while_serving() {
    let server = Server::start().await;
    let ready = probe().send(&server).await;
    assert_eq!(ready.status, 200, "{ready:?}");
    assert_eq!(ready.body, b"ready");
    assert_eq!(ready.header("content-type"), Some("text/plain"));

    // No host, origin or identity check runs.
    for request in [
        probe().without("host"),
        probe().without("host").header("host", "evil.example"),
        probe().header("origin", "http://evil.example"),
        probe().bearer("not-a-token"),
    ] {
        let answer = request.send(&server).await;
        assert_eq!(
            (answer.status, answer.body.as_slice()),
            (200, &b"ready"[..])
        );
    }

    for method in ["POST", "PUT", "DELETE"] {
        let mut request = probe();
        request.method = method.to_owned();
        let answer = request.send(&server).await;
        assert_eq!(answer.status, 405, "{method}: {answer:?}");
        assert_eq!(answer.header("allow"), Some("GET"));
    }
    server.assert_nothing_ran();
}

#[tokio::test]
async fn shutting_down_fails_readiness_first_and_serves_until_the_removal_is_over() {
    let removal = Duration::from_secs(2);
    let mut server = Server::start_with(Timeouts {
        readiness_removal: removal,
        ..short()
    })
    .await;
    assert_eq!(probe().send(&server).await.status, 200);

    server.stop.take().unwrap().send(()).unwrap();
    let stopped = Instant::now();
    let unready = tokio::time::timeout(PATIENCE, async {
        loop {
            let answer = probe().send(&server).await;
            if answer.status != 200 {
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the readiness check still passes");
    assert_eq!(unready.status, 503, "{unready:?}");
    assert_eq!(unready.body, b"not ready");

    // Still in the removal window: a call is taken, served and its row completed.
    let read = server
        .call(
            Caller::TeamA,
            SURFACE_READ,
            READ_TOOL,
            json!({"document": Caller::TeamA.own_document()}),
        )
        .send(&server)
        .await;
    assert_eq!(read.result()["isError"], json!(false), "{read:?}");
    assert!(stopped.elapsed() < removal, "the test was too slow");
    assert!(!server.serving.is_finished(), "stopped inside the removal");
    let row = server.store.row(0).unwrap();
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(row.completion.map(|c| c.outcome), Some(Outcome::Ok));

    // After it, nothing more is taken.
    let returned = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    returned.expect("the server stopped").unwrap().unwrap();
    assert!(stopped.elapsed() >= removal, "stopped before the removal");
    assert!(
        TcpStream::connect(server.address).await.is_err(),
        "still listening"
    );
}

// --- Shutting down --------------------------------------------------------------------------

#[tokio::test]
async fn the_server_stops_when_told_to() {
    let mut server = Server::start_with(Timeouts {
        readiness_removal: Duration::from_millis(300),
        ..Timeouts::default()
    })
    .await;
    let answer = server
        .post(SURFACE_READ, &legacy("ping", json!({})))
        .bearer(&server.token(Caller::TeamA))
        .send(&server)
        .await;
    assert_eq!(answer.status, 200);

    server.stop.take().unwrap().send(()).unwrap();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();
    assert!(
        TcpStream::connect(server.address).await.is_err(),
        "still listening"
    );
}

/// Timeouts short enough for a test, but for the ones it names.
fn short() -> Timeouts {
    Timeouts {
        header_read: Duration::from_millis(300),
        body_read: Duration::from_millis(300),
        readiness_removal: Duration::from_millis(300),
        shutdown_grace: Duration::from_millis(300),
    }
}

/// A request line and the start of a header, and nothing after.
const HALF_A_HEAD: &[u8] = b"POST /mcp/fixture-read HTTP/1.1\r\nHost: local";

/// Reads until the server closes `stream`, and says whether it did within [`PATIENCE`].
async fn closed_by_the_server(stream: &mut TcpStream) -> bool {
    let mut buffer = [0; 1024];
    loop {
        match tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await {
            Err(_) => return false,
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => {}
        }
    }
}

#[tokio::test]
async fn a_connection_that_does_not_finish_its_head_in_time_is_closed() {
    let server = Server::start_with(Timeouts {
        shutdown_grace: Duration::from_secs(60),
        ..short()
    })
    .await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(HALF_A_HEAD).await.unwrap();
    let started = std::time::Instant::now();
    assert!(
        closed_by_the_server(&mut stream).await,
        "still open after {PATIENCE:?}"
    );
    assert!(started.elapsed() >= Duration::from_millis(200));
    server.assert_nothing_ran();
}

#[tokio::test]
async fn a_body_that_does_not_arrive_in_time_is_408() {
    let server = Server::start_with(short()).await;
    let request = server
        .post(SURFACE_READ, &legacy("tools/list", json!({})))
        .bearer(&server.token(Caller::TeamA))
        .without("connection")
        .header("content-length", "100");
    let mut bytes = request.head();
    bytes.extend_from_slice(b"{\"jsonrpc\":");
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let answer = read_answer(&mut stream).await;
    assert_eq!(answer.status, 408);
    assert_eq!(answer.header("connection"), Some("close"));
    assert_eq!(
        answer.json(),
        json!({"jsonrpc": "2.0", "id": null, "error": {
            "code": INVALID_REQUEST,
            "message": "Request timeout: the body did not arrive in time, so nothing ran",
        }})
    );
    server.assert_nothing_ran();
}

#[tokio::test]
async fn shutting_down_stops_waiting_for_a_half_sent_request_after_the_grace() {
    let mut server = Server::start_with(Timeouts {
        header_read: Duration::from_secs(60),
        body_read: Duration::from_secs(60),
        ..short()
    })
    .await;
    // One connection stopped part way through its head, another part way through its body.
    let mut head = TcpStream::connect(server.address).await.unwrap();
    head.write_all(HALF_A_HEAD).await.unwrap();
    let request = server
        .post(SURFACE_READ, &legacy("tools/list", json!({})))
        .bearer(&server.token(Caller::TeamA))
        .header("content-length", "100");
    let mut body = TcpStream::connect(server.address).await.unwrap();
    body.write_all(&request.head()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    server.stop.take().unwrap().send(()).unwrap();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();
    server.assert_nothing_ran();
}

#[tokio::test]
async fn a_call_whose_body_arrives_after_shutting_down_never_starts() {
    let mut server = Server::start_with(Timeouts {
        header_read: Duration::from_secs(60),
        body_read: Duration::from_secs(60),
        ..short()
    })
    .await;
    let request = server.call(
        Caller::TeamA,
        SURFACE_READ,
        READ_TOOL,
        json!({"document": Caller::TeamA.own_document()}),
    );
    let length = request.body.len().to_string();
    let request = request.header("content-length", &length);
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&request.head()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    server.stop.take().unwrap().send(()).unwrap();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();
    server.assert_nothing_ran();

    // The body arrives once the server has returned. The connection is closed, so nothing
    // answers it and no call starts.
    let _ = stream.write_all(&request.body).await;
    let mut received = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        match tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await {
            Err(_) => panic!("the connection is still open after {PATIENCE:?}"),
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(read)) => received.extend_from_slice(&buffer[..read]),
        }
    }
    assert!(
        received.is_empty(),
        "answered after shutting down: {:?}",
        String::from_utf8_lossy(&received)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.assert_nothing_ran();
}

#[tokio::test]
async fn shutting_down_waits_past_the_grace_for_a_call_that_is_running() {
    let mut server = Server::start_with(short()).await;
    let gate = server.connector.hang_next();
    // A side effect: closing its connection after the grace cancels nothing.
    let _stream = send_and_wait(&server, propose(&server)).await;
    eventually("the call reaching the connector", || gate.waiting() == 1).await;

    server.stop.take().unwrap().send(()).unwrap();
    // Well past the grace, the call is still running and the server still waits for it.
    let waited = tokio::time::timeout(Duration::from_secs(1), &mut server.serving).await;
    assert!(waited.is_err(), "the server returned with a call running");
    assert_eq!(server.store.row(0).unwrap().completion, None);

    gate.open();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();
    assert!(server.store.row(0).unwrap().completion.is_some());
}

#[tokio::test]
async fn a_call_whose_body_arrives_during_the_grace_is_refused_and_never_starts() {
    let mut server = Server::start_with(Timeouts {
        header_read: Duration::from_secs(60),
        body_read: Duration::from_secs(60),
        readiness_removal: Duration::from_millis(100),
        shutdown_grace: Duration::from_secs(60),
    })
    .await;
    let request = propose(&server);
    let length = request.body.len().to_string();
    let request = request.header("content-length", &length);
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_all(&request.head()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    server.stop.take().unwrap().send(()).unwrap();
    // Past the readiness removal the server stops taking connections, and waits for this one.
    eventually("the server to stop taking connections", || {
        std::net::TcpStream::connect(server.address).is_err()
    })
    .await;
    assert!(!server.serving.is_finished());

    stream.write_all(&request.body).await.unwrap();
    let answer = read_answer(&mut stream).await;
    assert_eq!(answer.status, 503, "{answer:?}");
    assert_eq!(
        answer.json(),
        json!({"jsonrpc": "2.0", "id": null, "error": {
            "code": INTERNAL_ERROR,
            "message": SHUTTING_DOWN,
        }})
    );
    server.assert_nothing_ran();
    let stopped = tokio::time::timeout(PATIENCE, &mut server.serving).await;
    stopped.expect("the server stopped").unwrap().unwrap();
}
