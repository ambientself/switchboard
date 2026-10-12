//! The probe of a self-built server (decision 0010, "Self-built servers at registration")
//! against upstreams that answer with scripted bytes, and against the mock server: the three
//! calls it sends, and the verdict each kind of answer comes to.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{
    GATEWAY_TOKEN, Received, Scripted, Step, TemporaryFile, connector, json_response, response,
    upstream,
};
use connector_proxy::{
    CallVerdict, MALFORMED_CREDENTIAL, NotShown, PROBE_TOOL, PROTOCOL_VERSION, ProbeCall,
    ProbeCredential, ProbeError, ProbeFinding, ProbeReport, Upstream, UpstreamError, probe,
};
use gateway_core::ConnectorName;
use mock_docs_server::{AcceptedCredential, Config};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// The probe credential: a stranger's, which no server here accepts. A dummy.
const FOREIGN: &str = "dummy-stranger-token-for-the-probe-tests";

const DEADLINE: Duration = Duration::from_millis(500);

/// The server at `url`, with the probe tests' bounds.
fn target(url: &str) -> Upstream {
    Upstream {
        deadline: DEADLINE,
        max_response_bytes: 1000,
        ..Upstream::new("docs", url)
    }
}

/// A probe credential file holding [`FOREIGN`], and the credential read from it.
fn foreign() -> (TemporaryFile, ProbeCredential) {
    let file = TemporaryFile::new(format!("{FOREIGN}\n").as_bytes());
    let credential = ProbeCredential::load(ConnectorName::new("docs"), file.path()).unwrap();
    (file, credential)
}

/// The bearer `request` carries, if any.
fn bearer(request: &Received) -> Option<&str> {
    request
        .header("authorization")
        .map(|value| value.strip_prefix("Bearer ").unwrap())
}

/// A `401` with a challenge and a body that is not JSON-RPC, as the mock server refuses.
fn challenge() -> Vec<u8> {
    challenge_with(br#"{"error": "unauthorized"}"#)
}

/// A `401` with a challenge, carrying `body`.
fn challenge_with(body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"docs\"\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// A JSON-RPC error answering `request`, as a server that dispatched the call gives it.
fn rpc_error(request: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "error": {"code": -32602, "message": "Unknown tool"},
    })
}

/// A server that refuses as decision 0010 requires: `401` with a challenge with no credential
/// or a malformed one, and `403` for any other.
fn refusing(request: &Received) -> Vec<Step> {
    match bearer(request) {
        None | Some(MALFORMED_CREDENTIAL) => vec![Step::Write(challenge())],
        Some(_) => vec![Step::Write(response(
            "403 Forbidden",
            "text/plain",
            b"forbidden",
        ))],
    }
}

/// Probes a scripted server and returns the report and what it received.
async fn probed(
    script: impl Fn(&Received) -> Vec<Step> + Send + Sync + 'static,
) -> (ProbeReport, Vec<Received>) {
    let server = Scripted::start_for(script).await;
    let (_file, credential) = foreign();
    let report = probe(&target(server.url()), &credential).await.unwrap();
    (report, server.received())
}

fn verdicts(report: &ProbeReport) -> Vec<(ProbeCall, CallVerdict)> {
    report.calls().to_vec()
}

#[tokio::test]
async fn proper_refusals_are_refused() {
    let (report, received) = probed(refusing).await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::Refused))
    );
    assert_eq!(report.finding(), ProbeFinding::Refused);
    assert!(report.dispatched().is_empty());
    // Three calls, each for a tool that does not exist, sent as a call is.
    assert_eq!(received.len(), 3, "{received:?}");
    for request in &received {
        assert_eq!(request.request_line, "POST /mcp HTTP/1.1");
        assert_eq!(request.body["method"], "tools/call");
        assert_eq!(request.body["params"]["name"], PROBE_TOOL);
        assert_eq!(request.body["params"]["arguments"], json!({}));
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(
            request.header("mcp-protocol-version"),
            Some(PROTOCOL_VERSION)
        );
    }
}

#[tokio::test]
async fn the_foreign_token_is_sent_on_the_third_call_only() {
    let (_, received) = probed(refusing).await;

    let mut sent: Vec<(u64, Option<String>)> = received
        .iter()
        .map(|request| {
            (
                request.body["id"].as_u64().unwrap(),
                bearer(request).map(str::to_owned),
            )
        })
        .collect();
    sent.sort();
    assert_eq!(
        sent,
        [
            (1, None),
            (2, Some(MALFORMED_CREDENTIAL.to_owned())),
            (3, Some(FOREIGN.to_owned())),
        ]
    );
    assert!(
        received
            .iter()
            .all(|request| bearer(request) != Some(GATEWAY_TOKEN))
    );
}

#[tokio::test]
async fn a_401_without_a_challenge_is_not_shown() {
    let (report, _) = probed(|_| {
        vec![Step::Write(response(
            "401 Unauthorized",
            "application/json",
            br#"{"error": "unauthorized"}"#,
        ))]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        [
            (
                ProbeCall::NoCredential,
                CallVerdict::NotShown(NotShown::NoChallenge)
            ),
            (
                ProbeCall::MalformedCredential,
                CallVerdict::NotShown(NotShown::NoChallenge)
            ),
            // The third call needs no challenge.
            (ProbeCall::ForeignToken, CallVerdict::Refused),
        ]
    );
    assert_eq!(report.finding(), ProbeFinding::NotShown);
}

#[tokio::test]
async fn a_401_carrying_a_json_rpc_error_is_open() {
    let (report, _) = probed(|request| {
        vec![Step::Write(challenge_with(
            rpc_error(&request.body).to_string().as_bytes(),
        ))]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::Open))
    );
    assert_eq!(report.finding(), ProbeFinding::Open);
}

#[tokio::test]
async fn a_401_carrying_a_json_rpc_error_in_a_stream_event_split_over_data_lines_is_open() {
    let (report, _) = probed(|request| {
        let error = serde_json::to_string_pretty(&rpc_error(&request.body)).unwrap();
        let mut event = String::from("event: message\r\n");
        for line in error.lines() {
            event.push_str(&format!("data: {line}\r\n"));
        }
        event.push_str("\r\n");
        let mut bytes = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"docs\"\r\n\
             Content-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            event.len()
        )
        .into_bytes();
        bytes.extend_from_slice(event.as_bytes());
        vec![Step::Write(bytes)]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::Open))
    );
    assert_eq!(report.finding(), ProbeFinding::Open);
}

#[tokio::test]
async fn a_server_that_dispatches_only_the_foreign_token_is_open_on_that_call() {
    let (report, _) = probed(|request| match bearer(request) {
        Some(FOREIGN) => vec![Step::Write(json_response(&rpc_error(&request.body)))],
        _ => vec![Step::Write(challenge())],
    })
    .await;

    assert_eq!(report.finding(), ProbeFinding::Open);
    assert_eq!(report.dispatched(), [ProbeCall::ForeignToken]);
}

#[tokio::test]
async fn a_200_result_is_open() {
    let (report, _) = probed(|request| {
        vec![Step::Write(json_response(&json!({
            "jsonrpc": "2.0",
            "id": request.body["id"],
            "result": {"content": [{"type": "text", "text": "ran"}], "isError": false},
        })))]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::Open))
    );
    assert_eq!(report.finding(), ProbeFinding::Open);
}

#[tokio::test]
async fn a_200_with_no_json_rpc_answer_is_not_shown() {
    let (report, _) =
        probed(|_| vec![Step::Write(response("200 OK", "text/plain", b"hello"))]).await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::Status(200))))
    );
    assert_eq!(report.finding(), ProbeFinding::NotShown);
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_is_not_shown() {
    let (report, received) = probed(|_| {
        vec![Step::Write(
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:9/mcp\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::Status(307))))
    );
    assert_eq!(received.len(), 3);
}

#[tokio::test]
async fn a_refused_connection_is_not_shown_never_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    drop(listener);
    let (_file, credential) = foreign();

    let report = probe(&target(&url), &credential).await.unwrap();

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::Unreachable)))
    );
    assert_eq!(report.finding(), ProbeFinding::NotShown);
}

#[tokio::test]
async fn a_server_that_never_answers_is_not_shown_within_one_deadline() {
    let server = Scripted::start_for(|_| vec![Step::Hang]).await;
    let (_file, credential) = foreign();
    let started = Instant::now();

    let report = probe(&target(server.url()), &credential).await.unwrap();

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::TimedOut)))
    );
    assert_eq!(report.finding(), ProbeFinding::NotShown);
    // The three calls are sent together.
    assert!(started.elapsed() < DEADLINE * 2, "{:?}", started.elapsed());
}

#[tokio::test]
async fn an_answer_past_the_cap_is_not_shown() {
    let (report, _) = probed(|_| {
        let body = format!(r#"{{"error": "{}"}}"#, "x".repeat(2000));
        vec![Step::Write(challenge_with(body.as_bytes()))]
    })
    .await;

    assert_eq!(
        verdicts(&report),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::TooLarge)))
    );
}

#[tokio::test]
async fn an_unreadable_probe_credential_sends_the_first_two_calls_and_shows_nothing_for_the_third()
{
    let server = Scripted::start_for(refusing).await;
    let (file, credential) = foreign();
    std::fs::write(file.path(), "").unwrap();

    let report = probe(&target(server.url()), &credential).await.unwrap();

    assert!(matches!(
        report.calls()[2],
        (
            ProbeCall::ForeignToken,
            CallVerdict::NotShown(NotShown::Credential(_))
        )
    ));
    assert_eq!(report.finding(), ProbeFinding::NotShown);
    assert_eq!(server.received().len(), 2);
}

#[tokio::test]
async fn a_url_that_is_not_http_or_https_with_a_host_is_refused() {
    let (_file, credential) = foreign();
    for url in ["ftp://docs/mcp", "http://user:pw@docs/mcp", "docs"] {
        assert_eq!(
            probe(&target(url), &credential).await.unwrap_err(),
            ProbeError::Upstream(UpstreamError::BadUrl {
                connector: ConnectorName::new("docs"),
                url: url.to_owned()
            })
        );
    }
    // An https server is probed as a connector reaches it, so with its CA file only.
    assert_eq!(
        probe(&target("https://docs.example/mcp"), &credential)
            .await
            .unwrap_err(),
        ProbeError::Upstream(UpstreamError::NoCaFile(ConnectorName::new("docs")))
    );
}

/// The mock server checks its caller: it refuses all three calls, and none reaches a tool.
#[tokio::test]
async fn the_mock_server_refuses_all_three() {
    let server = mock_docs_server::start(Config::new(AcceptedCredential::token(GATEWAY_TOKEN)))
        .await
        .unwrap();
    let (_file, credential) = foreign();

    let report = probe(&Upstream::new("docs", server.url()), &credential)
        .await
        .unwrap();

    assert_eq!(report.finding(), ProbeFinding::Refused, "{report:?}");
}

/// The connector's own probe is held to its bounds and never sends the gateway's credential.
#[tokio::test]
async fn the_connectors_probe_uses_its_bounds_and_not_its_credential() {
    let server = Scripted::start_for(refusing).await;
    let (_file, credential) = foreign();
    let connector = connector(connector_proxy::Upstream {
        deadline: DEADLINE,
        ..upstream(server.url())
    });

    let report = connector.probe(&credential).await;

    assert_eq!(report.finding(), ProbeFinding::Refused);
    let received = server.received();
    assert_eq!(received.len(), 3);
    assert!(
        received
            .iter()
            .all(|request| bearer(request) != Some(GATEWAY_TOKEN))
    );

    let hanging = Scripted::start_for(|_| vec![Step::Hang]).await;
    let connector = common::connector(connector_proxy::Upstream {
        deadline: DEADLINE,
        ..upstream(hanging.url())
    });
    let started = Instant::now();
    let report = connector.probe(&credential).await;
    assert_eq!(report.finding(), ProbeFinding::NotShown);
    assert!(started.elapsed() < DEADLINE * 2, "{:?}", started.elapsed());
}
