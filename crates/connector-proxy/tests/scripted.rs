//! The connector against an upstream that answers with scripted bytes: exactly what is sent,
//! and how each kind of answer the mock server never gives is mapped.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{
    GATEWAY_TOKEN, Harness, READ_UPSTREAM, Scripted, Step, chunk, chunked_head, connector,
    json_response, last_chunk, response, result_of_size, text_result, upstream,
};
use connector_proxy::{
    DEFAULT_MAX_RESPONSE_BYTES, ListError, ListedTool, PROTOCOL_VERSION, Upstream, outcome,
};
use gateway_core::audit::{Answer, ErrorKind, Outcome};
use gateway_core::{ReceiptState, ToolName};
use gateway_testkit::{DRAFT_TOOL, READ_TOOL};
use serde_json::{Value, json};

const CAP: usize = 1000;
const DEADLINE: Duration = Duration::from_millis(500);

fn arguments() -> Value {
    json!({"project": "atlas", "document": "plan"})
}

/// A connector to `server` with a small cap and a short deadline, serving the draft tool, which
/// is classified `propose`, besides the fixture's read tools.
fn bounded(server: &Scripted) -> connector_proxy::ProxyConnector {
    connector(Upstream {
        deadline: DEADLINE,
        max_response_bytes: CAP,
        ..upstream(server.url()).tool(ToolName::parse(DRAFT_TOOL).unwrap(), "draft_document")
    })
}

/// The answer to one call to `tool`, and the outcome its row records.
async fn recorded(
    tool: &str,
    steps: impl Fn(&Value) -> Vec<Step> + Send + Sync + 'static,
) -> (Answer, Outcome) {
    let server = Scripted::start(steps).await;
    let harness = Harness::new();
    let answer = harness.call(&bounded(&server), tool, arguments()).await;
    let row = harness.rows().pop().unwrap();
    (answer, row.completion.unwrap().outcome)
}

async fn answer_to(steps: impl Fn(&Value) -> Vec<Step> + Send + Sync + 'static) -> Answer {
    timed_answer_to(steps).await.0
}

/// The answer, and how long the call alone took.
async fn timed_answer_to(
    steps: impl Fn(&Value) -> Vec<Step> + Send + Sync + 'static,
) -> (Answer, Duration) {
    let server = Scripted::start(steps).await;
    let harness = Harness::new();
    let connector = bounded(&server);
    let started = Instant::now();
    let answer = harness.call(&connector, READ_TOOL, arguments()).await;
    (answer, started.elapsed())
}

async fn answer_with(body: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Answer {
    answer_to(move |request| vec![Step::Write(json_response(&body(request)))]).await
}

/// A script made at run time, for a table of cases.
type BoxedScript = Box<dyn Fn(&Value) -> Vec<Step> + Send + Sync>;

fn not_mcp() -> Answer {
    Answer::Error(outcome::NOT_MCP.to_owned())
}

#[tokio::test]
async fn the_request_carries_the_gateway_credential_and_only_the_call() {
    let server =
        Scripted::start(|request| vec![Step::Write(json_response(&text_result(request, "fine")))])
            .await;
    let harness = Harness::new();
    let arguments = json!({"project": "atlas", "document": "plan", "note": "passed through"});

    let answer = harness
        .call(&bounded(&server), READ_TOOL, arguments.clone())
        .await;

    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
    let received = server.received();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(request.request_line, "POST /mcp HTTP/1.1");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {GATEWAY_TOKEN}").as_str())
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/event-stream")
    );
    assert_eq!(
        request.header("mcp-protocol-version"),
        Some(PROTOCOL_VERSION)
    );
    let mut names: Vec<&str> = request
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "accept",
            "authorization",
            "content-length",
            "content-type",
            "host",
            "mcp-protocol-version"
        ]
    );
    let caller = harness.caller_token();
    assert!(
        request
            .headers
            .iter()
            .all(|(_, value)| !value.contains(caller)),
        "the caller's token was sent: {:?}",
        request.headers
    );
    assert_eq!(
        request.body,
        json!({
            "jsonrpc": "2.0",
            "id": request.body["id"],
            "method": "tools/call",
            "params": {"name": READ_UPSTREAM, "arguments": arguments},
        })
    );
    assert!(request.body["id"].is_u64(), "{}", request.body);
}

#[tokio::test]
async fn a_403_is_the_servers_refusal() {
    let answer = answer_to(|_| {
        vec![Step::Write(response(
            "403 Forbidden",
            "application/json",
            br#"{"error":"insufficient_scope"}"#,
        ))]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::UPSTREAM_REFUSED.to_owned()));
}

/// From a read. From a side effect a `403` is `unknown`: see
/// `a_side_effect_the_server_answered_with_a_failure_is_unknown`.
#[tokio::test]
async fn a_403_is_recorded_as_a_vendor_refusal() {
    let (answer, outcome) = recorded(READ_TOOL, |_| {
        vec![Step::Write(response("403 Forbidden", "text/plain", b"no"))]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::UPSTREAM_REFUSED.to_owned()));
    assert_eq!(
        outcome,
        Outcome::Error {
            error_kind: ErrorKind::VendorRefusal
        }
    );
}

#[tokio::test]
async fn a_401_is_recorded_as_another_error() {
    let (answer, outcome) = recorded(READ_TOOL, |_| {
        vec![Step::Write(response(
            "401 Unauthorized",
            "text/plain",
            b"no",
        ))]
    })
    .await;

    assert_eq!(
        answer,
        Answer::Error(outcome::CREDENTIAL_REJECTED.to_owned())
    );
    assert_eq!(
        outcome,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
}

/// The answer to one call to `tool`, the outcome its row records, and the state of the receipt
/// it reserved, if it reserved one.
async fn settled(
    tool: &str,
    steps: impl Fn(&Value) -> Vec<Step> + Send + Sync + 'static,
) -> (Answer, Outcome, Option<ReceiptState>) {
    let server = Scripted::start(steps).await;
    let harness = Harness::new();
    let answer = harness.call(&bounded(&server), tool, arguments()).await;
    let row = harness.rows().pop().unwrap();
    let receipt = harness.store.receipts().pop().map(|receipt| receipt.state);
    (answer, row.completion.unwrap().outcome, receipt)
}

/// An answer too large, too late or broken off is its own kind of error from a tool classified
/// `read`. From the draft tool, classified `propose`, the request may have been acted on, so it
/// is `unknown`, and so is its receipt (decision 0009): an error would settle the receipt as
/// `not_performed` and invite the caller to try again.
#[tokio::test]
async fn an_oversized_or_late_answer_is_its_own_kind_from_a_read_and_unknown_from_a_side_effect() {
    fn too_large(request: &Value) -> Vec<Step> {
        vec![Step::Write(response(
            "200 OK",
            "application/json",
            &result_of_size(request, CAP + 1),
        ))]
    }
    fn declared_too_large(_: &Value) -> Vec<Step> {
        vec![
            Step::Write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n"
                    .to_vec(),
            ),
            Step::Hang,
        ]
    }
    fn late(_: &Value) -> Vec<Step> {
        vec![Step::Sleep(DEADLINE * 3)]
    }
    fn broken_off(request: &Value) -> Vec<Step> {
        let body = text_result(request, "cut short").to_string().into_bytes();
        vec![Step::Write(
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
                body[..body.len() / 2].to_vec(),
            ]
            .concat(),
        )]
    }
    type Script = fn(&Value) -> Vec<Step>;
    let cases: [(&str, Script, &str); 4] = [
        ("too large", too_large, outcome::TOO_LARGE),
        ("declared too large", declared_too_large, outcome::TOO_LARGE),
        ("late", late, outcome::TIMED_OUT),
        ("broken off", broken_off, outcome::BROKEN_OFF),
    ];
    for (case, steps, sentence) in cases {
        let (answer, outcome, receipt) = settled(READ_TOOL, steps).await;
        assert_eq!(answer, Answer::Error(sentence.to_owned()), "{case}");
        assert_eq!(
            outcome,
            Outcome::Error {
                error_kind: ErrorKind::OversizedOrLateRead
            },
            "{case}"
        );
        assert_eq!(receipt, None, "{case}: a read reserved a receipt");

        let (answer, outcome, receipt) = settled(DRAFT_TOOL, steps).await;
        assert!(
            matches!(&answer, Answer::Unknown(sentence) if sentence.contains("Do not repeat it")),
            "{case}: {answer:?}"
        );
        assert_eq!(outcome, Outcome::Unknown, "{case}");
        assert_eq!(receipt, Some(ReceiptState::Unknown), "{case}");
    }
}

/// From a side effect, every other failure once the request may have been sent is `unknown`
/// too: a status that is neither `200` nor `4xx`, whatever its body, a `200` that is not MCP,
/// and a connection the server closed without answering. From a read each is an error.
#[tokio::test]
async fn a_side_effect_with_no_definite_answer_is_unknown() {
    let status = |status: &'static str| {
        move |request: &Value| {
            vec![Step::Write(response(
                status,
                "application/json",
                text_result(request, "looks fine").to_string().as_bytes(),
            ))]
        }
    };
    let cases: Vec<(&str, BoxedScript)> = vec![
        ("500", Box::new(status("500 Internal Server Error"))),
        ("502", Box::new(status("502 Bad Gateway"))),
        ("202", Box::new(status("202 Accepted"))),
        ("201", Box::new(status("201 Created"))),
        ("303", Box::new(status("303 See Other"))),
        (
            "not MCP",
            Box::new(|_: &Value| {
                vec![Step::Write(response("200 OK", "text/html", b"<p>done</p>"))]
            }),
        ),
        ("closed unanswered", Box::new(|_: &Value| Vec::new())),
    ];
    for (case, steps) in cases {
        let steps = std::sync::Arc::new(steps);
        let script = {
            let steps = steps.clone();
            move |request: &Value| steps(request)
        };
        let (answer, outcome, receipt) = settled(DRAFT_TOOL, script).await;
        assert!(matches!(answer, Answer::Unknown(_)), "{case}: {answer:?}");
        assert_eq!(outcome, Outcome::Unknown, "{case}");
        assert_eq!(receipt, Some(ReceiptState::Unknown), "{case}");

        let script = move |request: &Value| steps(request);
        let (answer, outcome, _) = settled(READ_TOOL, script).await;
        assert!(matches!(answer, Answer::Error(_)), "{case}: {answer:?}");
        assert_eq!(
            outcome,
            Outcome::Error {
                error_kind: ErrorKind::Other
            },
            "{case}"
        );
    }
}

/// A side effect the server answered with a refusal or a failure is `unknown`, and so is its
/// receipt: a `4xx`, a JSON-RPC error and a tool result marked `isError` come after the
/// request was sent and do not establish that nothing took effect. Decision 0009 holds a
/// proxied tool's error to be `unknown` unless its approval says its errors are safe, which
/// no approval can say yet. From a read each is an error of its kind.
#[tokio::test]
async fn a_side_effect_the_server_answered_with_a_failure_is_unknown() {
    let status = |status: &'static str| {
        move |_: &Value| vec![Step::Write(response(status, "text/plain", b"no"))]
    };
    let cases: Vec<(&str, BoxedScript, ErrorKind)> = vec![
        ("400", Box::new(status("400 Bad Request")), ErrorKind::Other),
        (
            "401",
            Box::new(status("401 Unauthorized")),
            ErrorKind::Other,
        ),
        (
            "403",
            Box::new(status("403 Forbidden")),
            ErrorKind::VendorRefusal,
        ),
        ("409", Box::new(status("409 Conflict")), ErrorKind::Other),
        (
            "JSON-RPC error",
            Box::new(|request: &Value| {
                vec![Step::Write(json_response(&json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32602, "message": "No such document."},
                })))]
            }),
            ErrorKind::Other,
        ),
        (
            "isError",
            Box::new(|request: &Value| {
                vec![Step::Write(json_response(&json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {"content": [{"type": "text", "text": "Refused."}], "isError": true},
                })))]
            }),
            ErrorKind::Other,
        ),
    ];
    for (case, steps, kind) in cases {
        let steps = std::sync::Arc::new(steps);
        let script = {
            let steps = steps.clone();
            move |request: &Value| steps(request)
        };
        let (answer, outcome, receipt) = settled(DRAFT_TOOL, script).await;
        assert!(
            matches!(&answer, Answer::Unknown(sentence) if sentence.contains("Do not repeat it")),
            "{case}: {answer:?}"
        );
        assert_eq!(outcome, Outcome::Unknown, "{case}");
        assert_eq!(receipt, Some(ReceiptState::Unknown), "{case}");

        let script = move |request: &Value| steps(request);
        let (answer, outcome, receipt) = settled(READ_TOOL, script).await;
        assert!(matches!(answer, Answer::Error(_)), "{case}: {answer:?}");
        assert_eq!(outcome, Outcome::Error { error_kind: kind }, "{case}");
        assert_eq!(receipt, None, "{case}: a read reserved a receipt");
    }
}

/// A side effect whose connection could not be made sent nothing: it is an error, and its
/// receipt is settled as `not_performed`.
#[tokio::test]
async fn a_side_effect_that_could_not_connect_is_an_error_and_not_performed() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", closed.local_addr().unwrap());
    drop(closed);
    let connector = connector(Upstream {
        deadline: DEADLINE,
        max_response_bytes: CAP,
        ..upstream(&url).tool(ToolName::parse(DRAFT_TOOL).unwrap(), "draft_document")
    });
    let harness = Harness::new();
    let answer = harness.call(&connector, DRAFT_TOOL, arguments()).await;
    assert_eq!(answer, Answer::Error(outcome::UNREACHABLE.to_owned()));
    assert_eq!(
        harness.rows().pop().unwrap().completion.unwrap().outcome,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(
        harness.store.receipts().pop().map(|receipt| receipt.state),
        Some(ReceiptState::NotPerformed)
    );
}

#[tokio::test]
async fn any_other_status_is_an_error_even_with_a_result_in_its_body() {
    for status in ["500 Internal Server Error", "202 Accepted", "201 Created"] {
        let answer = answer_to(move |request| {
            vec![Step::Write(response(
                status,
                "application/json",
                text_result(request, "looks fine").to_string().as_bytes(),
            ))]
        })
        .await;
        let code: u16 = status[..3].parse().unwrap();
        assert_eq!(answer, Answer::Error(outcome::status(code)), "{status}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let elsewhere = Scripted::start(|request| {
        vec![Step::Write(json_response(&text_result(
            request,
            "elsewhere",
        )))]
    })
    .await;
    let location = elsewhere.url().to_owned();
    let answer = answer_to(move |_| {
        vec![Step::Write(
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes(),
        )]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::status(307)));
    assert!(elsewhere.received().is_empty());
}

#[tokio::test]
async fn an_answer_to_another_request_is_not_mcp() {
    let answer = answer_with(|request| {
        let mut body = text_result(request, "fine");
        body["id"] = json!(request["id"].as_u64().unwrap() + 1);
        body
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn an_answer_without_the_json_rpc_version_is_not_mcp() {
    let answer = answer_with(|request| {
        let mut body = text_result(request, "fine");
        body["jsonrpc"] = json!("1.0");
        body
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn a_result_without_content_is_not_mcp() {
    let answer = answer_with(|request| {
        json!({"jsonrpc": "2.0", "id": request["id"], "result": {"structuredContent": {}}})
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn an_answer_with_both_a_result_and_an_error_is_not_mcp() {
    let answer = answer_with(|request| {
        let mut body = text_result(request, "fine");
        body["error"] = json!({"code": -32603, "message": "and also not"});
        body
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn an_answer_that_is_not_json_is_not_mcp() {
    let answer = answer_to(|_| {
        vec![Step::Write(response(
            "200 OK",
            "application/json",
            b"<html>hello</html>",
        ))]
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn an_answer_of_another_media_type_is_not_mcp_even_if_it_parses() {
    let answer = answer_to(|request| {
        vec![Step::Write(response(
            "200 OK",
            "text/event-stream",
            text_result(request, "fine").to_string().as_bytes(),
        ))]
    })
    .await;

    assert_eq!(answer, not_mcp());
}

#[tokio::test]
async fn json_with_parameters_and_any_case_is_json() {
    let answer = answer_to(|request| {
        vec![Step::Write(response(
            "200 OK",
            "Application/JSON; charset=utf-8",
            text_result(request, "fine").to_string().as_bytes(),
        ))]
    })
    .await;

    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
}

#[tokio::test]
async fn a_failed_tool_with_no_text_is_an_error_with_a_fixed_sentence() {
    let answer = answer_with(|request| {
        json!({"jsonrpc": "2.0", "id": request["id"], "result": {
            "content": [{"type": "image", "data": "AAAA", "mimeType": "image/png"}],
            "isError": true,
        }})
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TOOL_FAILED.to_owned()));
}

#[tokio::test]
async fn text_from_the_server_is_cut_and_has_no_control_characters() {
    let long = format!("line one\nline\u{7}two{}", "y".repeat(5000));
    // Longer than the small cap the other tests use, so this one keeps the default.
    let server = Scripted::start(move |request| {
        vec![Step::Write(json_response(&json!({
            "jsonrpc": "2.0", "id": request["id"], "error": {"code": -32000, "message": long},
        })))]
    })
    .await;
    let answer = Harness::new()
        .call(&connector(upstream(server.url())), READ_TOOL, arguments())
        .await;

    let Answer::Error(sentence) = answer else {
        panic!("expected an error, got {answer:?}");
    };
    let prefix = "This tool's server answered with error -32000: ";
    let message = sentence.strip_prefix(prefix).unwrap();
    assert!(message.starts_with("line one line two"), "{message}");
    assert_eq!(message.chars().count(), outcome::MAX_MESSAGE_CHARS + 1);
    assert!(message.ends_with("y…"), "{message}");
}

#[tokio::test]
async fn an_answer_of_exactly_the_cap_is_read() {
    let answer = answer_to(|request| {
        vec![Step::Write(response(
            "200 OK",
            "application/json",
            &result_of_size(request, CAP),
        ))]
    })
    .await;

    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
}

#[tokio::test]
async fn an_answer_one_byte_over_the_cap_is_discarded() {
    let answer = answer_to(|request| {
        vec![Step::Write(response(
            "200 OK",
            "application/json",
            &result_of_size(request, CAP + 1),
        ))]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TOO_LARGE.to_owned()));
}

#[tokio::test]
async fn a_chunked_answer_of_exactly_the_cap_is_read() {
    let answer = answer_to(|request| {
        let body = result_of_size(request, CAP);
        let (first, second) = body.split_at(CAP / 2);
        vec![Step::Write(
            [chunked_head(), chunk(first), chunk(second), last_chunk()].concat(),
        )]
    })
    .await;

    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
}

#[tokio::test]
async fn a_chunked_answer_one_byte_over_the_cap_is_discarded() {
    let answer = answer_to(|request| {
        let body = result_of_size(request, CAP + 1);
        let (first, second) = body.split_at(CAP / 2);
        vec![Step::Write(
            [chunked_head(), chunk(first), chunk(second), last_chunk()].concat(),
        )]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TOO_LARGE.to_owned()));
}

#[tokio::test]
async fn an_endless_answer_is_discarded_at_the_cap_not_the_deadline() {
    let (answer, took) = timed_answer_to(|_| {
        let mut steps = vec![Step::Write(chunked_head())];
        // Ten times the cap, then nothing more: the connector must stop reading at the cap.
        for _ in 0..10 {
            steps.push(Step::Write(chunk(&[b' '; CAP])));
        }
        steps.push(Step::Hang);
        steps
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TOO_LARGE.to_owned()));
    assert!(took < DEADLINE, "took {took:?}");
}

#[tokio::test]
async fn a_declared_length_over_the_cap_is_refused_before_the_body_arrives() {
    let (answer, took) = timed_answer_to(|_| {
        vec![
            Step::Write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n"
                    .to_vec(),
            ),
            Step::Hang,
        ]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TOO_LARGE.to_owned()));
    assert!(took < DEADLINE, "took {took:?}");
}

#[tokio::test]
async fn the_deadline_covers_the_body_not_only_the_head() {
    let (answer, took) = timed_answer_to(|request| {
        let body = text_result(request, "late").to_string().into_bytes();
        let (first, second) = body.split_at(10);
        vec![
            Step::Write(chunked_head()),
            Step::Write(chunk(first)),
            Step::Sleep(DEADLINE * 3),
            Step::Write([chunk(second), last_chunk()].concat()),
        ]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::TIMED_OUT.to_owned()));
    assert!(took >= DEADLINE && took < DEADLINE * 3, "took {took:?}");
}

#[tokio::test]
async fn an_answer_that_breaks_off_is_an_error() {
    let answer = answer_to(|request| {
        let body = text_result(request, "cut short").to_string().into_bytes();
        vec![Step::Write(
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .into_bytes(),
                body[..body.len() / 2].to_vec(),
            ]
            .concat(),
        )]
    })
    .await;

    assert_eq!(answer, Answer::Error(outcome::BROKEN_OFF.to_owned()));
}

#[tokio::test]
async fn by_default_an_answer_of_64_kib_is_read_and_one_byte_more_is_not() {
    assert_eq!(DEFAULT_MAX_RESPONSE_BYTES, 64 * 1024);
    for (size, fits) in [
        (DEFAULT_MAX_RESPONSE_BYTES, true),
        (DEFAULT_MAX_RESPONSE_BYTES + 1, false),
    ] {
        let server = Scripted::start(move |request| {
            vec![Step::Write(response(
                "200 OK",
                "application/json",
                &result_of_size(request, size),
            ))]
        })
        .await;
        let answer = Harness::new()
            .call(&connector(upstream(server.url())), READ_TOOL, arguments())
            .await;
        assert_eq!(matches!(answer, Answer::Ok(_)), fits, "{size}: {answer:?}");
    }
}

/// A `tools/list` answer to `request` listing `tools`.
fn tool_list(request: &Value, tools: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": request["id"], "result": {"tools": tools}})
}

/// The read tool as a server lists it.
fn listed_read() -> Value {
    json!({"name": READ_UPSTREAM, "description": "Reads a document.",
           "inputSchema": {"type": "object"}})
}

/// The drift pass's own request carries the gateway's credential for the connector and asks for
/// the tool list alone, with no `initialize`, and the tools come back as served.
#[tokio::test]
async fn the_list_request_carries_the_gateway_credential_and_asks_only_for_the_list() {
    let server = Scripted::start(|request| {
        vec![Step::Write(json_response(&tool_list(
            request,
            json!([listed_read(), {"name": "unapproved", "title": "Other"}]),
        )))]
    })
    .await;

    let tools = bounded(&server).list_tools().await.unwrap();

    assert_eq!(
        tools,
        [
            ListedTool {
                name: READ_UPSTREAM.into(),
                title: None,
                description: Some("Reads a document.".into()),
                input_schema: Some(json!({"type": "object"})),
            },
            ListedTool {
                name: "unapproved".into(),
                title: Some("Other".into()),
                description: None,
                input_schema: None,
            },
        ]
    );
    let received = server.received();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(request.request_line, "POST /mcp HTTP/1.1");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {GATEWAY_TOKEN}").as_str())
    );
    assert_eq!(
        request.header("mcp-protocol-version"),
        Some(PROTOCOL_VERSION)
    );
    assert_eq!(
        request.body,
        json!({"jsonrpc": "2.0", "id": request.body["id"], "method": "tools/list", "params": {}})
    );
}

/// The list is abandoned at the connector's deadline, the body included.
#[tokio::test]
async fn the_list_is_abandoned_at_the_deadline() {
    let server = Scripted::start(|request| {
        let body = tool_list(request, json!([listed_read()]))
            .to_string()
            .into_bytes();
        let (first, second) = body.split_at(10);
        vec![
            Step::Write(chunked_head()),
            Step::Write(chunk(first)),
            Step::Sleep(DEADLINE * 3),
            Step::Write([chunk(second), last_chunk()].concat()),
        ]
    })
    .await;
    let started = Instant::now();

    let listed = bounded(&server).list_tools().await;

    let took = started.elapsed();
    assert_eq!(listed, Err(ListError::TimedOut));
    assert!(took >= DEADLINE && took < DEADLINE * 3, "took {took:?}");
}

/// A list larger than the connector's cap is discarded, whether its length is declared or not;
/// one of exactly the cap is read.
#[tokio::test]
async fn a_list_over_the_cap_is_discarded() {
    fn padded(request: &Value, size: usize) -> Vec<u8> {
        let empty = tool_list(request, json!([{"name": ""}])).to_string().len();
        let body = tool_list(request, json!([{"name": "x".repeat(size - empty)}])).to_string();
        assert_eq!(body.len(), size);
        body.into_bytes()
    }
    for (size, chunked, fits) in [
        (CAP, false, true),
        (CAP + 1, false, false),
        (CAP, true, true),
        (CAP + 1, true, false),
    ] {
        let server = Scripted::start(move |request| {
            let body = padded(request, size);
            if chunked {
                vec![Step::Write(
                    [chunked_head(), chunk(&body), last_chunk()].concat(),
                )]
            } else {
                vec![Step::Write(response("200 OK", "application/json", &body))]
            }
        })
        .await;
        let listed = bounded(&server).list_tools().await;
        if fits {
            assert_eq!(listed.unwrap().len(), 1, "{size}, chunked {chunked}");
        } else {
            assert_eq!(
                listed,
                Err(ListError::TooLarge),
                "{size}, chunked {chunked}"
            );
        }
    }
}

/// A redirect is a failed list, and is not followed.
#[tokio::test]
async fn a_list_redirect_is_not_followed() {
    let elsewhere = Scripted::start(|request| {
        vec![Step::Write(json_response(&tool_list(
            request,
            json!([listed_read()]),
        )))]
    })
    .await;
    let location = elsewhere.url().to_owned();
    let server = Scripted::start(move |_| {
        vec![Step::Write(
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes(),
        )]
    })
    .await;

    let listed = bounded(&server).list_tools().await;

    assert_eq!(listed, Err(ListError::Status(307)));
    assert!(elsewhere.received().is_empty());
}

/// A list that names a next page is a failed list: the tools on later pages must not look
/// removed, and later pages are not read.
#[tokio::test]
async fn a_list_with_a_next_page_is_a_failed_list() {
    let server = Scripted::start(|request| {
        let mut answer = tool_list(request, json!([listed_read()]));
        answer["result"]["nextCursor"] = json!("page-2");
        vec![Step::Write(json_response(&answer))]
    })
    .await;

    let listed = bounded(&server).list_tools().await;

    assert_eq!(listed, Err(ListError::Paginated));
    assert_eq!(server.received().len(), 1);
}
