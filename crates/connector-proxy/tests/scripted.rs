//! The connector against an upstream that answers with scripted bytes: exactly what is sent,
//! and how each kind of answer the mock server never gives is mapped.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{
    GATEWAY_TOKEN, Harness, READ_UPSTREAM, Scripted, Step, chunk, chunked_head, connector,
    json_response, last_chunk, response, result_of_size, text_result, upstream,
};
use connector_proxy::{DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION, Upstream, outcome};
use gateway_core::audit::{Answer, Outcome};
use gateway_testkit::READ_TOOL;
use serde_json::{Value, json};

const CAP: usize = 1000;
const DEADLINE: Duration = Duration::from_millis(500);

fn arguments() -> Value {
    json!({"project": "atlas", "document": "plan"})
}

/// A connector to `server` with a small cap and a short deadline.
fn bounded(server: &Scripted) -> connector_proxy::ProxyConnector {
    connector(Upstream {
        deadline: DEADLINE,
        max_response_bytes: CAP,
        ..upstream(server.url())
    })
}

async fn answer_to(steps: impl Fn(&Value) -> Vec<Step> + Send + Sync + 'static) -> Answer {
    let server = Scripted::start(steps).await;
    Harness::new()
        .call(&bounded(&server), READ_TOOL, arguments())
        .await
}

async fn answer_with(body: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Answer {
    answer_to(move |request| vec![Step::Write(json_response(&body(request)))]).await
}

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

    assert_eq!(
        answer,
        Answer::Refused(outcome::UPSTREAM_REFUSED.to_owned())
    );
}

#[tokio::test]
async fn a_403_is_recorded_as_refused() {
    let server =
        Scripted::start(|_| vec![Step::Write(response("403 Forbidden", "text/plain", b"no"))])
            .await;
    let harness = Harness::new();

    harness
        .call(&bounded(&server), READ_TOOL, arguments())
        .await;

    let row = harness.rows().pop().unwrap();
    assert_eq!(
        row.completion.unwrap().outcome,
        Outcome::Refused {
            sentence: outcome::UPSTREAM_REFUSED.to_owned()
        }
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
    let started = Instant::now();
    let answer = answer_to(|_| {
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
    assert!(started.elapsed() < DEADLINE, "took {:?}", started.elapsed());
}

#[tokio::test]
async fn a_declared_length_over_the_cap_is_refused_before_the_body_arrives() {
    let started = Instant::now();
    let answer = answer_to(|_| {
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
    assert!(started.elapsed() < DEADLINE, "took {:?}", started.elapsed());
}

#[tokio::test]
async fn the_deadline_covers_the_body_not_only_the_head() {
    let started = Instant::now();
    let answer = answer_to(|request| {
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
    let took = started.elapsed();
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
