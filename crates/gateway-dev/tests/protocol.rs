//! The protocol end to end: the 2026-07-28 header checks and the transport's refusals, sent by
//! a caller with a valid token. None of them reaches the connector or writes a row.
//!
//! Plan #26's tests 8 and 9, and test 7's 2025-06-18 shape with no version header.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use gateway::MAX_BODY_BYTES;
use gateway_dev::{FixtureGateway, start_fixture_gateway};
use gateway_mcp::{
    CLIENT_CAPABILITIES_META, Era, HEADER_MISMATCH, INVALID_PARAMS, INVALID_REQUEST,
    LAST_EVENT_ID_HEADER, LEGACY, METHOD_HEADER, METHOD_NOT_FOUND, MODERN, NAME_HEADER,
    PARSE_ERROR, PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, SESSION_ID_HEADER,
    UNSUPPORTED_VERSION,
};
use gateway_testkit::{Caller, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT, WRITE_TOOL};
use serde_json::{Value, json};
use support::{Answer, PATIENCE, Request, assert_nothing_ran, call_params, document, legacy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Team A's 2026-07-28 read of its own document, which is served as it is.
fn modern_read(gateway: &FixtureGateway) -> Request {
    Request::modern(
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .bearer(&gateway.token(Caller::TeamA))
}

/// A 2025-06-18 request from team A, with no version header.
fn legacy_request(gateway: &FixtureGateway, body: &Value) -> Request {
    Request::post(&gateway.url(SURFACE_READ), body).bearer(&gateway.token(Caller::TeamA))
}

fn sentinel(text: &str) -> String {
    format!("=?base64?{}?=", STANDARD.encode(text))
}

fn assert_refused(answer: &Answer, status: u16, code: i64, what: &str) {
    let body = answer.json();
    assert_eq!(answer.status, status, "{what}: {body}");
    assert_eq!(answer.error().0, code, "{what}: {body}");
    assert_eq!(
        answer.header("content-type"),
        Some("application/json"),
        "{what}"
    );
}

// --- The 2026-07-28 header checks ------------------------------------------------------------

#[tokio::test]
async fn a_modern_request_whose_headers_do_not_match_its_body_is_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    let read = || modern_read(&gateway);
    let cases = [
        (
            "no MCP-Protocol-Version",
            read().without(PROTOCOL_VERSION_HEADER),
        ),
        (
            "an MCP-Protocol-Version that disagrees with _meta",
            read()
                .without(PROTOCOL_VERSION_HEADER)
                .header(PROTOCOL_VERSION_HEADER, LEGACY),
        ),
        (
            "two MCP-Protocol-Version headers",
            read().header(PROTOCOL_VERSION_HEADER, MODERN),
        ),
        ("no Mcp-Method", read().without(METHOD_HEADER)),
        (
            "an Mcp-Method that names another method",
            read()
                .without(METHOD_HEADER)
                .header(METHOD_HEADER, "tools/list"),
        ),
        ("no Mcp-Name", read().without(NAME_HEADER)),
        (
            "an Mcp-Name that names another tool",
            read().without(NAME_HEADER).header(NAME_HEADER, WRITE_TOOL),
        ),
        (
            "an encoded Mcp-Name that names another tool",
            read()
                .without(NAME_HEADER)
                .header(NAME_HEADER, &sentinel(WRITE_TOOL)),
        ),
        (
            "an Mcp-Name that is not valid base64 in the sentinel",
            read()
                .without(NAME_HEADER)
                .header(NAME_HEADER, "=?base64?not base64!?="),
        ),
    ];
    for (what, request) in cases {
        let answer = request.send().await;
        assert_refused(&answer, 400, HEADER_MISMATCH, what);
        assert_eq!(answer.json()["id"], json!(1), "{what}");
    }
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn an_unsupported_version_is_refused_naming_the_one_supported() {
    let gateway = start_fixture_gateway().await.unwrap();
    let answer = modern_read(&gateway)
        .without(PROTOCOL_VERSION_HEADER)
        .header(PROTOCOL_VERSION_HEADER, "2099-01-01")
        .json(|body| body["params"]["_meta"][PROTOCOL_VERSION_META] = json!("2099-01-01"))
        .send()
        .await;
    assert_refused(&answer, 400, UNSUPPORTED_VERSION, "an unsupported version");
    assert_eq!(
        answer.json()["error"]["data"],
        json!({"supported": [MODERN], "requested": "2099-01-01"})
    );
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn a_modern_request_without_the_clients_capabilities_is_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    for capabilities in [None, Some(json!("all")), Some(json!(null))] {
        let answer = modern_read(&gateway)
            .json(|body| {
                let meta = body["params"]["_meta"].as_object_mut().unwrap();
                match &capabilities {
                    None => {
                        meta.remove(CLIENT_CAPABILITIES_META);
                    }
                    Some(value) => {
                        meta.insert(CLIENT_CAPABILITIES_META.to_owned(), value.clone());
                    }
                }
            })
            .send()
            .await;
        assert_refused(
            &answer,
            400,
            INVALID_PARAMS,
            &format!("capabilities {capabilities:?}"),
        );
    }
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn a_tool_name_in_the_base64_sentinel_is_decoded_and_served() {
    let gateway = start_fixture_gateway().await.unwrap();
    for header in [
        READ_TOOL.to_owned(),
        sentinel(READ_TOOL),
        format!("=?base64?{}?=", STANDARD_NO_PAD.encode(READ_TOOL)),
    ] {
        let answer = modern_read(&gateway)
            .without(NAME_HEADER)
            .header(NAME_HEADER, &header)
            .send()
            .await;
        let (is_error, result) = answer.tool_result();
        assert!(!is_error, "{header}: {result}");
    }
    assert_eq!(gateway.connector().received().len(), 3);
}

#[tokio::test]
async fn a_name_no_header_can_carry_is_sent_encoded_and_denied_on_the_record() {
    let gateway = start_fixture_gateway().await.unwrap();
    let name = "fixture__read\n`; DROP TABLE audit; é";
    let answer = Request::modern(
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .json(|body| body["params"]["name"] = json!(name))
    .without(NAME_HEADER)
    .header(NAME_HEADER, &sentinel(name))
    .bearer(&gateway.token(Caller::TeamA))
    .send()
    .await;
    let sentence = answer.denial();
    // The name is the caller's text: escaped in the sentence and on the row, never raw.
    assert!(!sentence.contains('\n'), "{sentence:?}");
    assert!(!sentence.contains('é'), "{sentence:?}");
    let row = gateway.store().row(0).unwrap();
    assert_eq!(row.sentence.as_deref(), Some(sentence.as_str()));
    assert!(
        row.tool.chars().all(|c| c.is_ascii_graphic() || c == ' '),
        "{:?}",
        row.tool
    );
    assert_eq!(gateway.connector().received(), Vec::new());
}

#[tokio::test]
async fn an_answer_carries_the_requests_own_identifier() {
    let gateway = start_fixture_gateway().await.unwrap();
    for id in [json!("call-7"), json!(0), json!(-3), json!(i64::MAX)] {
        for era in [Era::Legacy, Era::Modern] {
            let answer = Request::in_era(era, &gateway.url(SURFACE_READ), "tools/list", json!({}))
                .json(|body| body["id"] = id.clone())
                .bearer(&gateway.token(Caller::TeamB))
                .send()
                .await;
            assert_eq!(answer.json()["id"], id, "{era}");
        }
    }
    // An identifier that is neither a string nor an integer is refused.
    for id in [json!(1.5), json!(u64::MAX), json!({"n": 1}), json!(true)] {
        let answer = legacy_request(&gateway, &legacy("tools/list", json!({})))
            .json(|body| body["id"] = id.clone())
            .send()
            .await;
        assert_refused(&answer, 400, INVALID_REQUEST, &id.to_string());
    }
}

#[tokio::test]
async fn a_call_whose_params_are_malformed_is_refused_before_any_decision() {
    let gateway = start_fixture_gateway().await.unwrap();
    let url = gateway.url(SURFACE_READ);
    let token = gateway.token(Caller::TeamA);
    for (what, params) in [
        ("no name", json!({"arguments": document(TEAM_A_DOCUMENT)})),
        ("a name that is not text", json!({"name": 7})),
        (
            "arguments that are not an object",
            json!({"name": READ_TOOL, "arguments": [TEAM_A_DOCUMENT]}),
        ),
    ] {
        // 2025-06-18 answers with 200, as for other JSON-RPC errors; 2026-07-28 with 400.
        let answer = legacy_request(&gateway, &legacy("tools/call", params.clone()))
            .send()
            .await;
        assert_refused(&answer, 200, INVALID_PARAMS, what);
        let answer = Request::modern(&url, "tools/call", params)
            .header(NAME_HEADER, READ_TOOL)
            .bearer(&token)
            .send()
            .await;
        assert_refused(&answer, 400, INVALID_PARAMS, what);
    }
    let answer = legacy_request(
        &gateway,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "fixture__read"}),
    )
    .send()
    .await;
    assert_refused(
        &answer,
        200,
        INVALID_PARAMS,
        "params that are not an object",
    );
    assert_nothing_ran(&gateway);
}

// --- The 2025-06-18 era ------------------------------------------------------------------------

#[tokio::test]
async fn a_legacy_conversation_with_no_version_header_is_served_with_no_session() {
    let gateway = start_fixture_gateway().await.unwrap();
    // Otto's callers: no MCP-Protocol-Version, no Accept beyond the client's default, and a
    // session header from an older revision, which is ignored.
    let initialized = legacy_request(
        &gateway,
        &legacy(
            "initialize",
            json!({"protocolVersion": MODERN, "capabilities": {}, "clientInfo": {"name": "otto-harness", "version": "1"}}),
        ),
    )
    .send()
    .await
    .result();
    assert_eq!(initialized["protocolVersion"], json!(LEGACY));
    assert_eq!(
        initialized["capabilities"]["tools"],
        json!({"listChanged": false})
    );
    assert_eq!(
        initialized["serverInfo"]["name"],
        json!(gateway::SERVER_NAME)
    );

    let notified = legacy_request(
        &gateway,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .send()
    .await;
    assert_eq!((notified.status, notified.bytes.len()), (202, 0));

    let pong = legacy_request(&gateway, &legacy("ping", json!({})))
        .header(SESSION_ID_HEADER, "a-session-from-another-server")
        .header(LAST_EVENT_ID_HEADER, "7")
        .send()
        .await
        .result();
    assert_eq!(pong, json!({}));

    let read = legacy_request(
        &gateway,
        &legacy(
            "tools/call",
            call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
        ),
    )
    .send()
    .await;
    let (is_error, result) = read.tool_result();
    assert!(!is_error, "{result}");
    assert_eq!(
        result["structuredContent"]["echo"],
        document(TEAM_A_DOCUMENT)
    );

    // The version a legacy client agreed on is served too; any other is refused.
    let listed = legacy_request(&gateway, &legacy("tools/list", json!({})))
        .header(PROTOCOL_VERSION_HEADER, LEGACY)
        .send()
        .await;
    listed.result();
    let refused = legacy_request(&gateway, &legacy("tools/list", json!({})))
        .header(PROTOCOL_VERSION_HEADER, "2025-03-26")
        .send()
        .await;
    assert_refused(&refused, 400, INVALID_REQUEST, "an older version header");
    assert_eq!(gateway.store().rows().len(), 1);
}

// --- The transport -----------------------------------------------------------------------------

#[tokio::test]
async fn only_post_is_answered() {
    let gateway = start_fixture_gateway().await.unwrap();
    for method in ["GET", "DELETE", "PUT", "PATCH"] {
        let answer = legacy_request(&gateway, &legacy("tools/list", json!({})))
            .method(method)
            .send()
            .await;
        assert_eq!(answer.status, 405, "{method}");
        assert_eq!(answer.header("allow"), Some("POST"), "{method}");
    }
    // A GET for an event stream, as a 2025-03-26 client opens one, is not served either.
    let answer = Request::post(&gateway.url(SURFACE_READ), &json!({}))
        .method("GET")
        .without("content-type")
        .header("accept", "text/event-stream")
        .bearer(&gateway.token(Caller::TeamA))
        .body(Vec::new())
        .send()
        .await;
    assert_eq!(answer.status, 405);
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn an_unknown_method_is_not_found_and_ping_is_not_served_in_the_modern_era() {
    let gateway = start_fixture_gateway().await.unwrap();
    let url = gateway.url(SURFACE_READ);
    let token = gateway.token(Caller::TeamA);
    for method in ["ping", "resources/list", "initialize/again"] {
        let answer = Request::modern(&url, method, json!({}))
            .bearer(&token)
            .send()
            .await;
        assert_refused(&answer, 404, METHOD_NOT_FOUND, method);
    }
    // A legacy client is told the same with 200, so it does not take the endpoint for missing.
    let answer = legacy_request(&gateway, &legacy("resources/list", json!({})))
        .send()
        .await;
    assert_refused(&answer, 200, METHOD_NOT_FOUND, "a legacy unknown method");
    // server/discover is a modern method only.
    let answer = legacy_request(&gateway, &legacy("server/discover", json!({})))
        .send()
        .await;
    assert_refused(&answer, 200, METHOD_NOT_FOUND, "a legacy server/discover");
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn what_is_not_one_json_rpc_request_is_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    let request = |body: &[u8]| legacy_request(&gateway, &json!({})).body(body.to_vec());
    let one = legacy(
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    );
    let cases: [(&str, Vec<u8>, i64); 6] = [
        (
            "invalid JSON",
            b"{\"jsonrpc\": \"2.0\",".to_vec(),
            PARSE_ERROR,
        ),
        ("an empty body", Vec::new(), PARSE_ERROR),
        (
            "a batch",
            json!([one.clone(), one.clone()]).to_string().into_bytes(),
            INVALID_REQUEST,
        ),
        (
            "a null id",
            {
                let mut body = one.clone();
                body["id"] = Value::Null;
                body.to_string().into_bytes()
            },
            INVALID_REQUEST,
        ),
        (
            "a response",
            json!({"jsonrpc": "2.0", "id": 1, "result": {}})
                .to_string()
                .into_bytes(),
            INVALID_REQUEST,
        ),
        ("a JSON string", b"\"tools/call\"".to_vec(), INVALID_REQUEST),
    ];
    for (what, body, code) in cases {
        let answer = request(&body).send().await;
        assert_refused(&answer, 400, code, what);
    }
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn a_body_not_declared_as_json_or_an_answer_not_accepted_as_json_is_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    let list = || legacy_request(&gateway, &legacy("tools/list", json!({})));
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/json; charset=latin1"),
    ] {
        let mut request = list().without("content-type");
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let answer = request.send().await;
        assert_eq!(answer.status, 415, "{content_type:?}");
    }
    let answer = list().header("accept", "text/event-stream").send().await;
    assert_eq!(answer.status, 406);
    // A client that takes either is answered with JSON.
    let answer = list()
        .header("accept", "application/json, text/event-stream")
        .send()
        .await;
    assert_eq!(answer.header("content-type"), Some("application/json"));
    answer.result();
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn a_body_declared_over_the_limit_is_refused_before_it_is_sent() {
    let gateway = start_fixture_gateway().await.unwrap();
    // Written by hand: an HTTP client still sending a body this size when the gateway answers
    // and closes may see the connection reset rather than the answer. Here only the head is
    // sent, and the answer must come without the body.
    let head = format!(
        "POST /mcp/{SURFACE_READ} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\n\
         authorization: Bearer {}\r\ncontent-length: {}\r\n\r\n",
        gateway.address(),
        gateway.token(Caller::TeamA),
        MAX_BODY_BYTES + 1,
    );
    let mut stream = TcpStream::connect(gateway.address()).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut answer))
        .await
        .expect("an answer without the body")
        .unwrap();
    let answer = String::from_utf8(answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 413 "), "{answer}");
    assert!(
        answer.contains(r#""message":"Payload too large""#),
        "{answer}"
    );
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn a_body_of_the_largest_size_is_read() {
    let gateway = start_fixture_gateway().await.unwrap();
    let mut padded = legacy("tools/list", json!({}));
    let room = MAX_BODY_BYTES - padded.to_string().len() - r#","padding":"""#.len();
    padded["padding"] = json!("x".repeat(room));
    assert_eq!(padded.to_string().len(), MAX_BODY_BYTES);
    let listed = legacy_request(&gateway, &padded).send().await.result();
    assert_eq!(listed["tools"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_notification_is_accepted_with_no_body_and_no_row() {
    let gateway = start_fixture_gateway().await.unwrap();
    for (era, method, params) in [
        (Era::Legacy, "notifications/initialized", json!({})),
        (
            Era::Legacy,
            "notifications/cancelled",
            json!({"requestId": 1, "reason": "the user pressed escape"}),
        ),
        (
            Era::Modern,
            "notifications/cancelled",
            json!({"requestId": 1}),
        ),
        // A notification that names a tool call is not one: nothing runs.
        (
            Era::Legacy,
            "tools/call",
            call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
        ),
    ] {
        let answer = Request::in_era(era, &gateway.url(SURFACE_READ), method, params)
            .json(|body| {
                body.as_object_mut().unwrap().remove("id");
            })
            .bearer(&gateway.token(Caller::TeamA))
            .send()
            .await;
        assert_eq!(answer.status, 202, "{era} {method}: {answer:?}");
        assert!(answer.bytes.is_empty(), "{era} {method}");
        assert_eq!(answer.header("content-type"), None);
    }
    assert_nothing_ran(&gateway);
}
