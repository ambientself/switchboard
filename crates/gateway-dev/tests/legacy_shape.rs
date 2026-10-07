//! The legacy era as Otto's harness speaks it (plan #26 section 6, test 7): no
//! `MCP-Protocol-Version` header, no `Accept`, only a content type and a token. Every request
//! is served, and no answer ever carries an `Mcp-Session-Id`, even to a client that sends one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_core::audit::DecisionKind;
use gateway_dev::start_fixture_gateway;
use gateway_mcp::{DENIAL_CODE, LEGACY, PROTOCOL_VERSION_HEADER, SESSION_ID_HEADER};
use gateway_testkit::{
    Caller, DOCUMENT_ARGUMENT, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
};
use reqwest::header::HeaderMap;
use serde_json::{Value, json};

/// What came back from one POST.
struct Answer {
    status: u16,
    headers: HeaderMap,
    body: Value,
}

/// Posts a JSON-RPC message with only `Content-Type`, `Authorization` and `extra`.
async fn post(url: &str, token: &str, body: Value, extra: &[(&str, &str)]) -> Answer {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .bearer_auth(token)
        .body(body.to_string());
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    let answer = request.send().await.unwrap();
    let status = answer.status().as_u16();
    let headers = answer.headers().clone();
    let text = answer.text().await.unwrap();
    let body = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap()
    };
    Answer {
        status,
        headers,
        body,
    }
}

fn request(id: i64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn read(id: i64, document: &str) -> Value {
    request(
        id,
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {DOCUMENT_ARGUMENT: document}}),
    )
}

#[tokio::test]
async fn a_legacy_client_with_no_version_header_is_served_throughout() {
    let gateway = start_fixture_gateway().await.unwrap();
    let url = gateway.url(SURFACE_READ);
    let token = gateway.token(Caller::TeamA);
    let mut answers = Vec::new();

    // initialize: answered 2025-06-18 whatever was asked, with no session.
    let initialize = request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "otto-harness", "version": "0"},
        }),
    );
    let answer = post(&url, &token, initialize, &[]).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let result = &answer.body["result"];
    assert_eq!(result["protocolVersion"], json!(LEGACY));
    assert!(result["capabilities"]["tools"].is_object(), "{result}");
    assert!(result["serverInfo"]["name"].is_string(), "{result}");
    assert!(result.get("resultType").is_none(), "{result}");
    answers.push(answer);

    // The initialized notification: 202 and nothing else.
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let answer = post(&url, &token, initialized, &[]).await;
    assert_eq!(answer.status, 202);
    assert!(answer.body.is_null(), "{}", answer.body);
    answers.push(answer);

    // ping.
    let answer = post(&url, &token, request(2, "ping", json!({})), &[]).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["result"], json!({}));
    answers.push(answer);

    // tools/list, as 2025-06-18 shapes it.
    let answer = post(&url, &token, request(3, "tools/list", json!({})), &[]).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let result = &answer.body["result"];
    assert!(result.get("resultType").is_none(), "{result}");
    let names: Vec<&str> = result["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&READ_TOOL), "{names:?}");
    let listed = answer.body.clone();
    answers.push(answer);

    // Team A's own document, then team B's.
    let answer = post(&url, &token, read(4, TEAM_A_DOCUMENT), &[]).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["result"]["isError"], json!(false));
    answers.push(answer);
    let answer = post(&url, &token, read(5, TEAM_B_DOCUMENT), &[]).await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.body["error"]["code"], json!(DENIAL_CODE));
    let sentence = answer.body["error"]["message"].as_str().unwrap().to_owned();
    assert!(sentence.contains(TEAM_B_DOCUMENT), "{sentence}");
    answers.push(answer);

    // The same list with the 2025-06-18 header, and with a session the gateway never issued:
    // the same answer, and the session is not echoed.
    let with_header = post(
        &url,
        &token,
        request(3, "tools/list", json!({})),
        &[(PROTOCOL_VERSION_HEADER, LEGACY)],
    )
    .await;
    assert_eq!(with_header.body, listed);
    answers.push(with_header);
    let with_session = post(
        &url,
        &token,
        request(3, "tools/list", json!({})),
        &[(SESSION_ID_HEADER, "session-from-elsewhere")],
    )
    .await;
    assert_eq!(with_session.body, listed);
    answers.push(with_session);

    for answer in &answers {
        assert!(
            answer.headers.get(SESSION_ID_HEADER).is_none(),
            "a session was issued: {:?}",
            answer.headers
        );
        if !answer.body.is_null() {
            assert_eq!(
                answer.headers.get("content-type").unwrap(),
                "application/json",
                "{:?}",
                answer.headers
            );
        }
    }

    // Two calls, two rows: the read allowed and completed, the other denied with the sentence
    // the caller got.
    let rows = gateway.store().rows();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].decision, DecisionKind::Allow);
    assert!(rows[0].completion.is_some());
    assert_eq!(rows[1].decision, DecisionKind::Deny);
    assert_eq!(rows[1].sentence.as_deref(), Some(sentence.as_str()));
    assert_eq!(gateway.connector().received().len(), 1);
}
