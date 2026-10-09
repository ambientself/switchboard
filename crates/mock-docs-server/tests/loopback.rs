//! The server over real HTTP on loopback: the protocol, the one credential, the log, the
//! documents that misbehave and the tool list that changes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use mock_docs_server::{
    AcceptedCredential, Config, FAIL_CODE, HUGE_BYTES, PROTOCOL_VERSION, Running, ToolName, start,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A dummy credential, made up for these tests. It is not a secret anywhere.
const TOKEN: &str = "dummy-gateway-credential-for-tests";
/// Another dummy credential, standing in for a workload's own token.
const OTHER_TOKEN: &str = "dummy-workload-token-for-tests";
const SLOW: Duration = Duration::from_millis(300);

async fn server() -> Running {
    let config = Config {
        slow: SLOW,
        ..Config::new(AcceptedCredential::token(TOKEN))
    };
    start(config).await.unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn prefix(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()[..12]
        .to_owned()
}

/// Posts `body` to the MCP endpoint with `token` as the bearer, if any.
async fn post(server: &Running, token: Option<&str>, body: &str) -> reqwest::Response {
    let mut request = client()
        .post(server.url())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(body.to_owned());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap()
}

/// A JSON-RPC request with the accepted credential; the status and the JSON answer.
async fn rpc(server: &Running, method: &str, params: Value) -> (StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
    let response = post(server, Some(TOKEN), &body.to_string()).await;
    let status = response.status();
    (status, response.json().await.unwrap())
}

async fn call(server: &Running, tool: &str, arguments: Value) -> Value {
    let (status, answer) = rpc(
        server,
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["id"], 7, "{answer}");
    answer
}

fn text(answer: &Value) -> &str {
    assert_eq!(answer["result"]["isError"], false, "{answer}");
    answer["result"]["content"][0]["text"].as_str().unwrap()
}

fn tool_error(answer: &Value) -> &str {
    assert_eq!(answer["result"]["isError"], true, "{answer}");
    answer["result"]["content"][0]["text"].as_str().unwrap()
}

fn tool_names(answer: &Value) -> Vec<String> {
    answer["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

// --- The protocol ------------------------------------------------------------------------

#[tokio::test]
async fn initialize_answers_2025_06_18_without_a_session() {
    let server = server().await;
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
    });
    let response = post(&server, Some(TOKEN), &body.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("mcp-session-id").is_none());
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    let answer: Value = response.json().await.unwrap();
    assert_eq!(answer["id"], 1);
    assert_eq!(answer["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(answer["result"]["serverInfo"]["name"], "mock-docs-server");
    assert!(answer["result"]["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn ping_answers_an_empty_result() {
    let server = server().await;
    let (status, answer) = rpc(&server, "ping", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["result"], json!({}));
}

#[tokio::test]
async fn notifications_and_client_answers_get_202_and_no_body() {
    let server = server().await;
    for body in [
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 3, "result": {}}),
    ] {
        let response = post(&server, Some(TOKEN), &body.to_string()).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(response.bytes().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn unknown_methods_and_malformed_messages_are_refused() {
    let server = server().await;
    let (status, answer) = rpc(&server, "resources/list", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["error"]["code"], -32601);

    for (body, code) in [
        ("{not json", -32700),
        (r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#, -32600),
        (r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":5}"#, -32600),
    ] {
        let response = post(&server, Some(TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        let answer: Value = response.json().await.unwrap();
        assert_eq!(answer["error"]["code"], code, "{body}");
    }
}

#[tokio::test]
async fn an_unsupported_protocol_version_header_gets_400() {
    let server = server().await;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    for (version, status) in [
        ("2025-06-18", StatusCode::OK),
        ("2025-03-26", StatusCode::OK),
        ("2026-07-28", StatusCode::BAD_REQUEST),
        ("not-a-version", StatusCode::BAD_REQUEST),
    ] {
        let response = client()
            .post(server.url())
            .bearer_auth(TOKEN)
            .header("MCP-Protocol-Version", version)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{version}");
    }
}

#[tokio::test]
async fn get_and_delete_on_the_endpoint_get_405_and_other_paths_404() {
    let server = server().await;
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let response = client()
            .request(method.clone(), server.url())
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
        assert_eq!(response.headers()["allow"], "POST");
    }
    let elsewhere = server.url().replace("/mcp", "/other");
    let response = client()
        .post(elsewhere)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- The one credential ------------------------------------------------------------------

#[tokio::test]
async fn only_the_accepted_bearer_gets_an_answer() {
    let server = server().await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    for token in [
        None,
        Some(OTHER_TOKEN),
        Some(""),
        Some("dummy-gateway-credential-for-test"),
    ] {
        let response = post(&server, token, &ping).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{token:?}");
        assert!(
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .starts_with("Bearer"),
        );
    }
    assert_eq!(
        post(&server, Some(TOKEN), &ping).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_scheme_must_be_bearer_in_any_case() {
    let server = server().await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    for (authorization, status) in [
        (format!("bearer {TOKEN}"), StatusCode::OK),
        (format!("BEARER {TOKEN}"), StatusCode::OK),
        (format!("Basic {TOKEN}"), StatusCode::UNAUTHORIZED),
        (TOKEN.to_owned(), StatusCode::UNAUTHORIZED),
        (format!("Bearer {TOKEN}x"), StatusCode::UNAUTHORIZED),
    ] {
        let response = client()
            .post(server.url())
            .header("Authorization", &authorization)
            .body(ping.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{authorization}");
    }
}

/// The kind demo's probe posts `{}` with a workload's token and expects a 401: the credential
/// is checked before the body means anything, on every method and path.
#[tokio::test]
async fn the_credential_is_checked_before_anything_else() {
    let server = server().await;
    for body in ["{}", "{not json", ""] {
        let response = post(&server, Some(OTHER_TOKEN), body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{body:?}");
    }
    let response = client()
        .get(server.url())
        .bearer_auth(OTHER_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let elsewhere = server.url().replace("/mcp", "/other");
    let response = client().post(elsewhere).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = client()
        .post(server.url())
        .bearer_auth(OTHER_TOKEN)
        .header("MCP-Protocol-Version", "not-a-version")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Sends `method path` to `address` with `token` as the bearer and a declared body of 1 MiB,
/// of which not one byte is sent, and returns the status line that comes back within 5 s.
fn status_without_a_body(address: &str, method: &str, path: &str, token: &str) -> String {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: 1048576\r\n\r\n"
    )
    .unwrap();
    let mut answer = Vec::new();
    let mut buffer = [0; 1024];
    while !answer.windows(2).any(|pair| pair == b"\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => answer.extend_from_slice(&buffer[..read]),
        }
    }
    String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap_or("no answer within 5 s")
        .to_owned()
}

/// A refused caller is answered from its headers alone: its body is never waited for, so it
/// cannot hold the server up or make it buffer anything.
#[tokio::test]
async fn a_refused_caller_is_answered_before_its_body_is_read() {
    let server = server().await;
    let mcp = server.address().to_string();
    let admin = server
        .admin_url()
        .trim_start_matches("http://")
        .trim_end_matches("/admin/tools")
        .to_owned();
    let answers = tokio::task::spawn_blocking(move || {
        [
            status_without_a_body(&mcp, "POST", "/mcp", OTHER_TOKEN),
            status_without_a_body(&admin, "PUT", "/admin/tools", OTHER_TOKEN),
        ]
    })
    .await
    .unwrap();
    for answer in answers {
        assert_eq!(answer, "HTTP/1.1 401 Unauthorized");
    }
}

// --- The log -----------------------------------------------------------------------------

#[tokio::test]
async fn each_request_logs_the_hash_prefix_of_the_bearer_it_carried() {
    let server = server().await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    post(&server, Some(TOKEN), &ping).await;
    post(&server, Some(OTHER_TOKEN), &ping).await;
    post(&server, None, &ping).await;
    client()
        .get(server.url())
        .bearer_auth(OTHER_TOKEN)
        .send()
        .await
        .unwrap();

    let lines = server.log_lines();
    let seen: Vec<(Value, Value)> = lines
        .iter()
        .map(|line| (line["bearer_sha256"].clone(), line["accepted"].clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (json!(prefix(TOKEN)), json!(true)),
            (json!(prefix(OTHER_TOKEN)), json!(false)),
            (Value::Null, json!(false)),
            (json!(prefix(OTHER_TOKEN)), json!(false)),
        ]
    );
    assert!(lines.iter().all(|line| line["event"] == "request"));
    assert_eq!(lines[0]["rpc_method"], "ping");
    assert_eq!(lines[3]["http_method"], "GET");
    let all = serde_json::to_string(&lines).unwrap();
    assert!(
        !all.contains(TOKEN) && !all.contains(OTHER_TOKEN),
        "a raw token was logged"
    );
}

#[tokio::test]
async fn a_tool_call_is_logged_before_it_runs_with_its_tool_and_document() {
    let server = server().await;
    let hang = client()
        .post(server.url())
        .bearer_auth(TOKEN)
        .timeout(Duration::from_millis(300))
        .body(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "read_document", "arguments": {"project": "atlas", "document": "hang-doc"}}})
            .to_string(),
        )
        .send()
        .await;
    assert!(hang.unwrap_err().is_timeout());
    let lines = server.log_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["rpc_method"], "tools/call");
    assert_eq!(lines[0]["tool"], "read_document");
    assert_eq!(lines[0]["project"], "atlas");
    assert_eq!(lines[0]["document"], "hang-doc");
    assert_eq!(lines[0]["bearer_sha256"], prefix(TOKEN));
}

// --- The tools and the documents ---------------------------------------------------------

#[tokio::test]
async fn tools_list_offers_the_two_read_tools_with_their_schemas() {
    let server = server().await;
    let (_, answer) = rpc(&server, "tools/list", json!({})).await;
    assert_eq!(tool_names(&answer), ["list_documents", "read_document"]);
    let read = &answer["result"]["tools"][1];
    assert_eq!(
        read["inputSchema"]["required"],
        json!(["project", "document"])
    );
    assert_eq!(read["inputSchema"]["additionalProperties"], false);
    assert_eq!(read["annotations"]["readOnlyHint"], true);
}

#[tokio::test]
async fn each_project_lists_its_plan_and_the_documents_that_misbehave() {
    let server = server().await;
    for project in ["atlas", "borealis"] {
        let answer = call(&server, "list_documents", json!({"project": project})).await;
        let expected = json!({
            "project": project,
            "documents": ["fail-doc", "hang-doc", "huge-doc", "plan", "slow-doc"],
        });
        assert_eq!(answer["result"]["structuredContent"], expected);
        assert_eq!(
            serde_json::from_str::<Value>(text(&answer)).unwrap(),
            expected
        );
    }
    let answer = call(&server, "list_documents", json!({"project": "gamma"})).await;
    assert_eq!(tool_error(&answer), "There is no project `gamma`.");
}

#[tokio::test]
async fn a_document_is_found_by_its_project_and_name_together() {
    let server = server().await;
    let atlas = call(
        &server,
        "read_document",
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    let borealis = call(
        &server,
        "read_document",
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert!(text(&atlas).contains("project atlas"), "{atlas}");
    assert!(text(&borealis).contains("project borealis"), "{borealis}");
    assert!(!text(&borealis).contains("atlas"), "{borealis}");

    for (project, document) in [
        ("gamma", "plan"),
        ("atlas", "nothing"),
        ("atlas/plan", ""),
        ("", "atlas/plan"),
    ] {
        let answer = call(
            &server,
            "read_document",
            json!({"project": project, "document": document}),
        )
        .await;
        assert_eq!(
            tool_error(&answer),
            format!("There is no document `{document}` in project `{project}`."),
        );
    }
}

#[tokio::test]
async fn arguments_must_be_the_declared_strings_and_nothing_else() {
    let server = server().await;
    for arguments in [
        json!({}),
        json!({"project": "atlas"}),
        json!({"project": "atlas", "document": 5}),
        json!({"project": "atlas", "document": "plan", "team": "a"}),
    ] {
        let (_, answer) = rpc(
            &server,
            "tools/call",
            json!({"name": "read_document", "arguments": arguments}),
        )
        .await;
        assert_eq!(answer["error"]["code"], -32602, "{arguments}");
    }
    let (_, answer) = rpc(&server, "tools/call", json!({"arguments": {}})).await;
    assert_eq!(answer["error"]["code"], -32602);
}

#[tokio::test]
async fn slow_doc_answers_only_after_the_delay() {
    let server = server().await;
    let started = Instant::now();
    let answer = call(
        &server,
        "read_document",
        json!({"project": "borealis", "document": "slow-doc"}),
    )
    .await;
    assert!(
        started.elapsed() >= SLOW,
        "answered after {:?}",
        started.elapsed()
    );
    assert!(text(&answer).starts_with("slow-doc answered"));
}

#[tokio::test]
async fn hang_doc_never_answers_and_the_server_carries_on() {
    let server = server().await;
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "read_document", "arguments": {"project": "atlas", "document": "hang-doc"}}});
    // Longer than the slow document takes, so a hang that is really a delay is told apart.
    let wait = SLOW * 4;
    let started = Instant::now();
    let error = client()
        .post(server.url())
        .bearer_auth(TOKEN)
        .timeout(wait)
        .body(body.to_string())
        .send()
        .await
        .unwrap_err();
    assert!(error.is_timeout(), "{error}");
    assert!(started.elapsed() >= wait);
    let (status, _) = rpc(&server, "ping", json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn fail_doc_answers_with_a_json_rpc_error() {
    let server = server().await;
    let answer = call(
        &server,
        "read_document",
        json!({"project": "atlas", "document": "fail-doc"}),
    )
    .await;
    assert!(answer.get("result").is_none(), "{answer}");
    assert_eq!(answer["error"]["code"], FAIL_CODE);
    assert_eq!(answer["error"]["message"], "fail-doc fails on purpose.");
}

#[tokio::test]
async fn huge_doc_answers_with_one_mebibyte() {
    let server = server().await;
    let answer = call(
        &server,
        "read_document",
        json!({"project": "borealis", "document": "huge-doc"}),
    )
    .await;
    assert_eq!(HUGE_BYTES, 1024 * 1024);
    assert_eq!(text(&answer).len(), HUGE_BYTES);
}

// --- The tool list changes ---------------------------------------------------------------

#[tokio::test]
async fn a_withdrawn_tool_is_neither_listed_nor_callable() {
    let server = server().await;
    server.server().set_tools(vec![ToolName::ReadDocument]);
    let (_, answer) = rpc(&server, "tools/list", json!({})).await;
    assert_eq!(tool_names(&answer), ["read_document"]);
    let (_, answer) = rpc(
        &server,
        "tools/call",
        json!({"name": "list_documents", "arguments": {"project": "atlas"}}),
    )
    .await;
    assert_eq!(answer["error"]["code"], -32602);
    assert_eq!(answer["error"]["message"], "Unknown tool: list_documents");
    call(
        &server,
        "read_document",
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
}

#[tokio::test]
async fn search_documents_is_offered_only_when_added() {
    let server = server().await;
    let arguments = json!({"project": "atlas", "query": "project atlas"});
    let (_, answer) = rpc(
        &server,
        "tools/call",
        json!({"name": "search_documents", "arguments": arguments}),
    )
    .await;
    assert_eq!(answer["error"]["code"], -32602);

    server.server().set_tools(vec![
        ToolName::ListDocuments,
        ToolName::ReadDocument,
        ToolName::SearchDocuments,
    ]);
    let (_, answer) = rpc(&server, "tools/list", json!({})).await;
    assert_eq!(
        tool_names(&answer),
        ["list_documents", "read_document", "search_documents"]
    );
    let answer = call(&server, "search_documents", arguments).await;
    assert_eq!(
        answer["result"]["structuredContent"]["documents"],
        json!(["plan"])
    );
    let answer = call(
        &server,
        "search_documents",
        json!({"project": "borealis", "query": "project atlas"}),
    )
    .await;
    assert_eq!(
        answer["result"]["structuredContent"]["documents"],
        json!([])
    );
}

#[tokio::test]
async fn the_admin_endpoint_changes_the_tool_list_for_the_accepted_credential_only() {
    let server = server().await;
    let put = |token: &'static str, body: Value| {
        client()
            .put(server.admin_url())
            .bearer_auth(token)
            .json(&body)
            .send()
    };
    let response = put(OTHER_TOKEN, json!({"tools": []})).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = client().get(server.admin_url()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for body in [
        json!({"tools": ["read_document", "delete_document"]}),
        json!({"tools": ["read_document", "read_document"]}),
        json!({}),
    ] {
        let response = put(TOKEN, body.clone()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    let (_, answer) = rpc(&server, "tools/list", json!({})).await;
    assert_eq!(tool_names(&answer), ["list_documents", "read_document"]);

    let response = put(TOKEN, json!({"tools": ["read_document"]}))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"tools": ["read_document"]})
    );
    let (_, answer) = rpc(&server, "tools/list", json!({})).await;
    assert_eq!(tool_names(&answer), ["read_document"]);
    let response = client()
        .get(server.admin_url())
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"tools": ["read_document"]})
    );

    let admin: Vec<Value> = server
        .log_lines()
        .into_iter()
        .filter(|line| line["event"] == "admin")
        .collect();
    assert_eq!(admin.len(), 7, "{admin:?}");
    assert_eq!(admin[0]["bearer_sha256"], prefix(OTHER_TOKEN));
    assert_eq!(admin[0]["accepted"], false);
}
