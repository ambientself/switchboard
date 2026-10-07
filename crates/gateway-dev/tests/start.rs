//! Starting the fixture gateway: it serves on loopback, proves the fixture's callers and
//! records their calls.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_dev::start_fixture_gateway;
use gateway_testkit::{Caller, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// One HTTP/1.1 POST, written by hand, and the status and body that came back.
async fn post(
    address: std::net::SocketAddr,
    path: &str,
    token: &str,
    body: &Value,
) -> (u16, Value) {
    let body = body.to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\
         content-type: application/json\r\nauthorization: Bearer {token}\r\n\
         content-length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let answer = String::from_utf8(answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_fixture_gateway_serves_a_call_and_records_it() {
    let gateway = start_fixture_gateway().await.unwrap();
    assert!(gateway.address().ip().is_loopback());

    let (status, body) = post(
        gateway.address(),
        &format!("/mcp/{SURFACE_READ}"),
        &gateway.token(Caller::TeamA),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": READ_TOOL, "arguments": {"document": TEAM_A_DOCUMENT}}}),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(gateway.connector().received().len(), 1);
    assert_eq!(gateway.store().rows().len(), 1);

    gateway.shutdown().await.unwrap();
}
