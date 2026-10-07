//! Golden JSON for every envelope the adapter sends: status, headers and body.
//!
//! Each case is compared with `tests/golden/<name>.json`. After a deliberate change to an
//! envelope, regenerate them with `GOLDEN_UPDATE=1 cargo test -p gateway-mcp --test golden` and
//! read the diff before committing it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::Raw;
use gateway_mcp::{
    CHALLENGE, CLIENT_CAPABILITIES_META, Era, HttpResponse, Inbound, PROTOCOL_VERSION_META,
    Rejection, Reply, RequestId, SESSION_ID_HEADER, ServerInfo, ToolEntry, render,
};
use http::Method;
use serde_json::{Value, json};

/// The 401 message the gateway passes in. A stand-in for the core's identity sentence: this
/// crate does not depend on the core, so the real sentence is checked in the gateway's tests.
const DUMMY_IDENTITY_SENTENCE: &str = "Dummy identity sentence for the golden files.";

fn server() -> ServerInfo {
    ServerInfo {
        name: "switchboard".to_owned(),
        version: "0.1.0".to_owned(),
        instructions: Some("Dummy instructions for the golden files.".to_owned()),
    }
}

fn tools() -> Vec<ToolEntry> {
    vec![
        ToolEntry {
            name: "read_document".to_owned(),
            title: Some("Read a document".to_owned()),
            description: "Reads one document the caller's team may see.".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {"document": {"type": "string"}},
                "required": ["document"],
                "additionalProperties": false,
            }),
            read_only: true,
        },
        ToolEntry {
            name: "propose_change".to_owned(),
            title: None,
            description: "Proposes a change for a person to review.".to_owned(),
            input_schema: json!({"type": "object"}),
            read_only: false,
        },
    ]
}

fn reply(era: Era, id: RequestId, reply: Reply) -> HttpResponse {
    render(&server(), era, &id, reply)
}

fn refusal(raw: Raw) -> HttpResponse {
    raw.parse()
        .expect_err("the request was accepted")
        .response()
}

#[rustfmt::skip]
fn cases() -> Vec<(&'static str, HttpResponse)> {
    use Era::{Legacy, Modern};
    let one = || RequestId::Number(1);
    let named = || RequestId::String("call-7".to_owned());
    vec![
        // Results.
        ("initialize", reply(Legacy, one(), Reply::Initialized)),
        ("ping", reply(Legacy, one(), Reply::Pong)),
        ("discover", reply(Modern, one(), Reply::Discovered)),
        ("tools-list-legacy", reply(Legacy, one(), Reply::Tools(tools()))),
        ("tools-list-modern", reply(Modern, one(), Reply::Tools(tools()))),
        ("tools-list-empty-modern", reply(Modern, one(), Reply::Tools(vec![]))),
        ("tool-ok-object-legacy", reply(Legacy, one(), Reply::ToolOk(json!({"document": "team-a-notes", "text": "Dummy notes."})))),
        ("tool-ok-object-modern", reply(Modern, named(), Reply::ToolOk(json!({"document": "team-a-notes", "text": "Dummy notes."})))),
        ("tool-ok-string-legacy", reply(Legacy, one(), Reply::ToolOk(json!("plain")))),
        ("tool-ok-string-modern", reply(Modern, one(), Reply::ToolOk(json!("plain")))),
        ("tool-error-legacy", reply(Legacy, one(), Reply::ToolError("The tool failed: dummy cause.".to_owned()))),
        ("tool-error-modern", reply(Modern, one(), Reply::ToolError("The tool failed: dummy cause.".to_owned()))),
        // Errors the gateway decides.
        ("denied-legacy", reply(Legacy, one(), Reply::Denied("Dummy denial sentence.".to_owned()))),
        ("denied-modern", reply(Modern, named(), Reply::Denied("Dummy denial sentence.".to_owned()))),
        ("internal", reply(Modern, one(), Reply::Internal("Internal error".to_owned()))),
        ("notification-accepted", HttpResponse::accepted()),
        // Refusals the HTTP layer builds.
        ("unauthorized", Rejection::unauthorized(DUMMY_IDENTITY_SENTENCE).response()),
        ("forbidden-host", Rejection::forbidden_host().response()),
        ("forbidden-origin", Rejection::forbidden_origin().response()),
        ("payload-too-large", Rejection::payload_too_large().response()),
        // Refusals from the parser.
        ("get", refusal(Raw::legacy(json!(1), "ping", Value::Null).method(Method::GET))),
        ("delete", refusal(Raw::legacy(json!(1), "ping", Value::Null).method(Method::DELETE))),
        ("unsupported-media-type", refusal(Raw::legacy(json!(1), "ping", Value::Null).header("content-type", "text/plain"))),
        ("not-acceptable", refusal(Raw::legacy(json!(1), "ping", Value::Null).header("accept", "text/event-stream"))),
        ("parse-error", refusal(Raw::post("{"))),
        ("batch", refusal(Raw::json(&json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])))),
        ("null-id", refusal(Raw::json(&json!({"jsonrpc": "2.0", "id": null, "method": "ping"})))),
        ("posted-response", refusal(Raw::json(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})))),
        ("legacy-unsupported-header", refusal(Raw::legacy(json!(1), "tools/list", json!({})).header("mcp-protocol-version", "2025-03-26"))),
        ("legacy-invalid-params", refusal(Raw::legacy(json!(1), "tools/call", json!({})))),
        ("legacy-method-not-found", refusal(Raw::legacy(json!(1), "resources/list", json!({})))),
        ("modern-missing-version-header", refusal(Raw::modern(json!(1), "tools/list", json!({})).without("mcp-protocol-version"))),
        ("modern-method-header-mismatch", refusal(Raw::modern(json!(1), "tools/list", json!({})).header("mcp-method", "tools/call"))),
        ("modern-name-header-mismatch", refusal(Raw::modern(json!(1), "tools/call", json!({"name": "read_document"})).header("mcp-name", "propose_change"))),
        ("modern-unsupported-version", refusal(Raw::modern(json!(1), "tools/list", json!({"_meta": {PROTOCOL_VERSION_META: "2027-01-01"}})).header("mcp-protocol-version", "2027-01-01"))),
        ("modern-missing-capabilities", refusal(Raw::modern(json!(1), "tools/list", json!({"_meta": {CLIENT_CAPABILITIES_META: null}})))),
        ("modern-method-not-found", refusal(Raw::modern(json!(1), "ping", json!({})))),
    ]
}

fn as_json(response: &HttpResponse) -> Value {
    let headers: BTreeMap<String, String> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
        .collect();
    let body = if response.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&response.body).expect("the body is not JSON")
    };
    json!({"status": response.status.as_u16(), "headers": headers, "body": body})
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.json"))
}

#[test]
fn every_envelope_matches_its_golden_file() {
    let update = std::env::var_os("GOLDEN_UPDATE").is_some();
    let mut failures = Vec::new();
    for (name, response) in cases() {
        let actual = as_json(&response);
        let path = golden_path(name);
        if update {
            let text = serde_json::to_string_pretty(&actual).unwrap() + "\n";
            std::fs::write(&path, text).unwrap();
            continue;
        }
        let expected: Value = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap(),
            Err(_) => {
                failures.push(format!("{name}: no golden file at {}", path.display()));
                continue;
            }
        };
        if expected != actual {
            failures.push(format!(
                "{name}:\n  expected {expected}\n  actual   {actual}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_golden_file_has_a_case() {
    let names: Vec<&str> = cases().iter().map(|(name, _)| *name).collect();
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    for entry in std::fs::read_dir(directory).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        let name = file.strip_suffix(".json").unwrap();
        assert!(names.contains(&name), "tests/golden/{file} has no case");
    }
}

#[test]
fn no_response_carries_a_session() {
    for (name, response) in cases() {
        assert!(
            response.headers.get(SESSION_ID_HEADER).is_none(),
            "{name} carries Mcp-Session-Id"
        );
    }
}

#[test]
fn every_response_with_a_body_is_json_and_a_notification_has_none() {
    for (name, response) in cases() {
        if response.body.is_empty() {
            assert_eq!(
                response.status, 202,
                "{name} has an empty body but is not 202"
            );
            assert!(
                response.headers.is_empty(),
                "{name} has headers but no body"
            );
        } else {
            assert_eq!(
                response.headers.get("content-type").unwrap(),
                "application/json",
                "{name}"
            );
        }
    }
}

#[test]
fn a_parsed_notification_is_answered_with_202_and_nothing_else() {
    let Ok(Inbound::Notification { .. }) = Raw::notification("notifications/initialized").parse()
    else {
        panic!("the notification was not accepted")
    };
    let response = HttpResponse::accepted();
    assert_eq!(response.status, 202);
    assert!(response.body.is_empty());
}

#[test]
fn initialize_answers_the_legacy_version_whatever_was_asked() {
    for asked in ["2025-11-25", "2025-03-26", "2026-07-28", "2024-11-05"] {
        let raw = Raw::legacy(json!(1), "initialize", json!({"protocolVersion": asked}));
        let Ok(Inbound::Request(request)) = raw.parse() else {
            panic!("initialize was refused")
        };
        let body = as_json(&render(
            &server(),
            request.era,
            &request.id,
            Reply::Initialized,
        ));
        assert_eq!(body["body"]["result"]["protocolVersion"], "2025-06-18");
    }
}

#[test]
fn the_identity_failure_is_the_same_bytes_every_time_and_challenges() {
    let first = Rejection::unauthorized(DUMMY_IDENTITY_SENTENCE).response();
    let second = Rejection::unauthorized(DUMMY_IDENTITY_SENTENCE).response();
    assert_eq!(first, second);
    assert_eq!(first.headers.get("www-authenticate").unwrap(), CHALLENGE);
    assert_eq!(first.headers.len(), 2);
}

#[test]
fn a_modern_list_is_private_to_the_caller_and_discovery_is_public() {
    let list = as_json(&reply(
        Era::Modern,
        RequestId::Number(1),
        Reply::Tools(tools()),
    ));
    assert_eq!(list["body"]["result"]["cacheScope"], "private");
    assert_eq!(list["body"]["result"]["ttlMs"], 0);
    let discover = as_json(&reply(Era::Modern, RequestId::Number(1), Reply::Discovered));
    assert_eq!(
        discover["body"]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
}
