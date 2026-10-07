//! The parser as a table: raw `(method, headers, body)` in, a request, a notification or a
//! refusal out. One row per rule in plan26 section 2 and decision 0007.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::Raw;
use gateway_mcp::{
    CLIENT_CAPABILITIES_META, Call, DENIAL_CODE, Era, HEADER_MISMATCH, INVALID_PARAMS,
    INVALID_REQUEST, Inbound, METHOD_NOT_FOUND, MODERN, PARSE_ERROR, PROTOCOL_VERSION_META,
    RejectionKind, Request, RequestId, TOOL_USE_ID_META, ToolCall, UNSUPPORTED_VERSION,
};
use http::Method;
use serde_json::{Value, json};

enum Expect {
    Accepted(Inbound),
    Refused(RejectionKind, u16, i64),
}

use Expect::{Accepted, Refused};

fn request(id: i64, era: Era, call: Call) -> Expect {
    Accepted(Inbound::Request(Request {
        id: RequestId::Number(id),
        era,
        call,
    }))
}

fn call(name: &str, arguments: Value, tool_use_id: Option<&str>) -> Call {
    let Value::Object(arguments) = arguments else {
        panic!("arguments must be an object")
    };
    Call::ToolsCall(ToolCall {
        name: name.to_owned(),
        arguments,
        tool_use_id: tool_use_id.map(str::to_owned),
    })
}

fn notification(method: &str) -> Expect {
    Accepted(Inbound::Notification {
        method: method.to_owned(),
    })
}

fn sentinel(value: &str) -> String {
    format!("=?base64?{}?=", STANDARD.encode(value))
}

fn read_call() -> Value {
    json!({"name": "read_document", "arguments": {"document": "team-a-notes"}})
}

#[rustfmt::skip]
fn table() -> Vec<(&'static str, Raw, Expect)> {
    use Era::{Legacy, Modern};
    use RejectionKind::*;
    let legacy_list = Raw::legacy(json!(1), "tools/list", json!({}));
    let modern_call = Raw::modern(json!(1), "tools/call", read_call());
    vec![
        // --- Transport ---------------------------------------------------------------------
        ("GET is refused", legacy_list.clone().method(Method::GET), Refused(MethodNotAllowed, 405, INVALID_REQUEST)),
        ("DELETE is refused", legacy_list.clone().method(Method::DELETE), Refused(MethodNotAllowed, 405, INVALID_REQUEST)),
        ("PUT is refused", legacy_list.clone().method(Method::PUT), Refused(MethodNotAllowed, 405, INVALID_REQUEST)),
        ("no content type", legacy_list.clone().without("content-type"), Refused(UnsupportedMediaType, 415, INVALID_REQUEST)),
        ("a text content type", legacy_list.clone().header("content-type", "text/plain"), Refused(UnsupportedMediaType, 415, INVALID_REQUEST)),
        ("a JSON content type with a charset", legacy_list.clone().header("content-type", "application/json; charset=utf-8"), request(1, Legacy, Call::ToolsList)),
        ("two content types", legacy_list.clone().append("content-type", "application/json"), Refused(UnsupportedMediaType, 415, INVALID_REQUEST)),
        ("an Accept without JSON", legacy_list.clone().header("accept", "text/event-stream"), Refused(NotAcceptable, 406, INVALID_REQUEST)),
        ("an Accept refusing JSON", legacy_list.clone().header("accept", "application/json;q=0"), Refused(NotAcceptable, 406, INVALID_REQUEST)),
        ("an Accept of anything", legacy_list.clone().header("accept", "*/*"), request(1, Legacy, Call::ToolsList)),
        ("no Accept, as Otto's callers send", legacy_list.clone().without("accept"), request(1, Legacy, Call::ToolsList)),
        // --- The envelope ------------------------------------------------------------------
        ("not JSON", Raw::post("{not json"), Refused(ParseError, 400, PARSE_ERROR)),
        ("not UTF-8", Raw::post(vec![0xff, 0xfe]), Refused(ParseError, 400, PARSE_ERROR)),
        ("an empty body", Raw::post(""), Refused(ParseError, 400, PARSE_ERROR)),
        ("a batch", Raw::json(&json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("an empty batch", Raw::json(&json!([])), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a string", Raw::json(&json!("ping")), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a null id", Raw::json(&json!({"jsonrpc": "2.0", "id": null, "method": "ping"})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a fractional id", Raw::json(&json!({"jsonrpc": "2.0", "id": 1.5, "method": "ping"})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("an id past i64", Raw::post(r#"{"jsonrpc":"2.0","id":18446744073709551615,"method":"ping"}"#), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("an object id", Raw::json(&json!({"jsonrpc": "2.0", "id": {}, "method": "ping"})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a posted result", Raw::json(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a posted error", Raw::json(&json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "x"}})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("no method", Raw::json(&json!({"jsonrpc": "2.0", "id": 1})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("a method that is not a string", Raw::json(&json!({"jsonrpc": "2.0", "id": 1, "method": 7})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("no jsonrpc", Raw::json(&json!({"id": 1, "method": "ping"})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("jsonrpc 1.0", Raw::json(&json!({"jsonrpc": "1.0", "id": 1, "method": "ping"})), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        // --- Notifications -----------------------------------------------------------------
        ("notifications/initialized", Raw::notification("notifications/initialized"), notification("notifications/initialized")),
        ("notifications/cancelled", Raw::json(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}})), notification("notifications/cancelled")),
        ("a notification with modern headers", Raw::notification("notifications/initialized").header("mcp-protocol-version", MODERN), notification("notifications/initialized")),
        ("a notification still needs a POST", Raw::notification("notifications/initialized").method(Method::GET), Refused(MethodNotAllowed, 405, INVALID_REQUEST)),
        // --- Legacy ------------------------------------------------------------------------
        ("initialize asking for 2025-11-25", Raw::legacy(json!(1), "initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}})), request(1, Legacy, Call::Initialize)),
        ("initialize with no params", Raw::legacy(json!(1), "initialize", Value::Null), request(1, Legacy, Call::Initialize)),
        ("initialize is legacy whatever its headers say", Raw::legacy(json!(1), "initialize", json!({})).header("mcp-protocol-version", MODERN).header("mcp-method", "tools/list"), request(1, Legacy, Call::Initialize)),
        ("initialize is legacy whatever its _meta says", Raw::legacy(json!(1), "initialize", json!({"_meta": {PROTOCOL_VERSION_META: MODERN}})), request(1, Legacy, Call::Initialize)),
        ("ping", Raw::legacy(json!(1), "ping", Value::Null), request(1, Legacy, Call::Ping)),
        ("tools/list with the legacy header", legacy_list.clone().header("mcp-protocol-version", "2025-06-18"), request(1, Legacy, Call::ToolsList)),
        ("tools/list with an older header", legacy_list.clone().header("mcp-protocol-version", "2025-03-26"), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("tools/list with a future header and no _meta", legacy_list.clone().header("mcp-protocol-version", "2027-01-01"), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("tools/list with two legacy headers", legacy_list.clone().header("mcp-protocol-version", "2025-06-18").append("mcp-protocol-version", "2025-06-18"), Refused(InvalidRequest, 400, INVALID_REQUEST)),
        ("tools/list with a cursor", Raw::legacy(json!(1), "tools/list", json!({"cursor": "abc"})), Refused(InvalidParams, 200, INVALID_PARAMS)),
        ("tools/list with a null cursor", Raw::legacy(json!(1), "tools/list", json!({"cursor": null})), request(1, Legacy, Call::ToolsList)),
        ("tools/call", Raw::legacy(json!(1), "tools/call", read_call()), request(1, Legacy, call("read_document", json!({"document": "team-a-notes"}), None))),
        ("tools/call with a tool-use id", Raw::legacy(json!(1), "tools/call", json!({"name": "read_document", "_meta": {TOOL_USE_ID_META: "toolu_01"}})), request(1, Legacy, call("read_document", json!({}), Some("toolu_01")))),
        ("tools/call with a numeric tool-use id", Raw::legacy(json!(1), "tools/call", json!({"name": "read_document", "_meta": {TOOL_USE_ID_META: 7}})), request(1, Legacy, call("read_document", json!({}), None))),
        ("tools/call with null arguments", Raw::legacy(json!(1), "tools/call", json!({"name": "read_document", "arguments": null})), request(1, Legacy, call("read_document", json!({}), None))),
        ("tools/call without a name", Raw::legacy(json!(1), "tools/call", json!({"arguments": {}})), Refused(InvalidParams, 200, INVALID_PARAMS)),
        ("tools/call with a numeric name", Raw::legacy(json!(1), "tools/call", json!({"name": 3})), Refused(InvalidParams, 200, INVALID_PARAMS)),
        ("tools/call with array arguments", Raw::legacy(json!(1), "tools/call", json!({"name": "read_document", "arguments": []})), Refused(InvalidParams, 200, INVALID_PARAMS)),
        ("params that are not an object", Raw::legacy(json!(1), "tools/list", json!([1])), Refused(InvalidParams, 200, INVALID_PARAMS)),
        ("an unknown legacy method", Raw::legacy(json!(1), "resources/list", json!({})), Refused(MethodNotFound, 200, METHOD_NOT_FOUND)),
        ("server/discover without modern markers", Raw::legacy(json!(1), "server/discover", json!({})), Refused(MethodNotFound, 200, METHOD_NOT_FOUND)),
        ("a session header is ignored", legacy_list.clone().header("mcp-session-id", "abc").header("last-event-id", "4"), request(1, Legacy, Call::ToolsList)),
        // --- Modern ------------------------------------------------------------------------
        ("server/discover", Raw::modern(json!(1), "server/discover", json!({})), request(1, Modern, Call::Discover)),
        ("tools/list", Raw::modern(json!(1), "tools/list", json!({})), request(1, Modern, Call::ToolsList)),
        ("tools/list with a cursor", Raw::modern(json!(1), "tools/list", json!({"cursor": "abc"})), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("tools/call", modern_call.clone(), request(1, Modern, call("read_document", json!({"document": "team-a-notes"}), None))),
        ("tools/call with a tool-use id", Raw::modern(json!(1), "tools/call", json!({"name": "read_document", "_meta": {TOOL_USE_ID_META: "toolu_01"}})), request(1, Modern, call("read_document", json!({}), Some("toolu_01")))),
        ("tools/call with a sentinel Mcp-Name", modern_call.clone().header("mcp-name", &sentinel("read_document")), request(1, Modern, call("read_document", json!({"document": "team-a-notes"}), None))),
        ("tools/call with a non-ASCII name in a sentinel", Raw::modern(json!(1), "tools/call", json!({"name": "lire_le_café"})).header("mcp-name", &sentinel("lire_le_café")), request(1, Modern, call("lire_le_café", json!({}), None))),
        ("tools/call with a sentinel naming another tool", modern_call.clone().header("mcp-name", &sentinel("delete_document")), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call with a sentinel that does not decode", modern_call.clone().header("mcp-name", "=?base64?%%%?="), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call with a raw sentinel equal to the name", Raw::modern(json!(1), "tools/call", json!({"name": "=?base64?cmVhZA==?="})), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call naming another tool in Mcp-Name", modern_call.clone().header("mcp-name", "delete_document"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call without Mcp-Name", modern_call.clone().without("mcp-name"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call with two Mcp-Name headers", modern_call.clone().append("mcp-name", "read_document"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("tools/call without a name", Raw::modern(json!(1), "tools/call", json!({"arguments": {}})), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("Mcp-Method naming another method", modern_call.clone().header("mcp-method", "tools/list"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("Mcp-Method in another case", Raw::modern(json!(1), "tools/list", json!({})).header("mcp-method", "Tools/List"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("no Mcp-Method", Raw::modern(json!(1), "tools/list", json!({})).without("mcp-method"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("no MCP-Protocol-Version, with the version in _meta", Raw::modern(json!(1), "tools/list", json!({})).without("mcp-protocol-version"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("MCP-Protocol-Version disagreeing with _meta", Raw::modern(json!(1), "tools/list", json!({})).header("mcp-protocol-version", "2025-06-18"), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("two MCP-Protocol-Version headers", Raw::modern(json!(1), "tools/list", json!({})).append("mcp-protocol-version", MODERN), Refused(HeaderMismatch, 400, HEADER_MISMATCH)),
        ("a version this endpoint does not serve", Raw::modern(json!(1), "tools/list", json!({"_meta": {PROTOCOL_VERSION_META: "2027-01-01"}})).header("mcp-protocol-version", "2027-01-01"), Refused(UnsupportedVersion, 400, UNSUPPORTED_VERSION)),
        ("the legacy version, with modern _meta", Raw::modern(json!(1), "tools/list", json!({"_meta": {PROTOCOL_VERSION_META: "2025-06-18"}})).header("mcp-protocol-version", "2025-06-18"), Refused(UnsupportedVersion, 400, UNSUPPORTED_VERSION)),
        ("the modern header without _meta", Raw::legacy(json!(1), "tools/list", json!({})).header("mcp-protocol-version", MODERN).header("mcp-method", "tools/list"), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("a version in _meta that is not a string", Raw::modern(json!(1), "tools/list", json!({"_meta": {PROTOCOL_VERSION_META: 20260728}})), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("no clientCapabilities", Raw::modern(json!(1), "tools/list", json!({"_meta": {CLIENT_CAPABILITIES_META: null}})), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("clientCapabilities that is not an object", Raw::modern(json!(1), "tools/list", json!({"_meta": {CLIENT_CAPABILITIES_META: true}})), Refused(InvalidParams, 400, INVALID_PARAMS)),
        ("ping under 2026-07-28", Raw::modern(json!(1), "ping", json!({})), Refused(MethodNotFound, 404, METHOD_NOT_FOUND)),
        ("an unknown modern method", Raw::modern(json!(1), "resources/list", json!({})), Refused(MethodNotFound, 404, METHOD_NOT_FOUND)),
        ("a session header is ignored under 2026-07-28", modern_call.clone().header("mcp-session-id", "abc"), request(1, Modern, call("read_document", json!({"document": "team-a-notes"}), None))),
        ("header names are matched without case", Raw::modern(json!(1), "tools/list", json!({})).without("mcp-method").header("MCP-METHOD", "tools/list"), request(1, Modern, Call::ToolsList)),
    ]
}

#[test]
fn every_row_of_the_table() {
    let mut failures = Vec::new();
    for (name, raw, expect) in table() {
        let outcome = raw.parse();
        let matched = match (&expect, &outcome) {
            (Accepted(expected), Ok(inbound)) => expected == inbound,
            (Refused(kind, status, code), Err(rejection)) => {
                rejection.kind() == *kind
                    && rejection.status().as_u16() == *status
                    && rejection.code() == *code
                    && rejection.response().status == rejection.status()
            }
            _ => false,
        };
        if !matched {
            failures.push(format!("{name}: got {outcome:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn a_string_id_is_kept_as_a_string() {
    let Ok(Inbound::Request(request)) = Raw::legacy(json!("abc"), "ping", Value::Null).parse()
    else {
        panic!("ping was refused")
    };
    assert_eq!(request.id, RequestId::String("abc".to_owned()));
    let Ok(Inbound::Request(request)) = Raw::legacy(json!("1"), "ping", Value::Null).parse() else {
        panic!("ping was refused")
    };
    assert_eq!(request.id, RequestId::String("1".to_owned()));
}

#[test]
fn an_unsupported_version_names_the_one_supported_and_the_one_requested() {
    let rejection = Raw::modern(
        json!(9),
        "tools/list",
        json!({"_meta": {PROTOCOL_VERSION_META: "2027-01-01"}}),
    )
    .header("mcp-protocol-version", "2027-01-01")
    .parse()
    .unwrap_err();
    assert_eq!(
        rejection.data(),
        Some(&json!({"supported": [MODERN], "requested": "2027-01-01"}))
    );
    assert_eq!(rejection.id(), Some(&RequestId::Number(9)));
}

#[test]
fn a_refusal_after_the_id_is_read_echoes_it_and_one_before_does_not() {
    let after = Raw::modern(json!("x-1"), "tools/list", json!({}))
        .without("mcp-method")
        .parse()
        .unwrap_err();
    assert_eq!(after.id(), Some(&RequestId::String("x-1".to_owned())));
    let before = Raw::post("{").parse().unwrap_err();
    assert_eq!(before.id(), None);
}

#[test]
fn the_arguments_reach_the_call_as_sent() {
    let arguments =
        json!({"document": "team-a-notes", "nested": {"list": [1, 2, {"deep": null}]}, "n": 1e3});
    let raw = Raw::modern(
        json!(1),
        "tools/call",
        json!({"name": "read_document", "arguments": arguments.clone()}),
    );
    let Ok(Inbound::Request(Request {
        call: Call::ToolsCall(call),
        ..
    })) = raw.parse()
    else {
        panic!("the call was refused")
    };
    let Value::Object(expected) = arguments else {
        unreachable!()
    };
    assert_eq!(call.arguments, expected);
}

#[test]
fn check_transport_alone_refuses_before_any_body() {
    let raw = Raw::post("not json at all");
    assert!(gateway_mcp::check_transport(&raw.method, &raw.headers).is_ok());
    let get = raw.clone().method(Method::GET);
    assert_eq!(
        gateway_mcp::check_transport(&get.method, &get.headers)
            .unwrap_err()
            .kind(),
        RejectionKind::MethodNotAllowed
    );
}

#[test]
fn the_denial_code_is_not_a_protocol_code() {
    for code in [
        PARSE_ERROR,
        INVALID_REQUEST,
        METHOD_NOT_FOUND,
        INVALID_PARAMS,
        HEADER_MISMATCH,
        UNSUPPORTED_VERSION,
    ] {
        assert_ne!(DENIAL_CODE, code);
    }
    assert_eq!(DENIAL_CODE, -32001);
}
