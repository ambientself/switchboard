//! From a method, headers and body to a request, a notification or a refusal.

use http::{HeaderMap, Method};
use serde_json::{Map, Value};

use crate::constants::{
    CLIENT_CAPABILITIES_META, LEGACY, METHOD_HEADER, MODERN, NAME_HEADER, PROTOCOL_VERSION_HEADER,
    PROTOCOL_VERSION_META, TOOL_USE_ID_META,
};
use crate::headers::{Single, accept_admits_json, content_type_is_json, header_name_value, single};
use crate::message::{Call, Era, Inbound, Request, RequestId, ToolCall};
use crate::rejection::Rejection;

/// Refuses what is not a JSON POST, from the method and headers alone: 405 for any method but
/// POST, 415 for a body not declared as `application/json`, and 406 for an `Accept` header that
/// does not admit `application/json`. An absent `Accept` is allowed, because Otto's callers send
/// none.
///
/// The HTTP layer runs this before identity, so before the body is read. [`parse`] runs it too.
pub fn check_transport(method: &Method, headers: &HeaderMap) -> Result<(), Rejection> {
    if method != Method::POST {
        return Err(Rejection::method_not_allowed());
    }
    if !content_type_is_json(headers) {
        return Err(Rejection::unsupported_media_type());
    }
    if !accept_admits_json(headers) {
        return Err(Rejection::not_acceptable());
    }
    Ok(())
}

/// Parses one POST: the transport checks, the JSON-RPC envelope, the era, the 2026-07-28
/// header checks and the method's parameters, in that order.
///
/// The era is decided from this request alone. `initialize` is legacy. A request whose
/// `params._meta` carries a protocol version, or whose `MCP-Protocol-Version` header is
/// [`MODERN`], is modern and must pass every header check. Anything else is legacy, and its
/// `MCP-Protocol-Version` header, if any, must be [`LEGACY`].
///
/// `Mcp-Session-Id` and `Last-Event-ID` are ignored.
pub fn parse(method: &Method, headers: &HeaderMap, body: &[u8]) -> Result<Inbound, Rejection> {
    check_transport(method, headers)?;
    let message: Value = serde_json::from_slice(body).map_err(|_| Rejection::parse_error())?;
    let object = match message {
        Value::Object(object) => object,
        Value::Array(_) => {
            return Err(Rejection::invalid_request(
                "Invalid request: batches are not supported",
            ));
        }
        _ => {
            return Err(Rejection::invalid_request(
                "Invalid request: the body must be one JSON-RPC request or notification",
            ));
        }
    };
    let envelope = envelope(object)?;
    let Some(id) = envelope.id else {
        return Ok(Inbound::Notification {
            method: envelope.method,
        });
    };
    let era = era(&envelope.method, headers, &envelope.params);
    let call = match era {
        Era::Modern => modern(headers, &id, &envelope.method, envelope.params)?,
        Era::Legacy => legacy(headers, &id, &envelope.method, envelope.params)?,
    };
    Ok(Inbound::Request(Request { id, era, call }))
}

struct Envelope {
    id: Option<RequestId>,
    method: String,
    params: Params,
}

/// The request's `params`. A `params` that is present but not an object is kept apart, so it
/// is refused once the era, and so the status, is known.
enum Params {
    Object(Map<String, Value>),
    Malformed,
}

impl Params {
    fn meta(&self, key: &str) -> Option<&Value> {
        match self {
            Params::Object(params) => params.get("_meta")?.as_object()?.get(key),
            Params::Malformed => None,
        }
    }
}

fn envelope(mut object: Map<String, Value>) -> Result<Envelope, Rejection> {
    let method = match object.remove("method") {
        Some(Value::String(method)) => method,
        Some(_) => {
            return Err(Rejection::invalid_request(
                "Invalid request: method must be a string",
            ));
        }
        None if object.contains_key("result") || object.contains_key("error") => {
            return Err(Rejection::invalid_request(
                "Invalid request: this endpoint takes requests and notifications, not responses",
            ));
        }
        None => return Err(Rejection::invalid_request("Invalid request: no method")),
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(Rejection::invalid_request(
            "Invalid request: jsonrpc must be \"2.0\"",
        ));
    }
    let id = match object.remove("id") {
        None => None,
        Some(Value::Null) => {
            return Err(Rejection::invalid_request(
                "Invalid request: id must not be null",
            ));
        }
        Some(Value::String(id)) => Some(RequestId::String(id)),
        Some(Value::Number(id)) => match id.as_i64() {
            Some(id) => Some(RequestId::Number(id)),
            None => {
                return Err(Rejection::invalid_request(
                    "Invalid request: id must be a string or an integer",
                ));
            }
        },
        Some(_) => {
            return Err(Rejection::invalid_request(
                "Invalid request: id must be a string or an integer",
            ));
        }
    };
    let params = match object.remove("params") {
        None | Some(Value::Null) => Params::Object(Map::new()),
        Some(Value::Object(params)) => Params::Object(params),
        Some(_) => Params::Malformed,
    };
    Ok(Envelope { id, method, params })
}

fn era(method: &str, headers: &HeaderMap, params: &Params) -> Era {
    if method == "initialize" {
        return Era::Legacy;
    }
    let header_is_modern = headers
        .get_all(PROTOCOL_VERSION_HEADER)
        .iter()
        .any(|value| value == MODERN);
    if params.meta(PROTOCOL_VERSION_META).is_some() || header_is_modern {
        Era::Modern
    } else {
        Era::Legacy
    }
}

fn modern(
    headers: &HeaderMap,
    id: &RequestId,
    method: &str,
    params: Params,
) -> Result<Call, Rejection> {
    let era = Era::Modern;
    let Params::Object(params) = params else {
        return Err(Rejection::invalid_params(
            era,
            id,
            "Invalid params: params must be an object",
        ));
    };
    let meta = params.get("_meta").and_then(Value::as_object);
    let Some(version) = meta
        .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
        .and_then(Value::as_str)
    else {
        return Err(Rejection::invalid_params(
            era,
            id,
            format!("Invalid params: _meta must carry {PROTOCOL_VERSION_META} as a string"),
        ));
    };
    match single(headers, PROTOCOL_VERSION_HEADER) {
        Single::One(header) if header == version => {}
        Single::One(header) => {
            return Err(Rejection::header_mismatch(
                id,
                format!(
                    "Header mismatch: MCP-Protocol-Version header value '{header}' does not \
                     match body value '{version}'"
                ),
            ));
        }
        Single::Absent | Single::Malformed => {
            return Err(Rejection::header_mismatch(
                id,
                "Header mismatch: one MCP-Protocol-Version header is required",
            ));
        }
    }
    if version != MODERN {
        return Err(Rejection::unsupported_version(id, version));
    }
    if !meta
        .and_then(|meta| meta.get(CLIENT_CAPABILITIES_META))
        .is_some_and(Value::is_object)
    {
        return Err(Rejection::invalid_params(
            era,
            id,
            format!("Invalid params: _meta must carry {CLIENT_CAPABILITIES_META} as an object"),
        ));
    }
    match single(headers, METHOD_HEADER) {
        Single::One(header) if header == method => {}
        Single::One(header) => {
            return Err(Rejection::header_mismatch(
                id,
                format!(
                    "Header mismatch: Mcp-Method header value '{header}' does not match body \
                     value '{method}'"
                ),
            ));
        }
        Single::Absent | Single::Malformed => {
            return Err(Rejection::header_mismatch(
                id,
                "Header mismatch: one Mcp-Method header is required",
            ));
        }
    }
    match method {
        "server/discover" => Ok(Call::Discover),
        "tools/list" => tools_list(era, id, &params),
        "tools/call" => {
            let call = tools_call(era, id, params)?;
            check_name_header(headers, id, &call.name)?;
            Ok(Call::ToolsCall(call))
        }
        _ => Err(Rejection::method_not_found(era, id, method)),
    }
}

fn check_name_header(headers: &HeaderMap, id: &RequestId, name: &str) -> Result<(), Rejection> {
    let Single::One(header) = single(headers, NAME_HEADER) else {
        return Err(Rejection::header_mismatch(
            id,
            "Header mismatch: one Mcp-Name header is required on tools/call",
        ));
    };
    match header_name_value(header) {
        Some(decoded) if decoded == name => Ok(()),
        Some(_) => Err(Rejection::header_mismatch(
            id,
            "Header mismatch: Mcp-Name header value does not match body value params.name",
        )),
        None => Err(Rejection::header_mismatch(
            id,
            "Header mismatch: Mcp-Name header is not valid base64 sentinel encoding",
        )),
    }
}

fn legacy(
    headers: &HeaderMap,
    id: &RequestId,
    method: &str,
    params: Params,
) -> Result<Call, Rejection> {
    let era = Era::Legacy;
    if method == "initialize" {
        return Ok(Call::Initialize);
    }
    match single(headers, PROTOCOL_VERSION_HEADER) {
        Single::Absent => {}
        Single::One(header) if header == LEGACY => {}
        Single::One(_) | Single::Malformed => {
            return Err(Rejection::invalid_request(format!(
                "Invalid request: unsupported MCP-Protocol-Version header; this endpoint \
                 serves {MODERN} with per-request _meta, and {LEGACY} after initialize"
            ))
            .with_id(id));
        }
    }
    let Params::Object(params) = params else {
        return Err(Rejection::invalid_params(
            era,
            id,
            "Invalid params: params must be an object",
        ));
    };
    match method {
        "ping" => Ok(Call::Ping),
        "tools/list" => tools_list(era, id, &params),
        "tools/call" => Ok(Call::ToolsCall(tools_call(era, id, params)?)),
        _ => Err(Rejection::method_not_found(era, id, method)),
    }
}

/// No cursor is ever issued, so any cursor is one this server did not issue.
fn tools_list(era: Era, id: &RequestId, params: &Map<String, Value>) -> Result<Call, Rejection> {
    match params.get("cursor") {
        None | Some(Value::Null) => Ok(Call::ToolsList),
        Some(_) => Err(Rejection::invalid_params(
            era,
            id,
            "Invalid params: unknown cursor",
        )),
    }
}

fn tools_call(
    era: Era,
    id: &RequestId,
    mut params: Map<String, Value>,
) -> Result<ToolCall, Rejection> {
    let Some(Value::String(name)) = params.remove("name") else {
        return Err(Rejection::invalid_params(
            era,
            id,
            "Invalid params: tools/call needs a name, as a string",
        ));
    };
    let arguments = match params.remove("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(arguments)) => arguments,
        Some(_) => {
            return Err(Rejection::invalid_params(
                era,
                id,
                "Invalid params: arguments must be an object",
            ));
        }
    };
    let tool_use_id = params
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(TOOL_USE_ID_META))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ToolCall {
        name,
        arguments,
        tool_use_id,
    })
}
