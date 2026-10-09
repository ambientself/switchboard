//! What a forwarded call comes to, and the sentences the caller reads.
//!
//! The outcome follows the core's meaning of each [`ToolOutcome`]:
//!
//! - [`ToolOutcome::Refused`] when the connector would not send the call because of what it
//!   names ([`NOT_SERVED`], [`NO_CREDENTIAL`]), and when the server answered `403`, its
//!   refusal of the call's scope ([`UPSTREAM_REFUSED`]).
//! - [`ToolOutcome::Error`] for arguments that are not an object, which are never sent
//!   ([`ARGUMENTS_NOT_AN_OBJECT`]), and for everything that went wrong on the gateway's side
//!   or the server's: the deadline, the size cap, a connection that failed, a credential the
//!   server did not accept, any other HTTP status, an answer that is not MCP, a JSON-RPC error,
//!   and a tool result marked `isError`.
//! - [`ToolOutcome::Ok`] with the server's `result` object, unchanged, for anything else.
//!
//! A successful result is bounded only by the answer cap; the gateway passes its content and
//! structured content on to the caller as the server sent them. From a failure, text from the
//! server reaches the caller only from a JSON-RPC error's message and from a failed tool
//! result's text, each cut to [`MAX_MESSAGE_CHARS`] with control characters replaced by spaces.

use gateway_core::ToolOutcome;
use serde_json::{Map, Value};

/// The tool is not one this connector forwards: it routes to another connector, or the
/// connector has no upstream name for it. Nothing was sent.
pub const NOT_SERVED: &str =
    "This tool is not served by the proxied server it was routed to, so nothing was sent.";

/// The call's arguments are not a JSON object, which `tools/call` requires. Nothing was sent.
pub const ARGUMENTS_NOT_AN_OBJECT: &str =
    "The tool's arguments must be a JSON object, so nothing was sent.";

/// The credential source would not issue the gateway's credential for this server. Nothing was
/// sent.
pub const NO_CREDENTIAL: &str =
    "The gateway holds no credential for this tool's server, so nothing was sent.";

/// The credential source could not be reached. Nothing was sent.
pub const CREDENTIAL_UNAVAILABLE: &str =
    "The gateway's credential for this tool's server is unavailable, so nothing was sent.";

/// The request could not be built. Nothing was sent.
pub const NOT_SENT: &str =
    "The gateway could not build the request to this tool's server, so nothing was sent.";

/// The server could not be connected to, or the exchange failed before an answer began.
pub const UNREACHABLE: &str = "The gateway could not reach this tool's server.";

/// The call reached its deadline and was abandoned. The server may still have acted on it.
pub const TIMED_OUT: &str =
    "This tool's server did not answer before the call's deadline, so the call was abandoned.";

/// The answer was larger than the cap and was discarded.
pub const TOO_LARGE: &str =
    "This tool's answer was larger than the gateway accepts, so it was discarded.";

/// The answer stopped before it was complete.
pub const BROKEN_OFF: &str = "This tool's server stopped answering before its answer was complete.";

/// The server answered `401`: it did not accept the gateway's credential.
pub const CREDENTIAL_REJECTED: &str = "This tool's server did not accept the gateway's credential.";

/// The server answered `403`: it refused the call as outside what the gateway's credential
/// may do.
pub const UPSTREAM_REFUSED: &str =
    "This tool's server refused the call as outside what the gateway's credential may do.";

/// The answer was not one JSON-RPC response to the request, with a tool result or an error.
pub const NOT_MCP: &str = "This tool's server gave an answer that is not a valid MCP response.";

/// The tool result was marked `isError` and carried no text.
pub const TOOL_FAILED: &str = "This tool reported an error and gave no detail.";

/// The longest text taken from the server's answer into a sentence, in characters.
pub const MAX_MESSAGE_CHARS: usize = 1024;

/// The sentence for an HTTP status other than `200`, `401` and `403`.
pub fn status(code: u16) -> String {
    format!("This tool's server answered with HTTP status {code}.")
}

/// The sentence for a JSON-RPC error from the server.
pub fn rpc_error(code: i64, message: &str) -> String {
    format!(
        "This tool's server answered with error {code}: {}",
        bounded(message)
    )
}

/// The outcome of a `200` answer to the request with ID `id`.
pub(crate) fn interpret(content_type: Option<&str>, body: &[u8], id: u64) -> ToolOutcome {
    let not_mcp = || ToolOutcome::Error(NOT_MCP.to_owned());
    if !content_type.is_some_and(is_json) {
        return not_mcp();
    }
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(body) else {
        return not_mcp();
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || message.get("id").and_then(Value::as_u64) != Some(id)
    {
        return not_mcp();
    }
    match (message.get("result"), message.get("error")) {
        (Some(Value::Object(result)), None) => tool_result(result),
        (None, Some(Value::Object(error))) => {
            match (
                error.get("code").and_then(Value::as_i64),
                error.get("message").and_then(Value::as_str),
            ) {
                (Some(code), Some(text)) => ToolOutcome::Error(rpc_error(code, text)),
                _ => not_mcp(),
            }
        }
        _ => not_mcp(),
    }
}

fn tool_result(result: &Map<String, Value>) -> ToolOutcome {
    let Some(Value::Array(content)) = result.get("content") else {
        return ToolOutcome::Error(NOT_MCP.to_owned());
    };
    if result.get("isError") != Some(&Value::Bool(true)) {
        return ToolOutcome::Ok(Value::Object(result.clone()));
    }
    let text: Vec<&str> = content
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect();
    if text.is_empty() {
        ToolOutcome::Error(TOOL_FAILED.to_owned())
    } else {
        ToolOutcome::Error(bounded(&text.join("\n")))
    }
}

/// `application/json`, with or without parameters, in any case.
fn is_json(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("application/json")
}

/// At most [`MAX_MESSAGE_CHARS`] characters of `text`, with control characters replaced by
/// spaces and an ellipsis where it was cut.
fn bounded(text: &str) -> String {
    let mut kept: String = text
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().nth(MAX_MESSAGE_CHARS).is_some() {
        kept.push('…');
    }
    kept
}
