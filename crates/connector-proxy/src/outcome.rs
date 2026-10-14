//! What a forwarded call comes to, and the sentences the caller reads.
//!
//! The outcome follows the core's meaning of each [`ToolOutcome`]:
//!
//! - [`ToolOutcome::Refused`] when the connector would not send the call because of what it
//!   names ([`NOT_SERVED`], [`NO_CREDENTIAL`]).
//! - [`ToolOutcome::Error`], with its [`ErrorKind`]:
//!   - `InvalidArguments` for arguments that are not an object, which are never sent
//!     ([`ARGUMENTS_NOT_AN_OBJECT`]);
//!   - `VendorRefusal` when the server answered a read with `403`, its refusal of the call
//!     ([`UPSTREAM_REFUSED`]);
//!   - `OversizedOrLateRead` for the deadline, the size cap or an answer broken off, from a
//!     tool classified `read`;
//!   - `Other` for everything else that went wrong on the gateway's side or the server's: a
//!     credential that could not be had or a request that could not be built, a connection
//!     that could not be made or was refused for its address ([`DESTINATION_REFUSED`]), a
//!     credential the server did not accept, any other HTTP status, an answer that is not
//!     MCP, a JSON-RPC error, and a tool result marked `isError`.
//! - [`ToolOutcome::Unknown`] in place of an error, from a tool not classified `read`, for
//!   every outcome but a success once the request may have been sent: the deadline, the size
//!   cap, an answer broken off, an exchange that failed after its connection was made, any HTTP
//!   status other than `200`, `401`, `403` and every other `4xx` included, a `200` that is not
//!   MCP, a JSON-RPC error and a tool result marked `isError`. A side effect's error settles
//!   its receipt as `not_performed`, which must be established, and the server's own refusal
//!   or failure does not establish it: decision 0009 holds a proxied tool's error to be
//!   `unknown` unless its approval says its errors are safe, and no approval can say so yet.
//!   So a side effect is an error only when nothing was sent. The caller then reads the core's
//!   sentence that the call may have happened and must not be repeated, not one of the
//!   sentences here.
//! - [`ToolOutcome::Ok`] with the server's `result` object, unchanged, for anything else.
//!
//! A successful result is bounded only by the answer cap; the gateway passes its content and
//! structured content on to the caller as the server sent them. From a failure, text from the
//! server reaches the caller only from a JSON-RPC error's message and from a failed tool
//! result's text, each cut to [`MAX_MESSAGE_CHARS`] with control characters replaced by spaces.

use gateway_core::{ErrorKind, ToolOutcome};
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

/// Every address the server's name resolved to is one the gateway does not connect to, such
/// as a loopback or link-local address ([`destination`](crate::destination)). Nothing was sent.
pub const DESTINATION_REFUSED: &str = "The gateway does not connect to the address this tool's \
                                       server's name resolved to, so nothing was sent.";

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
/// may do. From a read, the outcome is an error of the kind `VendorRefusal`, which the row
/// records in place of this sentence; from a side effect it is `unknown`.
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

/// A `200` answer that is not one JSON-RPC response to the request, with a tool result or an
/// error: [`NOT_MCP`] from a read, and `unknown` from a side effect, since it says nothing of
/// what the server did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NotMcp;

/// The outcome of a `200` answer to the request with ID `id`, or [`NotMcp`].
pub(crate) fn interpret(
    content_type: Option<&str>,
    body: &[u8],
    id: u64,
) -> Result<ToolOutcome, NotMcp> {
    if !content_type.is_some_and(is_json) {
        return Err(NotMcp);
    }
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(body) else {
        return Err(NotMcp);
    };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || message.get("id").and_then(Value::as_u64) != Some(id)
    {
        return Err(NotMcp);
    }
    match (message.get("result"), message.get("error")) {
        (Some(Value::Object(result)), None) => tool_result(result),
        (None, Some(Value::Object(error))) => {
            match (
                error.get("code").and_then(Value::as_i64),
                error.get("message").and_then(Value::as_str),
            ) {
                (Some(code), Some(text)) => {
                    Ok(ToolOutcome::error(ErrorKind::Other, rpc_error(code, text)))
                }
                _ => Err(NotMcp),
            }
        }
        _ => Err(NotMcp),
    }
}

fn tool_result(result: &Map<String, Value>) -> Result<ToolOutcome, NotMcp> {
    let Some(Value::Array(content)) = result.get("content") else {
        return Err(NotMcp);
    };
    if result.get("isError") != Some(&Value::Bool(true)) {
        return Ok(ToolOutcome::Ok(Value::Object(result.clone())));
    }
    let text: Vec<&str> = content
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect();
    Ok(if text.is_empty() {
        ToolOutcome::error(ErrorKind::Other, TOOL_FAILED)
    } else {
        ToolOutcome::error(ErrorKind::Other, bounded(&text.join("\n")))
    })
}

/// `application/json`, with or without parameters, in any case.
pub(crate) fn is_json(content_type: &str) -> bool {
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
