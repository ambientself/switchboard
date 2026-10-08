//! What a parsed POST is: a request in one era, or a notification.

use std::fmt;

use serde_json::{Map, Value};

use crate::constants::{LEGACY, MODERN};

/// A JSON-RPC request identifier. MCP allows a string or an integer, and never `null`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RequestId {
    /// An integer identifier.
    Number(i64),
    /// A string identifier.
    String(String),
}

impl RequestId {
    /// The identifier as it is echoed in the response.
    pub fn to_json(&self) -> Value {
        match self {
            RequestId::Number(number) => Value::from(*number),
            RequestId::String(string) => Value::from(string.as_str()),
        }
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestId::Number(number) => write!(f, "{number}"),
            RequestId::String(string) => write!(f, "{string:?}"),
        }
    }
}

/// Which MCP revision a request is served under. Decided per request; there is no state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Era {
    /// `2026-07-28`: the request carries its version in `_meta` and mirrors it in headers.
    Modern,
    /// `2025-06-18`: the `initialize` handshake, and what follows it.
    Legacy,
}

impl Era {
    /// The protocol version this era answers with.
    pub fn version(self) -> &'static str {
        match self {
            Era::Modern => MODERN,
            Era::Legacy => LEGACY,
        }
    }
}

impl fmt::Display for Era {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.version())
    }
}

/// A POST body that passed every protocol check.
#[derive(Clone, Debug, PartialEq)]
pub enum Inbound {
    /// A request, which gets an answer.
    Request(Request),
    /// A notification, which gets 202 and an empty body. It is accepted and ignored, whatever
    /// its name; `notifications/initialized` and `notifications/cancelled` are the usual ones.
    Notification {
        /// The notification's `method`.
        method: String,
    },
}

/// A request: its identifier, the era it is served under, and what it asks for.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// Echoed in the answer.
    pub id: RequestId,
    /// Decides the answer's shape.
    pub era: Era,
    /// What is asked.
    pub call: Call,
}

/// The methods this endpoint serves. Which are reachable depends on the era: `initialize` and
/// `ping` only under [`Era::Legacy`], `server/discover` only under [`Era::Modern`].
#[derive(Clone, Debug, PartialEq)]
pub enum Call {
    /// `initialize` (legacy). Answered with [`LEGACY`] whatever version was asked for.
    Initialize,
    /// `ping` (legacy).
    Ping,
    /// `server/discover` (modern).
    Discover,
    /// `tools/list`, in either era. A cursor is refused at parse time: none is ever issued.
    ToolsList,
    /// `tools/call`, in either era.
    ToolsCall(ToolCall),
}

/// The parts of a `tools/call` the gateway uses.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    /// `params.name`, as sent. Under 2026-07-28 it has been compared with `Mcp-Name`. It is not
    /// checked against any naming rule here; the core's tool check does that.
    pub name: String,
    /// `params.arguments`; empty when absent.
    pub arguments: Map<String, Value>,
    /// `params._meta["claudecode/toolUseId"]` when it is a string, exactly as sent. It is
    /// unbounded here: the gateway bounds it before it reaches an audit row.
    pub tool_use_id: Option<String>,
}
