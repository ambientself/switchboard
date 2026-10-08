//! Answers: what the gateway decided, rendered as the HTTP response for the request's era.

use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::{Map, Value, json};

use crate::constants::{
    DENIAL_CODE, INTERNAL_ERROR, LEGACY, LIST_TTL_MS, MODERN, SERVER_INFO_META,
};
use crate::message::{Era, RequestId};

/// A response, ready for the HTTP layer to send as it is.
#[derive(Clone, Debug, PartialEq)]
pub struct HttpResponse {
    /// The status line.
    pub status: StatusCode,
    /// `Content-Type: application/json` on every response with a body, and `Allow` or
    /// `WWW-Authenticate` where they apply. Never `Mcp-Session-Id`.
    pub headers: HeaderMap,
    /// The JSON body; empty for 202.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// 202 with no body: the answer to every accepted notification.
    pub fn accepted() -> Self {
        HttpResponse {
            status: StatusCode::ACCEPTED,
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }

    fn json(status: StatusCode, body: &Value) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        HttpResponse {
            status,
            headers,
            body: body.to_string().into_bytes(),
        }
    }
}

/// How the server names itself, and what it tells clients about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    /// `serverInfo.name`.
    pub name: String,
    /// `serverInfo.version`.
    pub version: String,
    /// `instructions` on `initialize` and `server/discover`. The gateway says here, plainly,
    /// when identity or audit is turned off.
    pub instructions: Option<String>,
}

/// One tool as `tools/list` shows it. Plain strings and JSON: the gateway builds it from the
/// approved tool and its catalog entry.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolEntry {
    /// The tool's name.
    pub name: String,
    /// A display name, when the catalog has one.
    pub title: Option<String>,
    /// What the tool does, for the model.
    pub description: String,
    /// The tool's JSON Schema for its arguments; an object.
    pub input_schema: Value,
    /// Rendered as `annotations.readOnlyHint`.
    pub read_only: bool,
}

/// What the gateway answers a [`Request`](crate::Request) with.
#[derive(Clone, Debug, PartialEq)]
pub enum Reply {
    /// The answer to `initialize`: always [`LEGACY`], tools without change notifications, and
    /// no session.
    Initialized,
    /// The answer to `ping`: an empty result.
    Pong,
    /// The answer to `server/discover`: [`MODERN`] is the one version listed (decision 0007's
    /// 2026-10-07 amendment).
    Discovered,
    /// The answer to `tools/list`: the tools the caller may call, in the order given. Under
    /// 2026-07-28 it is marked private to the caller, because it varies by authorization.
    Tools(Vec<ToolEntry>),
    /// A tool ran and answered. Sent as text holding the value as JSON, and as structured
    /// content; under 2025-06-18 structured content must be an object, so other values are
    /// sent as text only.
    ToolOk(Value),
    /// A proxied MCP server's tool ran and answered. Its content blocks and its structured
    /// content are sent as the server gave them, not wrapped again. Under 2025-06-18
    /// structured content must be an object, so any other value is left out; the content
    /// blocks still carry the answer.
    ToolResult {
        /// The server's `content` blocks.
        content: Vec<Value>,
        /// The server's `structuredContent`, if it gave one.
        structured_content: Option<Value>,
    },
    /// A tool ran and failed: a result with `isError: true` and the message as text
    /// (decision 0007's 2026-10-07 amendment).
    ToolError(String),
    /// The call was refused: by policy, by the connector's scope check, by a failed audit, or
    /// because identity is turned off. A JSON-RPC error with [`DENIAL_CODE`] and the sentence
    /// as its message, with status 200.
    Denied(String),
    /// The gateway failed in a way that is not the caller's doing: status 500, -32603.
    Internal(String),
}

/// Renders `reply` as the answer to the request `id` under `era`.
///
/// Under 2026-07-28 every result carries `resultType: "complete"` and names the server in
/// `_meta`. Under 2025-06-18 results have neither.
pub fn render(server: &ServerInfo, era: Era, id: &RequestId, reply: Reply) -> HttpResponse {
    let result = match reply {
        Reply::Denied(sentence) => {
            return error_response(StatusCode::OK, Some(id), DENIAL_CODE, &sentence, None);
        }
        Reply::Internal(message) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(id),
                INTERNAL_ERROR,
                &message,
                None,
            );
        }
        Reply::Initialized => {
            // Always the legacy shape: `initialize` only exists in that era.
            let mut result = json!({
                "protocolVersion": LEGACY,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": server_info(server),
            });
            add_instructions(&mut result, server);
            return result_response(id, result);
        }
        Reply::Pong => json!({}),
        Reply::Discovered => {
            let mut result = json!({
                "supportedVersions": [MODERN],
                "capabilities": {"tools": {}},
                "ttlMs": LIST_TTL_MS,
                "cacheScope": "public",
            });
            add_instructions(&mut result, server);
            result
        }
        Reply::Tools(tools) => {
            let tools: Vec<Value> = tools.iter().map(tool_entry).collect();
            match era {
                Era::Modern => json!({
                    "tools": tools,
                    "ttlMs": LIST_TTL_MS,
                    "cacheScope": "private",
                }),
                Era::Legacy => json!({"tools": tools}),
            }
        }
        Reply::ToolOk(value) => {
            let mut result = json!({
                "content": [{"type": "text", "text": value.to_string()}],
                "isError": false,
            });
            if era == Era::Modern || value.is_object() {
                insert(&mut result, "structuredContent", value);
            }
            result
        }
        Reply::ToolResult {
            content,
            structured_content,
        } => {
            let mut result = json!({"content": content, "isError": false});
            let structured =
                structured_content.filter(|value| era == Era::Modern || value.is_object());
            if let Some(structured) = structured {
                insert(&mut result, "structuredContent", structured);
            }
            result
        }
        Reply::ToolError(message) => json!({
            "content": [{"type": "text", "text": message}],
            "isError": true,
        }),
    };
    let result = match era {
        Era::Modern => complete(result, server),
        Era::Legacy => result,
    };
    result_response(id, result)
}

fn complete(mut result: Value, server: &ServerInfo) -> Value {
    insert(&mut result, "resultType", Value::from("complete"));
    insert(
        &mut result,
        "_meta",
        json!({SERVER_INFO_META: server_info(server)}),
    );
    result
}

fn server_info(server: &ServerInfo) -> Value {
    json!({"name": server.name, "version": server.version})
}

fn add_instructions(result: &mut Value, server: &ServerInfo) {
    if let Some(instructions) = &server.instructions {
        insert(result, "instructions", Value::from(instructions.as_str()));
    }
}

fn tool_entry(tool: &ToolEntry) -> Value {
    let mut entry = json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": {"readOnlyHint": tool.read_only},
    });
    if let Some(title) = &tool.title {
        insert(&mut entry, "title", Value::from(title.as_str()));
    }
    entry
}

fn insert(object: &mut Value, key: &str, value: Value) {
    if let Value::Object(map) = object {
        map.insert(key.to_owned(), value);
    }
}

fn result_response(id: &RequestId, result: Value) -> HttpResponse {
    HttpResponse::json(
        StatusCode::OK,
        &json!({"jsonrpc": "2.0", "id": id.to_json(), "result": result}),
    )
}

/// A JSON-RPC error response. The `id` is `null` when the request's could not be read.
pub(crate) fn error_response(
    status: StatusCode,
    id: Option<&RequestId>,
    code: i64,
    message: &str,
    data: Option<&Value>,
) -> HttpResponse {
    let mut error = Map::new();
    error.insert("code".to_owned(), Value::from(code));
    error.insert("message".to_owned(), Value::from(message));
    if let Some(data) = data {
        error.insert("data".to_owned(), data.clone());
    }
    let id = id.map_or(Value::Null, RequestId::to_json);
    HttpResponse::json(
        status,
        &json!({"jsonrpc": "2.0", "id": id, "error": Value::Object(error)}),
    )
}
