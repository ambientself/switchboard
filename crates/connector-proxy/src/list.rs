//! A proxied server's tool list, as the gateway reads it for itself: what
//! [`ProxyConnector::list_tools`](crate::ProxyConnector::list_tools) returns.
//!
//! The drift pass compares what a server lists with what was approved (decision 0013,
//! section 5). A list that could not be read whole is a [`ListError`], never a shorter list: a
//! tool missing from a list withdraws it, so only a list read in full may say a tool is gone.

use serde_json::{Map, Value};
use thiserror::Error;

use crate::outcome::is_json;

/// One tool as the server lists it: the fields an approval's definition hash covers, as
/// served. A field the server left out is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedTool {
    /// The tool's name on the server.
    pub name: String,
    /// Its title, if it has one.
    pub title: Option<String>,
    /// Its description, if it has one.
    pub description: Option<String>,
    /// Its input schema, if it has one.
    pub input_schema: Option<Value>,
}

/// Why a server's tool list could not be read. None of these says that a tool changed: each is
/// a failed poll, which keeps the server's tools served (decision 0013, section 5). No variant
/// carries the server's text or the credential.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ListError {
    /// The gateway's credential for the server could not be read. Nothing was sent.
    #[error("the gateway's credential could not be read, so nothing was sent: {0}")]
    Credential(String),
    /// The request could not be built. Nothing was sent.
    #[error("the request could not be built, so nothing was sent")]
    NotSent,
    /// The server could not be connected to, or the exchange failed before an answer began.
    #[error("the server could not be reached")]
    Unreachable,
    /// The server answered with a status other than `200`. A redirect is not followed.
    #[error("the server answered with HTTP status {0}")]
    Status(u16),
    /// The server did not answer in full before the deadline.
    #[error("the server did not answer before the deadline")]
    TimedOut,
    /// The answer was larger than the cap, and was discarded.
    #[error("the answer was larger than the cap")]
    TooLarge,
    /// The answer stopped before it was complete.
    #[error("the answer stopped before it was complete")]
    BrokenOff,
    /// The answer is not one JSON-RPC response to the request with a tool list in it.
    #[error("the answer is not a tool list")]
    NotAToolList,
    /// The server answered with a JSON-RPC error.
    #[error("the server answered with a JSON-RPC error")]
    RpcError,
    /// The answer has a `nextCursor`: the list goes on in another page. It is not followed.
    /// One page is all a poll reads, under one deadline and one cap, and a list read in part
    /// would make the tools on later pages look removed.
    #[error("the list continues on another page, which is not read")]
    Paginated,
}

/// The tools in a `200` answer to the `tools/list` request with ID `id`.
pub(crate) fn tool_list(
    content_type: Option<&str>,
    body: &[u8],
    id: u64,
) -> Result<Vec<ListedTool>, ListError> {
    if !content_type.is_some_and(is_json) {
        return Err(ListError::NotAToolList);
    }
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(body) else {
        return Err(ListError::NotAToolList);
    };
    let answers_request = message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && message.get("id").and_then(Value::as_u64) == Some(id);
    if !answers_request {
        return Err(ListError::NotAToolList);
    }
    let result = match (message.get("result"), message.get("error")) {
        (Some(Value::Object(result)), None) => result,
        (None, Some(Value::Object(_))) => return Err(ListError::RpcError),
        _ => return Err(ListError::NotAToolList),
    };
    if result
        .get("nextCursor")
        .is_some_and(|cursor| !cursor.is_null())
    {
        return Err(ListError::Paginated);
    }
    let Some(Value::Array(tools)) = result.get("tools") else {
        return Err(ListError::NotAToolList);
    };
    tools
        .iter()
        .map(|tool| tool.as_object().and_then(listed_tool))
        .collect::<Option<Vec<_>>>()
        .ok_or(ListError::NotAToolList)
}

/// One entry of the list, or `None` if it is not a tool: a name that is not a string, or a
/// title or description that is there but not a string, or an input schema that is there but
/// not an object.
fn listed_tool(tool: &Map<String, Value>) -> Option<ListedTool> {
    let text = |field: &str| match tool.get(field) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(text)) => Some(Some(text.clone())),
        Some(_) => None,
    };
    let input_schema = match tool.get("inputSchema") {
        None | Some(Value::Null) => None,
        Some(schema @ Value::Object(_)) => Some(schema.clone()),
        Some(_) => return None,
    };
    Some(ListedTool {
        name: tool.get("name")?.as_str()?.to_owned(),
        title: text("title")?,
        description: text("description")?,
        input_schema,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    fn listed(answer: &Value) -> Result<Vec<ListedTool>, ListError> {
        tool_list(Some("application/json"), answer.to_string().as_bytes(), 7)
    }

    #[test]
    fn a_list_is_read_with_each_field_as_served() {
        let tools = listed(&json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
            {"name": "read_document", "title": "Read", "description": "Reads.",
             "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}},
            {"name": "bare"},
        ]}}))
        .unwrap();
        assert_eq!(
            tools,
            [
                ListedTool {
                    name: "read_document".into(),
                    title: Some("Read".into()),
                    description: Some("Reads.".into()),
                    input_schema: Some(json!({"type": "object"})),
                },
                ListedTool {
                    name: "bare".into(),
                    title: None,
                    description: None,
                    input_schema: None,
                },
            ]
        );
    }

    #[test]
    fn anything_but_one_page_of_tools_answering_the_request_is_not_a_list() {
        let page = |result: Value| json!({"jsonrpc": "2.0", "id": 7, "result": result});
        for (case, answer, error) in [
            (
                "another id",
                json!({"jsonrpc": "2.0", "id": 8, "result": {"tools": []}}),
                ListError::NotAToolList,
            ),
            (
                "no version",
                json!({"id": 7, "result": {"tools": []}}),
                ListError::NotAToolList,
            ),
            (
                "an error",
                json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "no"}}),
                ListError::RpcError,
            ),
            ("no tools", page(json!({})), ListError::NotAToolList),
            (
                "a tool with no name",
                page(json!({"tools": [{"description": "x"}]})),
                ListError::NotAToolList,
            ),
            (
                "a description that is not text",
                page(json!({"tools": [{"name": "x", "description": 1}]})),
                ListError::NotAToolList,
            ),
            (
                "a schema that is not an object",
                page(json!({"tools": [{"name": "x", "inputSchema": []}]})),
                ListError::NotAToolList,
            ),
            (
                "a next page",
                page(json!({"tools": [], "nextCursor": "2"})),
                ListError::Paginated,
            ),
        ] {
            assert_eq!(listed(&answer), Err(error), "{case}");
        }
        assert_eq!(
            listed(&page(json!({"tools": [], "nextCursor": null}))),
            Ok(Vec::new())
        );
        assert_eq!(
            tool_list(
                Some("text/plain"),
                page(json!({"tools": []})).to_string().as_bytes(),
                7
            ),
            Err(ListError::NotAToolList)
        );
    }
}
