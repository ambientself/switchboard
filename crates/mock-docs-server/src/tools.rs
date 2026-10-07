//! The tools the server can offer and their definitions.

use std::fmt;

use serde_json::{Value, json};

/// A tool the server knows. Which of them it offers is configured, and can change while it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ToolName {
    /// `list_documents {project}`: the names of a project's documents.
    ListDocuments,
    /// `read_document {project, document}`: one document's text.
    ReadDocument,
    /// `search_documents {project, query}`: the text documents of a project containing a
    /// string. Not offered unless configured, so a test can add a tool the gateway never
    /// approved.
    SearchDocuments,
}

/// The tools offered when nothing else is configured.
pub const DEFAULT_TOOLS: [ToolName; 2] = [ToolName::ListDocuments, ToolName::ReadDocument];

/// Every tool the server knows.
pub const ALL_TOOLS: [ToolName; 3] = [
    ToolName::ListDocuments,
    ToolName::ReadDocument,
    ToolName::SearchDocuments,
];

impl ToolName {
    /// The name on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ListDocuments => "list_documents",
            Self::ReadDocument => "read_document",
            Self::SearchDocuments => "search_documents",
        }
    }

    /// The tool with this wire name, if the server knows one.
    pub fn parse(name: &str) -> Option<Self> {
        ALL_TOOLS.into_iter().find(|tool| tool.as_str() == name)
    }

    /// The arguments the tool takes, in order. Each is a required string, and no other
    /// argument is accepted.
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::ListDocuments => &["project"],
            Self::ReadDocument => &["project", "document"],
            Self::SearchDocuments => &["project", "query"],
        }
    }

    /// The definition `tools/list` answers with.
    pub fn definition(self) -> Value {
        let description = match self {
            Self::ListDocuments => "List the names of the documents in one project.",
            Self::ReadDocument => "Read one document of one project.",
            Self::SearchDocuments => {
                "List the documents of one project whose text contains a string."
            }
        };
        let properties: serde_json::Map<String, Value> = self
            .arguments()
            .iter()
            .map(|argument| ((*argument).to_owned(), json!({"type": "string"})))
            .collect();
        json!({
            "name": self.as_str(),
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": self.arguments(),
                "additionalProperties": false,
            },
            "annotations": {"readOnlyHint": true},
        })
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Reads a comma-separated list of tool names. Spaces around names are ignored, and an empty
/// string is no tools. An unknown or repeated name is refused.
pub fn parse_tool_list(list: &str) -> Result<Vec<ToolName>, String> {
    let mut tools = Vec::new();
    for name in list
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let tool = ToolName::parse(name).ok_or_else(|| format!("unknown tool `{name}`"))?;
        if tools.contains(&tool) {
            return Err(format!("tool `{name}` is named twice"));
        }
        tools.push(tool);
    }
    Ok(tools)
}
