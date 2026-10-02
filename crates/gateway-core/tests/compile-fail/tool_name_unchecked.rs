// A tool name cannot be made without checking it against the naming rule.

use gateway_core::ToolName;

fn unchecked(text: &str) -> (ToolName, ToolName) {
    (text.into(), ToolName::new(text))
}

fn main() {}
