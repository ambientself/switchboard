// A tool cannot be approved with a classification that has not been parsed, or whose parse
// error has not been handled.

use gateway_core::{ApprovedTool, Classification};

fn approve(text: &str) -> (ApprovedTool, ApprovedTool) {
    let unhandled = ApprovedTool {
        name: "github__get_file".into(),
        classification: text.parse::<Classification>(),
        connector: "github".into(),
        declares_resources: true,
        checks_own_scope: false,
    };
    let unparsed = ApprovedTool {
        name: "github__get_file".into(),
        classification: text,
        connector: "github".into(),
        declares_resources: true,
        checks_own_scope: false,
    };
    (unhandled, unparsed)
}

fn main() {}
