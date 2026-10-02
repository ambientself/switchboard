// A tool cannot be approved with a classification that has not been parsed, or whose parse
// error has not been handled.

use gateway_core::{ApprovedTool, Classification, ResourceDeclaration};

fn approve(text: &str) -> (ApprovedTool, ApprovedTool) {
    let unhandled = ApprovedTool {
        name: "github__get_file".parse().unwrap(),
        classification: text.parse::<Classification>(),
        connector: "github".into(),
        resources: ResourceDeclaration::Declared,
    };
    let unparsed = ApprovedTool {
        name: "github__get_file".parse().unwrap(),
        classification: text,
        connector: "github".into(),
        resources: ResourceDeclaration::Declared,
    };
    (unhandled, unparsed)
}

fn main() {}
