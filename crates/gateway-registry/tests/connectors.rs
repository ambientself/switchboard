//! Built-in connector entries, `[[connectors]]`: what loads, and one case per way an entry
//! can be wrong.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{base, load, set, value};
use gateway_core::{ConnectorName, ToolName};
use gateway_registry::{Access, RegistryError};
use toml::Table;

const ENTRY: &str = r#"[
  { name = "github-read", system = "github", permissions = { issues = "read", pull_requests = "read" }, tools = ["github__get_issue", "github__get_pull_request"] },
  { name = "github-propose", system = "gh", permissions = { contents = "write", pull_requests = "write" }, tools = ["gh__propose"] },
]"#;

fn with_connectors(text: &str) -> Table {
    let mut table = base();
    set(&mut table, "", "connectors", value(text));
    table
}

fn name(text: &str) -> ConnectorName {
    ConnectorName::new(text)
}

fn tool(text: &str) -> ToolName {
    ToolName::parse(text).unwrap()
}

#[test]
fn a_file_without_connectors_loads_with_none() {
    let registry = load(&base()).unwrap();
    assert!(registry.connectors().is_empty());
}

#[test]
fn each_entry_states_its_permissions_and_tools() {
    let registry = load(&with_connectors(ENTRY)).unwrap();
    let read = &registry.connectors()[&name("github-read")];
    assert_eq!(read.system, "github");
    assert_eq!(read.permissions["issues"], Access::Read);
    assert_eq!(read.permissions["pull_requests"], Access::Read);
    assert_eq!(read.permissions.len(), 2);
    assert!(read.tools.contains(&tool("github__get_issue")));
    let propose = &registry.connectors()[&name("github-propose")];
    assert_eq!(propose.permissions["contents"], Access::Write);
    assert!(Access::Read < Access::Write);
}

#[test]
fn a_malformed_entry_is_refused() {
    let cases: [(&str, &str, RegistryError); 8] = [
        (
            "two entries with one name",
            r#"[{ name = "g", system = "github", permissions = { issues = "read" }, tools = ["github__a"] },
                { name = "g", system = "gh", permissions = { issues = "read" }, tools = ["gh__b"] }]"#,
            RegistryError::DuplicateEntry(name("g")),
        ),
        (
            "an entry named as a server",
            r#"[{ name = "docs-server", system = "github", permissions = { issues = "read" }, tools = ["github__a"] }]"#,
            RegistryError::DuplicateEntry(name("docs-server")),
        ),
        (
            "an entry with a server's system",
            r#"[{ name = "g", system = "docs", permissions = { issues = "read" }, tools = ["docs__other"] }]"#,
            RegistryError::DuplicateSystem {
                system: "docs".into(),
                first: name("docs-server"),
                second: name("g"),
            },
        ),
        (
            "an empty system",
            r#"[{ name = "g", system = "", permissions = { issues = "read" }, tools = ["github__a"] }]"#,
            RegistryError::EmptyField {
                field: "system",
                place: "connector `g`".into(),
            },
        ),
        (
            "no permissions",
            r#"[{ name = "g", system = "github", permissions = {}, tools = ["github__a"] }]"#,
            RegistryError::EntryWithoutPermissions(name("g")),
        ),
        (
            "a permission that is not a name",
            r#"[{ name = "g", system = "github", permissions = { "Issues" = "read" }, tools = ["github__a"] }]"#,
            RegistryError::PermissionName {
                entry: name("g"),
                permission: "Issues".into(),
            },
        ),
        (
            "no tools",
            r#"[{ name = "g", system = "github", permissions = { issues = "read" }, tools = [] }]"#,
            RegistryError::EntryWithoutTools(name("g")),
        ),
        (
            "a tool on two entries",
            r#"[{ name = "g", system = "github", permissions = { issues = "read" }, tools = ["github__a"] },
                { name = "h", system = "gh", permissions = { issues = "write" }, tools = ["github__a"] }]"#,
            RegistryError::ToolOnTwoEntries {
                tool: tool("github__a"),
                first: name("g"),
                second: name("h"),
            },
        ),
    ];
    for (case, text, want) in cases {
        let got = load(&with_connectors(text)).map(|_| ()).unwrap_err();
        assert_eq!(got, want, "{case}");
    }
}

#[test]
fn an_entry_cannot_serve_a_proxied_tool() {
    let text = r#"[{ name = "g", system = "github", permissions = { issues = "read" }, tools = ["docs__read"] }]"#;
    let got = load(&with_connectors(text)).map(|_| ()).unwrap_err();
    assert_eq!(
        got,
        RegistryError::BuiltInToolProxied {
            tool: tool("docs__read"),
            entry: name("g"),
        }
    );
}

#[test]
fn an_entry_refuses_unknown_fields_and_levels() {
    for text in [
        r#"[{ name = "g", system = "github", permissions = { issues = "read" }, tools = ["github__a"], extra = 1 }]"#,
        r#"[{ name = "g", system = "github", permissions = { issues = "admin" }, tools = ["github__a"] }]"#,
        r#"[{ name = "g", system = "github", tools = ["github__a"] }]"#,
    ] {
        let got = load(&with_connectors(text)).map(|_| ()).unwrap_err();
        assert!(matches!(got, RegistryError::Parse(_)), "{text}: {got:?}");
    }
}
