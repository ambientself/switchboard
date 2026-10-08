//! Helpers shared by the table tests: a registry file held as a TOML table, edited in place,
//! with each tool's approval hash recomputed so that an edit tests one rule and not the hash.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use gateway_registry::{Registry, RegistryError, definition_sha256};
use toml::{Table, Value};

/// A registry file that loads: two servers, three tools (one per kind of resource
/// declaration, one of them `write`), two surfaces, two profiles, a rule for workloads and one
/// for a group, and limits for a team and a group.
pub const BASE: &str = r#"
revision = "r1"

[[servers]]
name = "docs-server"
system = "docs"
owner = "team-docs"
identity = "docs-server"
address = "https://docs.internal.example.test/mcp"
credential = { mode = "bearer", reference = "docs-credential" }

[[servers]]
name = "wiki-server"
system = "wiki"
owner = "team-wiki"
identity = "wiki-server"
address = "http://wiki.internal.example.test:8080/mcp"
credential = { mode = "bearer", reference = "wiki-credential" }

[[tools]]
name = "docs__read"
server = "docs-server"
upstream_name = "read"
classification = "read"
title = "Read"
description = "Reads a document."
approved_by = "approver@example.test"
approved_at = 2026-10-01T12:00:00+01:00
definition_sha256 = ""
resources = { from_arguments = [{ from_argument = "project", system = "docs", kind = "project" }] }

[tools.input_schema]
type = "object"
required = ["project", "document"]

[tools.input_schema.properties.project]
type = "string"

[tools.input_schema.properties.document]
type = "string"

[[tools]]
name = "wiki__search"
server = "wiki-server"
upstream_name = "search"
classification = "read"
description = "Searches public pages."
approved_by = "approver@example.test"
approved_at = 2026-10-01T12:00:00Z
definition_sha256 = ""
resources = "no_resources"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.query]
type = "string"

[[tools]]
name = "wiki__edit"
server = "wiki-server"
upstream_name = "edit"
classification = "write"
description = "Edits a page."
approved_by = "approver@example.test"
approved_at = 2026-10-01T12:00:00Z
definition_sha256 = ""
resources = { from_arguments = [{ from_argument = "space", system = "wiki", kind = "space" }] }

[tools.input_schema]
type = "object"

[tools.input_schema.properties.space]
type = "string"

[tools.input_schema.properties.page]
type = "string"

[[surfaces]]
name = "docs"
tools = ["docs__read", "wiki__search"]
teams = ["team-a"]
groups = ["group-g"]
principals = "any_in_teams_and_groups"

[[surfaces]]
name = "control"
tools = ["wiki__edit"]
teams = ["team-a"]
principals = { only = [{ issuer = "https://workloads.example.test", subject = "system:serviceaccount:team-a:control" }] }

[[profiles]]
name = "workload-read"
classifications = ["read"]
requires_delegation = false

[[profiles]]
name = "user-read"
classifications = ["read"]
requires_delegation = false

[[profile_rules]]
issuer = "https://workloads.example.test"
principal = "workload"
profile = "workload-read"

[[profile_rules]]
issuer = "https://users.example.test"
principal = { user_in_group = "group-g" }
profile = "user-read"

[limits.teams]
team-a = [{ system = "docs", kind = "project", identifier = "atlas" }]

[limits.groups]
group-g = [
    { system = "docs", kind = "project", identifier = "atlas" },
    { system = "docs", kind = "project", identifier = "borealis" },
]
"#;

/// [`BASE`] as a table, with its hashes filled in.
pub fn base() -> Table {
    let mut table: Table = BASE.parse().unwrap();
    rehash(&mut table);
    table
}

/// Sets every tool's `definition_sha256` to the hash of its definition as it now stands.
pub fn rehash(table: &mut Table) {
    let Some(Value::Array(tools)) = table.get_mut("tools") else {
        return;
    };
    for tool in tools {
        let Some(tool) = tool.as_table_mut() else {
            continue;
        };
        let text = |key: &str| tool.get(key).and_then(Value::as_str).map(str::to_owned);
        let schema = tool
            .get("input_schema")
            .map(|schema| serde_json::to_value(schema).unwrap())
            .unwrap_or_default();
        let hash = definition_sha256(
            &text("upstream_name").unwrap_or_default(),
            text("title").as_deref(),
            &text("description").unwrap_or_default(),
            &schema,
        );
        tool.insert("definition_sha256".into(), Value::String(hash));
    }
}

/// Loads `table` as a registry file.
pub fn load(table: &Table) -> Result<Registry, RegistryError> {
    Registry::from_toml_str(&toml::to_string(table).unwrap())
}

/// The value at a dotted path such as `tools.0.input_schema.properties`; a number indexes an
/// array.
pub fn at<'a>(table: &'a mut Table, path: &str) -> &'a mut Value {
    let mut parts = path.split('.');
    let first = parts.next().unwrap();
    let mut value = table
        .get_mut(first)
        .unwrap_or_else(|| panic!("no `{first}`"));
    for part in parts {
        value = match value {
            Value::Array(items) => &mut items[part.parse::<usize>().unwrap()],
            Value::Table(table) => table
                .get_mut(part)
                .unwrap_or_else(|| panic!("no `{part}` in `{path}`")),
            other => panic!("`{part}` of `{path}` is inside {other:?}"),
        };
    }
    value
}

/// The table at a dotted path.
pub fn table_at<'a>(table: &'a mut Table, path: &str) -> &'a mut Table {
    at(table, path).as_table_mut().unwrap()
}

/// Sets `key` in the table at `path` (an empty path is the top level).
pub fn set(table: &mut Table, path: &str, key: &str, value: Value) {
    let target = if path.is_empty() {
        table
    } else {
        table_at(table, path)
    };
    target.insert(key.into(), value);
}

/// Removes `key` from the table at `path`.
pub fn remove(table: &mut Table, path: &str, key: &str) {
    let target = if path.is_empty() {
        table
    } else {
        table_at(table, path)
    };
    assert!(target.remove(key).is_some(), "no `{key}` at `{path}`");
}

/// A TOML value from its text, such as `"x"` or `{ a = 1 }`.
pub fn value(text: &str) -> Value {
    let table: Table = format!("v = {text}").parse().unwrap();
    table["v"].clone()
}
