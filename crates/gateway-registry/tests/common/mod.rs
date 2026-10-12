//! Helpers shared by the table tests: a registry file held as a TOML table, edited in place,
//! with each tool's approval hashes recomputed so that an edit tests one rule and not the
//! hashes.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use gateway_core::Resource;
use gateway_registry::{
    Credential, ReachTest, Registry, RegistryError, Server, binding_sha256, definition_sha256,
};
use toml::{Table, Value};

/// A registry file that loads: two servers, one reaching a project and one reaching nothing,
/// three read tools (two declared from their arguments, one with no resources), two surfaces,
/// two profiles, a rule for workloads and one for a group, and limits for a team and a group.
pub const BASE: &str = r#"
revision = "r1"

[[servers]]
name = "docs-server"
system = "docs"
owner = "team-docs"
identity = "docs.internal.example.test"
address = "https://docs.internal.example.test/mcp"
credential = { mode = "team_service_identity", reference = "docs-credential", principal = "docs-reader" }
narrowing = "none"
permits = "read"
reach = [{ system = "docs", kind = "project", identifier = "atlas" }]
reach_test = { date = 2026-10-01, record = "a caller limited to atlas was refused borealis" }
destination = "public"
probe = { result = "refused", date = 2026-10-01 }
reach_check = { tool = "docs__read", arguments = { project = "borealis", document = "plan" } }

[[servers]]
name = "wiki-server"
system = "wiki"
owner = "team-wiki"
identity = "wiki.internal.example.test"
address = "http://wiki.internal.example.test:8080/mcp"
credential = { mode = "gateway_token", reference = "wiki-credential", principal = "wiki-reader" }
narrowing = "limit"
permits = "read"
reach = []
destination = "in_cluster"
probe = { result = "refused", date = 2026-10-02 }

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
binding_sha256 = ""
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
binding_sha256 = ""
resources = "no_resources"

[tools.input_schema]
type = "object"

[tools.input_schema.properties.query]
type = "string"

[[tools]]
name = "wiki__page"
server = "wiki-server"
upstream_name = "page"
classification = "read"
description = "Reads a page."
approved_by = "approver@example.test"
approved_at = 2026-10-01T12:00:00Z
definition_sha256 = ""
binding_sha256 = ""
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
tools = ["wiki__page"]
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

/// Sets every tool's `definition_sha256` to the hash of its definition as it now stands, and
/// its `binding_sha256` to the hash of its server's entry as it now stands. A tool whose server
/// is not registered keeps its binding hash.
pub fn rehash(table: &mut Table) {
    let servers: Vec<Server> = match table.get("servers") {
        Some(Value::Array(servers)) => servers.iter().filter_map(server).collect(),
        _ => Vec::new(),
    };
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
        let named = tool.get("server").and_then(Value::as_str);
        if let Some(server) = servers
            .iter()
            .find(|server| Some(server.name.as_str()) == named)
        {
            let hash = binding_sha256(server);
            tool.insert("binding_sha256".into(), Value::String(hash));
        }
    }
}

/// A server entry of the file as the loader would read it, if it has the fields the binding
/// needs. The probe and the reach check are not in the binding, and are left out.
fn server(entry: &Value) -> Option<Server> {
    let text = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_owned);
    let parsed = |key: &str| entry.get(key).cloned();
    let credential = entry.get("credential")?;
    let credential_text = |key: &str| {
        credential
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let reach: Vec<Resource> = parsed("reach")?.try_into().ok()?;
    let reach_test = entry.get("reach_test").and_then(|test| {
        Some(ReachTest {
            date: test.get("date")?.as_datetime()?.to_string(),
            record: test.get("record")?.as_str()?.to_owned(),
        })
    });
    Some(Server {
        name: text("name")?.as_str().into(),
        system: text("system").unwrap_or_default(),
        owner: text("owner").unwrap_or_default(),
        identity: text("identity").unwrap_or_default(),
        address: text("address").unwrap_or_default(),
        credential: Credential {
            mode: credential.get("mode")?.clone().try_into().ok()?,
            reference: credential_text("reference")?,
            principal: credential_text("principal")?,
        },
        narrowing: parsed("narrowing")?.try_into().ok()?,
        permits: parsed("permits")?.try_into().ok()?,
        reach: reach.into_iter().collect(),
        reach_test,
        destination: parsed("destination")?.try_into().ok()?,
        probe: None,
        reach_check: None,
    })
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
