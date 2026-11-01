//! Built-in tools' approvals, `[[built_in_tools]]`, on the `[[connectors]]` entries that declare
//! their credential: what loads, and one case per way an approval or its entry can be wrong.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{base, load, set, value};
use gateway_core::{
    Classification, ConnectorName, CredentialMode, DeclaredFrom, EntryKind, Narrowing, Resource,
    ResourceDeclaration, Resources, SnapshotError, ToolName,
};
use gateway_registry::{
    Assurance, RegistryError, ResourceSource, StatedResources, built_in_binding_sha256,
    definition_sha256,
};
use serde_json::json;
use toml::Table;

const DECLARED: &str = r#"credential = { mode = "team_service_identity", principal = "switchboard-github-app" }
narrowing = "limit"
permits = "read""#;

const SCHEMA: &str = r#"{ type = "object", additionalProperties = false, required = ["owner", "repo", "path"], properties = { owner = { type = "string" }, repo = { type = "string" }, path = { type = "string" } } }"#;

const FROM_ARGUMENTS: &str = r#"{ from_arguments = [{ from_argument = "repo", qualified_by = "owner", system = "github", kind = "repository" }] }"#;

fn name(text: &str) -> ConnectorName {
    ConnectorName::new(text)
}

fn tool(text: &str) -> ToolName {
    ToolName::parse(text).unwrap()
}

/// The base registry with a GitHub entry `github-read` whose fields after its tools are
/// `declared`, serving `github__get_file`, and an approval of that tool on it with `resources`
/// and `classification`, its hashes computed from the entry as written.
fn registry(declared: &str, classification: &str, resources: &str) -> Table {
    let mut table = base();
    let entry = format!(
        r#"[{{ name = "github-read", system = "github", permissions = {{ contents = "read" }}, tools = ["github__get_file"], {} }}]"#,
        declared.replace('\n', ", ")
    );
    set(&mut table, "", "connectors", value(&entry));
    let binding = load(&table)
        .ok()
        .and_then(|registry| built_in_binding_sha256(&registry.connectors()[&name("github-read")]))
        .unwrap_or_default();
    let schema: serde_json::Value = serde_json::to_value(value(SCHEMA)).unwrap();
    let definition = definition_sha256("github__get_file", None, "Reads a file.", &schema);
    let approval = format!(
        r#"[{{ name = "github__get_file", connector = "github-read", classification = "{classification}", description = "Reads a file.", input_schema = {SCHEMA}, approved_by = "reviewer", approved_at = 2026-10-15T00:00:00Z, definition_sha256 = "{definition}", binding_sha256 = "{binding}", resources = {resources} }}]"#
    );
    set(&mut table, "", "built_in_tools", value(&approval));
    table
}

fn approved() -> Table {
    registry(DECLARED, "read", FROM_ARGUMENTS)
}

#[test]
fn a_built_in_tool_loads_with_its_definition_adapter_and_entry() {
    let registry = load(&approved()).unwrap();
    let name_ = tool("github__get_file");
    assert_eq!(registry.built_in_tools()[&name_], name("github-read"));
    assert!(registry.definitions().contains_key(&name_));
    assert!(registry.approvals().contains_key(&name_));
    assert!(
        !registry.routes().contains_key(&name_),
        "nothing is forwarded"
    );

    // What the approval declares the tool is, for the gateway to compare with what its
    // connector's code states.
    assert_eq!(
        registry.built_in_assurances()[&name_],
        Assurance {
            classification: Classification::Read,
            resources: StatedResources::FromArguments(vec![ResourceSource {
                from_argument: "repo".into(),
                qualified_by: Some("owner".into()),
                system: "github".into(),
                kind: "repository".into(),
            }]),
        }
    );

    let approved = registry.snapshot().tool(&name_).unwrap();
    assert_eq!(approved.connector, name("github-read"));
    assert_eq!(approved.classification, Classification::Read);
    assert_eq!(approved.resources, ResourceDeclaration::Declared);
    assert_eq!(approved.declared_from, Some(DeclaredFrom::Arguments));

    let entry = registry.snapshot().entry(&name("github-read")).unwrap();
    assert_eq!(entry.kind, EntryKind::BuiltIn);
    assert_eq!(entry.narrowing, Narrowing::Limit);
    assert_eq!(entry.credential, CredentialMode::TeamServiceIdentity);
    assert_eq!(entry.principal, "switchboard-github-app");
    assert!(entry.reach.is_empty());

    // The adapter names the repository as a limit holds it, `owner/repo`.
    let arguments = json!({"owner": "example-org", "repo": "atlas", "path": "README.md"});
    assert_eq!(
        registry.adapters()[&name_].resources(arguments.as_object().unwrap()),
        Resources::Named(vec![Resource {
            system: "github".into(),
            kind: "repository".into(),
            identifier: "example-org/atlas".into(),
        }])
    );
    // A missing or empty owner names nothing, which check 6 denies.
    for arguments in [
        json!({"repo": "atlas", "path": "x"}),
        json!({"owner": "", "repo": "atlas", "path": "x"}),
        json!({"owner": 7, "repo": "atlas", "path": "x"}),
    ] {
        assert_eq!(
            registry.adapters()[&name_].resources(arguments.as_object().unwrap()),
            Resources::Named(Vec::new()),
            "{arguments}"
        );
    }
}

#[test]
fn an_entry_that_declares_its_credential_is_a_built_in_entry_of_the_snapshot() {
    let mut table = base();
    let entry = format!(
        r#"[{{ name = "github-read", system = "github", permissions = {{ contents = "read" }}, tools = ["github__get_file"], {} }}]"#,
        DECLARED.replace('\n', ", ")
    );
    set(&mut table, "", "connectors", value(&entry));
    let registry = load(&table).unwrap();
    assert!(registry.snapshot().entry(&name("github-read")).is_some());
    assert!(
        registry.connectors()[&name("github-read")]
            .declaration
            .is_some()
    );
}

#[test]
fn an_entry_without_a_credential_keeps_its_meaning() {
    let mut table = base();
    set(
        &mut table,
        "",
        "connectors",
        value(
            r#"[{ name = "github-read", system = "github", permissions = { contents = "read" }, tools = ["github__get_file"] }]"#,
        ),
    );
    let registry = load(&table).unwrap();
    assert!(
        registry.connectors()[&name("github-read")]
            .declaration
            .is_none()
    );
    assert!(registry.snapshot().entry(&name("github-read")).is_none());
    assert!(registry.built_in_tools().is_empty());
}

#[test]
fn a_built_in_tool_may_check_its_own_scope() {
    let registry = load(&registry(DECLARED, "read", r#""checks_own_scope""#)).unwrap();
    let approved = registry.snapshot().tool(&tool("github__get_file")).unwrap();
    assert_eq!(approved.resources, ResourceDeclaration::ChecksOwnScope);
    assert_eq!(approved.declared_from, None);
    assert_eq!(
        registry.built_in_assurances()[&tool("github__get_file")].resources,
        StatedResources::ChecksOwnScope
    );
}

/// Each declaration an approval can make is what the registry gives the gateway to compare with
/// the connector's statement, and no other. `as_reach` is in tests/reach_report.rs, since its
/// entry needs a reach report.
#[test]
fn each_declaration_is_the_assurance_the_approval_states() {
    for (resources, stated) in [
        (r#""no_resources""#, StatedResources::NoResources),
        (r#""checks_own_scope""#, StatedResources::ChecksOwnScope),
    ] {
        let registry = load(&registry(DECLARED, "read", resources)).unwrap();
        assert_eq!(
            registry.built_in_assurances()[&tool("github__get_file")],
            Assurance {
                classification: Classification::Read,
                resources: stated,
            },
            "{resources}"
        );
    }
}

/// A repository of the GitHub entry's reach.
const ATLAS: &str =
    r#"{ system = "github", kind = "repository", identifier = "example-org/atlas" }"#;

/// A tool declared as its entry's reach names the whole reach on every call, so its entry must
/// record one (decision 0011, section 1), as a proxied entry must; and a GitHub entry with a
/// reach must name the reach report it is checked against (decision 0011, section 4).
#[test]
fn a_reach_that_is_required_cannot_be_left_out() {
    let missing = || RegistryError::ReachMissing {
        tool: tool("github__get_file"),
        connector: name("github-read"),
    };
    // No reach at all, and a reach that is empty.
    let empty = format!("{DECLARED}\nreach = []");
    for declared in [DECLARED.to_owned(), empty] {
        let got = load(&registry(&declared, "read", r#""as_reach""#))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(got, missing(), "{declared}");
        assert_eq!(
            got.to_string(),
            "built-in tool `github__get_file` is declared as the reach of connector \
             `github-read`, which declares no reach; record the entry's reach, as a proxied \
             entry records its own"
        );
    }
    // A GitHub entry with a reach and no reach report, whatever its tools declare.
    let unchecked = format!("{DECLARED}\nreach = [{ATLAS}]");
    for resources in [r#""as_reach""#, FROM_ARGUMENTS] {
        let got = load(&registry(&unchecked, "read", resources))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            got,
            RegistryError::ReachReportMissing(name("github-read")),
            "{resources}"
        );
    }
    // The entry alone, with no approval, is refused too.
    let mut table = base();
    let entry = format!(
        r#"[{{ name = "github-read", system = "github", permissions = {{ contents = "read" }}, tools = ["github__get_file"], {} }}]"#,
        unchecked.replace('\n', ", ")
    );
    set(&mut table, "", "connectors", value(&entry));
    assert_eq!(
        load(&table).map(|_| ()).unwrap_err(),
        RegistryError::ReachReportMissing(name("github-read"))
    );
    // An entry of a system whose vendor report is not built may declare a reach without one.
    let mut table = base();
    set(
        &mut table,
        "",
        "connectors",
        value(&format!(
            r#"[{{ name = "jira-read", system = "jira", permissions = {{ read = "read" }}, tools = ["jira__get_issue"], {}, reach = [{{ system = "jira", kind = "site", identifier = "example.atlassian.net" }}] }}]"#,
            DECLARED.replace('\n', ", ")
        )),
    );
    load(&table).unwrap();
}

#[test]
fn a_malformed_approval_or_entry_is_refused() {
    let partly = r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit""#;
    let reach_alone = r#"reach = []"#;
    let call = r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "call"
permits = "read""#;
    let cases: Vec<(&str, Table, RegistryError)> = vec![
        (
            "an entry declaring part of its credential",
            registry(partly, "read", FROM_ARGUMENTS),
            RegistryError::EntryPartlyDeclared(name("github-read")),
        ),
        (
            "an entry with a reach and no credential",
            registry(reach_alone, "read", FROM_ARGUMENTS),
            RegistryError::EntryPartlyDeclared(name("github-read")),
        ),
        (
            "an approval on an entry that declares no credential",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "",
                    "connectors",
                    value(
                        r#"[{ name = "github-read", system = "github", permissions = { contents = "read" }, tools = ["github__get_file"] }]"#,
                    ),
                );
                table
            },
            RegistryError::EntryUndeclared {
                tool: tool("github__get_file"),
                connector: name("github-read"),
            },
        ),
        (
            "an approval on an entry the file does not have",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "built_in_tools.0",
                    "connector",
                    value(r#""github-write""#),
                );
                table
            },
            RegistryError::UnknownConnector {
                tool: tool("github__get_file"),
                connector: name("github-write"),
            },
        ),
        (
            "an approval of a tool its entry does not list",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "connectors.0",
                    "tools",
                    value(r#"["github__get_pr"]"#),
                );
                table
            },
            RegistryError::BuiltInToolNotListed {
                tool: tool("github__get_file"),
                connector: name("github-read"),
            },
        ),
        (
            "an approval named outside its entry's system",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "connectors.0",
                    "tools",
                    value(r#"["gh__get_file"]"#),
                );
                set(
                    &mut table,
                    "built_in_tools.0",
                    "name",
                    value(r#""gh__get_file""#),
                );
                table
            },
            RegistryError::NameOutsideSystem {
                tool: tool("gh__get_file"),
                system: "github".into(),
            },
        ),
        (
            "a definition edited after its approval",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "built_in_tools.0",
                    "description",
                    value(r#""Reads anything.""#),
                );
                table
            },
            RegistryError::DefinitionChanged {
                tool: tool("github__get_file"),
                recorded: String::new(),
                computed: String::new(),
            },
        ),
        (
            "a permission widened after its approval",
            {
                let mut table = approved();
                set(
                    &mut table,
                    "connectors.0",
                    "permissions",
                    value(r#"{ contents = "write" }"#),
                );
                table
            },
            RegistryError::BuiltInBindingChanged {
                tool: tool("github__get_file"),
                connector: name("github-read"),
                recorded: String::new(),
                computed: String::new(),
            },
        ),
        (
            "a qualifier the schema does not declare",
            registry(
                DECLARED,
                "read",
                r#"{ from_arguments = [{ from_argument = "repo", qualified_by = "org", system = "github", kind = "repository" }] }"#,
            ),
            RegistryError::AdapterQualifierNotString {
                tool: tool("github__get_file"),
                argument: "org".into(),
            },
        ),
        (
            "a source the schema does not declare",
            registry(
                DECLARED,
                "read",
                r#"{ from_arguments = [{ from_argument = "repository", system = "github", kind = "repository" }] }"#,
            ),
            RegistryError::AdapterArgumentUndeclared {
                tool: tool("github__get_file"),
                argument: "repository".into(),
            },
        ),
        (
            "a side effect with no settlement",
            registry(DECLARED, "propose", FROM_ARGUMENTS),
            RegistryError::Snapshot(SnapshotError::SettlementUndeclared {
                tool: tool("github__get_file"),
                classification: Classification::Propose,
            }),
        ),
        (
            "an entry whose credential names no principal",
            registry(
                &DECLARED.replace("switchboard-github-app", ""),
                "read",
                FROM_ARGUMENTS,
            ),
            RegistryError::EmptyField {
                field: "credential.principal",
                place: "connector `github-read`".into(),
            },
        ),
        (
            "an entry narrowed per call serving a tool that checks its own scope (rule 7)",
            registry(call, "read", r#""checks_own_scope""#),
            RegistryError::Snapshot(SnapshotError::CallNarrowingWithoutArguments {
                entry: name("github-read"),
                tool: tool("github__get_file"),
            }),
        ),
    ];
    for (case, table, want) in cases {
        let got = load(&table).map(|_| ()).unwrap_err();
        match (&got, &want) {
            // The hashes differ every run of the case's own edit; the variant and tool are what
            // the case shows.
            (
                RegistryError::DefinitionChanged { tool: got, .. },
                RegistryError::DefinitionChanged { tool: want, .. },
            )
            | (
                RegistryError::BuiltInBindingChanged { tool: got, .. },
                RegistryError::BuiltInBindingChanged { tool: want, .. },
            ) => assert_eq!(got, want, "{case}"),
            _ => assert_eq!(got, want, "{case}"),
        }
    }
}

#[test]
fn an_approval_refuses_unknown_fields() {
    let mut table = approved();
    set(
        &mut table,
        "built_in_tools.0",
        "server",
        value(r#""docs-server""#),
    );
    let got = load(&table).map(|_| ()).unwrap_err();
    assert!(matches!(got, RegistryError::Parse(_)), "{got:?}");
}

#[test]
fn the_built_in_binding_covers_the_entry_but_not_its_name_or_tools() {
    let binding = |declared: &str, permissions: &str, entry_name: &str, tools: &str| {
        let mut table = base();
        let entry = format!(
            r#"[{{ name = "{entry_name}", system = "github", permissions = {permissions}, tools = {tools}, {} }}]"#,
            declared.replace('\n', ", ")
        );
        set(&mut table, "", "connectors", value(&entry));
        let registry = load(&table).unwrap();
        built_in_binding_sha256(&registry.connectors()[&name(entry_name)]).unwrap()
    };
    let read = r#"{ contents = "read" }"#;
    let tools = r#"["github__get_file"]"#;
    let unchanged = binding(DECLARED, read, "github-read", tools);
    assert_eq!(unchanged, binding(DECLARED, read, "github-other", tools));
    assert_eq!(
        unchanged,
        binding(
            DECLARED,
            read,
            "github-read",
            r#"["github__get_file", "github__get_pr"]"#
        )
    );
    assert_ne!(
        unchanged,
        binding(DECLARED, r#"{ contents = "write" }"#, "github-read", tools)
    );
    assert_ne!(
        unchanged,
        binding(
            DECLARED,
            r#"{ contents = "read", issues = "read" }"#,
            "github-read",
            tools
        )
    );
    for changed in [
        DECLARED.replace("limit", "call"),
        DECLARED.replace("\"read\"", "\"propose\""),
        DECLARED.replace("switchboard-github-app", "another-app"),
        DECLARED.replace("team_service_identity", "gateway_token"),
    ] {
        assert_ne!(
            unchanged,
            binding(&changed, read, "github-read", tools),
            "{changed}"
        );
    }
    // A GitHub entry with a reach loads only with a reach report beside it, so the reach is
    // given to the entry as loaded.
    let mut table = base();
    let entry = format!(
        r#"[{{ name = "github-read", system = "github", permissions = {read}, tools = {tools}, {} }}]"#,
        DECLARED.replace('\n', ", ")
    );
    set(&mut table, "", "connectors", value(&entry));
    let mut entry = load(&table).unwrap().connectors()[&name("github-read")].clone();
    assert_eq!(built_in_binding_sha256(&entry).unwrap(), unchanged);
    if let Some(declaration) = entry.declaration.as_mut() {
        declaration.reach.insert(Resource {
            system: "github".into(),
            kind: "repository".into(),
            identifier: "example-org/atlas".into(),
        });
    }
    assert_ne!(built_in_binding_sha256(&entry).unwrap(), unchanged);
}
