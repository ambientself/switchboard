//! The loader's rules, one table case per way a registry file can be wrong. Each case makes
//! one edit to a file that loads and names the one error it must produce, so a rule that
//! stops firing, or a different rule firing first, fails its case.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{at, base, load, rehash, remove, set, table_at, value};
use gateway_core::{Classification, ResourceDeclaration, SnapshotError, ToolName};
use gateway_registry::{RegistryError, RulePrincipal};
use toml::Table;

fn tool(name: &str) -> ToolName {
    ToolName::parse(name).unwrap()
}

enum Want {
    /// The file loads.
    Loads,
    /// The file is refused with exactly this error.
    Error(RegistryError),
    /// The file does not parse, and the message says this.
    Parse(&'static str),
    /// The file is refused with an error that satisfies this test.
    Matches(fn(&RegistryError) -> bool),
}

struct Case {
    name: &'static str,
    edit: fn(&mut Table),
    rehash: bool,
    want: Want,
}

fn case(name: &'static str, edit: fn(&mut Table), want: Want) -> Case {
    Case {
        name,
        edit,
        rehash: true,
        want,
    }
}

/// A case whose edit is not re-approved: the hash stays as it was.
fn unapproved(name: &'static str, edit: fn(&mut Table), want: Want) -> Case {
    Case {
        name,
        edit,
        rehash: false,
        want,
    }
}

fn empty(field: &'static str, place: &str) -> Want {
    Want::Error(RegistryError::EmptyField {
        field,
        place: place.into(),
    })
}

fn cases() -> Vec<Case> {
    use RegistryError as E;
    vec![
        case("the base file loads", |_| {}, Want::Loads),
        // Unknown fields, everywhere.
        case(
            "an unknown top-level field",
            |t| set(t, "", "tool", value("[]")),
            Want::Parse("unknown field `tool`"),
        ),
        case(
            "an unknown server field",
            |t| set(t, "servers.0", "token", value("\"x\"")),
            Want::Parse("unknown field `token`"),
        ),
        case(
            "an unknown credential field",
            |t| set(t, "servers.0.credential", "secret", value("\"x\"")),
            Want::Parse("unknown field `secret`"),
        ),
        case(
            "an unknown credential mode",
            |t| set(t, "servers.0.credential", "mode", value("\"passthrough\"")),
            Want::Parse("unknown variant `passthrough`"),
        ),
        case(
            "an unknown tool field",
            |t| set(t, "tools.0", "classfication", value("\"write\"")),
            Want::Parse("unknown field `classfication`"),
        ),
        case(
            "an unknown resource source field",
            |t| {
                set(
                    t,
                    "tools.0.resources.from_arguments.0",
                    "default",
                    value("\"atlas\""),
                )
            },
            Want::Parse("unknown field `default`"),
        ),
        case(
            "a tool that says it checks its own scope",
            |t| set(t, "tools.0", "resources", value("\"checks_own_scope\"")),
            Want::Parse("unknown variant `checks_own_scope`"),
        ),
        case(
            "a resources table with a second key",
            |t| set(t, "tools.0.resources", "no_resources", value("true")),
            Want::Matches(|e| matches!(e, RegistryError::Parse(_))),
        ),
        case(
            "an unknown surface field",
            |t| set(t, "surfaces.0", "users", value("[]")),
            Want::Parse("unknown field `users`"),
        ),
        case(
            "an unknown principal id field",
            |t| {
                set(
                    t,
                    "surfaces.1.principals.only.0",
                    "team",
                    value("\"team-a\""),
                )
            },
            Want::Parse("unknown field `team`"),
        ),
        case(
            "an unknown profile field",
            |t| set(t, "profiles.0", "default", value("true")),
            Want::Parse("unknown field `default`"),
        ),
        case(
            "an unknown profile rule field",
            |t| set(t, "profile_rules.0", "team", value("\"team-a\"")),
            Want::Parse("unknown field `team`"),
        ),
        case(
            "an unknown kind of rule principal",
            |t| set(t, "profile_rules.0", "principal", value("\"anyone\"")),
            Want::Parse("unknown variant `anyone`"),
        ),
        case(
            "an unknown limits field",
            |t| set(t, "limits", "users", value("{}")),
            Want::Parse("unknown field `users`"),
        ),
        case(
            "an unknown limit resource field",
            |t| set(t, "limits.teams.team-a.0", "pattern", value("true")),
            Want::Parse("unknown field `pattern`"),
        ),
        // Required fields, none with a default.
        case(
            "a tool with no classification",
            |t| remove(t, "tools.0", "classification"),
            Want::Parse("missing field `classification`"),
        ),
        case(
            "a tool with an unknown classification",
            |t| set(t, "tools.0", "classification", value("\"admin\"")),
            Want::Parse("admin"),
        ),
        case(
            "a tool that does not say how its resources are known",
            |t| remove(t, "tools.1", "resources"),
            Want::Parse("missing field `resources`"),
        ),
        case(
            "a tool with no description",
            |t| remove(t, "tools.0", "description"),
            Want::Parse("missing field `description`"),
        ),
        case(
            "a tool with no input schema",
            |t| remove(t, "tools.0", "input_schema"),
            Want::Parse("missing field `input_schema`"),
        ),
        unapproved(
            "a tool with no approval hash",
            |t| remove(t, "tools.0", "definition_sha256"),
            Want::Parse("missing field `definition_sha256`"),
        ),
        case(
            "a tool with no approver",
            |t| remove(t, "tools.0", "approved_by"),
            Want::Parse("missing field `approved_by`"),
        ),
        case(
            "a tool with no server",
            |t| remove(t, "tools.0", "server"),
            Want::Parse("missing field `server`"),
        ),
        case(
            "an approval time that is text",
            |t| {
                set(
                    t,
                    "tools.0",
                    "approved_at",
                    value("\"2026-10-01T12:00:00Z\""),
                )
            },
            Want::Parse("approved_at"),
        ),
        case(
            "a surface that does not say whether it restricts principals",
            |t| remove(t, "surfaces.0", "principals"),
            Want::Parse("missing field `principals`"),
        ),
        case(
            "a profile that does not say whether it requires a delegation",
            |t| remove(t, "profiles.0", "requires_delegation"),
            Want::Parse("missing field `requires_delegation`"),
        ),
        case(
            "a file with no profile rules",
            |t| remove(t, "", "profile_rules"),
            Want::Parse("missing field `profile_rules`"),
        ),
        case(
            "a file with no limits",
            |t| remove(t, "", "limits"),
            Want::Parse("missing field `limits`"),
        ),
        case(
            "an invalid exposed name",
            |t| set(t, "tools.0", "name", value("\"docs__read file\"")),
            Want::Parse("not a valid tool name"),
        ),
        // Empty text.
        case(
            "an empty revision",
            |t| set(t, "", "revision", value("\"\"")),
            empty("revision", "the registry"),
        ),
        case(
            "a server with no system",
            |t| set(t, "servers.0", "system", value("\"\"")),
            empty("system", "server `docs-server`"),
        ),
        case(
            "a server with no owner",
            |t| set(t, "servers.0", "owner", value("\"\"")),
            empty("owner", "server `docs-server`"),
        ),
        case(
            "a server with no identity",
            |t| set(t, "servers.0", "identity", value("\"\"")),
            empty("identity", "server `docs-server`"),
        ),
        case(
            "a credential with no reference",
            |t| set(t, "servers.0.credential", "reference", value("\"\"")),
            empty("credential.reference", "server `docs-server`"),
        ),
        case(
            "a tool with no upstream name",
            |t| set(t, "tools.0", "upstream_name", value("\"\"")),
            empty("upstream_name", "tool `docs__read`"),
        ),
        case(
            "a tool with an empty description",
            |t| set(t, "tools.0", "description", value("\"\"")),
            empty("description", "tool `docs__read`"),
        ),
        case(
            "a tool with an empty approver",
            |t| set(t, "tools.0", "approved_by", value("\"\"")),
            empty("approved_by", "tool `docs__read`"),
        ),
        case(
            "a tool with an empty title",
            |t| set(t, "tools.0", "title", value("\"\"")),
            empty("title", "tool `docs__read`"),
        ),
        case(
            "a resource source with no system",
            |t| {
                set(
                    t,
                    "tools.0.resources.from_arguments.0",
                    "system",
                    value("\"\""),
                )
            },
            empty("resources.system", "tool `docs__read`"),
        ),
        case(
            "a resource source with no kind",
            |t| {
                set(
                    t,
                    "tools.0.resources.from_arguments.0",
                    "kind",
                    value("\"\""),
                )
            },
            empty("resources.kind", "tool `docs__read`"),
        ),
        case(
            "a team limit with an empty identifier",
            |t| set(t, "limits.teams.team-a.0", "identifier", value("\"\"")),
            empty("identifier", "a limit of team `team-a`"),
        ),
        case(
            "a group limit with no kind",
            |t| set(t, "limits.groups.group-g.1", "kind", value("\"\"")),
            empty("kind", "a limit of group `group-g`"),
        ),
        case(
            "a group limit with no system",
            |t| set(t, "limits.groups.group-g.1", "system", value("\"\"")),
            empty("system", "a limit of group `group-g`"),
        ),
        // Servers.
        case(
            "a server registered twice",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"docs-server\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::DuplicateServer("docs-server".into())),
        ),
        case(
            "an ftp address",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"ftp://docs.example.test/\""),
                )
            },
            Want::Error(E::AddressNotHttp {
                server: "docs-server".into(),
                address: "ftp://docs.example.test/".into(),
            }),
        ),
        case(
            "an address with no scheme",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"docs.example.test:8080/mcp\""),
                )
            },
            Want::Error(E::AddressNotHttp {
                server: "docs-server".into(),
                address: "docs.example.test:8080/mcp".into(),
            }),
        ),
        case(
            "an address with no host",
            |t| set(t, "servers.0", "address", value("\"https:///mcp\"")),
            Want::Error(E::AddressNotHttp {
                server: "docs-server".into(),
                address: "https:///mcp".into(),
            }),
        ),
        case(
            "an address that is only a scheme",
            |t| set(t, "servers.0", "address", value("\"http://\"")),
            Want::Error(E::AddressNotHttp {
                server: "docs-server".into(),
                address: "http://".into(),
            }),
        ),
        // Tools: names, servers, collisions.
        case(
            "a tool approved twice under one name",
            |t| {
                let mut copy = table_at(t, "tools.0").clone();
                copy.insert("upstream_name".into(), value("\"read_again\""));
                at(t, "tools").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::DuplicateTool(tool("docs__read"))),
        ),
        case(
            "one upstream tool approved under two names",
            |t| {
                let mut copy = table_at(t, "tools.0").clone();
                copy.insert("name".into(), value("\"docs__read_again\""));
                at(t, "tools").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::DuplicateUpstream {
                server: "docs-server".into(),
                upstream_name: "read".into(),
            }),
        ),
        case(
            "the same upstream name on two servers",
            |t| set(t, "tools.2", "upstream_name", value("\"read\"")),
            Want::Loads,
        ),
        case(
            "a tool on a server that is not registered",
            |t| set(t, "tools.0", "server", value("\"files-server\"")),
            Want::Error(E::UnknownServer {
                tool: tool("docs__read"),
                server: "files-server".into(),
            }),
        ),
        case(
            "a tool named after another server's system",
            |t| set(t, "tools.0", "server", value("\"wiki-server\"")),
            Want::Error(E::NameOutsideSystem {
                tool: tool("docs__read"),
                system: "wiki".into(),
            }),
        ),
        case(
            "a tool name with one underscore after the system",
            |t| set(t, "tools.0", "name", value("\"docs_read\"")),
            Want::Error(E::NameOutsideSystem {
                tool: tool("docs_read"),
                system: "docs".into(),
            }),
        ),
        case(
            "a tool name that only starts like the system",
            |t| set(t, "tools.0", "name", value("\"docsy__read\"")),
            Want::Error(E::NameOutsideSystem {
                tool: tool("docsy__read"),
                system: "docs".into(),
            }),
        ),
        case(
            "a tool name with nothing after the system",
            |t| set(t, "tools.0", "name", value("\"docs__\"")),
            Want::Error(E::NameOutsideSystem {
                tool: tool("docs__"),
                system: "docs".into(),
            }),
        ),
        // Approval.
        case(
            "an approval time with no offset",
            |t| set(t, "tools.0", "approved_at", value("2026-10-01T12:00:00")),
            Want::Error(E::ApprovedAtIncomplete(tool("docs__read"))),
        ),
        case(
            "an approval date with no time",
            |t| set(t, "tools.0", "approved_at", value("2026-10-01")),
            Want::Error(E::ApprovedAtIncomplete(tool("docs__read"))),
        ),
        unapproved(
            "a description edited after approval",
            |t| {
                set(
                    t,
                    "tools.0",
                    "description",
                    value("\"Reads any document.\""),
                )
            },
            Want::Matches(
                |e| matches!(e, E::DefinitionChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a title edited after approval",
            |t| set(t, "tools.0", "title", value("\"Read anything\"")),
            Want::Matches(|e| matches!(e, E::DefinitionChanged { .. })),
        ),
        unapproved(
            "a title removed after approval",
            |t| remove(t, "tools.0", "title"),
            Want::Matches(|e| matches!(e, E::DefinitionChanged { .. })),
        ),
        unapproved(
            "a schema edited after approval",
            |t| {
                set(
                    t,
                    "tools.0.input_schema.properties",
                    "all",
                    value("{ type = \"boolean\" }"),
                )
            },
            Want::Matches(|e| matches!(e, E::DefinitionChanged { .. })),
        ),
        unapproved(
            "an upstream name edited after approval",
            |t| set(t, "tools.0", "upstream_name", value("\"read_any\"")),
            Want::Matches(|e| matches!(e, E::DefinitionChanged { .. })),
        ),
        unapproved(
            "a hash in capitals",
            |t| {
                let hash = at(t, "tools.0.definition_sha256")
                    .as_str()
                    .unwrap()
                    .to_uppercase();
                set(t, "tools.0", "definition_sha256", toml::Value::String(hash));
            },
            Want::Matches(|e| matches!(e, E::DefinitionChanged { .. })),
        ),
        unapproved(
            "a classification changed after approval needs no new hash",
            |t| set(t, "tools.1", "classification", value("\"write\"")),
            Want::Loads,
        ),
        // Input schemas.
        case(
            "a schema whose type is not object",
            |t| set(t, "tools.1.input_schema", "type", value("\"array\"")),
            Want::Error(E::SchemaNotObject(tool("wiki__search"))),
        ),
        case(
            "a schema with no type",
            |t| remove(t, "tools.1.input_schema", "type"),
            Want::Error(E::SchemaNotObject(tool("wiki__search"))),
        ),
        case(
            "a schema combined with anyOf",
            |t| {
                set(
                    t,
                    "tools.1.input_schema",
                    "anyOf",
                    value("[{ required = [\"query\"] }]"),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaUnfollowed { tool, keyword, at } if tool.as_str() == "wiki__search" && keyword == "anyOf" && at.as_str().is_empty()),
            ),
        ),
        case(
            "a property that is a reference",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties.query",
                    "$ref",
                    value("\"#/$defs/q\""),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaUnfollowed { keyword, at, .. } if keyword == "$ref" && at.as_str() == "/properties/query"),
            ),
        ),
        case(
            "array items with pattern properties",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties",
                    "tags",
                    value(
                        "{ type = \"array\", items = { type = \"object\", patternProperties = { x = {} } } }",
                    ),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaUnfollowed { keyword, at, .. } if keyword == "patternProperties" && at.as_str() == "/properties/tags/items"),
            ),
        ),
        case(
            "a property named like a keyword is still a property",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties",
                    "anyOf",
                    value("{ type = \"string\" }"),
                )
            },
            Want::Loads,
        ),
        case(
            "properties that are a list",
            |t| {
                set(
                    t,
                    "tools.1.input_schema",
                    "properties",
                    value("[\"query\"]"),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaMalformed { at, .. } if at.as_str() == "/properties"),
            ),
        ),
        case(
            "a property that is not a schema",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties",
                    "query",
                    value("\"string\""),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaMalformed { at, .. } if at.as_str() == "/properties/query"),
            ),
        ),
        case(
            "items that are not a schema",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties",
                    "tags",
                    value("{ type = \"array\", items = [] }"),
                )
            },
            Want::Matches(
                |e| matches!(e, E::SchemaMalformed { at, .. } if at.as_str() == "/properties/tags/items"),
            ),
        ),
        case(
            "a property that is true",
            |t| {
                set(
                    t,
                    "tools.1.input_schema.properties",
                    "anything",
                    value("true"),
                )
            },
            Want::Loads,
        ),
        // Adapters.
        case(
            "resources from arguments with no source",
            |t| set(t, "tools.0", "resources", value("{ from_arguments = [] }")),
            Want::Error(E::AdapterWithoutSources(tool("docs__read"))),
        ),
        case(
            "a source reading an undeclared argument",
            |t| {
                set(
                    t,
                    "tools.0.resources.from_arguments.0",
                    "from_argument",
                    value("\"projects\""),
                )
            },
            Want::Error(E::AdapterArgumentUndeclared {
                tool: tool("docs__read"),
                argument: "projects".into(),
            }),
        ),
        case(
            "a source reading a nested argument by its dotted path",
            |t| {
                set(
                    t,
                    "tools.0.resources.from_arguments.0",
                    "from_argument",
                    value("\"options.project\""),
                )
            },
            Want::Error(E::AdapterArgumentUndeclared {
                tool: tool("docs__read"),
                argument: "options.project".into(),
            }),
        ),
        case(
            "a source reading an argument of a tool with no properties",
            |t| {
                remove(t, "tools.0.input_schema", "properties");
            },
            Want::Error(E::AdapterArgumentUndeclared {
                tool: tool("docs__read"),
                argument: "project".into(),
            }),
        ),
        case(
            "a source reading an argument typed as an integer",
            |t| {
                set(
                    t,
                    "tools.0.input_schema.properties.project",
                    "type",
                    value("\"integer\""),
                )
            },
            Want::Error(E::AdapterArgumentNotString {
                tool: tool("docs__read"),
                argument: "project".into(),
            }),
        ),
        case(
            "a source reading an untyped argument",
            |t| remove(t, "tools.0.input_schema.properties.project", "type"),
            Want::Error(E::AdapterArgumentNotString {
                tool: tool("docs__read"),
                argument: "project".into(),
            }),
        ),
        case(
            "a source reading an argument that may be a string or null",
            |t| {
                set(
                    t,
                    "tools.0.input_schema.properties.project",
                    "type",
                    value("[\"string\", \"null\"]"),
                )
            },
            Want::Error(E::AdapterArgumentNotString {
                tool: tool("docs__read"),
                argument: "project".into(),
            }),
        ),
        case(
            "two sources",
            |t| {
                set(
                    t,
                    "tools.0",
                    "resources",
                    value(
                        "{ from_arguments = [{ from_argument = \"project\", system = \"docs\", kind = \"project\" }, { from_argument = \"document\", system = \"docs\", kind = \"document\" }] }",
                    ),
                )
            },
            Want::Loads,
        ),
        // The snapshot's own rules, reported through the registry.
        case(
            "a surface serving a tool nobody approved",
            |t| {
                set(
                    t,
                    "surfaces.0",
                    "tools",
                    value("[\"docs__read\", \"docs__write\"]"),
                )
            },
            Want::Error(E::Snapshot(SnapshotError::UnapprovedToolOnSurface {
                surface: "docs".into(),
                tool: tool("docs__write"),
            })),
        ),
        case(
            "a surface defined twice",
            |t| {
                let copy = table_at(t, "surfaces.0").clone();
                at(t, "surfaces").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::Snapshot(SnapshotError::DuplicateSurface("docs".into()))),
        ),
        case(
            "a profile defined twice",
            |t| {
                let copy = table_at(t, "profiles.1").clone();
                at(t, "profiles").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::Snapshot(SnapshotError::DuplicateProfile(
                "user-read".into(),
            ))),
        ),
        // Profile rules.
        case(
            "a rule naming a profile that is not defined",
            |t| set(t, "profile_rules.1", "profile", value("\"admin\"")),
            Want::Error(E::UnknownProfile("admin".into())),
        ),
        case(
            "two workload rules for one issuer",
            |t| {
                let mut copy = table_at(t, "profile_rules.0").clone();
                copy.insert("profile".into(), value("\"user-read\""));
                at(t, "profile_rules")
                    .as_array_mut()
                    .unwrap()
                    .push(copy.into());
            },
            Want::Error(E::DuplicateRule {
                issuer: "https://workloads.example.test".into(),
                principal: RulePrincipal::Workload,
            }),
        ),
        case(
            "two rules for one group of one issuer, even agreeing",
            |t| {
                let copy = table_at(t, "profile_rules.1").clone();
                at(t, "profile_rules")
                    .as_array_mut()
                    .unwrap()
                    .push(copy.into());
            },
            Want::Error(E::DuplicateRule {
                issuer: "https://users.example.test".into(),
                principal: RulePrincipal::UserInGroup("group-g".into()),
            }),
        ),
        case(
            "rules for one group of two issuers",
            |t| {
                let mut copy = table_at(t, "profile_rules.1").clone();
                copy.insert(
                    "issuer".into(),
                    value("\"https://other-users.example.test\""),
                );
                at(t, "profile_rules")
                    .as_array_mut()
                    .unwrap()
                    .push(copy.into());
            },
            Want::Loads,
        ),
        case(
            "rules for two groups of one issuer",
            |t| {
                let mut copy = table_at(t, "profile_rules.1").clone();
                copy.insert("principal".into(), value("{ user_in_group = \"group-h\" }"));
                at(t, "profile_rules")
                    .as_array_mut()
                    .unwrap()
                    .push(copy.into());
            },
            Want::Loads,
        ),
    ]
}

#[test]
fn each_rule_refuses_its_case() {
    let mut failures = Vec::new();
    for case in cases() {
        let mut table = base();
        (case.edit)(&mut table);
        if case.rehash {
            rehash(&mut table);
        }
        let got = load(&table);
        let ok = match (&case.want, &got) {
            (Want::Loads, Ok(_)) => true,
            (Want::Error(want), Err(got)) => want == got,
            (Want::Parse(text), Err(RegistryError::Parse(message))) => message.contains(text),
            (Want::Matches(test), Err(got)) => test(got),
            _ => false,
        };
        if !ok {
            failures.push(format!(
                "{}: got {:?}",
                case.name,
                got.map(|_| "a registry")
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_base_file_becomes_the_snapshot_definitions_and_adapters_it_states() {
    let registry = load(&base()).unwrap();
    let snapshot = registry.snapshot();
    let read = snapshot.tool(&tool("docs__read")).unwrap();
    assert_eq!(read.classification, Classification::Read);
    assert_eq!(read.connector.as_str(), "docs-server");
    assert_eq!(read.resources, ResourceDeclaration::Declared);
    let search = snapshot.tool(&tool("wiki__search")).unwrap();
    assert_eq!(search.resources, ResourceDeclaration::NoResources);

    let definitions = registry.definitions();
    assert_eq!(definitions.len(), 3);
    assert!(definitions[&tool("docs__read")].read_only);
    assert!(
        !definitions[&tool("wiki__edit")].read_only,
        "a write tool was shown as read-only"
    );
    assert_eq!(
        definitions[&tool("docs__read")].title.as_deref(),
        Some("Read")
    );
    assert_eq!(definitions[&tool("wiki__search")].title, None);
    assert_eq!(
        definitions[&tool("docs__read")].description,
        "Reads a document."
    );

    assert_eq!(registry.adapters().len(), 3);
    assert_eq!(registry.routes()[&tool("wiki__edit")].upstream_name, "edit");
    let approval = &registry.approvals()[&tool("docs__read")];
    assert_eq!(approval.approved_by, "approver@example.test");
    assert_eq!(approval.approved_at, "2026-10-01T12:00:00+01:00");
    assert_eq!(approval.definition_sha256.len(), 64);
    assert_eq!(registry.profile_rules().rules().len(), 2);
}

#[test]
fn a_file_that_cannot_be_read_is_refused() {
    let missing = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-registry.toml");
    assert!(matches!(
        gateway_registry::Registry::load(&missing),
        Err(RegistryError::Read { .. })
    ));
}
