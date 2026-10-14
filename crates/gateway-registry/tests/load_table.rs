//! The loader's rules, one table case per way a registry file can be wrong. Each case makes
//! one edit to a file that loads and names the one error it must produce, so a rule that
//! stops firing, or a different rule firing first, fails its case.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{at, base, load, rehash, remove, set, table_at, value};
use gateway_core::{
    Admitted, Classification, ConnectorEntry, CredentialMode, DeclaredFrom, EntryKind, Narrowing,
    Resource, ResourceDeclaration, SnapshotError, ToolName,
};
use gateway_registry::{Destination, Probe, ProbeResult, RegistryError, RulePrincipal};
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
            "a revision in the form a withdrawal derives",
            |t| set(t, "", "revision", value("\"r1+withdrawn:docs__read\"")),
            Want::Error(E::RevisionReserved("r1+withdrawn:docs__read".into())),
        ),
        case(
            "a revision with a plus anywhere",
            |t| set(t, "", "revision", value("\"+\"")),
            Want::Error(E::RevisionReserved("+".into())),
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
        // Each server's tools, and its reach check's tool, are named after a system no other
        // server has.
        case(
            "a second server with another server's system",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"wiki-mirror\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::DuplicateSystem {
                system: "wiki".into(),
                first: "wiki-server".into(),
                second: "wiki-mirror".into(),
            }),
        ),
        case(
            "a second server with a system of its own",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"wiki-mirror\""));
                copy.insert("system".into(), value("\"wiki-mirror\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Loads,
        ),
        // Nor may a system contain `__` or end in `_`, or a tool name could be under two systems:
        // `docs__wiki__search` under `docs` and `docs__wiki`, `docs___search` under `docs` and
        // `docs_`.
        case(
            "a second server whose system is another's, `__` and more",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"docs-wiki\""));
                copy.insert("system".into(), value("\"docs__wiki\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::SystemOverlaps {
                server: "docs-wiki".into(),
                system: "docs__wiki".into(),
            }),
        ),
        case(
            "a system with `__` inside, whatever the other systems",
            |t| set(t, "servers.1", "system", value("\"wiki__a\"")),
            Want::Error(E::SystemOverlaps {
                server: "wiki-server".into(),
                system: "wiki__a".into(),
            }),
        ),
        case(
            "a second server whose system is another's and `_`",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"docs-under\""));
                copy.insert("system".into(), value("\"docs_\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Error(E::SystemOverlaps {
                server: "docs-under".into(),
                system: "docs_".into(),
            }),
        ),
        case(
            "a system ending in `_`, whatever the other systems",
            |t| set(t, "servers.1", "system", value("\"wiki_\"")),
            Want::Error(E::SystemOverlaps {
                server: "wiki-server".into(),
                system: "wiki_".into(),
            }),
        ),
        case(
            "a second server whose system has one `_` inside",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"docs-team\""));
                copy.insert("system".into(), value("\"docs_team\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Loads,
        ),
        case(
            "a second server whose system has `-` inside",
            |t| {
                let mut copy = table_at(t, "servers.1").clone();
                copy.insert("name".into(), value("\"docs-team-a\""));
                copy.insert("system".into(), value("\"docs-team-a\""));
                at(t, "servers").as_array_mut().unwrap().push(copy.into());
            },
            Want::Loads,
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
        case(
            "an address whose host is empty after its user information",
            |t| set(t, "servers.0", "address", value("\"https://user@/mcp\"")),
            Want::Error(E::AddressNotHttp {
                server: "docs-server".into(),
                address: "https://user@/mcp".into(),
            }),
        ),
        // A server's identity is the host in its address.
        case(
            "an identity that is not the address's host",
            |t| set(t, "servers.0", "identity", value("\"docs-server\"")),
            Want::Error(E::IdentityNotHost {
                server: "docs-server".into(),
                identity: "docs-server".into(),
                host: "docs.internal.example.test".into(),
            }),
        ),
        case(
            "an identity that carries the address's port",
            |t| {
                set(
                    t,
                    "servers.1",
                    "identity",
                    value("\"wiki.internal.example.test:8080\""),
                )
            },
            Want::Error(E::IdentityNotHost {
                server: "wiki-server".into(),
                identity: "wiki.internal.example.test:8080".into(),
                host: "wiki.internal.example.test".into(),
            }),
        ),
        case(
            "an identity in another case than the host",
            |t| {
                set(
                    t,
                    "servers.0",
                    "identity",
                    value("\"Docs.internal.example.test\""),
                )
            },
            Want::Matches(|e| matches!(e, E::IdentityNotHost { .. })),
        ),
        case(
            "an address moved to another host with the identity left behind",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"https://docs.elsewhere.example.test/mcp\""),
                )
            },
            Want::Error(E::IdentityNotHost {
                server: "docs-server".into(),
                identity: "docs.internal.example.test".into(),
                host: "docs.elsewhere.example.test".into(),
            }),
        ),
        case(
            "an identity and address moved together, and approved again",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"https://docs.elsewhere.example.test/mcp\""),
                );
                set(
                    t,
                    "servers.0",
                    "identity",
                    value("\"docs.elsewhere.example.test\""),
                );
            },
            Want::Loads,
        ),
        case(
            "an IPv6 literal identity keeps its brackets",
            |t| {
                set(
                    t,
                    "servers.1",
                    "address",
                    value("\"http://[fd00::1]:8080/mcp\""),
                );
                set(t, "servers.1", "identity", value("\"[fd00::1]\""));
            },
            Want::Loads,
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
            "a classification changed after approval is in neither hash: rule 2 refuses it",
            |t| set(t, "tools.1", "classification", value("\"write\"")),
            Want::Matches(|e| {
                matches!(e, E::Snapshot(SnapshotError::ProxiedNotRead { tool, .. })
                    if tool.as_str() == "wiki__search")
            }),
        ),
        // The binding: the server entry each approval was made against.
        unapproved(
            "a tool with no binding hash",
            |t| remove(t, "tools.0", "binding_sha256"),
            Want::Parse("missing field `binding_sha256`"),
        ),
        unapproved(
            "an address changed after approval",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"https://docs.internal.example.test:8443/mcp\""),
                )
            },
            Want::Matches(|e| {
                matches!(e, E::BindingChanged { tool, server, .. }
                    if tool.as_str() == "docs__read" && server.as_str() == "docs-server")
            }),
        ),
        unapproved(
            "an address's path changed after approval",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"https://docs.internal.example.test/other\""),
                )
            },
            Want::Matches(|e| matches!(e, E::BindingChanged { .. })),
        ),
        unapproved(
            "an identity and address changed together after approval",
            |t| {
                set(
                    t,
                    "servers.0",
                    "address",
                    value("\"https://docs.elsewhere.example.test/mcp\""),
                );
                set(
                    t,
                    "servers.0",
                    "identity",
                    value("\"docs.elsewhere.example.test\""),
                );
            },
            Want::Matches(|e| matches!(e, E::BindingChanged { .. })),
        ),
        unapproved(
            "a credential reference changed after approval",
            |t| {
                set(
                    t,
                    "servers.1.credential",
                    "reference",
                    value("\"other-credential\""),
                )
            },
            Want::Matches(|e| {
                matches!(e, E::BindingChanged { tool, server, .. }
                    if tool.as_str() == "wiki__search" && server.as_str() == "wiki-server")
            }),
        ),
        // The connector entry's fields are in the binding too (decision 0013, section 1), and the
        // records that describe it are not.
        unapproved(
            "a credential mode changed after approval",
            |t| {
                set(
                    t,
                    "servers.0.credential",
                    "mode",
                    value("\"gateway_token\""),
                )
            },
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a credential principal changed after approval",
            |t| {
                set(
                    t,
                    "servers.0.credential",
                    "principal",
                    value("\"docs-writer\""),
                )
            },
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a narrowing changed after approval",
            |t| set(t, "servers.0", "narrowing", value("\"limit\"")),
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "what the credential permits changed after approval",
            |t| set(t, "servers.1", "permits", value("\"propose\"")),
            Want::Matches(
                |e| matches!(e, E::BindingChanged { server, .. } if server.as_str() == "wiki-server"),
            ),
        ),
        unapproved(
            "a reach widened after approval",
            |t| {
                set(
                    t,
                    "servers.0",
                    "reach",
                    value(
                        "[{ system = \"docs\", kind = \"project\", identifier = \"atlas\" }, { system = \"docs\", kind = \"project\", identifier = \"borealis\" }]",
                    ),
                )
            },
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a reach test run again after approval",
            |t| set(t, "servers.0.reach_test", "date", value("2026-10-02")),
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a destination changed after approval",
            |t| set(t, "servers.0", "destination", value("\"in_cluster\"")),
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a reach test's record reworded is not in the binding",
            |t| set(t, "servers.0.reach_test", "record", value("\"atlas only\"")),
            Want::Loads,
        ),
        unapproved(
            "a probe run again is not in the binding",
            |t| set(t, "servers.0.probe", "date", value("2026-10-05")),
            Want::Loads,
        ),
        unapproved(
            "a reach check's arguments changed are not in the binding",
            |t| {
                set(
                    t,
                    "servers.0.reach_check",
                    "arguments",
                    value("{ project = \"cygnus\", document = \"plan\" }"),
                )
            },
            Want::Loads,
        ),
        unapproved(
            "a binding hash in capitals",
            |t| {
                let hash = at(t, "tools.0.binding_sha256")
                    .as_str()
                    .unwrap()
                    .to_uppercase();
                set(t, "tools.0", "binding_sha256", toml::Value::String(hash));
            },
            Want::Matches(|e| matches!(e, E::BindingChanged { .. })),
        ),
        unapproved(
            "one server's binding approved for another server's tool",
            |t| {
                let hash = at(t, "tools.1.binding_sha256").clone();
                set(t, "tools.0", "binding_sha256", hash);
            },
            Want::Matches(
                |e| matches!(e, E::BindingChanged { tool, .. } if tool.as_str() == "docs__read"),
            ),
        ),
        unapproved(
            "a server's owner is not in the binding",
            |t| set(t, "servers.0", "owner", value("\"team-other\"")),
            Want::Loads,
        ),
        // Connector entries (decision 0011, section 1): every field required where stated, and
        // values the format does not know refused.
        case(
            "a server with no narrowing",
            |t| remove(t, "servers.0", "narrowing"),
            Want::Parse("missing field `narrowing`"),
        ),
        case(
            "a server with no permits",
            |t| remove(t, "servers.0", "permits"),
            Want::Parse("missing field `permits`"),
        ),
        case(
            "a server with no reach",
            |t| remove(t, "servers.1", "reach"),
            Want::Parse("missing field `reach`"),
        ),
        case(
            "a server with no destination",
            |t| remove(t, "servers.1", "destination"),
            Want::Parse("missing field `destination`"),
        ),
        case(
            "a credential with no principal",
            |t| remove(t, "servers.0.credential", "principal"),
            Want::Parse("missing field `principal`"),
        ),
        case(
            "a reach test with no date",
            |t| remove(t, "servers.0.reach_test", "date"),
            Want::Parse("missing field `date`"),
        ),
        case(
            "a reach test with no record",
            |t| remove(t, "servers.0.reach_test", "record"),
            Want::Parse("missing field `record`"),
        ),
        case(
            "a reach check with no tool",
            |t| remove(t, "servers.0.reach_check", "tool"),
            Want::Parse("missing field `tool`"),
        ),
        case(
            "a reach check with no arguments",
            |t| remove(t, "servers.0.reach_check", "arguments"),
            Want::Parse("missing field `arguments`"),
        ),
        case(
            "a probe with no result",
            |t| remove(t, "servers.0.probe", "result"),
            Want::Parse("missing field `result`"),
        ),
        case(
            "a probe with no date",
            |t| remove(t, "servers.0.probe", "date"),
            Want::Parse("missing field `date`"),
        ),
        case(
            "a credential with an empty principal",
            |t| set(t, "servers.0.credential", "principal", value("\"\"")),
            empty("credential.principal", "server `docs-server`"),
        ),
        case(
            "the old bearer mode",
            |t| set(t, "servers.0.credential", "mode", value("\"bearer\"")),
            Want::Parse("unknown variant `bearer`"),
        ),
        case(
            "an unknown narrowing",
            |t| set(t, "servers.0", "narrowing", value("\"some\"")),
            Want::Parse("unknown variant `some`"),
        ),
        case(
            "an unknown permits",
            |t| set(t, "servers.0", "permits", value("\"admin\"")),
            Want::Parse("`admin` is not a classification"),
        ),
        case(
            "an unknown destination",
            |t| set(t, "servers.0", "destination", value("\"internal\"")),
            Want::Parse("unknown variant `internal`"),
        ),
        case(
            "an unknown probe result",
            |t| set(t, "servers.0.probe", "result", value("\"passed\"")),
            Want::Parse("unknown variant `passed`"),
        ),
        case(
            "an unknown reach field",
            |t| set(t, "servers.0.reach.0", "scope", value("\"x\"")),
            Want::Parse("unknown field `scope`"),
        ),
        case(
            "an unknown reach test field",
            |t| set(t, "servers.0.reach_test", "by", value("\"x\"")),
            Want::Parse("unknown field `by`"),
        ),
        case(
            "an unknown probe field",
            |t| set(t, "servers.0.probe", "by", value("\"x\"")),
            Want::Parse("unknown field `by`"),
        ),
        case(
            "an unknown reach check field",
            |t| set(t, "servers.0.reach_check", "by", value("\"x\"")),
            Want::Parse("unknown field `by`"),
        ),
        case(
            "a reach resource with an empty identifier",
            |t| set(t, "servers.0.reach.0", "identifier", value("\"\"")),
            empty("identifier", "the reach of server `docs-server`"),
        ),
        case(
            "a reach test with an empty record",
            |t| set(t, "servers.0.reach_test", "record", value("\"\"")),
            empty("reach_test.record", "server `docs-server`"),
        ),
        case(
            "a reach test dated with a time",
            |t| {
                set(
                    t,
                    "servers.0.reach_test",
                    "date",
                    value("2026-10-01T00:00:00Z"),
                )
            },
            Want::Error(E::NotADate {
                field: "reach_test.date",
                place: "server `docs-server`".into(),
            }),
        ),
        case(
            "a probe dated with a local time",
            |t| set(t, "servers.0.probe", "date", value("2026-10-01T09:00:00")),
            Want::Error(E::NotADate {
                field: "probe.date",
                place: "server `docs-server`".into(),
            }),
        ),
        case(
            "a reach with no reach test",
            |t| remove(t, "servers.0", "reach_test"),
            Want::Error(E::ReachTestMissing("docs-server".into())),
        ),
        case(
            "a reach test on an entry that reaches nothing",
            |t| {
                set(
                    t,
                    "servers.1",
                    "reach_test",
                    value("{ date = 2026-10-01, record = \"nothing to reach\" }"),
                )
            },
            Want::Loads,
        ),
        case(
            "no probe record",
            |t| remove(t, "servers.0", "probe"),
            Want::Error(E::ProbeMissing("docs-server".into())),
        ),
        case(
            "no probe record on an entry that reaches nothing",
            |t| remove(t, "servers.1", "probe"),
            Want::Error(E::ProbeMissing("wiki-server".into())),
        ),
        case(
            "a probe that found the server open",
            |t| set(t, "servers.0.probe", "result", value("\"open\"")),
            Want::Error(E::ProbeNotRefused {
                server: "docs-server".into(),
                result: "open",
            }),
        ),
        case(
            "a probe that showed no refusal",
            |t| set(t, "servers.1.probe", "result", value("\"not_shown\"")),
            Want::Error(E::ProbeNotRefused {
                server: "wiki-server".into(),
                result: "not_shown",
            }),
        ),
        case(
            "a reach with no reach check",
            |t| remove(t, "servers.0", "reach_check"),
            Want::Error(E::ReachCheckMissing("docs-server".into())),
        ),
        case(
            "a reach narrowed to the limit with no reach check",
            |t| {
                set(t, "servers.0", "narrowing", value("\"limit\""));
                remove(t, "servers.0", "reach_check");
            },
            Want::Error(E::ReachCheckMissing("docs-server".into())),
        ),
        case(
            "a reach narrowed per call with no reach check",
            |t| {
                set(t, "servers.0", "narrowing", value("\"call\""));
                remove(t, "servers.0", "reach_check");
            },
            Want::Error(E::ReachCheckMissing("docs-server".into())),
        ),
        case(
            "a per-user entry needs no reach check, served to a group only",
            |t| {
                set(
                    t,
                    "servers.0.credential",
                    "mode",
                    value("\"per_user_grant\""),
                );
                remove(t, "servers.0", "reach_check");
                set(t, "surfaces.0", "teams", value("[]"));
            },
            Want::Loads,
        ),
        // Withdrawal removes a tool's approval (decision 0013, section 8). The reach check's
        // tool, with every other tool of its entry, can be withdrawn without touching the
        // reach check.
        case(
            "withdrawing the reach check's tool, the entry's last, loads",
            |t| {
                at(t, "tools").as_array_mut().unwrap().remove(0);
                set(t, "surfaces.0", "tools", value("[\"wiki__search\"]"));
            },
            Want::Loads,
        ),
        // Alone, it cannot: the entry's other tools would be served under a credential whose
        // reach is never checked again. Here the wiki server's reach check calls its page tool.
        case(
            "the reach check's tool approved with the entry's other tools loads",
            |t| {
                set(
                    t,
                    "servers.1",
                    "reach_check",
                    value("{ tool = \"wiki__page\", arguments = { space = \"ops\" } }"),
                )
            },
            Want::Loads,
        ),
        case(
            "withdrawing the reach check's tool and keeping another tool of the entry",
            |t| {
                set(
                    t,
                    "servers.1",
                    "reach_check",
                    value("{ tool = \"wiki__page\", arguments = { space = \"ops\" } }"),
                );
                at(t, "tools").as_array_mut().unwrap().remove(2);
                set(t, "surfaces.1", "tools", value("[]"));
            },
            Want::Error(E::ReachCheckUnapproved {
                server: "wiki-server".into(),
                tool: tool("wiki__page"),
            }),
        ),
        case(
            "withdrawing every tool of the entry, the reach check's with them, loads",
            |t| {
                set(
                    t,
                    "servers.1",
                    "reach_check",
                    value("{ tool = \"wiki__page\", arguments = { space = \"ops\" } }"),
                );
                at(t, "tools").as_array_mut().unwrap().truncate(1);
                set(t, "surfaces.0", "tools", value("[\"docs__read\"]"));
                set(t, "surfaces.1", "tools", value("[]"));
            },
            Want::Loads,
        ),
        // Another entry's approved tools do not count: the docs server's reach check calls a
        // tool that was never approved and its one tool is withdrawn, while the wiki server's
        // tools stay.
        case(
            "an unapproved reach check tool on an entry whose tools are all withdrawn loads",
            |t| {
                set(
                    t,
                    "servers.0.reach_check",
                    "tool",
                    value("\"docs__canary\""),
                );
                at(t, "tools").as_array_mut().unwrap().remove(0);
                set(t, "surfaces.0", "tools", value("[\"wiki__search\"]"));
            },
            Want::Loads,
        ),
        // The reach check calls one of the entry's own tools: its name is under the server's
        // system.
        case(
            "a reach check naming another server's tool",
            |t| {
                set(
                    t,
                    "servers.0.reach_check",
                    "tool",
                    value("\"wiki__search\""),
                )
            },
            Want::Error(E::ReachCheckOutsideSystem {
                server: "docs-server".into(),
                tool: tool("wiki__search"),
                system: "docs".into(),
            }),
        ),
        case(
            "a reach check naming a tool with no separator after the system",
            |t| set(t, "servers.0.reach_check", "tool", value("\"docsread\"")),
            Want::Error(E::ReachCheckOutsideSystem {
                server: "docs-server".into(),
                tool: tool("docsread"),
                system: "docs".into(),
            }),
        ),
        case(
            "a reach check naming the system and nothing after it",
            |t| set(t, "servers.0.reach_check", "tool", value("\"docs__\"")),
            Want::Error(E::ReachCheckOutsideSystem {
                server: "docs-server".into(),
                tool: tool("docs__"),
                system: "docs".into(),
            }),
        ),
        case(
            "a reach check naming an unapproved tool of the server's own system",
            |t| {
                set(
                    t,
                    "servers.0.reach_check",
                    "tool",
                    value("\"docs__canary\""),
                )
            },
            Want::Error(E::ReachCheckUnapproved {
                server: "docs-server".into(),
                tool: tool("docs__canary"),
            }),
        ),
        // The destination against the address's scheme (decision 0013, section 3).
        case(
            "an http address with a public destination",
            |t| set(t, "servers.1", "destination", value("\"public\"")),
            Want::Error(E::DestinationScheme {
                server: "wiki-server".into(),
                address: "http://wiki.internal.example.test:8080/mcp".into(),
            }),
        ),
        case(
            "an https address with an in-cluster destination",
            |t| set(t, "servers.0", "destination", value("\"in_cluster\"")),
            Want::Loads,
        ),
        // A tool declared as the reach loads, held to the loader's rules like any other.
        case(
            "a tool declared as its entry's reach",
            |t| set(t, "tools.0", "resources", value("\"as_reach\"")),
            Want::Loads,
        ),
        // The snapshot loader's rules (decision 0011, section 3), through the registry. Rule 1
        // cannot be written here: `checks_own_scope` does not parse. Rule 3 is the registry's
        // own `ReachTestMissing` above, which comes first.
        case(
            "rule 2: a proxied tool classified propose",
            |t| {
                set(t, "tools.0", "classification", value("\"propose\""));
                // Settled by a person, as every tool not classified read must say, so
                // that rule 2 is the only refusal.
                set(t, "tools.0", "settlement", value("\"person\""));
            },
            Want::Error(E::Snapshot(SnapshotError::ProxiedNotRead {
                tool: tool("docs__read"),
                entry: "docs-server".into(),
                classification: Classification::Propose,
            })),
        ),
        case(
            "rule 2: a proxied tool classified write",
            |t| {
                set(t, "tools.1", "classification", value("\"write\""));
                // Settled by a person, as every tool not classified read must say, so
                // that rule 2 is the only refusal.
                set(t, "tools.1", "settlement", value("\"person\""));
            },
            Want::Error(E::Snapshot(SnapshotError::ProxiedNotRead {
                tool: tool("wiki__search"),
                entry: "wiki-server".into(),
                classification: Classification::Write,
            })),
        ),
        case(
            "rule 4: a credential that permits more than its read tools",
            |t| set(t, "servers.0", "permits", value("\"propose\"")),
            Want::Error(E::Snapshot(SnapshotError::PermitsMoreThanTool {
                entry: "docs-server".into(),
                permits: Classification::Propose,
                tool: tool("docs__read"),
                classification: Classification::Read,
            })),
        ),
        case(
            "rule 5: one entry reaching both projects, served to both teams",
            |t| {
                set(
                    t,
                    "servers.0",
                    "reach",
                    value(
                        "[{ system = \"docs\", kind = \"project\", identifier = \"atlas\" }, { system = \"docs\", kind = \"project\", identifier = \"borealis\" }]",
                    ),
                );
                set(t, "surfaces.0", "teams", value("[\"team-a\", \"team-b\"]"));
                set(
                    t,
                    "limits.teams",
                    "team-b",
                    value("[{ system = \"docs\", kind = \"project\", identifier = \"borealis\" }]"),
                );
            },
            Want::Error(E::Snapshot(SnapshotError::ReachOutsideLimit {
                tool: tool("docs__read"),
                surface: "docs".into(),
                admitted: Admitted::Team("team-a".into()),
                resource: Box::new(Resource {
                    system: "docs".into(),
                    kind: "project".into(),
                    identifier: "borealis".into(),
                }),
            })),
        ),
        case(
            "rule 5: the same entry narrowed to each caller's limit",
            |t| {
                set(
                    t,
                    "servers.0",
                    "reach",
                    value(
                        "[{ system = \"docs\", kind = \"project\", identifier = \"atlas\" }, { system = \"docs\", kind = \"project\", identifier = \"borealis\" }]",
                    ),
                );
                set(t, "servers.0", "narrowing", value("\"limit\""));
                set(t, "surfaces.0", "teams", value("[\"team-a\", \"team-b\"]"));
            },
            Want::Loads,
        ),
        case(
            "rule 6: a no_resources tool on an entry that reaches a space",
            |t| {
                set(
                    t,
                    "servers.1",
                    "reach",
                    value("[{ system = \"wiki\", kind = \"space\", identifier = \"eng\" }]"),
                );
                set(
                    t,
                    "servers.1",
                    "reach_test",
                    value("{ date = 2026-10-01, record = \"other spaces refused\" }"),
                );
                set(
                    t,
                    "servers.1",
                    "reach_check",
                    value("{ tool = \"wiki__page\", arguments = { space = \"ops\" } }"),
                );
            },
            Want::Error(E::Snapshot(SnapshotError::NoResourcesWithReach {
                tool: tool("wiki__search"),
                entry: "wiki-server".into(),
                resource: Box::new(Resource {
                    system: "wiki".into(),
                    kind: "space".into(),
                    identifier: "eng".into(),
                }),
            })),
        ),
        case(
            "rule 7: an entry narrowing per call serving a no_resources tool",
            |t| set(t, "servers.1", "narrowing", value("\"call\"")),
            Want::Error(E::Snapshot(SnapshotError::CallNarrowingWithoutArguments {
                entry: "wiki-server".into(),
                tool: tool("wiki__search"),
            })),
        ),
        case(
            "rule 8: a per-user entry's tool served to a team",
            |t| {
                set(
                    t,
                    "servers.0.credential",
                    "mode",
                    value("\"per_user_grant\""),
                )
            },
            Want::Error(E::Snapshot(SnapshotError::PerUserToTeam {
                tool: tool("docs__read"),
                entry: "docs-server".into(),
                surface: "docs".into(),
                team: "team-a".into(),
            })),
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

/// A tool declared as its entry's reach is approved as `declared`, from the reach. Its adapter
/// names nothing from the arguments: the gateway names the reach for it.
/// A profile declares that its callers set `Idempotency-Key` per request only when it says so:
/// a profile that does not mention it, as every file written before the setting does not, does
/// not declare it.
#[test]
fn a_profile_declares_the_key_header_only_when_it_says_so() {
    let mut table = base();
    set(
        &mut table,
        "profiles.1",
        "idempotency_key_header",
        value("true"),
    );
    let registry = load(&table).unwrap();
    let declares = |name: &str| {
        registry
            .snapshot()
            .profile(&name.into())
            .unwrap()
            .idempotency_key_header
    };
    assert!(!declares("workload-read"));
    assert!(declares("user-read"));
    set(
        &mut table,
        "profiles.1",
        "idempotency_key_header",
        value("\"yes\""),
    );
    assert!(
        load(&table).is_err(),
        "a setting that is not a boolean loaded"
    );
}

#[test]
fn a_tool_declared_as_the_reach_is_approved_as_declared_from_the_reach() {
    let mut table = base();
    set(&mut table, "tools.0", "resources", value("\"as_reach\""));
    let registry = load(&table).unwrap();
    let read = registry.snapshot().tool(&tool("docs__read")).unwrap();
    assert_eq!(read.resources, ResourceDeclaration::Declared);
    assert_eq!(read.declared_from, Some(DeclaredFrom::Reach));
    assert_eq!(read.connector.as_str(), "docs-server");
}

#[test]
fn the_base_file_becomes_the_snapshot_definitions_and_adapters_it_states() {
    let registry = load(&base()).unwrap();
    let snapshot = registry.snapshot();
    let read = snapshot.tool(&tool("docs__read")).unwrap();
    assert_eq!(read.classification, Classification::Read);
    assert_eq!(read.connector.as_str(), "docs-server");
    assert_eq!(read.resources, ResourceDeclaration::Declared);
    assert_eq!(read.declared_from, Some(DeclaredFrom::Arguments));
    let search = snapshot.tool(&tool("wiki__search")).unwrap();
    assert_eq!(search.resources, ResourceDeclaration::NoResources);
    assert_eq!(search.declared_from, None);

    // Each server is a proxied connector entry, as its file states it.
    let atlas = Resource {
        system: "docs".into(),
        kind: "project".into(),
        identifier: "atlas".into(),
    };
    assert_eq!(
        snapshot.entry(&"docs-server".into()),
        Some(&ConnectorEntry {
            name: "docs-server".into(),
            kind: EntryKind::Proxied,
            credential: CredentialMode::TeamServiceIdentity,
            principal: "docs-reader".into(),
            narrowing: Narrowing::None,
            permits: Classification::Read,
            reach: [atlas.clone()].into(),
            reach_tested_on: Some("2026-10-01".into()),
        })
    );
    let wiki = snapshot.entry(&"wiki-server".into()).unwrap();
    assert_eq!(
        (wiki.kind, wiki.credential, wiki.narrowing, wiki.reach.len()),
        (
            EntryKind::Proxied,
            CredentialMode::GatewayToken,
            Narrowing::Limit,
            0
        )
    );
    assert_eq!(wiki.reach_tested_on, None);
    let docs = &registry.servers()[&"docs-server".into()];
    assert_eq!(docs.destination, Destination::Public);
    assert_eq!(
        docs.reach_test.as_ref().map(|test| test.record.as_str()),
        Some("a caller limited to atlas was refused borealis")
    );
    assert_eq!(
        docs.probe,
        Some(Probe {
            result: ProbeResult::Refused,
            date: "2026-10-01".into()
        })
    );
    let check = docs.reach_check.as_ref().unwrap();
    assert_eq!(check.tool, tool("docs__read"));
    assert_eq!(
        serde_json::Value::Object(check.arguments.clone()),
        serde_json::json!({"project": "borealis", "document": "plan"})
    );
    let wiki = &registry.servers()[&"wiki-server".into()];
    assert_eq!(wiki.destination, Destination::InCluster);
    assert_eq!(
        wiki.probe,
        Some(Probe {
            result: ProbeResult::Refused,
            date: "2026-10-02".into()
        })
    );
    assert_eq!(wiki.reach_check, None);

    let definitions = registry.definitions();
    assert_eq!(definitions.len(), 3);
    assert!(definitions[&tool("docs__read")].read_only);
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
    assert_eq!(registry.routes()[&tool("wiki__page")].upstream_name, "page");
    let approval = &registry.approvals()[&tool("docs__read")];
    assert_eq!(approval.approved_by, "approver@example.test");
    assert_eq!(approval.approved_at, "2026-10-01T12:00:00+01:00");
    assert_eq!(approval.definition_sha256.len(), 64);
    assert_eq!(
        approval.binding_sha256,
        gateway_registry::binding_sha256(&registry.servers()[&"docs-server".into()])
    );
    assert_ne!(
        approval.binding_sha256,
        registry.approvals()[&tool("wiki__search")].binding_sha256
    );
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

/// `switchboard probe` reads one entry, checked as the loader checks it but for the probe rule,
/// so an entry can be probed before it has a record, and nothing else in the file is checked.
#[test]
fn one_server_entry_is_read_alone_and_needs_no_probe_record() {
    let entry = |table: &Table, name: &str| {
        gateway_registry::Registry::server_entry(&toml::to_string(table).unwrap(), &name.into())
    };
    let mut table = base();
    remove(&mut table, "servers.0", "probe");
    set(&mut table, "servers.1.probe", "result", value("\"open\""));
    // A tool that would refuse the whole file.
    set(
        &mut table,
        "tools.0",
        "definition_sha256",
        value("\"changed\""),
    );
    assert!(load(&table).is_err());

    let docs = entry(&table, "docs-server").unwrap();
    assert_eq!(docs.address, "https://docs.internal.example.test/mcp");
    assert_eq!(docs.probe, None);
    let wiki = entry(&table, "wiki-server").unwrap();
    assert_eq!(
        wiki.probe.map(|probe| probe.result),
        Some(ProbeResult::Open)
    );

    assert_eq!(
        entry(&table, "mail-server").unwrap_err(),
        RegistryError::NoSuchServer("mail-server".into())
    );
    // The entry itself is checked.
    set(&mut table, "servers.0", "identity", value("\"elsewhere\""));
    assert!(matches!(
        entry(&table, "docs-server"),
        Err(RegistryError::IdentityNotHost { .. })
    ));
    set(&mut table, "servers.0", "colour", value("\"red\""));
    assert!(matches!(
        entry(&table, "docs-server"),
        Err(RegistryError::Parse(message)) if message.contains("unknown field `colour`")
    ));
    let mut twice = base();
    let servers = twice["servers"].as_array_mut().unwrap();
    servers.push(servers[0].clone());
    assert_eq!(
        entry(&twice, "docs-server").unwrap_err(),
        RegistryError::DuplicateServer("docs-server".into())
    );
}

/// The refusal of a reach check outside the server's system names the server, the tool and
/// the system its tools are named after.
#[test]
fn a_reach_check_outside_the_system_is_refused_naming_the_server_and_the_tool() {
    let mut table = base();
    set(
        &mut table,
        "servers.0.reach_check",
        "tool",
        value("\"wiki__search\""),
    );
    let message = load(&table).unwrap_err().to_string();
    assert_eq!(
        message,
        "server `docs-server`'s reach check calls `wiki__search`, which is not one of its own \
         tools: name it `docs__<tool>`, after the server's system"
    );
}

/// The refusal of an entry whose reach check's tool is withdrawn while another of its tools is
/// approved names the server and the tool, and says how to withdraw them.
#[test]
fn a_reach_check_tool_withdrawn_alone_is_refused_naming_the_server_and_the_tool() {
    let mut table = base();
    set(
        &mut table,
        "servers.1",
        "reach_check",
        value("{ tool = \"wiki__page\", arguments = { space = \"ops\" } }"),
    );
    at(&mut table, "tools").as_array_mut().unwrap().remove(2);
    set(&mut table, "surfaces.1", "tools", value("[]"));
    let message = load(&table).unwrap_err().to_string();
    assert_eq!(
        message,
        "server `wiki-server`'s reach check calls `wiki__page`, which is not approved, and other \
         tools of the server are: remove the server's approvals together, or name another tool \
         in its reach check"
    );
}

/// The refusal of two servers with one system names the system and both servers.
#[test]
fn two_servers_with_one_system_are_refused_naming_the_system_and_both_servers() {
    let mut table = base();
    set(&mut table, "servers.1", "system", value("\"docs\""));
    let message = load(&table).unwrap_err().to_string();
    assert_eq!(
        message,
        "servers `docs-server` and `wiki-server` both have the system `docs`; each server needs a \
         system of its own"
    );
}

/// The refusal of a system that could share a tool name with another names the server and the
/// system, and says why.
#[test]
fn a_system_with_a_double_underscore_is_refused_naming_the_server_and_the_system() {
    let mut table = base();
    set(&mut table, "servers.1", "system", value("\"docs__wiki\""));
    let message = load(&table).unwrap_err().to_string();
    assert_eq!(
        message,
        "server `wiki-server` has the system `docs__wiki`, which contains `__` or ends in `_`; a \
         tool name must be under one system only, so a system may do neither"
    );
}
