//! Loading the registry file and checking it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gateway_core::{
    ApprovedTool, ConnectorName, Issuer, PolicyRevision, PolicySnapshot, Principal, PrincipalId,
    PrincipalRestriction, Profile, ProfileName, Resource, ResourceLimits, SnapshotData,
    SnapshotError, Surface, ToolName,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::adapter::{self, ArgumentAdapter, JsonPointer, ResourceSource, SchemaProblem};
use crate::definition::{Approval, Route, ToolDefinition, definition_sha256};
use crate::file::{
    CredentialFile, PrincipalsFile, RegistryFile, ResourceFile, ResourcesFile, RulePrincipalFile,
    ServerFile, ToolFile,
};
use crate::selection::{NoProfile, ProfileRule, ProfileRules, RulePrincipal};

/// A proxied MCP server, as its owner registered it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Server {
    /// The server's name. Approved tools name it as their connector.
    pub name: ConnectorName,
    /// The system part of its tools' exposed names: every tool on this server is exposed as
    /// `{system}__{tool}`.
    pub system: String,
    /// The team that owns the server and answers for it.
    pub owner: String,
    /// The identity the server is expected to present, recorded with its approvals, such as
    /// the `serverInfo.name` of its `initialize` answer. Nothing compares it yet.
    pub identity: String,
    /// Where the gateway sends its calls: an `http` or `https` URL.
    pub address: String,
    /// The credential the gateway presents to it.
    pub credential: Credential,
}

/// How the gateway authenticates to a server. Never the caller's token (design.md section 13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Credential {
    /// The gateway sends `Authorization: Bearer` with a secret it holds.
    Bearer {
        /// Which secret: a label the credential source resolves, never the secret itself.
        reference: String,
    },
}

/// Why a registry file was refused. Each names the first problem found.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// The file could not be read.
    #[error("could not read the registry file `{path}`: {message}")]
    Read {
        /// The path given.
        path: String,
        /// The error, as the operating system gave it.
        message: String,
    },
    /// The file is not valid TOML, lacks a required field, has a field the format does not
    /// know, or holds a value of the wrong type.
    #[error("the registry file does not parse: {0}")]
    Parse(String),
    /// A required piece of text is empty.
    #[error("`{field}` of {place} is empty")]
    EmptyField {
        /// The field.
        field: &'static str,
        /// What it belongs to.
        place: String,
    },
    /// Two servers share a name.
    #[error("server `{0}` is registered more than once")]
    DuplicateServer(ConnectorName),
    /// A server's address is not an `http` or `https` URL.
    #[error("server `{server}` has address `{address}`, which is not an http or https URL")]
    AddressNotHttp {
        /// The server.
        server: ConnectorName,
        /// Its address.
        address: String,
    },
    /// Two tools share an exposed name.
    #[error("tool `{0}` is approved more than once")]
    DuplicateTool(ToolName),
    /// One upstream tool on one server is approved under two exposed names.
    #[error("tool `{upstream_name}` on server `{server}` is approved more than once")]
    DuplicateUpstream {
        /// The server.
        server: ConnectorName,
        /// The tool's name there.
        upstream_name: String,
    },
    /// A tool names a server that is not registered.
    #[error("tool `{tool}` names server `{server}`, which is not registered")]
    UnknownServer {
        /// The tool.
        tool: ToolName,
        /// The server it names.
        server: ConnectorName,
    },
    /// A tool's exposed name is not `{system}__{tool}` for its server's system.
    #[error("tool `{tool}` must be named `{system}__<tool>`, after its server's system")]
    NameOutsideSystem {
        /// The tool.
        tool: ToolName,
        /// Its server's system.
        system: String,
    },
    /// A tool's `approved_at` is not a full date-time with an offset.
    #[error("tool `{0}` has an `approved_at` that is not a date-time with an offset")]
    ApprovedAtIncomplete(ToolName),
    /// A tool's definition does not hash to what was approved: it changed after approval.
    #[error(
        "tool `{tool}`'s definition hashes to {computed}, not the approved {recorded}; approve it again"
    )]
    DefinitionChanged {
        /// The tool.
        tool: ToolName,
        /// The hash the approval recorded.
        recorded: String,
        /// The hash of the definition in the file.
        computed: String,
    },
    /// A tool's input schema is not an object schema.
    #[error("tool `{0}`'s input schema is not a JSON Schema with `type` `object`")]
    SchemaNotObject(ToolName),
    /// A tool's input schema uses a keyword the argument check does not follow.
    #[error(
        "tool `{tool}`'s input schema uses `{keyword}` at `{at}`, which the argument check does not follow"
    )]
    SchemaUnfollowed {
        /// The tool.
        tool: ToolName,
        /// The keyword.
        keyword: String,
        /// Where, as a JSON Pointer into the schema.
        at: JsonPointer,
    },
    /// A tool's input schema has `properties` that is not an object, or a property or
    /// `items` that is not a schema.
    #[error("tool `{tool}`'s input schema is malformed at `{at}`")]
    SchemaMalformed {
        /// The tool.
        tool: ToolName,
        /// Where, as a JSON Pointer into the schema.
        at: JsonPointer,
    },
    /// A tool says its resources come from its arguments, and lists no source.
    #[error("tool `{0}` reads its resources from its arguments but lists none")]
    AdapterWithoutSources(ToolName),
    /// An adapter reads an argument the tool's schema does not declare at the top level.
    #[error(
        "tool `{tool}` reads its resource from `{argument}`, which its input schema does not declare"
    )]
    AdapterArgumentUndeclared {
        /// The tool.
        tool: ToolName,
        /// The argument.
        argument: String,
    },
    /// An adapter reads an argument the tool's schema does not type as a string.
    #[error(
        "tool `{tool}` reads its resource from `{argument}`, which its input schema does not type as a string"
    )]
    AdapterArgumentNotString {
        /// The tool.
        tool: ToolName,
        /// The argument.
        argument: String,
    },
    /// The policy data does not make a snapshot.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// A profile rule names a profile the file does not define.
    #[error("a profile rule names profile `{0}`, which is not defined")]
    UnknownProfile(ProfileName),
    /// Two profile rules cover the same issuer and kind of principal.
    #[error("two profile rules cover {principal} from issuer `{issuer}`")]
    DuplicateRule {
        /// The issuer.
        issuer: Issuer,
        /// The principals both cover.
        principal: RulePrincipal,
    },
}

/// A loaded, checked registry.
#[derive(Clone, Debug)]
pub struct Registry {
    snapshot: PolicySnapshot,
    definitions: BTreeMap<ToolName, ToolDefinition>,
    adapters: BTreeMap<ToolName, ArgumentAdapter>,
    routes: BTreeMap<ToolName, Route>,
    approvals: BTreeMap<ToolName, Approval>,
    servers: BTreeMap<ConnectorName, Server>,
    profile_rules: ProfileRules,
}

impl Registry {
    /// Reads and checks the registry file at `path`.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = std::fs::read_to_string(path).map_err(|error| RegistryError::Read {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        Self::from_toml_str(&text)
    }

    /// Checks a registry file's text.
    pub fn from_toml_str(text: &str) -> Result<Self, RegistryError> {
        let file: RegistryFile =
            toml::from_str(text).map_err(|error| RegistryError::Parse(error.to_string()))?;
        build(file)
    }

    /// The policy snapshot.
    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    /// Every approved tool's definition, by exposed name.
    pub fn definitions(&self) -> &BTreeMap<ToolName, ToolDefinition> {
        &self.definitions
    }

    /// Every approved tool's adapter, by exposed name.
    pub fn adapters(&self) -> &BTreeMap<ToolName, ArgumentAdapter> {
        &self.adapters
    }

    /// Where every approved tool's calls go, by exposed name.
    pub fn routes(&self) -> &BTreeMap<ToolName, Route> {
        &self.routes
    }

    /// Every approved tool's approval, by exposed name.
    pub fn approvals(&self) -> &BTreeMap<ToolName, Approval> {
        &self.approvals
    }

    /// Every registered server, by name.
    pub fn servers(&self) -> &BTreeMap<ConnectorName, Server> {
        &self.servers
    }

    /// The profile-selection rules.
    pub fn profile_rules(&self) -> &ProfileRules {
        &self.profile_rules
    }

    /// The profile `principal`'s calls are decided under. See [`ProfileRules::select`].
    pub fn select_profile(&self, principal: &Principal) -> Result<ProfileName, NoProfile> {
        self.profile_rules.select(principal)
    }
}

fn require(
    value: &str,
    field: &'static str,
    place: impl FnOnce() -> String,
) -> Result<(), RegistryError> {
    if value.is_empty() {
        Err(RegistryError::EmptyField {
            field,
            place: place(),
        })
    } else {
        Ok(())
    }
}

fn build(file: RegistryFile) -> Result<Registry, RegistryError> {
    require(&file.revision, "revision", || "the registry".into())?;
    let servers = servers(file.servers)?;

    let mut definitions = BTreeMap::new();
    let mut adapters = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut approvals = BTreeMap::new();
    let mut upstream = BTreeSet::new();
    let mut approved = Vec::new();
    for tool in file.tools {
        let checked = check_tool(tool, &servers)?;
        if definitions.contains_key(&checked.definition.name) {
            return Err(RegistryError::DuplicateTool(checked.definition.name));
        }
        if !upstream.insert((
            checked.route.server.clone(),
            checked.route.upstream_name.clone(),
        )) {
            return Err(RegistryError::DuplicateUpstream {
                server: checked.route.server,
                upstream_name: checked.route.upstream_name,
            });
        }
        let name = checked.definition.name.clone();
        approved.push(ApprovedTool {
            name: name.clone(),
            classification: checked.classification,
            connector: checked.route.server.clone(),
            resources: checked.adapter.declaration(),
        });
        definitions.insert(name.clone(), checked.definition);
        adapters.insert(name.clone(), checked.adapter);
        routes.insert(name.clone(), checked.route);
        approvals.insert(name, checked.approval);
    }

    let surfaces = file
        .surfaces
        .into_iter()
        .map(|surface| Surface {
            name: surface.name,
            tools: surface.tools,
            teams: surface.teams,
            groups: surface.groups,
            principals: match surface.principals {
                PrincipalsFile::AnyInTeamsAndGroups => PrincipalRestriction::AnyInTeamsAndGroups,
                PrincipalsFile::Only(ids) => PrincipalRestriction::Only(
                    ids.into_iter()
                        .map(|id| PrincipalId {
                            issuer: id.issuer,
                            subject: id.subject,
                        })
                        .collect(),
                ),
            },
        })
        .collect();
    let profiles = file
        .profiles
        .into_iter()
        .map(|profile| Profile {
            name: profile.name,
            classifications: profile.classifications,
            requires_delegation: profile.requires_delegation,
        })
        .collect();
    let limits = ResourceLimits {
        teams: limit_sets(file.limits.teams, "team")?,
        groups: limit_sets(file.limits.groups, "group")?,
    };
    let snapshot = PolicySnapshot::new(SnapshotData {
        revision: PolicyRevision::new(file.revision),
        tools: approved,
        surfaces,
        profiles,
        limits,
    })?;

    let mut covered = BTreeSet::new();
    let mut rules = Vec::new();
    for rule in file.profile_rules {
        let principal = match rule.principal {
            RulePrincipalFile::Workload => RulePrincipal::Workload,
            RulePrincipalFile::UserInGroup(group) => RulePrincipal::UserInGroup(group),
        };
        if snapshot.profile(&rule.profile).is_none() {
            return Err(RegistryError::UnknownProfile(rule.profile));
        }
        if !covered.insert((rule.issuer.clone(), principal.clone())) {
            return Err(RegistryError::DuplicateRule {
                issuer: rule.issuer,
                principal,
            });
        }
        rules.push(ProfileRule {
            issuer: rule.issuer,
            principal,
            profile: rule.profile,
        });
    }

    Ok(Registry {
        snapshot,
        definitions,
        adapters,
        routes,
        approvals,
        servers,
        profile_rules: ProfileRules::new(rules),
    })
}

fn servers(files: Vec<ServerFile>) -> Result<BTreeMap<ConnectorName, Server>, RegistryError> {
    let mut servers = BTreeMap::new();
    for server in files {
        let place = || format!("server `{}`", server.name);
        require(server.name.as_str(), "name", place)?;
        require(&server.system, "system", place)?;
        require(&server.owner, "owner", place)?;
        require(&server.identity, "identity", place)?;
        let credential = match server.credential {
            CredentialFile::Bearer { reference } => {
                require(&reference, "credential.reference", place)?;
                Credential::Bearer { reference }
            }
        };
        let http = ["http://", "https://"].iter().any(|scheme| {
            server
                .address
                .strip_prefix(scheme)
                .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        });
        if !http {
            return Err(RegistryError::AddressNotHttp {
                server: server.name,
                address: server.address,
            });
        }
        let checked = Server {
            name: server.name.clone(),
            system: server.system,
            owner: server.owner,
            identity: server.identity,
            address: server.address,
            credential,
        };
        if servers.insert(server.name.clone(), checked).is_some() {
            return Err(RegistryError::DuplicateServer(server.name));
        }
    }
    Ok(servers)
}

struct CheckedTool {
    definition: ToolDefinition,
    adapter: ArgumentAdapter,
    route: Route,
    approval: Approval,
    classification: gateway_core::Classification,
}

fn check_tool(
    tool: ToolFile,
    servers: &BTreeMap<ConnectorName, Server>,
) -> Result<CheckedTool, RegistryError> {
    let name = tool.name;
    let place = || format!("tool `{name}`");
    let Some(server) = servers.get(&tool.server) else {
        return Err(RegistryError::UnknownServer {
            tool: name,
            server: tool.server,
        });
    };
    let under_system = name
        .as_str()
        .strip_prefix(server.system.as_str())
        .and_then(|rest| rest.strip_prefix("__"))
        .is_some_and(|rest| !rest.is_empty());
    if !under_system {
        return Err(RegistryError::NameOutsideSystem {
            tool: name,
            system: server.system.clone(),
        });
    }
    require(&tool.upstream_name, "upstream_name", place)?;
    require(&tool.description, "description", place)?;
    require(&tool.approved_by, "approved_by", place)?;
    if let Some(title) = &tool.title {
        require(title, "title", place)?;
    }
    // In TOML only an offset date-time has an offset, and it always has a date and a time.
    let at = tool.approved_at;
    if at.offset.is_none() {
        return Err(RegistryError::ApprovedAtIncomplete(name));
    }

    if tool.input_schema.get("type") != Some(&Value::String("object".into())) {
        return Err(RegistryError::SchemaNotObject(name));
    }
    adapter::followable(&tool.input_schema, &JsonPointer::default()).map_err(|problem| {
        match problem {
            SchemaProblem::Unfollowed { keyword, at } => RegistryError::SchemaUnfollowed {
                tool: name.clone(),
                keyword,
                at,
            },
            SchemaProblem::Malformed { at } => RegistryError::SchemaMalformed {
                tool: name.clone(),
                at,
            },
        }
    })?;

    let computed = definition_sha256(
        &tool.upstream_name,
        tool.title.as_deref(),
        &tool.description,
        &tool.input_schema,
    );
    if computed != tool.definition_sha256 {
        return Err(RegistryError::DefinitionChanged {
            tool: name,
            recorded: tool.definition_sha256,
            computed,
        });
    }

    let sources = match tool.resources {
        ResourcesFile::NoResources => Vec::new(),
        ResourcesFile::FromArguments(sources) => {
            if sources.is_empty() {
                return Err(RegistryError::AdapterWithoutSources(name));
            }
            let properties = tool.input_schema.get("properties");
            let mut checked = Vec::with_capacity(sources.len());
            for source in sources {
                require(&source.system, "resources.system", place)?;
                require(&source.kind, "resources.kind", place)?;
                let Some(property) = properties.and_then(|p| p.get(&source.from_argument)) else {
                    return Err(RegistryError::AdapterArgumentUndeclared {
                        tool: name,
                        argument: source.from_argument,
                    });
                };
                if property.get("type") != Some(&Value::String("string".into())) {
                    return Err(RegistryError::AdapterArgumentNotString {
                        tool: name,
                        argument: source.from_argument,
                    });
                }
                checked.push(ResourceSource {
                    from_argument: source.from_argument,
                    system: source.system,
                    kind: source.kind,
                });
            }
            checked
        }
    };

    Ok(CheckedTool {
        adapter: ArgumentAdapter::new(name.clone(), sources, tool.input_schema.clone()),
        definition: ToolDefinition {
            name,
            title: tool.title,
            description: tool.description,
            input_schema: tool.input_schema,
            read_only: tool.classification == gateway_core::Classification::Read,
        },
        route: Route {
            server: tool.server,
            upstream_name: tool.upstream_name,
        },
        approval: Approval {
            approved_by: tool.approved_by,
            approved_at: at.to_string(),
            definition_sha256: tool.definition_sha256,
        },
        classification: tool.classification,
    })
}

fn limit_sets<K: Ord + std::fmt::Display>(
    limits: BTreeMap<K, Vec<ResourceFile>>,
    owner: &str,
) -> Result<BTreeMap<K, BTreeSet<Resource>>, RegistryError> {
    let mut sets = BTreeMap::new();
    for (key, resources) in limits {
        let place = || format!("a limit of {owner} `{key}`");
        let mut set = BTreeSet::new();
        for resource in resources {
            require(&resource.system, "system", place)?;
            require(&resource.kind, "kind", place)?;
            require(&resource.identifier, "identifier", place)?;
            set.insert(Resource {
                system: resource.system,
                kind: resource.kind,
                identifier: resource.identifier,
            });
        }
        sets.insert(key, set);
    }
    Ok(sets)
}
