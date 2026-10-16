//! Loading the registry file and checking it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use gateway_core::{
    ApprovedTool, Classification, ConnectorEntry, ConnectorName, CredentialMode, DeclaredFrom,
    EntryKind, Issuer, Narrowing, PolicyRevision, PolicySnapshot, Principal, PrincipalId,
    PrincipalRestriction, Profile, ProfileName, Resource, ResourceDeclaration, ResourceLimits,
    Settlement, SnapshotData, SnapshotError, Surface, SurfaceName, ToolName,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use toml::value::Datetime;

use crate::adapter::{self, ArgumentAdapter, JsonPointer, ResourceSource, SchemaProblem};
use crate::builtin::{BuiltInEntry, built_in};
use crate::definition::{
    Approval, Route, ToolDefinition, binding_sha256, built_in_binding_sha256, definition_sha256,
};
use crate::file::{
    BuiltInResourcesFile, BuiltInToolFile, PrincipalsFile, RegistryFile, ResourceFile,
    ResourcesFile, RulePrincipalFile, ServerFile, SourceFile, ToolFile,
};
use crate::selection::{NoProfile, ProfileRule, ProfileRules, RulePrincipal};

/// A proxied MCP server, as its owner registered it, and its connector entry (decision 0011,
/// section 1): every server is one entry, with one credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Server {
    /// The server's name. Approved tools name it as their connector.
    pub name: ConnectorName,
    /// The system part of its tools' exposed names: every tool on this server is exposed as
    /// `{system}__{tool}`. No two servers have the same system, and none contains `__` or ends
    /// in `_`.
    pub system: String,
    /// The team that owns the server and answers for it.
    pub owner: String,
    /// The server's identity: the DNS name the connection proves, which is the host in its
    /// address (decision 0013). The loader refuses an identity that is not that host, as
    /// [`address_host`] reads it. Each approval's [`binding_sha256`](crate::binding_sha256)
    /// covers it. `serverInfo.name` is only the server's claim about itself and is not used.
    pub identity: String,
    /// Where the gateway sends its calls: an `http` or `https` URL with a host.
    pub address: String,
    /// The credential the gateway presents to it.
    pub credential: Credential,
    /// What the credential is narrowed to on each call.
    pub narrowing: Narrowing,
    /// The highest classification any call made with the credential could have.
    pub permits: Classification,
    /// Every resource the credential and route can reach. Empty for an entry that reaches
    /// nothing a limit applies to.
    pub reach: BTreeSet<Resource>,
    /// The recorded test showing that a call outside the reach fails. Required when the reach
    /// is not empty.
    pub reach_test: Option<ReachTest>,
    /// Which class of destination the address is (decision 0013, section 3).
    pub destination: Destination,
    /// The registration probe's record (decision 0013, section 9). The loader refuses an entry
    /// without one, or with a result other than `refused`, so every server of a loaded
    /// registry has one; only [`Registry::server_entry`], which `switchboard probe` reads an
    /// entry with before it has a record, returns a server without. Not in the binding: the
    /// drift pass repeats the probe.
    pub probe: Option<Probe>,
    /// The call outside the reach that the scheduled reach check makes (decision 0011,
    /// section 4). Required when the reach is not empty and the credential is not per-user.
    pub reach_check: Option<ReachCheck>,
}

/// How the gateway authenticates to a server. Never the caller's token (design.md section 13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Credential {
    /// The credential's mode. For a team service identity or a gateway token, the gateway
    /// sends `Authorization: Bearer` with a secret it holds. A per-user grant is refused at
    /// start until milestone 5 builds it.
    pub mode: CredentialMode,
    /// Which secret: a label the credential source resolves, never the secret itself.
    pub reference: String,
    /// The identity the credential acts as, such as a ServiceAccount's name: the same in every
    /// deployment of one entry.
    pub principal: String,
}

/// The class of a server's destination (decision 0013, section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// A Service inside the cluster. Only such an entry may use plain `http`.
    InCluster,
    /// Anywhere else, over `https` only.
    Public,
}

impl Destination {
    /// The destination's name, as written in the registry and hashed in the binding.
    pub fn as_str(self) -> &'static str {
        match self {
            Destination::InCluster => "in_cluster",
            Destination::Public => "public",
        }
    }
}

/// A recorded reach test (decision 0011, section 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReachTest {
    /// When it was run, `YYYY-MM-DD`.
    pub date: String,
    /// What was run and what it showed.
    pub record: String,
}

/// What the registration probe found, as `switchboard probe` prints its record. Only `refused`
/// loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeResult {
    /// The server refused each of the probe's calls.
    Refused,
    /// The server dispatched at least one of them: it does not check its caller.
    Open,
    /// Neither was shown: a call could not be made, or its answer was not a refusal.
    NotShown,
}

impl ProbeResult {
    /// The result's name, as a probe record writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Open => "open",
            Self::NotShown => "not_shown",
        }
    }
}

/// A recorded registration probe (decision 0013, section 9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    /// What it found.
    pub result: ProbeResult,
    /// When it was run, `YYYY-MM-DD`.
    pub date: String,
}

/// The reach check's call outside the reach: one of the entry's tools, and arguments naming a
/// canary resource outside the reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReachCheck {
    /// The tool, by its exposed name, which the loader requires to be `{system}__<tool>` for
    /// the server's own system. No two servers have the same system, and no system contains
    /// `__` or ends in `_`, so a name is under one system at most: the check cannot name
    /// another server's tool or a malformed one. The loader requires the tool to be approved
    /// while any other tool of the server is, so that nothing is served under a credential
    /// whose reach can no longer be checked. Removing a tool's approval withdraws it (decision
    /// 0013, section 8): this tool is withdrawn together with the server's others, which needs
    /// no edit to the reach check.
    pub tool: ToolName,
    /// Its arguments.
    pub arguments: serde_json::Map<String, Value>,
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
    /// The registry's revision contains `+`, which is reserved for the revisions a withdrawal
    /// derives from it (decision 0013).
    #[error(
        "the registry's revision `{0}` contains `+`, which only a withdrawal's derived revision may"
    )]
    RevisionReserved(String),
    /// Two servers share a name.
    #[error("server `{0}` is registered more than once")]
    DuplicateServer(ConnectorName),
    /// Two servers have the same system, so a tool named after it could be either's.
    #[error(
        "servers `{first}` and `{second}` both have the system `{system}`; each server needs a \
         system of its own"
    )]
    DuplicateSystem {
        /// The system.
        system: String,
        /// The server registered first with it.
        first: ConnectorName,
        /// The server registered second with it.
        second: ConnectorName,
    },
    /// A server's system contains `__` or ends in `_`, so a tool name under it could also be
    /// under a shorter system, such as `docs` for `docs__wiki` or `docs_`.
    #[error(
        "server `{server}` has the system `{system}`, which contains `__` or ends in `_`; a \
         tool name must be under one system only, so a system may do neither"
    )]
    SystemOverlaps {
        /// The server.
        server: ConnectorName,
        /// Its system.
        system: String,
    },
    /// A server's address is not an `http` or `https` URL with a host.
    #[error("server `{server}` has address `{address}`, which is not an http or https URL")]
    AddressNotHttp {
        /// The server.
        server: ConnectorName,
        /// Its address.
        address: String,
    },
    /// A server's identity is not the host in its address (decision 0013).
    #[error(
        "server `{server}` has identity `{identity}`, which is not `{host}`, the host in its address"
    )]
    IdentityNotHost {
        /// The server.
        server: ConnectorName,
        /// Its identity, as written.
        identity: String,
        /// The host in its address.
        host: String,
    },
    /// A date is not a plain date such as `2026-10-12`.
    #[error("`{field}` of {place} is not a date such as 2026-10-12")]
    NotADate {
        /// The field.
        field: &'static str,
        /// What it belongs to.
        place: String,
    },
    /// A server's address is plain `http`, and its destination is not `in_cluster` (decision
    /// 0013, section 3).
    #[error(
        "server `{server}` has the http address `{address}`; only an `in_cluster` destination may use http"
    )]
    DestinationScheme {
        /// The server.
        server: ConnectorName,
        /// Its address.
        address: String,
    },
    /// A server has a reach and no recorded reach test (decision 0011, section 2).
    #[error(
        "server `{0}` has a reach and no `reach_test`; record the test that shows a call outside it fails"
    )]
    ReachTestMissing(ConnectorName),
    /// A server has a reach and no reach check, the call outside it that the scheduled check
    /// makes (decision 0011, section 4).
    #[error(
        "server `{0}` has a reach and no `reach_check`, the call outside it the reach check makes"
    )]
    ReachCheckMissing(ConnectorName),
    /// A server's reach check calls a tool that is not named `{system}__<tool>` for the
    /// server's own system: another server's tool, or a malformed name.
    #[error(
        "server `{server}`'s reach check calls `{tool}`, which is not one of its own tools: \
         name it `{system}__<tool>`, after the server's system"
    )]
    ReachCheckOutsideSystem {
        /// The server.
        server: ConnectorName,
        /// The tool its reach check names.
        tool: ToolName,
        /// The server's system.
        system: String,
    },
    /// A server's reach check calls a tool that is not approved, and another of the server's
    /// tools is approved: that tool would be served under a credential whose reach can no
    /// longer be checked.
    #[error(
        "server `{server}`'s reach check calls `{tool}`, which is not approved, and other tools \
         of the server are: remove the server's approvals together, or name another tool in its \
         reach check"
    )]
    ReachCheckUnapproved {
        /// The server.
        server: ConnectorName,
        /// The tool its reach check names.
        tool: ToolName,
    },
    /// A server has no probe record (decision 0013, section 9).
    #[error(
        "server `{0}` has no `probe` record; run `switchboard probe` and record its result and date"
    )]
    ProbeMissing(ConnectorName),
    /// A server's probe record does not say it refused all three calls.
    #[error(
        "server `{server}` has a `probe` record whose result is `{result}`; only a server that refused all three probe calls is registered"
    )]
    ProbeNotRefused {
        /// The server.
        server: ConnectorName,
        /// The recorded result.
        result: &'static str,
    },
    /// The registry has no server of the name asked for.
    #[error("the registry has no server `{0}`")]
    NoSuchServer(ConnectorName),
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
    /// A tool's server entry does not hash to the binding that was approved: the server's
    /// identity, address or credential changed after approval.
    #[error(
        "tool `{tool}`'s binding to server `{server}` hashes to {computed}, not the approved {recorded}; approve it again"
    )]
    BindingChanged {
        /// The tool.
        tool: ToolName,
        /// Its server.
        server: ConnectorName,
        /// The hash the approval recorded.
        recorded: String,
        /// The hash of the server entry in the file.
        computed: String,
    },
    /// A tool's input schema is not an object schema.
    #[error("tool `{0}`'s input schema is not a JSON Schema with `type` `object`")]
    SchemaNotObject(ToolName),
    /// A tool's input schema uses a keyword outside the subset of JSON Schema 2020-12 the
    /// argument check enforces or ignores as an annotation (see [`ArgumentAdapter`]).
    #[error(
        "tool `{tool}`'s input schema uses `{keyword}` at `{at}`, which the argument check does not follow"
    )]
    SchemaUnfollowed {
        /// The tool.
        tool: ToolName,
        /// The keyword.
        keyword: String,
        /// Where, as a JSON Pointer into the schema: the schema that uses the keyword.
        at: JsonPointer,
    },
    /// A tool's input schema has an enforced keyword whose value does not have the JSON type
    /// JSON Schema 2020-12 gives it, such as `properties` that is not an object, `items` that is a list, or a
    /// property that is not a schema.
    #[error("tool `{tool}`'s input schema is malformed at `{at}`")]
    SchemaMalformed {
        /// The tool.
        tool: ToolName,
        /// Where, as a JSON Pointer into the schema: the value that is malformed.
        at: JsonPointer,
    },
    /// A tool's input schema names, in `$schema`, a dialect other than JSON Schema 2020-12.
    /// Decision 0011 lets such a schema be refused or converted at approval; this loader
    /// refuses it.
    #[error(
        "tool `{tool}`'s input schema names the dialect `{dialect}`; only JSON Schema 2020-12 is approved, so convert it and approve it again"
    )]
    SchemaDialect {
        /// The tool.
        tool: ToolName,
        /// The `$schema` value, as written.
        dialect: String,
    },
    /// A tool's input schema has an `additionalProperties` that is neither a boolean nor a
    /// schema (#94). Read loosely, a value such as `"false"` would leave the object open.
    #[error(
        "tool `{tool}`'s input schema has an `additionalProperties` at `{at}` that is neither true, false nor a schema"
    )]
    SchemaAdditionalPropertiesMalformed {
        /// The tool.
        tool: ToolName,
        /// Where, as a JSON Pointer into the schema.
        at: JsonPointer,
    },
    /// A tool's input schema has a `type` list or a `required` list that names one name twice
    /// (#127). JSON Schema 2020-12 says the names in each must be unique.
    #[error(
        "tool `{tool}`'s input schema names `{name}` twice in the list at `{at}`; JSON Schema 2020-12 requires its names to be unique"
    )]
    SchemaRepeatedName {
        /// The tool.
        tool: ToolName,
        /// The name given twice.
        name: String,
        /// Where, as a JSON Pointer into the schema: the `type` or `required` list.
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
    /// Two connector entries share a name: two built-in entries, or a built-in entry and a
    /// server.
    #[error("connector entry `{0}` is registered more than once, as a server or a connector")]
    DuplicateEntry(ConnectorName),
    /// A built-in entry states no vendor permission, which GitHub reads as every permission
    /// the installation has.
    #[error("connector `{0}` states no permissions; state the set its credential may be asked for")]
    EntryWithoutPermissions(ConnectorName),
    /// A built-in entry states a permission whose name is not lowercase letters and underscores.
    #[error(
        "connector `{entry}` states the permission `{permission}`, which is not a permission name"
    )]
    PermissionName {
        /// The entry.
        entry: ConnectorName,
        /// The name as written.
        permission: String,
    },
    /// A built-in entry serves no tool.
    #[error("connector `{0}` serves no tool")]
    EntryWithoutTools(ConnectorName),
    /// A tool is served by two built-in entries, so its permission set would be ambiguous.
    #[error("tool `{tool}` is served by both connector `{first}` and connector `{second}`")]
    ToolOnTwoEntries {
        /// The tool.
        tool: ToolName,
        /// The entry that lists it first.
        first: ConnectorName,
        /// The other.
        second: ConnectorName,
    },
    /// A built-in entry lists a tool that is approved on a proxied server.
    #[error("connector `{entry}` serves tool `{tool}`, which is approved on a proxied server")]
    BuiltInToolProxied {
        /// The tool.
        tool: ToolName,
        /// The built-in entry.
        entry: ConnectorName,
    },
    /// A built-in entry gives some of its credential, narrowing, what it permits and its reach,
    /// and not the rest: they are given together or not at all.
    #[error(
        "connector `{0}` gives some of `credential`, `narrowing`, `permits` and `reach` but not \
         the others; give the first three together, with `reach` if a tool is declared as it, \
         or none of them"
    )]
    EntryPartlyDeclared(ConnectorName),
    /// A built-in tool's approval names a connector entry the file does not have.
    #[error(
        "built-in tool `{tool}` names connector `{connector}`, which is not a `[[connectors]]` entry"
    )]
    UnknownConnector {
        /// The tool.
        tool: ToolName,
        /// The entry it names.
        connector: ConnectorName,
    },
    /// A built-in tool's entry declares no credential, so decision 0011 cannot hold its tools
    /// to the snapshot loader's rules.
    #[error(
        "built-in tool `{tool}` is approved on connector `{connector}`, which declares no \
         `credential`, `narrowing` and `permits`; declare them on the entry"
    )]
    EntryUndeclared {
        /// The tool.
        tool: ToolName,
        /// The entry it names.
        connector: ConnectorName,
    },
    /// A built-in tool is approved on an entry that does not list it among the tools it
    /// serves, so the key custodian would not know its permission set.
    #[error(
        "built-in tool `{tool}` is approved on connector `{connector}`, which does not list it in `tools`"
    )]
    BuiltInToolNotListed {
        /// The tool.
        tool: ToolName,
        /// The entry it names.
        connector: ConnectorName,
    },
    /// A built-in tool's binding to its entry does not hash to what was approved: the entry's
    /// credential, narrowing, permissions or reach changed after approval.
    #[error(
        "built-in tool `{tool}`'s binding to connector `{connector}` hashes to {computed}, not \
         the approved {recorded}; approve it again"
    )]
    BuiltInBindingChanged {
        /// The tool.
        tool: ToolName,
        /// Its entry.
        connector: ConnectorName,
        /// The hash the approval recorded.
        recorded: String,
        /// The hash of the entry in the file.
        computed: String,
    },
    /// A reach-report entry, or a tool approved on one, is not held to its one job (decision
    /// 0011, section 4; see [`BuiltInEntry::reports_reach`]).
    #[error(
        "connector `{connector}` reports reach, and {problem}; a reach-report entry declares its \
         credential, narrowed \"none\", permitting \"read\", with no reach or reach report of \
         its own, and serves only `read` tools"
    )]
    ReachReportEntry {
        /// The entry.
        connector: ConnectorName,
        /// What is wrong with it.
        problem: String,
    },
    /// A surface serves a reach report's tool to any principal of its teams and groups.
    #[error(
        "surface `{surface}` serves `{tool}`, a reach report's tool, to any principal of its \
         teams and groups; serve it only on a surface restricted to named principals, the \
         registry's own"
    )]
    ReachReportSurface {
        /// The surface.
        surface: SurfaceName,
        /// The tool.
        tool: ToolName,
    },
    /// An entry's reach report cannot check its reach.
    #[error("connector `{connector}`'s reach report {problem}")]
    ReachReport {
        /// The entry whose reach is checked.
        connector: ConnectorName,
        /// What is wrong.
        problem: String,
    },
    /// A tool qualifies its resource by an argument its schema does not declare as a string at
    /// the top level.
    #[error(
        "tool `{tool}` qualifies its resource by `{argument}`, which its input schema does not \
         declare as a string"
    )]
    AdapterQualifierNotString {
        /// The tool.
        tool: ToolName,
        /// The argument.
        argument: String,
    },
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
    connectors: BTreeMap<ConnectorName, BuiltInEntry>,
    built_in_tools: BTreeMap<ToolName, ConnectorName>,
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

    /// The entry of server `name` in a registry file's text, read and checked alone: what
    /// `switchboard probe` reads (decision 0013, section 9). It is checked as the loader checks
    /// a server entry, except that it need not have a probe record, so an entry can be probed
    /// before it is registered. Nothing else in the file is read beyond what TOML needs to parse
    /// it.
    pub fn server_entry(text: &str, name: &ConnectorName) -> Result<Server, RegistryError> {
        let parse = |error: toml::de::Error| RegistryError::Parse(error.to_string());
        let file: toml::Table = toml::from_str(text).map_err(parse)?;
        let Some(toml::Value::Array(entries)) = file.get("servers") else {
            return Err(RegistryError::Parse(
                "`servers` is missing or not an array of tables".to_owned(),
            ));
        };
        let mut named = entries.iter().filter(|server| {
            server.get("name").and_then(toml::Value::as_str) == Some(name.as_str())
        });
        let Some(entry) = named.next() else {
            return Err(RegistryError::NoSuchServer(name.clone()));
        };
        if named.next().is_some() {
            return Err(RegistryError::DuplicateServer(name.clone()));
        }
        let entry: ServerFile = entry.clone().try_into().map_err(parse)?;
        servers(vec![entry], ProbeRule::NotApplied)?
            .into_values()
            .next()
            .ok_or_else(|| RegistryError::NoSuchServer(name.clone()))
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

    /// Every built-in connector entry, by name.
    pub fn connectors(&self) -> &BTreeMap<ConnectorName, BuiltInEntry> {
        &self.connectors
    }

    /// Every approved built-in tool, by exposed name, with the entry it is approved on. Its
    /// definition, adapter and approval are among the others; it has no route, since nothing
    /// is forwarded.
    pub fn built_in_tools(&self) -> &BTreeMap<ToolName, ConnectorName> {
        &self.built_in_tools
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
    if file.revision.contains('+') {
        return Err(RegistryError::RevisionReserved(file.revision));
    }
    let servers = servers(file.servers, ProbeRule::Applied)?;

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
            resources: checked.resources,
            declared_from: checked.declared_from,
            settlement: checked.settlement,
        });
        definitions.insert(name.clone(), checked.definition);
        adapters.insert(name.clone(), checked.adapter);
        routes.insert(name.clone(), checked.route);
        approvals.insert(name, checked.approval);
    }
    // A reach check's tool stays approved while any other tool of its server is, so that
    // nothing is served under a credential whose reach can no longer be checked; removing
    // every approval of a server still loads (decision 0013, section 8). A tool is the
    // server's when its route names the server, as the drift pass takes an entry's tools. Its
    // name is under the server's system, as the reach check's is, so the two agree.
    for server in servers.values() {
        if let Some(check) = &server.reach_check
            && !routes.contains_key(&check.tool)
            && routes.values().any(|route| route.server == server.name)
        {
            return Err(RegistryError::ReachCheckUnapproved {
                server: server.name.clone(),
                tool: check.tool.clone(),
            });
        }
    }

    let proxied: BTreeSet<ToolName> = routes.keys().cloned().collect();
    let connectors = built_in(file.connectors, &servers, &proxied)?;
    let mut built_in_tools = BTreeMap::new();
    for tool in file.built_in_tools {
        let checked = check_built_in_tool(tool, &connectors)?;
        let name = checked.definition.name.clone();
        if definitions.contains_key(&name) {
            return Err(RegistryError::DuplicateTool(name));
        }
        approved.push(ApprovedTool {
            name: name.clone(),
            classification: checked.classification,
            connector: checked.route.server.clone(),
            resources: checked.resources,
            declared_from: checked.declared_from,
            settlement: checked.settlement,
        });
        built_in_tools.insert(name.clone(), checked.route.server);
        definitions.insert(name.clone(), checked.definition);
        adapters.insert(name.clone(), checked.adapter);
        approvals.insert(name, checked.approval);
    }
    // A reach report's tool stays approved while any tool of an entry it checks is, as a
    // reach check's tool does, so that nothing is served under a credential whose reach is
    // never checked.
    for entry in connectors.values() {
        if let Some(report) = &entry.reach_report
            && !built_in_tools.contains_key(&report.tool)
            && built_in_tools.values().any(|on| *on == entry.name)
        {
            return Err(RegistryError::ReachReport {
                connector: entry.name.clone(),
                problem: format!(
                    "names `{}`, which is not approved, and other tools of the entry are: they \
                     would be served under a credential whose reach is never checked",
                    report.tool
                ),
            });
        }
    }

    // A reach report's tool reads what a whole installation reaches: it is served only to
    // named principals, the registry's own (decision 0011, section 4).
    for surface in &file.surfaces {
        if !matches!(surface.principals, PrincipalsFile::AnyInTeamsAndGroups) {
            continue;
        }
        let reporting = surface.tools.iter().find(|tool| {
            built_in_tools
                .get(*tool)
                .and_then(|entry| connectors.get(entry))
                .is_some_and(|entry| entry.reports_reach)
        });
        if let Some(tool) = reporting {
            return Err(RegistryError::ReachReportSurface {
                surface: surface.name.clone(),
                tool: tool.clone(),
            });
        }
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
            requires_currency: profile.requires_currency,
            idempotency_key_header: profile.idempotency_key_header,
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
        entries: servers
            .values()
            .map(entry)
            .chain(connectors.values().filter_map(BuiltInEntry::snapshot_entry))
            .collect(),
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
        connectors,
        built_in_tools,
        profile_rules: ProfileRules::new(rules),
    })
}

/// Whether [`servers`] applies the probe rule: the loader does, and
/// [`Registry::server_entry`] does not.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeRule {
    Applied,
    NotApplied,
}

fn servers(
    files: Vec<ServerFile>,
    probe_rule: ProbeRule,
) -> Result<BTreeMap<ConnectorName, Server>, RegistryError> {
    let mut servers = BTreeMap::new();
    let mut systems = BTreeMap::new();
    for server in files {
        let place = || format!("server `{}`", server.name);
        require(server.name.as_str(), "name", place)?;
        require(&server.system, "system", place)?;
        // A tool name is under a system when it is `{system}__<tool>`. If a name is under two
        // systems, s1 and a longer s2, then s2 and `s1__` are both prefixes of it, so s2 is
        // `s1_` (it ends in `_`) or begins with `s1__` (it contains `__`). Refusing both leaves
        // every name under one system at most.
        if server.system.contains("__") || server.system.ends_with('_') {
            return Err(RegistryError::SystemOverlaps {
                server: server.name,
                system: server.system,
            });
        }
        require(&server.owner, "owner", place)?;
        require(&server.identity, "identity", place)?;
        require(&server.credential.reference, "credential.reference", place)?;
        require(&server.credential.principal, "credential.principal", place)?;
        let Some(host) = address_host(&server.address) else {
            return Err(RegistryError::AddressNotHttp {
                server: server.name,
                address: server.address,
            });
        };
        if server.identity != host {
            return Err(RegistryError::IdentityNotHost {
                host: host.to_owned(),
                server: server.name,
                identity: server.identity,
            });
        }
        // Plain http only inside the cluster (decision 0013, section 3). Whether the address
        // is one, and TLS for the rest, are checked when the gateway connects.
        if server.address.starts_with("http://") && server.destination != Destination::InCluster {
            return Err(RegistryError::DestinationScheme {
                server: server.name,
                address: server.address,
            });
        }
        let reach = resource_set(server.reach, || {
            format!("the reach of server `{}`", server.name)
        })?;
        let reach_test = match server.reach_test {
            Some(test) => {
                require(&test.record, "reach_test.record", place)?;
                Some(ReachTest {
                    date: date(test.date, "reach_test.date", place)?,
                    record: test.record,
                })
            }
            None => None,
        };
        if !reach.is_empty() && reach_test.is_none() {
            return Err(RegistryError::ReachTestMissing(server.name));
        }
        // Every proxied entry with a reach is checked on a schedule, whatever its narrowing,
        // except a per-user one (decision 0011, section 4).
        if !reach.is_empty()
            && server.credential.mode != CredentialMode::PerUserGrant
            && server.reach_check.is_none()
        {
            return Err(RegistryError::ReachCheckMissing(server.name));
        }
        // The reach check calls one of the entry's own tools: its name must be under the
        // server's system. Whether it is approved is checked against the tools, in `build`.
        if let Some(check) = &server.reach_check
            && !under_system(&check.tool, &server.system)
        {
            return Err(RegistryError::ReachCheckOutsideSystem {
                tool: check.tool.clone(),
                system: server.system,
                server: server.name,
            });
        }
        let probe = match server.probe {
            Some(probe) => Some(Probe {
                result: probe.result,
                date: date(probe.date, "probe.date", place)?,
            }),
            None => None,
        };
        // Registration is the approval pull request, which records a probe the server refused
        // (decision 0013, section 9).
        if probe_rule == ProbeRule::Applied {
            match &probe {
                None => return Err(RegistryError::ProbeMissing(server.name)),
                Some(probe) if probe.result != ProbeResult::Refused => {
                    return Err(RegistryError::ProbeNotRefused {
                        server: server.name,
                        result: probe.result.as_str(),
                    });
                }
                Some(_) => {}
            }
        }
        let checked = Server {
            name: server.name.clone(),
            system: server.system,
            owner: server.owner,
            identity: server.identity,
            address: server.address,
            credential: Credential {
                mode: server.credential.mode,
                reference: server.credential.reference,
                principal: server.credential.principal,
            },
            narrowing: server.narrowing,
            permits: server.permits,
            reach,
            reach_test,
            destination: server.destination,
            probe,
            reach_check: server.reach_check.map(|check| ReachCheck {
                tool: check.tool,
                arguments: check.arguments,
            }),
        };
        let system = checked.system.clone();
        if servers.insert(server.name.clone(), checked).is_some() {
            return Err(RegistryError::DuplicateServer(server.name));
        }
        // Every tool is named `{system}__<tool>` after its server's system, and so is a reach
        // check's tool: a system shared by two servers would let one's names be the other's.
        if let Some(first) = systems.insert(system.clone(), server.name.clone()) {
            return Err(RegistryError::DuplicateSystem {
                system,
                first,
                second: server.name,
            });
        }
    }
    Ok(servers)
}

/// A server's connector entry in the snapshot. Every registered server is proxied.
fn entry(server: &Server) -> ConnectorEntry {
    ConnectorEntry {
        name: server.name.clone(),
        kind: EntryKind::Proxied,
        credential: server.credential.mode,
        principal: server.credential.principal.clone(),
        narrowing: server.narrowing,
        permits: server.permits,
        reach: server.reach.clone(),
        reach_tested_on: server.reach_test.as_ref().map(|test| test.date.clone()),
    }
}

/// `value` as `YYYY-MM-DD`, if it is a plain date: no time and no offset.
fn date(
    value: Datetime,
    field: &'static str,
    place: impl FnOnce() -> String,
) -> Result<String, RegistryError> {
    match value {
        Datetime {
            date: Some(date),
            time: None,
            offset: None,
        } => Ok(date.to_string()),
        _ => Err(RegistryError::NotADate {
            field,
            place: place(),
        }),
    }
}

/// The host in an `http` or `https` address, as written: what follows the scheme, up to the
/// first `/`, `?` or `#`, after any user information and without the port. An IPv6 literal
/// keeps its brackets. `None` when the address has another scheme or no host. The loader
/// requires a server's identity to equal it.
pub fn address_host(address: &str) -> Option<&str> {
    let rest = address
        .strip_prefix("http://")
        .or_else(|| address.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_and_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if host_and_port.starts_with('[') {
        &host_and_port[..=host_and_port.find(']')?]
    } else {
        host_and_port.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then_some(host)
}

struct CheckedTool {
    definition: ToolDefinition,
    adapter: ArgumentAdapter,
    route: Route,
    approval: Approval,
    classification: gateway_core::Classification,
    resources: ResourceDeclaration,
    declared_from: Option<DeclaredFrom>,
    settlement: Option<Settlement>,
}

/// Whether `name` is `{system}__<tool>` for `system`, with something after the separator.
fn under_system(name: &ToolName, system: &str) -> bool {
    name.as_str()
        .strip_prefix(system)
        .and_then(|rest| rest.strip_prefix("__"))
        .is_some_and(|rest| !rest.is_empty())
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
    if !under_system(&name, &server.system) {
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

    check_schema(&name, &tool.input_schema)?;

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
    let computed = binding_sha256(server);
    if computed != tool.binding_sha256 {
        return Err(RegistryError::BindingChanged {
            tool: name,
            server: tool.server,
            recorded: tool.binding_sha256,
            computed,
        });
    }

    let (sources, declared_from) = match tool.resources {
        ResourcesFile::NoResources => (Vec::new(), None),
        // The gateway's one constant adapter names the entry's reach for it, so its argument
        // adapter reads no resources; it still checks the arguments against the schema.
        ResourcesFile::AsReach => (Vec::new(), Some(DeclaredFrom::Reach)),
        ResourcesFile::FromArguments(sources) => (
            sources_from(&name, &tool.input_schema, sources)?,
            Some(DeclaredFrom::Arguments),
        ),
    };
    let adapter = ArgumentAdapter::new(name.clone(), sources, tool.input_schema.clone());
    let resources = match declared_from {
        Some(DeclaredFrom::Reach) => ResourceDeclaration::Declared,
        _ => adapter.declaration(),
    };

    Ok(CheckedTool {
        resources,
        declared_from,
        adapter,
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
            binding_sha256: tool.binding_sha256,
        },
        classification: tool.classification,
        settlement: tool.settlement,
    })
}

/// Checks a tool's input schema: an object schema, in the subset of JSON Schema 2020-12 the
/// argument check follows.
fn check_schema(name: &ToolName, schema: &Value) -> Result<(), RegistryError> {
    if schema.get("type") != Some(&Value::String("object".into())) {
        return Err(RegistryError::SchemaNotObject(name.clone()));
    }
    adapter::followable(schema, &JsonPointer::default()).map_err(|problem| match problem {
        SchemaProblem::Unfollowed { keyword, at } => RegistryError::SchemaUnfollowed {
            tool: name.clone(),
            keyword,
            at,
        },
        SchemaProblem::Malformed { at } => RegistryError::SchemaMalformed {
            tool: name.clone(),
            at,
        },
        SchemaProblem::Dialect { dialect } => RegistryError::SchemaDialect {
            tool: name.clone(),
            dialect,
        },
        SchemaProblem::AdditionalProperties { at } => {
            RegistryError::SchemaAdditionalPropertiesMalformed {
                tool: name.clone(),
                at,
            }
        }
        SchemaProblem::Repeated { name: repeated, at } => RegistryError::SchemaRepeatedName {
            tool: name.clone(),
            name: repeated,
            at,
        },
    })
}

/// The resource sources of a tool that reads its resources from its arguments: at least one,
/// each from a string argument its schema declares at the top level, and qualified, if at all,
/// by another.
fn sources_from(
    name: &ToolName,
    schema: &Value,
    sources: Vec<SourceFile>,
) -> Result<Vec<ResourceSource>, RegistryError> {
    if sources.is_empty() {
        return Err(RegistryError::AdapterWithoutSources(name.clone()));
    }
    let place = || format!("tool `{name}`");
    let properties = schema.get("properties");
    // Whether `argument` is declared, and if so whether as a string.
    let string = |argument: &str| {
        properties
            .and_then(|p| p.get(argument))
            .map(|property| property.get("type") == Some(&Value::String("string".into())))
    };
    let mut checked = Vec::with_capacity(sources.len());
    for source in sources {
        require(&source.system, "resources.system", place)?;
        require(&source.kind, "resources.kind", place)?;
        match string(&source.from_argument) {
            None => {
                return Err(RegistryError::AdapterArgumentUndeclared {
                    tool: name.clone(),
                    argument: source.from_argument,
                });
            }
            Some(false) => {
                return Err(RegistryError::AdapterArgumentNotString {
                    tool: name.clone(),
                    argument: source.from_argument,
                });
            }
            Some(true) => {}
        }
        if let Some(qualifier) = &source.qualified_by
            && string(qualifier) != Some(true)
        {
            return Err(RegistryError::AdapterQualifierNotString {
                tool: name.clone(),
                argument: qualifier.clone(),
            });
        }
        checked.push(ResourceSource {
            from_argument: source.from_argument,
            qualified_by: source.qualified_by,
            system: source.system,
            kind: source.kind,
        });
    }
    Ok(checked)
}

/// Checks a built-in tool's approval against its entry, as [`check_tool`] checks a proxied
/// tool's against its server. Its definition is hashed under its exposed name, since it has no
/// upstream name, and its binding by [`built_in_binding_sha256`]. Its route names its entry and
/// its own name; it carries the entry to the loader and is not kept, since nothing is
/// forwarded.
fn check_built_in_tool(
    tool: BuiltInToolFile,
    connectors: &BTreeMap<ConnectorName, BuiltInEntry>,
) -> Result<CheckedTool, RegistryError> {
    let name = tool.name;
    let place = || format!("built-in tool `{name}`");
    let Some(entry) = connectors.get(&tool.connector) else {
        return Err(RegistryError::UnknownConnector {
            tool: name,
            connector: tool.connector,
        });
    };
    let Some(binding) = built_in_binding_sha256(entry) else {
        return Err(RegistryError::EntryUndeclared {
            tool: name,
            connector: tool.connector,
        });
    };
    if !under_system(&name, &entry.system) {
        return Err(RegistryError::NameOutsideSystem {
            tool: name,
            system: entry.system.clone(),
        });
    }
    if !entry.tools.contains(&name) {
        return Err(RegistryError::BuiltInToolNotListed {
            tool: name,
            connector: tool.connector,
        });
    }
    if entry.reports_reach && tool.classification != gateway_core::Classification::Read {
        return Err(RegistryError::ReachReportEntry {
            connector: tool.connector,
            problem: format!("approves `{name}` as `{}`", tool.classification.as_str()),
        });
    }
    require(&tool.description, "description", place)?;
    require(&tool.approved_by, "approved_by", place)?;
    if let Some(title) = &tool.title {
        require(title, "title", place)?;
    }
    let at = tool.approved_at;
    if at.offset.is_none() {
        return Err(RegistryError::ApprovedAtIncomplete(name));
    }
    check_schema(&name, &tool.input_schema)?;
    let computed = definition_sha256(
        name.as_str(),
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
    if binding != tool.binding_sha256 {
        return Err(RegistryError::BuiltInBindingChanged {
            tool: name,
            connector: tool.connector,
            recorded: tool.binding_sha256,
            computed: binding,
        });
    }
    let (sources, declared_from, resources) = match tool.resources {
        BuiltInResourcesFile::NoResources => (Vec::new(), None, ResourceDeclaration::NoResources),
        BuiltInResourcesFile::AsReach => (
            Vec::new(),
            Some(DeclaredFrom::Reach),
            ResourceDeclaration::Declared,
        ),
        BuiltInResourcesFile::FromArguments(sources) => (
            sources_from(&name, &tool.input_schema, sources)?,
            Some(DeclaredFrom::Arguments),
            ResourceDeclaration::Declared,
        ),
        BuiltInResourcesFile::ChecksOwnScope => {
            (Vec::new(), None, ResourceDeclaration::ChecksOwnScope)
        }
    };
    let adapter = ArgumentAdapter::new(name.clone(), sources, tool.input_schema.clone());
    Ok(CheckedTool {
        resources,
        declared_from,
        adapter,
        definition: ToolDefinition {
            name: name.clone(),
            title: tool.title,
            description: tool.description,
            input_schema: tool.input_schema,
            read_only: tool.classification == gateway_core::Classification::Read,
        },
        route: Route {
            server: tool.connector,
            upstream_name: name.as_str().to_owned(),
        },
        approval: Approval {
            approved_by: tool.approved_by,
            approved_at: at.to_string(),
            definition_sha256: tool.definition_sha256,
            binding_sha256: tool.binding_sha256,
        },
        classification: tool.classification,
        settlement: tool.settlement,
    })
}

fn limit_sets<K: Ord + std::fmt::Display>(
    limits: BTreeMap<K, Vec<ResourceFile>>,
    owner: &str,
) -> Result<BTreeMap<K, BTreeSet<Resource>>, RegistryError> {
    let mut sets = BTreeMap::new();
    for (key, resources) in limits {
        let set = resource_set(resources, || format!("a limit of {owner} `{key}`"))?;
        sets.insert(key, set);
    }
    Ok(sets)
}

/// A limit's or a reach's resources, each with a system, a kind and an identifier.
pub(crate) fn resource_set(
    resources: Vec<ResourceFile>,
    place: impl Fn() -> String,
) -> Result<BTreeSet<Resource>, RegistryError> {
    let mut set = BTreeSet::new();
    for resource in resources {
        require(&resource.system, "system", &place)?;
        require(&resource.kind, "kind", &place)?;
        require(&resource.identifier, "identifier", &place)?;
        set.insert(Resource {
            system: resource.system,
            kind: resource.kind,
            identifier: resource.identifier,
        });
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A tool not classified `read` never loads from a registry, since every server is proxied
    /// (rule 2), so a definition's `read_only` is checked where it is made.
    #[test]
    fn a_definition_is_read_only_exactly_when_its_tool_is_read() {
        let server = Server {
            name: "docs".into(),
            system: "docs".into(),
            owner: "o".into(),
            identity: "h".into(),
            address: "http://h/mcp".into(),
            credential: Credential {
                mode: CredentialMode::GatewayToken,
                reference: "c".into(),
                principal: "p".into(),
            },
            narrowing: Narrowing::None,
            permits: Classification::Read,
            reach: BTreeSet::new(),
            reach_test: None,
            destination: Destination::InCluster,
            probe: None,
            reach_check: None,
        };
        let binding = binding_sha256(&server);
        let definition = definition_sha256("t", None, "d", &serde_json::json!({"type": "object"}));
        let servers = BTreeMap::from([(server.name.clone(), server)]);
        for (classification, read_only) in [
            ("read", true),
            ("propose", false),
            ("write", false),
            ("destructive", false),
        ] {
            let tool: ToolFile = toml::from_str(&format!(
                "name = \"docs__t\"\nserver = \"docs\"\nupstream_name = \"t\"\n\
                 classification = \"{classification}\"\ndescription = \"d\"\n\
                 approved_by = \"a\"\napproved_at = 2026-10-12T00:00:00Z\n\
                 definition_sha256 = \"{definition}\"\nbinding_sha256 = \"{binding}\"\n\
                 resources = \"no_resources\"\ninput_schema = {{ type = \"object\" }}\n"
            ))
            .unwrap();
            let checked = check_tool(tool, &servers).unwrap();
            assert_eq!(checked.definition.read_only, read_only, "{classification}");
        }
    }
}
