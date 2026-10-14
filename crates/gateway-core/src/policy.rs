//! The policy snapshot: approved tools, surfaces and who may use them, profiles, and resource
//! limits. All of it is data; adding a rule means adding data and table cases, not changing
//! the decision function.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::classification::Classification;
use crate::names::{
    ConnectorName, GroupId, PolicyRevision, ProfileName, SurfaceName, TeamId, ToolName,
};
use crate::principal::{Principal, PrincipalId, PrincipalKind};

/// A tool a person has classified and approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedTool {
    /// The exposed name, `{system}__{tool}`.
    pub name: ToolName,
    /// The tool's classification. Required, with no default: a tool with none cannot be
    /// approved.
    pub classification: Classification,
    /// The connector or proxied server that runs the tool.
    pub connector: ConnectorName,
    /// How the resources a call reaches are known: see [`ResourceDeclaration`].
    pub resources: ResourceDeclaration,
    /// For a tool `declared`, where its adapter finds the resources (decision 0011, section 1).
    /// `None` when the approval does not say, as for the in-process connectors of the JSON
    /// configuration and the tests, which have no connector entry. Set only on a `declared`
    /// tool.
    #[serde(default)]
    pub declared_from: Option<DeclaredFrom>,
}

/// Where a `declared` tool's adapter finds the resources a call reaches (decision 0011,
/// section 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredFrom {
    /// The adapter reads them from structured arguments.
    Arguments,
    /// The adapter names its connector entry's whole recorded reach on every call, whatever
    /// the arguments, as [`Resources::Reach`]. The gateway's one constant adapter does this
    /// for every such tool, and the row records the entry, not the list. The tool's connector
    /// must have an entry.
    Reach,
}

/// A connector entry: one credential for one connector, and what it can reach (decision 0011,
/// section 1). A system reached in two credential modes, or with a service account per team,
/// is several entries. An approved tool's `connector` names its entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorEntry {
    /// The entry's name, which its tools name as their connector.
    pub name: ConnectorName,
    /// Whether the entry is gateway code or someone else's server.
    pub kind: EntryKind,
    /// How the gateway authenticates for this entry.
    pub credential: CredentialMode,
    /// The vendor-side identity the credential acts as, such as a service account's name.
    /// Never the secret.
    pub principal: String,
    /// What the credential is narrowed to on each call.
    pub narrowing: Narrowing,
    /// The highest classification any call made with the credential could have.
    pub permits: Classification,
    /// Every resource the credential and route can reach. Required, with no default: a
    /// missing reach is refused when the data is read, and an empty one says the entry reaches
    /// nothing a limit applies to.
    pub reach: BTreeSet<Resource>,
    /// The date of the recorded test showing a call outside the reach fails, as `YYYY-MM-DD`.
    #[serde(default)]
    pub reach_tested_on: Option<String>,
}

/// Whether a connector entry is gateway code or a proxied server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Someone else's MCP server, which the gateway forwards calls to.
    Proxied,
    /// A connector that is gateway code.
    BuiltIn,
}

/// The mode of a connector entry's one credential (design.md section 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// A service identity of the team the entry serves.
    TeamServiceIdentity,
    /// A token the gateway holds.
    GatewayToken,
    /// Each person's own grant. Not built until milestone 5.
    PerUserGrant,
}

/// What a connector entry's credential is narrowed to on each call (decision 0011, section 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Narrowing {
    /// To the resources the call names.
    Call,
    /// To the caller's limit, as the snapshot holds it.
    Limit,
    /// Not narrowed: every call can reach the entry's whole reach.
    None,
}

/// How a tool's resources are checked. Decision 0006 describes two facts about a tool, whether
/// it declares its resources and whether it checks its own scope when it runs. Of their four
/// combinations, one (neither) could never be allowed when called, and another (a tool that
/// reaches nothing scoped) has to be said explicitly, or a resource adapter that finds nothing
/// would be indistinguishable from one that failed. So the declaration is one of three, and
/// the uncallable combination cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDeclaration {
    /// The tool reaches nothing a resource limit applies to, such as a search of public
    /// documentation. A call names no resources; any it does name are still checked.
    NoResources,
    /// The tool's resource adapter names the resources a call reaches before it runs. Every
    /// named resource must be within the caller's limit, and a call that names none, or whose
    /// resources are unknown, is denied: the adapter failing to find one must not let the call
    /// through.
    Declared,
    /// The tool checks its own scope when it runs, and refuses what is outside it. Its calls
    /// may arrive with unknown resources; any resources that are named are still checked.
    ChecksOwnScope,
}

/// One resource a call names: a system, a kind of thing in it, and which one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// The system, such as `github`.
    pub system: String,
    /// The kind of thing within the system, such as `repository`.
    pub kind: String,
    /// Which one, such as `example-org/payments-api`.
    pub identifier: String,
}

/// The resources a call names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resources {
    /// The resources the tool's resource adapter found in the arguments. Empty when the call
    /// names none, and for `tools/list`.
    Named(Vec<Resource>),
    /// The whole recorded reach of a connector entry, which a tool declared as the reach names
    /// on every call, whatever its arguments (decision 0011, section 1). The decision checks
    /// each of its resources as it checks named ones. The audit row records the entry, not the
    /// list: the policy revision on the row says exactly what the reach was.
    Reach {
        /// The connector entry whose reach this is.
        entry: ConnectorName,
        /// The entry's reach, as the snapshot the decision is made from holds it.
        resources: Vec<Resource>,
    },
    /// The tool cannot say which resources the call names until it runs.
    Unknown,
}

/// A named tool surface: the approved tools one endpoint exposes, and who may use it.
///
/// Who may use a surface is an allowlist, denied by default: a workload whose team is listed,
/// or a user in a listed group. A surface can also be restricted to named principals, which is
/// how actions meant for a control plane are kept away from sandboxes of the same team.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Surface {
    /// The surface's name.
    pub name: SurfaceName,
    /// The approved tools this surface serves.
    pub tools: BTreeSet<ToolName>,
    /// Teams whose workloads may use this surface.
    #[serde(default)]
    pub teams: BTreeSet<TeamId>,
    /// Groups whose users may use this surface.
    #[serde(default)]
    pub groups: BTreeSet<GroupId>,
    /// Whether the surface is further restricted to named principals. Required, with no
    /// default: a dropped field must not read as "unrestricted".
    pub principals: PrincipalRestriction,
}

/// Which principals, among those the team and group allowlist admits, may use a surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRestriction {
    /// Any principal the team and group allowlist admits.
    AnyInTeamsAndGroups,
    /// Only these principals, and only if the allowlist also admits them. Each is an issuer
    /// and a subject, so the same subject from another issuer is not admitted.
    Only(BTreeSet<PrincipalId>),
}

impl Surface {
    /// Whether `principal` may use this surface.
    pub fn permits(&self, principal: &Principal) -> bool {
        let by_team_or_group = match &principal.kind {
            PrincipalKind::Workload { team, .. } => self.teams.contains(team),
            PrincipalKind::User { groups } => !self.groups.is_disjoint(groups),
        };
        let by_principal = match &self.principals {
            PrincipalRestriction::AnyInTeamsAndGroups => true,
            PrincipalRestriction::Only(principals) => principals.contains(&principal.id),
        };
        by_team_or_group && by_principal
    }
}

/// The policy set for one kind of caller, such as Otto's sandboxes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The profile's name.
    pub name: ProfileName,
    /// The classifications this profile permits. Listing `write` or `destructive` here has no
    /// effect: the decision function denies both in every profile, so what a profile can
    /// permit is `read` and `propose`.
    pub classifications: BTreeSet<Classification>,
    /// Whether a call under this profile must carry a delegation.
    pub requires_delegation: bool,
    /// Whether this profile's callers set the `Idempotency-Key` header per request, so the
    /// gateway may take a call's key from it (decision 0009, "The key"). False unless a policy
    /// says so. MCP clients set headers once per server, so a header fixed in a client's
    /// configuration would make every later side effect a reuse of one key; the gateway
    /// ignores the header from a profile that does not declare it, and keys the call as if it
    /// were absent. The decision function does not read this: the request path does, where it
    /// reads the key's carriers.
    #[serde(default)]
    pub idempotency_key_header: bool,
}

/// Which resources each team and group may reach: an allowlist of exact matches on system,
/// kind and identifier. A resource not listed for the caller is outside its limit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Resources a workload of each team may reach.
    #[serde(default)]
    pub teams: BTreeMap<TeamId, BTreeSet<Resource>>,
    /// Resources a user in each group may reach. A user may reach the union of their groups'.
    #[serde(default)]
    pub groups: BTreeMap<GroupId, BTreeSet<Resource>>,
}

impl ResourceLimits {
    /// Whether `resource` is within what `principal` may reach.
    pub fn permits(&self, principal: &Principal, resource: &Resource) -> bool {
        match &principal.kind {
            PrincipalKind::Workload { team, .. } => self
                .teams
                .get(team)
                .is_some_and(|allowed| allowed.contains(resource)),
            PrincipalKind::User { groups } => groups.iter().any(|group| {
                self.groups
                    .get(group)
                    .is_some_and(|allowed| allowed.contains(resource))
            }),
        }
    }
}

/// The policy data as configuration states it, before it is checked. Turn it into a
/// [`PolicySnapshot`] with [`PolicySnapshot::new`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotData {
    /// The snapshot's revision, recorded with every decision made from it.
    pub revision: PolicyRevision,
    /// Every approved tool.
    pub tools: Vec<ApprovedTool>,
    /// Every surface.
    pub surfaces: Vec<Surface>,
    /// Every profile.
    pub profiles: Vec<Profile>,
    /// Resource limits per team and group.
    #[serde(default)]
    pub limits: ResourceLimits,
    /// Every connector entry. Empty for the JSON configuration and the tests, whose
    /// in-process connectors have none; the registry gives every server one. When there are
    /// any, every tool's connector must have one.
    #[serde(default)]
    pub entries: Vec<ConnectorEntry>,
}

/// A team or a group a surface admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// A team, whose workloads the surface admits.
    Team(TeamId),
    /// A group, whose users the surface admits.
    Group(GroupId),
}

impl std::fmt::Display for Admitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Admitted::Team(team) => write!(f, "team `{team}`"),
            Admitted::Group(group) => write!(f, "group `{group}`"),
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{} / {} / {}`", self.system, self.kind, self.identifier)
    }
}

/// Why policy data could not become a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SnapshotError {
    /// Two approved tools share a name, so which one a call means is ambiguous.
    #[error("tool `{0}` is approved more than once")]
    DuplicateTool(ToolName),
    /// Two surfaces share a name.
    #[error("surface `{0}` is defined more than once")]
    DuplicateSurface(SurfaceName),
    /// Two profiles share a name.
    #[error("profile `{0}` is defined more than once")]
    DuplicateProfile(ProfileName),
    /// A surface serves a tool that is not approved.
    #[error("surface `{surface}` serves tool `{tool}`, which is not approved")]
    UnapprovedToolOnSurface {
        /// The surface.
        surface: SurfaceName,
        /// The tool it names.
        tool: ToolName,
    },
    /// Two connector entries share a name.
    #[error("connector entry `{0}` is defined more than once")]
    DuplicateEntry(ConnectorName),
    /// The snapshot has connector entries, and a tool's connector is not one of them, so the
    /// loader's rules could not be checked for it.
    #[error("tool `{tool}` names connector `{connector}`, which has no connector entry")]
    ToolWithoutEntry {
        /// The tool.
        tool: ToolName,
        /// The connector it names.
        connector: ConnectorName,
    },
    /// A tool not `declared` says where its adapter finds resources.
    #[error("tool `{0}` says where its resources are declared from, but is not `declared`")]
    DeclaredFromWithoutDeclared(ToolName),
    /// A tool is `declared` as its entry's reach, and its connector has no entry, so there is
    /// no reach to name.
    #[error(
        "tool `{tool}` is declared as its connector entry's reach, and its connector \
         `{connector}` has no connector entry"
    )]
    ReachWithoutEntry {
        /// The tool.
        tool: ToolName,
        /// The connector it names.
        connector: ConnectorName,
    },
    /// Rule 1 of decision 0011, section 3: a proxied tool declared `checks_own_scope`.
    #[error(
        "rule 1: tool `{tool}` is proxied through entry `{entry}` and declared \
         `checks_own_scope`; a proxied server's scope check is not assurance"
    )]
    ProxiedChecksOwnScope {
        /// The tool.
        tool: ToolName,
        /// Its entry.
        entry: ConnectorName,
    },
    /// Rule 2: a proxied tool classified anything but `read`.
    #[error(
        "rule 2: tool `{tool}` is proxied through entry `{entry}` and classified \
         `{classification}`; a proxied tool must be `read`"
    )]
    ProxiedNotRead {
        /// The tool.
        tool: ToolName,
        /// Its entry.
        entry: ConnectorName,
        /// Its classification.
        classification: Classification,
    },
    /// Rule 3: a proxied entry with a non-empty reach and no recorded test. An entry with no
    /// reach at all is refused when the data is read.
    #[error("rule 3: proxied entry `{entry}` reaches {resource} and has no recorded reach test")]
    ReachUntested {
        /// The entry.
        entry: ConnectorName,
        /// A resource in its reach.
        resource: Box<Resource>,
    },
    /// Rule 4: a proxied entry whose credential permits more than a tool it serves.
    #[error(
        "rule 4: proxied entry `{entry}`'s credential permits `{permits}`, more than tool \
         `{tool}`, which is classified `{classification}`"
    )]
    PermitsMoreThanTool {
        /// The entry.
        entry: ConnectorName,
        /// What its credential permits.
        permits: Classification,
        /// The tool.
        tool: ToolName,
        /// The tool's classification.
        classification: Classification,
    },
    /// Rule 5: a surface admits a team or group whose limit does not hold a resource of the
    /// reach of a tool it serves, where the tool is `declared` as the reach, or is proxied and
    /// its entry narrows `none`.
    #[error(
        "rule 5: surface `{surface}` serves tool `{tool}`, whose entry reaches {resource}, to \
         {admitted}, whose limit does not hold it"
    )]
    ReachOutsideLimit {
        /// The tool.
        tool: ToolName,
        /// The surface.
        surface: SurfaceName,
        /// The team or group the surface admits.
        admitted: Admitted,
        /// The resource of the reach outside its limit.
        resource: Box<Resource>,
    },
    /// Rule 6: a proxied `no_resources` tool whose entry's reach is not empty.
    #[error(
        "rule 6: tool `{tool}` is proxied and declared `no_resources`, but its entry `{entry}` \
         reaches {resource}"
    )]
    NoResourcesWithReach {
        /// The tool.
        tool: ToolName,
        /// Its entry.
        entry: ConnectorName,
        /// A resource in the entry's reach.
        resource: Box<Resource>,
    },
    /// Rule 7: an entry narrowing per `call` serves a tool not `declared` from the arguments.
    #[error(
        "rule 7: entry `{entry}` narrows per call, and serves tool `{tool}`, which is not \
         declared from its arguments"
    )]
    CallNarrowingWithoutArguments {
        /// The entry.
        entry: ConnectorName,
        /// The tool.
        tool: ToolName,
    },
    /// Rule 8: a per-user entry's tool on a surface that admits a team.
    #[error(
        "rule 8: surface `{surface}` serves tool `{tool}`, of per-user entry `{entry}`, to \
         team `{team}`; services never act as a named user"
    )]
    PerUserToTeam {
        /// The tool.
        tool: ToolName,
        /// Its entry.
        entry: ConnectorName,
        /// The surface.
        surface: SurfaceName,
        /// A team the surface admits.
        team: TeamId,
    },
    /// Rule 9: a `propose` tool on a surface that admits a group, and its connector has no
    /// per-user entry: its entry is shared, or it has none.
    #[error(
        "rule 9: surface `{surface}` serves `propose` tool `{tool}` to group `{group}`, and its \
         connector `{connector}` has no per-user entry"
    )]
    ProposeToGroup {
        /// The tool.
        tool: ToolName,
        /// Its connector.
        connector: ConnectorName,
        /// The surface.
        surface: SurfaceName,
        /// A group the surface admits.
        group: GroupId,
    },
}

/// A checked, immutable copy of the policy, which decisions are made from.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "SnapshotData")]
pub struct PolicySnapshot {
    revision: PolicyRevision,
    tools: BTreeMap<ToolName, ApprovedTool>,
    surfaces: BTreeMap<SurfaceName, Surface>,
    profiles: BTreeMap<ProfileName, Profile>,
    limits: ResourceLimits,
    entries: BTreeMap<ConnectorName, ConnectorEntry>,
}

impl PolicySnapshot {
    /// Checks `data` and builds a snapshot from it.
    ///
    /// Refuses duplicate names rather than letting one silently shadow another, and a surface
    /// that serves a tool nobody approved. Then, when there are connector entries, refuses a
    /// tool with no entry. Then it refuses a snapshot that breaks one of the nine rules of
    /// decision 0011, section 3, each named by its [`SnapshotError`] variant. Rules 1 to 8
    /// apply to tools whose connector has an entry, and rule 9 to every tool: one with no entry
    /// is not per-user. Last, it refuses a tool `declared` as the reach whose connector has no
    /// entry, which a snapshot with no entries at all could otherwise hold: there would be no
    /// reach for its calls to name.
    pub fn new(data: SnapshotData) -> Result<Self, SnapshotError> {
        let mut tools = BTreeMap::new();
        for tool in data.tools {
            if tool.declared_from.is_some() && tool.resources != ResourceDeclaration::Declared {
                return Err(SnapshotError::DeclaredFromWithoutDeclared(tool.name));
            }
            if let Some(previous) = tools.insert(tool.name.clone(), tool) {
                return Err(SnapshotError::DuplicateTool(previous.name));
            }
        }
        let mut surfaces = BTreeMap::new();
        for surface in data.surfaces {
            if let Some(tool) = surface.tools.iter().find(|tool| !tools.contains_key(*tool)) {
                return Err(SnapshotError::UnapprovedToolOnSurface {
                    surface: surface.name.clone(),
                    tool: tool.clone(),
                });
            }
            if let Some(previous) = surfaces.insert(surface.name.clone(), surface) {
                return Err(SnapshotError::DuplicateSurface(previous.name));
            }
        }
        let mut profiles = BTreeMap::new();
        for profile in data.profiles {
            if let Some(previous) = profiles.insert(profile.name.clone(), profile) {
                return Err(SnapshotError::DuplicateProfile(previous.name));
            }
        }
        let mut entries = BTreeMap::new();
        for entry in data.entries {
            if let Some(previous) = entries.insert(entry.name.clone(), entry) {
                return Err(SnapshotError::DuplicateEntry(previous.name));
            }
        }
        if !entries.is_empty()
            && let Some(tool) = tools
                .values()
                .find(|tool| !entries.contains_key(&tool.connector))
        {
            return Err(SnapshotError::ToolWithoutEntry {
                tool: tool.name.clone(),
                connector: tool.connector.clone(),
            });
        }
        let snapshot = Self {
            revision: data.revision,
            tools,
            surfaces,
            profiles,
            limits: data.limits,
            entries,
        };
        check_rules(&snapshot)?;
        if let Some(tool) = snapshot.tools.values().find(|tool| {
            tool.declared_from == Some(DeclaredFrom::Reach)
                && !snapshot.entries.contains_key(&tool.connector)
        }) {
            return Err(SnapshotError::ReachWithoutEntry {
                tool: tool.name.clone(),
                connector: tool.connector.clone(),
            });
        }
        Ok(snapshot)
    }

    /// This snapshot with `withdrawn` removed: from the approved tools and from every surface
    /// (decision 0011, section 4). Nothing else changes: not the surfaces' teams and groups,
    /// the profiles, the limits or the connector entries. The result is under `revision`.
    ///
    /// The loader's rules are not run again. A removal can only narrow what is allowed, so an
    /// unrelated change that breaks a rule cannot hold up a withdrawal.
    pub fn without(&self, withdrawn: &BTreeSet<ToolName>, revision: PolicyRevision) -> Self {
        let mut derived = self.clone();
        derived.revision = revision;
        derived.tools.retain(|name, _| !withdrawn.contains(name));
        for surface in derived.surfaces.values_mut() {
            surface.tools.retain(|name| !withdrawn.contains(name));
        }
        derived
    }

    /// The snapshot's revision.
    pub fn revision(&self) -> &PolicyRevision {
        &self.revision
    }

    /// The connector entry with this name.
    pub fn entry(&self, name: &ConnectorName) -> Option<&ConnectorEntry> {
        self.entries.get(name)
    }

    /// Every connector entry, in name order.
    pub fn entries(&self) -> impl Iterator<Item = &ConnectorEntry> {
        self.entries.values()
    }

    /// The approved tool with this name, on any surface.
    pub fn tool(&self, name: &ToolName) -> Option<&ApprovedTool> {
        self.tools.get(name)
    }

    /// The surface with this name.
    pub fn surface(&self, name: &SurfaceName) -> Option<&Surface> {
        self.surfaces.get(name)
    }

    /// Every surface, in name order.
    pub fn surfaces(&self) -> impl Iterator<Item = &Surface> {
        self.surfaces.values()
    }

    /// The profile with this name.
    pub fn profile(&self, name: &ProfileName) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// The resource limits.
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// The approved tool with this name, if `surface` serves it.
    pub fn tool_on_surface(&self, surface: &SurfaceName, name: &ToolName) -> Option<&ApprovedTool> {
        self.surface(surface)
            .filter(|surface| surface.tools.contains(name))
            .and_then(|_| self.tool(name))
    }
}

/// The nine rules of decision 0011, section 3, which say where approvals contradict each other
/// or the limits. Each refusal names the tool, entry, surface, team or group, and resource.
///
/// Rules 1 to 8 apply to tools whose connector has an entry. A snapshot from the JSON
/// configuration or the tests has none, and its in-process connectors are neither proxied nor
/// per-user; a snapshot with entries gives every tool one (see [`PolicySnapshot::new`]). Rule 9
/// allows a `propose` tool on a surface that admits a group only when its entry is per-user,
/// so it applies to every tool: a tool with no entry is not per-user, and is refused there.
///
/// No rule reads which surfaces a tool is on except 5, 8 and 9, which are about who is served.
/// A tool approved but on no surface is still checked against its entry.
fn check_rules(snapshot: &PolicySnapshot) -> Result<(), SnapshotError> {
    for tool in snapshot.tools.values() {
        let Some(entry) = snapshot.entries.get(&tool.connector) else {
            continue;
        };
        let proxied = entry.kind == EntryKind::Proxied;
        // Rule 1: a proxied tool declared `checks_own_scope`.
        if proxied && tool.resources == ResourceDeclaration::ChecksOwnScope {
            return Err(SnapshotError::ProxiedChecksOwnScope {
                tool: tool.name.clone(),
                entry: entry.name.clone(),
            });
        }
        // Rule 2: a proxied tool classified anything but `read`.
        if proxied && tool.classification != Classification::Read {
            return Err(SnapshotError::ProxiedNotRead {
                tool: tool.name.clone(),
                entry: entry.name.clone(),
                classification: tool.classification,
            });
        }
        // Rule 4: a proxied entry whose credential permits more than a tool it serves.
        if proxied && entry.permits > tool.classification {
            return Err(SnapshotError::PermitsMoreThanTool {
                entry: entry.name.clone(),
                permits: entry.permits,
                tool: tool.name.clone(),
                classification: tool.classification,
            });
        }
        // Rule 6: a proxied `no_resources` tool whose entry's reach is not empty.
        if proxied
            && tool.resources == ResourceDeclaration::NoResources
            && let Some(resource) = entry.reach.first()
        {
            return Err(SnapshotError::NoResourcesWithReach {
                tool: tool.name.clone(),
                entry: entry.name.clone(),
                resource: Box::new(resource.clone()),
            });
        }
        // Rule 7: an entry narrowing per call that serves a tool not declared from the
        // arguments.
        if entry.narrowing == Narrowing::Call && tool.declared_from != Some(DeclaredFrom::Arguments)
        {
            return Err(SnapshotError::CallNarrowingWithoutArguments {
                entry: entry.name.clone(),
                tool: tool.name.clone(),
            });
        }
    }
    // Rule 3: a proxied entry with a non-empty reach and no recorded test. With no reach at all
    // it does not parse.
    for entry in snapshot.entries.values() {
        let tested = entry.reach_tested_on.as_deref().is_some_and(is_date);
        if entry.kind == EntryKind::Proxied
            && !tested
            && let Some(resource) = entry.reach.first()
        {
            return Err(SnapshotError::ReachUntested {
                entry: entry.name.clone(),
                resource: Box::new(resource.clone()),
            });
        }
    }
    for surface in snapshot.surfaces.values() {
        for tool in surface
            .tools
            .iter()
            .filter_map(|name| snapshot.tools.get(name))
        {
            let entry = snapshot.entries.get(&tool.connector);
            if let Some(entry) = entry {
                // Rule 5: a team or group admitted to the surface whose limit does not hold the
                // whole reach, where the tool is declared as the reach, or is proxied and its
                // entry narrows `none`.
                let whole_reach = tool.declared_from == Some(DeclaredFrom::Reach)
                    || (entry.kind == EntryKind::Proxied && entry.narrowing == Narrowing::None);
                if whole_reach {
                    reach_within_limits(snapshot, surface, tool, entry)?;
                }
                // Rule 8: a per-user entry's tool on a surface that admits any team.
                if entry.credential == CredentialMode::PerUserGrant
                    && let Some(team) = surface.teams.first()
                {
                    return Err(SnapshotError::PerUserToTeam {
                        tool: tool.name.clone(),
                        entry: entry.name.clone(),
                        surface: surface.name.clone(),
                        team: team.clone(),
                    });
                }
            }
            // Rule 9: a `propose` tool on a surface that admits any group, unless its entry is
            // per-user. A tool with no entry is not per-user.
            let per_user =
                entry.is_some_and(|entry| entry.credential == CredentialMode::PerUserGrant);
            if tool.classification == Classification::Propose
                && !per_user
                && let Some(group) = surface.groups.first()
            {
                return Err(SnapshotError::ProposeToGroup {
                    tool: tool.name.clone(),
                    connector: tool.connector.clone(),
                    surface: surface.name.clone(),
                    group: group.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Rule 5 for one tool on one surface: every team and group the surface admits has the whole
/// reach of the tool's entry in its limit.
fn reach_within_limits(
    snapshot: &PolicySnapshot,
    surface: &Surface,
    tool: &ApprovedTool,
    entry: &ConnectorEntry,
) -> Result<(), SnapshotError> {
    let admitted = surface
        .teams
        .iter()
        .map(|team| {
            (
                Admitted::Team(team.clone()),
                snapshot.limits.teams.get(team),
            )
        })
        .chain(surface.groups.iter().map(|group| {
            (
                Admitted::Group(group.clone()),
                snapshot.limits.groups.get(group),
            )
        }));
    for (admitted, limit) in admitted {
        if let Some(resource) = entry
            .reach
            .iter()
            .find(|resource| !limit.is_some_and(|limit| limit.contains(*resource)))
        {
            return Err(SnapshotError::ReachOutsideLimit {
                tool: tool.name.clone(),
                surface: surface.name.clone(),
                admitted,
                resource: Box::new(resource.clone()),
            });
        }
    }
    Ok(())
}

/// Whether `text` is a date written `YYYY-MM-DD`. Only its shape is checked.
fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

impl TryFrom<SnapshotData> for PolicySnapshot {
    type Error = SnapshotError;

    fn try_from(data: SnapshotData) -> Result<Self, Self::Error> {
        Self::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_name(name: &str) -> ToolName {
        ToolName::parse(name).unwrap()
    }

    fn tool(tool: &str) -> ApprovedTool {
        ApprovedTool {
            name: tool_name(tool),
            classification: Classification::Read,
            connector: "fixture".into(),
            resources: ResourceDeclaration::NoResources,
            declared_from: None,
        }
    }

    fn surface(name: &str, tools: &[&str]) -> Surface {
        Surface {
            name: name.into(),
            tools: tools.iter().map(|&tool| tool_name(tool)).collect(),
            teams: BTreeSet::new(),
            groups: BTreeSet::new(),
            principals: PrincipalRestriction::AnyInTeamsAndGroups,
        }
    }

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.into(),
            classifications: BTreeSet::new(),
            requires_delegation: false,
            idempotency_key_header: false,
        }
    }

    fn data() -> SnapshotData {
        SnapshotData {
            revision: "r1".into(),
            tools: vec![tool("a__read"), tool("b__read")],
            surfaces: vec![surface("one", &["a__read"]), surface("two", &["b__read"])],
            profiles: vec![profile("p"), profile("q")],
            limits: ResourceLimits::default(),
            entries: Vec::new(),
        }
    }

    #[test]
    fn well_formed_data_becomes_a_snapshot() {
        let snapshot = PolicySnapshot::new(data());
        assert!(snapshot.is_ok(), "{snapshot:?}");
    }

    #[test]
    fn a_tool_approved_twice_is_refused() {
        let mut data = data();
        data.tools.push(tool("a__read"));
        assert_eq!(
            PolicySnapshot::new(data),
            Err(SnapshotError::DuplicateTool(tool_name("a__read")))
        );
    }

    #[test]
    fn a_surface_defined_twice_is_refused() {
        let mut data = data();
        data.surfaces.push(surface("one", &[]));
        assert_eq!(
            PolicySnapshot::new(data),
            Err(SnapshotError::DuplicateSurface("one".into()))
        );
    }

    #[test]
    fn a_profile_defined_twice_is_refused() {
        let mut data = data();
        data.profiles.push(profile("q"));
        assert_eq!(
            PolicySnapshot::new(data),
            Err(SnapshotError::DuplicateProfile("q".into()))
        );
    }

    #[test]
    fn a_surface_serving_an_unapproved_tool_is_refused() {
        let mut data = data();
        data.surfaces
            .push(surface("three", &["a__read", "c__unapproved"]));
        assert_eq!(
            PolicySnapshot::new(data),
            Err(SnapshotError::UnapprovedToolOnSurface {
                surface: "three".into(),
                tool: tool_name("c__unapproved"),
            })
        );
    }

    #[test]
    fn without_removes_the_tools_from_the_list_and_every_surface_and_nothing_else() {
        let mut data = data();
        data.surfaces.push(surface("both", &["a__read", "b__read"]));
        data.surfaces[2].teams.insert("alpha".into());
        data.limits = limits();
        let snapshot = PolicySnapshot::new(data).unwrap();
        let derived = snapshot.without(&[tool_name("a__read")].into(), "r1+w".into());
        assert_eq!(derived.revision().as_str(), "r1+w");
        assert!(derived.tool(&tool_name("a__read")).is_none());
        assert!(derived.tool(&tool_name("b__read")).is_some());
        for surface in derived.surfaces() {
            assert!(
                !surface.tools.contains(&tool_name("a__read")),
                "{surface:?}"
            );
        }
        let both = derived.surface(&"both".into()).unwrap();
        assert_eq!(both.tools, [tool_name("b__read")].into());
        assert_eq!(both.teams, ["alpha".into()].into());
        assert_eq!(derived.limits(), snapshot.limits());
        assert_eq!(derived.profiles, snapshot.profiles);
        assert_eq!(derived.entries, snapshot.entries);
        // Withdrawing nothing changes only the revision.
        let same = snapshot.without(&BTreeSet::new(), "r1".into());
        assert_eq!(same, snapshot);
    }

    #[test]
    fn a_date_is_ten_characters_of_digits_and_two_dashes() {
        assert!(is_date("2026-10-12"));
        for text in [
            "",
            "2026-10-1",
            "2026/10/12",
            "2026-10-12T00",
            "yes",
            "2026-1a-12",
        ] {
            assert!(!is_date(text), "{text}");
        }
    }

    const TOOL: &str = r#""name": "a__read", "connector": "fixture""#;

    #[test]
    fn a_tool_with_no_classification_cannot_be_loaded() {
        let json = format!(r#"{{{TOOL}, "resources": "declared"}}"#);
        assert!(serde_json::from_str::<ApprovedTool>(&json).is_err());
    }

    #[test]
    fn a_tool_must_say_how_its_resources_are_known() {
        let parse = |rest: &str| {
            serde_json::from_str::<ApprovedTool>(&format!(
                "{{{TOOL}, \"classification\": \"read\"{rest}}}"
            ))
        };
        assert!(parse(r#", "resources": "declared""#).is_ok());
        assert!(parse(r#", "resources": "checks_own_scope""#).is_ok());
        assert!(parse(r#", "resources": "no_resources""#).is_ok());
        assert!(parse("").is_err(), "a missing declaration was accepted");
        assert!(parse(r#", "resources": null"#).is_err());
        assert!(parse(r#", "resources": "neither""#).is_err());
    }

    #[test]
    fn a_tool_with_an_unknown_field_is_refused() {
        let json = format!(
            r#"{{{TOOL}, "classification": "read", "resources": "declared", "classfication": "write"}}"#
        );
        assert!(serde_json::from_str::<ApprovedTool>(&json).is_err());
    }

    const SURFACE: &str = r#""name": "s", "tools": [], "teams": ["t"]"#;

    #[test]
    fn a_surface_must_say_whether_it_restricts_principals() {
        let parse = |rest: &str| serde_json::from_str::<Surface>(&format!("{{{SURFACE}{rest}}}"));
        let any = parse(r#", "principals": "any_in_teams_and_groups""#).unwrap();
        assert_eq!(any.principals, PrincipalRestriction::AnyInTeamsAndGroups);
        let only = parse(r#", "principals": {"only": [{"issuer": "i", "subject": "s"}]}"#);
        assert!(
            matches!(only.unwrap().principals, PrincipalRestriction::Only(set) if set.len() == 1)
        );
        assert!(
            parse("").is_err(),
            "a missing restriction read as unrestricted"
        );
        assert!(
            parse(r#", "principals": null"#).is_err(),
            "null read as unrestricted"
        );
        assert!(parse(r#", "principals": {"only": null}"#).is_err());
    }

    #[test]
    fn a_surface_with_an_unknown_field_is_refused() {
        let json =
            format!(r#"{{{SURFACE}, "principals": "any_in_teams_and_groups", "subjects": []}}"#);
        assert!(serde_json::from_str::<Surface>(&json).is_err());
    }

    fn resource(system: &str, kind: &str, identifier: &str) -> Resource {
        Resource {
            system: system.into(),
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }

    fn workload(team: &str) -> Principal {
        Principal {
            id: PrincipalId {
                issuer: "i".into(),
                subject: "w".into(),
            },
            kind: PrincipalKind::Workload {
                team: team.into(),
                pod: None,
            },
        }
    }

    fn user(groups: &[&str]) -> Principal {
        Principal {
            id: PrincipalId {
                issuer: "i".into(),
                subject: "u".into(),
            },
            kind: PrincipalKind::User {
                groups: groups.iter().map(|&group| group.into()).collect(),
            },
        }
    }

    /// Team `alpha` and group `alpha` share a name and nothing else.
    fn limits() -> ResourceLimits {
        ResourceLimits {
            teams: [("alpha".into(), [resource("git", "repo", "org/a")].into())].into(),
            groups: [("beta".into(), [resource("git", "repo", "org/b")].into())].into(),
        }
    }

    #[test]
    fn a_limit_is_an_exact_match_on_system_kind_and_identifier() {
        let limits = limits();
        for principal in [workload("alpha")] {
            assert!(limits.permits(&principal, &resource("git", "repo", "org/a")));
            for outside in [
                resource("other", "repo", "org/a"),
                resource("git", "other", "org/a"),
                resource("git", "repo", "org/A"),
                resource("git", "repo", "org/a-two"),
                resource("git", "repo", "org/"),
            ] {
                assert!(!limits.permits(&principal, &outside), "{outside:?}");
            }
        }
        let principal = user(&["beta"]);
        assert!(limits.permits(&principal, &resource("git", "repo", "org/b")));
        for outside in [
            resource("other", "repo", "org/b"),
            resource("git", "other", "org/b"),
            resource("git", "repo", "ORG/B"),
            resource("git", "repo", "org/b-two"),
        ] {
            assert!(!limits.permits(&principal, &outside), "{outside:?}");
        }
    }

    #[test]
    fn a_team_and_a_group_with_the_same_name_do_not_share_limits() {
        let mut limits = limits();
        limits.groups.insert("alpha".into(), BTreeSet::new());
        limits.teams.insert("beta".into(), BTreeSet::new());
        assert!(!limits.permits(&user(&["alpha"]), &resource("git", "repo", "org/a")));
        assert!(!limits.permits(&workload("beta"), &resource("git", "repo", "org/b")));
        limits.groups.remove(&GroupId::from("alpha"));
        limits.teams.remove(&TeamId::from("beta"));
        assert!(!limits.permits(&user(&["alpha"]), &resource("git", "repo", "org/a")));
        assert!(!limits.permits(&workload("beta"), &resource("git", "repo", "org/b")));
    }

    #[test]
    fn a_user_reaches_any_of_their_groups_limits() {
        let limits = limits();
        assert!(limits.permits(
            &user(&["unlisted", "beta"]),
            &resource("git", "repo", "org/b")
        ));
    }

    #[test]
    fn a_team_and_a_group_with_the_same_name_do_not_share_a_surface() {
        let surface = Surface {
            name: "s".into(),
            tools: BTreeSet::new(),
            teams: ["alpha".into()].into(),
            groups: ["beta".into()].into(),
            principals: PrincipalRestriction::AnyInTeamsAndGroups,
        };
        assert!(surface.permits(&workload("alpha")));
        assert!(surface.permits(&user(&["beta"])));
        assert!(!surface.permits(&user(&["alpha"])));
        assert!(!surface.permits(&workload("beta")));
    }
}
