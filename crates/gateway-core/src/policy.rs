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
            PrincipalKind::Workload { team } => self.teams.contains(team),
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
    /// The classifications this profile permits. Listing `destructive` here has no effect:
    /// the decision function denies a destructive tool in every profile.
    pub classifications: BTreeSet<Classification>,
    /// Whether a call under this profile must carry a delegation.
    pub requires_delegation: bool,
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
            PrincipalKind::Workload { team } => self
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
}

impl PolicySnapshot {
    /// Checks `data` and builds a snapshot from it.
    ///
    /// Refuses duplicate names rather than letting one silently shadow another, and a surface
    /// that serves a tool nobody approved.
    pub fn new(data: SnapshotData) -> Result<Self, SnapshotError> {
        let mut tools = BTreeMap::new();
        for tool in data.tools {
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
        Ok(Self {
            revision: data.revision,
            tools,
            surfaces,
            profiles,
            limits: data.limits,
        })
    }

    /// The snapshot's revision.
    pub fn revision(&self) -> &PolicyRevision {
        &self.revision
    }

    /// The approved tool with this name, on any surface.
    pub fn tool(&self, name: &ToolName) -> Option<&ApprovedTool> {
        self.tools.get(name)
    }

    /// The surface with this name.
    pub fn surface(&self, name: &SurfaceName) -> Option<&Surface> {
        self.surfaces.get(name)
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
        }
    }

    fn data() -> SnapshotData {
        SnapshotData {
            revision: "r1".into(),
            tools: vec![tool("a__read"), tool("b__read")],
            surfaces: vec![surface("one", &["a__read"]), surface("two", &["b__read"])],
            profiles: vec![profile("p"), profile("q")],
            limits: ResourceLimits::default(),
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
            kind: PrincipalKind::Workload { team: team.into() },
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
