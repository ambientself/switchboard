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
    /// Whether the tool's resource adapter can name the resources a call touches before it
    /// runs.
    ///
    /// The resource adapter reads this, not the decision function: the decision function
    /// checks whatever resources the call context names, so a wrong declaration cannot widen
    /// what a call may reach.
    pub declares_resources: bool,
    /// Whether the tool checks its own scope when it runs, and refuses what is outside it. Only
    /// such a tool may be called when the resources a call names are unknown.
    pub checks_own_scope: bool,
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
    /// If present, only these principals may use the surface, in addition to the team and
    /// group allowlist. Absent means no restriction by principal.
    #[serde(default)]
    pub subjects: Option<BTreeSet<PrincipalId>>,
}

impl Surface {
    /// Whether `principal` may use this surface.
    pub fn permits(&self, principal: &Principal) -> bool {
        let by_team_or_group = match &principal.kind {
            PrincipalKind::Workload { team } => self.teams.contains(team),
            PrincipalKind::User { groups } => !self.groups.is_disjoint(groups),
        };
        let by_subject = self
            .subjects
            .as_ref()
            .is_none_or(|subjects| subjects.contains(&principal.id));
        by_team_or_group && by_subject
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

    fn tool(name: &str) -> ApprovedTool {
        ApprovedTool {
            name: name.into(),
            classification: Classification::Read,
            connector: "fixture".into(),
            declares_resources: false,
            checks_own_scope: false,
        }
    }

    fn surface(name: &str, tools: &[&str]) -> Surface {
        Surface {
            name: name.into(),
            tools: tools.iter().map(|&tool| tool.into()).collect(),
            teams: BTreeSet::new(),
            groups: BTreeSet::new(),
            subjects: None,
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
            Err(SnapshotError::DuplicateTool("a__read".into()))
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
                tool: "c__unapproved".into(),
            })
        );
    }

    #[test]
    fn a_tool_with_no_classification_cannot_be_loaded() {
        let json = r#"{"name": "a__read", "connector": "fixture",
                       "declares_resources": false, "checks_own_scope": false}"#;
        assert!(serde_json::from_str::<ApprovedTool>(json).is_err());
    }
}
