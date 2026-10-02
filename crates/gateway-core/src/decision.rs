//! The call context, the decision, and the function that turns one into the other.
//!
//! [`decide`] reads the snapshot and the call context and nothing else: no clock, no network,
//! no global state. It runs the six checks of decision 0006 in order, and the first that fails
//! decides the reason.

// The checks return a `Reason` in their `Err`, which is large because a reason carries the
// principal and resource its sentence names. At most one is built per decision, so boxing it
// would add an allocation to every denial to save a copy on a path that runs once.
#![allow(clippy::result_large_err)]

use serde::{Deserialize, Serialize};

use crate::classification::Classification;
use crate::names::{DeploymentName, PolicyRevision, ProfileName, SurfaceName, TeamId, ToolName};
use crate::policy::{ApprovedTool, PolicySnapshot, Profile, Resource, ResourceLimits, Resources};
use crate::principal::{Delegation, Principal, PrincipalId};
use crate::proof::Proved;
use crate::sentences;

/// The part of a call context that does not depend on which tool is called. `tools/list`
/// decides from this alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerContext {
    /// The proved caller.
    pub principal: Proved<Principal>,
    /// A verified statement of whom the principal is acting for, if one was presented.
    pub delegation: Option<Proved<Delegation>>,
    /// The policy set selected for this caller from its issuer, the deployment and the
    /// principal. Selection happens before the decision, so the decision never sees a
    /// profile that does not exist.
    pub profile: Profile,
    /// The surface the request arrived on, as the request named it. It may not exist.
    pub surface: SurfaceName,
    /// The deployment that received the call.
    pub deployment: DeploymentName,
}

/// Everything the decision function sees about one `tools/call`.
///
/// The call's arguments are not here. Policy reasons about the resources a call names, so the
/// core never parses a tool's argument format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallContext {
    /// Who is calling, on which surface, under which profile.
    pub caller: CallerContext,
    /// The tool the call names, as the request named it. Whether it is approved, and on which
    /// surfaces, is resolved against the snapshot inside [`decide`], so the classification a
    /// decision uses is always the one in the snapshot whose revision it records.
    pub tool: ToolName,
    /// The resources the call names, from the tool's resource adapter.
    pub resources: Resources,
}

/// Why a call was denied. One of a fixed set of kinds; [`Reason::sentence`] gives the sentence
/// returned to the caller and written to the audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The tool is not approved on any surface.
    UnknownTool {
        /// The tool the call named.
        tool: ToolName,
        /// The surface the call arrived on.
        surface: SurfaceName,
    },
    /// The tool is approved, but this surface does not serve it.
    ToolNotOnSurface {
        /// The tool the call named.
        tool: ToolName,
        /// The surface the call arrived on.
        surface: SurfaceName,
    },
    /// The principal may not use this surface, or the surface does not exist.
    SurfaceNotPermitted {
        /// The surface the call arrived on.
        surface: SurfaceName,
        /// The proved caller.
        principal: Principal,
    },
    /// The delegation lists the tools it permits, and this is not one of them.
    ToolNotInDelegation {
        /// The tool the call named.
        tool: ToolName,
    },
    /// The delegation is missing where the profile requires one, or disagrees with the
    /// principal.
    DelegationDisagrees(DelegationProblem),
    /// The profile does not permit the tool's classification. Always the case for a
    /// destructive tool.
    ClassificationNotPermitted {
        /// The tool the call named.
        tool: ToolName,
        /// The tool's classification.
        classification: Classification,
        /// The caller's profile.
        profile: ProfileName,
    },
    /// A resource the call names is outside what the caller may reach, or the resources are
    /// unknown and the tool does not check its own scope.
    ResourceOutsideLimit(ResourceProblem),
}

/// How a delegation failed check 3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationProblem {
    /// The profile requires a delegation and the call carried none.
    Missing {
        /// The profile that requires one.
        profile: ProfileName,
    },
    /// The delegation was issued for a different team from the principal's.
    TeamMismatch {
        /// The team the principal is proved to belong to.
        proved_team: TeamId,
        /// The team the delegation was issued for.
        delegated_team: TeamId,
    },
    /// The principal is a user, who has no team for a delegation to agree with.
    PrincipalHasNoTeam {
        /// The principal.
        principal: PrincipalId,
        /// The team the delegation was issued for.
        delegated_team: TeamId,
    },
}

/// How a call failed check 6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceProblem {
    /// A named resource is not in the caller's allowlist.
    Outside {
        /// The tool the call named.
        tool: ToolName,
        /// The first resource outside the limit.
        resource: Resource,
        /// The proved caller.
        principal: Principal,
    },
    /// The tool cannot name its resources before it runs, and is not marked as checking its
    /// own scope.
    Unknown {
        /// The tool the call named.
        tool: ToolName,
    },
}

/// The kind of a [`Reason`], without its details. This is what the audit record's reason
/// column holds and what the decision table names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    /// See [`Reason::UnknownTool`].
    UnknownTool,
    /// See [`Reason::ToolNotOnSurface`].
    ToolNotOnSurface,
    /// See [`Reason::SurfaceNotPermitted`].
    SurfaceNotPermitted,
    /// See [`Reason::ToolNotInDelegation`].
    ToolNotInDelegation,
    /// See [`Reason::DelegationDisagrees`].
    DelegationDisagrees,
    /// See [`Reason::ClassificationNotPermitted`].
    ClassificationNotPermitted,
    /// See [`Reason::ResourceOutsideLimit`].
    ResourceOutsideLimit,
}

impl ReasonKind {
    /// Every kind of reason.
    pub const ALL: [ReasonKind; 7] = [
        ReasonKind::UnknownTool,
        ReasonKind::ToolNotOnSurface,
        ReasonKind::SurfaceNotPermitted,
        ReasonKind::ToolNotInDelegation,
        ReasonKind::DelegationDisagrees,
        ReasonKind::ClassificationNotPermitted,
        ReasonKind::ResourceOutsideLimit,
    ];
}

impl Reason {
    /// This reason's kind.
    pub fn kind(&self) -> ReasonKind {
        match self {
            Reason::UnknownTool { .. } => ReasonKind::UnknownTool,
            Reason::ToolNotOnSurface { .. } => ReasonKind::ToolNotOnSurface,
            Reason::SurfaceNotPermitted { .. } => ReasonKind::SurfaceNotPermitted,
            Reason::ToolNotInDelegation { .. } => ReasonKind::ToolNotInDelegation,
            Reason::DelegationDisagrees(_) => ReasonKind::DelegationDisagrees,
            Reason::ClassificationNotPermitted { .. } => ReasonKind::ClassificationNotPermitted,
            Reason::ResourceOutsideLimit(_) => ReasonKind::ResourceOutsideLimit,
        }
    }

    /// The sentence for this reason: the text returned to the caller and written to the audit
    /// record. The wording lives in [`sentences`](crate::sentences).
    pub fn sentence(&self) -> String {
        sentences::render(self)
    }
}

/// Allow, or deny with a reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The call may run this approved tool.
    Allow(ApprovedTool),
    /// The call is denied.
    Deny {
        /// Why: the first check that failed.
        reason: Reason,
        /// The approved tool the call named, if the surface serves it, for the audit record.
        tool: Option<ApprovedTool>,
    },
}

/// The result of [`decide`]: the verdict, the call it was made for, and the policy revision it
/// was made from.
///
/// Only [`decide`] constructs one, so an allowed decision is evidence that the checks ran. The
/// audit begin step consumes it, which ties the audit row, the guard and the tool that runs to
/// this one decision. It is not `Clone`, so one decision begins one row.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    call: CallContext,
    verdict: Verdict,
    policy_revision: PolicyRevision,
}

impl Decision {
    /// The call context the decision was made for.
    pub fn call(&self) -> &CallContext {
        &self.call
    }

    /// Allow or deny.
    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// The revision of the snapshot the decision was made from.
    pub fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Whether the call is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self.verdict, Verdict::Allow(_))
    }

    /// The reason, if the call is denied.
    pub fn reason(&self) -> Option<&Reason> {
        match &self.verdict {
            Verdict::Allow(_) => None,
            Verdict::Deny { reason, .. } => Some(reason),
        }
    }

    /// The approved tool the call named, if the surface serves it.
    pub fn tool(&self) -> Option<&ApprovedTool> {
        match &self.verdict {
            Verdict::Allow(tool) => Some(tool),
            Verdict::Deny { tool, .. } => tool.as_ref(),
        }
    }

    pub(crate) fn into_parts(self) -> (CallContext, Verdict, PolicyRevision) {
        (self.call, self.verdict, self.policy_revision)
    }
}

/// Decides one `tools/call`.
pub fn decide(snapshot: &PolicySnapshot, call: &CallContext) -> Decision {
    let verdict = match check(snapshot, &call.caller, &call.tool, &call.resources) {
        Ok(tool) => Verdict::Allow(tool.clone()),
        Err(reason) => Verdict::Deny {
            reason,
            tool: snapshot
                .tool_on_surface(&call.caller.surface, &call.tool)
                .cloned(),
        },
    };
    Decision {
        call: call.clone(),
        verdict,
        policy_revision: snapshot.revision().clone(),
    }
}

/// Answers `tools/list`: the tools on the caller's surface that pass every check, decided
/// one at a time by the same checks as [`decide`], with no resources.
pub fn list_tools<'s>(
    snapshot: &'s PolicySnapshot,
    caller: &CallerContext,
) -> Vec<&'s ApprovedTool> {
    let Some(surface) = snapshot.surface(&caller.surface) else {
        return Vec::new();
    };
    let no_resources = Resources::Named(Vec::new());
    surface
        .tools
        .iter()
        .filter_map(|tool| check(snapshot, caller, tool, &no_resources).ok())
        .collect()
}

/// The six checks, in the order decision 0006 states. The order is the contract: a call that
/// fails two checks is reported by the earlier one.
fn check<'s>(
    snapshot: &'s PolicySnapshot,
    caller: &CallerContext,
    tool: &ToolName,
    resources: &Resources,
) -> Result<&'s ApprovedTool, Reason> {
    let principal = caller.principal.get();
    surface_is_permitted(snapshot, caller, principal)?;
    let tool = tool_is_approved_on_surface(snapshot, &caller.surface, tool)?;
    delegation_agrees(caller, principal)?;
    delegation_lists_tool(caller.delegation.as_ref(), tool)?;
    classification_is_permitted(&caller.profile, tool)?;
    resources_are_within_limit(snapshot.limits(), principal, tool, resources)?;
    Ok(tool)
}

/// Check 1. A surface that does not exist is reported the same way as one the principal may
/// not use, so the answer does not reveal which surfaces exist.
fn surface_is_permitted(
    snapshot: &PolicySnapshot,
    caller: &CallerContext,
    principal: &Principal,
) -> Result<(), Reason> {
    match snapshot.surface(&caller.surface) {
        Some(surface) if surface.permits(principal) => Ok(()),
        _ => Err(Reason::SurfaceNotPermitted {
            surface: caller.surface.clone(),
            principal: principal.clone(),
        }),
    }
}

/// Check 2.
fn tool_is_approved_on_surface<'s>(
    snapshot: &'s PolicySnapshot,
    surface: &SurfaceName,
    tool: &ToolName,
) -> Result<&'s ApprovedTool, Reason> {
    if let Some(approved) = snapshot.tool_on_surface(surface, tool) {
        return Ok(approved);
    }
    let (tool, surface) = (tool.clone(), surface.clone());
    Err(match snapshot.tool(&tool) {
        Some(_) => Reason::ToolNotOnSurface { tool, surface },
        None => Reason::UnknownTool { tool, surface },
    })
}

/// Check 3. A delegation that is present must agree with the principal even when the profile
/// does not require one: a delegation contradicting the proved team is a sign of something
/// wrong, and ignoring it would let a caller present one only when it narrows nothing.
fn delegation_agrees(caller: &CallerContext, principal: &Principal) -> Result<(), Reason> {
    let Some(delegation) = &caller.delegation else {
        return if caller.profile.requires_delegation {
            Err(Reason::DelegationDisagrees(DelegationProblem::Missing {
                profile: caller.profile.name.clone(),
            }))
        } else {
            Ok(())
        };
    };
    let delegated_team = &delegation.get().team;
    match principal.team() {
        Some(proved_team) if proved_team == delegated_team => Ok(()),
        Some(proved_team) => Err(Reason::DelegationDisagrees(
            DelegationProblem::TeamMismatch {
                proved_team: proved_team.clone(),
                delegated_team: delegated_team.clone(),
            },
        )),
        None => Err(Reason::DelegationDisagrees(
            DelegationProblem::PrincipalHasNoTeam {
                principal: principal.id.clone(),
                delegated_team: delegated_team.clone(),
            },
        )),
    }
}

/// Check 4.
fn delegation_lists_tool(
    delegation: Option<&Proved<Delegation>>,
    tool: &ApprovedTool,
) -> Result<(), Reason> {
    match delegation.and_then(|delegation| delegation.get().tools.as_ref()) {
        Some(permitted) if !permitted.contains(&tool.name) => Err(Reason::ToolNotInDelegation {
            tool: tool.name.clone(),
        }),
        _ => Ok(()),
    }
}

/// Check 5. Destructive is refused before the profile is consulted, so no profile data can
/// permit it.
fn classification_is_permitted(profile: &Profile, tool: &ApprovedTool) -> Result<(), Reason> {
    let permitted = tool.classification != Classification::Destructive
        && profile.classifications.contains(&tool.classification);
    if permitted {
        Ok(())
    } else {
        Err(Reason::ClassificationNotPermitted {
            tool: tool.name.clone(),
            classification: tool.classification,
            profile: profile.name.clone(),
        })
    }
}

/// Check 6.
fn resources_are_within_limit(
    limits: &ResourceLimits,
    principal: &Principal,
    tool: &ApprovedTool,
    resources: &Resources,
) -> Result<(), Reason> {
    match resources {
        Resources::Named(named) => match named
            .iter()
            .find(|resource| !limits.permits(principal, resource))
        {
            Some(outside) => Err(Reason::ResourceOutsideLimit(ResourceProblem::Outside {
                tool: tool.name.clone(),
                resource: outside.clone(),
                principal: principal.clone(),
            })),
            None => Ok(()),
        },
        Resources::Unknown if tool.checks_own_scope => Ok(()),
        Resources::Unknown => Err(Reason::ResourceOutsideLimit(ResourceProblem::Unknown {
            tool: tool.name.clone(),
        })),
    }
}
