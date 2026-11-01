//! The call context, the decision, and the function that turns one into the other.
//!
//! [`decide`] reads the snapshot and the call context and nothing else: no clock, no network,
//! no global state. It first finds the caller's profile in the snapshot, then runs the six
//! checks of decision 0006 in order, with decision 0012's currency check between checks 5 and
//! 6, and then the key check, which its amendment of 2026-10-07 adds last. The first that fails
//! decides the reason. Check 5 lets a `write` tool past only when the calling profile's own
//! list of exceptions names it (decision 0011, section 9), and every later check still runs.
//!
//! A decision does not give out the sentence a caller would read. That sentence exists only on
//! the [`Refusal`](crate::audit::Refusal) that [`audit::begin`](crate::audit::begin) returns
//! once the denial's row is written, so no call path can answer a denial it has not recorded.

// The checks return a `Reason` in their `Err`, which is large because a reason carries the
// principal and resource its sentence names. At most one is built per decision, so boxing it
// would add an allocation to every denial to save a copy on a path that runs once.
#![allow(clippy::result_large_err)]

use serde::{Deserialize, Serialize};

use crate::classification::Classification;
use crate::names::{
    DeploymentName, ExceptionName, PolicyRevision, ProfileName, RequestedTool, SurfaceName,
    TeamId, ToolName,
};
use crate::policy::{
    ApprovedTool, Narrowing, PolicySnapshot, Profile, Resource, ResourceDeclaration,
    ResourceLimits, Resources,
};
use crate::principal::{DelegationFailure, PresentedDelegation, Principal, PrincipalId};
use crate::proof::Proved;
use crate::receipt::IdempotencyKey;
use crate::sentences;

/// The part of a call context that does not depend on which tool is called. `tools/list`
/// decides from this alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerContext {
    /// The proved caller.
    pub principal: Proved<Principal>,
    /// The delegation the request carried, if it carried one, verified or not: so a delegation
    /// is absent, present and verified, or present and unverified. The delegation's verifier
    /// runs before the decision and never denies; check 3 denies an unverified delegation
    /// (decisions 0009 and 0012).
    pub delegation: Option<PresentedDelegation>,
    /// The name of the policy set selected for this caller from its issuer, the deployment and
    /// the principal. The decision looks it up in the snapshot it decides from, so a profile
    /// cannot be supplied from anywhere else.
    pub profile: ProfileName,
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
    /// The tool the call names, exactly as the request named it. Whether it is a valid name,
    /// whether it is approved and on which surfaces is resolved inside [`decide`], so the
    /// classification a decision uses is always the one in the snapshot whose revision it
    /// records.
    pub tool: RequestedTool,
    /// The resources the call names, from the tool's resource adapter.
    pub resources: Resources,
    /// The call's idempotency key, if it carries one (decision 0009, "The key"). The decision
    /// reads only whether there is one: a call of a tool not classified `read` without one is
    /// denied by the key check. [`audit::begin`](crate::audit::begin) takes the key from here,
    /// through the decision, to reserve the call's receipt, so the key the decision saw is the
    /// key the receipt holds.
    pub key: Option<IdempotencyKey>,
    /// Whether the control plane that issued the delegation says the call's turn is current
    /// (decision 0012, "Currency"). An adapter asks only for a tool not classified `read` under
    /// a profile that requires currency; one that does not ask leaves [`Currency::NotAsked`],
    /// which the currency check denies.
    pub currency: Currency,
}

/// The call's currency: whether the control plane that issued its delegation says the turn is
/// current, and if it was asked, what it answered (decision 0012, "Currency").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Currency {
    /// The control plane was asked, and this is the answer.
    Asked(CurrencyAnswer),
    /// Nobody asked. Where the currency check applies, denied as unconfirmed.
    NotAsked,
}

impl Currency {
    /// The answer, if the control plane was asked: what the audit row records.
    pub fn answer(self) -> Option<CurrencyAnswer> {
        match self {
            Currency::Asked(answer) => Some(answer),
            Currency::NotAsked => None,
        }
    }
}

/// What the control plane answered about a turn's currency, or that it gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrencyAnswer {
    /// The control plane that issued the delegation still holds the lease at its epoch, and
    /// the turn has neither ended nor been revoked.
    Current,
    /// Not current: a newer epoch holds the lease.
    Superseded,
    /// Not current: the turn has ended.
    Ended,
    /// Not current: the turn was revoked.
    Revoked,
    /// No answer within the budget, an error, an unknown version, or an answer to another
    /// question.
    Unconfirmed,
}

impl CurrencyAnswer {
    /// Every answer.
    pub const ALL: [CurrencyAnswer; 5] = [
        CurrencyAnswer::Current,
        CurrencyAnswer::Superseded,
        CurrencyAnswer::Ended,
        CurrencyAnswer::Revoked,
        CurrencyAnswer::Unconfirmed,
    ];

    /// The answer's name, as the audit row records it.
    pub fn as_str(self) -> &'static str {
        match self {
            CurrencyAnswer::Current => "current",
            CurrencyAnswer::Superseded => "superseded",
            CurrencyAnswer::Ended => "ended",
            CurrencyAnswer::Revoked => "revoked",
            CurrencyAnswer::Unconfirmed => "unconfirmed",
        }
    }
}

/// Why a call was denied: one of a fixed set of kinds, with the details its sentence names.
///
/// Inspectable, for logging and tests. The sentence a caller reads is not available here: only
/// [`Refusal::sentence`](crate::audit::Refusal::sentence) gives it, once the row is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The snapshot has no profile with the name the caller's context carries.
    ProfileUnknown {
        /// The profile the context named.
        profile: ProfileName,
    },
    /// The tool is not approved on any surface, or the requested name is not a valid tool
    /// name.
    UnknownTool {
        /// The tool the call named, as it named it.
        tool: RequestedTool,
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
    /// This tool is not among the tools the delegation permits.
    ToolNotInDelegation {
        /// The tool the call named.
        tool: ToolName,
    },
    /// The delegation is missing where the profile requires one, or disagrees with the
    /// principal.
    DelegationDisagrees(DelegationProblem),
    /// The request carried a delegation that did not verify (decisions 0009 and 0012). Check 3
    /// denies it, whatever failed, with one fixed sentence that names nothing.
    DelegationUnverified {
        /// Which check the delegation failed: for the row and the logs, never the sentence.
        failure: DelegationFailure,
    },
    /// The profile does not permit the tool's classification. Always the case for a `write`
    /// or `destructive` tool, unless the profile's own list of exceptions names the tool.
    ClassificationNotPermitted {
        /// The tool the call named.
        tool: ToolName,
        /// The tool's classification.
        classification: Classification,
        /// The caller's profile.
        profile: ProfileName,
    },
    /// The profile requires currency, the tool is not classified `read`, and the control plane
    /// that issued the delegation says the turn is not current: superseded, ended or revoked
    /// (decision 0012). The currency check.
    NotCurrent {
        /// The tool the call named.
        tool: ToolName,
        /// The tool's classification, which is not `read`.
        classification: Classification,
    },
    /// The profile requires currency, the tool is not classified `read`, and whether the turn
    /// is current could not be confirmed, or was not asked (decision 0012). The currency check.
    CurrencyUnconfirmed {
        /// The tool the call named.
        tool: ToolName,
        /// The tool's classification, which is not `read`.
        classification: Classification,
    },
    /// A resource the call names is outside what the caller may reach, or the resources the
    /// call reaches are not known well enough to check.
    ResourceOutsideLimit(ResourceProblem),
    /// The tool is not classified `read`, and the call carries no idempotency key (decision
    /// 0009). The key check, last.
    KeyMissing {
        /// The tool the call named.
        tool: ToolName,
        /// The tool's classification, which is not `read`.
        classification: Classification,
    },
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
    /// The resources are unknown, and the tool does not check its own scope.
    Unknown {
        /// The tool the call named.
        tool: ToolName,
    },
    /// The tool declares its resources, and the call named none: the resource adapter found
    /// nothing to check, which must not read as "nothing to check against".
    NoneNamed {
        /// The tool the call named.
        tool: ToolName,
    },
}

/// The kind of a [`Reason`], without its details. This is what the audit record's reason
/// column holds and what the decision table names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    /// See [`Reason::ProfileUnknown`].
    ProfileUnknown,
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
    /// See [`Reason::DelegationUnverified`].
    DelegationUnverified,
    /// See [`Reason::ClassificationNotPermitted`].
    ClassificationNotPermitted,
    /// See [`Reason::NotCurrent`].
    NotCurrent,
    /// See [`Reason::CurrencyUnconfirmed`].
    CurrencyUnconfirmed,
    /// See [`Reason::ResourceOutsideLimit`].
    ResourceOutsideLimit,
    /// See [`Reason::KeyMissing`].
    KeyMissing,
}

impl ReasonKind {
    /// Every kind of reason.
    pub const ALL: [ReasonKind; 12] = [
        ReasonKind::ProfileUnknown,
        ReasonKind::UnknownTool,
        ReasonKind::ToolNotOnSurface,
        ReasonKind::SurfaceNotPermitted,
        ReasonKind::ToolNotInDelegation,
        ReasonKind::DelegationDisagrees,
        ReasonKind::DelegationUnverified,
        ReasonKind::ClassificationNotPermitted,
        ReasonKind::NotCurrent,
        ReasonKind::CurrencyUnconfirmed,
        ReasonKind::ResourceOutsideLimit,
        ReasonKind::KeyMissing,
    ];
}

impl Reason {
    /// This reason's kind.
    pub fn kind(&self) -> ReasonKind {
        match self {
            Reason::ProfileUnknown { .. } => ReasonKind::ProfileUnknown,
            Reason::UnknownTool { .. } => ReasonKind::UnknownTool,
            Reason::ToolNotOnSurface { .. } => ReasonKind::ToolNotOnSurface,
            Reason::SurfaceNotPermitted { .. } => ReasonKind::SurfaceNotPermitted,
            Reason::ToolNotInDelegation { .. } => ReasonKind::ToolNotInDelegation,
            Reason::DelegationDisagrees(_) => ReasonKind::DelegationDisagrees,
            Reason::DelegationUnverified { .. } => ReasonKind::DelegationUnverified,
            Reason::ClassificationNotPermitted { .. } => ReasonKind::ClassificationNotPermitted,
            Reason::NotCurrent { .. } => ReasonKind::NotCurrent,
            Reason::CurrencyUnconfirmed { .. } => ReasonKind::CurrencyUnconfirmed,
            Reason::ResourceOutsideLimit(_) => ReasonKind::ResourceOutsideLimit,
            Reason::KeyMissing { .. } => ReasonKind::KeyMissing,
        }
    }

    /// The sentence for this reason. Crate-private on purpose: outside the crate it is reached
    /// only through [`Refusal::sentence`](crate::audit::Refusal::sentence), after the row is
    /// written.
    pub(crate) fn sentence(&self) -> String {
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

/// The result of [`decide`]: the verdict, the call it was made for, the policy revision it was
/// made from, and, for a call allowed by an exception, which one.
///
/// Only [`decide`] constructs one, so an allowed decision is evidence that the checks ran. The
/// audit begin step consumes it, which ties the audit row, the guard and the tool that runs to
/// this one decision. It is not `Clone`, so one decision begins one row.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    call: CallContext,
    verdict: Verdict,
    policy_revision: PolicyRevision,
    caller_limit: Option<Vec<Resource>>,
    exception: Option<ExceptionName>,
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

    /// The caller's limit, as the snapshot the decision was made from holds it, when the call
    /// is allowed and its tool's connector entry narrows its credential to the caller's limit
    /// (decision 0011, section 1): the connector narrows the call's credential to it. `None`
    /// for a denial, and for a tool whose entry narrows per call or not at all, or that has no
    /// entry.
    pub fn caller_limit(&self) -> Option<&[Resource]> {
        self.caller_limit.as_deref()
    }

    /// The exception in the caller's profile that let the call's `write` tool past check 5
    /// (decision 0011, section 9), when the call is allowed and needed one. `None` for every
    /// denial, a call that passed check 5 by an exception and was then denied included, and for
    /// a call whose tool the profile's classifications permit. The audit row records it.
    pub fn exception(&self) -> Option<&ExceptionName> {
        self.exception.as_ref()
    }

    pub(crate) fn into_parts(self) -> DecisionParts {
        DecisionParts {
            call: self.call,
            verdict: self.verdict,
            policy_revision: self.policy_revision,
            caller_limit: self.caller_limit,
            exception: self.exception,
        }
    }
}

/// A [`Decision`] taken apart by the audit begin step, which consumes it.
pub(crate) struct DecisionParts {
    pub(crate) call: CallContext,
    pub(crate) verdict: Verdict,
    pub(crate) policy_revision: PolicyRevision,
    pub(crate) caller_limit: Option<Vec<Resource>>,
    pub(crate) exception: Option<ExceptionName>,
}

/// What a call that passed every check of [`check`] got past check 5 with: its approved tool,
/// and the exception in the caller's profile that named it, if check 5 needed one.
type Passed<'s> = (&'s ApprovedTool, Option<&'s ExceptionName>);

/// Decides one `tools/call`: every check [`list_tools`] runs, then the currency check and check
/// 6, then the key check, last. A call check 5 let past by an exception goes through all of
/// them too, and its decision names the exception only if it is allowed.
pub fn decide(snapshot: &PolicySnapshot, call: &CallContext) -> Decision {
    let checked = check(
        snapshot,
        &call.caller,
        &call.tool,
        Some(call.currency),
        Some(&call.resources),
    )
    .and_then(|(tool, exception)| {
        key_is_carried(tool, call.key.as_ref()).map(|()| (tool, exception))
    });
    let (verdict, exception) = match checked {
        Ok((tool, exception)) => (Verdict::Allow(tool.clone()), exception.cloned()),
        Err(reason) => (
            Verdict::Deny {
                reason,
                tool: call
                    .tool
                    .name()
                    .ok()
                    .and_then(|name| snapshot.tool_on_surface(&call.caller.surface, &name))
                    .cloned(),
            },
            // A denial names no exception, whichever check denied it.
            None,
        ),
    };
    // Only an allowed call runs, so only its decision carries the limit its credential is
    // narrowed to, read from the same snapshot as the checks.
    let caller_limit = match &verdict {
        Verdict::Allow(tool)
            if snapshot
                .entry(&tool.connector)
                .is_some_and(|entry| entry.narrowing == Narrowing::Limit) =>
        {
            Some(
                snapshot
                    .limits()
                    .of(call.caller.principal.get())
                    .into_iter()
                    .collect(),
            )
        }
        _ => None,
    };
    Decision {
        call: call.clone(),
        verdict,
        policy_revision: snapshot.revision().clone(),
        caller_limit,
        exception,
    }
}

/// Answers `tools/list`: the tools on the caller's surface that pass every check, decided
/// one at a time by the same checks as [`decide`], with no currency, no resources and no key.
/// The currency check, check 6 and the key check are skipped: a list request asks no control
/// plane, names no resources and carries no key, so a `propose` tool is listed to a caller who
/// may call it, and is denied on `tools/call` unless its turn is current and it carries a key.
/// A `write` tool is listed only to callers whose own profile's exceptions name it, as check 5
/// decides a call of it.
pub fn list_tools<'s>(
    snapshot: &'s PolicySnapshot,
    caller: &CallerContext,
) -> Vec<&'s ApprovedTool> {
    let Some(surface) = snapshot.surface(&caller.surface) else {
        return Vec::new();
    };
    surface
        .tools
        .iter()
        .filter_map(|tool| check(snapshot, caller, &tool.clone().into(), None, None).ok())
        .map(|(tool, _)| tool)
        .collect()
}

/// The checks, in order. The order is the contract: a call that fails two checks is reported
/// by the earlier one. Checks 1 to 6 are decision 0006's; the profile lookup comes first
/// because none of them means anything without a profile. Check 5 includes decision 0011's
/// exception step: it returns the exception in the caller's own profile that let a `write`
/// tool past, if it needed one, and nothing returns early on it, so decision 0012's currency
/// check, after check 5 and before check 6, and check 6 still run. The key check is not here:
/// it is last, after check 6, and [`decide`] runs it once these pass.
///
/// `currency` and `resources` are `None` for `tools/list`, which decides with neither, so the
/// currency check and check 6 are skipped for it; for a call they are the call's.
fn check<'s>(
    snapshot: &'s PolicySnapshot,
    caller: &CallerContext,
    tool: &RequestedTool,
    currency: Option<Currency>,
    resources: Option<&Resources>,
) -> Result<Passed<'s>, Reason> {
    let principal = caller.principal.get();
    let profile = profile_is_known(snapshot, &caller.profile)?;
    surface_is_permitted(snapshot, caller, principal)?;
    let tool = tool_is_approved_on_surface(snapshot, &caller.surface, tool)?;
    delegation_agrees(caller, profile, principal)?;
    delegation_lists_tool(caller.delegation.as_ref(), tool)?;
    let exception = classification_is_permitted(profile, tool)?;
    if let Some(currency) = currency {
        control_plane_is_current(profile, tool, currency)?;
    }
    if let Some(resources) = resources {
        resources_are_within_limit(snapshot.limits(), principal, tool, resources)?;
    }
    Ok((tool, exception))
}

/// Check 0. The profile comes from the snapshot the decision is made from, never from the
/// context, so a profile the snapshot does not hold cannot permit anything.
fn profile_is_known<'s>(
    snapshot: &'s PolicySnapshot,
    profile: &ProfileName,
) -> Result<&'s Profile, Reason> {
    snapshot
        .profile(profile)
        .ok_or_else(|| Reason::ProfileUnknown {
            profile: profile.clone(),
        })
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

/// Check 2. A requested name that is not a valid tool name is an unknown tool.
fn tool_is_approved_on_surface<'s>(
    snapshot: &'s PolicySnapshot,
    surface: &SurfaceName,
    requested: &RequestedTool,
) -> Result<&'s ApprovedTool, Reason> {
    let unknown = || Reason::UnknownTool {
        tool: requested.clone(),
        surface: surface.clone(),
    };
    let name = requested.name().map_err(|_| unknown())?;
    if let Some(approved) = snapshot.tool_on_surface(surface, &name) {
        return Ok(approved);
    }
    Err(match snapshot.tool(&name) {
        Some(_) => Reason::ToolNotOnSurface {
            tool: name,
            surface: surface.clone(),
        },
        None => unknown(),
    })
}

/// Check 3. A delegation that is present must agree with the principal even when the profile
/// does not require one: a delegation contradicting the proved team is a sign of something
/// wrong, and ignoring it would let a caller present one only when it narrows nothing.
///
/// A delegation that did not verify is denied here too, whether or not the profile requires
/// one, under a reason kind of its own and one fixed sentence whatever failed (decisions 0009
/// and 0012). A team mismatch is still named: such a delegation verified, and the mismatch is
/// usually a rollout fault.
fn delegation_agrees(
    caller: &CallerContext,
    profile: &Profile,
    principal: &Principal,
) -> Result<(), Reason> {
    let delegation = match &caller.delegation {
        None if profile.requires_delegation => {
            return Err(Reason::DelegationDisagrees(DelegationProblem::Missing {
                profile: profile.name.clone(),
            }));
        }
        None => return Ok(()),
        Some(PresentedDelegation::Unverified(unverified)) => {
            return Err(Reason::DelegationUnverified {
                failure: unverified.failure(),
            });
        }
        Some(PresentedDelegation::Verified(delegation)) => delegation,
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

/// Check 4. A delegation always lists its tools, so one that is present always narrows. One
/// that did not verify lists nothing; check 3 has denied it already.
fn delegation_lists_tool(
    delegation: Option<&PresentedDelegation>,
    tool: &ApprovedTool,
) -> Result<(), Reason> {
    let listed = match delegation {
        None => true,
        Some(PresentedDelegation::Verified(delegation)) => {
            delegation.get().tools.contains(&tool.name)
        }
        Some(PresentedDelegation::Unverified(_)) => false,
    };
    if listed {
        Ok(())
    } else {
        Err(Reason::ToolNotInDelegation {
            tool: tool.name.clone(),
        })
    }
}

/// Check 5. A direct write and a destructive tool are refused whatever classifications the
/// profile lists, so no profile's classifications can permit either. The one way past is
/// decision 0011's exception (section 9): a tool whose exact name the calling profile's own
/// list of exceptions names, never another profile's list, a classification or a part of a
/// name. Then this returns the exception, for the decision to name if the call is allowed. The
/// loader lets a list name only approved `write` tools settled by a lookup, and only on a
/// profile that requires currency, so every call an exception lets past is fenced by the
/// currency check, and still meets check 6 and the key check. Permitting direct writes in
/// general takes a decision record that replaces this part of decision 0006, and a change here.
fn classification_is_permitted<'p>(
    profile: &'p Profile,
    tool: &ApprovedTool,
) -> Result<Option<&'p ExceptionName>, Reason> {
    let denied_everywhere = matches!(
        tool.classification,
        Classification::Write | Classification::Destructive
    );
    let permitted = !denied_everywhere && profile.classifications.contains(&tool.classification);
    if permitted {
        return Ok(None);
    }
    match profile.excepting(&tool.name) {
        Some(exception) => Ok(Some(exception)),
        None => Err(Reason::ClassificationNotPermitted {
            tool: tool.name.clone(),
            classification: tool.classification,
            profile: profile.name.clone(),
        }),
    }
}

/// The currency check (decision 0012), after check 5 and before check 6. Under a profile that
/// requires currency, a call of a tool not classified `read` is allowed only if the control
/// plane that issued its delegation says the turn is current. That covers every such tool, not
/// only `propose`: a `write` tool that decision 0011's exception lets past check 5 is fenced the
/// same way, and the loader lets only a profile that requires currency list one. Not current is denied under its own reason; unconfirmed and not asked are denied
/// as unconfirmed. Run only for a `tools/call`: a list request asks no control plane.
fn control_plane_is_current(
    profile: &Profile,
    tool: &ApprovedTool,
    currency: Currency,
) -> Result<(), Reason> {
    if !profile.requires_currency || tool.classification == Classification::Read {
        return Ok(());
    }
    let (tool, classification) = (tool.name.clone(), tool.classification);
    match currency {
        Currency::Asked(CurrencyAnswer::Current) => Ok(()),
        Currency::Asked(
            CurrencyAnswer::Superseded | CurrencyAnswer::Ended | CurrencyAnswer::Revoked,
        ) => Err(Reason::NotCurrent {
            tool,
            classification,
        }),
        Currency::Asked(CurrencyAnswer::Unconfirmed) | Currency::NotAsked => {
            Err(Reason::CurrencyUnconfirmed {
                tool,
                classification,
            })
        }
    }
}

/// Check 6. Every named resource is checked, whatever the tool declares, so a wrong
/// declaration cannot widen what a call reaches; the declaration only decides what an empty or
/// unknown list means. A connector entry's reach is checked exactly as named resources are.
fn resources_are_within_limit(
    limits: &ResourceLimits,
    principal: &Principal,
    tool: &ApprovedTool,
    resources: &Resources,
) -> Result<(), Reason> {
    let problem = match (resources, tool.resources) {
        (
            Resources::Named(named)
            | Resources::Reach {
                resources: named, ..
            },
            declaration,
        ) => {
            match named
                .iter()
                .find(|resource| !limits.permits(principal, resource))
            {
                Some(outside) => ResourceProblem::Outside {
                    tool: tool.name.clone(),
                    resource: outside.clone(),
                    principal: principal.clone(),
                },
                None if named.is_empty() && declaration == ResourceDeclaration::Declared => {
                    ResourceProblem::NoneNamed {
                        tool: tool.name.clone(),
                    }
                }
                None => return Ok(()),
            }
        }
        (Resources::Unknown, ResourceDeclaration::ChecksOwnScope) => return Ok(()),
        (Resources::Unknown, ResourceDeclaration::Declared | ResourceDeclaration::NoResources) => {
            ResourceProblem::Unknown {
                tool: tool.name.clone(),
            }
        }
    };
    Err(Reason::ResourceOutsideLimit(problem))
}

/// The key check, last (decision 0006, amended on 2026-10-07). A call of a tool not classified
/// `read` must carry an idempotency key, so that a retry of its side effect is answered from
/// its receipt rather than run again. A `read` tool needs none. Run only for a `tools/call`: a
/// list request carries no key.
fn key_is_carried(tool: &ApprovedTool, key: Option<&IdempotencyKey>) -> Result<(), Reason> {
    if tool.classification == Classification::Read || key.is_some() {
        Ok(())
    } else {
        Err(Reason::KeyMissing {
            tool: tool.name.clone(),
            classification: tool.classification,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn tool(classification: Classification) -> ApprovedTool {
        ApprovedTool {
            name: ToolName::parse("sys__tool").unwrap(),
            classification,
            connector: "sys".into(),
            resources: ResourceDeclaration::NoResources,
            declared_from: None,
            settlement: None,
        }
    }

    fn profile(requires_currency: bool) -> Profile {
        Profile {
            name: "profile".into(),
            classifications: Classification::ALL.into_iter().collect::<BTreeSet<_>>(),
            requires_delegation: false,
            requires_currency,
            idempotency_key_header: false,
            exceptions: Vec::new(),
        }
    }

    fn every_currency() -> impl Iterator<Item = Currency> {
        CurrencyAnswer::ALL
            .into_iter()
            .map(Currency::Asked)
            .chain([Currency::NotAsked])
    }

    /// The currency check covers every classification but `read`, `write` and `destructive`
    /// included: decision 0011's exception lets a `write` tool past check 5, which must then
    /// be fenced like a proposal (decision 0012, "Tools and resources").
    #[test]
    fn the_currency_check_fences_every_tool_not_classified_read() {
        for classification in Classification::ALL {
            for currency in every_currency() {
                let checked =
                    control_plane_is_current(&profile(true), &tool(classification), currency)
                        .map_err(|reason| reason.kind());
                let expected = match (classification, currency) {
                    (Classification::Read, _) | (_, Currency::Asked(CurrencyAnswer::Current)) => {
                        Ok(())
                    }
                    (
                        _,
                        Currency::Asked(
                            CurrencyAnswer::Superseded
                            | CurrencyAnswer::Ended
                            | CurrencyAnswer::Revoked,
                        ),
                    ) => Err(ReasonKind::NotCurrent),
                    (_, Currency::Asked(CurrencyAnswer::Unconfirmed) | Currency::NotAsked) => {
                        Err(ReasonKind::CurrencyUnconfirmed)
                    }
                };
                assert_eq!(checked, expected, "{classification} {currency:?}");
            }
        }
    }

    /// A profile that does not require currency is not fenced, whatever the answer.
    #[test]
    fn a_profile_that_does_not_require_currency_is_not_fenced() {
        for classification in Classification::ALL {
            for currency in every_currency() {
                assert_eq!(
                    control_plane_is_current(&profile(false), &tool(classification), currency),
                    Ok(()),
                    "{classification} {currency:?}"
                );
            }
        }
    }

    #[test]
    fn an_answer_is_written_as_its_name() {
        for answer in CurrencyAnswer::ALL {
            assert_eq!(serde_json::to_value(answer).unwrap(), answer.as_str());
            assert_eq!(Currency::Asked(answer).answer(), Some(answer));
        }
        assert_eq!(Currency::NotAsked.answer(), None);
    }
}
