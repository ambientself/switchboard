//! The audit record, the store interface, and the path a call takes through them.
//!
//! # The audited path
//!
//! ```text
//! decide ─▶ Decision ─▶ begin ─┬─▶ AuditGuard ─▶ run ─▶ Ran ─▶ finish ─▶ Finished
//!                              └─▶ Refusal (the denial's sentence)
//! ```
//!
//! Each arrow is a value with private fields that only the step before it can make, and each
//! step consumes what it is given:
//!
//! - A [`Decision`] comes only from [`decide`](crate::decide), and is not `Clone`.
//! - [`begin`] writes the row first. Only if the write succeeds does it return an
//!   [`AuditGuard`] (for an allowed decision) or a [`Refusal`] (for a denied one). The guard
//!   owns the call's arguments; the refusal holds the sentence for the caller, which nothing
//!   else in the crate's public interface can produce. So a call path that skips the row has
//!   no guard to run with and no sentence to answer with.
//! - [`run`] consumes the guard, hands the connector a [`ToolCall`] that only
//!   it can make, and returns a [`Ran`]. One guard runs one call, once.
//! - [`finish`] consumes the `Ran`, completes the row through a [`RowCompletion`] that only it
//!   can make, and only then gives out the answer, including a connector's refusal sentence.
//!   A store's `finish` cannot be called for a denied row, or for a call that never ran.
//!
//! A `tools/list` takes a shorter path. [`listed`] writes a row of kind `list`, complete, and
//! only then returns a [`Listed`]. A `Listed` cannot be made any other way, but the types do not
//! make a path answer from one: the caller already holds the list it passes to `listed`, as
//! [`list_tools`](crate::list_tools) gives it, so writing the row before answering is the
//! path's job and its tests'.
//!
//! What the types cannot establish is that an [`AuditStore`] implementation really wrote the
//! row when it says it did. That is the store's contract, and its own tests'.

use std::collections::BTreeSet;
use std::error::Error;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::classification::Classification;
use crate::connector::{BoxFuture, Connector, ToolCall, ToolOutcome};
use crate::decision::{
    CallContext, CallerContext, Decision, Reason, ReasonKind, ResourceProblem, Verdict,
};
use crate::names::{
    ConnectorName, DeploymentName, InstanceName, Person, PolicyRevision, ProfileName, SurfaceName,
    TeamId, ToolUseId,
};
use crate::policy::{ApprovedTool, Resource, Resources};
use crate::principal::Principal;
use crate::proof::{Claimed, WasProved};
use crate::sentences;

/// The most named resources one audit row records. A call can name any number, so the rest are
/// counted in [`AuditRecord::resources_omitted`] rather than written out.
pub const MAX_RECORDED_RESOURCES: usize = 64;

/// The most tool names one list row records. A surface can serve any number, so the rest are
/// counted in [`ListRecord::tools_omitted`] rather than written out.
pub const MAX_RECORDED_TOOLS: usize = 64;

/// The longest a recorded resource identifier is, in characters after escaping, before it is
/// cut short. An AWS ARN can be 2,048 characters, the longest of the identifier lengths
/// checked in `docs/systems.md`, so each of those is recorded whole. Not every system was
/// checked, and a self-built server's identifiers have no documented bound. A resource's
/// system and kind are capped at 128 characters, like the tool and surface columns.
pub const MAX_RECORDED_IDENTIFIER: usize = 2048;

/// A resource as an audit row records it: each value escaped and possibly cut short. It is a
/// record of what the call named, kept apart from [`Resource`] so that it cannot be checked
/// against a limit or mistaken for the resource that was.
///
/// The escaping is reversible: a backslash is written `\\`, so different values are recorded
/// differently unless they were cut, which ends them with `…`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedResource {
    /// The system, escaped and capped at 128 characters.
    pub system: String,
    /// The kind of thing within the system, escaped and capped at 128 characters.
    pub kind: String,
    /// Which one, escaped and capped at [`MAX_RECORDED_IDENTIFIER`] characters.
    pub identifier: String,
}

/// The resources a call named, as an audit row records them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedResources {
    /// The resources the call named: see [`AuditRecord::resources`].
    Named(Vec<RecordedResource>),
    /// The tool could not say which resources the call names until it ran.
    Unknown,
}

/// Allow or deny, as the audit record's decision column holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// The call was allowed.
    Allow,
    /// The call was denied.
    Deny,
}

/// What a row records: a tool call, or a listing of tools (decision 0009).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowKind {
    /// A `tools/call` that reached a decision. It has a deadline, past which a row with no
    /// outcome reads as open.
    Call,
    /// A `tools/list`, written complete by [`listed`] as a [`ListRecord`]. It has no deadline
    /// and is never open.
    List,
}

/// What happened to an allowed call once it ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Outcome {
    /// The tool ran and succeeded.
    Ok,
    /// The tool ran and failed.
    Error,
    /// The connector refused the call because of what it names, such as a repository outside
    /// the team's scope. The only decision made outside the decision function, and it can only
    /// refuse.
    Refused {
        /// The connector's sentence: exactly the text the caller receives.
        sentence: String,
    },
}

/// The second half of an allowed call's audit row, written after the tool returns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    /// `ok`, `error` or `refused`.
    #[serde(flatten)]
    pub outcome: Outcome,
    /// How long the tool took, measured by the caller of this crate: the core reads no clock.
    pub latency_ms: u64,
}

/// One audit row: one per request that reaches a decision, denials included.
///
/// Proved and claimed values are separate fields of separate types, so they are separate
/// columns and cannot be mixed up on the way to the store. The proved columns are
/// [`WasProved`], so a row can be read back without reading back proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// A call or a listing. [`begin`] makes call rows only.
    pub kind: RowKind,
    /// The gateway instance that began the row, escaped and capped at 128 characters.
    pub instance: InstanceName,
    /// The call deadline of the connector the call names, in milliseconds, as the gateway
    /// supplied it in [`RowStart`]. A store adds its own begin budget and finish deadline to
    /// it for the allowance it gives the database, which sets the row's deadline from its own
    /// clock. The time at begin and the deadline are not fields here: the store sets them.
    pub call_deadline_ms: u64,
    /// The caller's identifier for this tool call, so its control plane can find the row.
    pub tool_use_id: Option<ToolUseId>,
    /// The deployment that received the call.
    pub deployment: DeploymentName,
    /// The surface the call arrived on, made safe: the caller chose it.
    pub surface: SurfaceName,
    /// The profile it was decided under.
    pub profile: ProfileName,
    /// The tool the call named, made safe: the caller chose it, and it may not be a valid
    /// tool name at all. For a valid name this is the name itself.
    pub tool: String,
    /// The connector that runs the tool, if the surface serves it.
    pub connector: Option<ConnectorName>,
    /// The tool's classification, if the surface serves it.
    pub classification: Option<Classification>,
    /// The resources the call named, or `unknown` when the tool could not say before it ran.
    /// The caller chose them, through the arguments, so they are bounded:
    ///
    /// - Each resource once, in the order first named. A repeat is dropped, not counted.
    /// - The first [`MAX_RECORDED_RESOURCES`] of those. When a resource denial names one that
    ///   falls past them, it takes the place of the last, so the resource that caused the
    ///   denial is always recorded.
    /// - Each value escaped and capped, as [`RecordedResource`] says.
    ///
    /// These are what the call named, not what the decision checked. A call denied before the
    /// resource check, or at one resource of several, still records the others it named.
    pub resources: RecordedResources,
    /// How many distinct named resources were left out of `resources`. Zero when none were.
    /// Repeats are not counted.
    pub resources_omitted: usize,
    /// Allow or deny.
    pub decision: DecisionKind,
    /// The kind of reason, for a denial. Unknown tool and tool not on this surface are told
    /// apart here even though the caller reads the same sentence for both.
    pub reason: Option<ReasonKind>,
    /// The denial sentence: exactly the text the caller receives.
    pub sentence: Option<String>,
    /// The revision of the policy snapshot the decision was made from.
    pub policy_revision: PolicyRevision,
    /// The caller, as proved.
    pub proved_principal: WasProved<Principal>,
    /// The team the delegation was issued for, which its signature proves.
    pub proved_delegation_team: Option<WasProved<TeamId>>,
    /// The person the delegation names. Attested, not proved.
    pub claimed_acting_person: Option<Claimed<Person>>,
    /// A team the caller stated, for example in a header.
    pub claimed_team: Option<Claimed<TeamId>>,
    /// The outcome and latency. Empty when the row is begun, and always empty for a denial;
    /// filled by [`finish`]. An allowed row that stays empty is evidence that the gateway
    /// allowed a call and never learned what happened.
    pub completion: Option<Completion>,
}

/// One row of kind `list`: a `tools/list` answer, written complete before the answer goes out
/// (decision 0009). It has no tool, decision, resources, outcome or deadline, and is never
/// open. Made only by [`listed`].
///
/// As in [`AuditRecord`], proved and claimed values are separate fields of separate types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRecord {
    /// The gateway instance that wrote the row, escaped and capped at 128 characters.
    pub instance: InstanceName,
    /// The deployment that received the request.
    pub deployment: DeploymentName,
    /// The surface the request arrived on, made safe: the caller chose it.
    pub surface: SurfaceName,
    /// The profile the list was decided under.
    pub profile: ProfileName,
    /// The revision of the policy snapshot the list was decided from.
    pub policy_revision: PolicyRevision,
    /// The caller, as proved.
    pub proved_principal: WasProved<Principal>,
    /// The team the delegation was issued for, which its signature proves.
    pub proved_delegation_team: Option<WasProved<TeamId>>,
    /// The person the delegation names. Attested, not proved.
    pub claimed_acting_person: Option<Claimed<Person>>,
    /// A team the caller stated, for example in a header.
    pub claimed_team: Option<Claimed<TeamId>>,
    /// The names of the tools the answer lists, in the order it lists them: the first
    /// [`MAX_RECORDED_TOOLS`], each escaped and capped at 128 characters.
    pub tools: Vec<String>,
    /// How many tools the answer lists past the first [`MAX_RECORDED_TOOLS`]. Zero when none.
    pub tools_omitted: usize,
}

/// What the request carried that the decision does not use but the audit record keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMetadata {
    /// The caller's identifier for this tool call.
    pub tool_use_id: Option<ToolUseId>,
    /// A team the caller stated without proof.
    pub claimed_team: Option<Claimed<TeamId>>,
}

/// An audit row's identifier. The gateway chooses it before begin, a UUIDv7 (decision 0009),
/// and gives it to the store with the record, so that begin can be retried without writing a
/// second row. The core reads no clock and makes no identifier: it carries the one it is
/// given. A store may refuse an identifier it cannot hold, as the Postgres store refuses one
/// that is not a UUID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditRowId(String);

impl AuditRowId {
    /// Wraps an identifier the gateway chose.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The identifier as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a store could not write.
pub type StoreError = Box<dyn Error + Send + Sync + 'static>;

/// Where audit rows are written. A Postgres store and an explicit no-op store live in other
/// crates; this crate only states the interface. Usable as `dyn AuditStore`, so one store can
/// sit in shared server state.
pub trait AuditStore: Send + Sync {
    /// Writes `record` as the row `row`, before any tool runs or any denial is returned.
    ///
    /// - The row is durable when begin returns `Ok`, and not before.
    /// - A second begin with an identifier already stored, whose stored decision (allow or
    ///   deny) is the same as `record`'s, returns `Ok` and writes no second row. So begin can
    ///   be retried by identifier.
    /// - A second begin with an identifier already stored, whose stored decision differs,
    ///   returns `Err`, and the stored row stands.
    ///
    /// The comparison stops at the decision on purpose. The Postgres store's role cannot read
    /// who called what, so it cannot compare more, and a store for tests must not check more
    /// than Postgres can: a test would then rely on a check the real store does not make.
    fn begin<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Fills in the outcome and latency of a row that [`begin`](AuditStore::begin) wrote.
    /// Takes a [`RowCompletion`], which only [`finish`] can make, from a
    /// call that ran.
    ///
    /// A repeat of the completion a row already has, the same outcome and latency, returns
    /// `Ok`, so finish can be retried. A different completion of a row already complete
    /// returns `Err`, and the first completion stands.
    fn finish<'a>(&'a self, completion: &'a RowCompletion)
    -> BoxFuture<'a, Result<(), StoreError>>;

    /// Writes `record` as the row `row`, of kind `list`, complete, before the list is
    /// returned. It has no deadline, no completion, and is never open.
    ///
    /// - The row is durable when list returns `Ok`, and not before.
    /// - A second list with an identifier already stored as a row of kind `list` returns `Ok`
    ///   and writes no second row, so list can be retried by identifier. As with begin, nothing
    ///   more is compared.
    /// - A list with an identifier already stored as a row of kind `call` returns `Err`, and
    ///   the stored row stands. So does a begin with an identifier stored as a list row.
    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

/// What the gateway supplies for a row before [`begin`], besides the decision and the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowStart {
    /// The row's identifier, chosen once per call. A retry of begin reuses it.
    pub row: AuditRowId,
    /// The gateway instance beginning the row. The record holds it escaped and capped.
    pub instance: InstanceName,
    /// How long the connector the call names may run, in milliseconds. Recorded so the store
    /// can give the row a deadline that covers the call; the core enforces nothing with it.
    pub call_deadline_ms: u64,
}

/// The completion of one allowed row, for [`AuditStore::finish`]. Made only by [`finish`].
#[derive(Debug)]
pub struct RowCompletion {
    row: AuditRowId,
    completion: Completion,
}

impl RowCompletion {
    /// The row to complete.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// The outcome and latency to write.
    pub fn completion(&self) -> &Completion {
        &self.completion
    }
}

/// Evidence that the audit row for an allowed call was written. Running the tool consumes it.
///
/// Obtainable only from [`begin`]; see the [module documentation](self).
#[must_use = "an allowed call whose guard is dropped never runs, and its row keeps an empty outcome"]
#[derive(Debug)]
pub struct AuditGuard {
    row: AuditRowId,
    call: CallContext,
    tool: ApprovedTool,
    arguments: serde_json::Value,
}

impl AuditGuard {
    /// The row this guard was issued for.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// The call that was decided.
    pub fn call(&self) -> &CallContext {
        &self.call
    }

    /// The approved tool the decision allowed.
    pub fn tool(&self) -> &ApprovedTool {
        &self.tool
    }
}

/// A denial whose audit row has been written: the complete record of the call.
#[derive(Debug)]
pub struct Refusal {
    row: AuditRowId,
    reason: Reason,
    sentence: String,
}

impl Refusal {
    /// The row that records this denial.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// Why the call was denied.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    /// The sentence to return to the caller: the same text the row holds. The only way a
    /// denial's sentence leaves this crate.
    pub fn sentence(&self) -> &str {
        &self.sentence
    }
}

/// A `tools/list` answer whose row has been written. It has private fields and comes only from
/// [`listed`], so a `Listed` cannot be made without the row. Unlike a denial's sentence, which
/// leaves this crate only through [`Refusal`], the list itself does not depend on it: the
/// caller passes `listed` a list it already holds.
#[must_use = "a list whose row was written is answered with its tools"]
#[derive(Debug)]
pub struct Listed {
    row: AuditRowId,
    tools: Vec<ApprovedTool>,
}

impl Listed {
    /// The row that records this list.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// The tools to answer with, in the order the row records them. Every one, including any
    /// past the [`MAX_RECORDED_TOOLS`] the row names.
    pub fn tools(&self) -> &[ApprovedTool] {
        &self.tools
    }
}

/// What [`begin`] returns once the row is written.
#[must_use]
#[derive(Debug)]
pub enum Begun {
    /// The call may run; pass the guard to [`run`].
    Allowed(AuditGuard),
    /// The call is denied; return the refusal's sentence.
    Denied(Refusal),
}

/// An audit row could not be written. At [`begin`] the call is refused, whatever the decision
/// was: audit failure fails closed.
#[derive(Debug, Error)]
#[error("the audit row could not be written: {source}")]
pub struct AuditFailure {
    #[source]
    source: StoreError,
}

impl AuditFailure {
    fn from_store(source: StoreError) -> Self {
        Self { source }
    }

    /// The sentence to return to the caller: distinct from every denial and from the identity
    /// failure, so the caller can tell the gateway failed rather than refused.
    pub fn sentence(&self) -> &'static str {
        sentences::AUDIT_FAILURE
    }
}

/// Writes the audit row for `decision`, as the row `start` names, before anything runs and
/// before any denial is returned.
///
/// Returns [`Begun::Allowed`] with the guard that running the tool requires, which owns
/// `arguments`, or [`Begun::Denied`] with the sentence for the caller. The arguments are not
/// part of the decision or the record, and the core never reads them. If the row cannot be
/// written, returns [`AuditFailure`] and the call must be refused, whatever the decision was.
pub async fn begin(
    store: &dyn AuditStore,
    start: RowStart,
    decision: Decision,
    arguments: serde_json::Value,
    metadata: RequestMetadata,
) -> Result<Begun, AuditFailure> {
    let (call, verdict, policy_revision) = decision.into_parts();
    // The sentence is rendered once, and the same string goes to the row and to the caller.
    let decided = match verdict {
        Verdict::Allow(tool) => Decided::Allow(tool),
        Verdict::Deny { reason, tool } => Decided::Deny {
            sentence: reason.sentence(),
            reason,
            tool,
        },
    };
    let denied_resource = match &decided {
        Decided::Deny {
            reason: Reason::ResourceOutsideLimit(ResourceProblem::Outside { resource, .. }),
            ..
        } => Some(resource),
        _ => None,
    };
    let (resources, resources_omitted) = recorded(&call.resources, denied_resource);
    let (tool, decision, reason, sentence) = match &decided {
        Decided::Allow(tool) => (Some(tool), DecisionKind::Allow, None, None),
        Decided::Deny {
            reason,
            sentence,
            tool,
        } => (
            tool.as_ref(),
            DecisionKind::Deny,
            Some(reason.kind()),
            Some(sentence.clone()),
        ),
    };
    let RowStart {
        row,
        instance,
        call_deadline_ms,
    } = start;
    let record = AuditRecord {
        kind: RowKind::Call,
        instance: InstanceName::new(sentences::escape(
            instance.as_str(),
            sentences::MAX_RENDERED,
        )),
        call_deadline_ms,
        tool_use_id: metadata.tool_use_id,
        deployment: call.caller.deployment.clone(),
        surface: SurfaceName::new(sentences::escape(
            call.caller.surface.as_str(),
            sentences::MAX_RENDERED,
        )),
        profile: call.caller.profile.clone(),
        tool: sentences::escape(call.tool.as_str(), sentences::MAX_RENDERED),
        connector: tool.map(|tool| tool.connector.clone()),
        classification: tool.map(|tool| tool.classification),
        resources,
        resources_omitted,
        decision,
        reason,
        sentence,
        policy_revision,
        proved_principal: call.caller.principal.clone().into(),
        proved_delegation_team: call
            .caller
            .delegation
            .as_ref()
            .map(|delegation| delegation.team().into()),
        claimed_acting_person: call
            .caller
            .delegation
            .as_ref()
            .map(|delegation| delegation.acting_person()),
        claimed_team: metadata.claimed_team,
        completion: None,
    };
    store
        .begin(&row, &record)
        .await
        .map_err(AuditFailure::from_store)?;
    Ok(match decided {
        Decided::Allow(tool) => Begun::Allowed(AuditGuard {
            row,
            call,
            tool,
            arguments,
        }),
        Decided::Deny {
            reason, sentence, ..
        } => Begun::Denied(Refusal {
            row,
            reason,
            sentence,
        }),
    })
}

/// Writes the row of kind `list` for a `tools/list` answer, as the row `start` names, before
/// the list is returned.
///
/// `tools` is the answer, as [`list_tools`](crate::list_tools) gives it for `caller` from the
/// snapshot whose revision is `policy_revision`. `claimed_team` is a team the caller stated.
/// The row names the first [`MAX_RECORDED_TOOLS`] tools, each escaped and capped, and counts
/// the rest. The call deadline in `start` is not used: a list row has no deadline.
///
/// Returns a [`Listed`] holding every tool. If the row cannot be written, returns
/// [`AuditFailure`] and no `Listed`.
pub async fn listed(
    store: &dyn AuditStore,
    start: RowStart,
    caller: &CallerContext,
    policy_revision: PolicyRevision,
    tools: Vec<&ApprovedTool>,
    claimed_team: Option<Claimed<TeamId>>,
) -> Result<Listed, AuditFailure> {
    let RowStart { row, instance, .. } = start;
    let tools_omitted = tools.len().saturating_sub(MAX_RECORDED_TOOLS);
    let record = ListRecord {
        instance: InstanceName::new(sentences::escape(
            instance.as_str(),
            sentences::MAX_RENDERED,
        )),
        deployment: caller.deployment.clone(),
        surface: SurfaceName::new(sentences::escape(
            caller.surface.as_str(),
            sentences::MAX_RENDERED,
        )),
        profile: caller.profile.clone(),
        policy_revision,
        proved_principal: caller.principal.clone().into(),
        proved_delegation_team: caller
            .delegation
            .as_ref()
            .map(|delegation| delegation.team().into()),
        claimed_acting_person: caller
            .delegation
            .as_ref()
            .map(|delegation| delegation.acting_person()),
        claimed_team,
        tools: tools
            .iter()
            .take(MAX_RECORDED_TOOLS)
            .map(|tool| sentences::escape(tool.name.as_str(), sentences::MAX_RENDERED))
            .collect(),
        tools_omitted,
    };
    store
        .list(&row, &record)
        .await
        .map_err(AuditFailure::from_store)?;
    Ok(Listed {
        row,
        tools: tools.into_iter().cloned().collect(),
    })
}

/// The resources as a row records them, and how many distinct ones were left out. See
/// [`AuditRecord::resources`]. `denied` is the resource a resource denial names.
fn recorded(resources: &Resources, denied: Option<&Resource>) -> (RecordedResources, usize) {
    let Resources::Named(named) = resources else {
        return (RecordedResources::Unknown, 0);
    };
    let mut seen = BTreeSet::new();
    let distinct: Vec<&Resource> = named
        .iter()
        .filter(|resource| seen.insert(*resource))
        .collect();
    let mut kept: Vec<&Resource> = distinct
        .iter()
        .copied()
        .take(MAX_RECORDED_RESOURCES)
        .collect();
    if let Some(denied) = denied
        && !kept.contains(&denied)
    {
        kept.truncate(MAX_RECORDED_RESOURCES - 1);
        kept.push(denied);
    }
    let omitted = distinct.len().saturating_sub(kept.len());
    let recorded = kept
        .into_iter()
        .map(|resource| RecordedResource {
            system: sentences::escape(&resource.system, sentences::MAX_RENDERED),
            kind: sentences::escape(&resource.kind, sentences::MAX_RENDERED),
            identifier: sentences::escape(&resource.identifier, MAX_RECORDED_IDENTIFIER),
        })
        .collect();
    (RecordedResources::Named(recorded), omitted)
}

enum Decided {
    Allow(ApprovedTool),
    Deny {
        reason: Reason,
        sentence: String,
        tool: Option<ApprovedTool>,
    },
}

/// A call that ran: what [`finish`] needs. Made only by [`run`].
#[must_use = "a call that ran and is never finished leaves its row's outcome empty"]
#[derive(Debug)]
pub struct Ran {
    row: AuditRowId,
    outcome: ToolOutcome,
}

/// Runs the guarded call on `connector`, consuming the guard.
pub async fn run(connector: &dyn Connector, guard: AuditGuard) -> Ran {
    let AuditGuard {
        row,
        call,
        tool,
        arguments,
    } = guard;
    let outcome = connector.run(ToolCall::new(call, tool, arguments)).await;
    Ran { row, outcome }
}

/// What to answer the caller with, once [`finish`] has tried to complete the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The tool's result.
    Ok(serde_json::Value),
    /// The tool failed; its message.
    Error(String),
    /// The connector refused; its sentence, which the row also holds.
    Refused(String),
    /// The connector refused and the row could not be completed, so the refusal was never
    /// recorded. Nothing ran, so the call fails closed with the audit-failure sentence.
    AuditFailed {
        /// The audit-failure sentence.
        sentence: &'static str,
    },
}

/// The end of an allowed call: the answer, and whether the row could be completed.
#[derive(Debug)]
pub struct Finished {
    answer: Answer,
    failure: Option<AuditFailure>,
}

impl Finished {
    /// What to send the caller.
    pub fn answer(&self) -> &Answer {
        &self.answer
    }

    /// Why the row could not be completed, if it could not. For a tool that ran, the answer
    /// goes out regardless, because withholding the result of a write that already happened
    /// invites a retry; the empty outcome left behind is the evidence.
    pub fn failure(&self) -> Option<&AuditFailure> {
        self.failure.as_ref()
    }
}

/// Completes the row for a call that ran, with its outcome and latency, and only then gives
/// out the answer.
pub async fn finish(store: &dyn AuditStore, ran: Ran, latency_ms: u64) -> Finished {
    let Ran { row, outcome } = ran;
    let (recorded, answer) = match outcome {
        ToolOutcome::Ok(result) => (Outcome::Ok, Answer::Ok(result)),
        ToolOutcome::Error(message) => (Outcome::Error, Answer::Error(message)),
        ToolOutcome::Refused(sentence) => (
            Outcome::Refused {
                sentence: sentence.clone(),
            },
            Answer::Refused(sentence),
        ),
    };
    let completion = RowCompletion {
        row,
        completion: Completion {
            outcome: recorded,
            latency_ms,
        },
    };
    match store.finish(&completion).await {
        Ok(()) => Finished {
            answer,
            failure: None,
        },
        Err(error) => Finished {
            answer: match answer {
                Answer::Refused(_) => Answer::AuditFailed {
                    sentence: sentences::AUDIT_FAILURE,
                },
                ran => ran,
            },
            failure: Some(AuditFailure::from_store(error)),
        },
    }
}
