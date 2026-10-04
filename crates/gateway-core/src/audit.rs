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
//! What the types cannot establish is that an [`AuditStore`] implementation really wrote the
//! row when it says it did. That is the store's contract, and its own tests'.

use std::error::Error;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::classification::Classification;
use crate::connector::{BoxFuture, Connector, ToolCall, ToolOutcome};
use crate::decision::{CallContext, Decision, Reason, ReasonKind, Verdict};
use crate::names::{
    ConnectorName, DeploymentName, Person, PolicyRevision, ProfileName, SurfaceName, TeamId,
    ToolUseId,
};
use crate::policy::{ApprovedTool, Resource, Resources};
use crate::principal::Principal;
use crate::proof::{Claimed, WasProved};
use crate::sentences;

/// The most named resources one audit row records. A call can name any number, so the rest are
/// counted in [`AuditRecord::resources_omitted`] rather than written out.
pub const MAX_RECORDED_RESOURCES: usize = 64;

/// Allow or deny, as the audit record's decision column holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// The call was allowed.
    Allow,
    /// The call was denied.
    Deny,
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
    /// The resources the call named, as the decision checked them, or `unknown` when the tool
    /// could not say before it ran. Made safe, in the order named, and at most
    /// [`MAX_RECORDED_RESOURCES`] of them: the caller chose them, through the arguments. The
    /// one a resource denial names is always in the row's sentence, even if it was left out
    /// here.
    pub resources: Resources,
    /// How many named resources were left out of `resources` because the call named more than
    /// [`MAX_RECORDED_RESOURCES`]. Zero when none were.
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

/// What the request carried that the decision does not use but the audit record keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestMetadata {
    /// The caller's identifier for this tool call.
    pub tool_use_id: Option<ToolUseId>,
    /// A team the caller stated without proof.
    pub claimed_team: Option<Claimed<TeamId>>,
}

/// The store's identifier for an audit row.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditRowId(String);

impl AuditRowId {
    /// Wraps the identifier a store assigned.
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
    /// Writes the row before any tool runs or any denial is returned, and returns its
    /// identifier. Must not return `Ok` unless the row is durable.
    fn begin<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>>;

    /// Fills in the outcome and latency of a row that [`begin`](AuditStore::begin) wrote.
    /// Takes a [`RowCompletion`], which only [`finish`] can make, from a
    /// call that ran.
    fn finish<'a>(&'a self, completion: &'a RowCompletion)
    -> BoxFuture<'a, Result<(), StoreError>>;
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

/// Writes the audit row for `decision`, before anything runs and before any denial is
/// returned.
///
/// Returns [`Begun::Allowed`] with the guard that running the tool requires, which owns
/// `arguments`, or [`Begun::Denied`] with the sentence for the caller. The arguments are not
/// part of the decision or the record, and the core never reads them. If the row cannot be
/// written, returns [`AuditFailure`] and the call must be refused, whatever the decision was.
pub async fn begin(
    store: &dyn AuditStore,
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
    let (resources, resources_omitted) = recorded(&call.resources);
    let record = AuditRecord {
        tool_use_id: metadata.tool_use_id,
        deployment: call.caller.deployment.clone(),
        surface: SurfaceName::new(sentences::safe(
            call.caller.surface.as_str(),
            sentences::MAX_RENDERED,
        )),
        profile: call.caller.profile.clone(),
        tool: sentences::safe(call.tool.as_str(), sentences::MAX_RENDERED),
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
    let row = store
        .begin(&record)
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

/// The resources as a row records them, and how many were left out: each value made safe, in
/// the order named, and no more than [`MAX_RECORDED_RESOURCES`].
fn recorded(resources: &Resources) -> (Resources, usize) {
    let Resources::Named(named) = resources else {
        return (Resources::Unknown, 0);
    };
    let safe = |text: &str| sentences::safe(text, sentences::MAX_RENDERED);
    let kept = named
        .iter()
        .take(MAX_RECORDED_RESOURCES)
        .map(|resource| Resource {
            system: safe(&resource.system),
            kind: safe(&resource.kind),
            identifier: safe(&resource.identifier),
        })
        .collect();
    let omitted = named.len().saturating_sub(MAX_RECORDED_RESOURCES);
    (Resources::Named(kept), omitted)
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
