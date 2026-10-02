//! The audit record, the store interface, and the guard that running a tool requires.
//!
//! # How the guard is enforced
//!
//! [`Connector::run`](crate::Connector::run) takes an [`AuditGuard`] as an argument. An
//! `AuditGuard` has private fields and no public constructor; the only function that returns
//! one is [`begin`], which writes the audit row first and hands out the guard only if the
//! write succeeded and the [`Decision`] allowed the call. A `Decision` in turn can only come
//! from [`decide`](crate::decide). So a call path that skips the audit write has nothing to
//! pass to `run`, and does not compile.
//!
//! The guard carries the decided call and the approved tool, so what runs is the tool the row
//! was written for. It is not `Clone`: one row, one guard. [`finish`] consumes it.
//!
//! A denied decision also goes through [`begin`], which returns a [`Refusal`] holding the
//! sentence for the caller. The sentence is obtainable only after the row is written, which is
//! "a denial still passes through the audit write before the caller reads it".
//!
//! What the types cannot establish is that an [`AuditStore`] implementation really wrote the
//! row when it says it did. That is the store's contract, and its own tests'.

use std::error::Error;
use std::future::Future;

use serde::Serialize;
use thiserror::Error;

use crate::classification::Classification;
use crate::decision::{CallContext, Decision, Reason, ReasonKind, Verdict};
use crate::names::{
    ConnectorName, DeploymentName, Person, PolicyRevision, ProfileName, SurfaceName, TeamId,
    ToolName, ToolUseId,
};
use crate::policy::ApprovedTool;
use crate::principal::Principal;
use crate::proof::{Claimed, Proved};
use crate::sentences;

/// Allow or deny, as the audit record's decision column holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// The call was allowed.
    Allow,
    /// The call was denied.
    Deny,
}

/// What happened to an allowed call once it ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
        /// The connector's sentence, returned to the caller and recorded here.
        sentence: String,
    },
}

/// The second half of an allowed call's audit row, written after the tool returns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
/// columns and cannot be mixed up on the way to the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// The caller's identifier for this tool call, so its control plane can find the row.
    pub tool_use_id: Option<ToolUseId>,
    /// The deployment that received the call.
    pub deployment: DeploymentName,
    /// The surface the call arrived on.
    pub surface: SurfaceName,
    /// The profile it was decided under.
    pub profile: ProfileName,
    /// The tool the call named.
    pub tool: ToolName,
    /// The connector that runs the tool, if the surface serves it.
    pub connector: Option<ConnectorName>,
    /// The tool's classification, if the surface serves it.
    pub classification: Option<Classification>,
    /// Allow or deny.
    pub decision: DecisionKind,
    /// The kind of reason, for a denial.
    pub reason: Option<ReasonKind>,
    /// The denial sentence: exactly the text the caller receives.
    pub sentence: Option<String>,
    /// The revision of the policy snapshot the decision was made from.
    pub policy_revision: PolicyRevision,
    /// The caller, as proved.
    pub proved_principal: Proved<Principal>,
    /// The team the delegation was issued for, which its signature proves.
    pub proved_delegation_team: Option<Proved<TeamId>>,
    /// The person the delegation names. Attested, not proved.
    pub claimed_acting_person: Option<Claimed<Person>>,
    /// A team the caller stated, for example in a header.
    pub claimed_team: Option<Claimed<TeamId>>,
    /// The outcome and latency. Empty when the row is begun; filled by [`finish`]. A row that
    /// stays empty is evidence that the gateway allowed a call and never learned what happened.
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
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

/// Where audit rows are written. A Postgres store and an explicit no-op store live in other
/// crates; this crate only states the interface.
pub trait AuditStore {
    /// Why a write failed.
    type Error: Error + Send + Sync + 'static;

    /// Writes the row before any tool runs or any denial is returned, and returns its
    /// identifier. Must not return `Ok` unless the row is durable.
    fn begin(
        &self,
        record: &AuditRecord,
    ) -> impl Future<Output = Result<AuditRowId, Self::Error>> + Send;

    /// Fills in the outcome and latency of a row that [`begin`](AuditStore::begin) wrote.
    fn finish(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Evidence that the audit row for an allowed call was written. Required to run the tool.
///
/// Obtainable only from [`begin`]; see the [module documentation](self).
#[must_use = "an allowed call whose guard is dropped never runs, and its row keeps an empty outcome"]
#[derive(Debug)]
pub struct AuditGuard {
    row: AuditRowId,
    call: CallContext,
    tool: ApprovedTool,
}

impl AuditGuard {
    /// The row this guard was issued for.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// The call that was decided, for the connector to run.
    pub fn call(&self) -> &CallContext {
        &self.call
    }

    /// The approved tool the decision allowed. The connector runs this tool and no other.
    pub fn tool(&self) -> &ApprovedTool {
        &self.tool
    }
}

/// A denial whose audit row has been written: the complete record of the call. The sentence is
/// what the caller receives.
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

    /// The sentence to return to the caller: the same text the row holds.
    pub fn sentence(&self) -> &str {
        &self.sentence
    }
}

/// What [`begin`] returns once the row is written.
#[must_use]
#[derive(Debug)]
pub enum Begun {
    /// The call may run; pass the guard to the connector.
    Allowed(AuditGuard),
    /// The call is denied; return the refusal's sentence.
    Denied(Refusal),
}

/// The audit row could not be written, so the call is refused. Audit failure fails closed.
#[derive(Debug, Error)]
#[error("the audit row could not be written: {source}")]
pub struct AuditFailure {
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl AuditFailure {
    fn from_store<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self {
            source: Box::new(error),
        }
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
/// Returns [`Begun::Allowed`] with the guard that running the tool requires, or
/// [`Begun::Denied`] with the sentence for the caller. If the row cannot be written, returns
/// [`AuditFailure`] and the call must be refused, whatever the decision was.
pub async fn begin<S>(
    store: &S,
    decision: Decision,
    metadata: RequestMetadata,
) -> Result<Begun, AuditFailure>
where
    S: AuditStore + ?Sized,
{
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
    let record = AuditRecord {
        tool_use_id: metadata.tool_use_id,
        deployment: call.caller.deployment.clone(),
        surface: call.caller.surface.clone(),
        profile: call.caller.profile.name.clone(),
        tool: call.tool.clone(),
        connector: tool.map(|tool| tool.connector.clone()),
        classification: tool.map(|tool| tool.classification),
        decision,
        reason,
        sentence,
        policy_revision,
        proved_principal: call.caller.principal.clone(),
        proved_delegation_team: call
            .caller
            .delegation
            .as_ref()
            .map(|delegation| delegation.team()),
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
        Decided::Allow(tool) => Begun::Allowed(AuditGuard { row, call, tool }),
        Decided::Deny {
            reason, sentence, ..
        } => Begun::Denied(Refusal {
            row,
            reason,
            sentence,
        }),
    })
}

enum Decided {
    Allow(ApprovedTool),
    Deny {
        reason: Reason,
        sentence: String,
        tool: Option<ApprovedTool>,
    },
}

/// Completes the row the guard was issued for, with the outcome and latency.
///
/// Consumes the guard: a row is finished once. If this fails the tool has already run, so the
/// answer still goes to the caller; the empty outcome left behind is the evidence.
pub async fn finish<S>(
    store: &S,
    guard: AuditGuard,
    completion: Completion,
) -> Result<(), AuditFailure>
where
    S: AuditStore + ?Sized,
{
    store
        .finish(&guard.row, &completion)
        .await
        .map_err(AuditFailure::from_store)
}
