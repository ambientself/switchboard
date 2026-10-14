//! The audit record, the store interface, and the path a call takes through them.
//!
//! # The audited path
//!
//! ```text
//! decide ─▶ Decision ─▶ begin ─┬─▶ AuditGuard ─┬─▶ run ─▶ Ran ─▶ finish ─▶ Finished
//!                              │               └─▶ give_up ─▶ GaveUp (the row as error)
//!                              ├─▶ Refusal (the denial's sentence)
//!                              └─▶ Reused (the answer to a reused key; nothing runs)
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
//! - For an allowed call of a tool not classified `read`, a side effect, [`begin`] asks the
//!   store to reserve a receipt in the same write as the row
//!   ([`AuditStore::begin_with_receipt`]). If the call's key already has a receipt in its
//!   scope, the store writes the row already complete instead, and `begin` returns a
//!   [`Reused`]: the answer to the reused key, and no guard (decision 0009, "Reuse"). A denial
//!   reserves nothing.
//! - [`run`] consumes the guard, hands the connector a [`ToolCall`] that only
//!   it can make, and returns a [`Ran`]. One guard runs one call, once. [`run_unless`] does the
//!   same, except that a read whose caller goes away is cancelled and recorded as `error`.
//! - [`finish`] consumes the `Ran`, completes the row through a [`RowCompletion`] that only it
//!   and `give_up` can make, and only then gives out the answer, including a connector's
//!   refusal sentence. A side effect's receipt is settled in the same write, unless the row's
//!   deadline has passed by the store's clock, when the row is completed and the receipt stays
//!   `pending` for reconciliation or a person.
//! - [`give_up`] consumes a guard instead of running it, calls no connector, and completes the
//!   row as `error` with a latency of zero. It returns a [`GaveUp`], which holds no answer:
//!   nothing ran, so the caller chooses its own reply.
//!
//! So a store's `finish` cannot be called for a denied row, and is called for an allowed row
//! only with the outcome of its call or, for a guard given up, as `error`. A guard cannot be
//! both run and given up.
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
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::classification::Classification;
pub use crate::connector::ErrorKind;
use crate::connector::{BoxFuture, Connector, ToolCall, ToolOutcome};
use crate::decision::{
    CallContext, CallerContext, Decision, Reason, ReasonKind, ResourceProblem, Verdict,
};
use crate::names::{
    ConnectorName, DeploymentName, InstanceName, Person, PolicyRevision, ProfileName, SurfaceName,
    TeamId, ToolUseId,
};
use crate::policy::{
    ApprovedTool, ConnectorEntry, CredentialMode, PolicySnapshot, Resource, Resources,
};
use crate::principal::Principal;
use crate::proof::{Claimed, WasProved};
use crate::receipt::{
    ArgumentDigest, KeyScope, ReceiptRequest, Reservation, Reuse, VendorReference,
};
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
    /// The whole reach of this connector entry, which the tool, declared as the reach, named
    /// on every call (decision 0011, section 1). Recorded by reference, not as a list: a reach
    /// can hold more resources than a row keeps, and the row's policy revision says exactly
    /// what it was.
    Reach(ConnectorName),
    /// The tool could not say which resources the call names until it ran.
    Unknown,
}

/// The credential identity a row records: the configured identity of the tool's connector
/// entry, recorded at begin (decisions 0011 and 0014). It is what the entry states, its
/// credential's mode and the vendor-side principal that credential acts as, never the secret,
/// and not what the credential layer reports while the call runs. An entry has one credential
/// and no fallback, so this is the identity the call runs under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIdentity {
    /// The entry's credential mode.
    pub mode: CredentialMode,
    /// The vendor-side identity the entry's credential acts as, such as a service account's
    /// name, as the entry states it.
    pub principal: String,
}

impl CredentialIdentity {
    /// The identity `entry` states. It has no secret to copy: an entry holds none.
    pub fn of(entry: &ConnectorEntry) -> Self {
        Self {
            mode: entry.credential,
            principal: entry.principal.clone(),
        }
    }
}

/// The credential identity for the row of `decision`, for [`RowStart::credential`]: that of the
/// connector entry of the tool the decision names, from `snapshot`, which must be the snapshot
/// the decision was made from. `None` when the decision names no tool, or the tool's connector
/// has no entry, as the JSON configuration's in-process connectors have none.
pub fn credential_identity(
    snapshot: &PolicySnapshot,
    decision: &Decision,
) -> Option<CredentialIdentity> {
    let tool = decision.tool()?;
    snapshot.entry(&tool.connector).map(CredentialIdentity::of)
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
    Error {
        /// What kind of failure. The caller's message is not recorded.
        error_kind: ErrorKind,
    },
    /// The connector refused the call because of what it names, such as a repository outside
    /// the team's scope. The only decision made outside the decision function, and it can only
    /// refuse.
    Refused {
        /// The connector's sentence: exactly the text the caller receives.
        sentence: String,
    },
    /// A side effect was sent and no definite answer came back (decision 0009). Never the
    /// outcome of a read. Its receipt is `unknown`.
    Unknown,
    /// Nothing ran, because the same call under the same key was already completed: the answer
    /// to a reused key whose earlier receipt is `completed` (decision 0009, "Reuse"). Written
    /// at begin, never by finish.
    Duplicate {
        /// The earlier call's receipt, which is its row.
        receipt: AuditRowId,
    },
}

/// The second half of an allowed call's audit row, written after the tool returns, or at begin
/// for the answer to a reused key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    /// `ok`, `error` with its kind, `refused` with its sentence, `unknown`, or `duplicate`
    /// with the earlier receipt.
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
    /// supplied it in [`RowStart`]. A store adds its own begin budget, finish deadline and
    /// answer budget to it for the allowance it gives the database, which sets the row's
    /// deadline from its own clock. The time at begin and the deadline are not fields here: the store sets them.
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
    ///
    /// A tool declared as its connector entry's reach records the entry, as
    /// [`RecordedResources::Reach`], with nothing left out, whatever the decision.
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
    /// The configured identity of the connector entry of the tool the call names, recorded at
    /// begin, as [`RowStart::credential`] gives it: see [`CredentialIdentity`]. Recorded for a
    /// denial too, as the connector is. `None` when the call names no tool the surface serves,
    /// or the tool's connector has no entry.
    pub credential: Option<CredentialIdentity>,
    /// The outcome and latency. Empty when the row is begun, and always empty for a denial;
    /// filled by [`finish`]. An allowed row that stays empty is evidence that the gateway
    /// allowed a call and never learned what happened. The one row written complete is the
    /// answer to a reused key, which the store completes at begin, in the same write
    /// ([`AuditStore::begin_with_receipt`]); the record begin hands the store is still empty.
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

    /// Writes `record`, the begin of an allowed call of a tool not classified `read`, as the
    /// row `row`, and in the same write reserves the receipt `receipt` asks for or answers the
    /// reuse of its key (decision 0009, part 2). [`begin`] calls this, and not
    /// [`begin`](AuditStore::begin), for every such call, and for nothing else.
    ///
    /// - First the reuse check: a receipt for the same key in the same scope
    ///   ([`ReceiptRequest::same_key`]) reserved under a row other than `row`. A receipt
    ///   reserved under `row` itself is passed over, so a retried begin never refuses itself.
    /// - If there is one, the row is written already complete, with the
    ///   [`completion`](Reuse::completion) of [`Reuse::answer`] for that receipt, nothing is
    ///   reserved and the earlier receipt is left as it is, and this returns
    ///   [`Reservation::Reused`] with that answer.
    /// - Otherwise the row is written open, the receipt
    ///   [`ReceiptRequest::reserve`] makes is reserved under it as `pending`, and this returns
    ///   [`Reservation::Reserved`].
    /// - It is one write: when this returns `Ok`, the row is durable with its receipt or with
    ///   its answer, and not before. Two calls with one key in one scope never both reserve.
    /// - A second call with an identifier already stored, whose stored decision is the same,
    ///   writes nothing and returns what the first wrote: [`Reservation::Reserved`] while the
    ///   row's receipt is `pending` and the row's deadline has not passed, and the same answer
    ///   for a row written as one. A row whose receipt has left `pending` is refused, since its
    ///   call has run or has been settled without running, and must not run again. So is one
    ///   whose receipt is still `pending` past the row's deadline, which reads as `unknown`, so
    ///   its call may have run; a row of another decision, as at
    ///   [`begin`](AuditStore::begin); and a row stored with no receipt and no answer.
    /// - A record that is not an allowed call is refused, and nothing is written: a denial
    ///   reserves nothing.
    /// - A store that keeps no receipts refuses every call, and nothing runs.
    fn begin_with_receipt<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
        receipt: &'a ReceiptRequest,
    ) -> BoxFuture<'a, Result<Reservation, StoreError>>;

    /// Fills in the outcome and latency of a row that [`begin`](AuditStore::begin) or
    /// [`begin_with_receipt`](AuditStore::begin_with_receipt) wrote open. Takes a
    /// [`RowCompletion`], which only [`finish`] can make, from a call that ran, and only
    /// [`give_up`], as `error`, from a guard given up without running.
    ///
    /// A repeat of the completion a row already has, the same outcome, with the same error kind
    /// or sentence, and the same latency, returns `Ok`, so finish can be retried. A different
    /// completion of a row already complete, an error of another kind included, returns `Err`,
    /// and the first completion stands.
    ///
    /// For a row that reserved a receipt, the receipt moves in the same write, established by
    /// the call, to the state the outcome settles it in
    /// ([`ReceiptState::settled_by`](crate::ReceiptState::settled_by)), with the completion's
    /// [`reference`](RowCompletion::reference), as
    /// [`may_move`](crate::receipt::may_move) allows. A receipt that reconciliation or a person
    /// has already settled is left as it is, and the row is still completed (decision 0009).
    /// So is a receipt whose row's deadline has passed, judged by the store's own clock at the
    /// time of the write: it stays `pending` for reconciliation or a person.
    /// An `unknown` outcome or a vendor reference for a row that reserved no receipt is
    /// refused, since a read reports neither, and so is a `duplicate`, which only begin writes.
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
    /// The credential identity of the connector entry of the tool the decision names, from the
    /// snapshot the decision was made from: see [`credential_identity`]. [`begin`] records it
    /// only on a row that names a tool, and [`listed`] not at all.
    pub credential: Option<CredentialIdentity>,
}

/// The completion of one allowed row, for [`AuditStore::finish`]. Made only by [`finish`] and
/// [`give_up`].
#[derive(Debug)]
pub struct RowCompletion {
    row: AuditRowId,
    completion: Completion,
    reference: Option<VendorReference>,
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

    /// The vendor's reference for what a side effect made, for its receipt: set only for a
    /// call that reserved a receipt and whose connector reported one, made safe and capped.
    pub fn reference(&self) -> Option<&VendorReference> {
        self.reference.as_ref()
    }
}

/// Evidence that the audit row for an allowed call was written. Running the tool consumes it,
/// and so does giving it up without running.
///
/// Obtainable only from [`begin`]; see the [module documentation](self).
#[must_use = "a guard is run or given up; one that is dropped leaves its row with an empty outcome"]
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

    /// Whether begin reserved a receipt under this guard's row: for every tool not classified
    /// `read`, since [`begin`] hands out a guard for one only once its receipt is reserved.
    fn reserved(&self) -> bool {
        self.tool.classification != Classification::Read
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

/// A call allowed by the decision function and answered from an earlier receipt under its key:
/// its row was written complete with the answer, and nothing runs (decision 0009, "Reuse").
/// Made only by [`begin`].
#[derive(Debug)]
pub struct Reused {
    row: AuditRowId,
    reuse: Reuse,
}

impl Reused {
    /// The row that records this answer.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// Which of the five answers it is: a `duplicate`, answered as a success with the earlier
    /// receipt and the vendor's reference, or one of four refusals.
    pub fn reuse(&self) -> &Reuse {
        &self.reuse
    }

    /// The sentence for the caller. For a refusal it is the sentence the row holds.
    pub fn sentence(&self) -> String {
        self.reuse.sentence()
    }
}

/// What [`begin`] returns once the row is written.
#[must_use]
// A `Begun` is made once per call and taken apart at once, so boxing the guard would add an
// allocation to every allowed call to save a copy on a path that runs once.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Begun {
    /// The call may run; pass the guard to [`run`].
    Allowed(AuditGuard),
    /// The call is denied; return the refusal's sentence.
    Denied(Refusal),
    /// The call was allowed, and its key already has a receipt in its scope, so it does not
    /// run: answer with the [`Reused`]'s sentence, as a success for a `duplicate` and as a
    /// refusal otherwise.
    Reused(Reused),
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
/// part of the decision or the record, and the core never parses them. If the row cannot be
/// written, returns [`AuditFailure`] and the call must be refused, whatever the decision was.
///
/// An allowed call of a tool not classified `read` is begun through
/// [`AuditStore::begin_with_receipt`], with a receipt for the key the decided call carries,
/// scoped to its proved principal and its delegation's key scope, and the
/// [`ArgumentDigest`] of `arguments`. If its key already has a receipt in its scope, this
/// returns [`Begun::Reused`] and no guard. A denial reserves nothing.
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
        credential,
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
        credential: tool.and(credential),
        completion: None,
    };
    let receipt = match &decided {
        Decided::Allow(tool) if tool.classification != Classification::Read => {
            Some(receipt_request(&call, tool, &arguments, &record)?)
        }
        _ => None,
    };
    let reservation = match &receipt {
        Some(receipt) => Some(
            store
                .begin_with_receipt(&row, &record, receipt)
                .await
                .map_err(AuditFailure::from_store)?,
        ),
        None => {
            store
                .begin(&row, &record)
                .await
                .map_err(AuditFailure::from_store)?;
            None
        }
    };
    if let Some(Reservation::Reused(reuse)) = reservation {
        return Ok(Begun::Reused(Reused { row, reuse }));
    }
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
    let named = match resources {
        Resources::Named(named) => named,
        Resources::Reach { entry, .. } => return (RecordedResources::Reach(entry.clone()), 0),
        Resources::Unknown => return (RecordedResources::Unknown, 0),
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

/// The receipt to reserve for `call`, an allowed call of `tool`, which is not classified `read`:
/// its key, scoped to its proved principal and its delegation's key scope, the tool, the
/// tool-use identifier and resources its row records, and the digest of `arguments`.
///
/// The decision function denies such a call when it carries no key, so an allowed one always
/// carries one. If one did not, nothing would run: the call is refused as an audit failure,
/// before anything is written.
fn receipt_request(
    call: &CallContext,
    tool: &ApprovedTool,
    arguments: &serde_json::Value,
    record: &AuditRecord,
) -> Result<ReceiptRequest, AuditFailure> {
    let Some(key) = call.key.clone() else {
        return Err(AuditFailure::from_store(
            "an allowed call of a tool not classified `read` carried no key, so no receipt can be reserved for it"
                .into(),
        ));
    };
    let scope = KeyScope {
        principal: call.caller.principal.get().id.clone(),
        delegation: call
            .caller
            .delegation
            .as_ref()
            .and_then(|delegation| delegation.get().key_scope.clone()),
    };
    Ok(ReceiptRequest::new(
        scope,
        key,
        tool.name.clone(),
        record.tool_use_id.clone(),
        ArgumentDigest::of(arguments),
        (record.resources.clone(), record.resources_omitted),
    ))
}

// Large for the reason a check's `Err` is (see decision.rs): a reason carries the principal,
// pod and all, and the resource its sentence names. One is made per call and moved once.
#[allow(clippy::large_enum_variant)]
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
    reserved: bool,
}

/// Runs the guarded call on `connector`, consuming the guard.
pub async fn run(connector: &dyn Connector, guard: AuditGuard) -> Ran {
    let reserved = guard.reserved();
    let AuditGuard {
        row,
        call,
        tool,
        arguments,
    } = guard;
    let outcome = connector.run(ToolCall::new(call, tool, arguments)).await;
    Ran {
        row,
        outcome,
        reserved,
    }
}

/// Runs the guarded call on `connector`, as [`run`] does, unless its caller goes away first:
/// `gone` completes when the caller has disconnected. What that does depends on the tool's
/// classification (decision 0009, "Where a call runs"):
///
/// - A tool classified `read` is cancelled. If `gone` has already completed, the connector is
///   not called. Otherwise the call is raced against `gone`, and if `gone` completes first the
///   connector's future is dropped. Either way the `Ran` records the call as an error, with the
///   sentence that the caller disconnected, so [`finish`] completes the row as `error`. A read
///   that has returned is never thrown away: the connector is polled before `gone`.
/// - Any other classification ignores `gone`, which is never polled. A side effect runs to
///   completion, so that its outcome is learned rather than made unknown by a cancellation.
pub async fn run_unless(
    connector: &dyn Connector,
    guard: AuditGuard,
    gone: impl Future<Output = ()>,
) -> Ran {
    if guard.tool.classification != Classification::Read {
        return run(connector, guard).await;
    }
    let AuditGuard {
        row,
        call,
        tool,
        arguments,
    } = guard;
    let cancelled = || ToolOutcome::error(ErrorKind::Other, sentences::CALLER_DISCONNECTED);
    let mut gone = pin!(gone);
    // A caller already gone is not called for.
    let already_gone = poll_fn(|context| Poll::Ready(gone.as_mut().poll(context).is_ready())).await;
    if already_gone {
        return Ran {
            row,
            outcome: cancelled(),
            reserved: false,
        };
    }
    let mut running = connector.run(ToolCall::new(call, tool, arguments));
    let outcome = poll_fn(|context| {
        if let Poll::Ready(outcome) = running.as_mut().poll(context) {
            return Poll::Ready(outcome);
        }
        gone.as_mut().poll(context).map(|()| cancelled())
    })
    .await;
    // On a cancellation, this is what cancels the read.
    drop(running);
    Ran {
        row,
        outcome,
        reserved: false,
    }
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
    /// A side effect was sent and no definite answer came back: the sentence saying it may
    /// have taken effect, must not be repeated, and will be checked as its receipt.
    Unknown(String),
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
/// out the answer. A side effect's receipt is settled in the same write, with the vendor's
/// reference when its connector reported one, unless the row's deadline has passed by the
/// store's clock, when the receipt stays `pending` for reconciliation or a person.
///
/// A connector that reports [`ToolOutcome::Unknown`] for a `read` tool, which has no receipt,
/// has its call recorded as an error of the kind `other`: a read never reports `unknown`.
pub async fn finish(store: &dyn AuditStore, ran: Ran, latency_ms: u64) -> Finished {
    let Ran {
        row,
        outcome,
        reserved,
    } = ran;
    let mut reference = None;
    let (recorded, answer) = match outcome {
        ToolOutcome::Ok(result) => (Outcome::Ok, Answer::Ok(result)),
        ToolOutcome::Completed(result, made) => {
            reference = reserved.then(|| made.recorded());
            (Outcome::Ok, Answer::Ok(result))
        }
        ToolOutcome::Unknown if reserved => (
            Outcome::Unknown,
            Answer::Unknown(sentences::render_unknown(&row)),
        ),
        ToolOutcome::Unknown => (
            Outcome::Error {
                error_kind: ErrorKind::Other,
            },
            Answer::Error(sentences::NO_DEFINITE_ANSWER.to_owned()),
        ),
        ToolOutcome::Error(error_kind, message) => {
            (Outcome::Error { error_kind }, Answer::Error(message))
        }
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
        reference,
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

/// A guard given up without running: its row, and whether the row could be completed. Made
/// only by [`give_up`]. It holds no answer, because nothing ran.
#[must_use = "a guard given up still needs a reply to the caller, and its failure reported"]
#[derive(Debug)]
pub struct GaveUp {
    row: AuditRowId,
    failure: Option<AuditFailure>,
}

impl GaveUp {
    /// The row that was given up.
    pub fn row(&self) -> &AuditRowId {
        &self.row
    }

    /// Why the row could not be completed, if it could not. The row then keeps an empty
    /// outcome, and reads as open once its deadline passes.
    pub fn failure(&self) -> Option<&AuditFailure> {
        self.failure.as_ref()
    }
}

/// Gives up a guard without running its call: consumes the guard, calls no connector, and
/// completes the row as `error`, of the kind [`ErrorKind::Other`], with a latency of zero
/// (decision 0009). A row can overstate what ran, never understate it, so a call that never ran
/// is never recorded as `ok`. A side effect's receipt is settled as `not_performed` in the same
/// write, since nothing was sent, unless the row's deadline has passed by the store's clock,
/// when the receipt stays `pending` for reconciliation or a person.
///
/// The caller chooses its own reply, since nothing ran.
pub async fn give_up(store: &dyn AuditStore, guard: AuditGuard) -> GaveUp {
    let AuditGuard { row, .. } = guard;
    let completion = RowCompletion {
        row,
        completion: Completion {
            outcome: Outcome::Error {
                error_kind: ErrorKind::Other,
            },
            latency_ms: 0,
        },
        reference: None,
    };
    let failure = store
        .finish(&completion)
        .await
        .err()
        .map(AuditFailure::from_store);
    GaveUp {
        row: completion.row,
        failure,
    }
}
