//! The audit store contract suite (design.md section 18): test functions that every
//! [`AuditStore`] must pass, run unchanged against [`InMemoryAuditStore`] in the per-change loop
//! and against the Postgres store in the slow loop.
//!
//! A runner gives each function a [`ContractStore`]: the store, a way to read a row back as the
//! store holds it, the budgets the store was given, and the time on the store's clock. The
//! read-back belongs to the runner, not to the
//! store's interface, so it sees what that interface hides: the Postgres runner reads as a
//! superuser, and [`InMemoryAuditStore`]'s reads the store's own state. Each expectation is
//! written to what the Postgres store does, so a fake that does more than Postgres can fails
//! it rather than passing a test the real store would fail.
//!
//! It covers the suite's items 1 to 3; of item 4, that a call row's time at begin comes from
//! the store's clock and its deadline is that time plus the budgets and the call deadline, as
//! Postgres works it out; and of item 5, that a list row is stored complete with no deadline,
//! with its time at begin from the store's clock, and is never completed, and that a call
//! record of kind `list` is refused at begin. Of item 3, it covers decision 0011's report of
//! what a tool that checks its own scope reached: written in place of the row's `unknown`
//! resources in the same write as the completion, and refused from any other tool. Of item 2, it
//! covers decision 0011's exception: stored on an allowed call of a `write` tool, the answer to
//! a reused key included, and refused on any other row. That the
//! store overwrites times an insert
//! carries cannot be tried through [`AuditStore`], whose callers pass no times: the Postgres
//! schema tests try it. The open-row query is not here: it is Postgres's alone for now.
//!
//! It covers item 6, receipts (decision 0009, part 2), with the functions under "Item 6": a
//! receipt is reserved with its row or not at all, and moves with its finish, but not once its
//! row's deadline has passed, when a late finish completes the row and leaves the receipt
//! `pending`, read as `unknown`, for reconciliation or a person; a key is unique
//! in its scope under concurrent calls, and two delegations under one principal may each use
//! it; a key's scope over its cap is refused at begin; a begin retried after a lost
//! confirmation finds its own receipt and runs once, but once its row's deadline has passed
//! with the receipt still `pending` it is refused and runs
//! nothing; a begin whose confirmation is lost on every attempt leaves its row `error` and its
//! receipt `not_performed`, and one under a reused key leaves its row with its answer and gives
//! nothing up; a retried begin of a `duplicate` is answered with the earlier receipt's
//! reference, which Postgres reads as it is now and the in-memory store keeps from the first
//! answer, and which cannot differ, since a `completed` receipt is final; and each receipt state
//! against each line of the reuse table. Both stores run every one of them.
//!
//! It covers reconciliation (decision 0009, "Reconciliation") with the functions under "Item
//! 7", through the store's [`ReceiptQueue`]: a receipt records the vendor target its tool's
//! settlement takes from the call; two claimants never both hold a receipt's lease; an ended
//! lease can be claimed again; the number of attempts is bounded, and the last hands the
//! receipt to a person, who finds it still `unknown`; an authoritative search that found
//! nothing settles `not_performed`, and one that is not never does; a found effect settles
//! `completed` with its reference; a lookup record is appended and never changed; a receipt
//! settled by reconciliation is not moved by a late finish, and a late finish that disagrees
//! with it is counted, once; each claim is counted as an attempt; a receipt held for its
//! call, `pending` or `unknown`, is not due and no one else can claim it until the hold ends;
//! and a receipt answered `unknown` is not due, nor claimed, before its row's deadline.
//!
//! Some of what the in-memory store copies from Postgres cannot be tried here, and its own
//! tests try it. A deadline whose interval is past what Postgres holds is refused, but from
//! any time at begin after 1999 so is the deadline it gives, and a runner cannot set the
//! database's clock, so the two refusals look alike.
//!
//! The functions read no clock but the store's, through [`ContractStore::now`], and spawn
//! nothing, so they run on whatever executor the runner has: [`block_on`](crate::block_on)
//! for the in-memory store, a Tokio runtime for Postgres. They are tests: a broken
//! expectation panics, as an assertion does.

#![allow(
    clippy::expect_used,
    reason = "these are test functions, and a broken expectation fails the test"
)]

use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::audit::RecordedResources;
use gateway_core::audit::{
    self, Answer, AuditFailure, AuditRowId, Begun, Completion, DecisionKind, ErrorKind, ListRecord,
    MAX_RECORDED_RESOURCES, Outcome, RecordedDelegation, RecordedFailure, RecordedResource,
    RequestMetadata, RowKind, RowStart,
};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{
    ArgumentDigest, AuditGuard, AuditRecord, AuditStore, BoxFuture, CallContext, CallerContext,
    Claimed, Classification, Connector, CredentialIdentity, CredentialMode, Currency,
    CurrencyAnswer, Decision, Delegation, DelegationDigest, DelegationFailure, DelegationKeyScope,
    Egress, ExceptionName, IdempotencyKey, Issuer, KeyScope, LeaseHolder, LookupAnswer,
    MAX_IDEMPOTENCY_KEY, PodUid, PolicySnapshot, PresentedDelegation, Principal, PrincipalKind,
    Proved, Reason, ReasonKind, Receipt, ReceiptQueue, ReceiptState, Recorded, RequestedTool,
    Resource, Resources, Reuse, Subject, TeamId, ToolCall, ToolOutcome, ToolUseId,
    UnverifiedDelegation, VendorReference, Verifier, WasProved, decide,
};
use serde_json::{Value, json};

use crate::audit::{InMemoryAuditStore, StoreBudgets, fresh_key, row_start};
use crate::connector::{
    DOCUMENT_ARGUMENT, DRAFT_TOOL, FORBIDDEN_DOCUMENT, FixtureConnector, READ_TOOL,
    SCOPED_READ_TOOL, WRITE_TOOL, document,
};
use crate::credentials::FakeCredentialSource;
use crate::fixture::{
    Caller, Fixture, PROFILE_TEAM_A, SURFACE_ALL, SURFACE_READ, TEAM_A, TEAM_A_DOCUMENT,
    TEAM_B_DOCUMENT, UNKNOWN_PROFILE, draft_lookup, policy_data, policy_data_with_draft_lookup,
};
use crate::row_bound::{
    MAX_BEGUN_ROW_BYTES, MAX_KEY_SCOPE_BYTES, MAX_OUTCOME_SENTENCE_BYTES, MAX_REACHED_BYTES,
    MAX_ROW_BYTES, call_row_sizes, list_row_sizes,
};

/// What a contract function needs of a store: the store, a read-back, its budgets and its clock.
pub trait ContractStore {
    /// The store under test.
    fn store(&self) -> &dyn AuditStore;

    /// The row stored under `row`, read back as the store holds it, or `None` if it holds none.
    /// As strict as the store allows: the whole record, its completion and kind, its time at
    /// begin, and whether the store set a deadline. A store that holds two rows under one
    /// identifier, which Postgres's primary key forbids, makes this panic.
    fn stored(&self, row: &AuditRowId) -> impl Future<Output = Option<StoredRow>>;

    /// The begin budget, the finish deadline and the answer budget the store was given, to add
    /// to each call row's deadline. A runner answers with the budgets it gave the store, not
    /// with what the store holds, so a store that ignores the ones it was given is caught.
    fn budgets(&self) -> StoreBudgets;

    /// The time on the store's own clock: database time for Postgres, the store's clock for the
    /// in-memory store. A row begun between two readings has its time at begin between them.
    fn now(&self) -> impl Future<Output = SystemTime>;

    /// Every receipt the store holds, as it holds them, in any order. For item 6's functions
    /// only.
    fn receipts(&self) -> impl Future<Output = Vec<Receipt>>;

    /// From here on, every begin writes its row and then reports failure: its confirmation is
    /// lost on every attempt within the begin budget, as decision 0009 says a begin may be. The
    /// store then completes an allowed row as `error` and settles its receipt as
    /// `not_performed`. For item 6's functions only.
    fn lose_every_begin_confirmation(&self);

    /// Moves the store's clock past the deadline of the call row `row`, which must have one.
    /// For item 6's and item 7's functions only.
    fn pass_deadline(&self, row: &AuditRowId) -> impl Future<Output = ()>;

    /// The store's queue of `unknown` receipts. For item 7's functions only.
    fn queue(&self) -> &dyn ReceiptQueue;

    /// Ends the lease on the receipt reserved under `row` now, as if its time had passed: the
    /// in-memory store's clock moves past it, and Postgres's lease is set to have ended. For
    /// item 7's functions only.
    fn pass_lease(&self, row: &AuditRowId) -> impl Future<Output = ()>;

    /// How many late finishes the store has counted as disagreeing with the state
    /// reconciliation settled their receipt in. For item 7's functions only.
    fn late_finish_disagreements(&self) -> u64;

    /// How many completions of a lost begin's row the store has given up, once every completion
    /// it has in flight has ended. The Postgres store counts them with every other finish it
    /// gives up, so a function that asks gives up no other. For item 6's functions only.
    fn lost_begins_given_up(&self) -> impl Future<Output = u64>;
}

/// The record a row holds.
// Test-only, made once per read-back: boxing a call record would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredRecord {
    /// A row of kind `call`, with its completion once finished.
    Call(AuditRecord),
    /// A row of kind `list`.
    List(ListRecord),
}

/// A row as a store holds it, read back by a [`ContractStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRow {
    /// The call or list record.
    pub record: StoredRecord,
    /// The row's kind, as the store holds it.
    pub kind: RowKind,
    /// The completion, as the store holds it.
    pub completion: Option<Completion>,
    /// The row's time at begin, if the store set one.
    pub begun_at: Option<SystemTime>,
    /// Whether the store set the row's deadline.
    pub deadline_set: bool,
    /// The deadline less the time at begin, where both are set.
    pub deadline_after_begin: Option<Duration>,
}

/// The row `store` holds under `row`, for a runner's [`ContractStore::stored`] over the
/// in-memory store. The runner answers [`ContractStore::budgets`] and [`ContractStore::now`]
/// with the budgets and the clock it gave the store, not with any the store holds, so a store
/// that ignores them is caught.
pub fn stored_in_memory(store: &InMemoryAuditStore, row: &AuditRowId) -> Option<StoredRow> {
    let mut found = store.stored_under(row);
    assert!(
        found.len() <= 1,
        "the store holds {} rows under {}, where Postgres's primary key allows one",
        found.len(),
        row.as_str()
    );
    let (record, begun_at, deadline) = found.pop()?;
    let (kind, completion) = match &record {
        StoredRecord::Call(call) => (call.kind, call.completion.clone()),
        StoredRecord::List(_) => (RowKind::List, None),
    };
    Some(StoredRow {
        record,
        kind,
        completion,
        begun_at: Some(begun_at),
        deadline_set: deadline.is_some(),
        deadline_after_begin: deadline.map(|deadline| {
            deadline
                .duration_since(begun_at)
                .expect("the row's deadline is before its time at begin")
        }),
    })
}

// --- Calls a function makes through the core ----------------------------------------------------

/// A call through the fixture's policy.
#[derive(Debug)]
struct Call {
    caller: Caller,
    surface: &'static str,
    tool: &'static str,
    document: &'static str,
}

/// Allowed: team A reads its own document.
const ALLOWED: Call = Call {
    caller: Caller::TeamA,
    surface: SURFACE_ALL,
    tool: READ_TOOL,
    document: TEAM_A_DOCUMENT,
};

/// Allowed too, on another surface: the same decision as [`ALLOWED`] in another record.
const ALLOWED_ELSEWHERE: Call = Call {
    caller: Caller::TeamA,
    surface: SURFACE_READ,
    tool: READ_TOOL,
    document: TEAM_A_DOCUMENT,
};

/// Denied: team B's profile does not permit a write.
const DENIED: Call = Call {
    caller: Caller::TeamB,
    surface: SURFACE_ALL,
    tool: WRITE_TOOL,
    document: TEAM_B_DOCUMENT,
};

/// Allowed, and the connector refuses it, with a sentence.
const REFUSED_BY_CONNECTOR: Call = Call {
    caller: Caller::TeamA,
    surface: SURFACE_READ,
    tool: SCOPED_READ_TOOL,
    document: FORBIDDEN_DOCUMENT,
};

fn fixture() -> Fixture {
    Fixture::new().expect("the fixture builds")
}

fn connector() -> FixtureConnector {
    FixtureConnector::new(Arc::new(FakeCredentialSource::new()))
}

fn arguments(call: &Call) -> Value {
    json!({ DOCUMENT_ARGUMENT: call.document })
}

fn decision(fixture: &Fixture, call: &Call) -> Decision {
    decide(&fixture.policy, &decision_context(fixture, call))
}

/// The context `call` is decided with, its resources read by the fixture's adapter.
fn decision_context(fixture: &Fixture, call: &Call) -> CallContext {
    let arguments = arguments(call);
    CallContext {
        resources: FixtureConnector::resources_of(call.tool, &arguments),
        caller: fixture
            .caller_context(call.caller, call.surface)
            .expect("the fixture knows the caller"),
        tool: RequestedTool::new(call.tool),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    }
}

/// Begins `call` through the core as the row `start` names.
async fn begin(
    store: &dyn AuditStore,
    fixture: &Fixture,
    start: &RowStart,
    call: &Call,
    metadata: RequestMetadata,
) -> Result<Begun, AuditFailure> {
    audit::begin(
        store,
        start.clone(),
        decision(fixture, call),
        arguments(call),
        metadata,
    )
    .await
}

/// The guard for `call`, which must be allowed, begun as the row `start` names.
async fn guard(
    store: &dyn AuditStore,
    fixture: &Fixture,
    start: &RowStart,
    call: &Call,
) -> AuditGuard {
    match begin(store, fixture, start, call, RequestMetadata::default()).await {
        Ok(Begun::Allowed(guard)) => guard,
        other => panic!("{call:?} was not begun as allowed: {other:?}"),
    }
}

/// The row stored under `row`, which there must be.
async fn stored(contract: &impl ContractStore, row: &AuditRowId) -> StoredRow {
    contract
        .stored(row)
        .await
        .unwrap_or_else(|| panic!("no row is stored under {}", row.as_str()))
}

/// A duration in whole milliseconds, as the Postgres store counts each budget: a part
/// millisecond is dropped.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// What a store adds to a call row's call deadline for its allowance: the begin budget, the
/// finish deadline and the answer budget, each in whole milliseconds (decision 0009, as
/// amended on 2026-10-11). Worked out here, not with a store's own arithmetic, so a store that
/// leaves one out is caught.
fn budgets_ms(budgets: &StoreBudgets) -> u64 {
    millis(budgets.begin) + millis(budgets.finish_deadline) + millis(budgets.answer)
}

// --- Item 1: begin ------------------------------------------------------------------------------

/// `begin` returns `Ok` only once the row is stored, under the identifier it was given. A
/// second begin under that identifier with the same decision returns `Ok` and changes nothing,
/// even for another record: the Postgres store's role cannot read who called what, so only the
/// decision is compared. One with another decision is refused, and the first row stands. The
/// same holds for a denial's row.
pub async fn begin_is_ok_only_once_stored_and_idempotent_by_identifier(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();

    let start = row_start();
    assert_eq!(contract.stored(&start.row).await, None);
    let _ = guard(store, &fixture, &start, &ALLOWED).await;
    let first = contract
        .stored(&start.row)
        .await
        .expect("begin returned Ok with no row stored under its identifier");
    let StoredRecord::Call(record) = &first.record else {
        panic!("a call was stored as {:?}", first.record);
    };
    assert_eq!(record.decision, DecisionKind::Allow);
    assert_eq!(record.surface.as_str(), SURFACE_ALL);
    assert_eq!((first.kind, &first.completion), (RowKind::Call, &None));

    for call in [&ALLOWED, &ALLOWED_ELSEWHERE] {
        let begun = begin(store, &fixture, &start, call, RequestMetadata::default()).await;
        assert!(
            matches!(&begun, Ok(Begun::Allowed(guard)) if guard.row() == &start.row),
            "a retried begin with the same decision was refused: {begun:?}"
        );
        assert_eq!(
            contract.stored(&start.row).await.as_ref(),
            Some(&first),
            "a retried begin changed the stored row"
        );
    }
    let begun = begin(store, &fixture, &start, &DENIED, RequestMetadata::default()).await;
    assert!(
        begun.is_err(),
        "a begin with another decision was accepted: {begun:?}"
    );
    assert_eq!(contract.stored(&start.row).await.as_ref(), Some(&first));

    let denial = row_start();
    for _ in 0..2 {
        let begun = begin(
            store,
            &fixture,
            &denial,
            &DENIED,
            RequestMetadata::default(),
        )
        .await;
        assert!(
            matches!(&begun, Ok(Begun::Denied(refusal)) if refusal.row() == &denial.row),
            "{begun:?}"
        );
    }
    let denied = stored(contract, &denial.row).await;
    let StoredRecord::Call(record) = &denied.record else {
        panic!("a denial was stored as {:?}", denied.record);
    };
    assert_eq!(record.decision, DecisionKind::Deny);
    let begun = begin(
        store,
        &fixture,
        &denial,
        &ALLOWED,
        RequestMetadata::default(),
    )
    .await;
    assert!(
        begun.is_err(),
        "an allowed begin under a denial's identifier was accepted: {begun:?}"
    );
    assert_eq!(contract.stored(&denial.row).await, Some(denied));
    assert_eq!(contract.stored(&start.row).await, Some(first));
}

// --- Item 2: the stored row ---------------------------------------------------------------------

fn call_record(value: Value) -> AuditRecord {
    serde_json::from_value(value).expect("the record is well formed")
}

/// Records with every value set, each to a value no other field holds, and with none of the
/// optional ones set.
fn records() -> Vec<AuditRecord> {
    let common = |decision: &str| {
        json!({
            "kind": "call",
            "instance": format!("instance-{decision}"),
            "call_deadline_ms": decision.len() * 1_000 + 7,
            "tool_use_id": format!("toolu-{decision}"),
            "deployment": format!("deployment-{decision}"),
            "surface": format!("surface-{decision}"),
            "profile": format!("profile-{decision}"),
            "tool": format!("tool-{decision}"),
            "connector": format!("connector-{decision}"),
            "classification": "write",
            "resources": {"named": [
                {"system": "system-1", "kind": "kind-1", "identifier": "identifier-1"},
                {"system": "system-2", "kind": "kind-2", "identifier": "back\\\\slash, \"quoted\", é"},
                {"system": "system-3", "kind": "kind-3", "identifier": "x".repeat(2048)}
            ]},
            "resources_omitted": 3,
            "policy_revision": format!("revision-{decision}"),
            "proved_delegation_team": format!("delegation-team-{decision}"),
            "claimed_acting_person": format!("acting-person-{decision}"),
            "claimed_team": format!("claimed-team-{decision}"),
            "credential": {
                "mode": "team_service_identity",
                "principal": format!("credential-principal-{decision}")
            },
            "completion": null
        })
    };
    let mut allowed = common("allow");
    allowed["decision"] = json!("allow");
    allowed["reason"] = json!(null);
    allowed["sentence"] = json!(null);
    allowed["proved_principal"] = json!({
        "id": {"issuer": "issuer-allow", "subject": "subject-allow"},
        "kind": "workload",
        "team": "proved-team-allow"
    });
    let mut denied = common("deny");
    denied["decision"] = json!("deny");
    denied["reason"] = json!("classification_not_permitted");
    denied["sentence"] = json!("sentence-deny");
    denied["proved_principal"] = json!({
        "id": {"issuer": "issuer-deny", "subject": "subject-deny"},
        "kind": "user",
        "groups": ["group-1", "group-2"]
    });
    denied["credential"]["mode"] = json!("gateway_token");
    let bare = json!({
        "kind": "call",
        "instance": "instance-bare",
        "call_deadline_ms": 0,
        "tool_use_id": null,
        "deployment": "deployment-bare",
        "surface": "surface-bare",
        "profile": "profile-bare",
        "tool": "no such\\ntool",
        "connector": null,
        "classification": null,
        "resources": "unknown",
        "resources_omitted": 0,
        "decision": "deny",
        "reason": "unknown_tool",
        "sentence": "sentence-bare",
        "policy_revision": "revision-bare",
        "proved_principal": {
            "id": {"issuer": "issuer-bare", "subject": "subject-bare"},
            "kind": "user",
            "groups": []
        },
        "proved_delegation_team": null,
        "claimed_acting_person": null,
        "claimed_team": null,
        "credential": null,
        "completion": null
    });
    let mut no_resources = common("none");
    no_resources["decision"] = json!("allow");
    no_resources["reason"] = json!(null);
    no_resources["sentence"] = json!(null);
    no_resources["classification"] = json!("read");
    no_resources["resources"] = json!({"named": []});
    no_resources["resources_omitted"] = json!(0);
    no_resources["proved_principal"] = json!({
        "id": {"issuer": "issuer-none", "subject": "subject-none"},
        "kind": "workload",
        "team": "proved-team-none"
    });
    no_resources["credential"] = json!(null);
    let mut reach = common("reach");
    reach["decision"] = json!("allow");
    reach["reason"] = json!(null);
    reach["sentence"] = json!(null);
    reach["classification"] = json!("read");
    reach["resources"] = json!({"reach": "entry-reach"});
    reach["resources_omitted"] = json!(0);
    reach["proved_principal"] = json!({
        "id": {"issuer": "issuer-reach", "subject": "subject-reach"},
        "kind": "workload",
        "team": "proved-team-reach"
    });
    [allowed, denied, bare, no_resources, reach]
        .into_iter()
        .map(call_record)
        .collect()
}

/// The row a begin stores is exactly the record it was given, resources and counts included,
/// as a row of kind `call` with no completion, a time at begin and a deadline.
pub async fn the_stored_row_is_exactly_the_record(contract: &impl ContractStore) {
    for written in records() {
        let row = row_start().row;
        contract
            .store()
            .begin(&row, &written)
            .await
            .expect("the store refused a record it can hold");
        let stored = stored(contract, &row).await;
        assert_eq!(stored.record, StoredRecord::Call(written));
        assert_eq!(stored.kind, RowKind::Call);
        assert_eq!(stored.completion, None);
        assert!(
            stored.begun_at.is_some() && stored.deadline_set,
            "{stored:?}"
        );
    }
}

// --- Item 2: records the store cannot hold ------------------------------------------------------

/// A record the store cannot hold exactly is refused at begin, and leaves no row: U+0000 in a
/// text value, a credential identity's included, a record already complete, a count or an
/// allowance past a Postgres `bigint`, unknown resources or a reach with a count left out, a
/// reach naming no entry, a deadline past what Postgres can work out, and an identifier that
/// is not a lowercase hyphenated UUID. So is such a list record, and a
/// completion the store cannot hold leaves its row open.
pub async fn a_record_the_store_cannot_hold_is_refused_and_leaves_no_row(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let budgets = contract.budgets();
    let base = records().swap_remove(0);
    let refused = |change: &dyn Fn(&mut AuditRecord)| {
        let mut record = base.clone();
        change(&mut record);
        record
    };
    // The allowance is the budgets and the call deadline, in whole milliseconds.
    let budgets_ms = budgets_ms(&budgets);
    let cannot_hold = [
        refused(&|record| record.tool_use_id = Some(ToolUseId::new("toolu_\u{0}x"))),
        refused(&|record| record.claimed_team = Some(Claimed::new(TeamId::new("team\u{0}x")))),
        refused(&|record| record.tool = "tool\u{0}".into()),
        refused(&|record| {
            record.completion = Some(Completion {
                outcome: Outcome::Ok,
                latency_ms: 1,
            })
        }),
        refused(&|record| record.resources_omitted = usize::MAX),
        refused(&|record| {
            record.resources = RecordedResources::Unknown;
            record.resources_omitted = 3;
        }),
        refused(&|record| {
            record.resources = RecordedResources::Reach("entry".into());
            record.resources_omitted = 3;
        }),
        refused(&|record| {
            record.resources = RecordedResources::Reach("".into());
            record.resources_omitted = 0;
        }),
        refused(&|record| {
            record.credential = Some(CredentialIdentity {
                mode: CredentialMode::TeamServiceIdentity,
                principal: "service\u{0}account".into(),
            });
        }),
        // An allowance past a bigint.
        refused(&|record| record.call_deadline_ms = u64::MAX),
        // An allowance of exactly the largest bigint, whose interval Postgres cannot hold.
        refused(&|record| record.call_deadline_ms = i64::MAX.unsigned_abs() - budgets_ms),
        // An allowance Postgres's interval holds, whose deadline falls past the end of what a
        // Postgres time holds, 294277-01-01 UTC, from any time at begin after 2015.
        refused(&|record| record.call_deadline_ms = 9_222_900_000_000_000 - budgets_ms),
    ];
    for record in &cannot_hold {
        let row = row_start().row;
        let begun = store.begin(&row, record).await;
        assert!(begun.is_err(), "the store accepted {record:?}");
        assert_eq!(contract.stored(&row).await, None, "{record:?}");
    }

    // A UUID with uppercase hex letters, where a store wants lowercase.
    let uppercase = "6F9619FF-8B86-4D01-B42D-00C04FC964FF";
    for id in ["not-a-row", uppercase, ""] {
        let row = AuditRowId::new(id);
        let begun = store.begin(&row, &base).await;
        assert!(begun.is_err(), "the store accepted the identifier {id:?}");
        assert_eq!(contract.stored(&row).await, None, "{id:?}");
        let listed = store.list(&row, &list_records()[0]).await;
        assert!(listed.is_err(), "the store listed under {id:?}");
        assert_eq!(contract.stored(&row).await, None, "{id:?}");
    }

    let list = list_records().swap_remove(0);
    for record in [
        ListRecord {
            tools: vec!["fixture__read".into(), "tool\u{0}".into()],
            ..list.clone()
        },
        ListRecord {
            tools_omitted: usize::MAX,
            ..list.clone()
        },
    ] {
        let row = row_start().row;
        assert!(store.list(&row, &record).await.is_err(), "{record:?}");
        assert_eq!(contract.stored(&row).await, None, "{record:?}");
    }

    // A latency past a bigint, through the core's finish.
    let fixture = fixture();
    let start = row_start();
    let ran = audit::run(&connector(), guard(store, &fixture, &start, &ALLOWED).await).await;
    let before = stored(contract, &start.row).await;
    let finished = audit::finish(store, ran, u64::MAX).await;
    assert!(
        finished.failure().is_some(),
        "the store accepted a latency past a bigint"
    );
    assert_eq!(stored(contract, &start.row).await, before);
}

// --- Item 2: the row bound ---------------------------------------------------------------------

/// The bytes of a row, as [`row_bound`](crate::row_bound) counts its columns.
fn counted(columns: &[(&'static str, usize)]) -> usize {
    columns.iter().map(|(_, bytes)| bytes).sum()
}

/// Decision 0014, section 7: a call row of exactly begin's bound, [`MAX_BEGUN_ROW_BYTES`] as the
/// store counts it, is begun and stored as the record. One byte more is refused, naming the
/// row's largest column, and leaves no row. An allowed call whose resources are `unknown`, one
/// whose tool checks its own scope (decision 0011), is counted with room for the longest reach
/// finish may write in their place, [`MAX_REACHED_BYTES`], so its row is refused a byte over
/// that count, naming `resources`, though it holds far less when begun.
pub async fn a_call_row_over_begins_bound_is_refused_naming_its_largest_column(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let named = records().swap_remove(0);
    let mut self_scoped = named.clone();
    self_scoped.resources = RecordedResources::Unknown;
    self_scoped.resources_omitted = 0;
    for (mut record, largest) in [(named, "policy_revision"), (self_scoped, "resources")] {
        let row = row_start().row;
        let held = counted(&call_row_sizes(&row, &record)) - record.policy_revision.as_str().len();
        record.policy_revision = "r".repeat(MAX_BEGUN_ROW_BYTES - held).as_str().into();
        assert_eq!(counted(&call_row_sizes(&row, &record)), MAX_BEGUN_ROW_BYTES);
        if record.resources == RecordedResources::Unknown {
            assert!(call_row_sizes(&row, &record).contains(&("resources", MAX_REACHED_BYTES)));
        }
        store
            .begin(&row, &record)
            .await
            .expect("the store refused a call row at begin's bound");
        let at_bound = stored(contract, &row).await;
        assert_eq!(at_bound.record, StoredRecord::Call(record.clone()));
        assert_eq!(at_bound.completion, None);

        let over = AuditRecord {
            policy_revision: format!("{}r", record.policy_revision.as_str())
                .as_str()
                .into(),
            ..record
        };
        let row = row_start().row;
        let failure = store
            .begin(&row, &over)
            .await
            .expect_err("the store began a call row over begin's bound")
            .to_string();
        assert!(
            failure.contains(&format!(
                "would hold {} bytes, more than the {MAX_BEGUN_ROW_BYTES}",
                MAX_BEGUN_ROW_BYTES + 1
            )) && failure.ends_with(&format!("its largest column is {largest}")),
            "a call row over begin's bound was refused for another reason: {failure}"
        );
        assert_eq!(contract.stored(&row).await, None);
    }
}

/// Decision 0014, section 7: a list row of exactly the bound, [`MAX_ROW_BYTES`] as the store
/// counts it, the kind its statement writes included, is written and stored as the record. One
/// byte more is refused, naming the row's largest column, and leaves no row.
pub async fn a_list_row_over_the_bound_is_refused_naming_its_largest_column(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let row = row_start().row;
    let mut record = list_records().swap_remove(0);
    let held = counted(&list_row_sizes(&row, &record)) - record.deployment.as_str().len();
    record.deployment = "d".repeat(MAX_ROW_BYTES - held).as_str().into();
    assert_eq!(counted(&list_row_sizes(&row, &record)), MAX_ROW_BYTES);
    store
        .list(&row, &record)
        .await
        .expect("the store refused a list row at the bound");
    assert_eq!(
        stored(contract, &row).await.record,
        StoredRecord::List(record.clone())
    );

    let over = ListRecord {
        deployment: format!("{}d", record.deployment.as_str()).as_str().into(),
        ..record
    };
    let row = row_start().row;
    let failure = store
        .list(&row, &over)
        .await
        .expect_err("the store wrote a list row over the bound")
        .to_string();
    assert!(
        failure.contains(&format!(
            "would hold {} bytes, more than the {MAX_ROW_BYTES}",
            MAX_ROW_BYTES + 1
        )) && failure.ends_with("its largest column is deployment"),
        "a list row over the bound was refused for another reason: {failure}"
    );
    assert_eq!(contract.stored(&row).await, None);
}

/// A connector that refuses every call with one sentence.
struct RefusesWith(String);

impl Connector for RefusesWith {
    fn run(&self, _call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(std::future::ready(ToolOutcome::Refused(self.0.clone())))
    }
}

/// A refusal's sentence of [`MAX_OUTCOME_SENTENCE_BYTES`] is written whole at finish. One byte
/// longer is refused, not cut, as one holding U+0000 is: the finish fails, the caller gets the
/// audit-failure sentence, and the row is left open as begin wrote it.
pub async fn a_refusal_sentence_over_the_cap_is_refused_at_finish_and_leaves_the_row_open(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let whole = "w".repeat(MAX_OUTCOME_SENTENCE_BYTES);

    let start = row_start();
    let ran = audit::run(
        &RefusesWith(whole.clone()),
        guard(store, &fixture, &start, &ALLOWED).await,
    )
    .await;
    let finished = audit::finish(store, ran, 3).await;
    assert!(
        finished.failure().is_none(),
        "a sentence at the cap was refused: {:?}",
        finished.failure()
    );
    assert_eq!(
        stored(contract, &start.row).await.completion,
        Some(Completion {
            outcome: Outcome::Refused {
                sentence: whole.clone()
            },
            latency_ms: 3,
        })
    );

    let start = row_start();
    let guard = guard(store, &fixture, &start, &ALLOWED).await;
    let before = stored(contract, &start.row).await;
    let ran = audit::run(&RefusesWith(format!("{whole}o")), guard).await;
    let finished = audit::finish(store, ran, 3).await;
    let failure = finished
        .failure()
        .expect("a sentence over the cap was written")
        .to_string();
    assert!(
        failure.contains(&format!(
            "outcome_sentence would hold {} bytes, more than the {MAX_OUTCOME_SENTENCE_BYTES}",
            MAX_OUTCOME_SENTENCE_BYTES + 1
        )),
        "a sentence over the cap was refused for another reason: {failure}"
    );
    assert!(
        matches!(finished.answer(), Answer::AuditFailed { .. }),
        "{:?}",
        finished.answer()
    );
    assert_eq!(stored(contract, &start.row).await, before);
}

// --- Item 2: the reach and the credential identity ---------------------------------------------

/// A reach is stored as the connector entry it names, with nothing left out, as the core
/// records it for a tool declared as the reach (decision 0011, section 1), whether the call
/// was allowed or denied.
pub async fn a_reach_is_stored_as_the_entry_it_names(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    // Allowed, its reach more than a row names, every one within team A's limit; and denied.
    for (call, copies, decision) in [
        (&ALLOWED, MAX_RECORDED_RESOURCES + 3, DecisionKind::Allow),
        (&DENIED, 1, DecisionKind::Deny),
    ] {
        let context = CallContext {
            resources: Resources::Reach {
                entry: "entry-reach".into(),
                resources: vec![document(call.document); copies],
            },
            ..decision_context(&fixture, call)
        };
        let start = row_start();
        let _ = audit::begin(
            store,
            start.clone(),
            decide(&fixture.policy, &context),
            arguments(call),
            RequestMetadata::default(),
        )
        .await
        .expect("the store refused a reach");
        let StoredRecord::Call(record) = stored(contract, &start.row).await.record else {
            panic!("a call was not stored as one");
        };
        assert_eq!(record.decision, decision);
        assert_eq!(
            (record.resources, record.resources_omitted),
            (RecordedResources::Reach("entry-reach".into()), 0),
            "{call:?}"
        );
    }
}

/// A credential identity is stored as begin was given it, its mode and principal together, in
/// each mode, and a row given none stores none. Through the core, the identity the row start
/// carries is stored with the call it names, allowed or denied.
pub async fn a_credential_identity_is_stored_as_begin_was_given_it(contract: &impl ContractStore) {
    let store = contract.store();
    let base = records().swap_remove(0);
    for credential in [
        Some(CredentialIdentity {
            mode: CredentialMode::TeamServiceIdentity,
            principal: "docs-team-a".into(),
        }),
        Some(CredentialIdentity {
            mode: CredentialMode::GatewayToken,
            principal: "a token's \"holder\", \u{e9}".into(),
        }),
        Some(CredentialIdentity {
            mode: CredentialMode::PerUserGrant,
            principal: "per-user".into(),
        }),
        None,
    ] {
        let row = row_start().row;
        let written = AuditRecord {
            credential: credential.clone(),
            ..base.clone()
        };
        store
            .begin(&row, &written)
            .await
            .expect("the store refused a credential identity it can hold");
        assert_eq!(
            stored(contract, &row).await.record,
            StoredRecord::Call(written),
            "{credential:?}"
        );
    }

    let fixture = fixture();
    let identity = CredentialIdentity {
        mode: CredentialMode::TeamServiceIdentity,
        principal: "fixture-service".into(),
    };
    for call in [&ALLOWED, &DENIED] {
        let start = RowStart {
            credential: Some(identity.clone()),
            ..row_start()
        };
        let _ = begin(store, &fixture, &start, call, RequestMetadata::default())
            .await
            .expect("the store refused a row");
        let StoredRecord::Call(record) = stored(contract, &start.row).await.record else {
            panic!("a call was not stored as one");
        };
        assert_eq!(record.credential.as_ref(), Some(&identity), "{call:?}");
    }
}

/// What identifies a verified delegation, which check an unverified one failed with its digest
/// when its signature verified, the proved pod and the currency answer (decision 0012) are
/// stored as begin was given them, on a call row and, but for the failure and the currency, on
/// a list row. Through the core, a delegation that did not verify is stored by its failure and
/// digest alone, on the row check 3 denied.
pub async fn a_delegation_and_its_currency_are_stored_as_begin_was_given_them(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let records = records();
    let (allowed, denied) = (records[0].clone(), records[1].clone());
    let digest = DelegationDigest::of(b"a grant as presented");
    let verified = RecordedDelegation {
        digest,
        issuer: "otto-test".into(),
        key_id: "key-1".into(),
        session: "session-1".into(),
        turn: "turn \\\"one\\\"".into(),
        execution: "execution-1".into(),
        epoch: i64::MAX.unsigned_abs(),
        egress: Some(Egress::Open),
    };
    let mut with_pod = allowed.clone();
    with_pod.proved_principal = proved_with_pod(&allowed);
    let unverified = |failure: DelegationFailure, digest: Option<DelegationDigest>| AuditRecord {
        reason: Some(ReasonKind::DelegationUnverified),
        proved_delegation_team: None,
        claimed_acting_person: None,
        delegation_failure: Some(RecordedFailure { failure, digest }),
        ..denied.clone()
    };
    for written in [
        AuditRecord {
            delegation: Some(verified.clone()),
            currency: Some(CurrencyAnswer::Current),
            ..with_pod.clone()
        },
        AuditRecord {
            delegation: Some(RecordedDelegation {
                egress: None,
                epoch: 0,
                ..verified.clone()
            }),
            currency: Some(CurrencyAnswer::Unconfirmed),
            ..denied.clone()
        },
        AuditRecord {
            currency: Some(CurrencyAnswer::Revoked),
            ..allowed.clone()
        },
        unverified(DelegationFailure::WrongPod, Some(digest)),
        unverified(DelegationFailure::Signature, None),
        unverified(DelegationFailure::Expired, None),
    ] {
        let row = row_start().row;
        store
            .begin(&row, &written)
            .await
            .expect("the store refused a delegation it can hold");
        assert_eq!(
            stored(contract, &row).await.record,
            StoredRecord::Call(written.clone()),
            "{written:?}"
        );
    }

    let list = list_records().swap_remove(0);
    let listed = ListRecord {
        delegation: Some(verified.clone()),
        ..list.clone()
    };
    let row = row_start().row;
    store
        .list(&row, &listed)
        .await
        .expect("the store refused a list row's delegation");
    assert_eq!(
        stored(contract, &row).await.record,
        StoredRecord::List(listed)
    );

    let fixture = fixture();
    let mut context = decision_context(&fixture, &ALLOWED);
    context.caller.delegation = Some(
        UnverifiedDelegation::after_signature(DelegationFailure::WrongAudience, digest)
            .expect("an audience is checked after the signature")
            .into(),
    );
    context.currency = Currency::Asked(CurrencyAnswer::Current);
    let start = row_start();
    let begun = audit::begin(
        store,
        start.clone(),
        decide(&fixture.policy, &context),
        arguments(&ALLOWED),
        RequestMetadata::default(),
    )
    .await
    .expect("the store refused a denial at check 3");
    assert!(matches!(begun, Begun::Denied(_)), "{begun:?}");
    let StoredRecord::Call(record) = stored(contract, &start.row).await.record else {
        panic!("a call was not stored as one");
    };
    assert_eq!(record.reason, Some(ReasonKind::DelegationUnverified));
    assert_eq!(
        record.delegation_failure,
        Some(RecordedFailure {
            failure: DelegationFailure::WrongAudience,
            digest: Some(digest),
        })
    );
    assert_eq!(
        (
            &record.delegation,
            &record.proved_delegation_team,
            &record.claimed_acting_person
        ),
        (&None, &None, &None)
    );
    assert_eq!(record.currency, Some(CurrencyAnswer::Current));
}

/// A call carrying a delegation that did not verify, denied before check 3 at the profile, the
/// surface or the tool, is stored through the core as that denial alone: its reason is the
/// earlier check's, and the row records no failure, no digest and nothing of the delegation
/// (decision 0012). The failure belongs only on the row check 3 denied for it, and a store
/// refuses it anywhere else.
pub async fn an_unverified_delegation_denied_before_check_3_is_stored_as_that_denial_alone(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let digest = DelegationDigest::of(b"a grant as presented");
    let unverified = [
        UnverifiedDelegation::new(DelegationFailure::Signature),
        UnverifiedDelegation::after_signature(DelegationFailure::WrongPod, digest)
            .expect("a pod is checked after the signature"),
    ];
    // Each case: what it names, how it changes an allowed call, and the reason it is denied.
    type Earlier = (&'static str, fn(&mut CallContext), ReasonKind);
    let earlier: [Earlier; 4] = [
        (
            "an unknown profile",
            |context| context.caller.profile = UNKNOWN_PROFILE.into(),
            ReasonKind::ProfileUnknown,
        ),
        (
            "a surface that does not exist",
            |context| context.caller.surface = "no-such-surface".into(),
            ReasonKind::SurfaceNotPermitted,
        ),
        (
            "an unknown tool",
            |context| context.tool = RequestedTool::new("no_such__tool"),
            ReasonKind::UnknownTool,
        ),
        (
            "a tool its surface does not serve",
            |context| {
                context.caller.surface = SURFACE_READ.into();
                context.tool = RequestedTool::new(WRITE_TOOL);
            },
            ReasonKind::ToolNotOnSurface,
        ),
    ];
    for delegation in &unverified {
        for (case, change, reason) in &earlier {
            let mut context = decision_context(&fixture, &ALLOWED);
            context.caller.delegation = Some(delegation.clone().into());
            change(&mut context);
            let decided = decide(&fixture.policy, &context);
            assert_eq!(decided.reason().map(Reason::kind), Some(*reason), "{case}");
            let start = row_start();
            let begun = audit::begin(
                store,
                start.clone(),
                decided,
                arguments(&ALLOWED),
                RequestMetadata::default(),
            )
            .await
            .unwrap_or_else(|failure| panic!("{case}: the denial was not recorded: {failure:?}"));
            assert!(matches!(begun, Begun::Denied(_)), "{case}: {begun:?}");
            let StoredRecord::Call(record) = stored(contract, &start.row).await.record else {
                panic!("{case}: a call was not stored as one");
            };
            assert_eq!(record.reason, Some(*reason), "{case}");
            assert_eq!(
                (
                    &record.delegation_failure,
                    &record.delegation,
                    &record.proved_delegation_team,
                    &record.claimed_acting_person
                ),
                (&None, &None, &None, &None),
                "{case}"
            );
        }
    }
}

/// Decision 0011, section 9: an allowed call of a `write` tool records the exception in its
/// profile that let it past check 5, and the store keeps it as begun. A store refuses one
/// anywhere else, and leaves no row: on a denial, on an allowed read and on an allowed
/// proposal. Through the core, the exception is recorded on the row of an allowed call and on
/// the row of a reused key's answer, written complete at begin, and not on the row of a call
/// that check 5 let past by the exception and the currency check then denied. A list row has
/// no exception in the core; the Postgres schema tests try one there.
pub async fn an_exception_is_stored_on_an_allowed_write_and_refused_elsewhere(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let records = records();
    let (allowed, denied) = (records[0].clone(), records[1].clone());
    let exception = ExceptionName::parse("otto-comment-tools").expect("a valid exception name");
    for written in [
        AuditRecord {
            allowed_by_exception: Some(exception.clone()),
            ..allowed.clone()
        },
        AuditRecord {
            classification: Some(Classification::Destructive),
            allowed_by_exception: Some(exception.clone()),
            ..allowed.clone()
        },
    ] {
        let row = row_start().row;
        store
            .begin(&row, &written)
            .await
            .expect("the store refused an allowed write's exception");
        assert_eq!(
            stored(contract, &row).await.record,
            StoredRecord::Call(written.clone()),
            "{written:?}"
        );
    }
    for refused in [
        AuditRecord {
            allowed_by_exception: Some(exception.clone()),
            ..denied.clone()
        },
        AuditRecord {
            classification: Some(Classification::Read),
            allowed_by_exception: Some(exception.clone()),
            ..allowed.clone()
        },
        AuditRecord {
            classification: Some(Classification::Propose),
            allowed_by_exception: Some(exception.clone()),
            ..allowed.clone()
        },
    ] {
        let row = row_start().row;
        assert!(
            store.begin(&row, &refused).await.is_err(),
            "the store accepted {refused:?}"
        );
        assert_eq!(contract.stored(&row).await, None, "{refused:?}");
    }

    // Through the core: team A's profile requires currency and excepts the write tool, which
    // is settled by a lookup, as the loader requires.
    let fixture = fixture();
    let mut data = policy_data();
    for tool in data["tools"].as_array_mut().expect("the fixture's tools") {
        if tool["name"] == WRITE_TOOL {
            tool["settlement"] = draft_lookup();
        }
    }
    for profile in data["profiles"]
        .as_array_mut()
        .expect("the fixture's profiles")
    {
        if profile["name"] == PROFILE_TEAM_A {
            profile["requires_currency"] = json!(true);
            profile["exceptions"] = json!([{"name": exception.as_str(), "tools": [WRITE_TOOL]}]);
        }
    }
    let policy: PolicySnapshot = serde_json::from_value(data).expect("the excepting policy loads");
    let arguments = json!({ DOCUMENT_ARGUMENT: TEAM_A_DOCUMENT });
    let key = fresh_key();
    let context = |currency: Currency| CallContext {
        caller: fixture
            .caller_context(Caller::TeamA, SURFACE_ALL)
            .expect("the fixture knows team A"),
        tool: RequestedTool::new(WRITE_TOOL),
        resources: FixtureConnector::resources_of(WRITE_TOOL, &arguments),
        key: gateway_core::CallKey::Valid(key.clone()),
        currency,
    };
    let excepted = |row: &AuditRowId| {
        let row = row.clone();
        async move {
            match stored(contract, &row).await.record {
                StoredRecord::Call(record) => record.allowed_by_exception,
                StoredRecord::List(_) => panic!("a call was stored as a list"),
            }
        }
    };

    let start = row_start();
    let decided = decide(&policy, &context(Currency::NotAsked));
    assert_eq!(
        decided.reason().map(Reason::kind),
        Some(ReasonKind::CurrencyUnconfirmed)
    );
    let begun = begin_keyed(store, &start, decided, &arguments, Some(key.as_str()))
        .await
        .expect("the store refused a denial at the currency check");
    assert!(matches!(begun, Begun::Denied(_)), "{begun:?}");
    assert_eq!(excepted(&start.row).await, None);

    let start = row_start();
    let decided = decide(&policy, &context(Currency::Asked(CurrencyAnswer::Current)));
    assert_eq!(decided.exception(), Some(&exception));
    let Ok(Begun::Allowed(guard)) =
        begin_keyed(store, &start, decided, &arguments, Some(key.as_str())).await
    else {
        panic!("an excepted write was not begun as allowed");
    };
    assert_eq!(excepted(&start.row).await, Some(exception.clone()));
    let ran = audit::run(&Answering::with(ToolOutcome::Ok(json!({}))), guard).await;
    let finished = audit::finish(store, ran, 4).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());

    let reused = row_start();
    let decided = decide(&policy, &context(Currency::Asked(CurrencyAnswer::Current)));
    let begun = begin_keyed(store, &reused, decided, &arguments, Some(key.as_str()))
        .await
        .expect("the store refused a reused key");
    assert!(matches!(begun, Begun::Reused(_)), "{begun:?}");
    let answered = stored(contract, &reused.row).await;
    assert!(answered.completion.is_some(), "{answered:?}");
    assert_eq!(excepted(&reused.row).await, Some(exception));
}

/// `record`'s proved workload, with a pod.
fn proved_with_pod(record: &AuditRecord) -> WasProved<Principal> {
    let mut principal = record.proved_principal.get().clone();
    if let PrincipalKind::Workload { pod, .. } = &mut principal.kind {
        *pod = Some(PodUid::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("a pod UID"));
    }
    serde_json::from_value(serde_json::to_value(principal).expect("a principal is JSON"))
        .expect("a principal reads back as was proved")
}

/// A row whose delegation columns break decision 0012's shape is refused at begin, and leaves
/// no row: a failure beside anything from the delegation's claims, a failure with a digest found
/// before the signature verified, a failure on a row check 3 did not deny for it, a denial at
/// check 3 with no failure, a verified delegation without its team or person, and an epoch past
/// a Postgres `bigint`. So is a list row with a verified delegation without its team or person.
pub async fn a_delegation_of_the_wrong_shape_is_refused_and_leaves_no_row(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let records = records();
    let (allowed, denied) = (records[0].clone(), records[1].clone());
    let digest = DelegationDigest::of(b"a grant as presented");
    let verified = RecordedDelegation {
        digest,
        issuer: "otto-test".into(),
        key_id: "key-1".into(),
        session: "session-1".into(),
        turn: "turn-1".into(),
        execution: "execution-1".into(),
        epoch: 7,
        egress: None,
    };
    let failure = |failure: DelegationFailure, digest: Option<DelegationDigest>| {
        Some(RecordedFailure { failure, digest })
    };
    let at_check_3 = AuditRecord {
        reason: Some(ReasonKind::DelegationUnverified),
        proved_delegation_team: None,
        claimed_acting_person: None,
        delegation_failure: failure(DelegationFailure::Signature, None),
        ..denied.clone()
    };
    let cannot_hold = [
        // Something from the delegation's claims beside its failure.
        AuditRecord {
            claimed_acting_person: denied.claimed_acting_person.clone(),
            ..at_check_3.clone()
        },
        AuditRecord {
            proved_delegation_team: denied.proved_delegation_team.clone(),
            ..at_check_3.clone()
        },
        AuditRecord {
            delegation: Some(verified.clone()),
            proved_delegation_team: denied.proved_delegation_team.clone(),
            claimed_acting_person: denied.claimed_acting_person.clone(),
            ..at_check_3.clone()
        },
        // A digest for a failure found before the signature verified.
        AuditRecord {
            delegation_failure: failure(DelegationFailure::Signature, Some(digest)),
            ..at_check_3.clone()
        },
        AuditRecord {
            delegation_failure: failure(DelegationFailure::Malformed, Some(digest)),
            ..at_check_3.clone()
        },
        // A failure on a row check 3 did not deny for it, and such a denial with none.
        AuditRecord {
            reason: Some(ReasonKind::ClassificationNotPermitted),
            ..at_check_3.clone()
        },
        AuditRecord {
            proved_delegation_team: None,
            claimed_acting_person: None,
            delegation_failure: failure(DelegationFailure::Expired, Some(digest)),
            ..allowed.clone()
        },
        AuditRecord {
            delegation_failure: None,
            ..at_check_3.clone()
        },
        // A verified delegation without its team or its person.
        AuditRecord {
            delegation: Some(verified.clone()),
            proved_delegation_team: None,
            ..allowed.clone()
        },
        AuditRecord {
            delegation: Some(verified.clone()),
            claimed_acting_person: None,
            ..allowed.clone()
        },
        // An epoch past a bigint.
        AuditRecord {
            delegation: Some(RecordedDelegation {
                epoch: u64::MAX,
                ..verified.clone()
            }),
            ..allowed.clone()
        },
    ];
    for record in &cannot_hold {
        let row = row_start().row;
        let begun = store.begin(&row, record).await;
        assert!(begun.is_err(), "the store accepted {record:?}");
        assert_eq!(contract.stored(&row).await, None, "{record:?}");
    }

    let list = list_records().swap_remove(0);
    for record in [
        ListRecord {
            delegation: Some(verified.clone()),
            proved_delegation_team: None,
            ..list.clone()
        },
        ListRecord {
            delegation: Some(verified.clone()),
            claimed_acting_person: None,
            ..list.clone()
        },
    ] {
        let row = row_start().row;
        assert!(store.list(&row, &record).await.is_err(), "{record:?}");
        assert_eq!(contract.stored(&row).await, None, "{record:?}");
    }
}

/// A second begin under a stored row's identifier compares the decision and nothing more, as
/// [`begin_is_ok_only_once_stored_and_idempotent_by_identifier`] says: one with the same
/// decision and another reach, other resources, another credential identity or none is
/// accepted and changes nothing. One with another decision is refused, and the row stands.
pub async fn a_repeated_begin_compares_the_decision_and_not_the_reach_or_credential(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let first = records()
        .into_iter()
        .find(|record| matches!(record.resources, RecordedResources::Reach(_)))
        .expect("a record names a reach");
    assert!(first.credential.is_some(), "the record has no credential");
    let row = row_start().row;
    store
        .begin(&row, &first)
        .await
        .expect("the store refused the first begin");
    let stored_first = stored(contract, &row).await;

    for repeat in [
        AuditRecord {
            resources: RecordedResources::Reach("another-entry".into()),
            ..first.clone()
        },
        AuditRecord {
            resources: RecordedResources::Named(Vec::new()),
            ..first.clone()
        },
        AuditRecord {
            credential: Some(CredentialIdentity {
                mode: CredentialMode::GatewayToken,
                principal: "another-principal".into(),
            }),
            ..first.clone()
        },
        AuditRecord {
            credential: None,
            ..first.clone()
        },
    ] {
        store
            .begin(&row, &repeat)
            .await
            .expect("a repeat with the same decision was refused");
        assert_eq!(
            stored(contract, &row).await,
            stored_first,
            "a repeat changed the stored row"
        );
    }
    let denial = AuditRecord {
        decision: DecisionKind::Deny,
        reason: Some(gateway_core::ReasonKind::UnknownTool),
        sentence: Some("Denied.".into()),
        ..first.clone()
    };
    assert!(
        store.begin(&row, &denial).await.is_err(),
        "a repeat with another decision was accepted"
    );
    assert_eq!(stored(contract, &row).await, stored_first);
}

// --- Item 3: finish -----------------------------------------------------------------------------

/// `finish` completes a row once. An identical repeat is accepted and changes nothing; a
/// different completion, by outcome or by latency, or a guard given up for a row already
/// complete, is refused with a returned error, and the first completion stands.
pub async fn finish_completes_once_accepts_an_identical_repeat_and_refuses_a_different_one(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let connector = connector();
    let start = row_start();

    let ran = audit::run(&connector, guard(store, &fixture, &start, &ALLOWED).await).await;
    let finished = audit::finish(store, ran, 17).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    let first = stored(contract, &start.row).await;
    assert_eq!(
        first.completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 17,
        })
    );

    // The same completion again: a guard for the same row, from a retried begin.
    let ran = audit::run(&connector, guard(store, &fixture, &start, &ALLOWED).await).await;
    let finished = audit::finish(store, ran, 17).await;
    assert!(
        finished.failure().is_none(),
        "an identical repeat was refused: {:?}",
        finished.failure()
    );
    assert_eq!(stored(contract, &start.row).await, first);

    for (fails, latency_ms) in [(false, 18), (true, 17)] {
        if fails {
            connector.fail_next();
        }
        let ran = audit::run(&connector, guard(store, &fixture, &start, &ALLOWED).await).await;
        let finished = audit::finish(store, ran, latency_ms).await;
        assert!(
            finished.failure().is_some(),
            "a different completion was accepted: failed {fails}, latency {latency_ms}"
        );
        assert_eq!(stored(contract, &start.row).await, first);
    }
    let gave_up = audit::give_up(store, guard(store, &fixture, &start, &ALLOWED).await).await;
    assert!(
        gave_up.failure().is_some(),
        "a guard given up completed a row already complete"
    );
    assert_eq!(stored(contract, &start.row).await, first);
}

/// `finish` writes the completion and nothing else: the record, its kind, its time at begin
/// and its deadline are as begin left them, for each outcome, and for a row that left some of
/// its resources out.
pub async fn finish_touches_only_the_completion(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let connector = connector();
    let stated = RequestMetadata {
        tool_use_id: Some(ToolUseId::new("toolu_contract")),
        claimed_team: Some(Claimed::new(TeamId::new("team-claimed"))),
    };
    for (call, metadata, fails, latency_ms) in [
        (&ALLOWED, stated, false, 23),
        (&ALLOWED, RequestMetadata::default(), true, 0),
        (&REFUSED_BY_CONNECTOR, RequestMetadata::default(), false, 9),
    ] {
        let start = row_start();
        let guard = match begin(store, &fixture, &start, call, metadata).await {
            Ok(Begun::Allowed(guard)) => guard,
            other => panic!("{call:?} was not begun as allowed: {other:?}"),
        };
        if fails {
            connector.fail_next();
        }
        finish_touches_only_its_completion(contract, &connector, guard, latency_ms).await;
    }

    // Team A may reach more documents than a row names, and the call names them all.
    let named: Vec<Resource> = (0..MAX_RECORDED_RESOURCES + 3)
        .map(|n| document(&format!("team-a-{n}")))
        .collect();
    let mut data = policy_data();
    data["limits"]["teams"][TEAM_A] =
        serde_json::to_value(&named).expect("the documents are a limit");
    let mut wide = Fixture::new().expect("the fixture builds");
    wide.policy = serde_json::from_value(data).expect("the policy is well formed");
    let context = CallContext {
        caller: wide
            .caller_context(Caller::TeamA, SURFACE_ALL)
            .expect("the fixture knows team A"),
        tool: RequestedTool::new(READ_TOOL),
        resources: Resources::Named(named),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    let begun = audit::begin(
        store,
        row_start(),
        decide(&wide.policy, &context),
        json!({ DOCUMENT_ARGUMENT: "team-a-0" }),
        RequestMetadata::default(),
    )
    .await;
    let Ok(Begun::Allowed(guard)) = begun else {
        panic!("a call naming its own documents was not begun as allowed: {begun:?}");
    };
    let StoredRecord::Call(record) = stored(contract, guard.row()).await.record else {
        panic!("a call was not stored as one");
    };
    assert_eq!(record.resources_omitted, 3);
    finish_touches_only_its_completion(contract, &connector, guard, 5).await;
}

/// Runs and finishes `guard`, and checks that the row afterwards is the row before with the
/// completion the core wrote.
async fn finish_touches_only_its_completion(
    contract: &impl ContractStore,
    connector: &FixtureConnector,
    guard: AuditGuard,
    latency_ms: u64,
) {
    let row = guard.row().clone();
    let before = stored(contract, &row).await;
    let ran = audit::run(connector, guard).await;
    let finished = audit::finish(contract.store(), ran, latency_ms).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    let outcome = match finished.answer() {
        Answer::Ok(_) => Outcome::Ok,
        // The fixture connector fails with no other kind.
        Answer::Error(_) => Outcome::Error {
            error_kind: ErrorKind::Other,
        },
        Answer::Refused(sentence) => Outcome::Refused {
            sentence: sentence.clone(),
        },
        Answer::Unknown(_) => Outcome::Unknown,
        Answer::AuditFailed { .. } => panic!("{:?}", finished.answer()),
    };
    let completion = Completion {
        outcome,
        latency_ms,
    };
    let StoredRecord::Call(record) = before.record.clone() else {
        panic!("a call was stored as {:?}", before.record);
    };
    let expected = StoredRow {
        record: StoredRecord::Call(AuditRecord {
            completion: Some(completion.clone()),
            ..record
        }),
        completion: Some(completion),
        ..before
    };
    assert_eq!(stored(contract, &row).await, expected);
}

/// A connector that fails every call with one kind of error.
struct FailsWith(ErrorKind);

impl Connector for FailsWith {
    fn run(&self, _call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(std::future::ready(ToolOutcome::error(
            self.0,
            "the contract's connector fails on purpose",
        )))
    }
}

/// Every kind of error is stored with its outcome and read back as it was written. A repeat of
/// the same error is accepted; an error of another kind, with the same latency, is refused with
/// a returned error, and the first completion stands.
pub async fn an_error_is_stored_with_its_kind_and_a_repeat_must_match_it(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let kinds = [
        ErrorKind::InvalidArguments,
        ErrorKind::OversizedOrLateRead,
        ErrorKind::CustodianRefusal,
        ErrorKind::VendorRefusal,
        ErrorKind::Other,
    ];
    for kind in kinds {
        let start = row_start();
        let ran = audit::run(
            &FailsWith(kind),
            guard(store, &fixture, &start, &ALLOWED).await,
        )
        .await;
        let finished = audit::finish(store, ran, 7).await;
        assert!(
            finished.failure().is_none(),
            "{kind:?}: {:?}",
            finished.failure()
        );
        let completion = Some(Completion {
            outcome: Outcome::Error { error_kind: kind },
            latency_ms: 7,
        });
        let row = stored(contract, &start.row).await;
        assert_eq!(row.completion, completion, "{kind:?}");
        let StoredRecord::Call(record) = row.record else {
            panic!("a call was not stored as one");
        };
        assert_eq!(record.completion, completion, "{kind:?}");
    }

    let start = row_start();
    let refusal = FailsWith(ErrorKind::VendorRefusal);
    let ran = audit::run(&refusal, guard(store, &fixture, &start, &ALLOWED).await).await;
    assert!(audit::finish(store, ran, 7).await.failure().is_none());
    let first = stored(contract, &start.row).await;
    let ran = audit::run(&refusal, guard(store, &fixture, &start, &ALLOWED).await).await;
    let finished = audit::finish(store, ran, 7).await;
    assert!(
        finished.failure().is_none(),
        "an identical repeat was refused: {:?}",
        finished.failure()
    );
    assert_eq!(stored(contract, &start.row).await, first);
    for kind in kinds
        .into_iter()
        .filter(|kind| *kind != ErrorKind::VendorRefusal)
    {
        let ran = audit::run(
            &FailsWith(kind),
            guard(store, &fixture, &start, &ALLOWED).await,
        )
        .await;
        let finished = audit::finish(store, ran, 7).await;
        assert!(
            finished.failure().is_some(),
            "an error of the kind {kind:?} completed a vendor refusal's row again"
        );
        assert_eq!(stored(contract, &start.row).await, first);
    }
}

/// Allowed, and its tool checks its own scope, so its resources are unknown until it runs.
const SELF_SCOPED: Call = Call {
    caller: Caller::TeamA,
    surface: SURFACE_READ,
    tool: SCOPED_READ_TOOL,
    document: TEAM_A_DOCUMENT,
};

/// Decision 0011: the resources a tool that checks its own scope reports it reached replace the
/// `unknown` its row was begun with, in the same write as the completion, and nothing else of
/// the row changes. They are recorded as begin records named ones: the first 64 distinct, with
/// the rest counted. An empty report is stored as an empty list, not as `unknown`. A repeat is
/// compared on its completion alone, as Postgres's role cannot read what a call named: one that
/// reports another reach is accepted, and the first stands.
pub async fn what_a_self_scoped_tool_reached_replaces_its_unknown_resources_at_finish(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let reached: Vec<Resource> = (0..MAX_RECORDED_RESOURCES + 2)
        .map(|n| document(&format!("team-a-{n}")))
        .collect();
    for (reached, omitted) in [(reached, 2), (Vec::new(), 0)] {
        let start = row_start();
        let begun = guard(store, &fixture, &start, &SELF_SCOPED).await;
        let before = stored(contract, &start.row).await;
        let StoredRecord::Call(record) = before.record.clone() else {
            panic!("a call was stored as {:?}", before.record);
        };
        assert_eq!(record.resources, RecordedResources::Unknown);
        let answering = Answering::with(ToolOutcome::Reached(json!({"found": 1}), reached.clone()));
        let finished = audit::finish(store, audit::run(&answering, begun).await, 6).await;
        assert!(finished.failure().is_none(), "{:?}", finished.failure());
        assert_eq!(finished.answer(), &Answer::Ok(json!({"found": 1})));
        let completion = Completion {
            outcome: Outcome::Ok,
            latency_ms: 6,
        };
        let recorded = reached
            .iter()
            .take(MAX_RECORDED_RESOURCES)
            .map(|resource| RecordedResource {
                system: resource.system.clone(),
                kind: resource.kind.clone(),
                identifier: resource.identifier.clone(),
            })
            .collect();
        let expected = StoredRow {
            record: StoredRecord::Call(AuditRecord {
                resources: RecordedResources::Named(recorded),
                resources_omitted: omitted,
                completion: Some(completion.clone()),
                ..record
            }),
            completion: Some(completion),
            ..before
        };
        assert_eq!(stored(contract, &start.row).await, expected);

        // The same completion again, from a retried begin, reporting a narrower reach.
        let begun = guard(store, &fixture, &start, &SELF_SCOPED).await;
        let answering = Answering::with(ToolOutcome::Reached(json!({"found": 1}), Vec::new()));
        let finished = audit::finish(store, audit::run(&answering, begun).await, 6).await;
        assert!(
            finished.failure().is_none(),
            "a repeat of the completion was refused for its reach: {:?}",
            finished.failure()
        );
        assert_eq!(stored(contract, &start.row).await, expected);
    }
}

/// Decision 0011: a tool not declared `checks_own_scope` may not report what it reached. The
/// row is completed as an error of the kind `other` with the resources begin recorded, and
/// nothing of the report is stored.
pub async fn a_report_of_what_was_reached_from_another_tool_is_stored_as_an_error(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let start = row_start();
    let begun = guard(store, &fixture, &start, &ALLOWED).await;
    let before = stored(contract, &start.row).await;
    let answering = Answering::with(ToolOutcome::Reached(
        json!({"found": 1}),
        vec![document(TEAM_B_DOCUMENT)],
    ));
    let finished = audit::finish(store, audit::run(&answering, begun).await, 3).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert!(
        matches!(finished.answer(), Answer::Error(_)),
        "{:?}",
        finished.answer()
    );
    let completion = Completion {
        outcome: Outcome::Error {
            error_kind: ErrorKind::Other,
        },
        latency_ms: 3,
    };
    let StoredRecord::Call(record) = before.record.clone() else {
        panic!("a call was stored as {:?}", before.record);
    };
    let expected = StoredRow {
        record: StoredRecord::Call(AuditRecord {
            completion: Some(completion.clone()),
            ..record
        }),
        completion: Some(completion),
        ..before
    };
    assert_eq!(stored(contract, &start.row).await, expected);
}

// --- Item 4: the deadline -----------------------------------------------------------------------

/// The span Postgres's `set_times` adds to a call row's time at begin for an allowance:
/// `allowance_ms * interval '1 millisecond'`. The `bigint` is cast to `float8` and multiplied
/// by the interval's 1000 microseconds in `float8`, so past 2^53 microseconds the span is the
/// nearest `float8` to the exact one, a few microseconds off it.
fn postgres_span(allowance_ms: u64) -> Duration {
    // At these sizes the product is a whole number, and below 2^64.
    Duration::from_micros((1000.0 * allowance_ms as f64) as u64)
}

/// The end of what a Postgres time holds, 294277-01-01 00:00:00 UTC, which is itself out of
/// range: 9,223,371,331,200,000,000 microseconds after the Postgres epoch, 2000-01-01 UTC.
fn postgres_end() -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(946_684_800_000_000 + 9_223_371_331_200_000_000)
}

/// Each row of kind `call`, allowed or denied, has a time at begin from the store's clock, and a
/// deadline the store sets: its time at begin plus the begin budget, the call deadline, the
/// finish deadline and the answer budget, each budget in whole milliseconds, added as Postgres
/// adds them. A deadline at the end of what a Postgres time holds is refused, and leaves no
/// row. The edge cases pick a call deadline for the allowance they need, so they reach the same
/// allowances whatever the budgets.
pub async fn the_deadline_is_the_begin_time_plus_begin_budget_call_deadline_finish_deadline_and_answer_budget(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let budgets = contract.budgets();
    let budgets_ms = budgets_ms(&budgets);
    for (call, call_deadline_ms) in [
        (&ALLOWED, crate::FIXTURE_CALL_DEADLINE_MS),
        (&DENIED, crate::FIXTURE_CALL_DEADLINE_MS),
        (&ALLOWED, 0),
        (&ALLOWED, 1),
        (&DENIED, 7 * 86_400_000 + 3),
        // An odd allowance whose span in microseconds is past 2^56, where a `float8` holds
        // only multiples of 16: Postgres's span is 8 microseconds off the exact one.
        (&ALLOWED, 100_000_000_000_001 - budgets_ms),
    ] {
        let start = RowStart {
            call_deadline_ms,
            ..row_start()
        };
        let before = contract.now().await;
        let _ = begin(store, &fixture, &start, call, RequestMetadata::default())
            .await
            .expect("begin");
        let after = contract.now().await;
        let stored = stored(contract, &start.row).await;
        let begun_at = stored.begun_at.expect("the row has no time at begin");
        assert!(
            before <= begun_at && begun_at <= after,
            "the time at begin is not from the store's clock: {begun_at:?} is not between \
             {before:?} and {after:?}"
        );
        assert!(stored.deadline_set, "{stored:?}");
        let allowance = budgets_ms + call_deadline_ms;
        assert_eq!(
            stored.deadline_after_begin,
            Some(postgres_span(allowance)),
            "{call:?} with a call deadline of {call_deadline_ms} ms"
        );
    }
    assert_eq!(
        postgres_span(100_000_000_000_001),
        Duration::from_micros(100_000_000_000_000_992),
        "Postgres's span is not the float8 product"
    );

    // The smallest allowance whose deadline, counted from a time read before the begin, is at
    // or past the end. The row is begun at that time or later, so its deadline is too. On a
    // clock that stands still, as the in-memory runner's does, the deadline is the end itself
    // where some allowance reaches it exactly.
    let before = contract.now().await;
    let room = postgres_end()
        .duration_since(before)
        .expect("the store's clock is past the end of a Postgres time");
    let (mut short, mut enough) = (0, u64::MAX / 1000);
    while enough - short > 1 {
        let middle = short + (enough - short) / 2;
        if postgres_span(middle) >= room {
            enough = middle;
        } else {
            short = middle;
        }
    }
    let start = RowStart {
        call_deadline_ms: enough - budgets_ms,
        ..row_start()
    };
    let begun = begin(
        store,
        &fixture,
        &start,
        &ALLOWED,
        RequestMetadata::default(),
    )
    .await;
    assert!(
        begun.is_err(),
        "a deadline {:?} past the end of a Postgres time was written",
        postgres_span(enough) - room
    );
    assert_eq!(contract.stored(&start.row).await, None);
}

// --- Item 5: list rows --------------------------------------------------------------------------

fn list_records() -> Vec<ListRecord> {
    let every = json!({
        "instance": "gateway-7f9c",
        "deployment": "fixture",
        "surface": "fixture-read",
        "profile": "user-ro",
        "policy_revision": "fixture-1",
        "proved_principal": {
            "id": {"issuer": "https://user-issuer.fixture.test", "subject": "user-1"},
            "kind": "user",
            "groups": ["group-g", "group-h"]
        },
        "proved_delegation_team": "team-d",
        "claimed_acting_person": "person@fixture.test",
        "claimed_team": "team-c",
        "tools": ["fixture__read", "back\\\\slash\\n"],
        "tools_omitted": 7
    });
    let many = json!({
        "instance": "gateway-many",
        "deployment": "fixture",
        "surface": "fixture-all",
        "profile": "workload-propose",
        "policy_revision": "fixture-2",
        "proved_principal": {
            "id": {"issuer": "https://workload-issuer.fixture.test", "subject": "sa"},
            "kind": "workload",
            "team": "team-a"
        },
        "proved_delegation_team": null,
        "claimed_acting_person": null,
        "claimed_team": null,
        "tools": (0..64).map(|n| format!("fixture__t{n}")).collect::<Vec<_>>(),
        "tools_omitted": 136
    });
    let none = json!({
        "instance": "gateway-none",
        "deployment": "fixture",
        "surface": "fixture-all",
        "profile": "workload-ro",
        "policy_revision": "fixture-3",
        "proved_principal": {
            "id": {"issuer": "https://workload-issuer.fixture.test", "subject": "sb"},
            "kind": "workload",
            "team": "team-b"
        },
        "proved_delegation_team": null,
        "claimed_acting_person": null,
        "claimed_team": null,
        "tools": [],
        "tools_omitted": 0
    });
    [every, many, none]
        .into_iter()
        .map(|value| serde_json::from_value(value).expect("the list record is well formed"))
        .collect()
}

/// A list row is stored exactly as the list record, of kind `list`, complete: with a time at
/// begin from the store's clock, no completion and no deadline. A second list under its
/// identifier returns `Ok` and changes nothing, whatever it records. A begin under a list row's
/// identifier, and a list under a call row's, are refused, and the stored row stands. A finish
/// naming a list row is refused as `complete_once` refuses it, as a listing, and the row stands.
pub async fn a_list_row_is_stored_complete_with_no_deadline(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let records = list_records();
    for (position, written) in records.iter().enumerate() {
        let row = row_start().row;
        let before = contract.now().await;
        store.list(&row, written).await.expect("list");
        let after = contract.now().await;
        let first = stored(contract, &row).await;
        let begun_at = first.begun_at.expect("the list row has no time at begin");
        assert!(
            before <= begun_at && begun_at <= after,
            "the list row's time at begin is not from the store's clock: {begun_at:?} is not \
             between {before:?} and {after:?}"
        );
        let expected = StoredRow {
            record: StoredRecord::List(written.clone()),
            kind: RowKind::List,
            completion: None,
            begun_at: first.begun_at,
            deadline_set: false,
            deadline_after_begin: None,
        };
        assert_eq!(first, expected);

        let other = &records[(position + 1) % records.len()];
        store.list(&row, other).await.expect("a retried list");
        assert_eq!(stored(contract, &row).await, expected, "a retried list");

        let start = RowStart {
            row: row.clone(),
            ..row_start()
        };
        let begun = begin(
            store,
            &fixture,
            &start,
            &ALLOWED,
            RequestMetadata::default(),
        )
        .await;
        assert!(
            begun.is_err(),
            "a call was begun under a list row's identifier"
        );
        assert_eq!(stored(contract, &row).await, expected);
    }

    let start = row_start();
    let _ = guard(store, &fixture, &start, &ALLOWED).await;
    let call = stored(contract, &start.row).await;
    let listed = store.list(&start.row, &records[0]).await;
    assert!(
        listed.is_err(),
        "a list was written under a call row's identifier"
    );
    assert_eq!(stored(contract, &start.row).await, call);

    // A guard for an identifier the store then lists under. The store refuses a begin under a
    // list row's identifier, so the guard is begun on another store, which only hands it out.
    let start = row_start();
    let guard = guard(&InMemoryAuditStore::new(), &fixture, &start, &ALLOWED).await;
    store.list(&start.row, &records[0]).await.expect("list");
    let listed = stored(contract, &start.row).await;
    let ran = audit::run(&connector(), guard).await;
    let failure = audit::finish(store, ran, 7)
        .await
        .failure()
        .expect("a list row was completed")
        .to_string();
    // complete_once's words: the row is there, and records a listing.
    assert!(
        failure.contains("records a listing"),
        "a finish naming a list row was refused for another reason: {failure}"
    );
    assert_eq!(stored(contract, &start.row).await, listed);
}

/// A call record of kind `list` handed to begin is refused, as the Postgres table's
/// `kind_shape` refuses a row of kind `list` with a call's columns, and leaves no row. That
/// holds for an allowed record and a denied one, and under the identifier of a call row already
/// stored with the same decision, which stands: Postgres checks the row before it looks for
/// one stored under its identifier.
pub async fn a_call_record_of_kind_list_is_refused_at_begin_and_leaves_no_row(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    for written in records() {
        let record = AuditRecord {
            kind: RowKind::List,
            ..written.clone()
        };
        let row = row_start().row;
        let failure = store
            .begin(&row, &record)
            .await
            .expect_err("a call record of kind list was begun")
            .to_string();
        assert!(
            failure.contains("kind_shape"),
            "a call record of kind list was refused for another reason: {failure}"
        );
        assert_eq!(contract.stored(&row).await, None, "{record:?}");

        store
            .begin(&row, &written)
            .await
            .expect("the store refused a record it can hold");
        let first = stored(contract, &row).await;
        let failure = store
            .begin(&row, &record)
            .await
            .expect_err("a call record of kind list was begun under a call row's identifier")
            .to_string();
        assert!(
            failure.contains("kind_shape"),
            "a call record of kind list was refused for another reason: {failure}"
        );
        assert_eq!(stored(contract, &row).await, first);
    }
}

// --- Item 6: receipts ---------------------------------------------------------------------------

/// A connector that answers every call with one outcome, and counts its calls.
struct Answering {
    outcome: ToolOutcome,
    calls: AtomicUsize,
}

impl Answering {
    fn with(outcome: ToolOutcome) -> Self {
        Self {
            outcome,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Connector for Answering {
    fn run(&self, _call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(self.outcome.clone()))
    }
}

/// Proves a delegation exactly as it is given. The contract suite's own, for item 6's scope
/// case and the delegation columns: the fixture has no delegation verifier. Every
/// `impl Verifier` creates proof, so it is private to this module and used only there.
struct DelegationAsGiven;

/// Team A's delegation for `turn` of one session and execution, listing the draft tool, as
/// [`DelegationAsGiven`] proves it. Its digest is of the turn's name.
fn turn_delegation(turn: &str) -> PresentedDelegation {
    let delegation = Delegation {
        acting_person: Claimed::new("requester@example.test".into()),
        team: TEAM_A.into(),
        tools: [DRAFT_TOOL.parse().expect("a valid tool name")].into(),
        issuer: "otto-test".into(),
        digest: DelegationDigest::of(turn.as_bytes()),
        key_id: "key-1".into(),
        session: "session-1".into(),
        turn: turn.into(),
        execution: "execution-1".into(),
        epoch: 7,
        egress: Some(Egress::Sealed),
    };
    PresentedDelegation::Verified(match Proved::verify(&DelegationAsGiven, &delegation) {
        Ok(proved) => proved,
        Err(never) => match never {},
    })
}

impl Verifier for DelegationAsGiven {
    type Evidence = Delegation;
    type Fact = Delegation;
    type Error = Infallible;

    fn verify(&self, evidence: &Delegation) -> Result<Delegation, Infallible> {
        Ok(evidence.clone())
    }
}

/// Proves a principal exactly as it is given, for item 6's key-scope case: the fixture's
/// issuer names no principal that long. Private to this module, as [`DelegationAsGiven`] is.
struct PrincipalAsGiven;

impl Verifier for PrincipalAsGiven {
    type Evidence = Principal;
    type Fact = Principal;
    type Error = Infallible;

    fn verify(&self, evidence: &Principal) -> Result<Principal, Infallible> {
        Ok(evidence.clone())
    }
}

/// `length` letters and digits from `seed`, in no pattern Postgres's compression of a long
/// value finds, so a value at a cap is held at its full length in an index entry.
fn incompressible(length: usize, seed: u64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let size = u64::try_from(ALPHABET.len()).expect("the alphabet is short");
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = usize::try_from(state % size).expect("an index into the alphabet");
            char::from(ALPHABET[at])
        })
        .collect()
}

/// A proposal: team A calls the draft tool on its own document, with `text`.
fn proposal(text: &str) -> Value {
    json!({ DOCUMENT_ARGUMENT: TEAM_A_DOCUMENT, "text": text })
}

/// A proposal by team A carrying `key`, as its tool-use identifier says, decided.
fn keyed_proposal(fixture: &Fixture, arguments: &Value, key: Option<&IdempotencyKey>) -> Decision {
    keyed_decision(
        fixture,
        fixture
            .caller_context(Caller::TeamA, SURFACE_ALL)
            .expect("the fixture knows team A"),
        arguments,
        key,
    )
}

fn keyed_decision(
    fixture: &Fixture,
    caller: CallerContext,
    arguments: &Value,
    key: Option<&IdempotencyKey>,
) -> Decision {
    let context = CallContext {
        caller,
        tool: RequestedTool::new(DRAFT_TOOL),
        resources: FixtureConnector::resources_of(DRAFT_TOOL, arguments),
        key: key.cloned().into(),
        currency: gateway_core::Currency::NotAsked,
    };
    decide(&fixture.policy, &context)
}

/// Begins `decision` as the row `start` names, with `arguments` and the tool-use identifier
/// `tool_use_id`.
async fn begin_keyed(
    store: &dyn AuditStore,
    start: &RowStart,
    decision: Decision,
    arguments: &Value,
    tool_use_id: Option<&str>,
) -> Result<Begun, AuditFailure> {
    audit::begin(
        store,
        start.clone(),
        decision,
        arguments.clone(),
        RequestMetadata {
            tool_use_id: tool_use_id.map(ToolUseId::from),
            claimed_team: None,
        },
    )
    .await
}

/// The guard of team A's proposal with `arguments` under `key`, which must be allowed, begun as
/// the row `start` names with `key` as its tool-use identifier.
async fn proposal_guard(
    store: &dyn AuditStore,
    fixture: &Fixture,
    start: &RowStart,
    arguments: &Value,
    key: &IdempotencyKey,
) -> AuditGuard {
    let decision = keyed_proposal(fixture, arguments, Some(key));
    match begin_keyed(store, start, decision, arguments, Some(key.as_str())).await {
        Ok(Begun::Allowed(guard)) => guard,
        other => panic!("a keyed proposal was not begun as allowed: {other:?}"),
    }
}

/// The receipts the store holds whose key is `key`.
async fn receipts_for(contract: &impl ContractStore, key: &IdempotencyKey) -> Vec<Receipt> {
    let mut found: Vec<Receipt> = contract
        .receipts()
        .await
        .into_iter()
        .filter(|receipt| receipt.key == *key)
        .collect();
    found.sort_by(|one, other| one.row.as_str().cmp(other.row.as_str()));
    found
}

/// The one receipt reserved under `row`, which there must be.
async fn receipt_under(contract: &impl ContractStore, row: &AuditRowId) -> Receipt {
    let mut found: Vec<Receipt> = contract
        .receipts()
        .await
        .into_iter()
        .filter(|receipt| receipt.row == *row)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{} receipts are reserved under {}",
        found.len(),
        row.as_str()
    );
    found.remove(0)
}

/// A receipt is reserved with its row or not at all (decision 0009, "How it is tested", item
/// 6). An allowed side effect's begin stores its row open and a `pending` receipt under it,
/// holding the scope, the proved principal's team, the key, tool, tool-use identifier, digest
/// and resources of the call. A
/// begin the store refuses writes neither. A denial writes its row and reserves nothing, even
/// with a key, and so uses up no key; nor does a read.
pub async fn a_receipt_is_reserved_with_its_row_or_not_at_all(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("A first proposal.");

    let start = row_start();
    let _ = proposal_guard(store, &fixture, &start, &arguments, &key).await;
    let row = stored(contract, &start.row).await;
    let StoredRecord::Call(record) = &row.record else {
        panic!("a call was stored as {:?}", row.record);
    };
    assert_eq!(
        (row.completion.as_ref(), record.decision),
        (None, DecisionKind::Allow)
    );
    let principal = fixture
        .caller_context(Caller::TeamA, SURFACE_ALL)
        .expect("the fixture knows team A")
        .principal
        .get()
        .id
        .clone();
    assert_eq!(
        receipt_under(contract, &start.row).await,
        Receipt {
            row: start.row.clone(),
            scope: KeyScope {
                principal,
                delegation: None,
            },
            team: Some(TEAM_A.into()),
            key: key.clone(),
            tool: DRAFT_TOOL.parse().expect("a valid tool name"),
            tool_use_id: Some(ToolUseId::new(key.as_str())),
            digest: ArgumentDigest::of(&arguments),
            resources: record.resources.clone(),
            resources_omitted: 0,
            state: ReceiptState::Pending,
            established_by: EstablishedBy::Call,
            reference: None,
            target: None,
            lookups: Vec::new(),
            handed_to_person: None,
            claims: 0,
        }
    );

    // A begin the store refuses, here for a tool-use identifier Postgres cannot hold, writes
    // no row and reserves no receipt.
    let refused = fresh_key();
    let start = row_start();
    let begun = begin_keyed(
        store,
        &start,
        keyed_proposal(&fixture, &arguments, Some(&refused)),
        &arguments,
        Some("toolu_\u{0}"),
    )
    .await;
    assert!(
        begun.is_err(),
        "a record the store cannot hold was begun: {begun:?}"
    );
    assert_eq!(contract.stored(&start.row).await, None);
    assert_eq!(receipts_for(contract, &refused).await, Vec::new());

    // A denial, with a key: team B may not propose. And a read.
    let denied_key = fresh_key();
    let start = row_start();
    let team_b = fixture
        .caller_context(Caller::TeamB, SURFACE_ALL)
        .expect("the fixture knows team B");
    let begun = begin_keyed(
        store,
        &start,
        keyed_decision(&fixture, team_b, &arguments, Some(&denied_key)),
        &arguments,
        Some(denied_key.as_str()),
    )
    .await;
    assert!(matches!(begun, Ok(Begun::Denied(_))), "{begun:?}");
    assert!(contract.stored(&start.row).await.is_some());
    let read = guard(store, &fixture, &row_start(), &ALLOWED).await;
    assert_eq!(receipts_for(contract, &denied_key).await, Vec::new());
    assert!(
        contract
            .receipts()
            .await
            .iter()
            .all(|receipt| receipt.row != *read.row())
    );

    // The denial used up no key: team A may still use it.
    let _ = proposal_guard(store, &fixture, &row_start(), &arguments, &denied_key).await;
    assert_eq!(receipts_for(contract, &denied_key).await.len(), 1);
}

/// A receipt moves with its finish, in the same write as the row's completion: `ok` settles it
/// as `completed` with the vendor's reference, `error` and `refused` as `not_performed`, and
/// `unknown` as `unknown`, each established by the call. A guard given up settles it as
/// `not_performed`. A finish the store refuses leaves both the row and the receipt as they
/// were, and an identical repeat changes neither.
pub async fn a_receipt_moves_with_its_finish(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let cases = [
        (
            ToolOutcome::Completed(json!({"draft": "d-1"}), VendorReference::new("d-1")),
            ReceiptState::Completed,
            Some(VendorReference::new("d-1")),
        ),
        (
            ToolOutcome::Ok(json!({"draft": "d-2"})),
            ReceiptState::Completed,
            None,
        ),
        (
            ToolOutcome::error(ErrorKind::VendorRefusal, "The vendor said no."),
            ReceiptState::NotPerformed,
            None,
        ),
        (
            ToolOutcome::Refused("The connector refused.".into()),
            ReceiptState::NotPerformed,
            None,
        ),
        (ToolOutcome::Unknown, ReceiptState::Unknown, None),
    ];
    for (reported, settled, reference) in cases {
        let start = row_start();
        let key = fresh_key();
        let guard = proposal_guard(store, &fixture, &start, &proposal("p"), &key).await;
        let connector = Answering::with(reported.clone());
        let ran = audit::run(&connector, guard).await;
        let finished = audit::finish(store, ran, 4).await;
        assert!(
            finished.failure().is_none(),
            "{reported:?}: {:?}",
            finished.failure()
        );
        let completion = stored(contract, &start.row)
            .await
            .completion
            .expect("the row was completed");
        assert_eq!(
            ReceiptState::settled_by(&completion.outcome),
            Some(settled),
            "{reported:?}"
        );
        let receipt = receipt_under(contract, &start.row).await;
        assert_eq!(
            (receipt.state, &receipt.reference, &receipt.established_by),
            (settled, &reference, &EstablishedBy::Call),
            "{reported:?}"
        );
    }

    let start = row_start();
    let guard = proposal_guard(store, &fixture, &start, &proposal("p"), &fresh_key()).await;
    let gave_up = audit::give_up(store, guard).await;
    assert!(gave_up.failure().is_none(), "{:?}", gave_up.failure());
    assert_eq!(
        receipt_under(contract, &start.row).await.state,
        ReceiptState::NotPerformed
    );

    // A finish the store refuses: a refusal's sentence over the cap. Nothing moves.
    let start = row_start();
    let guard = proposal_guard(store, &fixture, &start, &proposal("p"), &fresh_key()).await;
    let ran = audit::run(
        &RefusesWith("o".repeat(MAX_OUTCOME_SENTENCE_BYTES + 1)),
        guard,
    )
    .await;
    let finished = audit::finish(store, ran, 4).await;
    assert!(finished.failure().is_some(), "a refused finish was written");
    assert_eq!(stored(contract, &start.row).await.completion, None);
    assert_eq!(
        receipt_under(contract, &start.row).await.state,
        ReceiptState::Pending
    );
}

/// A finish that arrives after its row's deadline is still written to the row, but does not
/// move the receipt (decision 0009, "What a receipt is"): a `pending` receipt past its
/// deadline leaves `pending` only by reconciliation or a person, and is read as `unknown`
/// until then, whatever the late finish reported.
pub async fn a_late_finish_completes_its_row_and_leaves_its_receipt_pending(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let cases = [
        ToolOutcome::Completed(json!({"draft": "d-1"}), VendorReference::new("d-1")),
        ToolOutcome::error(ErrorKind::VendorRefusal, "The vendor said no."),
        ToolOutcome::Unknown,
    ];
    for reported in cases {
        let start = row_start();
        let key = fresh_key();
        let guard = proposal_guard(store, &fixture, &start, &proposal("p"), &key).await;
        let connector = Answering::with(reported.clone());
        let ran = audit::run(&connector, guard).await;
        contract.pass_deadline(&start.row).await;
        let finished = audit::finish(store, ran, 4).await;
        assert!(
            finished.failure().is_none(),
            "{reported:?}: {:?}",
            finished.failure()
        );
        assert!(
            stored(contract, &start.row).await.completion.is_some(),
            "{reported:?}: the late finish was not written to the row"
        );
        let receipt = receipt_under(contract, &start.row).await;
        assert_eq!(
            (receipt.state, &receipt.reference, &receipt.established_by),
            (ReceiptState::Pending, &None, &EstablishedBy::Call),
            "{reported:?}"
        );
        assert_eq!(receipt.state.as_read(true), ReceiptState::Unknown);
    }
}

/// Polls every future in `futures` together until each is ready, so that none waits for
/// another to finish before it starts: the store sees them at once.
async fn all_at_once<T>(futures: Vec<BoxFuture<'_, T>>) -> Vec<T> {
    let mut running: Vec<Option<BoxFuture<'_, T>>> = futures.into_iter().map(Some).collect();
    let mut done: Vec<Option<T>> = running.iter().map(|_| None).collect();
    poll_fn(|context| {
        for (future, slot) in running.iter_mut().zip(done.iter_mut()) {
            if let Some(polled) = future
                && let Poll::Ready(output) = polled.as_mut().poll(context)
            {
                *slot = Some(output);
                *future = None;
            }
        }
        if running.iter().all(Option::is_none) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    done.into_iter()
        .map(|output| output.expect("every future finished"))
        .collect()
}

/// A key stays unique in its scope under concurrent calls: of eight begins of one call under
/// one key, at once, exactly one reserves the receipt and runs, and each of the others is
/// answered from that receipt, which is `pending`, as one that may already have happened.
pub async fn a_key_is_unique_in_its_scope_under_concurrent_calls(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("At once.");
    let starts: Vec<RowStart> = (0..8).map(|_| row_start()).collect();
    let begins: Vec<BoxFuture<'_, Result<Begun, AuditFailure>>> = starts
        .iter()
        .map(|start| {
            let decision = keyed_proposal(&fixture, &arguments, Some(&key));
            let arguments = arguments.clone();
            let key = key.clone();
            Box::pin(async move {
                begin_keyed(store, start, decision, &arguments, Some(key.as_str())).await
            }) as BoxFuture<'_, _>
        })
        .collect();
    let begun = all_at_once(begins).await;
    let mut reserved = Vec::new();
    let mut answered = Vec::new();
    for begun in begun {
        match begun {
            Ok(Begun::Allowed(guard)) => reserved.push(guard.row().clone()),
            Ok(Begun::Reused(reused)) => answered.push(reused),
            other => panic!("a concurrent begin was neither reserved nor reused: {other:?}"),
        }
    }
    assert_eq!(
        reserved.len(),
        1,
        "{} begins reserved the one key",
        reserved.len()
    );
    assert_eq!(answered.len(), 7);
    for reused in answered {
        assert_eq!(
            reused.reuse(),
            &Reuse::MayHaveHappened {
                key: key.clone(),
                receipt: reserved[0].clone(),
            }
        );
    }
    let receipts = receipts_for(contract, &key).await;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].row, reserved[0]);
}

/// A key is scoped to the principal and the delegation's identifying fields: two delegations
/// under one principal may each use the same key, and each reserves its own receipt. Within
/// one delegation the key is used once.
pub async fn two_delegations_under_one_principal_may_use_the_same_key(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Under a delegation.");
    let in_turn = |turn: &str| {
        let mut caller = fixture
            .caller_context(Caller::TeamA, SURFACE_ALL)
            .expect("the fixture knows team A");
        caller.delegation = Some(turn_delegation(turn));
        keyed_decision(&fixture, caller, &arguments, Some(&key))
    };
    let mut rows = Vec::new();
    for turn in ["turn-1", "turn-2"] {
        let start = row_start();
        let begun = begin_keyed(store, &start, in_turn(turn), &arguments, Some(key.as_str())).await;
        assert!(matches!(begun, Ok(Begun::Allowed(_))), "{turn}: {begun:?}");
        rows.push(start.row);
    }
    let receipts = receipts_for(contract, &key).await;
    assert_eq!(receipts.len(), 2);
    let scopes: Vec<Option<&str>> = receipts
        .iter()
        .map(|receipt| {
            receipt
                .scope
                .delegation
                .as_ref()
                .map(DelegationKeyScope::as_str)
        })
        .collect();
    assert!(
        scopes.contains(&Some(r#"["session-1","execution-1","turn-1"]"#)),
        "{scopes:?}"
    );
    assert!(
        scopes.contains(&Some(r#"["session-1","execution-1","turn-2"]"#)),
        "{scopes:?}"
    );

    let again = begin_keyed(
        store,
        &row_start(),
        in_turn("turn-2"),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    assert!(
        matches!(&again, Ok(Begun::Reused(reused)) if reused.reuse()
            == &Reuse::MayHaveHappened { key: key.clone(), receipt: rows[1].clone() }),
        "{again:?}"
    );
    assert_eq!(receipts_for(contract, &key).await.len(), 2);
}

/// A begin retried after a lost confirmation finds its own receipt, runs once, and is not
/// refused as reuse. The retry is a second begin under the same row, as the store's own retry
/// by identifier is; whatever the first answered is thrown away, as a lost confirmation's is.
/// Once the call has run, a begin under its row is refused, and runs nothing.
pub async fn a_begin_retried_after_a_lost_confirmation_finds_its_own_receipt_and_runs_once(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Retried.");
    let start = row_start();
    let decide_again = || keyed_proposal(&fixture, &arguments, Some(&key));

    let _lost = begin_keyed(
        store,
        &start,
        decide_again(),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    let retried = begin_keyed(
        store,
        &start,
        decide_again(),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    let Ok(Begun::Allowed(guard)) = retried else {
        panic!("a retried begin was not answered with its own reservation: {retried:?}");
    };
    assert_eq!(guard.row(), &start.row);
    assert_eq!(receipts_for(contract, &key).await.len(), 1);

    let connector = Answering::with(ToolOutcome::Completed(
        json!({"draft": "d-1"}),
        VendorReference::new("d-1"),
    ));
    let ran = audit::run(&connector, guard).await;
    let finished = audit::finish(store, ran, 2).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert_eq!(connector.calls(), 1);
    assert_eq!(
        receipt_under(contract, &start.row).await.state,
        ReceiptState::Completed
    );

    let after = stored(contract, &start.row).await;
    let again = begin_keyed(
        store,
        &start,
        decide_again(),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    assert!(again.is_err(), "a call that ran was begun again: {again:?}");
    assert_eq!(stored(contract, &start.row).await, after);
    assert_eq!(connector.calls(), 1);
}

/// A begin retried under a row whose receipt is still `pending` is answered with its own
/// reservation while the row's deadline has not passed, and refused once it has (decision
/// 0009, "What a receipt is"): the receipt then reads as `unknown`, wherever it is read, so its
/// call may have run and is no longer the call's to run. The refused begin runs nothing and
/// writes nothing: the row stays open, and the receipt is held `pending`.
pub async fn a_retried_begin_of_a_receipt_pending_past_its_deadline_is_refused_and_runs_nothing(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Retried late.");
    let start = row_start();
    let decide_again = || keyed_proposal(&fixture, &arguments, Some(&key));

    // Begun and never run, as a begin whose confirmation was lost is.
    let _lost = proposal_guard(store, &fixture, &start, &arguments, &key).await;
    let retried = begin_keyed(
        store,
        &start,
        decide_again(),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    assert!(
        matches!(&retried, Ok(Begun::Allowed(guard)) if guard.row() == &start.row),
        "a retried begin before its row's deadline was not answered with its own reservation: \
         {retried:?}"
    );

    contract.pass_deadline(&start.row).await;
    let before = stored(contract, &start.row).await;
    let late = begin_keyed(
        store,
        &start,
        decide_again(),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    // Refused, the begin hands out no guard, so nothing can run.
    assert!(
        late.is_err(),
        "a retried begin of a receipt pending past its row's deadline was answered: {late:?}"
    );
    let receipts = receipts_for(contract, &key).await;
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_eq!(
        (&receipts[0].row, receipts[0].state),
        (&start.row, ReceiptState::Pending)
    );
    let after = stored(contract, &start.row).await;
    assert_eq!(after, before);
    assert_eq!(after.completion, None);
}

/// A begin whose confirmation was lost on every attempt leaves its row completed as `error`,
/// of the kind `other` with a latency of zero, and its receipt `not_performed`: the instance
/// knows nothing ran.
pub async fn a_begin_whose_confirmation_is_lost_on_every_attempt_leaves_its_row_error_and_its_receipt_not_performed(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Lost.");
    let start = row_start();
    contract.lose_every_begin_confirmation();
    let begun = begin_keyed(
        store,
        &start,
        keyed_proposal(&fixture, &arguments, Some(&key)),
        &arguments,
        Some(key.as_str()),
    )
    .await;
    assert!(
        begun.is_err(),
        "a begin whose confirmation was lost succeeded: {begun:?}"
    );
    assert_eq!(
        stored(contract, &start.row).await.completion,
        Some(Completion {
            outcome: Outcome::Error {
                error_kind: ErrorKind::Other
            },
            latency_ms: 0,
        })
    );
    let receipt = receipt_under(contract, &start.row).await;
    assert_eq!(
        (receipt.state, receipt.established_by),
        (ReceiptState::NotPerformed, EstablishedBy::Call)
    );
}

/// A key's scope, the principal's issuer and subject and the delegation's scope, is held with
/// the key in the unique index that makes a key unique in its scope, and Postgres's index holds
/// an entry of at most 2,704 bytes. So each of the three is held to
/// [`MAX_KEY_SCOPE_BYTES`] at begin: a longer one is
/// refused, rather than cut, and leaves no row and no receipt (#203). Values Postgres cannot
/// compress, each at its cap, with a key at its own, are reserved.
pub async fn a_key_scope_over_its_cap_is_refused_at_begin_and_one_at_it_is_reserved(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let arguments = proposal("Scoped.");
    // A delegation's scope is `["session-1","execution-1","<turn>"]`: 30 bytes and the turn.
    let cap = MAX_KEY_SCOPE_BYTES;
    let turn_at_cap = cap - r#"["session-1","execution-1",""]"#.len();
    let caller = |issuer: usize, subject: usize, turn: usize| {
        let mut caller = fixture
            .caller_context(Caller::TeamA, SURFACE_ALL)
            .expect("the fixture knows team A");
        let mut principal = caller.principal.get().clone();
        principal.id.issuer = Issuer::new(format!("https://{}", incompressible(issuer - 8, 1)));
        principal.id.subject = Subject::new(incompressible(subject, 2));
        caller.principal = match Proved::verify(&PrincipalAsGiven, &principal) {
            Ok(proved) => proved,
            Err(never) => match never {},
        };
        caller.delegation = Some(turn_delegation(&incompressible(turn, 3)));
        caller
    };

    let key = IdempotencyKey::parse(&incompressible(MAX_IDEMPOTENCY_KEY, 4)).expect("a key");
    let start = row_start();
    let decision = keyed_decision(
        &fixture,
        caller(cap, cap, turn_at_cap),
        &arguments,
        Some(&key),
    );
    let begun = begin_keyed(store, &start, decision, &arguments, Some(key.as_str())).await;
    assert!(
        matches!(&begun, Ok(Begun::Allowed(guard)) if guard.row() == &start.row),
        "a key's scope at its cap was not reserved: {begun:?}"
    );
    let reserved = receipts_for(contract, &key).await;
    assert_eq!(reserved.len(), 1, "{reserved:?}");
    assert_eq!(
        (
            reserved[0].scope.principal.issuer.as_str().len(),
            reserved[0].scope.principal.subject.as_str().len(),
            reserved[0]
                .scope
                .delegation
                .as_ref()
                .map(|scope| scope.as_str().len()),
        ),
        (cap, cap, Some(cap))
    );

    for (over, (issuer, subject, turn)) in [
        ("issuer", (cap + 1, cap, turn_at_cap)),
        ("subject", (cap, cap + 1, turn_at_cap)),
        ("delegation scope", (cap, cap, turn_at_cap + 1)),
    ] {
        let key = fresh_key();
        let start = row_start();
        let decision = keyed_decision(
            &fixture,
            caller(issuer, subject, turn),
            &arguments,
            Some(&key),
        );
        let begun = begin_keyed(store, &start, decision, &arguments, Some(key.as_str())).await;
        assert!(begun.is_err(), "{over} over its cap: {begun:?}");
        assert_eq!(contract.stored(&start.row).await, None, "{over}");
        assert_eq!(receipts_for(contract, &key).await, Vec::new(), "{over}");
    }
}

/// A begin under a reused key whose confirmation was lost on every attempt leaves its row as its
/// begin wrote it, complete with the answer to its key, and the store gives nothing up (#203).
/// The completion the store then tries finds the row complete with the answer to its own key:
/// nothing was lost, so that is settled, not a completion that failed. A duplicate and a
/// refusal are each tried, and the earlier receipt is left as it was.
pub async fn a_reused_keys_begin_whose_confirmation_is_lost_keeps_its_answer_and_gives_nothing_up(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Done once.");
    let first = row_start();
    let guard = proposal_guard(store, &fixture, &first, &arguments, &key).await;
    let connector = Answering::with(ToolOutcome::Completed(
        json!({"draft": "d-1"}),
        VendorReference::new("d-1"),
    ));
    let ran = audit::run(&connector, guard).await;
    let finished = audit::finish(store, ran, 1).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    let earlier = receipt_under(contract, &first.row).await;

    contract.lose_every_begin_confirmation();
    for (tool_use_id, expected) in [
        (
            key.as_str(),
            Reuse::Duplicate {
                key: key.clone(),
                receipt: first.row.clone(),
                reference: Some(VendorReference::new("d-1")),
            },
        ),
        (
            "toolu_another_call",
            Reuse::DifferentCall { key: key.clone() },
        ),
    ] {
        let start = row_start();
        let begun = begin_keyed(
            store,
            &start,
            keyed_proposal(&fixture, &arguments, Some(&key)),
            &arguments,
            Some(tool_use_id),
        )
        .await;
        assert!(
            begun.is_err(),
            "{tool_use_id}: a begin whose confirmation was lost succeeded: {begun:?}"
        );
        assert_eq!(
            stored(contract, &start.row).await.completion,
            Some(expected.completion()),
            "{tool_use_id}"
        );
    }
    assert_eq!(receipts_for(contract, &key).await, vec![earlier]);
    assert_eq!(contract.lost_begins_given_up().await, 0);
    assert_eq!(connector.calls(), 1);
}

/// A retried begin of a row written as a `duplicate` is answered with the earlier receipt's
/// reference, as the first begin was (#203). The stores reach it differently, and the Postgres
/// store is the reference: it keeps no reference on the duplicate's row, and reads the earlier
/// receipt's as it is now, where the in-memory store keeps the answer it wrote. They cannot
/// differ: a `duplicate` answers only a `completed` receipt, which is final, so nothing moves it
/// again and its reference never changes.
pub async fn a_retried_begin_of_a_duplicate_answers_with_the_earlier_receipts_reference(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let key = fresh_key();
    let arguments = proposal("Done once.");
    let first = row_start();
    let guard = proposal_guard(store, &fixture, &first, &arguments, &key).await;
    let connector = Answering::with(ToolOutcome::Completed(
        json!({"draft": "d-1"}),
        VendorReference::new("d-1"),
    ));
    let finished = audit::finish(store, audit::run(&connector, guard).await, 1).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());

    let duplicate = Reuse::Duplicate {
        key: key.clone(),
        receipt: first.row.clone(),
        reference: Some(VendorReference::new("d-1")),
    };
    let start = row_start();
    for attempt in ["first", "retried"] {
        let begun = begin_keyed(
            store,
            &start,
            keyed_proposal(&fixture, &arguments, Some(&key)),
            &arguments,
            Some(key.as_str()),
        )
        .await;
        let Ok(Begun::Reused(reused)) = begun else {
            panic!("the {attempt} begin was not answered from the receipt: {begun:?}");
        };
        assert_eq!(reused.reuse(), &duplicate, "{attempt}");
    }
    assert_eq!(
        stored(contract, &start.row).await.completion,
        Some(duplicate.completion())
    );
    assert_eq!(connector.calls(), 1);
}

/// Each receipt state against each line of the reuse table (decision 0009, "Reuse"). For an
/// earlier receipt in each state, `pending`, `completed`, `not_performed` and `unknown`, a call
/// under its key with another tool-use identifier is refused as a different call; one with the
/// same identifier and other arguments as conflicting reuse; and the same call is a
/// `duplicate` of a `completed` receipt, may have happened for `pending` and `unknown`, and
/// needs a new key for `not_performed`. None of them runs or reserves a receipt, each row is
/// written complete with its answer, and the earlier receipt is left as it was.
pub async fn each_receipt_state_is_answered_by_the_first_line_of_the_reuse_table_that_matches(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let arguments = proposal("The first call.");
    let states = [
        (None, ReceiptState::Pending),
        (
            Some(ToolOutcome::Completed(
                json!({"draft": "d-1"}),
                VendorReference::new("d-1"),
            )),
            ReceiptState::Completed,
        ),
        (
            Some(ToolOutcome::error(ErrorKind::VendorRefusal, "No.")),
            ReceiptState::NotPerformed,
        ),
        (Some(ToolOutcome::Unknown), ReceiptState::Unknown),
    ];
    for (outcome, state) in states {
        let key = fresh_key();
        let first = row_start();
        let guard = proposal_guard(store, &fixture, &first, &arguments, &key).await;
        match outcome {
            Some(outcome) => {
                let ran = audit::run(&Answering::with(outcome), guard).await;
                let finished = audit::finish(store, ran, 1).await;
                assert!(finished.failure().is_none(), "{:?}", finished.failure());
            }
            // Begun and never finished: still pending.
            None => drop(guard),
        }
        let earlier = receipt_under(contract, &first.row).await;
        assert_eq!(earlier.state, state);

        let receipt = first.row.clone();
        let same_call = match state {
            ReceiptState::Completed => Reuse::Duplicate {
                key: key.clone(),
                receipt: receipt.clone(),
                reference: Some(VendorReference::new("d-1")),
            },
            ReceiptState::Pending | ReceiptState::Unknown => Reuse::MayHaveHappened {
                key: key.clone(),
                receipt: receipt.clone(),
            },
            ReceiptState::NotPerformed => Reuse::NotPerformed {
                key: key.clone(),
                receipt: receipt.clone(),
            },
        };
        let other_arguments = proposal("Another call.");
        for (tool_use_id, call_arguments, expected) in [
            (
                "toolu_another_call",
                &arguments,
                Reuse::DifferentCall { key: key.clone() },
            ),
            (
                key.as_str(),
                &other_arguments,
                Reuse::Conflicting { key: key.clone() },
            ),
            (key.as_str(), &arguments, same_call),
        ] {
            let start = row_start();
            let begun = begin_keyed(
                store,
                &start,
                keyed_proposal(&fixture, call_arguments, Some(&key)),
                call_arguments,
                Some(tool_use_id),
            )
            .await;
            let Ok(Begun::Reused(reused)) = begun else {
                panic!("{state:?}, {tool_use_id}: not answered from the receipt: {begun:?}");
            };
            assert_eq!(reused.reuse(), &expected, "{state:?}, {tool_use_id}");
            let row = stored(contract, &start.row).await;
            assert_eq!(
                row.completion,
                Some(expected.completion()),
                "{state:?}, {tool_use_id}"
            );
            let StoredRecord::Call(record) = &row.record else {
                panic!("a call was stored as {:?}", row.record);
            };
            assert_eq!(record.decision, DecisionKind::Allow);
        }
        assert_eq!(receipts_for(contract, &key).await, vec![earlier]);
    }
}

// --- Item 7: reconciliation ---------------------------------------------------------------------

/// The lease every claim in item 7 asks for: long enough that nothing ends it but
/// [`ContractStore::pass_lease`].
const LEASE: Duration = Duration::from_secs(600);

/// The attempts every lookup in item 7 is recorded under, unless a function says otherwise.
const ATTEMPTS: u32 = 5;

fn holder(name: &str) -> LeaseHolder {
    LeaseHolder::new(format!("contract-instance {name}"))
}

/// A receipt in `unknown`: team A's proposal, whose connector reported `unknown`, finished
/// within its deadline, with the deadline then passed, so it is due.
async fn unknown_receipt(contract: &impl ContractStore) -> AuditRowId {
    let row = unknown_within_deadline(contract).await;
    contract.pass_deadline(&row).await;
    row
}

/// A receipt in `unknown`: team A's proposal, whose connector reported `unknown`, finished
/// within its deadline, which has not passed.
async fn unknown_within_deadline(contract: &impl ContractStore) -> AuditRowId {
    let store = contract.store();
    let start = row_start();
    let guard = proposal_guard(store, &fixture(), &start, &proposal("p"), &fresh_key()).await;
    let ran = audit::run(&Answering::with(ToolOutcome::Unknown), guard).await;
    let finished = audit::finish(store, ran, 1).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert_eq!(
        receipt_under(contract, &start.row).await.state,
        ReceiptState::Unknown
    );
    start.row
}

/// A receipt the call answered `unknown` is not due before its row's deadline, on any
/// instance (#217): its call may be a side effect still running whose hold of the lease is not
/// written yet. No one claims it, and it is not listed. Once the deadline has passed it is due
/// and claimed as any other.
pub async fn an_unknown_receipt_is_not_due_before_its_rows_deadline(contract: &impl ContractStore) {
    let row = unknown_within_deadline(contract).await;
    let holder = holder("other");
    assert!(
        !is_due(contract, &row).await,
        "an unknown receipt was due before its row's deadline"
    );
    assert_eq!(
        contract
            .queue()
            .claim(&row, &holder, LEASE)
            .await
            .expect("a claim failed"),
        None,
        "an unknown receipt was claimed before its row's deadline"
    );
    assert_eq!(receipt_under(contract, &row).await.claims, 0);
    contract.pass_deadline(&row).await;
    assert!(is_due(contract, &row).await);
    assert_eq!(claimed(contract, &row, &holder).await.claims, 1);
}

/// Whether the queue lists the receipt `row` as due.
async fn is_due(contract: &impl ContractStore, row: &AuditRowId) -> bool {
    contract
        .queue()
        .due(1000)
        .await
        .expect("the queue could not be read")
        .iter()
        .any(|receipt| receipt.row == *row)
}

/// `holder` claims `row`, which must be claimed.
async fn claimed(contract: &impl ContractStore, row: &AuditRowId, holder: &LeaseHolder) -> Receipt {
    contract
        .queue()
        .claim(row, holder, LEASE)
        .await
        .expect("the claim failed")
        .unwrap_or_else(|| panic!("{holder} could not claim {}", row.as_str()))
}

/// `holder` records `answer` on `row` under `attempts`, which must be written.
async fn recorded(
    contract: &impl ContractStore,
    row: &AuditRowId,
    holder: &LeaseHolder,
    answer: LookupAnswer,
    attempts: u32,
) -> Recorded {
    contract
        .queue()
        .record_lookup(row, holder, &answer, attempts)
        .await
        .unwrap_or_else(|error| panic!("{answer:?} was not recorded: {error}"))
}

/// A receipt records the vendor target its tool's settlement takes from the call: the one
/// document a proposal names, when the draft tool is settled by a lookup in documents, and
/// none when it is settled by a person. The queue gives it back with the receipt, and with the
/// team the receipt recorded, which a lookup asks for its read credential for.
pub async fn a_receipt_records_the_vendor_target_its_settlement_takes(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let mut by_lookup = fixture();
    by_lookup.policy = serde_json::from_value(policy_data_with_draft_lookup())
        .expect("the fixture policy with a lookup loads");
    let start = row_start();
    let guard = proposal_guard(store, &by_lookup, &start, &proposal("p"), &fresh_key()).await;
    assert_eq!(
        receipt_under(contract, &start.row).await.target,
        Some(document(TEAM_A_DOCUMENT))
    );
    let ran = audit::run(&Answering::with(ToolOutcome::Unknown), guard).await;
    assert!(audit::finish(store, ran, 1).await.failure().is_none());
    contract.pass_deadline(&start.row).await;
    let claimed = claimed(contract, &start.row, &holder("a")).await;
    assert_eq!(claimed.target, Some(document(TEAM_A_DOCUMENT)));
    // The team a lookup asks for its read credential for, as the receipt recorded it at begin.
    assert_eq!(claimed.team, Some(TEAM_A.into()));

    let by_person = unknown_receipt(contract).await;
    assert_eq!(receipt_under(contract, &by_person).await.target, None);
}

/// Two claimants never both hold a receipt's lease. Of six claims of one receipt at once,
/// exactly one succeeds; the receipt is no longer due; and the others can record no lookup and
/// hand it to no one, while the one that holds it can.
pub async fn two_claimants_never_both_hold_a_receipts_lease(contract: &impl ContractStore) {
    let queue = contract.queue();
    for round in 0..3 {
        let row = unknown_receipt(contract).await;
        assert!(is_due(contract, &row).await, "round {round}");
        let holders: Vec<LeaseHolder> = (0..6).map(|at| holder(&format!("{round}-{at}"))).collect();
        let claims: Vec<BoxFuture<'_, _>> = holders
            .iter()
            .map(|holder| queue.claim(&row, holder, LEASE))
            .collect();
        let answers = all_at_once(claims).await;
        let mut winners = Vec::new();
        for (holder, answer) in holders.iter().zip(answers) {
            if answer.expect("a claim failed").is_some() {
                winners.push(holder.clone());
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "round {round}: {winners:?} all hold the lease"
        );
        let winner = &winners[0];
        assert!(
            !is_due(contract, &row).await,
            "a claimed receipt is still due"
        );
        for loser in holders.iter().filter(|holder| *holder != winner) {
            assert_eq!(
                queue
                    .claim(&row, loser, LEASE)
                    .await
                    .expect("a claim failed"),
                None,
                "{loser} claimed a receipt {winner} holds"
            );
            assert!(
                queue
                    .record_lookup(&row, loser, &LookupAnswer::Failed, ATTEMPTS)
                    .await
                    .is_err(),
                "{loser} recorded a lookup on a receipt {winner} holds"
            );
            assert!(
                queue.hand_to_person(&row, loser).await.is_err(),
                "{loser} handed off a receipt {winner} holds"
            );
        }
        let receipt = receipt_under(contract, &row).await;
        assert_eq!((receipt.lookups.len(), receipt.handed_to_person), (0, None));
        assert_eq!(
            recorded(contract, &row, winner, LookupAnswer::Failed, ATTEMPTS).await,
            Recorded::Left
        );
    }
}

/// A lease that has ended can be claimed again, by another holder, who gets the receipt with
/// the lookups made so far; the holder whose lease ended can then write nothing.
pub async fn an_ended_lease_can_be_claimed_again(contract: &impl ContractStore) {
    let queue = contract.queue();
    let row = unknown_receipt(contract).await;
    let (first, second) = (holder("first"), holder("second"));
    claimed(contract, &row, &first).await;
    assert_eq!(
        recorded(contract, &row, &first, LookupAnswer::Failed, ATTEMPTS).await,
        Recorded::Left
    );
    assert!(!is_due(contract, &row).await, "a held receipt is due");

    contract.pass_lease(&row).await;
    assert!(
        is_due(contract, &row).await,
        "a receipt whose lease ended is not due"
    );
    let again = claimed(contract, &row, &second).await;
    assert_eq!(again.lookups.len(), 1);
    assert_eq!(again.lookups[0].answer, LookupAnswer::Failed);
    assert!(
        queue
            .record_lookup(&row, &first, &LookupAnswer::Failed, ATTEMPTS)
            .await
            .is_err(),
        "a holder whose lease ended recorded a lookup"
    );
    assert!(queue.hand_to_person(&row, &first).await.is_err());
    assert_eq!(
        recorded(contract, &row, &second, LookupAnswer::Failed, ATTEMPTS).await,
        Recorded::Left
    );
    assert_eq!(receipt_under(contract, &row).await.lookups.len(), 2);
}

/// The number of attempts is bounded. With two allowed, the second lookup that settles nothing
/// hands the receipt to a person in the same write, with the store's time, and it stays
/// `unknown`, established by its call; then no third lookup is recorded, it is not due, and no
/// one can claim it or hand it off again. A receipt with nothing to look in is handed off
/// directly, and stays `unknown` too.
pub async fn the_number_of_attempts_is_bounded(contract: &impl ContractStore) {
    let queue = contract.queue();
    let row = unknown_receipt(contract).await;
    let holder = holder("a");
    claimed(contract, &row, &holder).await;
    assert_eq!(
        recorded(contract, &row, &holder, LookupAnswer::Failed, 2).await,
        Recorded::Left
    );
    let before = contract.now().await;
    let empty = LookupAnswer::NotFound {
        authoritative: false,
    };
    assert_eq!(
        recorded(contract, &row, &holder, empty, 2).await,
        Recorded::HandedToPerson
    );
    let after = contract.now().await;
    let receipt = receipt_under(contract, &row).await;
    assert_eq!(
        (
            receipt.state,
            &receipt.established_by,
            receipt.lookups.len()
        ),
        (ReceiptState::Unknown, &EstablishedBy::Call, 2)
    );
    let handed = receipt
        .handed_to_person
        .expect("the receipt was not handed off");
    assert!(
        before <= handed && handed <= after,
        "handed off at {handed:?}"
    );
    assert!(
        queue
            .record_lookup(&row, &holder, &LookupAnswer::Failed, 2)
            .await
            .is_err(),
        "a third lookup was recorded"
    );
    assert!(
        queue
            .record_lookup(&row, &holder, &LookupAnswer::Failed, 3)
            .await
            .is_err(),
        "a lookup was recorded on a receipt handed to a person"
    );
    assert!(queue.hand_to_person(&row, &holder).await.is_err());
    assert!(
        !is_due(contract, &row).await,
        "a receipt handed off is still due"
    );
    contract.pass_lease(&row).await;
    assert!(
        !is_due(contract, &row).await,
        "a receipt handed off is due again"
    );
    assert_eq!(
        queue
            .claim(&row, &holder, LEASE)
            .await
            .expect("a claim failed"),
        None
    );
    assert_eq!(receipt_under(contract, &row).await, receipt);

    let direct = unknown_receipt(contract).await;
    claimed(contract, &direct, &holder).await;
    queue
        .hand_to_person(&direct, &holder)
        .await
        .expect("the receipt was not handed off");
    let receipt = receipt_under(contract, &direct).await;
    assert_eq!(
        (receipt.state, receipt.lookups.len()),
        (ReceiptState::Unknown, 0)
    );
    assert!(receipt.handed_to_person.is_some());
    assert!(!is_due(contract, &direct).await);
}

/// An authoritative search that found nothing settles a receipt `not_performed`, established by
/// reconciliation; a search that is not authoritative, or a failed lookup, never does, however
/// often it is made. A `pending` receipt past its row's deadline is settled the same way; one
/// within its deadline is not due, and cannot be claimed.
pub async fn an_authoritative_empty_search_settles_not_performed_and_no_other_does(
    contract: &impl ContractStore,
) {
    let row = unknown_receipt(contract).await;
    let holder = holder("a");
    claimed(contract, &row, &holder).await;
    for answer in [
        LookupAnswer::NotFound {
            authoritative: false,
        },
        LookupAnswer::Failed,
        LookupAnswer::NotFound {
            authoritative: false,
        },
    ] {
        assert_eq!(
            recorded(contract, &row, &holder, answer.clone(), ATTEMPTS).await,
            Recorded::Left,
            "{answer:?}"
        );
        assert_eq!(
            receipt_under(contract, &row).await.state,
            ReceiptState::Unknown,
            "{answer:?} settled the receipt"
        );
    }
    let authoritative = LookupAnswer::NotFound {
        authoritative: true,
    };
    assert_eq!(
        recorded(contract, &row, &holder, authoritative.clone(), ATTEMPTS).await,
        Recorded::Settled(ReceiptState::NotPerformed)
    );
    let receipt = receipt_under(contract, &row).await;
    assert_eq!(
        (receipt.state, &receipt.established_by, &receipt.reference),
        (
            ReceiptState::NotPerformed,
            &EstablishedBy::Reconciliation,
            &None
        )
    );
    assert_eq!(receipt.handed_to_person, None);
    assert!(!is_due(contract, &row).await);

    // A pending receipt: not due within its deadline, and settled like any other past it.
    let store = contract.store();
    let start = row_start();
    let guard = proposal_guard(store, &fixture(), &start, &proposal("p"), &fresh_key()).await;
    assert!(
        !is_due(contract, &start.row).await,
        "a pending receipt is due"
    );
    assert_eq!(
        contract
            .queue()
            .claim(&start.row, &holder, LEASE)
            .await
            .expect("a claim failed"),
        None,
        "a pending receipt within its deadline was claimed"
    );
    contract.pass_deadline(&start.row).await;
    assert!(is_due(contract, &start.row).await);
    claimed(contract, &start.row, &holder).await;
    assert_eq!(
        recorded(contract, &start.row, &holder, authoritative, ATTEMPTS).await,
        Recorded::Settled(ReceiptState::NotPerformed)
    );
    drop(guard);
}

/// A found effect settles a receipt `completed`, established by reconciliation, with the
/// vendor's reference made safe as a finish's is; it is then no longer due, and its holder can
/// record nothing more on it.
pub async fn a_found_effect_settles_completed_with_its_reference(contract: &impl ContractStore) {
    let row = unknown_receipt(contract).await;
    let holder = holder("a");
    claimed(contract, &row, &holder).await;
    assert_eq!(
        recorded(contract, &row, &holder, LookupAnswer::Failed, ATTEMPTS).await,
        Recorded::Left
    );
    let found = LookupAnswer::Found {
        reference: VendorReference::new("draft\n9"),
    };
    assert_eq!(
        recorded(contract, &row, &holder, found, ATTEMPTS).await,
        Recorded::Settled(ReceiptState::Completed)
    );
    let safe = VendorReference::new("draft\\n9");
    let receipt = receipt_under(contract, &row).await;
    assert_eq!(
        (receipt.state, &receipt.established_by, &receipt.reference),
        (
            ReceiptState::Completed,
            &EstablishedBy::Reconciliation,
            &Some(safe.clone())
        )
    );
    assert_eq!(
        receipt.lookups[1].answer,
        LookupAnswer::Found { reference: safe }
    );
    assert!(!is_due(contract, &row).await);
    assert!(
        contract
            .queue()
            .record_lookup(&row, &holder, &LookupAnswer::Failed, ATTEMPTS)
            .await
            .is_err(),
        "a lookup was recorded on a settled receipt"
    );
    assert!(
        contract
            .queue()
            .hand_to_person(&row, &holder)
            .await
            .is_err()
    );
    assert_eq!(receipt_under(contract, &row).await, receipt);
}

/// A lookup record is appended and never changed: each lookup adds one record, in order, with
/// the store's time, and the records already there stay exactly as they were.
pub async fn a_lookup_record_is_append_only(contract: &impl ContractStore) {
    let row = unknown_receipt(contract).await;
    let holder = holder("a");
    claimed(contract, &row, &holder).await;
    let answers = [
        LookupAnswer::Failed,
        LookupAnswer::NotFound {
            authoritative: false,
        },
        LookupAnswer::Failed,
    ];
    let mut kept = Vec::new();
    for answer in answers.clone() {
        let before = contract.now().await;
        assert_eq!(
            recorded(contract, &row, &holder, answer.clone(), ATTEMPTS).await,
            Recorded::Left
        );
        let after = contract.now().await;
        let lookups = receipt_under(contract, &row).await.lookups;
        assert_eq!(lookups.len(), kept.len() + 1);
        assert_eq!(lookups[..kept.len()], kept[..], "a lookup record changed");
        let added = lookups.last().expect("a lookup was recorded").clone();
        assert_eq!(added.answer, answer);
        assert!(
            before <= added.at && added.at <= after,
            "recorded at {:?}",
            added.at
        );
        kept.push(added);
    }
    assert_eq!(
        kept.iter()
            .map(|lookup| lookup.answer.clone())
            .collect::<Vec<_>>(),
        answers.to_vec()
    );
}

/// A receipt settled by reconciliation is not moved by a late finish: a call whose answer
/// arrives after its row's deadline, by which time a lookup has settled its receipt, completes
/// its row, and the receipt keeps the state, the establishment and the reference the lookup
/// gave it, whatever the late finish reported. A late finish that settles the other state is
/// counted as a disagreement, once; one that agrees, or reports `unknown`, is not.
pub async fn a_receipt_settled_by_reconciliation_is_not_moved_by_a_late_finish(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let holder = holder("a");
    let cases = [
        (
            ToolOutcome::error(ErrorKind::VendorRefusal, "The vendor said no."),
            LookupAnswer::Found {
                reference: VendorReference::new("found-1"),
            },
            ReceiptState::Completed,
            true,
        ),
        (
            ToolOutcome::Completed(json!({"draft": "d-2"}), VendorReference::new("d-2")),
            LookupAnswer::NotFound {
                authoritative: true,
            },
            ReceiptState::NotPerformed,
            true,
        ),
        (
            ToolOutcome::Completed(json!({"draft": "d-3"}), VendorReference::new("d-3")),
            LookupAnswer::Found {
                reference: VendorReference::new("d-3"),
            },
            ReceiptState::Completed,
            false,
        ),
        (
            ToolOutcome::Unknown,
            LookupAnswer::NotFound {
                authoritative: true,
            },
            ReceiptState::NotPerformed,
            false,
        ),
    ];
    for (late, answer, settled, disagrees) in cases {
        let before = contract.late_finish_disagreements();
        let start = row_start();
        let guard = proposal_guard(store, &fixture, &start, &proposal("p"), &fresh_key()).await;
        let ran = audit::run(&Answering::with(late.clone()), guard).await;
        contract.pass_deadline(&start.row).await;
        claimed(contract, &start.row, &holder).await;
        assert_eq!(
            recorded(contract, &start.row, &holder, answer.clone(), ATTEMPTS).await,
            Recorded::Settled(settled)
        );
        let finished = audit::finish(store, ran, 4).await;
        assert!(
            finished.failure().is_none(),
            "{late:?}: {:?}",
            finished.failure()
        );
        assert!(
            stored(contract, &start.row).await.completion.is_some(),
            "{late:?}: the late finish was not written to the row"
        );
        assert_eq!(
            contract.late_finish_disagreements() - before,
            u64::from(disagrees),
            "{late:?} against {answer:?}"
        );
        let receipt = receipt_under(contract, &start.row).await;
        assert_eq!(
            (
                receipt.state,
                &receipt.established_by,
                receipt.reference.as_ref()
            ),
            (settled, &EstablishedBy::Reconciliation, answer.reference()),
            "{late:?}"
        );
    }
}

/// Each claim is counted on the receipt, in the claim's own write, as an attempt: the claim
/// returns the receipt with its count, a claim that finds the receipt not due counts nothing,
/// and the count stands whether or not a lookup was recorded under the claim. A receipt is
/// reserved with none.
pub async fn each_claim_is_counted_as_an_attempt(contract: &impl ContractStore) {
    let row = unknown_receipt(contract).await;
    assert_eq!(receipt_under(contract, &row).await.claims, 0);
    let (first, second) = (holder("first"), holder("second"));
    assert_eq!(claimed(contract, &row, &first).await.claims, 1);
    assert_eq!(
        contract
            .queue()
            .claim(&row, &second, LEASE)
            .await
            .expect("a claim failed"),
        None
    );
    assert_eq!(
        receipt_under(contract, &row).await.claims,
        1,
        "a claim that found the receipt held was counted"
    );
    // No lookup is recorded under the first claim, as when its save fails.
    contract.pass_lease(&row).await;
    let again = claimed(contract, &row, &second).await;
    assert_eq!((again.claims, again.lookups.len()), (2, 0));
    assert_eq!(
        recorded(contract, &row, &second, LookupAnswer::Failed, ATTEMPTS).await,
        Recorded::Left
    );
    contract.pass_lease(&row).await;
    assert_eq!(claimed(contract, &row, &first).await.claims, 3);
    assert_eq!(receipt_under(contract, &row).await.claims, 3);
}

/// A receipt held for its call is not due, and no one else claims it, while the hold lasts
/// (#217). The call holds its receipt while it is `pending` within its row's deadline, before
/// it is answered; the hold stands once the receipt is `unknown`, and again past the row's
/// deadline; the holder holds it again as often as it likes; another holder cannot hold or
/// claim it; and a hold counts no claim. Once the hold ends the receipt is due and claimed as
/// any other, and then the call's holder cannot hold it. A receipt settled or handed to a
/// person cannot be held.
pub async fn a_receipt_held_for_its_call_is_not_due_and_no_one_else_claims_it(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let queue = contract.queue();
    let (call, other) = (holder("call"), holder("other"));

    // Held while pending within its deadline, then answered unknown.
    let start = row_start();
    let guard = proposal_guard(store, &fixture(), &start, &proposal("p"), &fresh_key()).await;
    let row = start.row.clone();
    assert!(
        queue
            .hold(&row, &call, LEASE)
            .await
            .expect("the hold failed")
    );
    let ran = audit::run(&Answering::with(ToolOutcome::Unknown), guard).await;
    assert!(audit::finish(store, ran, 1).await.failure().is_none());
    assert_eq!(
        receipt_under(contract, &row).await.state,
        ReceiptState::Unknown
    );
    assert!(!is_due(contract, &row).await, "a held receipt is due");
    assert_eq!(
        queue
            .claim(&row, &other, LEASE)
            .await
            .expect("a claim failed"),
        None,
        "a receipt held for its call was claimed"
    );
    assert!(
        !queue
            .hold(&row, &other, LEASE)
            .await
            .expect("the hold failed"),
        "another holder held a receipt held for its call"
    );
    assert!(
        queue
            .hold(&row, &call, LEASE)
            .await
            .expect("the hold failed"),
        "the call could not hold its receipt again"
    );
    contract.pass_deadline(&row).await;
    assert!(
        queue
            .hold(&row, &call, LEASE)
            .await
            .expect("the hold failed")
    );
    assert!(!is_due(contract, &row).await);
    assert_eq!(
        receipt_under(contract, &row).await.claims,
        0,
        "a hold was counted as a claim"
    );

    // Once the hold ends, the receipt is claimed as any other, and the call cannot hold it.
    contract.pass_lease(&row).await;
    assert!(
        is_due(contract, &row).await,
        "a receipt whose hold ended is not due"
    );
    assert_eq!(claimed(contract, &row, &other).await.claims, 1);
    assert!(
        !queue
            .hold(&row, &call, LEASE)
            .await
            .expect("the hold failed"),
        "the call held a receipt another holder claimed"
    );

    // A settled receipt, and one handed to a person, cannot be held.
    let found = LookupAnswer::Found {
        reference: VendorReference::new("draft-1"),
    };
    assert_eq!(
        recorded(contract, &row, &other, found, ATTEMPTS).await,
        Recorded::Settled(ReceiptState::Completed)
    );
    contract.pass_lease(&row).await;
    assert!(
        !queue
            .hold(&row, &call, LEASE)
            .await
            .expect("the hold failed")
    );
    let handed = unknown_receipt(contract).await;
    claimed(contract, &handed, &other).await;
    queue
        .hand_to_person(&handed, &other)
        .await
        .expect("the receipt was not handed off");
    contract.pass_lease(&handed).await;
    assert!(
        !queue
            .hold(&handed, &call, LEASE)
            .await
            .expect("the hold failed")
    );
    let unclaimed = unknown_receipt(contract).await;
    let start = row_start();
    let guard = proposal_guard(store, &fixture(), &start, &proposal("p"), &fresh_key()).await;
    let ran = audit::run(
        &Answering::with(ToolOutcome::Completed(
            json!({"draft": "d-4"}),
            VendorReference::new("d-4"),
        )),
        guard,
    )
    .await;
    assert!(audit::finish(store, ran, 1).await.failure().is_none());
    assert!(
        !queue
            .hold(&start.row, &call, LEASE)
            .await
            .expect("the hold failed"),
        "a receipt its call settled was held"
    );
    assert!(
        queue
            .hold(&unclaimed, &call, LEASE)
            .await
            .expect("the hold failed")
    );
}
