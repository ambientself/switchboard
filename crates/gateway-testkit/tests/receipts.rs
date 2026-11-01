//! The in-memory store reads a receipt still `pending` past its row's deadline as `unknown`
//! (decision 0009, "What a receipt is"): in the receipts it gives back, and in the answer to a
//! reused key. The shared contract suite reads receipts as a store holds them, so these cases
//! are here and not there. A retried begin of the receipt's own row, which both stores refuse
//! rather than answer as reserved, is the contract suite's.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use gateway_core::audit::{self, AuditFailure, Begun, RequestMetadata, RowStart};
use gateway_core::{
    CallContext, IdempotencyKey, ReceiptState, RequestedTool, Reuse, ToolUseId, decide,
};
use gateway_identity::Clock;
use gateway_testkit::{
    DRAFT_TOOL, FIXTURE_NOW, FakeCredentialSource, Fixture, FixtureConnector, InMemoryAuditStore,
    SURFACE_ALL, SteppableClock, TEAM_A_DOCUMENT, block_on, fresh_key, row_start,
};
use serde_json::json;

const TOOL_USE_ID: &str = "toolu_the_one_call";

/// A store on a clock the test moves.
fn store() -> (InMemoryAuditStore, SteppableClock) {
    let clock = SteppableClock::at(FIXTURE_NOW);
    let store = InMemoryAuditStore::new().with_clock(Arc::new(clock.clone()));
    (store, clock)
}

/// Begins team A's proposal under `key`, as the row `start` names, with the one tool-use
/// identifier every call here sends.
fn propose(
    fixture: &Fixture,
    store: &InMemoryAuditStore,
    start: &RowStart,
    key: &IdempotencyKey,
) -> Result<Begun, AuditFailure> {
    let arguments = json!({"document": TEAM_A_DOCUMENT, "text": "A proposed change."});
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(DRAFT_TOOL),
        resources: FixtureConnector::resources_of(DRAFT_TOOL, &arguments),
        key: gateway_core::CallKey::Valid(key.clone()),
        currency: gateway_core::Currency::NotAsked,
    };
    block_on(audit::begin(
        store,
        start.clone(),
        decide(&fixture.policy, &call),
        arguments,
        RequestMetadata {
            tool_use_id: Some(ToolUseId::new(TOOL_USE_ID)),
            claimed_team: None,
        },
    ))
}

/// Moves `clock` just past the deadline the store gave the row `start` names.
fn pass_deadline(store: &InMemoryAuditStore, clock: &SteppableClock, start: &RowStart) {
    let deadline = store.deadline(&start.row).expect("the row has a deadline");
    let to_go = deadline.duration_since(clock.now()).unwrap_or_default();
    clock.advance(to_go + Duration::from_millis(1));
}

/// Begun and never finished, a receipt is `pending`; once its row's deadline has passed it
/// reads as `unknown`, from `receipts` and from `receipt`, and is still held as `pending`. A
/// receipt the call settled reads as itself.
#[test]
fn a_pending_receipt_past_its_rows_deadline_reads_as_unknown() {
    let fixture = Fixture::new().unwrap();
    let (store, clock) = store();
    let open = row_start();
    let Begun::Allowed(guard) = propose(&fixture, &store, &open, &fresh_key()).unwrap() else {
        panic!("the proposal was not allowed");
    };
    drop(guard);
    let settled = row_start();
    let Begun::Allowed(guard) = propose(&fixture, &store, &settled, &fresh_key()).unwrap() else {
        panic!("the proposal was not allowed");
    };
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let ran = block_on(audit::run(&connector, guard));
    assert!(block_on(audit::finish(&store, ran, 3)).failure().is_none());

    let states = |receipts: Vec<gateway_core::Receipt>| -> Vec<ReceiptState> {
        receipts.into_iter().map(|receipt| receipt.state).collect()
    };
    let before = [ReceiptState::Pending, ReceiptState::Completed];
    assert_eq!(states(store.receipts()), before);
    assert_eq!(
        store.receipt(&open.row).map(|receipt| receipt.state),
        Some(ReceiptState::Pending)
    );

    pass_deadline(&store, &clock, &open);
    pass_deadline(&store, &clock, &settled);
    assert_eq!(
        states(store.receipts()),
        [ReceiptState::Unknown, ReceiptState::Completed]
    );
    assert_eq!(
        store.receipt(&open.row).map(|receipt| receipt.state),
        Some(ReceiptState::Unknown)
    );
    assert_eq!(
        store.receipt(&settled.row).map(|receipt| receipt.state),
        Some(ReceiptState::Completed)
    );
    assert_eq!(
        states(store.held_receipts()),
        before,
        "the store changed what it holds"
    );
}

/// Another call under a key whose receipt is `pending` past its deadline is answered as one
/// that may already have happened, naming that receipt, and does not run.
#[test]
fn a_reused_key_whose_receipt_is_pending_past_its_deadline_may_have_happened() {
    let fixture = Fixture::new().unwrap();
    let (store, clock) = store();
    let first = row_start();
    let key = fresh_key();
    let Begun::Allowed(guard) = propose(&fixture, &store, &first, &key).unwrap() else {
        panic!("the proposal was not allowed");
    };
    drop(guard);
    pass_deadline(&store, &clock, &first);

    let again = propose(&fixture, &store, &row_start(), &key).unwrap();
    let Begun::Reused(reused) = again else {
        panic!("the reused key ran: {again:?}");
    };
    assert_eq!(
        reused.reuse(),
        &Reuse::MayHaveHappened {
            key,
            receipt: first.row.clone()
        }
    );
    assert_eq!(
        store.held_receipts().len(),
        1,
        "a second receipt was reserved"
    );
}
