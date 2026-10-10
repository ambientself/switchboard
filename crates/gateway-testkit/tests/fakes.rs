//! Each fake does what it says, and each way a fake can be told to fail has a test that shows
//! the failure happening and, as important, not happening when it has not been asked for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

use gateway_core::audit::{
    self, Answer, AuditFailure, AuditRowId, Begun, Completion, DecisionKind, ListRecord, Outcome,
    RecordedResource, RecordedResources, RequestMetadata, RowKind, RowStart,
};
use gateway_core::{
    AuditGuard, AuditRecord, AuditStore, BoxFuture, CallContext, Claimed, Connector, ConnectorName,
    CredentialError, CredentialHandle, CredentialSource, InstanceName, Principal, Proved,
    RequestedTool, Resource, Resources, TeamId, ToolCall, ToolOutcome, ToolUseId, decide,
    list_tools,
};
use gateway_identity::Clock;
use gateway_testkit::{
    Caller, DRAFT_REFUSAL, DRAFT_TOOL, FIXTURE_CALL_DEADLINE_MS, FIXTURE_INSTANCE, FIXTURE_NOW,
    FORBIDDEN_DOCUMENT, FOREIGN_DRAFT, FakeCredentialSource, FixedClock, Fixture, FixtureConnector,
    GROUP_G_DOCUMENT, Gate, InMemoryAuditStore, PROFILE_TEAM_B, READ_TOOL, RESOURCE_KIND,
    RESOURCE_SYSTEM, SCOPE_REFUSAL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, SteppableClock,
    StoreBudgets, TEAM_A, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT, WRITE_TOOL, WriteRecord, block_on,
    document, policy_data, poll_once, row_start,
};
use serde_json::{Value, json};

fn fixture() -> Fixture {
    Fixture::new().unwrap()
}

/// An allowed call's guard, from the real decision and the real begin step, written to `store`.
fn guard_for(
    fixture: &Fixture,
    store: &dyn AuditStore,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> AuditGuard {
    let resources = FixtureConnector::resources_of(tool, &arguments);
    let call = CallContext {
        caller: fixture.caller_context(caller, SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(tool),
        resources,
    };
    let decision = decide(&fixture.policy, &call);
    assert!(decision.is_allowed(), "{decision:?}");
    match block_on(audit::begin(
        store,
        row_start(),
        decision,
        arguments,
        RequestMetadata::default(),
    ))
    .unwrap()
    {
        Begun::Allowed(guard) => guard,
        Begun::Denied(refusal) => panic!("{refusal:?}"),
    }
}

fn principal(fixture: &Fixture, caller: Caller) -> Proved<Principal> {
    fixture.principal(caller).unwrap()
}

/// Asks `source` for the fixture connector's credential for `caller`, as a connector would.
fn ask(
    source: &FakeCredentialSource,
    caller: &Proved<Principal>,
) -> Result<CredentialHandle, CredentialError> {
    block_on(source.credential_for(&ConnectorName::from("fixture"), caller))
}

// --- Clocks ---------------------------------------------------------------------------------

#[test]
fn a_fixed_clock_never_moves_and_a_steppable_one_moves_only_when_told() {
    let fixed = FixedClock::at(FIXTURE_NOW);
    assert_eq!(fixed.now(), UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW));
    assert_eq!(fixed.now(), fixed.now());

    let clock = SteppableClock::at(100);
    let other_handle = clock.clone();
    assert_eq!(clock.now(), UNIX_EPOCH + Duration::from_secs(100));
    clock.advance(Duration::from_millis(1500));
    assert_eq!(
        other_handle.unix_millis(),
        101_500,
        "a clone shares the time"
    );
    other_handle.set(7);
    assert_eq!(clock.unix_millis(), 7_000, "set can go back");
    clock.advance(Duration::MAX);
    assert_eq!(
        clock.unix_millis(),
        u64::MAX,
        "advance saturates rather than wraps"
    );
}

// --- The gate -------------------------------------------------------------------------------

#[test]
fn a_gate_holds_until_it_is_opened_and_then_lets_everything_through() {
    let gate = Gate::closed();
    let mut first = pin!(gate.wait());
    let mut second = Box::pin(gate.wait());
    assert_eq!(poll_once(first.as_mut()), Poll::Pending);
    assert_eq!(poll_once(second.as_mut()), Poll::Pending);
    assert_eq!(gate.waiting(), 2);
    gate.open();
    assert_eq!(poll_once(first.as_mut()), Poll::Ready(()));
    assert_eq!(gate.waiting(), 1);
    drop(second);
    assert_eq!(gate.waiting(), 0, "a wait that is dropped stops counting");
    assert_eq!(
        poll_once(pin!(gate.wait())),
        Poll::Ready(()),
        "an open gate stays open"
    );
}

/// The gate wakes the task that is waiting at it, on whatever executor: a thread parked in
/// `block_on` is woken by `open`. Bounded by a timeout so that a gate that never wakes fails
/// the test rather than hanging it.
#[test]
fn opening_a_gate_wakes_a_task_parked_at_it() {
    let gate = Gate::closed();
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiter = gate.clone();
    std::thread::spawn(move || {
        block_on(waiter.wait());
        let _ = sender.send(());
    });
    // Wait for the task to arrive at the gate, then open it.
    let mut spins = 0u32;
    while gate.waiting() == 0 {
        std::thread::yield_now();
        spins += 1;
        assert!(spins < 50_000_000, "the task never reached the gate");
    }
    gate.open();
    assert!(
        receiver.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the task was not woken when the gate opened"
    );
}

// --- The audit store ------------------------------------------------------------------------

#[test]
fn rows_come_back_in_the_order_they_were_begun_with_completions_filled_in() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let first = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes", "n": 1}),
    );
    let second = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes", "n": 2}),
    );
    assert_eq!(store.rows().len(), 2);
    assert!(store.rows().iter().all(|row| row.completion.is_none()));
    let begun = store.rows();
    assert_eq!(
        (&begun[0].resources, begun[0].resources_omitted),
        (
            &RecordedResources::Named(vec![RecordedResource {
                system: RESOURCE_SYSTEM.to_owned(),
                kind: RESOURCE_KIND.to_owned(),
                identifier: "team-a-notes".to_owned(),
            }]),
            0
        ),
        "the row keeps the resources the begin step recorded"
    );

    // Finishing the second first completes the second row, and only that one.
    let ran = block_on(audit::run(&connector, second));
    block_on(audit::finish(&store, ran, 5));
    let rows = store.rows();
    assert_eq!(rows[0], begun[0], "the other row is untouched");
    assert_eq!(
        AuditRecord {
            completion: None,
            ..rows[1].clone()
        },
        begun[1],
        "finishing a row fills in its completion and changes nothing else"
    );
    assert_eq!(
        rows[1].completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 5
        })
    );
    assert_eq!(store.row(1), Some(rows[1].clone()));
    assert_eq!(store.row(2), None);
    let ran = block_on(audit::run(&connector, first));
    block_on(audit::finish(&store, ran, 6));
    assert_eq!(
        store.rows()[0].completion.as_ref().map(|c| c.latency_ms),
        Some(6)
    );
    assert_eq!((store.begin_attempts(), store.finish_attempts()), (2, 2));
}

/// Every other row here omits no resources, so a store that dropped the count would pass them.
/// Team A may reach three more documents than a row records, and the call names them all.
#[test]
fn a_row_keeps_its_count_of_omitted_resources_through_begin_and_finish() {
    let (mut fixture, store) = (fixture(), InMemoryAuditStore::new());
    let named: Vec<Resource> = (0..audit::MAX_RECORDED_RESOURCES + 3)
        .map(|n| document(&format!("team-a-{n}")))
        .collect();
    let mut data = policy_data();
    data["limits"]["teams"][TEAM_A] = serde_json::to_value(&named).unwrap();
    fixture.policy = serde_json::from_value(data).unwrap();
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
        resources: Resources::Named(named),
    };
    let decision = decide(&fixture.policy, &call);
    assert!(decision.is_allowed(), "{decision:?}");
    let begun = block_on(audit::begin(
        &store,
        row_start(),
        decision,
        json!({"document": "team-a-0"}),
        RequestMetadata::default(),
    ));
    let Ok(Begun::Allowed(guard)) = begun else {
        panic!("{begun:?}")
    };
    assert_eq!(store.rows()[0].resources_omitted, 3, "begin kept the count");

    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let ran = block_on(audit::run(&connector, guard));
    block_on(audit::finish(&store, ran, 5));
    let row = store.row(0).unwrap();
    assert!(row.completion.is_some(), "{row:?}");
    assert_eq!(row.resources_omitted, 3, "finish kept the count");
}

#[test]
fn a_failed_begin_writes_nothing_and_the_next_one_works() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    store.fail_next_begin();
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
        resources: FixtureConnector::resources_of(READ_TOOL, &json!({"document": "team-a-notes"})),
    };
    let decision = decide(&fixture.policy, &call);
    let failure = block_on(audit::begin(
        &store,
        row_start(),
        decision,
        json!({}),
        RequestMetadata::default(),
    ));
    assert!(failure.is_err());
    assert!(
        store.rows().is_empty(),
        "a begin that failed left a row behind"
    );
    assert_eq!(store.begin_attempts(), 1);
    // Only the next one failed.
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes"}),
    );
    drop(guard);
    assert_eq!(store.rows().len(), 1);
}

#[test]
fn every_begin_fails_until_told_to_stop() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    store.fail_all_begins();
    let attempt = || {
        let call = CallContext {
            caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
            tool: RequestedTool::new(READ_TOOL),
            resources: FixtureConnector::resources_of(
                READ_TOOL,
                &json!({"document": "team-a-notes"}),
            ),
        };
        block_on(audit::begin(
            &store,
            row_start(),
            decide(&fixture.policy, &call),
            json!({}),
            RequestMetadata::default(),
        ))
        .is_err()
    };
    assert!(attempt() && attempt() && attempt());
    assert!(store.rows().is_empty());
    store.stop_failing();
    assert!(!attempt());
    assert_eq!(store.rows().len(), 1);
}

#[test]
fn a_failed_finish_leaves_the_row_with_an_empty_outcome_and_the_next_one_works() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    store.fail_next_finish();
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes"}),
    );
    let finished = block_on(audit::finish(
        &store,
        block_on(audit::run(&connector, guard)),
        1,
    ));
    assert!(finished.failure().is_some());
    assert_eq!(store.rows()[0].completion, None);
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes"}),
    );
    let finished = block_on(audit::finish(
        &store,
        block_on(audit::run(&connector, guard)),
        2,
    ));
    assert!(finished.failure().is_none());
    assert_eq!(
        store.rows()[1].completion.as_ref().map(|c| c.latency_ms),
        Some(2)
    );
}

#[test]
fn every_finish_fails_until_told_to_stop() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    store.fail_all_finishes();
    for _ in 0..2 {
        let guard = guard_for(
            &fixture,
            &store,
            Caller::TeamA,
            READ_TOOL,
            json!({"document": "team-a-notes"}),
        );
        let finished = block_on(audit::finish(
            &store,
            block_on(audit::run(&connector, guard)),
            1,
        ));
        assert!(finished.failure().is_some());
    }
    assert!(store.rows().iter().all(|row| row.completion.is_none()));
    store.stop_failing();
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes"}),
    );
    let finished = block_on(audit::finish(
        &store,
        block_on(audit::run(&connector, guard)),
        1,
    ));
    assert!(finished.failure().is_none());
    assert_eq!(
        store
            .rows()
            .iter()
            .filter(|row| row.completion.is_some())
            .count(),
        1
    );
}

#[test]
fn a_held_begin_writes_no_row_until_released() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let gate = store.hold_begins();
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
        resources: FixtureConnector::resources_of(READ_TOOL, &json!({"document": "team-a-notes"})),
    };
    let decision = decide(&fixture.policy, &call);
    let mut begin = pin!(audit::begin(
        &store,
        row_start(),
        decision,
        json!({}),
        RequestMetadata::default()
    ));
    assert!(poll_once(begin.as_mut()).is_pending());
    assert_eq!(gate.waiting(), 1);
    assert!(
        store.rows().is_empty(),
        "the row was written while the store was held"
    );
    assert_eq!(
        store.begin_attempts(),
        1,
        "the attempt is visible while it is held"
    );
    gate.open();
    assert!(matches!(
        poll_once(begin.as_mut()),
        Poll::Ready(Ok(Begun::Allowed(_)))
    ));
    assert_eq!(store.rows().len(), 1);
}

#[test]
fn a_held_finish_leaves_the_outcome_empty_until_released() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": "team-a-notes"}),
    );
    let ran = block_on(audit::run(&connector, guard));
    let gate = store.hold_finishes();
    let mut finish = pin!(audit::finish(&store, ran, 9));
    assert!(poll_once(finish.as_mut()).is_pending());
    assert_eq!(store.rows()[0].completion, None);
    gate.open();
    assert!(poll_once(finish.as_mut()).is_ready());
    assert_eq!(
        store.rows()[0].completion.as_ref().map(|c| c.latency_ms),
        Some(9)
    );
}

#[test]
fn a_failure_setting_is_not_consumed_by_a_held_call_until_it_is_released() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let gate = store.hold_begins();
    store.fail_next_begin();
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
        resources: FixtureConnector::resources_of(READ_TOOL, &json!({"document": "team-a-notes"})),
    };
    let mut begin = pin!(audit::begin(
        &store,
        row_start(),
        decide(&fixture.policy, &call),
        json!({}),
        RequestMetadata::default()
    ));
    assert!(poll_once(begin.as_mut()).is_pending());
    gate.open();
    assert!(matches!(poll_once(begin.as_mut()), Poll::Ready(Err(_))));
    assert!(store.rows().is_empty());
}

/// Begins team A's call to `tool` naming its own notes, as the row `start` names. The read
/// tool is allowed and the direct-write tool denied.
fn begin_as(
    fixture: &Fixture,
    store: &InMemoryAuditStore,
    start: &RowStart,
    tool: &str,
) -> Result<Begun, AuditFailure> {
    let arguments = json!({"document": TEAM_A_DOCUMENT});
    let call = CallContext {
        caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(tool),
        resources: FixtureConnector::resources_of(tool, &arguments),
    };
    block_on(audit::begin(
        store,
        start.clone(),
        decide(&fixture.policy, &call),
        arguments,
        RequestMetadata::default(),
    ))
}

/// Begins, runs and finishes team A's read as the row `start` names, with `latency_ms`.
fn read_and_finish(
    fixture: &Fixture,
    store: &InMemoryAuditStore,
    start: &RowStart,
    latency_ms: u64,
) -> Option<String> {
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let Ok(Begun::Allowed(guard)) = begin_as(fixture, store, start, READ_TOOL) else {
        panic!("the read was not allowed");
    };
    assert_eq!(guard.row(), &start.row);
    let ran = block_on(audit::run(&connector, guard));
    block_on(audit::finish(store, ran, latency_ms))
        .failure()
        .map(ToString::to_string)
}

/// The store sets each row's time at begin and deadline from its own clock, as Postgres does:
/// the time at begin plus the begin budget, the row's call deadline and the finish deadline.
#[test]
fn the_deadline_comes_from_the_stores_clock_and_includes_the_begin_budget() {
    let fixture = fixture();
    let clock = SteppableClock::at(FIXTURE_NOW);
    let budgets = StoreBudgets {
        begin: Duration::from_millis(1_500),
        finish_deadline: Duration::from_secs(20),
    };
    let store = InMemoryAuditStore::new()
        .with_clock(Arc::new(clock.clone()))
        .with_budgets(budgets);
    clock.advance(Duration::from_secs(90));
    let start = RowStart {
        call_deadline_ms: 7_250,
        ..row_start()
    };
    assert_eq!(store.deadline(&start.row), None, "no row yet");
    let denied = row_start();
    assert!(begin_as(&fixture, &store, &start, READ_TOOL).is_ok());
    clock.advance(Duration::from_secs(1));
    assert!(begin_as(&fixture, &store, &denied, WRITE_TOOL).is_ok());

    let begun_at = UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW + 90);
    assert_eq!(store.begun_at(&start.row), Some(begun_at));
    assert_eq!(
        store.deadline(&start.row),
        Some(begun_at + Duration::from_millis(1_500 + 7_250 + 20_000))
    );
    // A denial is a call row too, begun a second later, with the fixture's call deadline.
    let begun_at = begun_at + Duration::from_secs(1);
    assert_eq!(store.begun_at(&denied.row), Some(begun_at));
    assert_eq!(
        store.deadline(&denied.row),
        Some(begun_at + Duration::from_millis(1_500 + FIXTURE_CALL_DEADLINE_MS + 20_000))
    );

    // The record carries the instance and the call deadline, and no time.
    let row = store.row_with_id(&start.row).unwrap();
    assert_eq!(row.kind, RowKind::Call);
    assert_eq!(row.instance.as_str(), FIXTURE_INSTANCE);
    assert_eq!(row.call_deadline_ms, 7_250);

    // A retried begin keeps the first row's times.
    clock.advance(Duration::from_secs(60));
    assert!(begin_as(&fixture, &store, &start, READ_TOOL).is_ok());
    assert_eq!(
        store.begun_at(&start.row),
        Some(UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW + 90))
    );
}

/// Lists team A's tools on the full surface as the row `start` names.
fn list_as(
    fixture: &Fixture,
    store: &InMemoryAuditStore,
    start: &RowStart,
) -> Result<audit::Listed, AuditFailure> {
    let caller = fixture.team_a_workload(SURFACE_ALL).unwrap();
    block_on(audit::listed(
        store,
        start.clone(),
        &caller,
        fixture.policy.revision().clone(),
        list_tools(&fixture.policy, &caller),
        None,
    ))
}

/// A list row is kept apart from call rows, has a time at begin from the store's clock and no
/// deadline, and is written once per identifier. An identifier of the other kind is refused
/// either way, and the stored row stands.
#[test]
fn a_list_row_has_no_deadline_and_is_written_once_per_identifier() {
    let fixture = fixture();
    let store = InMemoryAuditStore::new();
    let start = row_start();
    let listed = list_as(&fixture, &store, &start).unwrap();
    assert_eq!(listed.row(), &start.row);
    assert!(!listed.tools().is_empty());
    assert!(
        list_as(&fixture, &store, &start).is_ok(),
        "a retried list failed"
    );
    let rows = store.list_rows();
    assert_eq!(rows.len(), 1, "a retried list wrote a second row");
    assert_eq!(rows[0].0, start.row);
    assert_eq!(rows[0].1.instance.as_str(), FIXTURE_INSTANCE);
    assert!(store.rows().is_empty(), "a list wrote a call row");
    assert_eq!(
        store.begun_at(&start.row),
        Some(UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW))
    );
    assert_eq!(store.deadline(&start.row), None);
    assert_eq!(store.begin_attempts(), 0);

    assert!(begin_as(&fixture, &store, &start, READ_TOOL).is_err());
    let call = row_start();
    assert!(begin_as(&fixture, &store, &call, READ_TOOL).is_ok());
    assert!(list_as(&fixture, &store, &call).is_err());
    assert_eq!((store.rows().len(), store.list_rows().len()), (1, 1));

    // A list fails as a begin would, and writes nothing.
    store.fail_next_begin();
    let failed = list_as(&fixture, &store, &row_start());
    assert!(failed.is_err());
    assert_eq!(store.list_rows().len(), 1);
}

#[test]
fn the_default_budgets_are_the_postgres_stores() {
    let store = InMemoryAuditStore::new();
    let start = row_start();
    assert!(begin_as(&fixture(), &store, &start, READ_TOOL).is_ok());
    let begun_at = UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW);
    assert_eq!(store.begun_at(&start.row), Some(begun_at));
    assert_eq!(
        store.deadline(&start.row),
        Some(begun_at + Duration::from_millis(2_000 + FIXTURE_CALL_DEADLINE_MS + 30_000))
    );
}

#[test]
fn a_second_begin_with_one_identifier_writes_one_row() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let start = row_start();
    for _ in 0..2 {
        let begun = begin_as(&fixture, &store, &start, READ_TOOL);
        assert!(matches!(begun, Ok(Begun::Allowed(_))), "{begun:?}");
    }
    assert_eq!(store.rows().len(), 1, "a retried begin wrote a second row");
    assert_eq!(store.begin_attempts(), 2);
    assert_eq!(store.row_with_id(&start.row), store.row(0));

    // Another identifier is another row.
    let other = row_start();
    assert_ne!(other, start);
    assert!(begin_as(&fixture, &store, &other, READ_TOOL).is_ok());
    assert_eq!(store.rows().len(), 2);
    assert_eq!(store.row_with_id(&other.row), store.row(1));
}

#[test]
fn a_begin_with_a_known_identifier_and_another_decision_is_refused() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let start = row_start();
    let denied = begin_as(&fixture, &store, &start, WRITE_TOOL);
    assert!(matches!(denied, Ok(Begun::Denied(_))), "{denied:?}");
    let allowed = begin_as(&fixture, &store, &start, READ_TOOL);
    assert!(
        allowed.is_err(),
        "an allowed call was begun under a denial's identifier: {allowed:?}"
    );
    assert_eq!(store.rows().len(), 1);
    let row = store.row_with_id(&start.row).unwrap();
    assert_eq!(row.decision, DecisionKind::Deny, "the first row stands");
    assert_eq!(row.tool, WRITE_TOOL);
    assert_eq!(store.row_with_id(&row_start().row), None);
}

#[test]
fn an_identical_second_completion_is_accepted() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let start = row_start();
    assert_eq!(read_and_finish(&fixture, &store, &start, 5), None);
    assert_eq!(
        read_and_finish(&fixture, &store, &start, 5),
        None,
        "a retried finish with the same completion failed"
    );
    assert_eq!(store.rows().len(), 1);
    assert_eq!(store.finish_attempts(), 2);
    assert_eq!(
        store.row(0).unwrap().completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 5
        })
    );
}

#[test]
fn a_different_second_completion_is_refused_and_the_first_stands() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let start = row_start();
    assert_eq!(read_and_finish(&fixture, &store, &start, 5), None);
    assert!(
        read_and_finish(&fixture, &store, &start, 9).is_some(),
        "a second, different completion for one row was accepted"
    );
    assert_eq!(
        store.row(0).unwrap().completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 5
        }),
        "the row kept its first completion"
    );
    assert_eq!(store.rows().len(), 1);
    assert_eq!(store.finish_attempts(), 2);
}

// --- The audit store's faults ---------------------------------------------------------------

/// The completion the store gives an allowed row whose begin confirmation was lost.
fn completed_as_error() -> Option<Completion> {
    Some(Completion {
        outcome: Outcome::Error,
        latency_ms: 0,
    })
}

#[test]
fn a_lost_confirmation_writes_the_row_and_completes_it_as_error() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    store.lose_next_begin_confirmation();
    let start = row_start();
    let begun = begin_as(&fixture, &store, &start, READ_TOOL);
    assert!(
        begun.is_err(),
        "a begin whose confirmation was lost succeeded: {begun:?}"
    );
    let row = store
        .row_with_id(&start.row)
        .expect("a lost confirmation wrote no row");
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion,
        completed_as_error(),
        "an allowed row whose confirmation was lost was left open"
    );
    assert!(store.deadline(&start.row).is_some());

    // Only the next one was lost.
    let next = row_start();
    let begun = begin_as(&fixture, &store, &next, READ_TOOL);
    assert!(matches!(begun, Ok(Begun::Allowed(_))), "{begun:?}");
    assert_eq!(store.row_with_id(&next.row).unwrap().completion, None);

    // Every one is lost until told to stop, a retry by identifier included, and each
    // identifier is one row.
    store.lose_all_begin_confirmations();
    let retried = row_start();
    let other = row_start();
    for start in [&retried, &retried, &other] {
        assert!(begin_as(&fixture, &store, start, READ_TOOL).is_err());
    }
    assert_eq!(store.rows().len(), 4);
    for start in [&retried, &other] {
        assert_eq!(
            store.row_with_id(&start.row).unwrap().completion,
            completed_as_error()
        );
    }
    store.stop_failing();
    let last = row_start();
    let begun = begin_as(&fixture, &store, &last, READ_TOOL);
    assert!(matches!(begun, Ok(Begun::Allowed(_))), "{begun:?}");
    assert_eq!(store.row_with_id(&last.row).unwrap().completion, None);
    assert_eq!(store.begin_attempts(), 6);
}

#[test]
fn a_lost_confirmation_on_a_denial_leaves_the_denial() {
    let fixture = fixture();
    let (store, confirmed) = (InMemoryAuditStore::new(), InMemoryAuditStore::new());
    store.lose_all_begin_confirmations();
    let start = row_start();
    assert!(begin_as(&fixture, &store, &start, WRITE_TOOL).is_err());
    let denied = begin_as(&fixture, &confirmed, &start, WRITE_TOOL);
    assert!(matches!(denied, Ok(Begun::Denied(_))), "{denied:?}");
    let row = store
        .row_with_id(&start.row)
        .expect("a lost confirmation wrote no row");
    assert_eq!(row.decision, DecisionKind::Deny);
    assert_eq!(row.completion, None, "a denial was completed");
    assert_eq!(
        Some(row),
        confirmed.row(0),
        "the denial is the row a confirmed begin writes"
    );

    // A list row is written complete, and is left as it is too.
    let listed = row_start();
    assert!(list_as(&fixture, &store, &listed).is_err());
    let rows = store.list_rows();
    assert_eq!(rows.len(), 1, "a lost confirmation wrote no list row");
    assert_eq!(rows[0].0, listed.row);
    assert_eq!(store.rows().len(), 1);
}

#[test]
fn finish_past_the_answer_budget_fails_and_completes_once_released() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let read = || json!({"document": TEAM_A_DOCUMENT});
    let guard = guard_for(&fixture, &store, Caller::TeamA, READ_TOOL, read());
    let row = guard.row().clone();
    let ran = block_on(audit::run(&connector, guard));
    let gate = store.finish_past_answer_budget();

    // The answer does not wait for the gate.
    let mut finish = pin!(audit::finish(&store, ran, 9));
    let Poll::Ready(finished) = poll_once(finish.as_mut()) else {
        panic!("finish waited past the answer budget");
    };
    let failure = finished
        .failure()
        .expect("a finish past the answer budget succeeded")
        .to_string();
    assert!(failure.contains("answer budget"), "{failure}");
    assert!(
        matches!(finished.answer(), Answer::Ok(_)),
        "{:?}",
        finished.answer()
    );
    assert_eq!(
        store.row_with_id(&row).unwrap().completion,
        None,
        "the row was completed before the gate opened"
    );
    assert_eq!(store.finish_attempts(), 1);

    gate.open();
    assert_eq!(
        store.row_with_id(&row).unwrap().completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 9
        }),
        "the row was not completed once the gate opened"
    );

    // Once the gate is open, finish writes at once.
    let guard = guard_for(&fixture, &store, Caller::TeamA, READ_TOOL, read());
    let other = guard.row().clone();
    let ran = block_on(audit::run(&connector, guard));
    let finished = block_on(audit::finish(&store, ran, 4));
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert_eq!(
        store
            .row_with_id(&other)
            .unwrap()
            .completion
            .map(|completion| completion.latency_ms),
        Some(4)
    );
    assert_eq!(
        store
            .row_with_id(&row)
            .unwrap()
            .completion
            .map(|completion| completion.latency_ms),
        Some(9)
    );
}

#[test]
fn a_forgotten_finish_leaves_the_row_open_for_a_new_gateway() {
    let fixture = fixture();
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let read = || json!({"document": TEAM_A_DOCUMENT});
    let store = Arc::new(InMemoryAuditStore::new());

    // The first gateway's process runs two calls. The finish of the first is still being tried
    // past the answer budget when the process is lost, and the second has not finished.
    let first: Arc<dyn AuditStore> = store.clone();
    let late = guard_for(&fixture, first.as_ref(), Caller::TeamA, READ_TOOL, read());
    let late_row = late.row().clone();
    let gate = store.finish_past_answer_budget();
    let ran = block_on(audit::run(&connector, late));
    assert!(
        block_on(audit::finish(first.as_ref(), ran, 3))
            .failure()
            .is_some()
    );
    let open = guard_for(&fixture, first.as_ref(), Caller::TeamA, READ_TOOL, read());
    let open_row = open.row().clone();
    let ran = block_on(audit::run(&connector, open));

    store.forget_finishes();
    let finished = block_on(audit::finish(first.as_ref(), ran, 5));
    assert!(
        finished.failure().is_some(),
        "a finish from a lost process succeeded"
    );
    drop(first);
    gate.open();

    // A new gateway over the same store finds both rows open, and completes only its own.
    store.stop_failing();
    let second: Arc<dyn AuditStore> = store.clone();
    for row in [&late_row, &open_row] {
        assert_eq!(
            store.row_with_id(row).unwrap().completion,
            None,
            "a row the lost process never finished was completed"
        );
        assert!(store.deadline(row).is_some());
    }
    let guard = guard_for(&fixture, second.as_ref(), Caller::TeamA, READ_TOOL, read());
    let own = guard.row().clone();
    let ran = block_on(audit::run(&connector, guard));
    let finished = block_on(audit::finish(second.as_ref(), ran, 6));
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert!(store.row_with_id(&own).unwrap().completion.is_some());
    for row in [&late_row, &open_row] {
        assert_eq!(store.row_with_id(row).unwrap().completion, None);
    }
    assert_eq!(store.rows().len(), 3);
}

/// Postgres's `complete_once` refuses to complete a denial or a list row, whatever the
/// completion. The fake refuses the same on every path a completion takes: a finish that
/// writes at once, one written late past the answer budget, and a lost begin's (the denial in
/// `a_lost_confirmation_on_a_denial_leaves_the_denial`). A test reaches such a row with a
/// guard from one store and a second store that holds a denial or a list row under the
/// guard's identifier.
#[test]
fn a_denial_or_a_list_row_is_never_completed() {
    let fixture = fixture();
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let allowed = InMemoryAuditStore::new();
    let other = InMemoryAuditStore::new();
    // An allowed call run under a guard from `allowed`, after `write` has written the row of
    // the same identifier to `other`.
    let ran_after = |write: &dyn Fn(&RowStart)| {
        let read = json!({"document": TEAM_A_DOCUMENT});
        let guard = guard_for(&fixture, &allowed, Caller::TeamA, READ_TOOL, read);
        let row = guard.row().clone();
        write(&RowStart {
            row: row.clone(),
            ..row_start()
        });
        (row, block_on(audit::run(&connector, guard)))
    };
    let deny = |start: &RowStart| {
        let denied = begin_as(&fixture, &other, start, WRITE_TOOL);
        assert!(matches!(denied, Ok(Begun::Denied(_))), "{denied:?}");
    };

    // A denial, finished at once.
    let (denial, ran) = ran_after(&deny);
    let failure = block_on(audit::finish(&other, ran, 7))
        .failure()
        .expect("a denial was completed")
        .to_string();
    assert!(failure.contains("records a denial"), "{failure}");
    assert_eq!(other.row_with_id(&denial).unwrap().completion, None);

    // A denial, finished past the answer budget and written once the gate opens.
    let gate = other.finish_past_answer_budget();
    let (late, ran) = ran_after(&deny);
    assert!(block_on(audit::finish(&other, ran, 8)).failure().is_some());
    gate.open();
    assert_eq!(
        other.row_with_id(&late).unwrap().completion,
        None,
        "a late completion completed a denial"
    );

    // A list row. It is not a call row, and finish does not make one.
    let (listed, ran) = ran_after(&|start| assert!(list_as(&fixture, &other, start).is_ok()));
    let failure = block_on(audit::finish(&other, ran, 9))
        .failure()
        .expect("a list row was completed")
        .to_string();
    assert!(failure.contains("records a listing"), "{failure}");
    assert_eq!(other.row_with_id(&listed), None);

    // A record of kind list handed to begin. The fake keeps it as a call row, where the
    // Postgres table's kind_shape would refuse it, and finish refuses it by its kind.
    let (call, _) = records(&fixture);
    let (kind_list, ran) = ran_after(&|start| {
        let record = AuditRecord {
            kind: RowKind::List,
            ..call.clone()
        };
        block_on(other.begin(&start.row, &record)).unwrap();
    });
    let failure = block_on(audit::finish(&other, ran, 10))
        .failure()
        .expect("a call row of kind list was completed")
        .to_string();
    assert!(failure.contains("records a listing"), "{failure}");
    assert_eq!(other.row_with_id(&kind_list).unwrap().completion, None);

    // The allowed rows themselves are open, and complete.
    let (own, ran) = ran_after(&|_| {});
    let finished = block_on(audit::finish(&allowed, ran, 11));
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert!(allowed.row_with_id(&own).unwrap().completion.is_some());
    assert_eq!(allowed.rows().len(), 5);
}

/// A connector that refuses every call with a sentence holding U+0000.
struct NulRefusal;

impl Connector for NulRefusal {
    fn run(&self, _call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(async { ToolOutcome::Refused("refused\0here".to_owned()) })
    }
}

/// An allowed call record and a denied one, as the core writes them for team A.
fn records(fixture: &Fixture) -> (AuditRecord, AuditRecord) {
    let scratch = InMemoryAuditStore::new();
    assert!(begin_as(fixture, &scratch, &row_start(), READ_TOOL).is_ok());
    assert!(begin_as(fixture, &scratch, &row_start(), WRITE_TOOL).is_ok());
    (scratch.row(0).unwrap(), scratch.row(1).unwrap())
}

/// A list record, as the core writes it for team A.
fn list_record(fixture: &Fixture) -> ListRecord {
    let scratch = InMemoryAuditStore::new();
    assert!(list_as(fixture, &scratch, &row_start()).is_ok());
    scratch.list_rows().remove(0).1
}

/// Postgres text, text arrays and jsonb cannot hold U+0000, so the Postgres store refuses a
/// record with it in any text value rather than write another character. The fake refuses the
/// same records, and writes them without it.
#[test]
fn a_nul_in_a_value_refuses_the_record_and_writes_no_row() {
    let fixture = fixture();
    let (allowed, denied) = records(&fixture);
    let refused = [
        AuditRecord {
            tool: format!("{READ_TOOL}\0"),
            ..allowed.clone()
        },
        AuditRecord {
            instance: InstanceName::new("instance\0"),
            ..allowed.clone()
        },
        AuditRecord {
            tool_use_id: Some(ToolUseId::new("use\0")),
            ..allowed.clone()
        },
        AuditRecord {
            claimed_team: Some(Claimed::new(TeamId::new("team\0"))),
            ..allowed.clone()
        },
        AuditRecord {
            resources: RecordedResources::Named(vec![RecordedResource {
                system: RESOURCE_SYSTEM.to_owned(),
                kind: RESOURCE_KIND.to_owned(),
                identifier: "notes\0".to_owned(),
            }]),
            ..allowed.clone()
        },
        AuditRecord {
            sentence: Some("denied\0".to_owned()),
            ..denied.clone()
        },
    ];
    let store = InMemoryAuditStore::new();
    for record in &refused {
        let error = block_on(store.begin(&row_start().row, record))
            .expect_err("a record with U+0000 was written")
            .to_string();
        assert!(error.contains("U+0000"), "{error}");
    }
    assert!(store.rows().is_empty(), "a record with U+0000 left a row");
    for record in [&allowed, &denied] {
        assert!(block_on(store.begin(&row_start().row, record)).is_ok());
    }
    assert_eq!(store.rows().len(), 2);

    // A list record with U+0000 in a tool's name.
    let listed = list_record(&fixture);
    let mut tools = listed.tools.clone();
    tools.push("tool\0".to_owned());
    let refused = ListRecord {
        tools,
        ..listed.clone()
    };
    assert!(block_on(store.list(&row_start().row, &refused)).is_err());
    assert!(
        store.list_rows().is_empty(),
        "a list row with U+0000 was written"
    );
    assert!(block_on(store.list(&row_start().row, &listed)).is_ok());

    // A connector's refusal sentence with U+0000 is not written as the row's completion.
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": TEAM_A_DOCUMENT}),
    );
    let row = guard.row().clone();
    let ran = block_on(audit::run(&NulRefusal, guard));
    let finished = block_on(audit::finish(&store, ran, 5));
    assert!(
        finished.failure().is_some(),
        "a completion with U+0000 was written"
    );
    assert_eq!(store.row_with_id(&row).unwrap().completion, None);
}

/// The Postgres store writes counts and latencies as `bigint`, and refuses one past it rather
/// than write less than it was. The fake refuses the same, and accepts the largest.
#[test]
fn a_count_or_a_latency_past_a_postgres_bigint_is_refused_and_writes_nothing() {
    let fixture = fixture();
    let most = usize::try_from(i64::MAX).unwrap();
    let (allowed, _) = records(&fixture);
    let listed = list_record(&fixture);
    let store = InMemoryAuditStore::new();
    let too_many = AuditRecord {
        resources_omitted: most + 1,
        ..allowed.clone()
    };
    assert!(block_on(store.begin(&row_start().row, &too_many)).is_err());
    let too_many = ListRecord {
        tools_omitted: most + 1,
        ..listed.clone()
    };
    assert!(block_on(store.list(&row_start().row, &too_many)).is_err());
    assert!(store.rows().is_empty() && store.list_rows().is_empty());

    let most_resources = AuditRecord {
        resources_omitted: most,
        ..allowed
    };
    assert!(block_on(store.begin(&row_start().row, &most_resources)).is_ok());
    let most_tools = ListRecord {
        tools_omitted: most,
        ..listed
    };
    assert!(block_on(store.list(&row_start().row, &most_tools)).is_ok());

    // A latency past a bigint is not written; the largest is.
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": TEAM_A_DOCUMENT}),
    );
    let row = guard.row().clone();
    let ran = block_on(audit::run(&connector, guard));
    let longest = i64::MAX.unsigned_abs();
    assert!(
        block_on(audit::finish(&store, ran, longest + 1))
            .failure()
            .is_some()
    );
    assert_eq!(store.row_with_id(&row).unwrap().completion, None);
    let guard = guard_for(
        &fixture,
        &store,
        Caller::TeamA,
        READ_TOOL,
        json!({"document": TEAM_A_DOCUMENT}),
    );
    let row = guard.row().clone();
    let ran = block_on(audit::run(&connector, guard));
    assert!(
        block_on(audit::finish(&store, ran, longest))
            .failure()
            .is_none()
    );
    assert_eq!(
        store
            .row_with_id(&row)
            .unwrap()
            .completion
            .map(|completion| completion.latency_ms),
        Some(longest)
    );
}

/// The Postgres store refuses an identifier that is not a UUID in the lowercase hyphenated
/// form, a record handed to begin already complete, and unknown resources with a count left
/// out. The fake refuses the same, and writes no row.
#[test]
fn an_identifier_a_completion_or_a_shape_postgres_refuses_writes_no_row() {
    let fixture = fixture();
    let (allowed, _) = records(&fixture);
    let listed = list_record(&fixture);
    let store = InMemoryAuditStore::new();
    let uuid = row_start().row;
    let spellings = [
        "not-a-uuid".to_owned(),
        "ROW-1".to_owned(),
        uuid.as_str().to_uppercase(),
        uuid.as_str().replace('-', ""),
        format!("{{{}}}", uuid.as_str()),
    ];
    for id in &spellings {
        let id = AuditRowId::new(id.clone());
        assert!(
            block_on(store.begin(&id, &allowed)).is_err(),
            "begin wrote the row {}",
            id.as_str()
        );
        assert!(
            block_on(store.list(&id, &listed)).is_err(),
            "list wrote the row {}",
            id.as_str()
        );
    }

    let complete = AuditRecord {
        completion: Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: u64::MAX,
        }),
        ..allowed.clone()
    };
    assert!(block_on(store.begin(&row_start().row, &complete)).is_err());
    let unknown_with_omitted = AuditRecord {
        resources: RecordedResources::Unknown,
        resources_omitted: 3,
        ..allowed.clone()
    };
    assert!(block_on(store.begin(&row_start().row, &unknown_with_omitted)).is_err());
    assert!(store.rows().is_empty() && store.list_rows().is_empty());

    // The same records, with a lowercase hyphenated identifier, no completion and no count
    // left out of unknown resources, are written.
    assert!(block_on(store.begin(&uuid, &allowed)).is_ok());
    assert!(block_on(store.list(&row_start().row, &listed)).is_ok());
    let unknown = AuditRecord {
        resources: RecordedResources::Unknown,
        resources_omitted: 0,
        ..allowed
    };
    assert!(block_on(store.begin(&row_start().row, &unknown)).is_ok());
    assert_eq!(store.rows().len(), 2);
    assert_eq!(store.list_rows().len(), 1);
}

/// The deadline is worked out as the Postgres store does: the begin budget and the finish
/// deadline in whole milliseconds, added to the call deadline without wrapping, and refused
/// past a `bigint` of milliseconds.
#[test]
fn the_deadline_is_counted_in_whole_milliseconds_and_never_wraps() {
    let fixture = fixture();
    let store = InMemoryAuditStore::new().with_budgets(StoreBudgets {
        begin: Duration::from_micros(1_500_999),
        finish_deadline: Duration::from_nanos(20_000_999_999),
    });
    let start = RowStart {
        call_deadline_ms: 7_250,
        ..row_start()
    };
    assert!(begin_as(&fixture, &store, &start, READ_TOOL).is_ok());
    let begun_at = UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW);
    assert_eq!(
        store.deadline(&start.row),
        Some(begun_at + Duration::from_millis(1_500 + 7_250 + 20_000))
    );

    // An allowance one past a bigint, and one that would wrap round to a short one.
    for call_deadline_ms in [i64::MAX.unsigned_abs() - 21_499, u64::MAX] {
        let start = RowStart {
            call_deadline_ms,
            ..row_start()
        };
        assert!(
            begin_as(&fixture, &store, &start, READ_TOOL).is_err(),
            "a call deadline of {call_deadline_ms} ms was written"
        );
        assert_eq!(store.row_with_id(&start.row), None);
    }
    assert_eq!(store.rows().len(), 1);
}

/// Postgres's `set_times` gives a call row the deadline `begun_at + allowance_ms * interval
/// '1 millisecond'`, and the insert fails where that arithmetic does: "timestamp out of range"
/// at or past 294277-01-01 UTC, and "interval out of range" at 2^63 microseconds or more. The
/// allowance is cast to `float8` on the way, so near those ends it moves by a few microseconds.
/// The fake refuses the same begins and gives the same deadlines. Each boundary here is one
/// Postgres 17 gives.
#[test]
fn the_deadline_is_refused_where_postgres_cannot_work_it_out() {
    let fixture = fixture();
    // The default budgets add 32,000 ms to the call deadline.
    let begin = |store: &InMemoryAuditStore, allowance_ms: u64| {
        let start = RowStart {
            call_deadline_ms: allowance_ms - 32_000,
            ..row_start()
        };
        let begun = begin_as(&fixture, store, &start, READ_TOOL);
        (start.row, begun.is_ok())
    };
    let postgres_epoch = UNIX_EPOCH + Duration::from_secs(946_684_800);
    let postgres_end = postgres_epoch + Duration::from_micros(9_223_371_331_200_000_000);

    // Begun at FIXTURE_NOW, the largest allowance Postgres accepts has a deadline 2,048
    // microseconds before the end: 294276-12-31 23:59:59.997952 UTC.
    let store = InMemoryAuditStore::new();
    let (row, begun) = begin(&store, 9_222_518_015_999_998);
    assert!(begun, "the largest allowance Postgres accepts was refused");
    assert_eq!(
        store.deadline(&row),
        Some(postgres_end - Duration::from_micros(2_048))
    );
    // One more is rounded to the end itself. A call deadline of 10^16 ms is within a bigint,
    // and past both ends.
    for allowance_ms in [
        9_222_518_015_999_999,
        9_222_518_016_000_000,
        10_000_000_000_000_000 + 32_000,
    ] {
        let (row, begun) = begin(&store, allowance_ms);
        assert!(!begun, "an allowance of {allowance_ms} ms was written");
        assert_eq!(store.row_with_id(&row), None);
    }
    assert_eq!(store.rows().len(), 1);

    // Begun at the Unix epoch, the end of a timestamp is further off than an interval holds,
    // so the interval is what refuses.
    let store = InMemoryAuditStore::new().with_clock(Arc::new(FixedClock::at(0)));
    let (row, begun) = begin(&store, 9_223_372_036_854_774);
    assert!(begun, "the largest interval Postgres accepts was refused");
    assert_eq!(
        store.deadline(&row),
        Some(UNIX_EPOCH + Duration::from_micros(9_223_372_036_854_773_760))
    );
    let (row, begun) = begin(&store, 9_223_372_036_854_775);
    assert!(!begun, "an interval of 2^63 microseconds was written");
    assert_eq!(store.row_with_id(&row), None);
    assert_eq!(store.rows().len(), 1);
}

// --- The credential source ------------------------------------------------------------------

#[test]
fn credentials_are_labelled_by_connector_team_and_count_and_every_request_is_recorded() {
    let (fixture, source) = (fixture(), FakeCredentialSource::new());
    let team_a = principal(&fixture, Caller::TeamA);
    let team_b = principal(&fixture, Caller::TeamB);
    let user = principal(&fixture, Caller::UserInGroupG);

    let label = |caller| ask(&source, caller).unwrap().label().to_owned();
    assert_eq!(label(&team_a), "fake-credential-for-fixture-team-a-1");
    assert_eq!(label(&team_b), "fake-credential-for-fixture-team-b-2");
    assert_eq!(label(&team_a), "fake-credential-for-fixture-team-a-3");
    assert_eq!(
        label(&user),
        "fake-credential-for-fixture-user-user-1@fixture.test-4"
    );

    let requests = source.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].principal, team_b.get().id);
    assert_eq!(requests[1].team, Some("team-b".into()));
    assert_eq!(requests[3].team, None);
    assert_eq!(
        requests[0].issued.as_deref(),
        Some("fake-credential-for-fixture-team-a-1")
    );
}

#[test]
fn a_credential_source_told_to_refuse_refuses_and_still_records_the_request() {
    let (fixture, source) = (fixture(), FakeCredentialSource::new());
    let caller = principal(&fixture, Caller::TeamA);
    let ask = || ask(&source, &caller);

    source.refuse_next();
    assert!(matches!(ask(), Err(CredentialError::Refused(_))));
    assert!(ask().is_ok(), "only the next request was refused");
    assert_eq!(
        ask().unwrap().label(),
        "fake-credential-for-fixture-team-a-2",
        "a refusal issues nothing and counts nothing"
    );

    source.refuse_all();
    assert!(ask().is_err() && ask().is_err());
    source.stop_refusing();
    assert!(ask().is_ok());

    let requests = source.requests();
    assert_eq!(requests.len(), 6, "refused requests are recorded too");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.issued.is_some())
            .collect::<Vec<_>>(),
        [false, true, true, false, false, true]
    );
}

#[test]
fn a_credential_source_told_to_be_unavailable_says_so_and_still_records_the_request() {
    let (fixture, source) = (fixture(), FakeCredentialSource::new());
    let caller = principal(&fixture, Caller::TeamA);
    let ask = || ask(&source, &caller);

    source.unavailable_next();
    assert_eq!(
        ask(),
        Err(CredentialError::Unavailable(
            "the fake credential source was told to be unavailable".into()
        ))
    );
    assert_eq!(
        ask().unwrap().label(),
        "fake-credential-for-fixture-team-a-1",
        "only the next request failed, and it issued nothing"
    );

    source.unavailable_all();
    assert!(matches!(ask(), Err(CredentialError::Unavailable(_))));
    assert!(matches!(ask(), Err(CredentialError::Unavailable(_))));
    // Refusing replaces being unavailable, and stopping ends either.
    source.refuse_all();
    assert!(matches!(ask(), Err(CredentialError::Refused(_))));
    source.stop_refusing();
    assert!(ask().is_ok());
    assert_eq!(
        source.requests().len(),
        6,
        "failed requests are recorded too"
    );
}

// --- The fixture connector ------------------------------------------------------------------

struct Rig {
    fixture: Fixture,
    store: InMemoryAuditStore,
    source: Arc<FakeCredentialSource>,
    connector: FixtureConnector,
}

fn rig() -> Rig {
    let source = Arc::new(FakeCredentialSource::new());
    Rig {
        fixture: fixture(),
        store: InMemoryAuditStore::new(),
        connector: FixtureConnector::new(source.clone()),
        source,
    }
}

impl Rig {
    fn guard(&self, caller: Caller, tool: &str, arguments: Value) -> AuditGuard {
        guard_for(&self.fixture, &self.store, caller, tool, arguments)
    }

    /// Runs an allowed call to its answer.
    fn answer(&self, caller: Caller, tool: &str, arguments: Value) -> Answer {
        let ran = block_on(audit::run(
            &self.connector,
            self.guard(caller, tool, arguments),
        ));
        block_on(audit::finish(&self.store, ran, 0))
            .answer()
            .clone()
    }
}

fn documents(name: &str) -> Value {
    json!({"document": name})
}

#[test]
fn the_read_tool_echoes_its_arguments_and_the_credential_label() {
    let rig = rig();
    let arguments = json!({"document": "team-a-notes", "extra": [1, 2]});
    let answer = rig.answer(Caller::TeamA, READ_TOOL, arguments.clone());
    assert_eq!(
        answer,
        Answer::Ok(json!({
            "tool": READ_TOOL,
            "echo": arguments,
            "credential": "fake-credential-for-fixture-team-a-1",
        }))
    );
    assert!(rig.connector.writes().is_empty(), "a read is not a write");
}

#[test]
fn the_draft_tool_opens_a_draft_and_records_a_write_under_the_callers_team_credential() {
    let rig = rig();
    assert!(rig.connector.writes().is_empty());
    let arguments = json!({"document": "team-a-notes", "text": "hi"});
    let answer = rig.answer(Caller::TeamA, DRAFT_TOOL, arguments.clone());
    assert_eq!(
        answer,
        Answer::Ok(json!({
            "tool": DRAFT_TOOL,
            "draft": "draft-1",
            "credential": "fake-credential-for-fixture-team-a-1",
        }))
    );
    assert_eq!(
        rig.connector.writes(),
        [WriteRecord {
            tool: DRAFT_TOOL.to_owned(),
            arguments,
            credential: "fake-credential-for-fixture-team-a-1".to_owned(),
            principal: rig
                .fixture
                .principal(Caller::TeamA)
                .unwrap()
                .get()
                .id
                .clone(),
        }]
    );
    // A call that names no draft opens another.
    let Answer::Ok(second) = rig.answer(Caller::TeamA, DRAFT_TOOL, documents("team-a-notes"))
    else {
        panic!("the second draft was not opened")
    };
    assert_eq!(second["draft"], "draft-2");
    assert_eq!(rig.connector.writes().len(), 2);
}

/// The fixture policy with team B's profile permitting proposals too, so that two teams each
/// open drafts.
fn with_team_b_proposing(rig: &mut Rig) {
    let mut data = policy_data();
    let profiles = data["profiles"].as_array_mut().unwrap();
    let team_b = profiles
        .iter_mut()
        .find(|profile| profile["name"] == PROFILE_TEAM_B)
        .unwrap();
    team_b["classifications"] = json!(["read", "propose"]);
    rig.fixture.policy = serde_json::from_value(data).unwrap();
}

/// A `propose` tool acts only on what the gateway created. The decision function cannot see
/// that, so it allows each of these calls, and the connector refuses them when they run.
#[test]
fn the_draft_tool_revises_only_a_draft_the_gateway_opened_for_the_same_document() {
    let mut rig = rig();
    with_team_b_proposing(&mut rig);
    let open =
        |caller: Caller| match rig.answer(caller, DRAFT_TOOL, documents(caller.own_document())) {
            Answer::Ok(answer) => answer["draft"].clone(),
            other => panic!("{caller:?} could not open a draft: {other:?}"),
        };
    let revise = |caller: Caller, draft: &Value| {
        rig.answer(
            caller,
            DRAFT_TOOL,
            json!({"document": caller.own_document(), "draft": draft, "text": "again"}),
        )
    };
    let team_a_draft = open(Caller::TeamA);
    let team_b_draft = open(Caller::TeamB);
    assert_eq!(
        (&team_a_draft, &team_b_draft),
        (&json!("draft-1"), &json!("draft-2"))
    );

    let Answer::Ok(revised) = revise(Caller::TeamA, &team_a_draft) else {
        panic!("team A could not revise its own draft")
    };
    assert_eq!(revised["draft"], "draft-1");
    assert!(matches!(
        revise(Caller::TeamB, &team_b_draft),
        Answer::Ok(_)
    ));
    assert_eq!(rig.connector.writes().len(), 4);

    let refused = Answer::Refused(DRAFT_REFUSAL.to_owned());
    for (caller, draft) in [
        // A draft a person opened.
        (Caller::TeamA, json!(FOREIGN_DRAFT)),
        // A draft not opened yet.
        (Caller::TeamA, json!("draft-3")),
        // Another team's draft, named with the caller's own document, which its limit allows.
        (Caller::TeamA, team_b_draft.clone()),
        (Caller::TeamB, team_a_draft.clone()),
        // Something that is not a draft's name.
        (Caller::TeamA, json!(1)),
        (Caller::TeamA, Value::Null),
    ] {
        assert_eq!(revise(caller, &draft), refused, "{caller:?} {draft}");
    }
    assert_eq!(
        rig.connector.writes().len(),
        4,
        "a refused call writes nothing"
    );
    assert_eq!(rig.connector.received().len(), 10, "and was received");
}

/// Runs the scoped tool for `caller` on a surface open to it, to its answer. The scoped tool
/// checks its own scope, so the decision allows any document and only the connector refuses.
fn scoped(rig: &Rig, caller: Caller, document: &str) -> Answer {
    let surface = if caller == Caller::UserInGroupG {
        SURFACE_READ
    } else {
        SURFACE_ALL
    };
    let arguments = documents(document);
    let call = CallContext {
        caller: rig.fixture.caller_context(caller, surface).unwrap(),
        tool: RequestedTool::new(SCOPED_READ_TOOL),
        resources: FixtureConnector::resources_of(SCOPED_READ_TOOL, &arguments),
    };
    let decision = decide(&rig.fixture.policy, &call);
    let Begun::Allowed(guard) = block_on(audit::begin(
        &rig.store,
        row_start(),
        decision,
        arguments,
        RequestMetadata::default(),
    ))
    .unwrap() else {
        panic!("the scoped tool was denied to {caller:?}")
    };
    let ran = block_on(audit::run(&rig.connector, guard));
    block_on(audit::finish(&rig.store, ran, 0)).answer().clone()
}

#[test]
fn the_scoped_tool_serves_each_caller_its_own_documents_and_refuses_the_rest() {
    let rig = rig();
    let refused = Answer::Refused(SCOPE_REFUSAL.to_owned());
    for (caller, own, others) in [
        (
            Caller::TeamA,
            TEAM_A_DOCUMENT,
            [TEAM_B_DOCUMENT, GROUP_G_DOCUMENT],
        ),
        (
            Caller::TeamB,
            TEAM_B_DOCUMENT,
            [TEAM_A_DOCUMENT, GROUP_G_DOCUMENT],
        ),
        (
            Caller::UserInGroupG,
            GROUP_G_DOCUMENT,
            [TEAM_A_DOCUMENT, TEAM_B_DOCUMENT],
        ),
    ] {
        assert!(
            matches!(scoped(&rig, caller, own), Answer::Ok(_)),
            "{caller:?} {own}"
        );
        for other in others.into_iter().chain([FORBIDDEN_DOCUMENT]) {
            assert_eq!(scoped(&rig, caller, other), refused, "{caller:?} {other}");
        }
    }
    // A call that names no document reaches nothing outside the caller's scope.
    assert!(matches!(
        rig.answer(Caller::TeamA, SCOPED_READ_TOOL, json!({})),
        Answer::Ok(_)
    ));
}

#[test]
fn the_scoped_tool_serves_a_granted_document_to_the_team_or_group_it_was_granted_to_only() {
    let rig = rig();
    let refused = Answer::Refused(SCOPE_REFUSAL.to_owned());
    assert_eq!(scoped(&rig, Caller::TeamA, "payroll"), refused);
    rig.connector.grant_to_team("team-a", "payroll");
    assert!(matches!(
        scoped(&rig, Caller::TeamA, "payroll"),
        Answer::Ok(_)
    ));
    assert_eq!(scoped(&rig, Caller::TeamB, "payroll"), refused);
    assert_eq!(scoped(&rig, Caller::UserInGroupG, "payroll"), refused);

    // A grant to a group the user is not in does not reach the user.
    rig.connector.grant_to_group("group-review", "review-notes");
    assert_eq!(scoped(&rig, Caller::UserInGroupG, "review-notes"), refused);
    rig.connector.grant_to_group("group-g", "review-notes");
    assert!(matches!(
        scoped(&rig, Caller::UserInGroupG, "review-notes"),
        Answer::Ok(_)
    ));
    assert_eq!(scoped(&rig, Caller::TeamA, "review-notes"), refused);
}

#[test]
fn a_resource_adapter_finds_the_document_a_call_names() {
    use gateway_testkit::document;
    assert_eq!(
        FixtureConnector::resources_of(READ_TOOL, &documents("x")),
        Resources::Named(vec![document("x")])
    );
    assert_eq!(
        FixtureConnector::resources_of(DRAFT_TOOL, &json!({"document": "x", "draft": "y"})),
        Resources::Named(vec![document("x")])
    );
    assert_eq!(
        FixtureConnector::resources_of(WRITE_TOOL, &json!({})),
        Resources::Named(vec![])
    );
    assert_eq!(
        FixtureConnector::resources_of(WRITE_TOOL, &json!({"document": 3})),
        Resources::Named(vec![])
    );
    assert_eq!(
        FixtureConnector::resources_of(SCOPED_READ_TOOL, &documents("x")),
        Resources::Unknown
    );
}

#[test]
fn the_connector_records_every_call_it_receives_in_order() {
    let rig = rig();
    rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes"));
    rig.answer(Caller::TeamB, READ_TOOL, documents("team-b-notes"));
    let received = rig.connector.received();
    assert_eq!(
        received
            .iter()
            .map(|call| (call.tool.as_str(), call.team.as_ref().map(|t| t.as_str())))
            .collect::<Vec<_>>(),
        [(READ_TOOL, Some("team-a")), (READ_TOOL, Some("team-b"))]
    );
    assert_eq!(received[1].arguments, documents("team-b-notes"));
}

#[test]
fn a_connector_told_to_fail_errors_without_doing_the_work_and_is_still_recorded() {
    let rig = rig();
    rig.connector.fail_next();
    let failed = rig.answer(Caller::TeamA, DRAFT_TOOL, documents("team-a-notes"));
    assert_eq!(
        failed,
        Answer::Error("the fixture connector was told to fail".into())
    );
    assert!(
        rig.connector.writes().is_empty(),
        "a failed write did not happen"
    );
    assert_eq!(rig.connector.received().len(), 1, "it was received");
    assert!(
        rig.source.requests().is_empty(),
        "and failed before asking for a credential"
    );
    // Only the next call failed.
    assert!(matches!(
        rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes")),
        Answer::Ok(_)
    ));

    rig.connector.fail_all();
    for _ in 0..2 {
        assert!(matches!(
            rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes")),
            Answer::Error(_)
        ));
    }
    rig.connector.stop_failing();
    assert!(matches!(
        rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes")),
        Answer::Ok(_)
    ));
    assert_eq!(rig.connector.received().len(), 5);
}

#[test]
fn a_connector_whose_credential_is_refused_errors_and_does_not_write() {
    let rig = rig();
    rig.source.refuse_next();
    let answer = rig.answer(Caller::TeamA, DRAFT_TOOL, documents("team-a-notes"));
    assert_eq!(
        answer,
        Answer::Error("the fixture connector could not get a credential".into())
    );
    assert!(rig.connector.writes().is_empty());
    assert_eq!(rig.source.requests().len(), 1);
}

#[test]
fn a_connector_told_to_hang_has_received_the_call_and_done_nothing_until_released() {
    let rig = rig();
    let gate = rig.connector.hang_next();
    let guard = rig.guard(Caller::TeamA, DRAFT_TOOL, documents("team-a-notes"));
    let mut run = pin!(audit::run(&rig.connector, guard));
    assert!(poll_once(run.as_mut()).is_pending());
    assert_eq!(rig.connector.received().len(), 1, "the call arrived");
    assert_eq!(gate.waiting(), 1);
    assert!(
        rig.connector.writes().is_empty(),
        "a held write has not happened"
    );
    assert!(rig.source.requests().is_empty());
    gate.open();
    let Poll::Ready(ran) = poll_once(run.as_mut()) else {
        panic!("still held after the gate opened")
    };
    assert!(matches!(
        block_on(audit::finish(&rig.store, ran, 0)).answer(),
        Answer::Ok(_)
    ));
    assert_eq!(rig.connector.writes().len(), 1);

    // Only the next call hangs: a second call starts and finishes while the first is held.
    let gate = rig.connector.hang_next();
    let held = rig.guard(Caller::TeamA, READ_TOOL, documents("team-a-notes"));
    let mut held = pin!(audit::run(&rig.connector, held));
    assert!(poll_once(held.as_mut()).is_pending());
    let next = rig.guard(Caller::TeamB, READ_TOOL, documents("team-b-notes"));
    let mut next = pin!(audit::run(&rig.connector, next));
    assert!(
        poll_once(next.as_mut()).is_ready(),
        "a call after the one told to hang was held too"
    );
    assert!(
        poll_once(held.as_mut()).is_pending(),
        "the held call is still held"
    );
    assert_eq!(gate.waiting(), 1);
    gate.open();
    assert!(poll_once(held.as_mut()).is_ready());

    // hang_all holds every call at one gate.
    let gate = rig.connector.hang_all();
    let first = rig.guard(Caller::TeamA, READ_TOOL, documents("team-a-notes"));
    let second = rig.guard(Caller::TeamB, READ_TOOL, documents("team-b-notes"));
    let (mut one, mut two) = (
        pin!(audit::run(&rig.connector, first)),
        pin!(audit::run(&rig.connector, second)),
    );
    assert!(poll_once(one.as_mut()).is_pending() && poll_once(two.as_mut()).is_pending());
    assert_eq!(gate.waiting(), 2);
    gate.open();
    assert!(poll_once(one.as_mut()).is_ready() && poll_once(two.as_mut()).is_ready());
}

#[test]
fn a_connector_can_move_the_clock_so_a_test_chooses_the_latency_it_measures() {
    let rig = rig();
    let clock = SteppableClock::at(FIXTURE_NOW);
    rig.connector
        .take_time(clock.clone(), Duration::from_millis(250));
    let before = clock.unix_millis();
    rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes"));
    assert_eq!(clock.unix_millis() - before, 250);
    // A failed call did no work and took no time.
    rig.connector.fail_next();
    rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes"));
    assert_eq!(clock.unix_millis() - before, 250);
}
