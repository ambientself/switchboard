//! Each fake does what it says, and each way a fake can be told to fail has a test that shows
//! the failure happening and, as important, not happening when it has not been asked for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

use gateway_core::audit::{self, Answer, Begun, Completion, Outcome, RequestMetadata};
use gateway_core::{
    AuditGuard, CallContext, ConnectorName, CredentialError, CredentialSource, Principal,
    RequestedTool, Resources, decide,
};
use gateway_identity::Clock;
use gateway_testkit::{
    Caller, FIXTURE_NOW, FakeCredentialSource, FixedClock, Fixture, FixtureConnector, Gate,
    InMemoryAuditStore, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SteppableClock, WRITE_TOOL,
    block_on, poll_once,
};
use serde_json::{Value, json};

fn fixture() -> Fixture {
    Fixture::new().unwrap()
}

/// An allowed call's guard, from the real decision and the real begin step, written to `store`.
fn guard_for(
    fixture: &Fixture,
    store: &InMemoryAuditStore,
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

fn principal(fixture: &Fixture, caller: Caller) -> gateway_core::Proved<Principal> {
    fixture.principal(caller).unwrap()
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

    // Finishing the second first completes the second row, and only that one.
    let ran = block_on(audit::run(&connector, second));
    block_on(audit::finish(&store, ran, 5));
    let rows = store.rows();
    assert_eq!(rows[0].completion, None);
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
        decide(&fixture.policy, &call),
        json!({}),
        RequestMetadata::default()
    ));
    assert!(poll_once(begin.as_mut()).is_pending());
    gate.open();
    assert!(matches!(poll_once(begin.as_mut()), Poll::Ready(Err(_))));
    assert!(store.rows().is_empty());
}

// --- The credential source ------------------------------------------------------------------

#[test]
fn credentials_are_labelled_by_connector_team_and_count_and_every_request_is_recorded() {
    let (fixture, source) = (fixture(), FakeCredentialSource::new());
    let connector = ConnectorName::from("fixture");
    let team_a = principal(&fixture, Caller::TeamA);
    let team_b = principal(&fixture, Caller::TeamB);
    let user = principal(&fixture, Caller::UserInGroupG);

    let label = |caller| {
        block_on(source.credential_for(&connector, caller))
            .unwrap()
            .label()
            .to_owned()
    };
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
    let connector = ConnectorName::from("fixture");
    let caller = principal(&fixture, Caller::TeamA);
    let ask = || block_on(source.credential_for(&connector, &caller));

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
fn the_write_tool_records_that_a_write_happened_under_the_callers_team_credential() {
    let rig = rig();
    assert!(rig.connector.writes().is_empty());
    let answer = rig.answer(
        Caller::TeamA,
        WRITE_TOOL,
        json!({"document": "team-a-notes", "text": "hi"}),
    );
    assert!(matches!(answer, Answer::Ok(_)));
    let writes = rig.connector.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].arguments,
        json!({"document": "team-a-notes", "text": "hi"})
    );
    assert_eq!(writes[0].credential, "fake-credential-for-fixture-team-a-1");
    assert_eq!(
        writes[0].principal,
        rig.fixture.principal(Caller::TeamA).unwrap().get().id
    );
}

#[test]
fn the_scoped_tool_refuses_a_forbidden_document_and_serves_any_other() {
    let rig = rig();
    let refused = rig.answer(
        Caller::TeamA,
        SCOPED_READ_TOOL,
        documents("restricted-notes"),
    );
    let Answer::Refused(sentence) = refused else {
        panic!("{refused:?}")
    };
    assert_eq!(
        sentence,
        "The fixture connector refused this call: the document `restricted-notes` is outside the scope of the caller's team."
    );
    assert!(matches!(
        rig.answer(Caller::TeamA, SCOPED_READ_TOOL, documents("team-a-notes")),
        Answer::Ok(_)
    ));
    // Other forbidden documents can be added, and are then refused.
    assert!(matches!(
        rig.answer(Caller::TeamA, SCOPED_READ_TOOL, documents("payroll")),
        Answer::Ok(_)
    ));
    rig.connector.forbid("payroll");
    assert!(matches!(
        rig.answer(Caller::TeamA, SCOPED_READ_TOOL, documents("payroll")),
        Answer::Refused(_)
    ));
    // A call that names no document is not a forbidden one.
    assert!(matches!(
        rig.answer(Caller::TeamA, SCOPED_READ_TOOL, json!({})),
        Answer::Ok(_)
    ));
}

#[test]
fn a_resource_adapter_finds_the_document_a_call_names() {
    use gateway_testkit::document;
    assert_eq!(
        FixtureConnector::resources_of(READ_TOOL, &documents("x")),
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
    let failed = rig.answer(Caller::TeamA, WRITE_TOOL, documents("team-a-notes"));
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
    let answer = rig.answer(Caller::TeamA, WRITE_TOOL, documents("team-a-notes"));
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
    let guard = rig.guard(Caller::TeamA, WRITE_TOOL, documents("team-a-notes"));
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

    // Only the next call hung; hang_all holds every call at one gate.
    assert!(matches!(
        rig.answer(Caller::TeamA, READ_TOOL, documents("team-a-notes")),
        Answer::Ok(_)
    ));
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
