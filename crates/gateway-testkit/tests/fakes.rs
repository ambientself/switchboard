//! Each fake does what it says, and each way a fake can be told to fail has a test that shows
//! the failure happening and, as important, not happening when it has not been asked for.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

use gateway_core::audit::{
    self, Answer, AuditRowId, Begun, Completion, Outcome, RecordedResource, RecordedResources,
    RequestMetadata, RowCompletion, StoreError,
};
use gateway_core::{
    AuditGuard, AuditRecord, AuditStore, BoxFuture, CallContext, ConnectorName, CredentialError,
    CredentialHandle, CredentialSource, Principal, Proved, RequestedTool, Resource, Resources,
    decide,
};
use gateway_identity::Clock;
use gateway_testkit::{
    Caller, DRAFT_REFUSAL, DRAFT_TOOL, FIXTURE_NOW, FORBIDDEN_DOCUMENT, FOREIGN_DRAFT,
    FakeCredentialSource, FixedClock, Fixture, FixtureConnector, GROUP_G_DOCUMENT, Gate,
    InMemoryAuditStore, PROFILE_TEAM_B, READ_TOOL, RESOURCE_KIND, RESOURCE_SYSTEM, SCOPE_REFUSAL,
    SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, SteppableClock, TEAM_A, TEAM_A_DOCUMENT,
    TEAM_B_DOCUMENT, WRITE_TOOL, WriteRecord, block_on, document, policy_data, poll_once,
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

/// A store in front of the in-memory one that names every row it begins `"0"`. Finishing the
/// second call therefore hands the in-memory store a completion for a row that is already
/// finished, which the core's own path never does.
struct EveryRowIsRowZero<'a>(&'a InMemoryAuditStore);

impl AuditStore for EveryRowIsRowZero<'_> {
    fn begin<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        Box::pin(async move {
            self.0.begin(record).await?;
            Ok(AuditRowId::new("0"))
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.0.finish(completion)
    }
}

#[test]
fn a_row_that_is_already_finished_cannot_be_finished_again() {
    let (fixture, store) = (fixture(), InMemoryAuditStore::new());
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let forwarding = EveryRowIsRowZero(&store);
    let guard = |n: u32| {
        let arguments = json!({"document": "team-a-notes", "n": n});
        let call = CallContext {
            caller: fixture.team_a_workload(SURFACE_ALL).unwrap(),
            tool: RequestedTool::new(READ_TOOL),
            resources: FixtureConnector::resources_of(READ_TOOL, &arguments),
        };
        let decision = decide(&fixture.policy, &call);
        match block_on(audit::begin(
            &forwarding,
            decision,
            arguments,
            RequestMetadata::default(),
        ))
        .unwrap()
        {
            Begun::Allowed(guard) => guard,
            Begun::Denied(refusal) => panic!("{refusal:?}"),
        }
    };
    let (first, second) = (guard(1), guard(2));
    assert_eq!(store.rows().len(), 2);

    let finished = block_on(audit::finish(
        &forwarding,
        block_on(audit::run(&connector, first)),
        5,
    ));
    assert!(finished.failure().is_none());
    // The second call's completion is for row 0 too, with another latency.
    let finished = block_on(audit::finish(
        &forwarding,
        block_on(audit::run(&connector, second)),
        9,
    ));
    assert!(
        finished.failure().is_some(),
        "a second completion for one row was accepted"
    );
    assert_eq!(
        store.rows()[0].completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 5
        }),
        "the row kept its first completion"
    );
    assert_eq!(store.rows()[1].completion, None);
    assert_eq!(store.finish_attempts(), 2);
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
