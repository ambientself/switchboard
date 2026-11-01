//! Reconciliation of `unknown` receipts end to end (decision 0009, "Reconciliation"): a side
//! effect made through the gateway's HTTP endpoint whose answer was lost is left `unknown`, and
//! the instance's reconciler later settles it by asking the connector's lookup, or hands it to
//! a person. The fixture's draft tool runs on the fixture connector, which can lose a draft's
//! answer after opening it, or hang past its deadline, and its lookup is the testkit's fake,
//! which sends nothing. A second instance's reconciler works the same store, as another replica
//! would.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use gateway::{
    Config, DEFAULT_IN_PROCESS_RESULT_BYTES, InProcessLimits, ReconcileSettings, Reconciler,
    TELEMETRY_QUEUE, Telemetry, Timeouts, Wiring, boot, serve_with_telemetry,
};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{LookupAnswer, Receipt, ReceiptState, VendorReference};
use gateway_identity::{Clock, SystemClock};
use gateway_mcp::TOOL_USE_ID_META;
use gateway_testkit::{
    CONNECTOR, Caller, DOCUMENT_ARGUMENT, DRAFT_TOOL, FakeCredentialSource, FakeLookup, Fixture,
    FixtureConnector, InMemoryAuditStore, SURFACE_ALL, TEAM_A, TEAM_A_DOCUMENT, document,
    fresh_key, policy_data, policy_data_with_draft_lookup,
};
use serde_json::{Value, json};
use support::{FixtureResources, Server, eventually, legacy};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// The settings the tests reconcile with: a lease of a minute, and three attempts.
const SETTINGS: ReconcileSettings = ReconcileSettings {
    interval: Duration::from_secs(60),
    lease: Duration::from_secs(60),
    attempts: 3,
};

/// The fixture served over loopback with `policy`, its store on the fixture's clock, and the
/// fake lookup registered for the fixture connector, answering `answer`; and another instance's
/// reconciler on the same store.
struct World {
    server: Server,
    reconciler: Reconciler,
    other: Reconciler,
    lookup: Arc<FakeLookup>,
}

/// How a world is set up beyond its policy and its lookup's answer.
struct Setup {
    settings: ReconcileSettings,
    /// The store reads the system's clock, not the fixture's, so a lease runs out in real time.
    real_time: bool,
    /// The fixture connector's deadline in the gateway's own process, if not the default.
    deadline: Option<Duration>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            settings: SETTINGS,
            real_time: false,
            deadline: None,
        }
    }
}

async fn start(policy: Value, answer: LookupAnswer) -> World {
    start_with(policy, answer, Setup::default()).await
}

async fn start_with(policy: Value, answer: LookupAnswer, setup: Setup) -> World {
    let fixture = Fixture::new().unwrap();
    let credentials = Arc::new(FakeCredentialSource::new());
    let connector = Arc::new(FixtureConnector::new(credentials.clone()));
    let clock: Arc<dyn Clock> = if setup.real_time {
        Arc::new(SystemClock)
    } else {
        Arc::new(fixture.clock.clone())
    };
    let store = Arc::new(InMemoryAuditStore::new().with_clock(clock));
    let lookup = Arc::new(FakeLookup::answering(answer));
    let mut config = support::config(&fixture);
    config["policy"] = policy;
    let wiring = || {
        let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
            .audit_store(store.clone())
            .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources))
            .lookup(CONNECTOR, lookup.clone());
        match setup.deadline {
            Some(deadline) => wiring.in_process_limits(
                CONNECTOR,
                InProcessLimits {
                    deadline,
                    max_result_bytes: DEFAULT_IN_PROCESS_RESULT_BYTES,
                },
            ),
            None => wiring,
        }
    };
    let gates = boot::check(serde_json::from_value(config.clone()).unwrap(), wiring()).unwrap();
    let reconciler = gates.reconciler(store.clone(), setup.settings);
    let others: Config = serde_json::from_value(config).unwrap();
    let other = boot::check(others, wiring())
        .unwrap()
        .reconciler(store.clone(), setup.settings);
    let grant_signals = gates.grant_signals();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let serving = tokio::spawn(serve_with_telemetry(
        listener,
        gates,
        telemetry.clone(),
        drain,
        async {
            let _ = stopped.await;
        },
        Timeouts::default(),
        gateway::DEFAULT_MAX_IN_FLIGHT,
    ));
    World {
        server: Server {
            fixture,
            store,
            credentials,
            connector,
            address,
            telemetry,
            grant_signals,
            stop: Some(stop),
            serving,
        },
        reconciler,
        other,
        lookup,
    }
}

impl World {
    /// Team A proposes on its own document, under `key`, and the connector loses the answer
    /// after opening the draft. Returns the receipt, which is `unknown`.
    async fn lost_proposal(&self, key: &str) -> Receipt {
        self.server.connector.lose_next_answer();
        let answer = self.propose(key).await;
        assert_eq!(answer.status, 200, "{answer:?}");
        assert_eq!(answer.result()["isError"], json!(true), "{answer:?}");
        let receipts = self.server.store.receipts();
        let receipt = receipts.last().expect("a receipt was reserved").clone();
        assert_eq!(receipt.state, ReceiptState::Unknown);
        assert_eq!(
            self.server.connector.writes().len(),
            1,
            "the draft was opened"
        );
        receipt
    }

    /// Team A's proposal on its own document, under `key`.
    async fn propose(&self, key: &str) -> support::Answer {
        let params = json!({
            "name": DRAFT_TOOL,
            "arguments": {DOCUMENT_ARGUMENT: TEAM_A_DOCUMENT, "text": "A proposal."},
            "_meta": {TOOL_USE_ID_META: key},
        });
        self.server
            .post(SURFACE_ALL, &legacy("tools/call", params))
            .bearer(&self.server.token(Caller::TeamA))
            .send(&self.server)
            .await
    }

    fn receipt(&self, of: &Receipt) -> Receipt {
        self.server
            .store
            .receipt(&of.row)
            .expect("the receipt is kept")
    }
}

/// A side effect whose answer was lost is left `unknown`, with the vendor target the draft
/// tool's settlement takes from the call, and a later pass settles it: the lookup is asked for
/// the receipt's marker in that document, with the team the receipt recorded and the revision
/// in force, finds the draft, and the receipt is `completed` by
/// reconciliation with the draft as its reference. The same call under the same key is then a
/// `duplicate`, answered as a success with that reference, and nothing is sent again.
#[tokio::test]
async fn a_side_effect_left_unknown_is_settled_by_the_queue() {
    let world = start(
        policy_data_with_draft_lookup(),
        LookupAnswer::Found {
            reference: VendorReference::new("draft-1"),
        },
    )
    .await;
    let key = fresh_key();
    let receipt = world.lost_proposal(key.as_str()).await;
    assert_eq!(receipt.target, Some(document(TEAM_A_DOCUMENT)));
    assert!(world.lookup.looked_up().is_empty(), "nothing looked yet");

    let report = world.reconciler.pass().await;
    assert_eq!(
        (report.claimed, report.looked_up, report.settled),
        (1, 1, 1),
        "{report:?}"
    );
    let looked_up = world.lookup.looked_up();
    assert_eq!(looked_up.len(), 1);
    assert_eq!(
        looked_up[0].marker, receipt.row,
        "the marker is the receipt"
    );
    assert_eq!(looked_up[0].target, document(TEAM_A_DOCUMENT));
    assert_eq!(looked_up[0].tool.as_str(), DRAFT_TOOL);
    assert_eq!(receipt.team, Some(TEAM_A.into()));
    assert_eq!(looked_up[0].team, receipt.team);
    let row = world.server.store.rows().pop().expect("the call's row");
    assert_eq!(looked_up[0].revision, row.policy_revision);
    let settled = world.receipt(&receipt);
    assert_eq!(
        (
            settled.state,
            &settled.established_by,
            settled.reference.as_ref().map(VendorReference::as_str)
        ),
        (
            ReceiptState::Completed,
            &EstablishedBy::Reconciliation,
            Some("draft-1")
        )
    );
    assert_eq!(settled.lookups.len(), 1);
    assert_eq!(settled.handed_to_person, None);
    let counts = world.reconciler.signals().counts();
    assert_eq!((counts.found, counts.handed_to_person), (1, 0));

    // Settled, it is no longer due.
    assert_eq!(world.reconciler.pass().await.due, 0);
    assert_eq!(world.lookup.looked_up().len(), 1);

    // The same call again is answered from the receipt, and does not run.
    let again = world.propose(key.as_str()).await;
    let result = again.result();
    assert_ne!(result["isError"], json!(true), "{again:?}");
    let duplicate: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().expect("a text block")).unwrap();
    assert_eq!(duplicate["receipt"], json!(receipt.row.as_str()));
    assert_eq!(duplicate["reference"], json!("draft-1"));
    assert_eq!(
        world.server.connector.writes().len(),
        1,
        "nothing ran again"
    );
}

/// A tool settled by a person has its `unknown` receipt handed to a person at once: its receipt
/// recorded no target, and the connector's lookup is never asked, though one is registered. The
/// receipt stays `unknown`, and later passes leave it alone.
#[tokio::test]
async fn a_tool_settled_by_a_person_is_handed_off_at_once() {
    let world = start(
        policy_data(),
        LookupAnswer::Found {
            reference: VendorReference::new("draft-1"),
        },
    )
    .await;
    let receipt = world.lost_proposal(fresh_key().as_str()).await;
    assert_eq!(
        receipt.target, None,
        "a person settles it, so nothing is looked in"
    );

    let report = world.reconciler.pass().await;
    assert_eq!(
        (report.claimed, report.looked_up, report.handed_to_person),
        (1, 0, 1),
        "{report:?}"
    );
    assert!(
        world.lookup.looked_up().is_empty(),
        "a receipt a person settles was sent to the lookup"
    );
    let handed = world.receipt(&receipt);
    assert_eq!(
        (handed.state, &handed.established_by, handed.lookups.len()),
        (ReceiptState::Unknown, &EstablishedBy::Call, 0)
    );
    assert!(handed.handed_to_person.is_some());
    assert_eq!(world.reconciler.signals().counts().handed_to_person, 1);

    world.server.fixture.clock.advance(SETTINGS.lease);
    assert_eq!(world.reconciler.pass().await.due, 0);
    assert_eq!(world.reconciler.signals().counts().handed_to_person, 1);
}

/// Each receipt is looked up a bounded number of times: a search that proves nothing leaves it
/// `unknown`, the lease spaces one attempt from the next, and the last attempt hands it to a
/// person. After that it is looked up no more.
#[tokio::test]
async fn a_receipt_is_looked_up_a_bounded_number_of_times_then_handed_off() {
    let world = start(
        policy_data_with_draft_lookup(),
        LookupAnswer::NotFound {
            authoritative: false,
        },
    )
    .await;
    let receipt = world.lost_proposal(fresh_key().as_str()).await;

    for attempt in 1..=SETTINGS.attempts {
        let report = world.reconciler.pass().await;
        assert_eq!(report.looked_up, 1, "attempt {attempt}: {report:?}");
        let receipt = world.receipt(&receipt);
        assert_eq!(
            receipt.state,
            ReceiptState::Unknown,
            "an empty search settled it"
        );
        assert_eq!(receipt.lookups.len(), usize::try_from(attempt).unwrap());
        // Within the lease, no other pass looks it up.
        assert_eq!(world.reconciler.pass().await.looked_up, 0);
        world.server.fixture.clock.advance(SETTINGS.lease);
    }
    let handed = world.receipt(&receipt);
    assert!(handed.handed_to_person.is_some(), "{handed:?}");
    assert_eq!(handed.state, ReceiptState::Unknown);
    let report = world.reconciler.pass().await;
    assert_eq!((report.due, report.looked_up), (0, 0));
    assert_eq!(world.lookup.looked_up().len(), 3);
    let counts = world.reconciler.signals().counts();
    assert_eq!((counts.not_found, counts.handed_to_person), (3, 1));
}

/// No lookup is made until the claim is committed: while the store holds the claim, the lookup
/// is not asked, and a claim the store refuses means no lookup at all.
#[tokio::test]
async fn nothing_is_looked_up_before_the_claim_is_committed() {
    let world = start(
        policy_data_with_draft_lookup(),
        LookupAnswer::Found {
            reference: VendorReference::new("draft-1"),
        },
    )
    .await;
    let receipt = world.lost_proposal(fresh_key().as_str()).await;

    world.server.store.fail_next_claim();
    let report = world.reconciler.pass().await;
    assert_eq!((report.claimed, report.looked_up), (0, 0), "{report:?}");
    assert!(world.lookup.looked_up().is_empty());
    assert_eq!(world.reconciler.signals().counts().store_failures, 1);

    let held = world.server.store.hold_claims();
    let reconciler = Arc::new(world.reconciler);
    let passing = tokio::spawn({
        let reconciler = reconciler.clone();
        async move { reconciler.pass().await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        world.lookup.looked_up().is_empty(),
        "a lookup was made before the claim was committed"
    );
    assert_eq!(world.server.store.lease_holder(&receipt.row), None);
    held.open();
    let report = passing.await.unwrap();
    assert_eq!((report.claimed, report.looked_up), (1, 1), "{report:?}");
    assert_eq!(world.lookup.looked_up().len(), 1);
}

/// A side effect answered `unknown` at its deadline runs on in a task of its own, and while it
/// runs no instance looks its receipt up, however long that is (#217): the task holds the
/// receipt's lease, from before the call is answered, renewing it, so neither this instance's
/// reconciler nor another's claims it, though a lookup would find nothing and settle it
/// `not_performed` while the draft is still on its way. When the side effect ends the task
/// holds the receipt once more, for a full lease, and only after that is it looked up.
#[tokio::test]
async fn no_instance_looks_up_a_receipt_while_its_late_side_effect_runs() {
    let lease = Duration::from_millis(1600);
    let world = start_with(
        policy_data_with_draft_lookup(),
        LookupAnswer::NotFound {
            authoritative: true,
        },
        Setup {
            settings: ReconcileSettings {
                interval: Duration::from_secs(60),
                lease,
                attempts: 3,
            },
            real_time: true,
            deadline: Some(Duration::from_millis(200)),
        },
    )
    .await;
    let store = &world.server.store;
    let draft = world.server.connector.hang_next();
    let answer = world.propose(fresh_key().as_str()).await;
    assert_eq!(answer.result()["isError"], json!(true), "{answer:?}");
    let receipt = store
        .receipts()
        .last()
        .expect("a receipt was reserved")
        .clone();
    assert_eq!(receipt.state, ReceiptState::Unknown);
    assert!(
        world.server.connector.writes().is_empty(),
        "the draft is still on its way"
    );
    let holder = store
        .lease_holder(&receipt.row)
        .expect("the receipt was answered unheld");
    assert!(holder.as_str().ends_with("late-call"), "{holder}");

    // For two leases, with the draft on its way, neither instance claims it.
    let until = Instant::now() + lease * 2;
    while Instant::now() < until {
        for reconciler in [&world.reconciler, &world.other] {
            let report = reconciler.pass().await;
            assert_eq!((report.claimed, report.looked_up), (0, 0), "{report:?}");
        }
        tokio::time::sleep(lease / 8).await;
    }
    assert!(
        world.lookup.looked_up().is_empty(),
        "looked up while it ran"
    );
    assert_eq!(world.receipt(&receipt).state, ReceiptState::Unknown);

    // It ends: the draft is opened, and the receipt is held a full lease from then.
    let opened = SystemTime::now();
    draft.open();
    eventually("the late side effect ran to its end", || {
        world.server.connector.writes().len() == 1
    })
    .await;
    eventually(
        "the receipt was held once more as the side effect ended",
        || {
            store
                .lease_until(&receipt.row)
                .is_some_and(|until| until >= opened + lease)
        },
    )
    .await;
    for reconciler in [&world.reconciler, &world.other] {
        assert_eq!(reconciler.pass().await.claimed, 0);
    }

    // A lease later, it is looked up as any unknown receipt, and the draft is found.
    world.lookup.answer(LookupAnswer::Found {
        reference: VendorReference::new("draft-1"),
    });
    tokio::time::sleep(lease + Duration::from_millis(200)).await;
    let report = world.reconciler.pass().await;
    assert_eq!(
        (report.claimed, report.looked_up, report.settled),
        (1, 1, 1),
        "{report:?}"
    );
    let settled = world.receipt(&receipt);
    assert_eq!(
        (settled.state, &settled.established_by),
        (ReceiptState::Completed, &EstablishedBy::Reconciliation)
    );
}

/// A lookup whose record fails to save still uses up its attempt (#206): an attempt is counted
/// when its claim is made, so a store that cannot save lookups lets a receipt be looked up
/// `attempts` times, and the next claim hands it to a person with no lookup.
#[tokio::test]
async fn a_lookup_whose_record_fails_to_save_still_uses_up_an_attempt() {
    let world = start(
        policy_data_with_draft_lookup(),
        LookupAnswer::NotFound {
            authoritative: false,
        },
    )
    .await;
    let receipt = world.lost_proposal(fresh_key().as_str()).await;
    world.server.store.fail_all_lookup_records();

    for attempt in 1..=SETTINGS.attempts {
        let report = world.reconciler.pass().await;
        assert_eq!(
            (report.claimed, report.looked_up),
            (1, 1),
            "attempt {attempt}: {report:?}"
        );
        world.server.fixture.clock.advance(SETTINGS.lease);
    }
    let report = world.reconciler.pass().await;
    assert_eq!(
        (report.claimed, report.looked_up, report.handed_to_person),
        (1, 0, 1),
        "{report:?}"
    );
    assert_eq!(
        world.lookup.looked_up().len(),
        usize::try_from(SETTINGS.attempts).unwrap()
    );
    let handed = world.receipt(&receipt);
    assert_eq!(
        (handed.state, handed.lookups.len(), handed.claims),
        (ReceiptState::Unknown, 0, SETTINGS.attempts + 1)
    );
    assert!(handed.handed_to_person.is_some());
    world.server.fixture.clock.advance(SETTINGS.lease);
    assert_eq!(world.reconciler.pass().await.due, 0);
    assert_eq!(
        world.reconciler.signals().counts().store_failures,
        u64::from(SETTINGS.attempts)
    );
}

/// A lookup has half the lease to answer, so it ends while the lease is held: one that never
/// answers is given up at half the lease and recorded as failed, leaving the receipt `unknown`.
#[tokio::test]
async fn a_lookup_has_half_the_lease_to_answer() {
    let lease = Duration::from_millis(1200);
    let world = start_with(
        policy_data_with_draft_lookup(),
        LookupAnswer::Found {
            reference: VendorReference::new("draft-1"),
        },
        Setup {
            settings: ReconcileSettings { lease, ..SETTINGS },
            ..Setup::default()
        },
    )
    .await;
    let receipt = world.lost_proposal(fresh_key().as_str()).await;
    let _never = world.lookup.hold();

    let started = Instant::now();
    let report = world.reconciler.pass().await;
    let took = started.elapsed();
    assert_eq!((report.claimed, report.looked_up), (1, 1), "{report:?}");
    assert!(
        took >= lease / 2 && took < lease * 3 / 4,
        "the lookup was given up after {took:?}"
    );
    let left = world.receipt(&receipt);
    assert_eq!(left.state, ReceiptState::Unknown);
    assert_eq!(left.lookups.len(), 1);
    assert_eq!(left.lookups[0].answer, LookupAnswer::Failed);
    assert_eq!(world.reconciler.signals().counts().failed, 1);
}
