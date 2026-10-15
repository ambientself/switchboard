//! Reconciliation of `unknown` receipts end to end (decision 0009, "Reconciliation"): a side
//! effect made through the gateway's HTTP endpoint whose answer was lost is left `unknown`, and
//! the instance's reconciler later settles it by asking the connector's lookup, or hands it to
//! a person. The fixture's draft tool runs on the fixture connector, which can lose a draft's
//! answer after opening it, and its lookup is the testkit's fake, which sends nothing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway::{
    Config, ReconcileSettings, Reconciler, TELEMETRY_QUEUE, Telemetry, Timeouts, Wiring, boot,
    serve_with_telemetry,
};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{LookupAnswer, Receipt, ReceiptState, VendorReference};
use gateway_mcp::TOOL_USE_ID_META;
use gateway_testkit::{
    CONNECTOR, Caller, DOCUMENT_ARGUMENT, DRAFT_TOOL, FakeCredentialSource, FakeLookup, Fixture,
    FixtureConnector, InMemoryAuditStore, SURFACE_ALL, TEAM_A_DOCUMENT, document, fresh_key,
    policy_data, policy_data_with_draft_lookup,
};
use serde_json::{Value, json};
use support::{FixtureResources, Server, legacy};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// The settings the tests reconcile with: a lease of a minute, and three attempts.
const SETTINGS: ReconcileSettings = ReconcileSettings {
    interval: Duration::from_secs(60),
    lease: Duration::from_secs(60),
    attempts: 3,
};

/// The fixture served over loopback with `policy`, its store on the fixture's clock, and the
/// fake lookup registered for the fixture connector, answering `answer`.
struct World {
    server: Server,
    reconciler: Reconciler,
    lookup: Arc<FakeLookup>,
}

async fn start(policy: Value, answer: LookupAnswer) -> World {
    let fixture = Fixture::new().unwrap();
    let credentials = Arc::new(FakeCredentialSource::new());
    let connector = Arc::new(FixtureConnector::new(credentials.clone()));
    let store = Arc::new(InMemoryAuditStore::new().with_clock(Arc::new(fixture.clock.clone())));
    let lookup = Arc::new(FakeLookup::answering(answer));
    let mut config = support::config(&fixture);
    config["policy"] = policy;
    let config: Config = serde_json::from_value(config).unwrap();
    let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
        .audit_store(store.clone())
        .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources))
        .lookup(CONNECTOR, lookup.clone());
    let gates = boot::check(config, wiring).unwrap();
    let reconciler = gates.reconciler(store.clone(), SETTINGS);
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
/// the receipt's marker in that document, finds the draft, and the receipt is `completed` by
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
