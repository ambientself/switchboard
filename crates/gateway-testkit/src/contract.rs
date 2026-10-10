//! The audit store contract suite (design.md section 18): test functions that every
//! [`AuditStore`] must pass, run unchanged against [`InMemoryAuditStore`] in the per-change loop
//! and against the Postgres store in the slow loop.
//!
//! A runner gives each function a [`ContractStore`]: the store, a way to read a row back as the
//! store holds it, and the store's budgets. The read-back belongs to the runner, not to the
//! store's interface, so it sees what that interface hides: the Postgres runner reads as a
//! superuser, and [`InMemoryAuditStore`]'s reads the store's own state. Each expectation is
//! written to what the Postgres store does, so a fake that does more than Postgres can fails
//! it rather than passing a test the real store would fail.
//!
//! It covers the suite's items 1 to 4, and of item 5 that a list row is stored complete with
//! no deadline. The open-row query and receipts are not here: the query is Postgres's alone
//! for now, and receipts are not built.
//!
//! The functions read no clock and spawn nothing, so they run on whatever executor the runner
//! has: [`block_on`](crate::block_on) for the in-memory store, a Tokio runtime for Postgres.
//! They are tests: a broken expectation panics, as an assertion does.

#![allow(
    clippy::expect_used,
    reason = "these are test functions, and a broken expectation fails the test"
)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use gateway_core::audit::{
    self, Answer, AuditFailure, AuditRowId, Begun, Completion, DecisionKind, ListRecord, Outcome,
    RequestMetadata, RowKind, RowStart,
};
use gateway_core::{
    AuditGuard, AuditRecord, AuditStore, CallContext, Claimed, Decision, RequestedTool, TeamId,
    ToolUseId, decide,
};
use serde_json::{Value, json};

use crate::audit::{InMemoryAuditStore, StoreBudgets, row_start};
use crate::connector::{
    DOCUMENT_ARGUMENT, FORBIDDEN_DOCUMENT, FixtureConnector, READ_TOOL, SCOPED_READ_TOOL,
    WRITE_TOOL,
};
use crate::credentials::FakeCredentialSource;
use crate::fixture::{
    Caller, Fixture, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
};

/// What a contract function needs of a store: the store, a read-back, and its budgets.
pub trait ContractStore {
    /// The store under test.
    fn store(&self) -> &dyn AuditStore;

    /// The row stored under `row`, read back as the store holds it, or `None` if it holds none.
    /// As strict as the store allows: the whole record, its completion and kind, and whether
    /// the store set a time at begin and a deadline. A store that holds two rows under one
    /// identifier, which Postgres's primary key forbids, makes this panic.
    fn stored(&self, row: &AuditRowId) -> impl Future<Output = Option<StoredRow>>;

    /// The begin budget and the finish deadline the store adds to each call row's deadline.
    fn budgets(&self) -> StoreBudgets;
}

/// The record a row holds.
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
    /// Whether the store set the row's time at begin.
    pub begun_at_set: bool,
    /// Whether the store set the row's deadline.
    pub deadline_set: bool,
    /// The deadline less the time at begin, where both are set.
    pub deadline_after_begin: Option<Duration>,
}

impl ContractStore for InMemoryAuditStore {
    fn store(&self) -> &dyn AuditStore {
        self
    }

    async fn stored(&self, row: &AuditRowId) -> Option<StoredRow> {
        let mut found = self.stored_under(row);
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
            begun_at_set: true,
            deadline_set: deadline.is_some(),
            deadline_after_begin: deadline.map(|deadline| {
                deadline
                    .duration_since(begun_at)
                    .expect("the row's deadline is before its time at begin")
            }),
        })
    }

    fn budgets(&self) -> StoreBudgets {
        self.store_budgets()
    }
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
    let arguments = arguments(call);
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &arguments),
        caller: fixture
            .caller_context(call.caller, call.surface)
            .expect("the fixture knows the caller"),
        tool: RequestedTool::new(call.tool),
    };
    decide(&fixture.policy, &context)
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

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
    [allowed, denied, bare, no_resources]
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
        assert!(stored.begun_at_set && stored.deadline_set, "{stored:?}");
    }
}

// --- Item 2: records the store cannot hold ------------------------------------------------------

/// A record the store cannot hold exactly is refused at begin, and leaves no row: U+0000 in a
/// text value, a record already complete, a count or an allowance past a Postgres `bigint`,
/// unknown resources with a count left out, a deadline past what Postgres can work out, and an
/// identifier that is not a lowercase hyphenated UUID. So is such a list record, and a
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
    let budgets_ms = millis(budgets.begin) + millis(budgets.finish_deadline);
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
            record.resources = gateway_core::audit::RecordedResources::Unknown;
            record.resources_omitted = 3;
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

    let uppercase = row_start().row.as_str().to_uppercase();
    for id in ["not-a-row", uppercase.as_str(), ""] {
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
/// and its deadline are as begin left them, for each outcome.
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
        let before = stored(contract, &start.row).await;
        if fails {
            connector.fail_next();
        }
        let ran = audit::run(&connector, guard).await;
        let finished = audit::finish(store, ran, latency_ms).await;
        assert!(finished.failure().is_none(), "{:?}", finished.failure());
        let outcome = match finished.answer() {
            Answer::Ok(_) => Outcome::Ok,
            Answer::Error(_) => Outcome::Error,
            Answer::Refused(sentence) => Outcome::Refused {
                sentence: sentence.clone(),
            },
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
        assert_eq!(stored(contract, &start.row).await, expected, "{call:?}");
    }
}

// --- Item 4: the deadline -----------------------------------------------------------------------

/// Each row of kind `call`, allowed or denied, has a time at begin and a deadline the store
/// sets: its time at begin plus the begin budget, the call deadline and the finish deadline,
/// each in whole milliseconds.
pub async fn the_deadline_is_the_begin_time_plus_begin_budget_call_deadline_and_finish_deadline(
    contract: &impl ContractStore,
) {
    let store = contract.store();
    let fixture = fixture();
    let budgets = contract.budgets();
    for (call, call_deadline_ms) in [
        (&ALLOWED, crate::FIXTURE_CALL_DEADLINE_MS),
        (&DENIED, crate::FIXTURE_CALL_DEADLINE_MS),
        (&ALLOWED, 0),
        (&ALLOWED, 1),
        (&DENIED, 7 * 86_400_000 + 3),
    ] {
        let start = RowStart {
            call_deadline_ms,
            ..row_start()
        };
        let _ = begin(store, &fixture, &start, call, RequestMetadata::default())
            .await
            .expect("begin");
        let stored = stored(contract, &start.row).await;
        assert!(stored.begun_at_set, "{stored:?}");
        assert!(stored.deadline_set, "{stored:?}");
        let allowance = millis(budgets.begin) + call_deadline_ms + millis(budgets.finish_deadline);
        assert_eq!(
            stored.deadline_after_begin,
            Some(Duration::from_millis(allowance)),
            "{call:?} with a call deadline of {call_deadline_ms} ms"
        );
    }
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
/// begin, no completion and no deadline. A second list under its identifier returns `Ok` and
/// changes nothing, whatever it records. A begin under a list row's identifier, and a list under
/// a call row's, are refused, and the stored row stands.
pub async fn a_list_row_is_stored_complete_with_no_deadline(contract: &impl ContractStore) {
    let store = contract.store();
    let fixture = fixture();
    let records = list_records();
    for (position, written) in records.iter().enumerate() {
        let row = row_start().row;
        store.list(&row, written).await.expect("list");
        let expected = StoredRow {
            record: StoredRecord::List(written.clone()),
            kind: RowKind::List,
            completion: None,
            begun_at_set: true,
            deadline_set: false,
            deadline_after_begin: None,
        };
        assert_eq!(stored(contract, &row).await, expected);

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
}
