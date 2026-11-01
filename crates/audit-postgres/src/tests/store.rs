//! The store, driven through the core's audited path and directly.

use std::time::Duration;

use gateway_core::audit::{
    self, AuditRowId, Begun, Completion, ErrorKind, Outcome, RequestMetadata,
};
use gateway_core::audit::{
    ListRecord, MAX_RECORDED_RESOURCES, MAX_RECORDED_TOOLS, RecordedResources, RowStart,
};
use gateway_core::{
    AuditRecord, AuditStore, CallContext, Claimed, RequestedTool, Resources, TeamId, ToolUseId,
    decide, list_tools,
};
use gateway_testkit::{
    Caller, FORBIDDEN_DOCUMENT, FakeCredentialSource, Fixture, FixtureConnector,
    InMemoryAuditStore, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT,
    TEAM_B_DOCUMENT, WRITE_TOOL, document, row_start,
};
use serde_json::{Value, json};
use tokio_postgres::{Client, NoTls};

use super::{DELEGATION_COLUMNS, DelegationRead, EXCEPTION_COLUMN, GATEWAY_ROLE, TestDatabase};
use crate::columns::{BeginRow, FinishRow, ListRow, allowance_ms};
use crate::{
    Budgets, FinishCounts, MAX_BEGUN_ROW_BYTES, MAX_OUTCOME_SENTENCE_BYTES, MAX_REACHED_BYTES,
    MAX_ROW_BYTES, PgAuditError, PgAuditStore, PoolSizes,
};

/// One call, as a test describes it.
pub(super) struct Call {
    pub(super) caller: Caller,
    pub(super) surface: &'static str,
    pub(super) tool: &'static str,
    pub(super) arguments: Value,
    /// The resources the call names, when not the ones its arguments name.
    pub(super) resources: Option<Resources>,
    pub(super) metadata: RequestMetadata,
    pub(super) connector_fails: bool,
    pub(super) latency_ms: u64,
}

impl Call {
    pub(super) fn new(
        caller: Caller,
        surface: &'static str,
        tool: &'static str,
        document: &str,
    ) -> Self {
        Self {
            caller,
            surface,
            tool,
            arguments: json!({"document": document}),
            resources: None,
            metadata: RequestMetadata::default(),
            connector_fails: false,
            latency_ms: 17,
        }
    }
}

/// Runs `call` through the core's begin, run and finish on `store`, and returns its row.
pub(super) async fn through_core(
    store: &dyn AuditStore,
    fixture: &Fixture,
    call: &Call,
) -> AuditRowId {
    let connector = FixtureConnector::new(std::sync::Arc::new(FakeCredentialSource::new()));
    if call.connector_fails {
        connector.fail_next();
    }
    let context = CallContext {
        resources: call
            .resources
            .clone()
            .unwrap_or_else(|| FixtureConnector::resources_of(call.tool, &call.arguments)),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    let decision = decide(&fixture.policy, &context);
    let begun = audit::begin(
        store,
        row_start(),
        decision,
        call.arguments.clone(),
        call.metadata.clone(),
    )
    .await
    .unwrap();
    match begun {
        Begun::Denied(refusal) => refusal.row().clone(),
        Begun::Reused(reused) => panic!("the Postgres store reserves no receipts: {reused:?}"),
        Begun::Allowed(guard) => {
            let row = guard.row().clone();
            let ran = audit::run(&connector, guard).await;
            let finished = audit::finish(store, ran, call.latency_ms).await;
            assert!(finished.failure().is_none(), "{:?}", finished.failure());
            row
        }
    }
}

/// Reads a row back as the core's record, through a superuser session: the gateway's role
/// cannot read who called. The row must have been begun by a store with the default
/// [`Budgets`]: the call deadline is its allowance less them. Checks on the way that the
/// row's deadline is its time at begin plus its allowance.
pub(super) async fn read_back(admin: &Client, row: &AuditRowId) -> AuditRecord {
    let row = admin
        .query_one(
            &format!(
                "SELECT tool_use_id, deployment, surface, profile, tool, connector, classification,
                    decision, reason, sentence, policy_revision,
                    proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
                    proved_delegation_team, claimed_acting_person, claimed_team,
                    outcome, outcome_sentence, error_kind, latency_ms, resources,
                    resources_omitted, instance, kind, allowance_ms,
                    deadline = begun_at + allowance_ms * interval '1 millisecond' AS on_time,
                    {DELEGATION_COLUMNS}, {EXCEPTION_COLUMN}
             FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid"
            ),
            &[&row.as_str()],
        )
        .await
        .unwrap();
    let text = |column: &str| row.get::<_, Option<String>>(column);
    let read = DelegationRead::of(&row);
    let mut principal = json!({
        "id": {"issuer": text("proved_issuer"), "subject": text("proved_subject")},
        "kind": text("proved_kind"),
    });
    match text("proved_kind").as_deref() {
        Some("workload") => principal["team"] = json!(text("proved_team")),
        _ => principal["groups"] = json!(row.get::<_, Option<Vec<String>>>("proved_groups")),
    }
    if let Some(pod) = &read.pod {
        principal["pod"] = json!(pod);
    }
    let completion = text("outcome").map(|outcome| {
        let mut completion = json!({
            "outcome": outcome,
            "latency_ms": row.get::<_, Option<i64>>("latency_ms"),
        });
        if let Some(sentence) = text("outcome_sentence") {
            completion["sentence"] = json!(sentence);
        }
        if let Some(error_kind) = text("error_kind") {
            completion["error_kind"] = json!(error_kind);
        }
        completion
    });
    let resources = match row.get::<_, Value>("resources") {
        Value::String(unknown) => json!(unknown),
        named => json!({ "named": named }),
    };
    assert_eq!(row.get::<_, Option<bool>>("on_time"), Some(true));
    let allowance = u64::try_from(row.get::<_, i64>("allowance_ms")).unwrap();
    let budgets = allowance_ms(&Budgets::default(), 0);
    serde_json::from_value(json!({
        "kind": text("kind"),
        "instance": text("instance"),
        "call_deadline_ms": allowance.checked_sub(budgets).unwrap(),
        "tool_use_id": text("tool_use_id"),
        "deployment": text("deployment"),
        "surface": text("surface"),
        "profile": text("profile"),
        "tool": text("tool"),
        "connector": text("connector"),
        "classification": text("classification"),
        "resources": resources,
        "resources_omitted": row.get::<_, i64>("resources_omitted"),
        "decision": text("decision"),
        "reason": text("reason"),
        "sentence": text("sentence"),
        "policy_revision": text("policy_revision"),
        "proved_principal": principal,
        "proved_delegation_team": text("proved_delegation_team"),
        "claimed_acting_person": text("claimed_acting_person"),
        "claimed_team": text("claimed_team"),
        "delegation": read.delegation,
        "delegation_failure": read.failure,
        "currency": read.currency,
        "allowed_by_exception": text(EXCEPTION_COLUMN),
        "completion": completion,
    }))
    .unwrap()
}

#[tokio::test]
async fn rows_read_back_exactly_as_the_core_wrote_them() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    let mut stated = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    stated.metadata = RequestMetadata {
        tool_use_id: Some(ToolUseId::new("toolu_01")),
        claimed_team: Some(Claimed::new(TeamId::new("team-claimed"))),
    };
    let mut failing = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    failing.connector_fails = true;
    failing.latency_ms = 0;
    let calls = [
        // Allowed and ok, with a tool-use identifier and a claimed team.
        stated,
        // Allowed, and the tool failed.
        failing,
        // Allowed, and the connector refused, with its sentence.
        Call::new(
            Caller::TeamA,
            SURFACE_READ,
            SCOPED_READ_TOOL,
            FORBIDDEN_DOCUMENT,
        ),
        // Denied: outside the limit, for a user with groups.
        Call::new(
            Caller::UserInGroupG,
            SURFACE_READ,
            READ_TOOL,
            TEAM_B_DOCUMENT,
        ),
        // Denied: the profile does not permit the classification.
        Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT),
        // Denied: a tool name that is not one, made safe by the core.
        Call::new(Caller::TeamB, SURFACE_ALL, "no such\ntool", TEAM_B_DOCUMENT),
    ];

    let memory = InMemoryAuditStore::new();
    for (position, call) in calls.iter().enumerate() {
        through_core(&memory, &fixture, call).await;
        let row = through_core(&store, &fixture, call).await;
        let expected = memory.row(position).unwrap();
        assert_eq!(read_back(&admin, &row).await, expected, "call {position}");
    }
    // Every outcome and both decisions were seen.
    let outcomes: Vec<Option<Outcome>> = memory
        .rows()
        .into_iter()
        .map(|row| row.completion.map(|c| c.outcome))
        .collect();
    assert!(outcomes.contains(&Some(Outcome::Ok)));
    assert!(outcomes.contains(&Some(Outcome::Error {
        error_kind: ErrorKind::Other
    })));
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Some(Outcome::Refused { .. })))
    );
    assert_eq!(outcomes.iter().filter(|o| o.is_none()).count(), 3);
}

/// The testkit's callers carry no delegation, so the calls above leave the delegation and
/// acting-person columns empty. A record with every optional value set, each to a value no
/// other column holds, reads back exactly, so a value written to another column's place is
/// caught, proved and claimed ones included.
#[tokio::test]
async fn a_record_with_every_value_set_reads_back_exactly() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let record = |value: Value| -> AuditRecord { serde_json::from_value(value).unwrap() };
    let common = |decision: &str| {
        json!({
            "kind": "call",
            "instance": format!("instance-{decision}"),
            "call_deadline_ms": decision.len() * 1_000,
            "tool_use_id": format!("toolu-{decision}"),
            "deployment": format!("deployment-{decision}"),
            "surface": format!("surface-{decision}"),
            "profile": format!("profile-{decision}"),
            "tool": format!("tool-{decision}"),
            "connector": format!("connector-{decision}"),
            "classification": "write",
            "resources": {"named": [
                {"system": "system-1", "kind": "kind-1", "identifier": "identifier-1"},
                {"system": "system-2", "kind": "kind-2", "identifier": "identifier-2"}
            ]},
            "resources_omitted": 3,
            "policy_revision": format!("revision-{decision}"),
            "proved_delegation_team": format!("delegation-team-{decision}"),
            "claimed_acting_person": format!("acting-person-{decision}"),
            "claimed_team": format!("claimed-team-{decision}"),
            "completion": null
        })
    };
    // An allowed call by a workload, which has a team.
    let mut allowed = common("allow");
    allowed["decision"] = json!("allow");
    allowed["reason"] = json!(null);
    allowed["sentence"] = json!(null);
    allowed["proved_principal"] = json!({
        "id": {"issuer": "issuer-allow", "subject": "subject-allow"},
        "kind": "workload",
        "team": "proved-team-allow"
    });
    // A denied call by a user, who has groups.
    let mut denied = common("deny");
    denied["decision"] = json!("deny");
    denied["reason"] = json!("classification_not_permitted");
    denied["sentence"] = json!("sentence-deny");
    denied["proved_principal"] = json!({
        "id": {"issuer": "issuer-deny", "subject": "subject-deny"},
        "kind": "user",
        "groups": ["group-1", "group-2"]
    });

    for written in [record(allowed), record(denied)] {
        let row = row_start().row;
        store.begin(&row, &written).await.unwrap();
        assert_eq!(read_back(&admin, &row).await, written);
    }
}

#[tokio::test]
async fn a_call_naming_more_resources_than_a_row_holds_records_how_many_were_left_out() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    // The team's own document twice, then more than a row holds, one of them a value the core
    // escapes.
    let mut named = vec![document(TEAM_A_DOCUMENT), document(TEAM_A_DOCUMENT)];
    named.push(document("line\nbreak, a \\ and a \"quote\""));
    named.extend((0..MAX_RECORDED_RESOURCES + 5).map(|n| document(&format!("other-{n}"))));
    let mut call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    call.resources = Some(Resources::Named(named));

    let memory = InMemoryAuditStore::new();
    through_core(&memory, &fixture, &call).await;
    let expected = memory.row(0).unwrap();
    let RecordedResources::Named(recorded) = &expected.resources else {
        panic!("{:?}", expected.resources);
    };
    assert_eq!(recorded.len(), MAX_RECORDED_RESOURCES);
    assert_eq!(expected.resources_omitted, 7);

    let row = through_core(&store, &fixture, &call).await;
    assert_eq!(read_back(&admin, &row).await, expected);
}

/// Postgres text cannot hold U+0000, and a caller chooses its tool-use identifier and the team
/// it states. A record carrying one is refused, so the call is refused and no row is written,
/// rather than a row that is not the record. The same holds for a refusal's sentence at finish,
/// which gives up and is reported.
#[tokio::test]
async fn a_nul_in_a_value_refuses_the_record_and_writes_no_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let given_up = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = std::sync::Arc::clone(&given_up);
    let store = db
        .store(PoolSizes::default())
        .on_given_up(move |report| kept.lock().unwrap().push(report.error.to_string()));
    let admin = db.admin().await;

    for metadata in [
        RequestMetadata {
            tool_use_id: Some(ToolUseId::new("toolu_\u{0}x")),
            claimed_team: None,
        },
        RequestMetadata {
            tool_use_id: None,
            claimed_team: Some(Claimed::new(TeamId::new("team\u{0}x"))),
        },
    ] {
        // A denial, whose row would otherwise be written at begin.
        let call = Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT);
        let context = CallContext {
            resources: FixtureConnector::resources_of(call.tool, &call.arguments),
            caller: fixture.caller_context(call.caller, call.surface).unwrap(),
            tool: RequestedTool::new(call.tool),
            key: gateway_core::CallKey::Absent,
            currency: gateway_core::Currency::NotAsked,
        };
        let decision = decide(&fixture.policy, &context);
        let failure = audit::begin(&store, row_start(), decision, call.arguments, metadata)
            .await
            .unwrap_err();
        let cause = std::error::Error::source(&failure)
            .and_then(|source| source.downcast_ref::<PgAuditError>())
            .unwrap();
        assert!(matches!(cause, PgAuditError::Nul { .. }), "{cause}");
    }
    let rows: i64 = admin
        .query_one("SELECT count(*) FROM switchboard_audit.call_rows", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0);

    let row = begun_row(&store, &fixture).await;
    let refused = completion(
        Outcome::Refused {
            sentence: "Not that one.\u{0}".into(),
        },
        3,
    );
    let error = store
        .finish_within_budget(&row, &refused)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PgAuditError::Nul {
                column: "outcome_sentence"
            }
        ),
        "{error}"
    );
    assert_eq!(read_back(&admin, &row).await.completion, None);
    assert_eq!(store.finishes().given_up, 1);
    assert_eq!(store.finishes().in_flight, 0);
    assert_eq!(given_up.lock().unwrap().clone(), vec![error.to_string()]);
}

/// A refusal's sentence of 2,048 bytes is written whole at finish. One of 2,049 is refused the
/// way a sentence holding U+0000 is, rather than cut: finish fails at once, naming the column
/// and the cap, gives up, and is counted under `other` and reported, and the row keeps no
/// completion, so it stays open. Nothing else is written to it.
#[tokio::test]
async fn an_over_long_sentence_is_refused_at_finish_as_a_nul_is() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let given_up = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = std::sync::Arc::clone(&given_up);
    let store = db
        .store(PoolSizes::default())
        .on_given_up(move |report| kept.lock().unwrap().push(report.error.to_string()));
    let admin = db.admin().await;

    let whole = "w".repeat(MAX_OUTCOME_SENTENCE_BYTES);
    let row = begun_row(&store, &fixture).await;
    let refused = completion(
        Outcome::Refused {
            sentence: whole.clone(),
        },
        3,
    );
    store.finish_within_budget(&row, &refused).await.unwrap();
    assert_eq!(read_back(&admin, &row).await.completion, Some(refused));

    let mut errors = Vec::new();
    for sentence in [format!("{whole}o"), "No.\u{0}".to_owned()] {
        let row = begun_row(&store, &fixture).await;
        let before = written_bytes(&admin, &row).await;
        let error = store
            .finish_within_budget(&row, &completion(Outcome::Refused { sentence }, 3))
            .await
            .unwrap_err();
        assert_eq!(read_back(&admin, &row).await.completion, None);
        assert_eq!(finished_at(&admin, &row).await, None);
        assert_eq!(written_bytes(&admin, &row).await, before);
        errors.push(error);
    }
    assert!(
        matches!(
            errors[0],
            PgAuditError::TooLong {
                column: "outcome_sentence",
                bytes: 2_049,
                cap: MAX_OUTCOME_SENTENCE_BYTES,
            }
        ),
        "{}",
        errors[0]
    );
    assert!(
        matches!(
            errors[1],
            PgAuditError::Nul {
                column: "outcome_sentence"
            }
        ),
        "{}",
        errors[1]
    );
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 2,
            never_written: 0,
        }
    );
    assert_eq!(store.stats().finishes_given_up.other, 2);
    assert_eq!(
        given_up.lock().unwrap().clone(),
        errors.iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

/// Decision 0014, section 7: the largest row a call can begin, at begin's bound, is written and
/// reads back exactly; a byte more is refused, naming its largest column, and no row is
/// written.
#[tokio::test]
async fn the_largest_row_is_written_and_a_row_over_the_bound_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    let largest = crate::columns::largest_record(MAX_BEGUN_ROW_BYTES);
    let row = row_start().row;
    store.begin(&row, &largest).await.unwrap();
    // read_back leaves the credential out; it is read here.
    let read = read_back(&admin, &row).await;
    assert!(
        read == AuditRecord {
            credential: None,
            ..largest.clone()
        }
    );
    // The row as written holds what begin counted, every column included.
    assert_eq!(written_bytes(&admin, &row).await, MAX_BEGUN_ROW_BYTES);
    let credential = admin
        .query_one(
            "SELECT credential_mode, credential_principal FROM switchboard_audit.call_rows
              WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            credential.get::<_, String>(0),
            credential.get::<_, String>(1)
        ),
        ("team_service_identity".to_owned(), "largest".to_owned())
    );

    let mut over = largest.clone();
    over.policy_revision = format!("{}r", over.policy_revision).as_str().into();
    let error = store.begin(&row_start().row, &over).await.unwrap_err();
    let error = error.downcast_ref::<PgAuditError>().unwrap();
    assert!(
        matches!(
            error,
            PgAuditError::RowTooLarge {
                column: "resources",
                bytes,
                bound: MAX_BEGUN_ROW_BYTES,
            } if *bytes == MAX_BEGUN_ROW_BYTES + 1
        ),
        "{error}"
    );
    assert_eq!(row_count(&admin).await, 1);
    assert_eq!(store.stats().begin_failures.value_refused, 1);
}

/// Decision 0014, section 7 bounds the whole row: the largest row an allowed call can begin,
/// finished with the longest completion finish writes, a refusal whose sentence is at the cap,
/// is written and reads back whole, and the row as the table holds it is at most 512 KiB.
#[tokio::test]
async fn the_largest_row_finished_with_the_longest_completion_is_within_the_bound() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    let largest = crate::columns::largest_allowed_record(MAX_BEGUN_ROW_BYTES);
    let row = row_start().row;
    store.begin(&row, &largest).await.unwrap();
    let refused = completion(
        Outcome::Refused {
            sentence: "s".repeat(MAX_OUTCOME_SENTENCE_BYTES),
        },
        u64::from(u32::MAX),
    );
    store.finish_within_budget(&row, &refused).await.unwrap();

    let read = read_back(&admin, &row).await;
    assert!(
        read == AuditRecord {
            credential: None,
            completion: Some(refused.clone()),
            ..largest.clone()
        }
    );
    let begun: usize = BeginRow::from_record(&row, &largest, &Budgets::default())
        .unwrap()
        .sizes()
        .iter()
        .map(|(_, bytes)| bytes)
        .sum();
    let finished: usize = FinishRow::from_completion(read.completion.as_ref().unwrap())
        .unwrap()
        .sizes()
        .iter()
        .map(|(_, bytes)| bytes)
        .sum();
    assert_eq!(begun, MAX_BEGUN_ROW_BYTES);
    assert_eq!(finished, "refused".len() + MAX_OUTCOME_SENTENCE_BYTES + 8);
    assert!(begun + finished <= MAX_ROW_BYTES, "{}", begun + finished);
    // The database holds the sentence at the cap, as the store counted it.
    let stored: i32 = admin
        .query_one(
            "SELECT octet_length(outcome_sentence) FROM switchboard_audit.call_rows
              WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(usize::try_from(stored).unwrap(), MAX_OUTCOME_SENTENCE_BYTES);
    // The row as written, every column the table holds, is what the store counted.
    let written = written_bytes(&admin, &row).await;
    assert_eq!(written, begun + finished);
    assert!(written <= MAX_ROW_BYTES, "{written}");
}

/// Decision 0011 and decision 0014, section 7: the largest row a tool that checks its own scope
/// can begin, its `unknown` resources counted as the longest reach, finished with the longest
/// reach and the longest completion finish writes, is written and reads back whole, and the
/// row as the table holds it is at most 512 KiB.
#[tokio::test]
async fn the_largest_self_scoped_row_finished_with_the_longest_reach_is_within_the_bound() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    let largest = crate::columns::largest_self_scoped_record(MAX_BEGUN_ROW_BYTES);
    let row = row_start().row;
    store.begin(&row, &largest).await.unwrap();
    let unknown = "\"unknown\"".len();
    assert_eq!(
        written_bytes(&admin, &row).await,
        MAX_BEGUN_ROW_BYTES - MAX_REACHED_BYTES + unknown
    );

    let refused = completion(
        Outcome::Refused {
            sentence: "s".repeat(MAX_OUTCOME_SENTENCE_BYTES),
        },
        u64::from(u32::MAX),
    );
    let reach = crate::columns::largest_reach();
    store
        .finish_with_reference(&row, &refused, None, Some(&reach))
        .await
        .unwrap();
    let read = read_back(&admin, &row).await;
    assert!(
        read == AuditRecord {
            credential: None,
            resources: RecordedResources::Named(reach.resources.clone()),
            resources_omitted: reach.omitted,
            completion: Some(refused.clone()),
            ..largest.clone()
        }
    );
    // The row as written, every column the table holds, is begin's bound, the reach now in the
    // room it counted, and the completion.
    let finished = "refused".len() + MAX_OUTCOME_SENTENCE_BYTES + 8;
    let written = written_bytes(&admin, &row).await;
    assert_eq!(written, MAX_BEGUN_ROW_BYTES + finished);
    assert!(written <= MAX_ROW_BYTES, "{written}");
}

/// A list row at its bound, [`MAX_ROW_BYTES`] as the store counts it, holds exactly that many
/// bytes as the table holds it, the kind its statement writes itself included.
#[tokio::test]
async fn a_list_row_at_the_bound_holds_what_the_store_counted() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;

    let mut list: ListRecord = serde_json::from_value(json!({
        "instance": "gateway-7f9c",
        "deployment": "",
        "surface": "fixture-read",
        "profile": "user-ro",
        "policy_revision": "fixture-1",
        "proved_principal": {
            "id": {"issuer": "https://user-issuer.fixture.test", "subject": "user-1"},
            "kind": "user",
            "groups": ["group-g"]
        },
        "proved_delegation_team": "team-d",
        "claimed_acting_person": "person@fixture.test",
        "claimed_team": "team-c",
        "tools": ["fixture__read", "back\\slash"],
        "tools_omitted": 2
    }))
    .unwrap();
    let row = row_start().row;
    let counted = |list: &ListRecord| -> usize {
        ListRow::from_record(&row, list)
            .unwrap()
            .sizes()
            .iter()
            .map(|(_, bytes)| bytes)
            .sum()
    };
    list.deployment = "d".repeat(MAX_ROW_BYTES - counted(&list)).as_str().into();
    assert_eq!(counted(&list), MAX_ROW_BYTES);
    store.list(&row, &list).await.unwrap();
    assert_eq!(read_back_list(&admin, &row).await, list);
    assert_eq!(written_bytes(&admin, &row).await, MAX_ROW_BYTES);
}

/// The columns the database sets itself, which the store never sends: when a row was begun and
/// finished, and its deadline, worked out from its allowance.
const SET_BY_THE_DATABASE: [&str; 3] = ["begun_at", "finished_at", "deadline"];

/// The bytes of the row `row` as the table holds it, counted from the table, not from the
/// store's own count, as decision 0014, section 7 counts them: each text value as its UTF-8, a
/// text array as its elements', a JSON value as its JSON text, an integer as 8 bytes, and the
/// identifier as the text the store sends. Every column the table has is counted, but for
/// [`SET_BY_THE_DATABASE`]; a column of any other type fails the test until it is counted here.
async fn written_bytes(admin: &Client, row: &AuditRowId) -> usize {
    let columns = admin
        .query(
            "SELECT column_name::text, data_type::text FROM information_schema.columns
              WHERE table_schema = 'switchboard_audit' AND table_name = 'call_rows'",
            &[],
        )
        .await
        .unwrap();
    let written: Value = admin
        .query_one(
            "SELECT to_jsonb(written) FROM switchboard_audit.call_rows AS written
              WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    let mut bytes = 0;
    for column in columns {
        let (name, data_type): (String, String) = (column.get(0), column.get(1));
        let value = &written[name.as_str()];
        if SET_BY_THE_DATABASE.contains(&name.as_str()) {
            assert_eq!(data_type, "timestamp with time zone", "{name}");
            continue;
        }
        bytes += match (data_type.as_str(), value) {
            (_, Value::Null) => 0,
            ("text" | "uuid", Value::String(text)) => text.len(),
            ("ARRAY", Value::Array(texts)) => texts
                .iter()
                .map(|text| text.as_str().expect("a text array").len())
                .sum(),
            ("jsonb", json) => json.to_string().len(),
            ("bigint" | "integer", Value::Number(_)) => 8,
            (other, value) => panic!("column {name}, of type {other}, holds {value}"),
        };
    }
    bytes
}

/// The decided call `call` in the fixture's policy.
fn decided(fixture: &Fixture, call: &Call) -> gateway_core::Decision {
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    decide(&fixture.policy, &context)
}

/// How many rows the table holds, read as a superuser.
async fn row_count(admin: &Client) -> i64 {
    admin
        .query_one("SELECT count(*) FROM switchboard_audit.call_rows", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn begin_stores_the_identifier_it_is_given() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let call = Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT);
    let (first, second) = (row_start(), row_start());
    for start in [&first, &second] {
        let begun = audit::begin(
            &store,
            start.clone(),
            decided(&fixture, &call),
            call.arguments.clone(),
            RequestMetadata::default(),
        )
        .await
        .unwrap();
        let Begun::Denied(refusal) = begun else {
            panic!("{begun:?}");
        };
        assert_eq!(refusal.row(), &start.row);
    }
    let stored: Vec<String> = admin
        .query(
            "SELECT id::text FROM switchboard_audit.call_rows ORDER BY begun_at",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        stored,
        vec![first.row.as_str(), second.row.as_str()],
        "each row is stored under the identifier the gateway gave it"
    );

    // An identifier that is not a UUID is refused before anything is sent.
    let error = store
        .begin(
            &AuditRowId::new("not-a-row"),
            &read_back(&admin, &first.row).await,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<PgAuditError>(),
            Some(PgAuditError::Column("id"))
        ),
        "{error}"
    );
    assert_eq!(row_count(&admin).await, 2);
}

#[tokio::test]
async fn a_second_begin_with_one_identifier_writes_one_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let start = row_start();
    for call in [
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
        // The same decision for another call: only the decision is compared, because the
        // gateway's role cannot read who called what.
        Call::new(Caller::TeamA, SURFACE_READ, READ_TOOL, TEAM_A_DOCUMENT),
    ] {
        let begun = audit::begin(
            &store,
            start.clone(),
            decided(&fixture, &call),
            call.arguments.clone(),
            RequestMetadata::default(),
        )
        .await;
        assert!(
            matches!(&begun, Ok(Begun::Allowed(guard)) if guard.row() == &start.row),
            "{begun:?}"
        );
    }
    assert_eq!(
        row_count(&admin).await,
        1,
        "a retried begin wrote a second row"
    );
    assert_eq!(
        read_back(&admin, &start.row).await.surface.as_str(),
        SURFACE_ALL,
        "the first row stands"
    );

    // Another decision under the same identifier is refused, and the first row stands.
    let denied = Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT);
    let failure = audit::begin(
        &store,
        start.clone(),
        decided(&fixture, &denied),
        denied.arguments.clone(),
        RequestMetadata::default(),
    )
    .await
    .unwrap_err();
    let cause = std::error::Error::source(&failure)
        .and_then(|source| source.downcast_ref::<PgAuditError>())
        .unwrap();
    assert!(
        matches!(cause, PgAuditError::BegunDifferently { row } if row == start.row.as_str()),
        "{cause}"
    );
    assert_eq!(row_count(&admin).await, 1);
    let stored = read_back(&admin, &start.row).await;
    assert_eq!(stored.decision, gateway_core::audit::DecisionKind::Allow);
}

/// An allowed call's row, begun through the core and not yet finished.
pub(super) async fn begun_row(store: &PgAuditStore, fixture: &Fixture) -> AuditRowId {
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    let decision = decide(&fixture.policy, &context);
    match audit::begin(store, row_start(), decision, call.arguments, call.metadata)
        .await
        .unwrap()
    {
        Begun::Allowed(guard) => guard.row().clone(),
        Begun::Denied(refusal) => panic!("denied: {}", refusal.sentence()),
        Begun::Reused(reused) => panic!("the Postgres store reserves no receipts: {reused:?}"),
    }
}

pub(super) fn completion(outcome: Outcome, latency_ms: u64) -> Completion {
    Completion {
        outcome,
        latency_ms,
    }
}

async fn finished_at(admin: &Client, row: &AuditRowId) -> Option<String> {
    admin
        .query_one(
            "SELECT finished_at::text FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn the_same_completion_written_again_is_accepted_and_changes_nothing() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let row = begun_row(&store, &fixture).await;
    let refused = completion(
        Outcome::Refused {
            sentence: "Not that one.".into(),
        },
        9,
    );
    store.complete(&row, &refused).await.unwrap();
    let first = finished_at(&admin, &row).await;
    assert!(first.is_some());
    store.complete(&row, &refused).await.unwrap();
    assert_eq!(finished_at(&admin, &row).await, first);
}

#[tokio::test]
async fn a_different_second_completion_is_refused_and_the_first_stands() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let row = begun_row(&store, &fixture).await;
    store
        .complete(&row, &completion(Outcome::Ok, 5))
        .await
        .unwrap();
    for different in [
        completion(
            Outcome::Error {
                error_kind: ErrorKind::Other,
            },
            5,
        ),
        completion(Outcome::Ok, 6),
        completion(
            Outcome::Refused {
                sentence: "No.".into(),
            },
            5,
        ),
    ] {
        assert!(matches!(
            store.complete(&row, &different).await,
            Err(PgAuditError::CompletedDifferently { .. })
        ));
    }
    let record = read_back(&admin, &row).await;
    assert_eq!(record.completion, Some(completion(Outcome::Ok, 5)));
}

/// An error is stored with its kind. The same error again is accepted; an error of another
/// kind, or none, is refused, and the first stands.
#[tokio::test]
async fn an_error_is_stored_with_its_kind_and_a_repeat_must_have_the_same_kind() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let error = |error_kind| completion(Outcome::Error { error_kind }, 5);
    let row = begun_row(&store, &fixture).await;
    let refusal = error(ErrorKind::VendorRefusal);
    store.complete(&row, &refusal).await.unwrap();
    assert_eq!(
        read_back(&admin, &row).await.completion,
        Some(refusal.clone())
    );
    store.complete(&row, &refusal).await.unwrap();
    for different in [
        error(ErrorKind::Other),
        error(ErrorKind::InvalidArguments),
        error(ErrorKind::OversizedOrLateRead),
        error(ErrorKind::CustodianRefusal),
        completion(Outcome::Ok, 5),
    ] {
        assert!(
            matches!(
                store.complete(&row, &different).await,
                Err(PgAuditError::CompletedDifferently { .. })
            ),
            "{different:?}"
        );
    }
    assert_eq!(read_back(&admin, &row).await.completion, Some(refusal));
}

#[tokio::test]
async fn completing_a_row_that_is_not_there_or_is_a_denial_fails() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let ok = completion(Outcome::Ok, 1);
    let missing = AuditRowId::new("00000000-0000-4000-8000-000000000000");
    assert!(matches!(
        store.complete(&missing, &ok).await,
        Err(PgAuditError::NoSuchRow { .. })
    ));
    let malformed = AuditRowId::new("not-a-row");
    assert!(matches!(
        store.complete(&malformed, &ok).await,
        Err(PgAuditError::Database(_))
    ));
    let denied = through_core(
        &store,
        &fixture,
        &Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT),
    )
    .await;
    let error = store.complete(&denied, &ok).await.unwrap_err();
    assert!(error.to_string().contains("records a denial"), "{error}");
}

#[tokio::test]
async fn every_session_commits_synchronously_whatever_the_role_default() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.cluster_wide(&format!(
        "ALTER ROLE {GATEWAY_ROLE} IN DATABASE {} SET synchronous_commit = off",
        db.name()
    ))
    .await;
    async fn show(client: &Client) -> String {
        client
            .query_one("SHOW synchronous_commit", &[])
            .await
            .unwrap()
            .get(0)
    }
    // The role's default reaches a plain session, so the store's setting is what differs.
    assert_eq!(show(&db.connect_as(GATEWAY_ROLE).await).await, "off");
    let store = db.store(PoolSizes::default());
    assert_eq!(show(&store.begin.get().await.unwrap()).await, "on");
    assert_eq!(show(&store.finish.get().await.unwrap()).await, "on");
    assert_eq!(show(&store.open_rows_pool.get().await.unwrap()).await, "on");

    // Options the caller set are kept beside the store's, and come before them, so where both
    // set one setting the store's value is the one that holds: the last wins.
    let mut config = db.config_as(GATEWAY_ROLE);
    config.options(
        "-c statement_timeout=4321 -c synchronous_commit=off -c search_path=public,pg_catalog",
    );
    let store = PgAuditStore::connect(config, NoTls, PoolSizes::default()).unwrap();
    // Each of the three pools, the open-row query's too, as the gateway's role.
    for (pool, client) in [
        ("begin", store.begin.get().await.unwrap()),
        ("finish", store.finish.get().await.unwrap()),
        ("open_rows", store.open_rows_pool.get().await.unwrap()),
    ] {
        assert_eq!(show(&client).await, "on", "{pool}");
        for (setting, expected) in [
            ("statement_timeout", "4321ms"),
            ("search_path", "pg_catalog,pg_temp"),
        ] {
            let found: String = client
                .query_one(&format!("SHOW {setting}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(found, expected, "{pool}: {setting}");
        }
        let role: String = client
            .query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(role, GATEWAY_ROLE, "{pool}");
    }
    store.check_at_boot().await.unwrap();
}

#[tokio::test]
async fn finish_has_a_pool_of_its_own() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes {
        begin: 1,
        finish: 1,
    });
    let row = begun_row(&store, &fixture).await;
    // Every begin connection is in use, as in a surge of begins.
    let _held = store.begin.get().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        store.finish_within_budget(&row, &completion(Outcome::Ok, 1)),
    )
    .await
    .expect("finish waited for a begin connection")
    .unwrap();
}

#[tokio::test]
async fn a_store_that_cannot_reach_its_database_refuses_the_call() {
    // Needs no server: nothing listens on port 1.
    let fixture = Fixture::new().unwrap();
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(1)
        .user(GATEWAY_ROLE)
        .dbname("switchboard");
    let store = PgAuditStore::connect(config, NoTls, PoolSizes::default()).unwrap();
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    let decision = decide(&fixture.policy, &context);
    let failure = audit::begin(&store, row_start(), decision, call.arguments, call.metadata)
        .await
        .unwrap_err();
    assert_eq!(
        failure.sentence(),
        "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later."
    );
}

/// Reads a list row back as the core's list record, through a superuser session. Checks on the
/// way that it is a list row, with no deadline, allowance or completion, begun just now.
async fn read_back_list(admin: &Client, row: &AuditRowId) -> ListRecord {
    let row = admin
        .query_one(
            &format!(
                "SELECT instance, deployment, surface, profile, policy_revision,
                    proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
                    proved_delegation_team, claimed_acting_person, claimed_team,
                    listed_tools, listed_omitted, kind,
                    begun_at > now() - interval '1 minute' AS begun_now,
                    deadline IS NULL AND allowance_ms IS NULL AND outcome IS NULL
                        AND finished_at IS NULL AS never_open,
                    {DELEGATION_COLUMNS}
             FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid"
            ),
            &[&row.as_str()],
        )
        .await
        .unwrap();
    let text = |column: &str| row.get::<_, Option<String>>(column);
    let read = DelegationRead::of(&row);
    assert_eq!(read.failure, Value::Null, "a list row records a failure");
    assert_eq!(
        read.currency,
        Value::Null,
        "a list row records a currency answer"
    );
    assert_eq!(text("kind").as_deref(), Some("list"));
    assert!(row.get::<_, bool>("begun_now"));
    assert!(row.get::<_, bool>("never_open"));
    let mut principal = json!({
        "id": {"issuer": text("proved_issuer"), "subject": text("proved_subject")},
        "kind": text("proved_kind"),
    });
    match text("proved_kind").as_deref() {
        Some("workload") => principal["team"] = json!(text("proved_team")),
        _ => principal["groups"] = json!(row.get::<_, Option<Vec<String>>>("proved_groups")),
    }
    if let Some(pod) = &read.pod {
        principal["pod"] = json!(pod);
    }
    serde_json::from_value(json!({
        "instance": text("instance"),
        "deployment": text("deployment"),
        "surface": text("surface"),
        "profile": text("profile"),
        "policy_revision": text("policy_revision"),
        "proved_principal": principal,
        "proved_delegation_team": text("proved_delegation_team"),
        "claimed_acting_person": text("claimed_acting_person"),
        "claimed_team": text("claimed_team"),
        "delegation": read.delegation,
        "tools": row.get::<_, Value>("listed_tools"),
        "tools_omitted": row.get::<_, i64>("listed_omitted"),
    }))
    .unwrap()
}

/// A list row written through the core reads back as the record the core made, which the
/// testkit's store keeps for the same list. So does one with every value set, and one naming
/// more tools than a row holds.
#[tokio::test]
async fn a_list_row_reads_back_exactly() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let memory = InMemoryAuditStore::new();
    let caller = fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap();
    let start = row_start();
    for written in [&store as &dyn AuditStore, &memory] {
        let listed = audit::listed(
            written,
            start.clone(),
            &caller,
            fixture.policy.revision().clone(),
            list_tools(&fixture.policy, &caller),
            Some(Claimed::new(TeamId::new("team-claimed"))),
        )
        .await
        .unwrap();
        assert_eq!(listed.row(), &start.row);
    }
    let (_, expected) = memory.list_rows().pop().unwrap();
    assert!(!expected.tools.is_empty());
    assert_eq!(read_back_list(&admin, &start.row).await, expected);

    let mut every: ListRecord = serde_json::from_value(json!({
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
        "tools": ["fixture__read", "back\\slash\\n"],
        "tools_omitted": 7
    }))
    .unwrap();
    let row = row_start().row;
    store.list(&row, &every).await.unwrap();
    assert_eq!(read_back_list(&admin, &row).await, every);
    every.tools = (0..MAX_RECORDED_TOOLS)
        .map(|n| format!("fixture__t{n}"))
        .collect();
    every.tools_omitted = 136;
    let row = row_start().row;
    store.list(&row, &every).await.unwrap();
    assert_eq!(read_back_list(&admin, &row).await, every);
}

/// A list is retried by identifier as begin is: a second list with a list row's identifier
/// writes nothing and succeeds. A list or a begin with the identifier of a row of the other
/// kind fails, and the stored row stands.
#[tokio::test]
async fn a_second_list_with_one_identifier_writes_one_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let caller = fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap();
    let list = |start| {
        audit::listed(
            &store,
            start,
            &caller,
            fixture.policy.revision().clone(),
            list_tools(&fixture.policy, &caller),
            None,
        )
    };
    let start = row_start();
    let _ = list(start.clone()).await.unwrap();
    let _ = list(start.clone()).await.unwrap();
    assert_eq!(
        row_count(&admin).await,
        1,
        "a retried list wrote a second row"
    );

    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let begun = audit::begin(
        &store,
        start.clone(),
        decided(&fixture, &call),
        call.arguments.clone(),
        RequestMetadata::default(),
    )
    .await;
    let error = begun.expect_err("a call was begun under a list row's identifier");
    assert!(
        matches!(
            std::error::Error::source(&error).and_then(|e| e.downcast_ref::<PgAuditError>()),
            Some(PgAuditError::OtherKind { .. })
        ),
        "{error:?}"
    );
    // The database answered that begin, so nothing sets out to complete the list row.
    assert_eq!(store.finishes(), FinishCounts::default());
    let call_row = begun_row(&store, &fixture).await;
    let listed = list(RowStart {
        row: call_row,
        ..row_start()
    })
    .await;
    let error = listed.expect_err("a list was written under a call row's identifier");
    assert!(
        matches!(
            std::error::Error::source(&error).and_then(|e| e.downcast_ref::<PgAuditError>()),
            Some(PgAuditError::OtherKind { .. })
        ),
        "{error:?}"
    );
    assert_eq!(row_count(&admin).await, 2);
    assert_eq!(read_back_list(&admin, &start.row).await.tools.len(), {
        list_tools(&fixture.policy, &caller).len()
    });
}
