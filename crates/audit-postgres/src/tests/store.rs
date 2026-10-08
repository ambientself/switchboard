//! The store, driven through the core's audited path and directly.

use std::time::Duration;

use gateway_core::audit::{self, AuditRowId, Begun, Completion, Outcome, RequestMetadata};
use gateway_core::audit::{MAX_RECORDED_RESOURCES, RecordedResources};
use gateway_core::{
    AuditRecord, AuditStore, CallContext, Claimed, RequestedTool, Resources, TeamId, ToolUseId,
    decide,
};
use gateway_testkit::{
    Caller, FORBIDDEN_DOCUMENT, FakeCredentialSource, Fixture, FixtureConnector,
    InMemoryAuditStore, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT,
    TEAM_B_DOCUMENT, WRITE_TOOL, document,
};
use serde_json::{Value, json};
use tokio_postgres::{Client, NoTls};

use super::{GATEWAY_ROLE, TestDatabase};
use crate::{PgAuditError, PgAuditStore, PoolSizes};

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
    };
    let decision = decide(&fixture.policy, &context);
    let begun = audit::begin(
        store,
        decision,
        call.arguments.clone(),
        call.metadata.clone(),
    )
    .await
    .unwrap();
    match begun {
        Begun::Denied(refusal) => refusal.row().clone(),
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
/// cannot read who called.
pub(super) async fn read_back(admin: &Client, row: &AuditRowId) -> AuditRecord {
    let row = admin
        .query_one(
            "SELECT tool_use_id, deployment, surface, profile, tool, connector, classification,
                    decision, reason, sentence, policy_revision,
                    proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
                    proved_delegation_team, claimed_acting_person, claimed_team,
                    outcome, outcome_sentence, latency_ms, resources, resources_omitted
             FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap();
    let text = |column: &str| row.get::<_, Option<String>>(column);
    let mut principal = json!({
        "id": {"issuer": text("proved_issuer"), "subject": text("proved_subject")},
        "kind": text("proved_kind"),
    });
    match text("proved_kind").as_deref() {
        Some("workload") => principal["team"] = json!(text("proved_team")),
        _ => principal["groups"] = json!(row.get::<_, Option<Vec<String>>>("proved_groups")),
    }
    let completion = text("outcome").map(|outcome| {
        let mut completion = json!({
            "outcome": outcome,
            "latency_ms": row.get::<_, Option<i64>>("latency_ms"),
        });
        if let Some(sentence) = text("outcome_sentence") {
            completion["sentence"] = json!(sentence);
        }
        completion
    });
    let resources = match row.get::<_, Value>("resources") {
        Value::String(unknown) => json!(unknown),
        named => json!({ "named": named }),
    };
    serde_json::from_value(json!({
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
    assert!(outcomes.contains(&Some(Outcome::Error)));
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Some(Outcome::Refused { .. })))
    );
    assert_eq!(outcomes.iter().filter(|o| o.is_none()).count(), 3);
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
        };
        let decision = decide(&fixture.policy, &context);
        let failure = audit::begin(&store, decision, call.arguments, metadata)
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

#[tokio::test]
async fn the_database_assigns_each_row_its_own_identifier() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let call = Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT);
    let first = through_core(&store, &fixture, &call).await;
    let second = through_core(&store, &fixture, &call).await;
    assert_ne!(first, second);
    for row in [&first, &second] {
        let parts: Vec<usize> = row.as_str().split('-').map(str::len).collect();
        assert_eq!(parts, vec![8, 4, 4, 4, 12], "{}", row.as_str());
    }
}

/// An allowed call's row, begun through the core and not yet finished.
pub(super) async fn begun_row(store: &PgAuditStore, fixture: &Fixture) -> AuditRowId {
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
    };
    let decision = decide(&fixture.policy, &context);
    match audit::begin(store, decision, call.arguments, call.metadata)
        .await
        .unwrap()
    {
        Begun::Allowed(guard) => guard.row().clone(),
        Begun::Denied(refusal) => panic!("denied: {}", refusal.sentence()),
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
        completion(Outcome::Error, 5),
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
    let admin = db.admin().await;
    admin
        .batch_execute(&format!(
            "ALTER ROLE {GATEWAY_ROLE} IN DATABASE {} SET synchronous_commit = off",
            db.name()
        ))
        .await
        .unwrap();
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

    // Options the caller set are kept beside it.
    let mut config = db.config_as(GATEWAY_ROLE);
    config.options("-c statement_timeout=4321");
    let store = PgAuditStore::connect(config, NoTls, PoolSizes::default()).unwrap();
    let client = store.begin.get().await.unwrap();
    assert_eq!(show(&client).await, "on");
    let timeout: String = client
        .query_one("SHOW statement_timeout", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(timeout, "4321ms");
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
    };
    let decision = decide(&fixture.policy, &context);
    let failure = audit::begin(&store, decision, call.arguments, call.metadata)
        .await
        .unwrap_err();
    assert_eq!(
        failure.sentence(),
        "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later."
    );
}
