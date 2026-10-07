//! The store's time budgets: begin gives up at its budget, and finish answers at its budget and
//! keeps trying until its deadline.

use std::error::Error as _;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use gateway_core::audit::{self, Answer, AuditFailure, Begun, Outcome, Ran};
use gateway_core::{CallContext, RequestedTool, decide};
use gateway_testkit::{
    Caller, FORBIDDEN_DOCUMENT, FakeCredentialSource, Fixture, FixtureConnector, READ_TOOL,
    SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT,
};
use tokio::time::{Instant, sleep};
use tokio_postgres::Client;

use super::store::{Call, begun_row, completion};
use super::{GATEWAY_ROLE, TestDatabase, connect};
use crate::{Budgets, FinishCounts, PgAuditError, PgAuditStore, PoolSizes};

/// How much later than its budget a step may end and still count as on time.
const SLACK: Duration = Duration::from_secs(2);

/// A test's own guard against a step that never ends: past `limit`, the test fails.
async fn within<T>(limit: Duration, step: impl Future<Output = T>) -> T {
    tokio::time::timeout(limit, step)
        .await
        .unwrap_or_else(|_| panic!("did not end within {limit:?}"))
}

/// Polls `condition` every 20 ms until it holds, failing the test after `limit`.
async fn until<F, Fut>(limit: Duration, what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let give_up = Instant::now() + limit;
    while !condition().await {
        assert!(
            Instant::now() < give_up,
            "{what} did not happen within {limit:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

/// The store's own error behind the core's audit failure.
fn cause(failure: &AuditFailure) -> &PgAuditError {
    failure
        .source()
        .and_then(|source| source.downcast_ref::<PgAuditError>())
        .expect("the failure came from the Postgres store")
}

fn decide_read(fixture: &Fixture, call: &Call) -> gateway_core::Decision {
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
    };
    decide(&fixture.policy, &context)
}

/// Begins an allowed read through the core.
async fn begin_read(store: &PgAuditStore, fixture: &Fixture) -> Result<Begun, AuditFailure> {
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let decision = decide_read(fixture, &call);
    audit::begin(store, decision, call.arguments, call.metadata).await
}

/// Begins and runs `call` through the core, ready to finish.
async fn ran(store: &PgAuditStore, fixture: &Fixture, call: Call) -> (String, Ran) {
    let decision = decide_read(fixture, &call);
    let Begun::Allowed(guard) = audit::begin(store, decision, call.arguments, call.metadata)
        .await
        .unwrap()
    else {
        panic!("denied");
    };
    let row = guard.row().as_str().to_owned();
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    (row, audit::run(&connector, guard).await)
}

/// A session holding a lock on `call_rows` that blocks every insert and update until
/// [`release`].
async fn lock_table(db: &TestDatabase) -> Client {
    let lock = db.admin().await;
    lock.batch_execute("BEGIN; LOCK TABLE switchboard_audit.call_rows IN SHARE MODE")
        .await
        .unwrap();
    lock
}

async fn release(lock: &Client) {
    lock.batch_execute("COMMIT").await.unwrap();
}

/// Lets the gateway's roles connect to the test database, or not.
async fn allow_connections(db: &TestDatabase, allow: bool) {
    connect(&db.server)
        .await
        .batch_execute(&format!(
            "ALTER DATABASE {} ALLOW_CONNECTIONS {allow}",
            db.name()
        ))
        .await
        .unwrap();
}

async fn count(admin: &Client, sql: &str) -> i64 {
    admin.query_one(sql, &[]).await.unwrap().get(0)
}

async fn outcome_of(admin: &Client, row: &str) -> Option<String> {
    admin
        .query_one(
            "SELECT outcome FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid",
            &[&row],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn begin_gives_up_at_its_budget_and_its_insert_never_lands() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let admin = db.admin().await;
    let lock = lock_table(&db).await;

    let started = Instant::now();
    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(started.elapsed() >= budgets.begin);
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { budget } if *budget == budgets.begin),
        "{failure}"
    );
    assert_eq!(
        failure.sentence(),
        "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later."
    );
    // The connection that ran out of time is gone from the pool, so no later begin queues
    // behind its statement.
    assert_eq!(store.begin.status().size, 0);

    // The insert was cancelled: once the lock goes, nothing is written for a refused call.
    until(
        Duration::from_secs(5),
        "the insert's cancellation",
        || async {
            count(
                &admin,
                &format!(
                    "SELECT count(*) FROM pg_stat_activity
                 WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}'
                     AND query LIKE '%INSERT INTO switchboard_audit.call_rows%'
                     AND state = 'active'",
                    db.name()
                ),
            )
            .await
                == 0
        },
    )
    .await;
    release(&lock).await;
    sleep(Duration::from_millis(200)).await;
    assert_eq!(
        count(&admin, "SELECT count(*) FROM switchboard_audit.call_rows").await,
        0
    );

    // And the next begin, with the table free, writes its row.
    assert!(matches!(
        begin_read(&store, &fixture).await.unwrap(),
        Begun::Allowed(_)
    ));
}

#[tokio::test]
async fn begin_counts_waiting_for_a_connection_in_its_budget() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let store = db
        .store(PoolSizes {
            begin: 1,
            finish: 1,
        })
        .with_budgets(budgets);
    // Every begin connection is in use.
    let held = store.begin.get().await.unwrap();
    let started = Instant::now();
    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(started.elapsed() >= budgets.begin);
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    drop(held);
    assert!(begin_read(&store, &fixture).await.is_ok());
}

#[tokio::test]
async fn finish_answers_at_its_budget_and_completes_the_rows_later() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_millis(300),
        finish_deadline: Duration::from_secs(20),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let admin = db.admin().await;
    let (refused_row, refused) = ran(
        &store,
        &fixture,
        Call::new(
            Caller::TeamA,
            SURFACE_READ,
            SCOPED_READ_TOOL,
            FORBIDDEN_DOCUMENT,
        ),
    )
    .await;
    let (ok_row, ok) = ran(
        &store,
        &fixture,
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
    )
    .await;
    let lock = lock_table(&db).await;

    // A refusal that could not be recorded in time becomes the audit-failure sentence.
    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, refused, 5)).await;
    assert!(started.elapsed() >= budgets.answer);
    assert!(
        matches!(finished.answer(), Answer::AuditFailed { .. }),
        "{:?}",
        finished.answer()
    );
    assert!(matches!(
        cause(finished.failure().unwrap()),
        PgAuditError::AnswerBudget { .. }
    ));
    // A tool that ran still gives its result.
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 6)).await;
    assert!(matches!(finished.answer(), Answer::Ok(_)));
    assert!(finished.failure().is_some());
    assert_eq!(store.finishes().in_flight, 2);

    // Several attempts run out of time while the lock is held, and are tried again.
    sleep(budgets.answer * 3).await;
    assert_eq!(outcome_of(&admin, &ok_row).await, None);
    release(&lock).await;
    until(Duration::from_secs(10), "both completions", || async {
        store.finishes().in_flight == 0
    })
    .await;
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 0
        }
    );
    assert_eq!(
        outcome_of(&admin, &refused_row).await.as_deref(),
        Some("refused")
    );
    assert_eq!(outcome_of(&admin, &ok_row).await.as_deref(), Some("ok"));
}

#[tokio::test]
async fn finish_tries_again_until_the_database_takes_connections() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
        ..Budgets::default()
    };
    // The finish pool has no connection yet, so finish must make one.
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let admin = db.admin().await;
    let (row, ok) = ran(
        &store,
        &fixture,
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
    )
    .await;
    allow_connections(&db, false).await;
    let refused_for = Duration::from_millis(500);
    let server = db.server.clone();
    let name = db.name().to_owned();
    let reopen = tokio::spawn(async move {
        sleep(refused_for).await;
        connect(&server)
            .await
            .batch_execute(&format!("ALTER DATABASE {name} ALLOW_CONNECTIONS true"))
            .await
            .unwrap();
    });

    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert!(matches!(finished.answer(), Answer::Ok(_)));
    // The first attempts failed: the database was refusing connections.
    assert!(started.elapsed() >= refused_for);
    reopen.await.unwrap();
    assert_eq!(outcome_of(&admin, &row).await.as_deref(), Some("ok"));
}

#[tokio::test]
async fn finish_gives_up_at_its_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_millis(200),
        finish_deadline: Duration::from_millis(1500),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let admin = db.admin().await;
    let (row, ok) = ran(
        &store,
        &fixture,
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
    )
    .await;
    allow_connections(&db, false).await;

    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(matches!(
        cause(finished.failure().unwrap()),
        PgAuditError::AnswerBudget { .. }
    ));
    until(
        budgets.finish_deadline + SLACK,
        "giving up at the deadline",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert!(started.elapsed() >= budgets.finish_deadline - Duration::from_millis(100));
    assert_eq!(store.finishes().given_up, 1);

    allow_connections(&db, true).await;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(outcome_of(&admin, &row).await, None);
}

#[tokio::test]
async fn finish_does_not_retry_what_trying_again_cannot_fix() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let row = begun_row(&store, &fixture).await;
    store
        .finish_within_budget(&row, &completion(Outcome::Ok, 5))
        .await
        .unwrap();

    // A second, different completion is refused at once, and the first stands.
    let started = Instant::now();
    let error = store
        .finish_within_budget(&row, &completion(Outcome::Error, 5))
        .await
        .unwrap_err();
    assert!(
        matches!(error, PgAuditError::CompletedDifferently { .. }),
        "{error}"
    );
    // The same one again is accepted.
    store
        .finish_within_budget(&row, &completion(Outcome::Ok, 5))
        .await
        .unwrap();
    // A row that is not there is not waited for.
    let missing = gateway_core::audit::AuditRowId::new("00000000-0000-4000-8000-000000000000");
    let error = store
        .finish_within_budget(&missing, &completion(Outcome::Ok, 5))
        .await
        .unwrap_err();
    assert!(matches!(error, PgAuditError::NoSuchRow { .. }), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 2
        }
    );
}
