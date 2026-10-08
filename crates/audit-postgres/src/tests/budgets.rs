//! The store's time budgets: begin gives up at its budget, and finish answers at its budget and
//! keeps trying until its deadline.

use std::error::Error as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gateway_core::audit::{self, Answer, AuditFailure, Begun, Outcome, Ran};
use gateway_core::{CallContext, RequestedTool, decide};
use gateway_testkit::{
    Caller, FORBIDDEN_DOCUMENT, FakeCredentialSource, Fixture, FixtureConnector, READ_TOOL,
    SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};
use tokio_postgres::config::Host;
use tokio_postgres::tls::{MakeTlsConnect, NoTlsStream, TlsConnect};
use tokio_postgres::{Client, Config, Socket};

use super::store::{Call, begun_row, completion};
use super::{DUMMY_PASSWORD, GATEWAY_ROLE, TestDatabase, connect};
use crate::store::CANCEL_WAIT;
use crate::{Budgets, FinishCounts, PgAuditError, PgAuditStore, PoolSizes};

/// How much later than its budget a step may end and still count as on time.
const SLACK: Duration = Duration::from_secs(2);

/// What a store reported of each finish that gave up: the row, the outcome, and why.
type Reports = Arc<std::sync::Mutex<Vec<(String, &'static str, String)>>>;

/// `store`, keeping what it reports of each finish that gives up.
fn reporting(store: PgAuditStore) -> (PgAuditStore, Reports) {
    let reports = Reports::default();
    let kept = Arc::clone(&reports);
    let store = store.on_given_up(move |given_up| {
        let why = match given_up.error {
            PgAuditError::Deadline { .. } => "deadline".to_owned(),
            PgAuditError::CompletedDifferently { .. } => "completed differently".to_owned(),
            PgAuditError::NoSuchRow { .. } => "no such row".to_owned(),
            other => other.to_string(),
        };
        kept.lock()
            .unwrap()
            .push((given_up.row.as_str().to_owned(), given_up.outcome, why));
    });
    (store, reports)
}

fn reports_of(reports: &Reports) -> Vec<(String, &'static str, String)> {
    reports.lock().unwrap().clone()
}

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
async fn begin_gives_up_at_its_budget_and_cancels_an_insert_still_waiting() {
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

    // The insert, still waiting on the lock, was cancelled: once the lock goes, nothing is
    // written for the refused call.
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

/// Sets `setting` for new sessions on the test database, or resets it with `None`.
async fn set_for_new_sessions(server: &Config, name: &str, setting: &str, value: Option<&str>) {
    let change = match value {
        Some(value) => format!("SET {setting} = '{value}'"),
        None => format!("RESET {setting}"),
    };
    connect(server)
        .await
        .batch_execute(&format!("ALTER DATABASE {name} {change}"))
        .await
        .unwrap();
}

/// A server that has become read-only, as the old primary does in a failover, is a failure
/// trying again can fix, on a new connection: the one that found the server read-only stays
/// read-only.
#[tokio::test]
async fn finish_tries_again_on_a_new_connection_while_the_server_is_read_only() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
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
    let read_only = "default_transaction_read_only";
    set_for_new_sessions(&db.server, db.name(), read_only, Some("on")).await;
    let read_only_for = Duration::from_millis(500);
    let server = db.server.clone();
    let name = db.name().to_owned();
    let writable = tokio::spawn(async move {
        sleep(read_only_for).await;
        set_for_new_sessions(&server, &name, read_only, None).await;
    });

    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    // The first attempts failed: every session was read-only.
    assert!(started.elapsed() >= read_only_for);
    writable.await.unwrap();
    assert_eq!(outcome_of(&admin, &row).await.as_deref(), Some("ok"));
}

/// A lock not had within `lock_timeout`, which a database or role may set, is tried again.
#[tokio::test]
async fn finish_tries_again_when_a_lock_times_out() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    set_for_new_sessions(&db.server, db.name(), "lock_timeout", Some("100ms")).await;
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
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
    let lock = lock_table(&db).await;
    let locked_for = Duration::from_millis(600);
    let release_later = async {
        sleep(locked_for).await;
        release(&lock).await;
    };

    let started = Instant::now();
    let (finished, ()) = tokio::join!(
        within(budgets.answer + SLACK, audit::finish(&store, ok, 7)),
        release_later
    );
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert!(started.elapsed() >= locked_for);
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
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
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
    // The caller stopped waiting at the answer budget, and the row is still named.
    assert_eq!(
        reports_of(&reports),
        vec![(row.clone(), "ok", "deadline".to_owned())]
    );

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
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
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
    assert_eq!(
        reports_of(&reports),
        vec![
            (
                row.as_str().to_owned(),
                "error",
                "completed differently".to_owned()
            ),
            (missing.as_str().to_owned(), "ok", "no such row".to_owned()),
        ]
    );
}

/// One attempt is cut off at the deadline, so a finish whose answer budget is longer than its
/// deadline still gives up at the deadline.
#[tokio::test]
async fn an_attempt_ends_at_the_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(4),
        finish_deadline: Duration::from_secs(1),
        ..Budgets::default()
    };
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
    let (row, ok) = ran(
        &store,
        &fixture,
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
    )
    .await;
    let lock = lock_table(&db).await;

    let started = Instant::now();
    let finished = within(
        budgets.finish_deadline + Duration::from_millis(500),
        audit::finish(&store, ok, 7),
    )
    .await;
    assert!(started.elapsed() >= budgets.finish_deadline - Duration::from_millis(100));
    let PgAuditError::Deadline { last, .. } = cause(finished.failure().unwrap()) else {
        panic!("{:?}", finished.failure());
    };
    assert!(matches!(**last, PgAuditError::AttemptTimedOut), "{last}");
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 1
        }
    );
    assert_eq!(
        reports_of(&reports),
        vec![(row.clone(), "ok", "deadline".to_owned())]
    );

    // The attempt that ran out of time is gone from the finish pool, so no later finish waits
    // behind its update, and the update was cancelled: once the lock goes, the row the store
    // gave up on is not completed after all.
    assert_eq!(store.finish.status().size, 0);
    let admin = db.admin().await;
    until(
        Duration::from_secs(5),
        "the update's cancellation",
        || async {
            count(
                &admin,
                &format!(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
                         AND query LIKE 'UPDATE switchboard_audit.call_rows%'",
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
    assert_eq!(outcome_of(&admin, &row).await, None);
}

/// A connection killed in the middle of an attempt is a failure trying again can fix.
#[tokio::test]
async fn finish_tries_again_when_its_connection_is_killed() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
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
    let lock = lock_table(&db).await;
    let waiting = format!(
        "FROM pg_stat_activity
         WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
             AND query LIKE 'UPDATE switchboard_audit.call_rows%'",
        db.name()
    );
    let kill = async {
        until(
            Duration::from_secs(5),
            "finish's update waiting on the lock",
            || async { count(&admin, &format!("SELECT count(*) {waiting}")).await == 1 },
        )
        .await;
        let killed: bool = admin
            .query_one(&format!("SELECT pg_terminate_backend(pid) {waiting}"), &[])
            .await
            .unwrap()
            .get(0);
        assert!(killed);
        release(&lock).await;
    };

    let (finished, ()) = tokio::join!(
        within(budgets.answer + SLACK, audit::finish(&store, ok, 7)),
        kill
    );
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    assert_eq!(outcome_of(&admin, &row).await.as_deref(), Some("ok"));
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 0
        }
    );
}

#[tokio::test]
async fn a_finish_the_caller_stops_waiting_for_still_completes_its_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let admin = db.admin().await;
    let row = begun_row(&store, &fixture).await;
    let lock = lock_table(&db).await;
    // The caller gives up, as a request handler does when its client goes away.
    let gave_up = tokio::time::timeout(
        Duration::from_millis(100),
        store.finish_within_budget(&row, &completion(Outcome::Ok, 3)),
    )
    .await;
    assert!(gave_up.is_err());
    release(&lock).await;
    until(Duration::from_secs(10), "the completion", || async {
        store.finishes().in_flight == 0
    })
    .await;
    assert_eq!(
        outcome_of(&admin, row.as_str()).await.as_deref(),
        Some("ok")
    );
}

/// Each attempt counts waiting for a connection from the finish pool, so a finish whose pool is
/// held, by a burst of other finishes or a connect that hangs, still gives up at its deadline.
#[tokio::test]
async fn finish_counts_waiting_for_a_connection_in_each_attempt() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(4),
        finish_deadline: Duration::from_secs(1),
        ..Budgets::default()
    };
    let (store, reports) = reporting(
        db.store(PoolSizes {
            begin: 1,
            finish: 1,
        })
        .with_budgets(budgets),
    );
    let (row, ok) = ran(
        &store,
        &fixture,
        Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT),
    )
    .await;
    // Every finish connection is in use.
    let held = store.finish.get().await.unwrap();

    let started = Instant::now();
    let finished = within(
        budgets.finish_deadline + SLACK,
        audit::finish(&store, ok, 7),
    )
    .await;
    assert!(started.elapsed() >= budgets.finish_deadline - Duration::from_millis(100));
    let PgAuditError::Deadline { last, .. } = cause(finished.failure().unwrap()) else {
        panic!("{:?}", finished.failure());
    };
    assert!(matches!(**last, PgAuditError::AttemptTimedOut), "{last}");
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 1
        }
    );
    assert_eq!(
        reports_of(&reports),
        vec![(row.clone(), "ok", "deadline".to_owned())]
    );
    drop(held);
    assert_eq!(outcome_of(&db.admin().await, &row).await, None);
}

/// Makes the first update of `call_rows` fail with SQLSTATE `code`, through a trigger that
/// fires before the table's own, and lets every later one through. Each update is counted in
/// the sequence `public.update_attempts`.
async fn fail_the_first_update_with(db: &TestDatabase, code: &str) {
    db.admin()
        .await
        .batch_execute(&format!(
            "CREATE SEQUENCE public.update_attempts;
             CREATE FUNCTION public.fail_the_first_update() RETURNS trigger
                 LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
             AS $$
             BEGIN
                 IF nextval('public.update_attempts') = 1 THEN
                     RAISE EXCEPTION 'the first update fails' USING ERRCODE = '{code}';
                 END IF;
                 RETURN NEW;
             END
             $$;
             CREATE TRIGGER a_fail_the_first_update
                 BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION public.fail_the_first_update();"
        ))
        .await
        .unwrap();
}

/// A finish whose first update fails with SQLSTATE `code` tries again and completes its row.
async fn finish_tries_again_after(code: &str) {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    fail_the_first_update_with(&db, code).await;
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_secs(5),
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

    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(
        finished.failure().is_none(),
        "{code}: {:?}",
        finished.failure()
    );
    assert_eq!(outcome_of(&admin, &row).await.as_deref(), Some("ok"));
    assert_eq!(
        count(&admin, "SELECT last_value FROM public.update_attempts").await,
        2,
        "{code}"
    );
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 0
        }
    );
}

/// Class 08, a connection exception.
#[tokio::test]
async fn finish_tries_again_after_a_connection_exception() {
    finish_tries_again_after("08006").await;
}

/// Class 40, a transaction rolled back, as by a serialization failure or a deadlock.
#[tokio::test]
async fn finish_tries_again_after_a_serialization_failure() {
    finish_tries_again_after("40001").await;
}

/// Class 53, insufficient resources, such as a full disk.
#[tokio::test]
async fn finish_tries_again_after_the_server_runs_short() {
    finish_tries_again_after("53100").await;
}

/// Class 57, operator intervention, such as a server shutting down.
#[tokio::test]
async fn finish_tries_again_after_an_operator_intervenes() {
    finish_tries_again_after("57P01").await;
}

/// Class 58, a system error outside Postgres, such as a failed read or write.
#[tokio::test]
async fn finish_tries_again_after_a_system_error() {
    finish_tries_again_after("58030").await;
}

/// The code a request for TLS starts with, where a startup has its protocol version.
const TLS_REQUEST_CODE: u32 = 80_877_103;

/// A TLS connector that offers TLS and never makes it, so a session asks the server for TLS
/// first and goes on without it when the server says no.
#[derive(Clone, Copy)]
struct AsksForTls;

impl MakeTlsConnect<Socket> for AsksForTls {
    type Stream = NoTlsStream;
    type TlsConnect = Self;
    type Error = std::io::Error;

    fn make_tls_connect(&mut self, _domain: &str) -> Result<Self, std::io::Error> {
        Ok(Self)
    }
}

impl TlsConnect<Socket> for AsksForTls {
    type Stream = NoTlsStream;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<NoTlsStream, std::io::Error>>;

    fn connect(self, _stream: Socket) -> Self::Future {
        std::future::ready(Err(std::io::Error::other("no TLS in this test")))
    }
}

/// When a connection the proxy stopped answering opened and closed.
#[derive(Debug, PartialEq, Eq)]
enum Unanswered {
    Opened,
    Closed,
}

/// A proxy in front of the test server. While `answering` holds, it says no to each request
/// for TLS and passes the connection through. After, it holds each new connection open and
/// says nothing, and reports when the connection opens and closes.
async fn proxy(
    db: &TestDatabase,
    answering: Arc<AtomicBool>,
) -> (u16, mpsc::UnboundedReceiver<(Unanswered, Instant)>) {
    let Some(Host::Tcp(host)) = db.server.get_hosts().first().cloned() else {
        panic!("the test server is not reached over TCP");
    };
    let upstream = (host, db.server.get_ports().first().copied().unwrap_or(5432));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (events, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let events = events.clone();
            let upstream = upstream.clone();
            let answering = Arc::clone(&answering);
            tokio::spawn(async move {
                let mut first = [0; 8];
                if client.read_exact(&mut first).await.is_err() {
                    return;
                }
                if first[4..] == TLS_REQUEST_CODE.to_be_bytes() {
                    if !answering.load(Ordering::SeqCst) {
                        let _ = events.send((Unanswered::Opened, Instant::now()));
                        let mut rest = Vec::new();
                        let _ = client.read_to_end(&mut rest).await;
                        let _ = events.send((Unanswered::Closed, Instant::now()));
                        return;
                    }
                    client.write_all(b"N").await.unwrap();
                    client.read_exact(&mut first).await.unwrap();
                }
                let mut server = TcpStream::connect(upstream).await.unwrap();
                server.write_all(&first).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    (port, received)
}

/// A request to cancel a statement that the server does not answer is given up after a while,
/// so it does not hold a connection open for ever.
#[tokio::test]
async fn a_cancel_the_server_does_not_answer_is_given_up() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let answering = Arc::new(AtomicBool::new(true));
    let (port, mut unanswered) = proxy(&db, Arc::clone(&answering)).await;
    let mut config = Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user(GATEWAY_ROLE)
        .password(DUMMY_PASSWORD)
        .dbname(db.name());
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let store = PgAuditStore::connect(config, AsksForTls, PoolSizes::default())
        .unwrap()
        .with_budgets(budgets);
    // Begin's connection is made, and then the proxy answers no new connection.
    drop(store.begin.get().await.unwrap());
    answering.store(false, Ordering::SeqCst);
    let lock = lock_table(&db).await;

    // Begin runs out of time, and asks the server to cancel its insert, over a new connection.
    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    let (event, opened) = within(SLACK, unanswered.recv()).await.unwrap();
    assert_eq!(event, Unanswered::Opened);
    let (event, closed) = within(CANCEL_WAIT + SLACK, unanswered.recv())
        .await
        .unwrap();
    assert_eq!(event, Unanswered::Closed);
    assert!(closed - opened >= CANCEL_WAIT - Duration::from_millis(100));
    release(&lock).await;
}
