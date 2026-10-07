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
    SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
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

/// The store's log, as JSON lines, for one test. Each `#[tokio::test]` runs its tasks on its
/// own thread, the store's spawned ones included, so a subscriber set there sees all of them
/// and nothing from other tests.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Starts capturing on this thread, until the guard is dropped.
    fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let captured = Self::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        (captured, tracing::subscriber::set_default(subscriber))
    }

    /// The fields of every event the store logged on giving up a row.
    fn given_up(&self) -> Vec<serde_json::Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["fields"]["event"] == crate::GIVEN_UP_EVENT)
            .inspect(|event| assert_eq!(event["level"], "ERROR", "{event}"))
            .map(|event| event["fields"].clone())
            .collect()
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
    // The insert was cancelled: once the lock goes, nothing is written for a refused call.
    // And the connection that ran out of time leaves the pool, so no later begin queues
    // behind it.
    until(
        Duration::from_secs(5),
        "the connection's removal from the pool",
        || async { store.begin.status().size == 0 },
    )
    .await;
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
async fn an_allowed_row_that_commits_after_its_budget_is_completed_as_error() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_millis(300),
        finish_deadline: Duration::from_secs(10),
    };
    // As against a paused server: the cancellation never reaches the insert.
    let store = db
        .store(PoolSizes::default())
        .with_budgets(budgets)
        .without_cancelling();
    let admin = db.admin().await;
    let lock = lock_table(&db).await;

    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    // The caller was refused, and the insert is still waiting on the lock.
    release(&lock).await;

    // The insert commits after all. Nothing ran, so the row is completed as `error`, not left
    // open as an allowed call that may have run.
    until(
        Duration::from_secs(5),
        "the late row's completion",
        || async {
            count(
                &admin,
                "SELECT count(*) FROM switchboard_audit.call_rows
              WHERE decision = 'allow' AND outcome = 'error' AND latency_ms = 0",
            )
            .await
                == 1
        },
    )
    .await;
    assert_eq!(
        count(&admin, "SELECT count(*) FROM switchboard_audit.call_rows").await,
        1
    );
    until(Duration::from_secs(5), "the late finish's end", || async {
        store.finishes() == FinishCounts::default()
    })
    .await;
    assert_eq!(store.begin.status().size, 0);
}

#[tokio::test]
async fn an_insert_with_no_answer_by_the_finish_deadline_is_given_up_and_its_connection_dropped() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_millis(300),
        finish_deadline: Duration::from_secs(1),
    };
    let store = db
        .store(PoolSizes::default())
        .with_budgets(budgets)
        .without_cancelling();
    let lock = lock_table(&db).await;
    let (log, _logging) = Captured::start();

    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    // The lock outlasts the finish deadline, so the insert never answers in time.
    until(
        Duration::from_secs(5),
        "the insert to be given up",
        || async { store.finishes().given_up == 1 },
    )
    .await;
    // Logged when it happens, not only counted. There is no row identifier to name.
    let given_up = log.given_up();
    assert_eq!(given_up.len(), 1, "{given_up:?}");
    assert_eq!(given_up[0]["stage"], "begin");
    assert_eq!(given_up[0]["decision"], "allow");
    assert!(given_up[0].get("row").is_none(), "{given_up:?}");
    // Its connection, still waiting on the lock, is not handed to a later begin.
    assert_eq!(store.begin.status().size, 0);
    release(&lock).await;
}

#[tokio::test]
async fn a_denied_row_that_commits_after_its_budget_is_left_as_it_is() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let store = db
        .store(PoolSizes::default())
        .with_budgets(budgets)
        .without_cancelling();
    let admin = db.admin().await;
    let lock = lock_table(&db).await;

    // Outside team-a's limit.
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_B_DOCUMENT);
    let decision = decide_read(&fixture, &call);
    assert!(!decision.is_allowed(), "{decision:?}");
    let failure = within(
        budgets.begin + SLACK,
        audit::begin(&store, decision, call.arguments, call.metadata),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    release(&lock).await;
    until(Duration::from_secs(5), "the late denial's row", || async {
        count(&admin, "SELECT count(*) FROM switchboard_audit.call_rows").await == 1
    })
    .await;
    // A denial is complete as it stands; nothing writes an outcome on it.
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM switchboard_audit.call_rows
              WHERE decision = 'deny' AND outcome IS NULL"
        )
        .await,
        1
    );
    assert_eq!(store.finishes(), FinishCounts::default());
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

/// Needs no server: nothing listens where the store connects, so every attempt fails, as when
/// the database is down, until the deadline. Runs in every CI job.
#[tokio::test]
async fn a_finish_given_up_at_its_deadline_is_logged_naming_its_row() {
    let config: tokio_postgres::Config = "host=127.0.0.1 port=1 user=nobody dbname=nothing"
        .parse()
        .unwrap();
    let budgets = Budgets {
        answer: Duration::from_millis(100),
        finish_deadline: Duration::from_millis(600),
        ..Budgets::default()
    };
    let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())
        .unwrap()
        .with_budgets(budgets);
    let (log, _logging) = Captured::start();
    let row = gateway_core::audit::AuditRowId::new("00000000-0000-4000-8000-000000000001");

    let error = within(
        budgets.answer + SLACK,
        store.finish_within_budget(&row, &completion(Outcome::Error, 9)),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, PgAuditError::AnswerBudget { .. }),
        "{error}"
    );
    // Still trying: nothing is given up before the deadline.
    assert!(log.given_up().is_empty());
    until(
        budgets.finish_deadline + SLACK,
        "giving up at the deadline",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert_eq!(store.finishes().given_up, 1);
    // Decision 0009: a finish not written by its deadline is a telemetry event naming the row
    // and the outcome's kind, when it happens.
    let given_up = log.given_up();
    assert_eq!(given_up.len(), 1, "{given_up:?}");
    assert_eq!(given_up[0]["stage"], "finish");
    assert_eq!(given_up[0]["row"], row.as_str());
    assert_eq!(given_up[0]["outcome"], "error");
    assert!(
        given_up[0]["cause"]
            .as_str()
            .is_some_and(|cause| cause.contains("finish deadline")),
        "{given_up:?}"
    );
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
    let (log, _logging) = Captured::start();

    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(matches!(
        cause(finished.failure().unwrap()),
        PgAuditError::AnswerBudget { .. }
    ));
    // Still trying: nothing is given up before the deadline.
    assert!(log.given_up().is_empty());
    until(
        budgets.finish_deadline + SLACK,
        "giving up at the deadline",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert!(started.elapsed() >= budgets.finish_deadline - Duration::from_millis(100));
    assert_eq!(store.finishes().given_up, 1);
    // Decision 0009: a finish not written by its deadline is a telemetry event naming the row
    // and the outcome's kind, when it happens.
    let given_up = log.given_up();
    assert_eq!(given_up.len(), 1, "{given_up:?}");
    assert_eq!(given_up[0]["stage"], "finish");
    assert_eq!(given_up[0]["row"], row.as_str());
    assert_eq!(given_up[0]["outcome"], "ok");
    assert!(
        given_up[0]["cause"]
            .as_str()
            .is_some_and(|cause| cause.contains("finish deadline")),
        "{given_up:?}"
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
