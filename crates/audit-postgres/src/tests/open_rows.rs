//! The open rows (decision 0009, "Open rows"): allowed rows of kind `call` with no completion
//! past their deadline, by the database's clock, counted through the view migration 0005 makes.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gateway_core::audit::{self, AuditRowId, Begun, ErrorKind, Outcome, RowStart};
use gateway_core::{CallContext, RequestedTool, decide, list_tools};
use gateway_testkit::{
    Caller, Fixture, FixtureConnector, READ_TOOL, SURFACE_ALL, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
    row_start,
};
use serde_json::json;
use tokio_postgres::Client;

use tokio::time::Instant;

use super::budgets::{SLACK, count, outcome_of, release, until, within};
use super::store::{begun_row, completion};
use super::{GATEWAY_ROLE, OWNER_ROLE, TestDatabase};
use crate::store::OPEN_ROWS_TIMEOUT;
use crate::{Budgets, OPEN_ROWS_POOL_SIZE, OpenRows, PgAuditError, PgAuditStore, PoolSizes};

/// Budgets that give a row begun with no call deadline an allowance of 3 s, so a test waits
/// that long, not the default 34 s, for a row's deadline to pass.
fn short() -> Budgets {
    Budgets {
        begin: Duration::from_secs(1),
        answer: Duration::from_secs(1),
        finish_deadline: Duration::from_secs(1),
    }
}

fn none_open() -> OpenRows {
    OpenRows {
        count: 0,
        oldest_deadline: None,
    }
}

/// A store with [`short`] budgets, as the gateway's role.
fn store(db: &TestDatabase) -> PgAuditStore {
    db.store(PoolSizes::default()).with_budgets(short())
}

/// Begins `caller`'s read of `document` through the core, with no call deadline, and leaves
/// it unfinished. Returns its row and whether it was allowed.
async fn begin(
    store: &PgAuditStore,
    fixture: &Fixture,
    caller: Caller,
    document: &str,
) -> (AuditRowId, bool) {
    let arguments = json!({"document": document});
    let context = CallContext {
        resources: FixtureConnector::resources_of(READ_TOOL, &arguments),
        caller: fixture.caller_context(caller, SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
        key: gateway_core::CallKey::Absent,
        currency: gateway_core::Currency::NotAsked,
    };
    let start = RowStart {
        call_deadline_ms: 0,
        ..row_start()
    };
    let decision = decide(&fixture.policy, &context);
    match audit::begin(store, start, decision, arguments, Default::default())
        .await
        .unwrap()
    {
        // Dropped unfinished: the row keeps an empty outcome.
        Begun::Allowed(guard) => (guard.row().clone(), true),
        Begun::Denied(refusal) => (refusal.row().clone(), false),
        Begun::Reused(reused) => panic!("the Postgres store reserves no receipts: {reused:?}"),
    }
}

/// The row's deadline, read as the server's superuser.
async fn deadline(admin: &Client, row: &AuditRowId) -> SystemTime {
    admin
        .query_one(
            "SELECT deadline FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0)
}

/// Whether the row's deadline has passed, by the database's clock.
async fn past(admin: &Client, row: &AuditRowId) -> bool {
    admin
        .query_one(
            "SELECT deadline < clock_timestamp() FROM switchboard_audit.call_rows
             WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0)
}

/// Waits until the row's deadline has passed, by the database's clock.
async fn wait_past(admin: &Client, row: &AuditRowId) {
    for _ in 0..200 {
        if past(admin, row).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the deadline of row {} did not pass", row.as_str());
}

#[tokio::test]
async fn an_allowed_row_is_open_once_its_deadline_has_passed_and_not_before() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = store(&db);
    let admin = db.admin().await;

    let (first, allowed) = begin(&store, &fixture, Caller::TeamA, TEAM_A_DOCUMENT).await;
    assert!(allowed);
    assert_eq!(store.open_rows().await.unwrap(), none_open());
    // The answer came before the deadline: had it not, the row could have been open.
    assert!(
        !past(&admin, &first).await,
        "the test ran too slowly to tell"
    );

    wait_past(&admin, &first).await;
    let (second, _) = begin(&store, &fixture, Caller::TeamA, TEAM_A_DOCUMENT).await;
    assert_eq!(
        store.open_rows().await.unwrap(),
        OpenRows {
            count: 1,
            oldest_deadline: Some(deadline(&admin, &first).await),
        }
    );
    // The earliest deadline is the oldest open row's.
    wait_past(&admin, &second).await;
    assert_eq!(
        store.open_rows().await.unwrap(),
        OpenRows {
            count: 2,
            oldest_deadline: Some(deadline(&admin, &first).await),
        }
    );
}

#[tokio::test]
async fn a_completed_row_is_not_open() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = store(&db);
    let admin = db.admin().await;
    let (completed, _) = begin(&store, &fixture, Caller::TeamA, TEAM_A_DOCUMENT).await;
    let (left, _) = begin(&store, &fixture, Caller::TeamA, TEAM_A_DOCUMENT).await;
    store
        .complete(&completed, &completion(Outcome::Ok, 3))
        .await
        .unwrap();
    wait_past(&admin, &completed).await;
    wait_past(&admin, &left).await;
    assert_eq!(
        store.open_rows().await.unwrap(),
        OpenRows {
            count: 1,
            oldest_deadline: Some(deadline(&admin, &left).await),
        }
    );
}

/// A denial has a deadline and no completion, and is never completed: it is not open.
#[tokio::test]
async fn a_denied_row_is_not_open() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = store(&db);
    let admin = db.admin().await;
    let (denied, allowed) = begin(&store, &fixture, Caller::TeamA, TEAM_B_DOCUMENT).await;
    assert!(!allowed);
    wait_past(&admin, &denied).await;
    assert_eq!(store.open_rows().await.unwrap(), none_open());
}

/// A list row has no deadline and is written complete, so it is never open. The table's
/// constraints keep a list row from having a decision or a deadline, and the trigger set_times
/// gives it none; the view does not rely on them. A list row planted with an allowed decision
/// and a deadline long past, with those constraints and the trigger out of the way, is not
/// open either.
#[tokio::test]
async fn a_list_row_is_never_open_past_any_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = store(&db);
    let admin = db.admin().await;
    let caller = fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap();
    let listed = audit::listed(
        &store,
        row_start(),
        &caller,
        fixture.policy.revision().clone(),
        list_tools(&fixture.policy, &caller),
        None,
    )
    .await
    .unwrap();
    assert!(!listed.tools().is_empty());

    admin
        .batch_execute(
            "ALTER TABLE switchboard_audit.call_rows
                 DROP CONSTRAINT kind_shape,
                 DROP CONSTRAINT deadline_shape,
                 DROP CONSTRAINT decision_shape;
             SET session_replication_role = replica;
             INSERT INTO switchboard_audit.call_rows
                 (id, begun_at, deployment, surface, profile, policy_revision,
                  proved_issuer, proved_subject, proved_kind, proved_team,
                  instance, kind, decision, allowance_ms, deadline,
                  listed_tools, listed_omitted)
             VALUES (gen_random_uuid(), clock_timestamp() - interval '1 hour', 'fixture',
                     'fixture-all', 'workload', 'fixture-1', 'https://issuer.fixture.test',
                     'planted', 'workload', 'team-a', 'planted', 'list', 'allow', 0,
                     clock_timestamp() - interval '1 hour', '[]', 0);
             RESET session_replication_role;",
        )
        .await
        .unwrap();
    assert_eq!(store.open_rows().await.unwrap(), none_open());
}

/// The open-row query runs on a pool of its own, of one connection, so neither begins nor
/// finishes that hold every connection of theirs hold it up.
#[tokio::test]
async fn the_open_row_query_runs_on_a_pool_of_its_own() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db
        .store(PoolSizes {
            begin: 1,
            finish: 1,
        })
        .with_budgets(short());
    let begin = store.begin.get().await.unwrap();
    let finish = store.finish.get().await.unwrap();
    assert_eq!(store.open_rows().await.unwrap(), none_open());
    assert_eq!(store.open_rows_pool.status().max_size, OPEN_ROWS_POOL_SIZE);
    assert_eq!(store.open_rows_pool.status().size, 1);
    assert_eq!(store.finish.status().size, 1);
    assert_eq!(store.begin.status().size, 1);
    drop((begin, finish));
}

/// `n` connections from the finish pool, held until dropped.
async fn finish_connections(store: &PgAuditStore, n: usize) -> Vec<deadpool_postgres::Object> {
    let mut held = Vec::new();
    for _ in 0..n {
        held.push(store.finish.get().await.unwrap());
    }
    held
}

/// Whether an open-row query by the gateway's role is waiting on a lock.
async fn open_row_query_waiting(admin: &Client, db: &TestDatabase) -> bool {
    count(
        admin,
        &format!(
            "SELECT count(*) FROM pg_stat_activity
             WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
                 AND wait_event_type = 'Lock' AND query LIKE '%open_call_rows%'",
            db.name()
        ),
    )
    .await
        == 1
}

/// An open-row query held up for as long as its time limit allows keeps its own connection,
/// and no finish waits for it: one with every finish connection free, and one with every
/// finish connection but one in use, each complete their row while the query is still held.
///
/// The query is held by a lock on the view alone, which an `ALTER VIEW` takes, so the
/// finishes' updates of `call_rows` do not wait on it. Each finish must be done while the
/// query is still waiting: a finish that needed the query's connection could have it only once
/// the query gave up, at its time limit.
#[tokio::test]
async fn a_held_open_row_query_does_not_delay_a_finish() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let sizes = PoolSizes::default();
    let store = Arc::new(db.store(sizes));
    let admin = db.admin().await;
    let first = begun_row(&store, &fixture).await;
    let second = begun_row(&store, &fixture).await;
    // Every finish connection is open, so a finish asks for none it must first make.
    drop(finish_connections(&store, sizes.finish).await);

    let lock = db.admin().await;
    lock.batch_execute(&format!(
        "BEGIN; ALTER VIEW switchboard_audit.open_call_rows OWNER TO {OWNER_ROLE}"
    ))
    .await
    .unwrap();
    let poll = tokio::spawn({
        let store = Arc::clone(&store);
        async move { store.open_rows().await }
    });
    until(
        OPEN_ROWS_TIMEOUT,
        "the open-row query waiting on the view's lock",
        || open_row_query_waiting(&admin, &db),
    )
    .await;

    store
        .finish_within_budget(&first, &completion(Outcome::Ok, 3))
        .await
        .unwrap();
    let held = finish_connections(&store, sizes.finish - 1).await;
    store
        .finish_within_budget(&second, &completion(Outcome::Ok, 4))
        .await
        .unwrap();
    assert!(
        !poll.is_finished() && open_row_query_waiting(&admin, &db).await,
        "the open-row query was no longer held when the finishes completed, so they may have \
         waited for it"
    );
    drop(held);

    release(&lock).await;
    assert_eq!(
        within(OPEN_ROWS_TIMEOUT + SLACK, poll)
            .await
            .unwrap()
            .unwrap(),
        none_open()
    );
    for row in [&first, &second] {
        assert!(outcome_of(&admin, row.as_str()).await.is_some());
    }
}

/// The open-row query has 2 s from asking for a connection. One held by a lock past that fails,
/// and the store asks the server to cancel it, so it stops waiting while the lock is still
/// held, and takes its connection out of the pool, so nothing later waits behind it.
#[tokio::test]
async fn an_open_row_query_held_past_its_time_limit_is_cancelled() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = store(&db);
    let admin = db.admin().await;
    // The open-row connection is open, so the time goes to the query.
    drop(store.open_rows_pool.get().await.unwrap());
    let lock = db.admin().await;
    lock.batch_execute("BEGIN; LOCK TABLE switchboard_audit.call_rows IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();

    let started = Instant::now();
    let error = within(OPEN_ROWS_TIMEOUT + SLACK, store.open_rows())
        .await
        .unwrap_err();
    assert!(
        matches!(error, PgAuditError::OpenRowsTimedOut { budget } if budget == OPEN_ROWS_TIMEOUT),
        "{error}"
    );
    assert!(started.elapsed() >= OPEN_ROWS_TIMEOUT);
    assert_eq!(store.open_rows_pool.status().size, 0);
    until(
        Duration::from_secs(5),
        "the open-row query's cancellation",
        || async {
            count(
                &admin,
                &format!(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
                         AND query LIKE '%open_call_rows%'",
                    db.name()
                ),
            )
            .await
                == 0
        },
    )
    .await;
    release(&lock).await;
    assert_eq!(store.open_rows().await.unwrap(), none_open());
}

/// A finish that comes after the deadline completes the row, which is then no longer open.
#[tokio::test]
async fn a_late_finish_closes_the_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = store(&db);
    let admin = db.admin().await;
    let (row, _) = begin(&store, &fixture, Caller::TeamA, TEAM_A_DOCUMENT).await;
    wait_past(&admin, &row).await;
    assert_eq!(store.open_rows().await.unwrap().count, 1);
    store
        .complete(
            &row,
            &completion(
                Outcome::Error {
                    error_kind: ErrorKind::Other,
                },
                2_500,
            ),
        )
        .await
        .unwrap();
    assert_eq!(store.open_rows().await.unwrap(), none_open());
}
