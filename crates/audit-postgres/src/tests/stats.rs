//! What the store counts for telemetry: each counter moves exactly when its cause happens, and
//! never on success.

use std::time::Duration;

use gateway_core::audit::{self, Begun, Outcome, RequestMetadata};
use gateway_core::{CallContext, RequestedTool, ToolUseId, decide};
use gateway_testkit::{
    Caller, Fixture, FixtureConnector, READ_TOOL, SURFACE_ALL, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT,
    WRITE_TOOL, row_start,
};
use tokio::time::Instant;

use super::TestDatabase;
use super::budgets::{
    SLACK, begin_read, cause, lock_table, outcome_of, ran, release, until, within,
};
use super::store::{Call, begun_row, completion};
use crate::{
    BeginFailures, Budgets, GivenUpCauses, LatencyHistogram, PgAuditError, PgAuditStore, PoolSizes,
    PoolStats, StoreStats,
};

fn allowed() -> Call {
    Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
}

/// Waits until the store has nothing in flight.
async fn settled(store: &PgAuditStore, limit: Duration) {
    until(limit, "nothing in flight", || async {
        store.stats().finishes_in_flight == 0
    })
    .await;
}

/// Every latency in the histogram fell in some bucket.
fn assert_whole(histogram: &LatencyHistogram) {
    assert_eq!(
        histogram.buckets.iter().sum::<u64>(),
        histogram.count,
        "{histogram:?}"
    );
}

/// A begin whose insert is held past the begin budget, here by a lock, counts one begin failure
/// for its budget, and nothing else.
#[tokio::test]
async fn a_begin_held_past_its_budget_counts_one_budget_exceeded() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let lock = lock_table(&db).await;
    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    let stats = store.stats();
    assert_eq!(
        stats.begin_failures,
        BeginFailures {
            budget_exceeded: 1,
            ..BeginFailures::default()
        }
    );
    assert_eq!(stats.begin_latency.count, 1);
    assert!(stats.begin_latency.sum >= budgets.begin, "{stats:?}");
    assert_eq!(stats.finish_latency.count, 0);
    release(&lock).await;
}

/// A begin that waits past its budget for a connection from the begin pool counts one begin
/// failure for the pool, not for the budget.
#[tokio::test]
async fn a_begin_waiting_past_its_budget_for_a_connection_counts_one_pool_timeout() {
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
    let held = store.begin.get().await.unwrap();
    assert_eq!(
        store.stats().begin_pool,
        PoolStats {
            in_use: 1,
            size: 1,
            max_size: 1,
        }
    );
    let failure = within(budgets.begin + SLACK, begin_read(&store, &fixture))
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    assert_eq!(
        store.stats().begin_failures,
        BeginFailures {
            pool_timeout: 1,
            ..BeginFailures::default()
        }
    );
    drop(held);
    assert_eq!(store.stats().begin_pool.in_use, 0);
}

/// A record with a value Postgres cannot store counts one begin failure for the value.
#[tokio::test]
async fn a_begin_refusing_a_value_counts_one_value_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let call = allowed();
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
    };
    let metadata = RequestMetadata {
        tool_use_id: Some(ToolUseId::new("toolu_\u{0}x")),
        claimed_team: None,
    };
    let decision = decide(&fixture.policy, &context);
    let failure = audit::begin(&store, row_start(), decision, call.arguments, metadata)
        .await
        .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::Nul { .. }),
        "{failure}"
    );
    let stats = store.stats();
    assert_eq!(
        stats.begin_failures,
        BeginFailures {
            value_refused: 1,
            ..BeginFailures::default()
        }
    );
    assert_eq!(stats.begin_latency.count, 1);
}

/// Begins and finishes that succeed count their latency, one each, and nothing else. Once
/// idle, no connection of either pool is in use.
#[tokio::test]
async fn the_latency_counts_equal_the_begins_and_finishes_and_success_counts_nothing_else() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let sizes = PoolSizes::default();
    let store = db.store(sizes);
    assert_eq!(
        store.stats(),
        StoreStats {
            begin_pool: PoolStats {
                max_size: sizes.begin,
                ..PoolStats::default()
            },
            finish_pool: PoolStats {
                max_size: sizes.finish,
                ..PoolStats::default()
            },
            ..StoreStats::default()
        }
    );

    let mut finishes = 0;
    for _ in 0..3 {
        let (_, ok) = ran(&store, &fixture, allowed()).await;
        let finished = audit::finish(&store, ok, 7).await;
        assert!(finished.failure().is_none(), "{:?}", finished.failure());
        finishes += 1;
    }
    // A denial is a begin too, written complete, with nothing to finish.
    let denied = Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT);
    let context = CallContext {
        resources: FixtureConnector::resources_of(denied.tool, &denied.arguments),
        caller: fixture
            .caller_context(denied.caller, denied.surface)
            .unwrap(),
        tool: RequestedTool::new(denied.tool),
    };
    let decision = decide(&fixture.policy, &context);
    let begun = audit::begin(
        &store,
        row_start(),
        decision,
        denied.arguments,
        denied.metadata,
    )
    .await
    .unwrap();
    assert!(matches!(begun, Begun::Denied(_)));
    settled(&store, Duration::from_secs(5)).await;

    let stats = store.stats();
    assert_eq!(stats.begin_latency.count, 4);
    assert_eq!(stats.finish_latency.count, finishes);
    assert_whole(&stats.begin_latency);
    assert_whole(&stats.finish_latency);
    assert!(stats.begin_latency.sum > Duration::ZERO);
    assert!(stats.finish_latency.sum > Duration::ZERO);
    assert_eq!(stats.begin_failures, BeginFailures::default());
    assert_eq!(stats.finishes_given_up, GivenUpCauses::default());
    assert_eq!(stats.answers_released_before_finish, 0);
    assert_eq!(stats.begins_never_committed, 0);
    assert_eq!(stats.finishes_in_flight, 0);
    // Idle: the connections are open, and none is in use.
    assert_eq!(stats.begin_pool.in_use, 0);
    assert_eq!(stats.finish_pool.in_use, 0);
    assert!(stats.begin_pool.size >= 1, "{stats:?}");
    assert!(stats.finish_pool.size >= 1, "{stats:?}");
    assert_eq!(
        (stats.begin_pool.max_size, stats.finish_pool.max_size),
        (sizes.begin, sizes.finish)
    );

    // A connection held is in use until it is returned.
    let held = store.finish.get().await.unwrap();
    assert_eq!(store.stats().finish_pool.in_use, 1);
    drop(held);
    assert_eq!(store.stats().finish_pool.in_use, 0);
}

/// A finish slowed past its answer budget answers the caller and keeps trying: one answer
/// released before its row was complete. The row is completed later, so nothing is given up.
#[tokio::test]
async fn a_finish_slowed_past_its_answer_budget_counts_one_late_answer() {
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
    let (row, ok) = ran(&store, &fixture, allowed()).await;
    let lock = lock_table(&db).await;

    let started = Instant::now();
    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(
        matches!(
            cause(finished.failure().unwrap()),
            PgAuditError::AnswerBudget { .. }
        ),
        "{:?}",
        finished.failure()
    );
    assert!(started.elapsed() >= budgets.answer);
    let stats = store.stats();
    assert_eq!(stats.answers_released_before_finish, 1);
    assert_eq!(stats.finishes_in_flight, 1);
    assert_eq!(stats.finish_latency.count, 1);

    release(&lock).await;
    settled(&store, Duration::from_secs(10)).await;
    assert_eq!(outcome_of(&admin, &row).await.as_deref(), Some("ok"));
    let stats = store.stats();
    assert_eq!(stats.answers_released_before_finish, 1);
    assert_eq!(stats.finishes_given_up, GivenUpCauses::default());
    assert_eq!(stats.finish_latency.count, 1);
}

/// A finish that is still trying at its deadline gives up: one given up, for the deadline.
#[tokio::test]
async fn a_finish_past_its_deadline_counts_one_given_up_for_the_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        answer: Duration::from_millis(200),
        finish_deadline: Duration::from_secs(1),
        ..Budgets::default()
    };
    let store = db.store(PoolSizes::default()).with_budgets(budgets);
    let (_, ok) = ran(&store, &fixture, allowed()).await;
    let lock = lock_table(&db).await;

    let finished = within(budgets.answer + SLACK, audit::finish(&store, ok, 7)).await;
    assert!(finished.failure().is_some());
    settled(&store, budgets.finish_deadline + SLACK).await;
    let stats = store.stats();
    assert_eq!(
        stats.finishes_given_up,
        GivenUpCauses {
            deadline: 1,
            ..GivenUpCauses::default()
        }
    );
    assert_eq!(stats.answers_released_before_finish, 1);
    assert_eq!(store.finishes().given_up, 1);
    release(&lock).await;
}

/// A different second completion is refused at once, and counted apart from a deadline; so is
/// a finish of a row that is not there. The same completion again is not given up.
#[tokio::test]
async fn a_different_second_completion_is_counted_apart_from_a_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let store = db.store(PoolSizes::default());
    let row = begun_row(&store, &fixture).await;
    store
        .finish_within_budget(&row, &completion(Outcome::Ok, 5))
        .await
        .unwrap();
    store
        .finish_within_budget(&row, &completion(Outcome::Ok, 5))
        .await
        .unwrap();
    assert_eq!(store.stats().finishes_given_up, GivenUpCauses::default());

    let error = store
        .finish_within_budget(&row, &completion(Outcome::Error, 5))
        .await
        .unwrap_err();
    assert!(
        matches!(error, PgAuditError::CompletedDifferently { .. }),
        "{error}"
    );
    assert_eq!(
        store.stats().finishes_given_up,
        GivenUpCauses {
            completed_differently: 1,
            ..GivenUpCauses::default()
        }
    );

    let missing = gateway_core::audit::AuditRowId::new("00000000-0000-4000-8000-000000000000");
    let error = store
        .finish_within_budget(&missing, &completion(Outcome::Ok, 5))
        .await
        .unwrap_err();
    assert!(matches!(error, PgAuditError::NoSuchRow { .. }), "{error}");
    let stats = store.stats();
    assert_eq!(
        stats.finishes_given_up,
        GivenUpCauses {
            completed_differently: 1,
            no_such_row: 1,
            ..GivenUpCauses::default()
        }
    );
    assert_eq!(stats.finish_latency.count, 4);
    assert_eq!(stats.answers_released_before_finish, 0);
    assert_eq!(store.finishes().given_up, 2);
}
