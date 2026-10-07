//! How long begin and finish take against a real server. Prints its numbers; run with
//! `--nocapture` to see them. They measure this machine and this server, not production.

use std::sync::Arc;
use std::time::Duration;

use gateway_core::audit::{self, Begun};
use gateway_core::{CallContext, RequestedTool, decide};
use gateway_testkit::{
    Caller, FakeCredentialSource, Fixture, FixtureConnector, READ_TOOL, SURFACE_ALL,
    TEAM_A_DOCUMENT,
};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::TestDatabase;
use super::store::Call;
use crate::{PgAuditStore, PoolSizes};

const CALLS: usize = 200;
const WORKERS: usize = 8;

/// One allowed read through the core: the time begin took, and the time finish took.
async fn one_call(store: &PgAuditStore, fixture: &Fixture) -> (Duration, Duration) {
    let call = Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    let context = CallContext {
        resources: FixtureConnector::resources_of(call.tool, &call.arguments),
        caller: fixture.caller_context(call.caller, call.surface).unwrap(),
        tool: RequestedTool::new(call.tool),
    };
    let decision = decide(&fixture.policy, &context);
    let started = Instant::now();
    let begun = audit::begin(store, decision, call.arguments, call.metadata)
        .await
        .unwrap();
    let begin = started.elapsed();
    let Begun::Allowed(guard) = begun else {
        panic!("denied");
    };
    let connector = FixtureConnector::new(Arc::new(FakeCredentialSource::new()));
    let ran = audit::run(&connector, guard).await;
    let started = Instant::now();
    let finished = audit::finish(store, ran, 1).await;
    let finish = started.elapsed();
    assert!(finished.failure().is_none(), "{:?}", finished.failure());
    (begin, finish)
}

/// The nearest-rank percentile `p` of `samples`.
fn percentile(samples: &mut [Duration], p: usize) -> Duration {
    samples.sort();
    let rank = (p * samples.len()).div_ceil(100).max(1);
    samples[rank - 1]
}

fn report(label: &str, timings: &[(Duration, Duration)]) {
    let mut begins: Vec<Duration> = timings.iter().map(|t| t.0).collect();
    let mut finishes: Vec<Duration> = timings.iter().map(|t| t.1).collect();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    println!(
        "{label}, {} calls: begin p50 {:.2} ms, p95 {:.2} ms; finish p50 {:.2} ms, p95 {:.2} ms",
        timings.len(),
        ms(percentile(&mut begins, 50)),
        ms(percentile(&mut begins, 95)),
        ms(percentile(&mut finishes, 50)),
        ms(percentile(&mut finishes, 95)),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latency_of_begin_and_finish_over_200_calls() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Arc::new(Fixture::new().unwrap());
    let store = Arc::new(db.store(PoolSizes::default()));
    // Opens the connections first, so the numbers are of writes, not of connecting.
    one_call(&store, &fixture).await;

    let mut one_at_a_time = Vec::with_capacity(CALLS);
    for _ in 0..CALLS {
        one_at_a_time.push(one_call(&store, &fixture).await);
    }
    report("one at a time", &one_at_a_time);

    let mut workers = JoinSet::new();
    for _ in 0..WORKERS {
        let store = Arc::clone(&store);
        let fixture = Arc::clone(&fixture);
        workers.spawn(async move {
            let mut timings = Vec::with_capacity(CALLS / WORKERS);
            for _ in 0..CALLS / WORKERS {
                timings.push(one_call(&store, &fixture).await);
            }
            timings
        });
    }
    let mut concurrent = Vec::with_capacity(CALLS);
    while let Some(timings) = workers.join_next().await {
        concurrent.extend(timings.unwrap());
    }
    report(&format!("{WORKERS} at a time"), &concurrent);

    let admin = db.admin().await;
    let complete: i64 = admin
        .query_one(
            "SELECT count(*) FROM switchboard_audit.call_rows WHERE outcome = 'ok'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(complete, i64::try_from(2 * CALLS + 1).unwrap());
}

#[test]
fn percentiles_are_nearest_rank() {
    let mut samples: Vec<Duration> = (1..=20).map(Duration::from_millis).collect();
    assert_eq!(percentile(&mut samples, 50), Duration::from_millis(10));
    assert_eq!(percentile(&mut samples, 95), Duration::from_millis(19));
    assert_eq!(percentile(&mut samples, 100), Duration::from_millis(20));
}
