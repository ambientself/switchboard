//! What the store counts for its telemetry (decision 0009, "counted and exported from milestone
//! 2"), read with [`PgAuditStore::stats`](crate::PgAuditStore::stats).
//!
//! Every count is an atomic, so nothing on the begin or finish path waits to count.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// The upper bound of each latency bucket but the last, in milliseconds: 5, 10, 25, 50, 100,
/// 250 and 500 ms, then 1, 2, 5 and 30 s. The last bucket has no bound.
pub const LATENCY_BOUNDS_MS: [u64; 11] =
    [5, 10, 25, 50, 100, 250, 500, 1_000, 2_000, 5_000, 30_000];

/// How many buckets a latency histogram has: one per bound, and one past the last.
pub const LATENCY_BUCKETS: usize = LATENCY_BOUNDS_MS.len() + 1;

const NANOS_PER_MS: u128 = 1_000_000;

/// The bucket a latency falls in: the first whose bound it does not exceed, so a latency of
/// exactly 5 ms is in the 5 ms bucket, and one a nanosecond longer in the 10 ms bucket.
fn bucket_of(latency: Duration) -> usize {
    let nanos = latency.as_nanos();
    LATENCY_BOUNDS_MS
        .iter()
        .position(|bound| nanos <= u128::from(*bound) * NANOS_PER_MS)
        .unwrap_or(LATENCY_BOUNDS_MS.len())
}

/// A latency histogram with the fixed buckets of [`LATENCY_BOUNDS_MS`], kept in atomics.
#[derive(Debug, Default)]
pub(crate) struct LatencyCounter {
    buckets: [AtomicU64; LATENCY_BUCKETS],
    count: AtomicU64,
    /// The sum of every latency, in nanoseconds. It would take 584 years of latency to fill.
    sum_nanos: AtomicU64,
}

impl LatencyCounter {
    /// Counts one latency.
    pub(crate) fn record(&self, latency: Duration) {
        self.buckets[bucket_of(latency)].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// What has been counted so far. Each number is read on its own, so one taken while a
    /// latency is being counted may count it in some and not yet in others.
    pub(crate) fn snapshot(&self) -> LatencyHistogram {
        LatencyHistogram {
            buckets: std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed)),
            count: self.count.load(Ordering::Relaxed),
            sum: Duration::from_nanos(self.sum_nanos.load(Ordering::Relaxed)),
        }
    }
}

/// How many latencies fell in each bucket of [`LATENCY_BOUNDS_MS`], how many there were, and
/// their sum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencyHistogram {
    /// How many fell in each bucket: `buckets[i]` counts those above the bound before it, if
    /// any, and at most [`LATENCY_BOUNDS_MS`]`[i]`; the last counts those above 30 s. Not
    /// cumulative: see [`cumulative`](Self::cumulative).
    pub buckets: [u64; LATENCY_BUCKETS],
    /// How many latencies were counted.
    pub count: u64,
    /// Their sum.
    pub sum: Duration,
}

impl LatencyHistogram {
    /// The sum, in milliseconds.
    #[must_use]
    pub fn sum_ms(&self) -> f64 {
        self.sum.as_secs_f64() * 1_000.0
    }

    /// How many fell at or under each bound, and, last, how many in all, as a Prometheus
    /// histogram's `le` buckets count them.
    #[must_use]
    pub fn cumulative(&self) -> [u64; LATENCY_BUCKETS] {
        let mut total = 0;
        self.buckets.map(|count| {
            total += count;
            total
        })
    }
}

/// Why begins failed, each counted once, when its begin fails. A list row is not a begin, and
/// is not counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BeginFailures {
    /// The begin budget ran out with a connection in hand: the insert, or the preparing of it,
    /// was still waiting, as on a lock.
    pub budget_exceeded: u64,
    /// The begin budget ran out while waiting for a connection from the begin pool.
    pub pool_timeout: u64,
    /// The database could not be reached, refused or failed the statement, or already holds
    /// the row under its identifier in another form.
    pub database_error: u64,
    /// A value of the record could not be put in its column, such as text holding U+0000.
    pub value_refused: u64,
}

impl BeginFailures {
    /// Every begin that failed.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.budget_exceeded + self.pool_timeout + self.database_error + self.value_refused
    }
}

/// Why finishes, and completions of failed begins' rows, gave up without completing their
/// row, each counted once. Each row given up keeps an empty outcome, if it was written, and is
/// reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GivenUpCauses {
    /// The finish deadline passed: [`PgAuditError::Deadline`](crate::PgAuditError::Deadline).
    pub deadline: u64,
    /// The row already had another completion:
    /// [`PgAuditError::CompletedDifferently`](crate::PgAuditError::CompletedDifferently).
    pub completed_differently: u64,
    /// A finish found no row: [`PgAuditError::NoSuchRow`](crate::PgAuditError::NoSuchRow).
    pub no_such_row: u64,
    /// The task was dropped before it ended, as when the runtime shuts down:
    /// [`PgAuditError::FinishTaskLost`](crate::PgAuditError::FinishTaskLost).
    pub task_lost: u64,
    /// Anything else: a completion the row cannot hold, or another refusal by the database.
    pub other: u64,
}

impl GivenUpCauses {
    /// Every finish that gave up.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.deadline + self.completed_differently + self.no_such_row + self.task_lost + self.other
    }
}

/// How many connections a pool has open, and how many of those are in use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Connections handed out and not yet returned.
    pub in_use: usize,
    /// Connections open, in use or idle.
    pub size: usize,
    /// The most it may open.
    pub max_size: usize,
}

/// What the store has counted since it was made, from [`PgAuditStore::stats`](crate::PgAuditStore::stats).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    /// Begins that failed, by cause.
    pub begin_failures: BeginFailures,
    /// Finishes that answered the caller at the answer budget, with the store still trying to
    /// complete the row.
    pub answers_released_before_finish: u64,
    /// Finishes and completions of failed begins' rows that gave up, by cause.
    pub finishes_given_up: GivenUpCauses,
    /// Failed begins whose row the store's last attempt, at the finish deadline, found
    /// missing: the insert had not committed by then. Not given up, and not reported.
    pub begins_never_committed: u64,
    /// Finishes, and completions of failed begins' rows, still trying.
    pub finishes_in_flight: usize,
    /// How long each begin took, from the call to its answer, failed or not.
    pub begin_latency: LatencyHistogram,
    /// How long each finish held the caller's answer, from the call to its answer: at most
    /// about the answer budget, after which the store goes on trying on its own task.
    pub finish_latency: LatencyHistogram,
    /// The begin pool, which begins and list rows use.
    pub begin_pool: PoolStats,
    /// The finish pool, which finishes, completions of failed begins' rows and the open-row
    /// query use.
    pub finish_pool: PoolStats,
}

#[cfg(test)]
mod unit {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const NS: Duration = Duration::from_nanos(1);

    #[test]
    fn a_latency_at_a_bound_is_in_that_bound_s_bucket_and_one_past_it_in_the_next() {
        assert_eq!(bucket_of(Duration::ZERO), 0);
        for (i, bound) in LATENCY_BOUNDS_MS.iter().enumerate() {
            let at = MS * u32::try_from(*bound).unwrap();
            assert_eq!(bucket_of(at - NS), i, "{bound} ms less a nanosecond");
            assert_eq!(bucket_of(at), i, "{bound} ms");
            assert_eq!(bucket_of(at + NS), i + 1, "{bound} ms and a nanosecond");
        }
        assert_eq!(bucket_of(Duration::from_secs(3_600)), LATENCY_BUCKETS - 1);
        assert_eq!(bucket_of(Duration::MAX), LATENCY_BUCKETS - 1);
    }

    #[test]
    fn a_histogram_counts_each_latency_once_and_sums_them() {
        let counter = LatencyCounter::default();
        assert_eq!(counter.snapshot(), LatencyHistogram::default());
        for latency in [MS * 5, MS * 5 + NS, MS * 40_000, Duration::from_micros(250)] {
            counter.record(latency);
        }
        let histogram = counter.snapshot();
        let mut expected = [0; LATENCY_BUCKETS];
        expected[0] = 2;
        expected[1] = 1;
        expected[LATENCY_BUCKETS - 1] = 1;
        assert_eq!(histogram.buckets, expected);
        assert_eq!(histogram.count, 4);
        assert_eq!(
            histogram.sum,
            MS * 5 + MS * 5 + NS + MS * 40_000 + Duration::from_micros(250)
        );
        assert!((histogram.sum_ms() - 40_010.250_001).abs() < 1e-6);
        let cumulative = histogram.cumulative();
        assert_eq!(cumulative[0], 2);
        assert_eq!(cumulative[1..LATENCY_BUCKETS - 1], [3; LATENCY_BUCKETS - 2]);
        assert_eq!(cumulative[LATENCY_BUCKETS - 1], 4);
    }

    #[test]
    fn the_totals_add_every_cause() {
        let failures = BeginFailures {
            budget_exceeded: 1,
            pool_timeout: 2,
            database_error: 4,
            value_refused: 8,
        };
        assert_eq!(failures.total(), 15);
        let given_up = GivenUpCauses {
            deadline: 1,
            completed_differently: 2,
            no_such_row: 4,
            task_lost: 8,
            other: 16,
        };
        assert_eq!(given_up.total(), 31);
    }
}
