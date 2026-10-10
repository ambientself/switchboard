//! The signals of design section 11, exported in Prometheus text (decision 0009, "counted and
//! exported from milestone 2").
//!
//! [`serve_metrics`] answers `GET /metrics` on a listener of its own, which the deployment
//! file's `[metrics]` names (see [`crate::deployment`]); without it nothing is served. The
//! listener is never the MCP listener, and nothing else is on it: any other path is 404, and
//! any method on `/metrics` other than GET is 405, except HEAD, which axum answers as GET
//! without a body. It runs no host, origin or identity check, so it belongs on a port only the
//! operator's scraper can reach. No sink is chosen (decision 0009, Still open 3): this is the
//! default until one is.
//!
//! [`Metrics::render`] writes, by hand and with no Prometheus crate:
//!
//! - Always, from [`Telemetry::counts`]: `switchboard_telemetry_events_total{event}`, each
//!   event counted when it is emitted, and `switchboard_telemetry_dropped_total`.
//! - With audit in Postgres, from [`PgAuditStore::stats`] and the request path:
//!   - `switchboard_audit_begin_failures_total{cause}`, `cause` one of `budget_exceeded`,
//!     `pool_timeout`, `database_error` and `value_refused`;
//!   - `switchboard_audit_failure_answers_total`, each `tools/call` or `tools/list` answered
//!     with the audit-failure sentence;
//!   - `switchboard_audit_answers_released_before_finish_total`;
//!   - `switchboard_audit_finishes_given_up_total{cause}`, `cause` one of `deadline`,
//!     `completed_differently`, `no_such_row`, `task_lost` and `other`;
//!   - `switchboard_audit_begins_never_committed_total`;
//!   - `switchboard_audit_finishes_in_flight`;
//!   - `switchboard_audit_open_rows`, `switchboard_audit_oldest_open_row_deadline_seconds`
//!     and `switchboard_audit_open_rows_poll_failures_total`, from the open-row poll below;
//!   - `switchboard_audit_begin_latency_seconds` and `switchboard_audit_finish_latency_seconds`,
//!     histograms with the store's fixed buckets;
//!   - `switchboard_audit_pool_connections_in_use{pool}`, and beside it, as separate gauges,
//!     `switchboard_audit_pool_connections_open{pool}` and
//!     `switchboard_audit_pool_connections_max{pool}`, `pool` one of `begin` and `finish`.
//!
//! With audit disabled only the telemetry counters are written: there is no store to count.
//!
//! Section 11 also names receipts in `unknown` and the age of the oldest. They are not
//! exported: receipts arrive with #10 stage 2, and a constant 0 would say no receipt is
//! unknown when none can be.
//!
//! **Open rows.** A task polls [`PgAuditStore::open_rows`] every [`OPEN_ROWS_POLL`], the first
//! time as soon as the listener serves. The query runs on the store's finish pool, holds one
//! connection, and gives up after 2 s. A failed poll counts in
//! `switchboard_audit_open_rows_poll_failures_total` and keeps the last value. Until a poll has
//! succeeded, `switchboard_audit_open_rows` has no sample; the oldest deadline has one only
//! while a row is open, as seconds since the Unix epoch. A scrape reads what the last poll
//! found and never waits on the database.
//!
//! Shutting down stops the poller and the listener; the binary does it after the MCP listener
//! has stopped and the store's finishes are done.

use std::fmt::{Display, Write};
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, UNIX_EPOCH};

use audit_postgres::{
    LATENCY_BOUNDS_MS, LatencyHistogram, OpenRows, PgAuditStore, PoolStats, StoreStats,
};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use http::HeaderValue;
use http::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::server::{HEADER_READ_TIMEOUT, accept_failed};
use crate::telemetry::{Telemetry, TelemetryCounts};

/// How often the open rows are counted.
pub const OPEN_ROWS_POLL: Duration = Duration::from_secs(15);

/// The content type of `GET /metrics`: Prometheus text, version 0.0.4.
pub const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// How long shutting down waits for a scrape still being answered.
const SCRAPE_GRACE: Duration = Duration::from_secs(5);

/// What `GET /metrics` reads: the telemetry counters and, with audit in Postgres, the store and
/// what the open-row poll last found. Cheap to clone; clones share everything.
#[derive(Clone)]
pub struct Metrics {
    telemetry: Telemetry,
    audit: Option<Arc<AuditSource>>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("telemetry", &self.telemetry)
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

struct AuditSource {
    store: Arc<PgAuditStore>,
    /// What the last poll that succeeded found, if one has.
    open: Mutex<Option<OpenRows>>,
    poll_failures: AtomicU64,
}

impl Metrics {
    /// The metrics of a gateway emitting to `telemetry`, with its audit `store` when audit is
    /// in Postgres and `None` when it is disabled.
    pub fn new(telemetry: Telemetry, store: Option<Arc<PgAuditStore>>) -> Self {
        Self {
            telemetry,
            audit: store.map(|store| {
                Arc::new(AuditSource {
                    store,
                    open: Mutex::new(None),
                    poll_failures: AtomicU64::new(0),
                })
            }),
        }
    }

    /// Every signal as it stands, in Prometheus text. See the [module documentation](self).
    pub fn render(&self) -> String {
        let mut text = Text::default();
        telemetry_signals(&mut text, &self.telemetry.counts());
        if let Some(audit) = &self.audit {
            let open = *audit.open.lock().unwrap_or_else(PoisonError::into_inner);
            audit_signals(
                &mut text,
                &AuditSignals {
                    stats: audit.store.stats(),
                    failure_answers: self.telemetry.counts().audit_failure_answers,
                    open,
                    poll_failures: audit.poll_failures.load(Ordering::Relaxed),
                },
            );
        }
        text.0
    }
}

/// Counts the open rows every [`OPEN_ROWS_POLL`], the first time at once, for ever.
async fn poll_open_rows(audit: Arc<AuditSource>) {
    let mut every = tokio::time::interval(OPEN_ROWS_POLL);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        match audit.store.open_rows().await {
            Ok(open) => {
                *audit.open.lock().unwrap_or_else(PoisonError::into_inner) = Some(open);
            }
            Err(error) => {
                audit.poll_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    event = "open_rows_poll_failed",
                    %error,
                    "could not count the open audit rows; the metrics keep the last count"
                );
            }
        }
    }
}

/// Aborts its task when dropped, so the poller stops however serving ends.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serves `GET /metrics` on `listener` until `shutdown` completes, and, with audit in Postgres,
/// polls the open rows while it does. Then it stops the poller, stops taking connections, and
/// waits up to 5 s for a scrape still being answered.
pub async fn serve_metrics<F>(
    listener: TcpListener,
    metrics: Metrics,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let address = listener.local_addr()?;
    let _poller = metrics
        .audit
        .clone()
        .map(|audit| AbortOnDrop(tokio::spawn(poll_open_rows(audit))));
    tracing::info!(%address, "serving metrics at /metrics");
    let router = Router::new()
        .route("/metrics", get(scrape))
        .with_state(metrics);
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    let connections = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => stream,
                Err(error) => {
                    accept_failed(&error).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let service = TowerToHyperService::new(router.clone());
        let connection = connections.watch(http.serve_connection(TokioIo::new(stream), service));
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "a metrics connection ended with an error");
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(SCRAPE_GRACE, connections.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(%address, "closing the metrics connections still open");
    }
    tracing::info!(%address, "stopped serving metrics");
    Ok(())
}

async fn scrape(State(metrics): State<Metrics>) -> Response {
    let mut response = Response::new(Body::from(metrics.render()));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(METRICS_CONTENT_TYPE));
    response
}

/// What the audit signals are rendered from.
struct AuditSignals {
    stats: StoreStats,
    failure_answers: u64,
    open: Option<OpenRows>,
    poll_failures: u64,
}

fn telemetry_signals(text: &mut Text, counts: &TelemetryCounts) {
    text.family(
        "switchboard_telemetry_events_total",
        "counter",
        "Telemetry events emitted, by event, whether or not the queue had room for them.",
    );
    for (event, count) in [
        ("identity_failed", counts.identity_failed),
        ("initialize", counts.initialize),
        ("ping", counts.ping),
        ("discover", counts.discover),
        ("unparsable_body", counts.unparsable),
    ] {
        text.sample(
            "switchboard_telemetry_events_total",
            &[("event", event)],
            count,
        );
    }
    text.single(
        "switchboard_telemetry_dropped_total",
        "counter",
        "Telemetry events dropped because the queue was full or closed.",
        counts.dropped,
    );
}

fn audit_signals(text: &mut Text, signals: &AuditSignals) {
    let stats = &signals.stats;
    let failures = &stats.begin_failures;
    text.family(
        "switchboard_audit_begin_failures_total",
        "counter",
        "Audit begins that failed, by cause. budget_exceeded: the begin budget ran out with a \
         connection in hand. pool_timeout: no connection obtained within the begin budget \
         (waiting for the pool or opening a connection). database_error: the database refused \
         or failed the statement. value_refused: a value could not be put in its column.",
    );
    for (cause, count) in [
        ("budget_exceeded", failures.budget_exceeded),
        ("pool_timeout", failures.pool_timeout),
        ("database_error", failures.database_error),
        ("value_refused", failures.value_refused),
    ] {
        text.sample(
            "switchboard_audit_begin_failures_total",
            &[("cause", cause)],
            count,
        );
    }
    text.single(
        "switchboard_audit_failure_answers_total",
        "counter",
        "tools/call and tools/list requests answered with the audit-failure sentence.",
        signals.failure_answers,
    );
    text.single(
        "switchboard_audit_answers_released_before_finish_total",
        "counter",
        "Calls answered at the answer budget with their row still being completed.",
        stats.answers_released_before_finish,
    );
    let given_up = &stats.finishes_given_up;
    text.family(
        "switchboard_audit_finishes_given_up_total",
        "counter",
        "Audit rows whose completion the store stopped trying to write, by cause.",
    );
    for (cause, count) in [
        ("deadline", given_up.deadline),
        ("completed_differently", given_up.completed_differently),
        ("no_such_row", given_up.no_such_row),
        ("task_lost", given_up.task_lost),
        ("other", given_up.other),
    ] {
        text.sample(
            "switchboard_audit_finishes_given_up_total",
            &[("cause", cause)],
            count,
        );
    }
    text.single(
        "switchboard_audit_begins_never_committed_total",
        "counter",
        "Failed begins whose row was still missing at the finish deadline.",
        stats.begins_never_committed,
    );
    text.single(
        "switchboard_audit_finishes_in_flight",
        "gauge",
        "Audit row completions still being tried.",
        stats.finishes_in_flight,
    );
    text.family(
        "switchboard_audit_open_rows",
        "gauge",
        "Allowed call rows with no completion past their deadline, as the last open-row poll \
         that succeeded counted them.",
    );
    if let Some(open) = &signals.open {
        text.sample("switchboard_audit_open_rows", &[], open.count);
    }
    text.family(
        "switchboard_audit_oldest_open_row_deadline_seconds",
        "gauge",
        "The earliest deadline among the open rows, in seconds since the Unix epoch, while one \
         is open.",
    );
    if let Some(deadline) = signals.open.and_then(|open| open.oldest_deadline) {
        let seconds = deadline
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        text.sample(
            "switchboard_audit_oldest_open_row_deadline_seconds",
            &[],
            seconds,
        );
    }
    text.single(
        "switchboard_audit_open_rows_poll_failures_total",
        "counter",
        "Open-row polls that failed; the open-row gauges keep the last count.",
        signals.poll_failures,
    );
    text.histogram(
        "switchboard_audit_begin_latency_seconds",
        "How long each audit begin took, failed or not.",
        &stats.begin_latency,
    );
    text.histogram(
        "switchboard_audit_finish_latency_seconds",
        "How long each audit finish held the caller's answer.",
        &stats.finish_latency,
    );
    for (name, help, of) in [
        (
            "switchboard_audit_pool_connections_in_use",
            "Audit store connections handed out and not yet returned, by pool.",
            (|pool: &PoolStats| pool.in_use) as fn(&PoolStats) -> usize,
        ),
        (
            "switchboard_audit_pool_connections_open",
            "Audit store connections open, in use or idle, by pool.",
            |pool| pool.size,
        ),
        (
            "switchboard_audit_pool_connections_max",
            "The most connections each audit store pool may open.",
            |pool| pool.max_size,
        ),
    ] {
        text.family(name, "gauge", help);
        text.sample(name, &[("pool", "begin")], of(&stats.begin_pool));
        text.sample(name, &[("pool", "finish")], of(&stats.finish_pool));
    }
}

/// Prometheus text, written as it goes. Every name and label here is a constant of this module,
/// so nothing needs escaping.
#[derive(Default)]
struct Text(String);

impl Text {
    /// A family's `HELP` and `TYPE` lines.
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    /// One sample.
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            let labels: Vec<String> = labels
                .iter()
                .map(|(label, value)| format!("{label}=\"{value}\""))
                .collect();
            let _ = write!(self.0, "{{{}}}", labels.join(","));
        }
        let _ = writeln!(self.0, " {value}");
    }

    /// A family with one sample and no labels.
    fn single(&mut self, name: &str, kind: &str, help: &str, value: impl Display) {
        self.family(name, kind, help);
        self.sample(name, &[], value);
    }

    /// A histogram: a cumulative `_bucket` per bound and `+Inf`, then `_sum` in seconds and
    /// `_count`.
    fn histogram(&mut self, name: &str, help: &str, histogram: &LatencyHistogram) {
        self.family(name, "histogram", help);
        let bucket = format!("{name}_bucket");
        let cumulative = histogram.cumulative();
        for (bound, count) in LATENCY_BOUNDS_MS.iter().zip(cumulative) {
            let le = Duration::from_millis(*bound).as_secs_f64().to_string();
            self.sample(&bucket, &[("le", &le)], count);
        }
        self.sample(&bucket, &[("le", "+Inf")], histogram.count);
        self.sample(&format!("{name}_sum"), &[], histogram.sum.as_secs_f64());
        self.sample(&format!("{name}_count"), &[], histogram.count);
    }
}

#[cfg(test)]
mod tests {
    use audit_postgres::{BeginFailures, LATENCY_BUCKETS};

    use super::*;

    fn rendered(signals: &AuditSignals) -> String {
        let mut text = Text::default();
        audit_signals(&mut text, signals);
        text.0
    }

    fn lines(text: &str) -> Vec<&str> {
        text.lines().filter(|line| !line.starts_with('#')).collect()
    }

    #[test]
    fn a_histogram_is_cumulative_with_inf_a_sum_in_seconds_and_a_count() {
        let mut buckets = [0; LATENCY_BUCKETS];
        buckets[0] = 2;
        buckets[3] = 1;
        buckets[LATENCY_BUCKETS - 1] = 1;
        let mut text = Text::default();
        text.histogram(
            "h_seconds",
            "A histogram.",
            &LatencyHistogram {
                buckets,
                count: 4,
                sum: Duration::from_millis(40_062),
            },
        );
        assert_eq!(
            lines(&text.0),
            [
                "h_seconds_bucket{le=\"0.005\"} 2",
                "h_seconds_bucket{le=\"0.01\"} 2",
                "h_seconds_bucket{le=\"0.025\"} 2",
                "h_seconds_bucket{le=\"0.05\"} 3",
                "h_seconds_bucket{le=\"0.1\"} 3",
                "h_seconds_bucket{le=\"0.25\"} 3",
                "h_seconds_bucket{le=\"0.5\"} 3",
                "h_seconds_bucket{le=\"1\"} 3",
                "h_seconds_bucket{le=\"2\"} 3",
                "h_seconds_bucket{le=\"5\"} 3",
                "h_seconds_bucket{le=\"30\"} 3",
                "h_seconds_bucket{le=\"+Inf\"} 4",
                "h_seconds_sum 40.062",
                "h_seconds_count 4",
            ]
        );
        assert!(text.0.contains("# TYPE h_seconds histogram\n"));
    }

    #[test]
    fn the_audit_signals_carry_every_store_count() {
        let stats = StoreStats {
            begin_failures: BeginFailures {
                budget_exceeded: 1,
                pool_timeout: 2,
                database_error: 3,
                value_refused: 4,
            },
            answers_released_before_finish: 5,
            begins_never_committed: 6,
            finishes_in_flight: 7,
            begin_pool: PoolStats {
                in_use: 8,
                size: 9,
                max_size: 10,
            },
            finish_pool: PoolStats {
                in_use: 11,
                size: 12,
                max_size: 13,
            },
            ..StoreStats::default()
        };
        let deadline = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let text = rendered(&AuditSignals {
            stats,
            failure_answers: 14,
            open: Some(OpenRows {
                count: 15,
                oldest_deadline: Some(deadline),
            }),
            poll_failures: 16,
        });
        let samples = lines(&text);
        for expected in [
            "switchboard_audit_begin_failures_total{cause=\"budget_exceeded\"} 1",
            "switchboard_audit_begin_failures_total{cause=\"pool_timeout\"} 2",
            "switchboard_audit_begin_failures_total{cause=\"database_error\"} 3",
            "switchboard_audit_begin_failures_total{cause=\"value_refused\"} 4",
            "switchboard_audit_answers_released_before_finish_total 5",
            "switchboard_audit_begins_never_committed_total 6",
            "switchboard_audit_finishes_in_flight 7",
            "switchboard_audit_pool_connections_in_use{pool=\"begin\"} 8",
            "switchboard_audit_pool_connections_open{pool=\"begin\"} 9",
            "switchboard_audit_pool_connections_max{pool=\"begin\"} 10",
            "switchboard_audit_pool_connections_in_use{pool=\"finish\"} 11",
            "switchboard_audit_pool_connections_open{pool=\"finish\"} 12",
            "switchboard_audit_pool_connections_max{pool=\"finish\"} 13",
            "switchboard_audit_failure_answers_total 14",
            "switchboard_audit_open_rows 15",
            "switchboard_audit_oldest_open_row_deadline_seconds 1800000000",
            "switchboard_audit_open_rows_poll_failures_total 16",
        ] {
            assert!(samples.contains(&expected), "{expected}\n{text}");
        }
    }

    #[test]
    fn before_a_poll_succeeds_and_with_no_row_open_the_open_row_gauges_have_no_sample() {
        let none = rendered(&AuditSignals {
            stats: StoreStats::default(),
            failure_answers: 0,
            open: None,
            poll_failures: 1,
        });
        let closed = rendered(&AuditSignals {
            stats: StoreStats::default(),
            failure_answers: 0,
            open: Some(OpenRows {
                count: 0,
                oldest_deadline: None,
            }),
            poll_failures: 0,
        });
        for text in [&none, &closed] {
            assert!(
                text.contains("# TYPE switchboard_audit_open_rows gauge\n"),
                "{text}"
            );
            assert!(
                !lines(text)
                    .iter()
                    .any(|line| line.starts_with("switchboard_audit_oldest_open_row")),
                "{text}"
            );
        }
        assert!(
            !lines(&none)
                .iter()
                .any(|line| line.starts_with("switchboard_audit_open_rows ")),
            "{none}"
        );
        assert!(lines(&closed).contains(&"switchboard_audit_open_rows 0"));
    }
}
