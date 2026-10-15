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
//!   event counted when it is emitted, and `switchboard_telemetry_dropped_total`. Event
//!   `policy_stale` counts each `tools/call` and `tools/list` refused because the policy is
//!   stale; there is no separate counter for them.
//! - Always: `switchboard_calls_shed_total{scope}`, the calls refused by a cap on calls in
//!   flight (decision 0014, section 2). `scope` is `instance` for requests answered 503 at
//!   admission, each a `call_shed` telemetry event, counted here and not among the events
//!   above; and `server` and `team` for calls completed as `refused` by a proxied server's cap
//!   or a team's cap on calls to it, summed over the servers.
//! - With proxied servers, from each one's [`Bulkhead`](crate::bulkhead::Bulkhead), labelled
//!   `server` with the server's name in the registry, so there is one series per server and
//!   nothing a caller chooses:
//!   - `switchboard_proxied_calls_total{server,outcome}`, the calls the server's connector
//!     completed, `outcome` one of `ok`, `error` and `refused`. A call refused by a cap is not
//!     sent, and is counted under `switchboard_calls_shed_total` instead;
//!   - `switchboard_proxied_call_seconds{server}`, a histogram of how long each took, with the
//!     audit store's buckets;
//!   - `switchboard_proxied_late_or_oversized_total{server}`, the calls that were an error of
//!     the kind `oversized_or_late_read`: a `read` tool's answer too large or not in time.
//! - With the drift pass, from its [`DriftSignals`], labelled `server` with each proxied
//!   server's name in the registry (decision 0013, section 5):
//!   - `switchboard_drift_polls_total{server,result}`, each read of the server's tool list,
//!     `result` one of `ok` and `failed`. A failed poll keeps the server's tools served;
//!   - `switchboard_drift_withdrawals_total{server}`, the tools withdrawn from the server;
//!   - `switchboard_probe_results_total{server,result}`, each probe of the server (decision
//!     0013, section 9), `result` one of `refused`, `open` and `not_shown`. An open server
//!     dispatched a call for a tool that does not exist; its tools stay listed;
//!   - `switchboard_reach_checks_total{server,result}`, each reach check of the server's entry
//!     (decision 0011, section 4), `result` one of `held`, `mismatch` and `failed`. A mismatch
//!     withdraws the entry's tools, which `switchboard_drift_withdrawals_total` counts too;
//!   - `switchboard_tools_withdrawn`, how many tools are withdrawn now. It falls when a reload
//!     clears a withdrawal, and is 0 again after a restart.
//! - With the registry's policy, from its [`Freshness`]: `switchboard_policy_age_seconds`, the
//!   seconds since the registry file was last read successfully, and
//!   `switchboard_policy_max_age_seconds`, the age past which the policy is stale (decision
//!   0013, section 8).
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
//!   - `switchboard_audit_unknown_receipts`,
//!     `switchboard_audit_oldest_unknown_receipt_reserved_seconds` and
//!     `switchboard_audit_unknown_receipts_poll_failures_total`, from the same poll: the
//!     receipts in `unknown` and the age of the oldest (design section 11, "Signals");
//!   - from [`ReconcileSignals`], reconciliation's (design section 11, "Signals"):
//!     `switchboard_reconciliation_lookups_total{result}`, the lookups made, `result` one of
//!     `found`, `not_found_authoritative`, `not_found` and `failed`;
//!     `switchboard_reconciliation_handed_to_person_total`, the receipts handed to a person,
//!     which stay `unknown` and so in `switchboard_audit_unknown_receipts`; and
//!     `switchboard_reconciliation_store_failures_total`, the reads and writes of the queue
//!     that failed;
//!   - `switchboard_audit_begin_latency_seconds` and `switchboard_audit_finish_latency_seconds`,
//!     histograms with the store's fixed buckets;
//!   - `switchboard_audit_pool_connections_in_use{pool}`, and beside it, as separate gauges,
//!     `switchboard_audit_pool_connections_open{pool}` and
//!     `switchboard_audit_pool_connections_max{pool}`, `pool` one of `begin`, `finish` and
//!     `open_rows`, the open-row poll's pool of its own.
//!
//! - With the turn-grant gate, from its [`GrantSignals`] (decision 0012, design section 11):
//!   `switchboard_grant_failures_total{kind}`, the grants refused, `kind` one of the eleven
//!   checks (`version`, `unknown_key`, `retired_key`, `encoding`, `signature`, `malformed`,
//!   `wrong_audience`, `not_yet_valid`, `expired`, `lifetime` and `wrong_pod`), each written
//!   from zero; and `switchboard_grants_accepted_total{key_id}`, the grants verified under each
//!   configured key, written only when a key is configured. A request with the grant header
//!   more than once counts as `malformed`.
//!
//! - With Otto's resolver configured, from its client's counts (decision 0012, "Currency"):
//!   `switchboard_resolver_answers_total{answer}`, each question by its answer, `answer` one of
//!   `current`, `superseded`, `ended`, `revoked` and `unconfirmed`, every failure counted as
//!   `unconfirmed`; `switchboard_resolver_failures_total{kind}`, each failure by its kind, one
//!   of `token`, `not_sent`, `timeout`, `unreachable`, `status`, `too_large`, `broken_off`,
//!   `malformed`, `unknown_version` and `other_question`; and
//!   `switchboard_resolver_question_seconds`, a histogram of how long each question took,
//!   failures included, with the audit store's buckets. Each answer and kind is written from
//!   zero.
//!
//! - With an issuer whose keys are fetched from a keys URL, from [`KeyAges`]:
//!   `switchboard_issuer_keys_age_seconds{issuer}`, the seconds since that issuer's keys were
//!   last fetched and put in force (see [`crate::keys`]). `issuer` is the issuer as the
//!   deployment file names it, so there is one series per configured issuer. An issuer with a
//!   keys file has none, and with no keys URL the family is not written.
//!
//! With audit disabled the audit signals are not written: there is no store to count.
//!
//! **Open rows.** A task polls [`PgAuditStore::open_rows`] every [`OPEN_ROWS_POLL`], the first
//! time as soon as the listener serves. The query has a connection of its own, apart from the
//! store's begin and finish pools, so a poll held up never delays a finish. It gives up 2 s
//! after asking for that connection. A failed poll counts in
//! `switchboard_audit_open_rows_poll_failures_total` and keeps the last value. Until a poll has
//! succeeded, `switchboard_audit_open_rows` has no sample; the oldest deadline has one only
//! while a row is open, as seconds since the Unix epoch. A scrape reads what the last poll
//! found and never waits on the database.
//!
//! **Receipts in `unknown`.** The same task then counts them with
//! [`PgAuditStore::unknown_receipts`], on the same connection of its own and with the same
//! 2 s: the receipts in the state `unknown`, and those still `pending` past their row's
//! deadline, which read as `unknown`, by the database's clock. The oldest is exported as the
//! time it was reserved, in seconds since the Unix epoch, while one is in `unknown`, so its age
//! is the time since. A count that fails is counted in
//! `switchboard_audit_unknown_receipts_poll_failures_total`, and nothing is exported in its
//! place: the two gauges have no sample until a count succeeds again, and none before the
//! first. A constant would say no receipt is unknown when none was counted.
//!
//! Shutting down closes the listener, waits for the scrapes being answered, and then stops the
//! poller (see [`serve_metrics`]). The binary shuts it down after the MCP listener has stopped
//! and the store's finishes are done.

use std::fmt::{Display, Write};
use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, UNIX_EPOCH};

use audit_postgres::{
    LATENCY_BOUNDS_MS, LATENCY_BUCKETS, LatencyHistogram, OpenRows, PgAuditStore, PoolStats,
    StoreStats, UnknownReceipts,
};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use gateway_core::{ConnectorName, CurrencyAnswer, Issuer};
use gateway_otto::resolver::ResolverCounts;
use gateway_otto::{HttpResolver, ResolverFailure};
use http::HeaderValue;
use http::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::bulkhead::{ProxiedSignals, ServerCounts};
use crate::drift::{DriftCounts, DriftSignals};
use crate::grants::{GrantCounts, GrantSignals};
use crate::keys::KeyAges;
use crate::reconcile::{ReconcileCounts, ReconcileSignals};
use crate::reload::Freshness;
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
    issuer_keys: KeyAges,
    policy: Option<Freshness>,
    proxied: ProxiedSignals,
    drift: Option<DriftSignals>,
    reconciliation: Option<ReconcileSignals>,
    grants: Option<GrantSignals>,
    resolver: Option<Arc<HttpResolver>>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("telemetry", &self.telemetry)
            .field("audit", &self.audit.is_some())
            .field("issuer_keys", &self.issuer_keys)
            .field("policy", &self.policy)
            .field("proxied", &self.proxied)
            .field("drift", &self.drift)
            .field("reconciliation", &self.reconciliation)
            .field("grants", &self.grants)
            .field("resolver", &self.resolver.is_some())
            .finish()
    }
}

struct AuditSource {
    store: Arc<PgAuditStore>,
    /// What the last poll that succeeded found, if one has.
    open: Mutex<Option<OpenRows>>,
    poll_failures: AtomicU64,
    /// What the last count of receipts in `unknown` found, if it succeeded.
    unknown: Mutex<Option<UnknownReceipts>>,
    unknown_failures: AtomicU64,
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
                    unknown: Mutex::new(None),
                    unknown_failures: AtomicU64::new(0),
                })
            }),
            issuer_keys: KeyAges::default(),
            policy: None,
            proxied: ProxiedSignals::default(),
            drift: None,
            reconciliation: None,
            grants: None,
            resolver: None,
        }
    }

    /// The same metrics, with what Otto's resolver client counts, which
    /// [`Gates::resolver`](crate::Gates::resolver) gives when one is configured.
    pub fn with_resolver(mut self, resolver: Arc<HttpResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The same metrics, with what the turn-grant gate counts, which
    /// [`Gates::grant_signals`](crate::Gates::grant_signals) gives.
    pub fn with_grants(mut self, grants: GrantSignals) -> Self {
        self.grants = Some(grants);
        self
    }

    /// The same metrics, with the drift pass's counts, which
    /// [`DriftPass::signals`](crate::drift::DriftPass::signals) gives.
    pub fn with_drift(mut self, drift: DriftSignals) -> Self {
        self.drift = Some(drift);
        self
    }

    /// The same metrics, with what reconciliation counts, which
    /// [`Reconciler::signals`](crate::reconcile::Reconciler::signals) gives. Written beside the
    /// audit signals.
    pub fn with_reconciliation(mut self, signals: ReconcileSignals) -> Self {
        self.reconciliation = Some(signals);
        self
    }

    /// The same metrics, with what each proxied server's bulkhead counts, which
    /// [`Prepared::proxied`](crate::start::Prepared::proxied) gives.
    pub fn with_proxied(mut self, proxied: ProxiedSignals) -> Self {
        self.proxied = proxied;
        self
    }

    /// The same metrics, with the age of each issuer's keys from `ages`, which
    /// [`KeyRefresher::ages`](crate::keys::KeyRefresher::ages) gives.
    pub fn with_issuer_keys(mut self, ages: KeyAges) -> Self {
        self.issuer_keys = ages;
        self
    }

    /// The same metrics, with the age of the policy from `freshness`, which
    /// [`Gates::freshness`](crate::Gates::freshness) gives.
    pub fn with_policy(mut self, freshness: Freshness) -> Self {
        self.policy = Some(freshness);
        self
    }

    /// Every signal as it stands, in Prometheus text. See the [module documentation](self).
    pub fn render(&self) -> String {
        let mut text = Text::default();
        let counts = self.telemetry.counts();
        telemetry_signals(&mut text, &counts);
        proxied_signals(&mut text, counts.calls_shed, &self.proxied.counts());
        if let Some(drift) = &self.drift {
            drift_signals(&mut text, &drift.counts(), drift.withdrawn());
        }
        if let Some(freshness) = &self.policy {
            policy_signals(&mut text, freshness);
        }
        issuer_key_signals(&mut text, &self.issuer_keys.ages());
        if let Some(grants) = &self.grants {
            grant_signals(&mut text, &grants.counts());
        }
        if let Some(resolver) = &self.resolver {
            resolver_signals(&mut text, &resolver.counts());
        }
        if let Some(audit) = &self.audit {
            let open = *audit.open.lock().unwrap_or_else(PoisonError::into_inner);
            let unknown = *audit.unknown.lock().unwrap_or_else(PoisonError::into_inner);
            audit_signals(
                &mut text,
                &AuditSignals {
                    stats: audit.store.stats(),
                    failure_answers: self.telemetry.counts().audit_failure_answers,
                    open,
                    poll_failures: audit.poll_failures.load(Ordering::Relaxed),
                    unknown,
                    unknown_failures: audit.unknown_failures.load(Ordering::Relaxed),
                },
            );
        }
        if let Some(reconciliation) = &self.reconciliation {
            reconciliation_signals(&mut text, &reconciliation.counts());
        }
        text.0
    }
}

/// Counts the open rows, and then the receipts in `unknown`, every [`OPEN_ROWS_POLL`], the
/// first time at once, for ever.
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
        let unknown = match audit.store.unknown_receipts().await {
            Ok(unknown) => Some(unknown),
            Err(error) => {
                audit.unknown_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    event = "unknown_receipts_poll_failed",
                    %error,
                    "could not count the receipts in unknown; the metrics show none until a \
                     count succeeds"
                );
                None
            }
        };
        *audit.unknown.lock().unwrap_or_else(PoisonError::into_inner) = unknown;
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
/// polls the open rows while it does. Then, in this order, it closes the listener, waits up to
/// 5 s for the scrapes still being answered, and stops the poller as it returns.
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
    unknown: Option<UnknownReceipts>,
    unknown_failures: u64,
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
        ("policy_stale", counts.policy_stale),
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

fn proxied_signals(text: &mut Text, instance_shed: u64, servers: &[(ConnectorName, ServerCounts)]) {
    text.family(
        "switchboard_calls_shed_total",
        "counter",
        "Calls refused by a cap on calls in flight, by scope. instance: answered 503 before the \
         body was read, with no row. server and team: completed as refused, not sent.",
    );
    let shed_server = servers
        .iter()
        .map(|(_, counts)| counts.shed_server)
        .sum::<u64>();
    let shed_team = servers
        .iter()
        .map(|(_, counts)| counts.shed_team)
        .sum::<u64>();
    for (scope, count) in [
        ("instance", instance_shed),
        ("server", shed_server),
        ("team", shed_team),
    ] {
        text.sample("switchboard_calls_shed_total", &[("scope", scope)], count);
    }
    if servers.is_empty() {
        return;
    }
    text.family(
        "switchboard_proxied_calls_total",
        "counter",
        "Calls each proxied server's connector completed, by outcome. A call a cap refused is \
         not sent and not counted here.",
    );
    for (server, counts) in servers {
        for (outcome, count) in [
            ("ok", counts.ok),
            ("error", counts.error),
            ("refused", counts.refused),
        ] {
            text.sample(
                "switchboard_proxied_calls_total",
                &[("server", server.as_str()), ("outcome", outcome)],
                count,
            );
        }
    }
    text.family(
        "switchboard_proxied_call_seconds",
        "histogram",
        "How long each call each proxied server's connector completed took.",
    );
    for (server, counts) in servers {
        text.histogram_samples(
            "switchboard_proxied_call_seconds",
            &[("server", server.as_str())],
            &counts.latency,
        );
    }
    text.family(
        "switchboard_proxied_late_or_oversized_total",
        "counter",
        "Calls to each proxied server whose read answer was too large or not in time.",
    );
    for (server, counts) in servers {
        text.sample(
            "switchboard_proxied_late_or_oversized_total",
            &[("server", server.as_str())],
            counts.late_or_oversized,
        );
    }
}

fn reconciliation_signals(text: &mut Text, counts: &ReconcileCounts) {
    text.family(
        "switchboard_reconciliation_lookups_total",
        "counter",
        "Lookups reconciliation made for unknown receipts, by result: found, \
         not_found_authoritative, not_found (a search that proves nothing) or failed.",
    );
    for (result, count) in [
        ("found", counts.found),
        ("not_found_authoritative", counts.not_found_authoritative),
        ("not_found", counts.not_found),
        ("failed", counts.failed),
    ] {
        text.sample(
            "switchboard_reconciliation_lookups_total",
            &[("result", result)],
            count,
        );
    }
    text.single(
        "switchboard_reconciliation_handed_to_person_total",
        "counter",
        "Unknown receipts handed to a person, with nothing to look in or their attempts used up. \
         Each stays unknown until a person settles it.",
        counts.handed_to_person,
    );
    text.single(
        "switchboard_reconciliation_store_failures_total",
        "counter",
        "Reads and writes of the queue of unknown receipts that failed. The next pass tries \
         again.",
        counts.store_failures,
    );
}

fn drift_signals(text: &mut Text, servers: &[(ConnectorName, DriftCounts)], withdrawn: u64) {
    text.family(
        "switchboard_drift_polls_total",
        "counter",
        "Reads of each proxied server's tool list by the drift pass, by result. A failed read \
         keeps the server's tools served.",
    );
    for (server, counts) in servers {
        for (result, count) in [("ok", counts.polls_ok), ("failed", counts.polls_failed)] {
            text.sample(
                "switchboard_drift_polls_total",
                &[("server", server.as_str()), ("result", result)],
                count,
            );
        }
    }
    text.family(
        "switchboard_drift_withdrawals_total",
        "counter",
        "Tools the drift pass withdrew from each proxied server, because the server no longer \
         served their approved definition or no longer listed them, or answered a call outside \
         its entry's reach.",
    );
    for (server, counts) in servers {
        text.sample(
            "switchboard_drift_withdrawals_total",
            &[("server", server.as_str())],
            counts.withdrawals,
        );
    }
    text.family(
        "switchboard_probe_results_total",
        "counter",
        "Probes of each proxied server by the drift pass, by result: refused, open (the server \
         dispatched a call it should have refused, so it can be reached around the gateway), or \
         not_shown.",
    );
    for (server, counts) in servers {
        for (result, count) in [
            ("refused", counts.probes_refused),
            ("open", counts.probes_open),
            ("not_shown", counts.probes_not_shown),
        ] {
            text.sample(
                "switchboard_probe_results_total",
                &[("server", server.as_str()), ("result", result)],
                count,
            );
        }
    }
    text.family(
        "switchboard_reach_checks_total",
        "counter",
        "Reach checks of each proxied server's entry, by result: held (the server refused the \
         call outside the entry's reach), mismatch (it answered, and the entry's tools were \
         withdrawn), or failed (the check showed nothing).",
    );
    for (server, counts) in servers {
        for (result, count) in [
            ("held", counts.reach_held),
            ("mismatch", counts.reach_mismatch),
            ("failed", counts.reach_failed),
        ] {
            text.sample(
                "switchboard_reach_checks_total",
                &[("server", server.as_str()), ("result", result)],
                count,
            );
        }
    }
    text.single(
        "switchboard_tools_withdrawn",
        "gauge",
        "Tools withdrawn now in this replica, until they are approved again or it restarts.",
        withdrawn,
    );
}

fn policy_signals(text: &mut Text, freshness: &Freshness) {
    text.single(
        "switchboard_policy_age_seconds",
        "gauge",
        "Seconds since the registry file was last read successfully, whether or not that \
         version loaded. Past the maximum age the policy is stale.",
        freshness.age().as_secs_f64(),
    );
    if let Some(max_age) = freshness.max_age() {
        text.single(
            "switchboard_policy_max_age_seconds",
            "gauge",
            "The policy's age past which /readyz fails and tools/call and tools/list are refused.",
            max_age.as_secs_f64(),
        );
    }
}

fn issuer_key_signals(text: &mut Text, ages: &[(Issuer, Duration)]) {
    if ages.is_empty() {
        return;
    }
    text.family(
        "switchboard_issuer_keys_age_seconds",
        "gauge",
        "Seconds since the issuer's keys were last fetched from its keys URL and put in force, \
         at boot or by a refresh. A refresh that fails leaves the keys in use, and this grows.",
    );
    for (issuer, age) in ages {
        text.sample(
            "switchboard_issuer_keys_age_seconds",
            &[("issuer", issuer.as_str())],
            age.as_secs_f64(),
        );
    }
}

fn grant_signals(text: &mut Text, counts: &GrantCounts) {
    text.family(
        "switchboard_grant_failures_total",
        "counter",
        "Turn grants refused, by the check they failed (decision 0012). Each wrong_audience or \
         wrong_pod is to be investigated; expired, not_yet_valid and lifetime are to alert on a \
         rate, and are not logged one by one.",
    );
    for (kind, count) in &counts.failures {
        text.sample(
            "switchboard_grant_failures_total",
            &[("kind", kind.as_str())],
            count,
        );
    }
    if counts.accepted.is_empty() {
        return;
    }
    text.family(
        "switchboard_grants_accepted_total",
        "counter",
        "Turn grants verified, by the ID of the key they verified under, which shows a key \
         rotation's progress.",
    );
    for (key_id, count) in &counts.accepted {
        text.sample(
            "switchboard_grants_accepted_total",
            &[("key_id", key_id.as_str())],
            count,
        );
    }
}

fn resolver_signals(text: &mut Text, counts: &ResolverCounts) {
    text.family(
        "switchboard_resolver_answers_total",
        "counter",
        "Questions to Otto's resolver about a turn's currency, by answer (decision 0012). Every \
         failure is unconfirmed, and denies the call it was asked for.",
    );
    for answer in CurrencyAnswer::ALL {
        text.sample(
            "switchboard_resolver_answers_total",
            &[("answer", answer.as_str())],
            counts.answered(answer),
        );
    }
    text.family(
        "switchboard_resolver_failures_total",
        "counter",
        "Questions to Otto's resolver that had no answer, by why: each is unconfirmed.",
    );
    for kind in ResolverFailure::LABELS {
        text.sample(
            "switchboard_resolver_failures_total",
            &[("kind", kind)],
            counts.failed(kind),
        );
    }
    text.histogram(
        "switchboard_resolver_question_seconds",
        "How long each question to Otto's resolver took, failures included; none takes much \
         longer than its budget of one second.",
        &LatencyHistogram {
            buckets: counts.latency_buckets,
            count: counts.latency_count,
            sum: counts.latency_sum,
        },
    );
}

fn audit_signals(text: &mut Text, signals: &AuditSignals) {
    let stats = &signals.stats;
    let failures = &stats.begin_failures;
    text.family(
        "switchboard_audit_begin_failures_total",
        "counter",
        "Audit begins that failed, by cause. budget_exceeded: the begin budget ran out with a \
         connection in hand. pool_timeout: no connection was obtained in time, whether waiting \
         for a pool permit or opening a new connection; a database that never answers, a \
         reconnect that runs past the budget and a pool too small for the load all count here, \
         and this count does not tell them apart. database_error: connecting failed with an \
         error, such as a refused connection, or the database refused or failed the statement. \
         value_refused: a value could not be put in its column.",
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
    text.family(
        "switchboard_audit_unknown_receipts",
        "gauge",
        "Receipts in unknown: in the state unknown, or pending past their row's deadline, as \
         the last count that succeeded found them.",
    );
    if let Some(unknown) = &signals.unknown {
        text.sample("switchboard_audit_unknown_receipts", &[], unknown.count);
    }
    text.family(
        "switchboard_audit_oldest_unknown_receipt_reserved_seconds",
        "gauge",
        "When the oldest receipt in unknown was reserved, in seconds since the Unix epoch, \
         while one is; its age is the time since.",
    );
    if let Some(reserved) = signals.unknown.and_then(|unknown| unknown.oldest_reserved) {
        let seconds = reserved
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        text.sample(
            "switchboard_audit_oldest_unknown_receipt_reserved_seconds",
            &[],
            seconds,
        );
    }
    text.single(
        "switchboard_audit_unknown_receipts_poll_failures_total",
        "counter",
        "Counts of the receipts in unknown that failed; the two gauges have no sample until \
         one succeeds.",
        signals.unknown_failures,
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
        text.sample(name, &[("pool", "open_rows")], of(&stats.open_rows_pool));
    }
}

/// Prometheus text, written as it goes. Every name and label name here is a constant of this
/// module. Label values are escaped as the format requires, since an issuer's comes from the
/// deployment file.
#[derive(Default)]
struct Text(String);

/// A label value as Prometheus text writes it: backslash, double quote and newline escaped.
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

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
                .map(|(label, value)| format!("{label}=\"{}\"", escape_label(value)))
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
    /// `_count`. `+Inf` and `_count` are both the last cumulative bucket, so one scrape never
    /// shows `+Inf` below a bound's bucket, even from a snapshot taken while a latency was being
    /// counted.
    fn histogram(&mut self, name: &str, help: &str, histogram: &LatencyHistogram) {
        self.family(name, "histogram", help);
        self.histogram_samples(name, &[], histogram);
    }

    /// One histogram's samples, each with `labels` before its `le`.
    fn histogram_samples(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        histogram: &LatencyHistogram,
    ) {
        let bucket = format!("{name}_bucket");
        let cumulative = histogram.cumulative();
        let total = cumulative[LATENCY_BUCKETS - 1];
        let bounds = LATENCY_BOUNDS_MS
            .iter()
            .map(|bound| Duration::from_millis(*bound).as_secs_f64().to_string())
            .zip(cumulative)
            .chain(std::iter::once(("+Inf".to_owned(), total)));
        for (le, count) in bounds {
            let mut with_le = labels.to_vec();
            with_le.push(("le", &le));
            self.sample(&bucket, &with_le, count);
        }
        self.sample(&format!("{name}_sum"), labels, histogram.sum.as_secs_f64());
        self.sample(&format!("{name}_count"), labels, total);
    }
}

#[cfg(test)]
mod tests {
    use audit_postgres::BeginFailures;

    use super::*;

    fn rendered(signals: &AuditSignals) -> String {
        let mut text = Text::default();
        audit_signals(&mut text, signals);
        text.0
    }

    fn lines(text: &str) -> Vec<&str> {
        text.lines().filter(|line| !line.starts_with('#')).collect()
    }

    /// The resolver client buckets its latencies by bounds of its own, which the metrics write
    /// as the audit store's: they must be the same bounds.
    #[test]
    fn the_resolvers_latency_bounds_are_the_audit_stores() {
        assert_eq!(gateway_otto::resolver::LATENCY_BOUNDS_MS, LATENCY_BOUNDS_MS);
        assert_eq!(gateway_otto::resolver::LATENCY_BUCKETS, LATENCY_BUCKETS);
    }

    /// The resolver's counts are written with every answer and kind of failure from zero, and
    /// its latencies as a histogram.
    #[test]
    fn the_resolvers_counts_are_written() {
        let mut latency_buckets = [0; LATENCY_BUCKETS];
        latency_buckets[1] = 2;
        latency_buckets[7] = 1;
        let counts = ResolverCounts {
            answers: [2, 0, 0, 0, 1],
            failures: [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            latency_buckets,
            latency_count: 3,
            latency_sum: Duration::from_millis(1_016),
        };
        let mut text = Text::default();
        resolver_signals(&mut text, &counts);
        let lines = lines(&text.0);
        for expected in [
            "switchboard_resolver_answers_total{answer=\"current\"} 2",
            "switchboard_resolver_answers_total{answer=\"revoked\"} 0",
            "switchboard_resolver_answers_total{answer=\"unconfirmed\"} 1",
            "switchboard_resolver_failures_total{kind=\"timeout\"} 1",
            "switchboard_resolver_failures_total{kind=\"other_question\"} 0",
            "switchboard_resolver_question_seconds_bucket{le=\"0.01\"} 2",
            "switchboard_resolver_question_seconds_bucket{le=\"1\"} 3",
            "switchboard_resolver_question_seconds_bucket{le=\"+Inf\"} 3",
            "switchboard_resolver_question_seconds_sum 1.016",
            "switchboard_resolver_question_seconds_count 3",
        ] {
            assert!(lines.contains(&expected), "{expected} not in {lines:#?}");
        }
        assert!(
            text.0
                .contains("# TYPE switchboard_resolver_question_seconds histogram\n")
        );
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

    /// A snapshot is read one atomic at a time, so one taken while a latency is being counted
    /// can hold a count other than its buckets' total. `+Inf` and `_count` are that total all
    /// the same: a scrape never shows `+Inf` below `le="30"`, nor a `_count` that disagrees.
    #[test]
    fn inf_and_the_count_are_the_buckets_total_whatever_count_was_read() {
        let mut buckets = [0; LATENCY_BUCKETS];
        buckets[0] = 1;
        buckets[LATENCY_BUCKETS - 2] = 2;
        for count in [2, 3, 4] {
            let mut text = Text::default();
            text.histogram(
                "h_seconds",
                "A histogram.",
                &LatencyHistogram {
                    buckets,
                    count,
                    sum: Duration::from_millis(30_005),
                },
            );
            let samples = lines(&text.0);
            for expected in [
                "h_seconds_bucket{le=\"30\"} 3",
                "h_seconds_bucket{le=\"+Inf\"} 3",
                "h_seconds_count 3",
            ] {
                assert!(
                    samples.contains(&expected),
                    "{count}: {expected}\n{}",
                    text.0
                );
            }
        }
    }

    #[test]
    fn an_issuer_label_is_escaped_and_with_no_fetched_issuer_nothing_is_written() {
        let mut text = Text::default();
        issuer_key_signals(
            &mut text,
            &[(
                Issuer::new("https://a.test/\"quoted\"\\path\nnext"),
                Duration::from_millis(1500),
            )],
        );
        assert_eq!(
            lines(&text.0),
            [
                "switchboard_issuer_keys_age_seconds{issuer=\"https://a.test/\\\"quoted\\\"\\\\path\\nnext\"} 1.5"
            ]
        );
        let mut none = Text::default();
        issuer_key_signals(&mut none, &[]);
        assert_eq!(none.0, "");
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
            open_rows_pool: PoolStats {
                in_use: 17,
                size: 18,
                max_size: 19,
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
            unknown: Some(UnknownReceipts {
                count: 20,
                oldest_reserved: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            }),
            unknown_failures: 21,
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
            "switchboard_audit_pool_connections_in_use{pool=\"open_rows\"} 17",
            "switchboard_audit_pool_connections_open{pool=\"open_rows\"} 18",
            "switchboard_audit_pool_connections_max{pool=\"open_rows\"} 19",
            "switchboard_audit_failure_answers_total 14",
            "switchboard_audit_open_rows 15",
            "switchboard_audit_oldest_open_row_deadline_seconds 1800000000",
            "switchboard_audit_open_rows_poll_failures_total 16",
            "switchboard_audit_unknown_receipts 20",
            "switchboard_audit_oldest_unknown_receipt_reserved_seconds 1700000000",
            "switchboard_audit_unknown_receipts_poll_failures_total 21",
        ] {
            assert!(samples.contains(&expected), "{expected}\n{text}");
        }
    }

    /// The receipts in `unknown` have no sample before a count succeeds, nor after one fails:
    /// nothing stands in for a count not made. With none in `unknown`, the count is 0 and the
    /// oldest has no sample.
    #[test]
    fn the_unknown_receipt_gauges_have_no_sample_when_they_could_not_be_counted() {
        let signals = |unknown| AuditSignals {
            stats: StoreStats::default(),
            failure_answers: 0,
            open: None,
            poll_failures: 0,
            unknown,
            unknown_failures: 1,
        };
        let uncounted = rendered(&signals(None));
        assert!(
            uncounted.contains("# TYPE switchboard_audit_unknown_receipts gauge\n"),
            "{uncounted}"
        );
        assert!(
            !lines(&uncounted).iter().any(|line| {
                line.starts_with("switchboard_audit_unknown_receipts ")
                    || line.starts_with("switchboard_audit_oldest_unknown_receipt")
            }),
            "{uncounted}"
        );
        assert!(
            lines(&uncounted).contains(&"switchboard_audit_unknown_receipts_poll_failures_total 1")
        );
        let none = rendered(&signals(Some(UnknownReceipts {
            count: 0,
            oldest_reserved: None,
        })));
        assert!(lines(&none).contains(&"switchboard_audit_unknown_receipts 0"));
        assert!(
            !lines(&none)
                .iter()
                .any(|line| line.starts_with("switchboard_audit_oldest_unknown_receipt")),
            "{none}"
        );
    }

    #[test]
    fn before_a_poll_succeeds_and_with_no_row_open_the_open_row_gauges_have_no_sample() {
        let none = rendered(&AuditSignals {
            stats: StoreStats::default(),
            failure_answers: 0,
            open: None,
            poll_failures: 1,
            unknown: None,
            unknown_failures: 0,
        });
        let closed = rendered(&AuditSignals {
            stats: StoreStats::default(),
            failure_answers: 0,
            open: Some(OpenRows {
                count: 0,
                oldest_deadline: None,
            }),
            poll_failures: 0,
            unknown: None,
            unknown_failures: 0,
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

    /// Reconciliation's signals: each lookup by its result, the receipts handed to a person and
    /// the store's failures, each a counter with a sample from the start.
    #[test]
    fn the_reconciliation_signals_count_lookups_by_result_and_hand_offs() {
        let mut text = Text::default();
        reconciliation_signals(
            &mut text,
            &ReconcileCounts {
                found: 1,
                not_found_authoritative: 2,
                not_found: 3,
                failed: 4,
                handed_to_person: 5,
                store_failures: 6,
            },
        );
        let text = text.0;
        for family in [
            "switchboard_reconciliation_lookups_total",
            "switchboard_reconciliation_handed_to_person_total",
            "switchboard_reconciliation_store_failures_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} counter\n")),
                "{text}"
            );
        }
        assert_eq!(
            lines(&text),
            [
                "switchboard_reconciliation_lookups_total{result=\"found\"} 1",
                "switchboard_reconciliation_lookups_total{result=\"not_found_authoritative\"} 2",
                "switchboard_reconciliation_lookups_total{result=\"not_found\"} 3",
                "switchboard_reconciliation_lookups_total{result=\"failed\"} 4",
                "switchboard_reconciliation_handed_to_person_total 5",
                "switchboard_reconciliation_store_failures_total 6",
            ]
        );
        let metrics = Metrics::new(Telemetry::bounded(1).0, None);
        assert!(
            !metrics.render().contains("switchboard_reconciliation"),
            "with no reconciler nothing is written"
        );
        let zero = metrics
            .with_reconciliation(ReconcileSignals::default())
            .render();
        assert!(
            lines(&zero).contains(&"switchboard_reconciliation_handed_to_person_total 0"),
            "{zero}"
        );
    }
}
