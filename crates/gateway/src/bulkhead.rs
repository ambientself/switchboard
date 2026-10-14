//! The caps on calls in flight to each proxied server, from each team and in all, and the
//! signals counted for each server (decision 0014, sections 2 and 9).
//!
//! A [`Bulkhead`] wraps one proxied server's connector. [`start`](crate::start) builds one per
//! server and registers it in the connector's place, so it sits inside the registry's check of
//! the arguments against the approved schema: a call whose arguments fail the check never
//! reaches it and takes no slot. Each call that reaches it takes, without waiting, a slot from the caller's team's
//! cap on calls to the server, when the caller has a proved team, and then a slot from the
//! server's own cap. The slots are held until the server's connector returns, or until the
//! call is dropped, as a read is when its client goes; the connector's deadline bounds how
//! long that can be. A caller with no team, such as a user, is held by the server's cap alone
//! until a per-user limit is decided (decision 0014, Still open).
//!
//! A call over either cap is not sent. It is outcome `refused`, with a fixed capacity sentence
//! naming the scope, the server and the tool, which the row records: [`server_at_capacity`] or
//! [`team_at_capacity`]. There is no queue and no circuit breaker. So a server that hangs holds
//! at most the server's cap in each instance, one team holds at most the team's cap of those,
//! and calls to other servers, or from other teams, are not held up.
//!
//! The caps are taken after the call's row was begun, inside the audited run, so every allowed
//! decision keeps its row. The instance's own cap, on requests in flight, is the HTTP server's:
//! it refuses before a body is read, with no row ([`crate::server`]).
//!
//! Each bulkhead counts, in [`ServerSignals`]: the calls its server's connector ran, by
//! outcome; how long each took; those that were late or too large, by their error kind; and
//! the calls each cap refused. A call dropped before its connector returned is counted in none
//! of the first three. [`crate::metrics`] exports them, labelled by the server's name in the
//! registry and nothing a caller chooses.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use audit_postgres::{LATENCY_BOUNDS_MS, LATENCY_BUCKETS, LatencyHistogram};
use gateway_core::{BoxFuture, Connector, ConnectorName, ErrorKind, TeamId, ToolCall, ToolOutcome};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The sentence for a call refused because its server has as many calls in flight from this
/// gateway instance as the server's cap allows. Nothing was sent.
pub fn server_at_capacity(server: &str, tool: &str) -> String {
    format!(
        "Server `{server}` already has as many calls in flight from this gateway as it allows, \
         so this call to tool `{tool}` was not sent. Try it again shortly."
    )
}

/// The sentence for a call refused because the caller's team has as many calls in flight to
/// its server from this gateway instance as the team's cap allows. Nothing was sent.
pub fn team_at_capacity(server: &str, tool: &str) -> String {
    format!(
        "Your team already has as many calls in flight to server `{server}` from this gateway as \
         it allows, so this call to tool `{tool}` was not sent. Try it again shortly."
    )
}

/// One proxied server's connector, behind the server's cap and each team's cap on calls in
/// flight. See the [module documentation](self).
pub struct Bulkhead {
    server: ConnectorName,
    inner: Arc<dyn Connector>,
    per_server: Arc<Semaphore>,
    per_team: usize,
    /// One cap per team that has called the server. Teams come from the team manifests, so
    /// the map is as large as they are at most, and nothing is removed from it.
    teams: Mutex<BTreeMap<TeamId, Arc<Semaphore>>>,
    signals: Arc<ServerSignals>,
}

impl std::fmt::Debug for Bulkhead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bulkhead")
            .field("server", &self.server)
            .field("per_server", &self.per_server.available_permits())
            .field("per_team", &self.per_team)
            .finish_non_exhaustive()
    }
}

impl Bulkhead {
    /// `inner`, the connector of the server `server`, with at most `per_server` calls in flight
    /// to it, and at most `per_team` from each team. A cap of zero is taken as one.
    pub fn new(
        server: ConnectorName,
        inner: Arc<dyn Connector>,
        per_server: usize,
        per_team: usize,
    ) -> Self {
        Self {
            server,
            inner,
            per_server: Arc::new(semaphore(per_server)),
            per_team,
            teams: Mutex::new(BTreeMap::new()),
            signals: Arc::default(),
        }
    }

    /// What this bulkhead counts, as it counts it.
    pub fn signals(&self) -> Arc<ServerSignals> {
        self.signals.clone()
    }

    /// `team`'s cap on calls to this server, made the first time the team calls it.
    fn team(&self, team: &TeamId) -> Arc<Semaphore> {
        let mut teams = self.teams.lock().unwrap_or_else(PoisonError::into_inner);
        teams
            .entry(team.clone())
            .or_insert_with(|| Arc::new(semaphore(self.per_team)))
            .clone()
    }

    /// A call refused by the cap of `scope`, counted and logged. Nothing is sent.
    fn shed(&self, scope: Scope, tool: &str) -> BoxFuture<'_, ToolOutcome> {
        let (counter, sentence) = match scope {
            Scope::Server => (
                &self.signals.shed_server,
                server_at_capacity(self.server.as_str(), tool),
            ),
            Scope::Team => (
                &self.signals.shed_team,
                team_at_capacity(self.server.as_str(), tool),
            ),
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            event = "call_shed",
            scope = scope.name(),
            server = self.server.as_str(),
            tool,
            "refused a call: it is over a cap on calls in flight, and it was not sent"
        );
        Box::pin(std::future::ready(ToolOutcome::Refused(sentence)))
    }
}

/// A semaphore with `permits`, at least one and at most what a semaphore can hold.
fn semaphore(permits: usize) -> Semaphore {
    Semaphore::new(permits.clamp(1, Semaphore::MAX_PERMITS))
}

/// Which cap refused a call.
#[derive(Clone, Copy, Debug)]
enum Scope {
    Server,
    Team,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Team => "team",
        }
    }
}

impl Connector for Bulkhead {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let tool = call.tool().name.clone();
        let team: Option<OwnedSemaphorePermit> = match call.call().caller.principal.get().team() {
            None => None,
            Some(team) => match self.team(team).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => return self.shed(Scope::Team, tool.as_str()),
            },
        };
        let Ok(server) = self.per_server.clone().try_acquire_owned() else {
            return self.shed(Scope::Server, tool.as_str());
        };
        Box::pin(async move {
            // Held until the server's connector returns, or until this future is dropped.
            let _slots = (server, team);
            let started = Instant::now();
            let outcome = self.inner.run(call).await;
            self.signals.record(&outcome, started.elapsed());
            outcome
        })
    }
}

/// What one bulkhead counts. Every count is an atomic, so nothing on a call's path waits to
/// count it.
#[derive(Debug, Default)]
pub struct ServerSignals {
    ok: AtomicU64,
    error: AtomicU64,
    refused: AtomicU64,
    late_or_oversized: AtomicU64,
    shed_server: AtomicU64,
    shed_team: AtomicU64,
    latency: [AtomicU64; LATENCY_BUCKETS],
    latency_count: AtomicU64,
    /// The sum of every latency, in nanoseconds.
    latency_sum_nanos: AtomicU64,
}

impl ServerSignals {
    fn record(&self, outcome: &ToolOutcome, latency: Duration) {
        let counter = match outcome {
            ToolOutcome::Ok(_) | ToolOutcome::Completed(..) => &self.ok,
            ToolOutcome::Error(kind, _) => {
                if *kind == ErrorKind::OversizedOrLateRead {
                    self.late_or_oversized.fetch_add(1, Ordering::Relaxed);
                }
                &self.error
            }
            ToolOutcome::Refused(_) => &self.refused,
            // Only a side effect reports it, and the registry's rule 2 approves no proxied tool
            // that is not a read yet.
            ToolOutcome::Unknown => &self.error,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let nanos = latency.as_nanos();
        let bucket = LATENCY_BOUNDS_MS
            .iter()
            .position(|bound| nanos <= u128::from(*bound) * 1_000_000)
            .unwrap_or(LATENCY_BOUNDS_MS.len());
        self.latency[bucket].fetch_add(1, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_nanos
            .fetch_add(u64::try_from(nanos).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// The counts as they stand. Each is read on its own.
    pub fn counts(&self) -> ServerCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ServerCounts {
            ok: read(&self.ok),
            error: read(&self.error),
            refused: read(&self.refused),
            late_or_oversized: read(&self.late_or_oversized),
            shed_server: read(&self.shed_server),
            shed_team: read(&self.shed_team),
            latency: LatencyHistogram {
                buckets: std::array::from_fn(|i| read(&self.latency[i])),
                count: read(&self.latency_count),
                sum: Duration::from_nanos(read(&self.latency_sum_nanos)),
            },
        }
    }
}

/// A snapshot of one bulkhead's counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerCounts {
    /// Calls the server's connector completed as `ok`.
    pub ok: u64,
    /// Calls it completed as `error`, late or too large ones included, and as `unknown`.
    pub error: u64,
    /// Calls it refused, such as one for a tool it does not serve.
    pub refused: u64,
    /// Calls that were an error of the kind `oversized_or_late_read`: a `read` tool's answer
    /// too large, or none by the deadline. Another tool's is reported as the outcome
    /// `unknown`, counted under `error` and not here.
    pub late_or_oversized: u64,
    /// Calls the server's cap refused.
    pub shed_server: u64,
    /// Calls a team's cap refused.
    pub shed_team: u64,
    /// How long each call the server's connector completed took.
    pub latency: LatencyHistogram,
}

/// The signals of every proxied server's bulkhead, by server. Cheap to clone; clones share
/// the counts.
#[derive(Clone, Debug, Default)]
pub struct ProxiedSignals(Arc<BTreeMap<ConnectorName, Arc<ServerSignals>>>);

impl ProxiedSignals {
    /// The signals of each server in `servers`.
    pub fn new(servers: BTreeMap<ConnectorName, Arc<ServerSignals>>) -> Self {
        Self(Arc::new(servers))
    }

    /// Each server's counts as they stand, in the order of its name.
    pub fn counts(&self) -> Vec<(ConnectorName, ServerCounts)> {
        self.0
            .iter()
            .map(|(server, signals)| (server.clone(), signals.counts()))
            .collect()
    }
}
