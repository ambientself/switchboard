//! The drift pass and the withdrawals it makes (decision 0013, sections 5 to 7; design section
//! 13).
//!
//! **The pass.** For each proxied server in the registry, [`DriftPass::pass`] reads the
//! server's `tools/list` with the gateway's own credential for it, under the server's call
//! deadline and answer cap ([`ProxyConnector::list_tools`]). For each tool approved on that
//! server it hashes the served definition (upstream name, title, description and input schema)
//! with [`definition_sha256`], the function the loader checks approvals with, and compares it
//! with the approval's `definition_sha256`. A tool whose hash differs, or that the server no
//! longer lists, is withdrawn. A tool the server lists that no approval names is ignored.
//!
//! **A poll is judged against the approvals it began under.** Each poll notes the key
//! ([`WithdrawalKey`]) of every tool approved on its server when it starts. When it ends, a
//! tool whose key has changed since, because a reload approved it again or removed it while the
//! poll was outstanding, is not judged by that poll: the list it read may predate the new
//! approval, and would withdraw it under a key it never compared. The next poll judges it.
//!
//! **A failed poll is not drift.** A server that cannot be reached, answers with a status other
//! than 200, answers with something that is not a tool list, answers after its call deadline,
//! answers with more than its answer cap, or answers with a list that goes on in another page,
//! keeps its tools served. The failure is logged as [`POLL_FAILED_EVENT`] at WARN, naming the
//! server and the reason, and counted in `switchboard_drift_polls_total{result="failed"}`. A
//! paginated list is a failure rather than a list read in part: the tools on later pages would
//! look removed, and a server's tools fit on one page in every case the gateway serves.
//!
//! **When it runs.** The first pass runs during boot, in
//! [`start::prepare`](crate::start::prepare), after the registry loads and before the listener
//! is bound, so a tool it withdraws is never served and nothing, `/readyz` included, is
//! answered until it ends. That first pass polls the servers together and ends when every poll
//! has answered or failed. A failed first poll does not stop boot. [`DriftPass::run`] then
//! polls each server every interval on a schedule of its own, one poll at a time, beside the
//! registry reloader, until the binary aborts it at shutdown. A server that answers slowly, or
//! not at all until its call deadline, delays only its own next poll, whatever the other
//! servers do. When the interval is at least a server's call deadline, as at the defaults and
//! in the demos, a changed definition on it is withdrawn within one interval plus that
//! deadline. When the interval is shorter, a list that answers late but inside the deadline
//! holds back the server's next poll until it arrives, so the worst case is about two call
//! deadlines (#165). The interval is `[drift] interval_seconds` in the deployment file
//! ([`DriftSection`]): 300 s unless given, and refused below 5 or above 900.
//!
//! **A withdrawal** ([`Withdrawals`]) makes a policy of its own: the loaded registry's, with
//! the withdrawn tools removed from the snapshot, every surface, the definitions and the
//! argument adapters ([`ServedPolicy`]'s `without`). Its revision is [`withdrawn_revision`]:
//! `{base}+withdrawn:{names}`, the withdrawn tools' exposed names sorted by byte and joined by
//! commas, so a row decided under it says exactly what was in force. It replaces the policy
//! served atomically, and the loader's rules are not run again. Each withdrawal is logged as
//! [`TOOL_WITHDRAWN_EVENT`] at ERROR, naming the tool, its server, the cause and the base and
//! derived revisions, and counted.
//!
//! **A standing withdrawal** is keyed by the tool's exposed name, `definition_sha256`,
//! `binding_sha256` and `approved_at` ([`WithdrawalKey`]). When the registry reloader serves a
//! new version, every standing withdrawal whose key is unchanged is applied to it, and the
//! derived revision names the new base. One whose tool was approved again (a new `approved_at`)
//! or removed is dropped, and logged as [`WITHDRAWAL_CLEARED_EVENT`] at INFO. Withdrawals live
//! in this replica's memory until then, or until it restarts (section 7): a restarted replica
//! withdraws a tool again only if its server still serves the changed definition. Each replica
//! checks for itself; nothing is passed between them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use connector_proxy::{ListError, ListedTool, ProxyConnector};
use gateway_core::{ConnectorName, PolicyRevision, ToolName};
use gateway_registry::{Registry, definition_sha256};
use serde::Deserialize;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::policy::{LivePolicy, ServedPolicy};

/// How often the drift pass runs when the deployment file does not say.
pub const DEFAULT_DRIFT_INTERVAL: Duration = Duration::from_secs(300);

/// The shortest interval the deployment file may set.
pub const MIN_DRIFT_INTERVAL: Duration = Duration::from_secs(5);

/// The longest interval the deployment file may set.
pub const MAX_DRIFT_INTERVAL: Duration = Duration::from_secs(900);

/// The `event` field of the error logged for each tool withdrawn.
pub const TOOL_WITHDRAWN_EVENT: &str = "tool_withdrawn";

/// The `event` field of the warning logged for each poll that failed.
pub const POLL_FAILED_EVENT: &str = "drift_poll_failed";

/// The `event` field of the line logged for each standing withdrawal a reload drops.
pub const WITHDRAWAL_CLEARED_EVENT: &str = "policy_withdrawal_cleared";

/// The deployment file's `[drift]` table. Optional, as is its one field.
///
/// ```toml
/// [drift]
/// interval_seconds = 300      # 300 if left out; 5 to 900
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftSection {
    /// How often, in seconds, each proxied server's tool list is read: 5 to 900, and
    /// [`DEFAULT_DRIFT_INTERVAL`] if left out.
    #[serde(default)]
    pub interval_seconds: Option<u64>,
}

/// Why the `[drift]` table was refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DriftError {
    /// The interval is outside 5 to 900 seconds.
    #[error(
        "`drift.interval_seconds` is {seconds}; it must be from {min} to {max}",
        min = MIN_DRIFT_INTERVAL.as_secs(),
        max = MAX_DRIFT_INTERVAL.as_secs()
    )]
    IntervalOutOfRange {
        /// The interval given, in seconds.
        seconds: u64,
    },
}

impl DriftSection {
    /// The interval `section` sets, [`DEFAULT_DRIFT_INTERVAL`] with no table or no field, or
    /// refused outside 5 to 900 seconds.
    pub fn interval(section: Option<&Self>) -> Result<Duration, DriftError> {
        let Some(seconds) = section.and_then(|section| section.interval_seconds) else {
            return Ok(DEFAULT_DRIFT_INTERVAL);
        };
        if seconds < MIN_DRIFT_INTERVAL.as_secs() || seconds > MAX_DRIFT_INTERVAL.as_secs() {
            return Err(DriftError::IntervalOutOfRange { seconds });
        }
        Ok(Duration::from_secs(seconds))
    }
}

/// What a standing withdrawal is keyed by: while the registry approves the tool under the same
/// key, the withdrawal stands (decision 0013, section 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalKey {
    /// The tool's exposed name.
    pub tool: ToolName,
    /// The approved definition's hash.
    pub definition_sha256: String,
    /// The approved binding's hash.
    pub binding_sha256: String,
    /// When it was approved.
    pub approved_at: String,
}

/// Why a tool was withdrawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The server serves a definition whose hash is not the approved one.
    DefinitionChanged,
    /// The server no longer lists the tool.
    NoLongerListed,
}

impl Cause {
    /// As the log line gives it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefinitionChanged => "definition changed",
            Self::NoLongerListed => "no longer listed",
        }
    }
}

/// The revision of `base` with `withdrawn` removed: `{base}+withdrawn:{names}`, the names
/// sorted by byte and joined by commas (decision 0013, section 6). The loader refuses a
/// registry revision containing `+`, so only a withdrawal makes one, and the first `+` ends
/// the base.
pub fn withdrawn_revision(base: &PolicyRevision, withdrawn: &BTreeSet<ToolName>) -> PolicyRevision {
    let names: Vec<&str> = withdrawn.iter().map(ToolName::as_str).collect();
    PolicyRevision::new(format!("{base}+withdrawn:{}", names.join(",")))
}

/// What one proxied server's polls and withdrawals came to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriftCounts {
    /// Polls that read the server's tool list.
    pub polls_ok: u64,
    /// Polls that failed.
    pub polls_failed: u64,
    /// Tools withdrawn.
    pub withdrawals: u64,
}

/// The drift pass's counts, for the metrics. Cheap to clone; clones share the counts.
#[derive(Clone, Debug, Default)]
pub struct DriftSignals(Arc<SignalsInner>);

#[derive(Debug, Default)]
struct SignalsInner {
    servers: Mutex<BTreeMap<ConnectorName, DriftCounts>>,
    withdrawn: AtomicU64,
}

impl DriftSignals {
    /// Signals with a zero count for each of `servers`, so each has a series from the start.
    fn for_servers<'a>(servers: impl IntoIterator<Item = &'a ConnectorName>) -> Self {
        let signals = Self::default();
        {
            let mut counts = signals.counts_mut();
            for server in servers {
                counts.insert(server.clone(), DriftCounts::default());
            }
        }
        signals
    }

    fn counts_mut(&self) -> std::sync::MutexGuard<'_, BTreeMap<ConnectorName, DriftCounts>> {
        self.0
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self, server: &ConnectorName, add: impl FnOnce(&mut DriftCounts)) {
        add(self.counts_mut().entry(server.clone()).or_default());
    }

    /// Each server's counts, by name.
    pub fn counts(&self) -> Vec<(ConnectorName, DriftCounts)> {
        self.counts_mut()
            .iter()
            .map(|(server, counts)| (server.clone(), *counts))
            .collect()
    }

    /// How many tools are withdrawn now.
    pub fn withdrawn(&self) -> u64 {
        self.0.withdrawn.load(Ordering::Relaxed)
    }
}

/// The standing withdrawals of one replica, over the policy the registry reloader loads.
///
/// It holds the loaded registry's policy (the base) and serves it, less every standing
/// withdrawal, in the [`LivePolicy`]. The reloader hands it each new version it loads, and
/// the drift pass each tool list it reads.
pub struct Withdrawals {
    live: Arc<LivePolicy>,
    state: Mutex<State>,
    signals: DriftSignals,
}

impl std::fmt::Debug for Withdrawals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Withdrawals")
            .field("standing", &self.standing())
            .finish_non_exhaustive()
    }
}

struct State {
    /// The loaded registry's policy.
    base: Arc<ServedPolicy>,
    /// Each tool the loaded registry approves, where it is served and under what key.
    approved: BTreeMap<ToolName, Approved>,
    /// The tools withdrawn now.
    standing: BTreeMap<ToolName, Standing>,
}

#[derive(Clone, Debug)]
struct Approved {
    server: ConnectorName,
    upstream_name: String,
    key: WithdrawalKey,
}

#[derive(Clone, Debug)]
struct Standing {
    key: WithdrawalKey,
    server: ConnectorName,
}

/// Each tool `registry` approves, with its server, its upstream name and its key.
fn approved(registry: &Registry) -> BTreeMap<ToolName, Approved> {
    registry
        .approvals()
        .iter()
        .filter_map(|(tool, approval)| {
            let route = registry.routes().get(tool)?;
            Some((
                tool.clone(),
                Approved {
                    server: route.server.clone(),
                    upstream_name: route.upstream_name.clone(),
                    key: WithdrawalKey {
                        tool: tool.clone(),
                        definition_sha256: approval.definition_sha256.clone(),
                        binding_sha256: approval.binding_sha256.clone(),
                        approved_at: approval.approved_at.clone(),
                    },
                },
            ))
        })
        .collect()
}

/// The hash of `tool`'s definition as served, or `None` when it has no description or no input
/// schema, which no approval lacks.
fn served_sha256(tool: &ListedTool) -> Option<String> {
    Some(definition_sha256(
        &tool.name,
        tool.title.as_deref(),
        tool.description.as_deref()?,
        tool.input_schema.as_ref()?,
    ))
}

impl Withdrawals {
    /// No withdrawals yet, over `registry`, whose policy `live` serves now.
    pub(crate) fn new(live: Arc<LivePolicy>, registry: &Registry) -> Self {
        let signals = DriftSignals::for_servers(registry.servers().keys());
        Self {
            state: Mutex::new(State {
                base: live.current(),
                approved: approved(registry),
                standing: BTreeMap::new(),
            }),
            live,
            signals,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The loaded registry's policy, before any withdrawal.
    pub fn base(&self) -> Arc<ServedPolicy> {
        self.state().base.clone()
    }

    /// The tools withdrawn now.
    pub fn standing(&self) -> BTreeSet<ToolName> {
        self.state().standing.keys().cloned().collect()
    }

    /// The counts, for the metrics.
    pub fn signals(&self) -> DriftSignals {
        self.signals.clone()
    }

    /// The key of each tool approved on `server` now, which a poll starting now is judged
    /// against.
    fn keys_on(&self, server: &ConnectorName) -> BTreeMap<ToolName, WithdrawalKey> {
        self.state()
            .approved
            .iter()
            .filter(|(_, approved)| approved.server == *server)
            .map(|(tool, approved)| (tool.clone(), approved.key.clone()))
            .collect()
    }

    /// Serves `policy`, `registry`'s, from now on, less every standing withdrawal whose key
    /// `registry` still approves. The rest are dropped and logged. Returns the revision served.
    pub(crate) fn load(&self, registry: &Registry, policy: ServedPolicy) -> PolicyRevision {
        let mut state = self.state();
        state.base = Arc::new(policy);
        state.approved = approved(registry);
        let mut cleared = Vec::new();
        let approved = state.approved.clone();
        state.standing.retain(|tool, standing| {
            let keep = approved
                .get(tool)
                .is_some_and(|now| now.key == standing.key);
            if !keep {
                cleared.push((standing.clone(), approved.contains_key(tool)));
            }
            keep
        });
        let revision = self.serve(&state);
        for (standing, still_approved) in cleared {
            tracing::info!(
                event = WITHDRAWAL_CLEARED_EVENT,
                tool = %standing.key.tool,
                server = %standing.server,
                reason = if still_approved {
                    "approved again"
                } else {
                    "no longer in the registry"
                },
                %revision,
                "a withdrawn tool's approval changed, so its withdrawal no longer stands"
            );
        }
        revision
    }

    /// Serves the base less the standing withdrawals, and returns its revision.
    fn serve(&self, state: &State) -> PolicyRevision {
        let served = if state.standing.is_empty() {
            (*state.base).clone()
        } else {
            let withdrawn: BTreeSet<ToolName> = state.standing.keys().cloned().collect();
            let revision = withdrawn_revision(state.base.revision(), &withdrawn);
            state.base.without(&withdrawn, revision)
        };
        let revision = served.revision().clone();
        self.signals
            .0
            .withdrawn
            .store(state.standing.len() as u64, Ordering::Relaxed);
        self.live.replace(served);
        revision
    }

    /// Judges what `server`'s poll read against the tools approved on it now, and withdraws
    /// each that changed or is gone. A tool whose key is not the one in `started`, the keys
    /// when the poll began, is left for the next poll. A failed poll withdraws nothing.
    fn judge(
        &self,
        server: &ConnectorName,
        started: &BTreeMap<ToolName, WithdrawalKey>,
        listed: Result<Vec<ListedTool>, ListError>,
    ) {
        let tools = match listed {
            Ok(tools) => {
                self.signals.count(server, |counts| counts.polls_ok += 1);
                tools
            }
            Err(reason) => {
                self.signals
                    .count(server, |counts| counts.polls_failed += 1);
                tracing::warn!(
                    event = POLL_FAILED_EVENT,
                    %server,
                    %reason,
                    "could not read the server's tool list; its tools stay served"
                );
                return;
            }
        };
        let mut state = self.state();
        let mut found = Vec::new();
        for (tool, approved) in &state.approved {
            if approved.server != *server || state.standing.contains_key(tool) {
                continue;
            }
            // Approved again, or newly, while the poll was outstanding: what it read may be
            // older than the approval.
            if started.get(tool) != Some(&approved.key) {
                continue;
            }
            let served: Vec<&ListedTool> = tools
                .iter()
                .filter(|listed| listed.name == approved.upstream_name)
                .collect();
            let cause = if served.is_empty() {
                Cause::NoLongerListed
            } else if served.iter().any(|listed| {
                served_sha256(listed).as_deref() != Some(approved.key.definition_sha256.as_str())
            }) {
                Cause::DefinitionChanged
            } else {
                continue;
            };
            found.push((approved.key.clone(), cause));
        }
        if found.is_empty() {
            return;
        }
        for (key, _) in &found {
            state.standing.insert(
                key.tool.clone(),
                Standing {
                    key: key.clone(),
                    server: server.clone(),
                },
            );
        }
        let revision = self.serve(&state);
        let base = state.base.revision().clone();
        drop(state);
        for (key, cause) in found {
            self.signals.count(server, |counts| counts.withdrawals += 1);
            tracing::error!(
                event = TOOL_WITHDRAWN_EVENT,
                tool = %key.tool,
                %server,
                cause = cause.as_str(),
                base = %base,
                %revision,
                "withdrew the tool from every surface: the server no longer serves its approved \
                 definition; approve it again, or remove it from the registry"
            );
        }
    }
}

/// The drift pass of one replica: each proxied server's connector, the withdrawals it makes,
/// and how often it runs. See the [module documentation](self).
pub struct DriftPass {
    withdrawals: Arc<Withdrawals>,
    servers: BTreeMap<ConnectorName, Arc<ProxyConnector>>,
    interval: Duration,
}

impl std::fmt::Debug for DriftPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftPass")
            .field("servers", &self.servers.keys().collect::<Vec<_>>())
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl DriftPass {
    /// A pass over `servers`, each the connector of the proxied server of that name, every
    /// `interval`, withdrawing into `withdrawals`, which the registry reloader
    /// ([`Reloader::withdrawals`](crate::reload::Reloader::withdrawals)) shares.
    pub fn new(
        withdrawals: Arc<Withdrawals>,
        servers: BTreeMap<ConnectorName, Arc<ProxyConnector>>,
        interval: Duration,
    ) -> Self {
        Self {
            withdrawals,
            servers,
            interval,
        }
    }

    /// The withdrawals this pass makes.
    pub fn withdrawals(&self) -> &Arc<Withdrawals> {
        &self.withdrawals
    }

    /// How often it runs.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The counts, for the metrics.
    pub fn signals(&self) -> DriftSignals {
        self.withdrawals.signals()
    }

    /// Reads every server's tool list, all at once, and withdraws what changed. Returns when
    /// every poll has answered or failed, each within its server's call deadline.
    pub async fn pass(&self) {
        let mut polls = JoinSet::new();
        for (server, connector) in &self.servers {
            polls.spawn(poll(
                Arc::clone(&self.withdrawals),
                server.clone(),
                Arc::clone(connector),
            ));
        }
        while let Some(polled) = polls.join_next().await {
            if let Err(error) = polled {
                tracing::error!(%error, "a drift poll's task failed");
            }
        }
    }

    /// Polls each server every interval, for ever, each on a schedule of its own, so a slow
    /// server delays no other server's polls. Each server's first poll is an interval from now:
    /// boot ran one already, before the listener was bound.
    pub async fn run(self) {
        let mut entries = JoinSet::new();
        for (server, connector) in self.servers {
            entries.spawn(poll_every(
                Arc::clone(&self.withdrawals),
                server,
                connector,
                self.interval,
            ));
        }
        while entries.join_next().await.is_some() {}
    }
}

/// Reads `server`'s tool list with `connector` and judges it against the approvals in force
/// when it began.
async fn poll(
    withdrawals: Arc<Withdrawals>,
    server: ConnectorName,
    connector: Arc<ProxyConnector>,
) {
    let started = withdrawals.keys_on(&server);
    let listed = connector.list_tools().await;
    withdrawals.judge(&server, &started, listed);
}

/// Polls `server` every `interval`, the first an interval from now, for ever. A poll that runs
/// past the interval delays the next one, which starts when it ends; the next is never run
/// beside it. So with an interval of at least the server's call deadline, a change is withdrawn
/// within one interval plus that deadline, and with a shorter one, within about two call
/// deadlines (#165). A poll whose task fails is logged, and the next runs as usual.
async fn poll_every(
    withdrawals: Arc<Withdrawals>,
    server: ConnectorName,
    connector: Arc<ProxyConnector>,
    interval: Duration,
) {
    let mut every = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        // Its own task, so a panic ends this poll alone; dropped with the set when the pass is
        // aborted.
        let mut one = JoinSet::new();
        one.spawn(poll(
            Arc::clone(&withdrawals),
            server.clone(),
            Arc::clone(&connector),
        ));
        if let Some(Err(error)) = one.join_next().await {
            tracing::error!(%error, %server, "a drift poll's task failed");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::boot::tests::registry;

    #[test]
    fn the_interval_is_300_s_unless_given_and_5_to_900_when_given() {
        assert_eq!(DriftSection::interval(None), Ok(Duration::from_secs(300)));
        assert_eq!(
            DriftSection::interval(Some(&DriftSection::default())),
            Ok(Duration::from_secs(300))
        );
        for seconds in [5, 10, 900] {
            let section = DriftSection {
                interval_seconds: Some(seconds),
            };
            assert_eq!(
                DriftSection::interval(Some(&section)),
                Ok(Duration::from_secs(seconds))
            );
        }
        for seconds in [0, 4, 901] {
            let section = DriftSection {
                interval_seconds: Some(seconds),
            };
            assert_eq!(
                DriftSection::interval(Some(&section)),
                Err(DriftError::IntervalOutOfRange { seconds })
            );
        }
    }

    #[test]
    fn the_derived_revision_names_the_withdrawn_tools_sorted_and_joined_by_commas() {
        let names: BTreeSet<ToolName> = ["docs__read_document", "docs__list_documents"]
            .into_iter()
            .map(|name| ToolName::parse(name).unwrap())
            .collect();
        assert_eq!(
            withdrawn_revision(&PolicyRevision::new("demo-3"), &names).as_str(),
            "demo-3+withdrawn:docs__list_documents,docs__read_document"
        );
    }

    /// A withdrawn tool is gone from the snapshot, the definitions and the argument adapters,
    /// and nothing else is.
    #[test]
    fn a_withdrawal_removes_the_tool_from_the_catalog_and_the_adapters_too() {
        let registry = registry("read", true);
        let policy = ServedPolicy::from_registry(&registry).unwrap();
        let tool = ToolName::parse("docs__list_documents").unwrap();
        assert!(policy.catalog().definition(&tool).is_some());
        assert!(policy.arguments(&tool).is_some());
        let withdrawn = BTreeSet::from([tool.clone()]);
        let derived = policy.without(&withdrawn, PolicyRevision::new("r1+withdrawn:x"));
        assert_eq!(derived.revision().as_str(), "r1+withdrawn:x");
        assert!(derived.snapshot().tool(&tool).is_none());
        assert!(derived.catalog().definition(&tool).is_none());
        assert!(derived.arguments(&tool).is_none());
        assert_eq!(
            derived.selected_profiles(),
            policy.selected_profiles(),
            "the profile rules are unchanged"
        );
    }
}
