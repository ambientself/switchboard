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
//! **The probe.** Beside each tool list, the poll probes the server
//! ([`ProxyConnector::probe`]): decision 0010's three `tools/call` requests for a tool that
//! does not exist, with no credential, a malformed one, and the server's probe credential, a
//! stranger's (`[drift.probe_credentials]`, [`probe_credentials`]). A server that dispatches
//! one is open: it is logged as [`SERVER_OPEN_EVENT`] at ERROR, naming the server and the
//! calls it dispatched, and counted in `switchboard_probe_results_total{result="open"}`. Its
//! tools stay listed: withdrawing them would close the governed route and leave the open one
//! (decision 0010). A probe that showed neither a refusal nor a dispatch, such as one that
//! could not connect, is logged as [`PROBE_NOT_SHOWN_EVENT`] at WARN and counted as
//! `not_shown`, never as refused. The probe runs while the list is read, so it adds nothing to
//! how long a poll takes, and an open server found by the first pass does not stop boot.
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
//! servers do. A poll takes at most the server's call deadline, and the gateway refuses to
//! start with an interval shorter than any proxied server's call deadline ([`crate::start`]),
//! so each poll ends by the next tick, and a changed definition is withdrawn within one
//! interval plus that deadline (decision 0013, section 5, as noted on 2026-10-12). The interval
//! is `[drift] interval_seconds` in the deployment file ([`DriftSection`]): 300 s unless given,
//! and refused below 5 or above 900.
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
//! **An entry's reach check tool withdrawn withdraws the entry** (decision 0011, section 4, as
//! noted on 2026-10-12). When a withdrawal, for any cause, takes the tool an entry's
//! `reach_check` calls, the entry's reach can no longer be checked: the check would fail
//! without a call for as long as the tool is withdrawn. So every other tool approved on the
//! entry is withdrawn with it, in the same policy and revision, with the cause `reach check
//! tool withdrawn` and the field `reach_check_tool` naming that tool, and nothing is served
//! under the entry's credential until the reach check tool is served again. Another entry's
//! tools are not touched.
//!
//! **The reach check** (decision 0011, section 4; decision 0013, section 5, step 3). Each
//! server whose registry entry has a `reach_check` is checked on its schedule, beside each
//! poll: [`ReachCaller`] sends the check's canary, a call outside the entry's reach, through
//! this replica's own listener, under the registry's own workload identity, so it is decided
//! and audited like any call. The deployment file's `[drift] reach_*` ([`ReachSettings`]) say
//! where and as whom, and the gateway refuses to start without them while any entry has a
//! `reach_check` ([`crate::start`]), so no entry is left unchecked for want of them. It goes
//! through the listener, so it never runs in the boot pass, which comes before the listener is
//! bound: [`DriftPass::run`] makes each entry's first check as soon as it starts, after the
//! binary has bound the listener, and one more at each tick of the entry's schedule after,
//! unless the last is still out. Each check runs beside the schedule, so no poll waits for one,
//! and the bound above holds with reach checked too. A check takes up to the call deadline plus
//! [`REACH_ALLOWANCE`](crate::reach::REACH_ALLOWANCE), and a tick that finds it still out makes
//! no check, so the next is at a later tick. With an interval longer than the deadline plus the
//! allowance, as at the defaults, a widened reach is withdrawn within one interval plus the
//! deadline and the allowance. With one no longer than that, as in the demos (10 s, with a 5 s
//! deadline), a check can still be out at the next tick, which skips, and it is withdrawn within
//! two intervals plus the deadline and the allowance (30 s in the demos), except at a 5 s
//! interval with a 5 s deadline, where two ticks can skip and it is withdrawn within three
//! intervals plus them (25 s). In every case it is withdrawn within one interval plus twice the
//! sum of the deadline and the allowance. What the answer means is
//! [`reach::Verdict`](crate::reach::Verdict)'s:
//!
//! - **Held**, the server refused the canary: logged as [`REACH_HELD_EVENT`] at INFO and
//!   counted in `switchboard_reach_checks_total{result="held"}`.
//! - **Mismatch**, the server answered it: the reach is wider than recorded. Every tool of the
//!   entry is withdrawn, as a changed definition is, with the cause `reach mismatch`, so only a
//!   new approval brings them back. It is logged as [`REACH_MISMATCH_EVENT`] at ERROR, with a
//!   [`TOOL_WITHDRAWN_EVENT`] for each tool, and counted as `mismatch`.
//! - **Failed**, anything else, such as a denial, an audit failure or no answer in time:
//!   logged as [`REACH_FAILED_EVENT`] at WARN and counted as `failed`. Nothing is withdrawn: a
//!   failed check shows nothing about the reach. A check whose canary tool is not served now,
//!   because it is withdrawn or not approved, fails without a call.
//!
//! A mismatch is judged against the approvals in force when the check began, as a poll is: a
//! tool approved again while the check was outstanding is left for the next check.
//!
//! **The vendor report** (decision 0011, section 4; #193) is the reach check's second kind, for
//! a built-in entry whose vendor reports what its credential reaches: a GitHub entry with a
//! `reach_report`, whose tool, a reach-report entry's, reads the App installation's list of
//! repositories. Each such entry is checked on a schedule of its own, every interval, as an
//! entry's canary is: once as soon as [`DriftPass::run`] starts, after the listener is bound, and
//! at each tick after unless the last is still out, never in the boot pass.
//! [`ReachCaller::report`] sends the tool through the same listener as the same principal, so
//! the call is decided and audited like any other, and [`compare`] compares the repositories it
//! lists with the entry's recorded reach both ways. The deadline is that of the report tool's
//! connector, `[connectors.<name>] deadline_seconds` or the default, plus the allowance, and the
//! bound is the canary's: a reach that widens or narrows is withdrawn within one interval plus
//! twice the sum of that deadline and the allowance.
//!
//! - **Held**, the report lists exactly the recorded reach: logged as [`REACH_HELD_EVENT`] at
//!   INFO, with `check = "vendor_report"`, and counted as `held`.
//! - **Mismatch**, a repository reported and not recorded, or recorded and not reported: every
//!   tool of the entry is withdrawn, with the cause `reach report mismatch`, judged against the
//!   approvals in force when the check began, so only a new approval brings them back. It is
//!   logged as [`REACH_MISMATCH_EVENT`] at ERROR, naming the repositories `added` and
//!   `dropped`, with a [`TOOL_WITHDRAWN_EVENT`] for each tool, and counted as `mismatch`. The
//!   report's own tool is another entry's, and stays served.
//! - **Failed**, a report that could not be read, for any reason the canary's call can fail,
//!   or a result that is an error or lists no repositories: logged as [`REACH_FAILED_EVENT`] at
//!   WARN and counted as `failed`. Nothing is withdrawn, and the next tick tries again. A check
//!   whose report tool is not served now fails without a call.
//!
//! Its counts are under the checked entry's name, beside the proxied servers'.
//!
//! **A standing withdrawal** is keyed by the tool's exposed name, `definition_sha256`,
//! `binding_sha256` and `approved_at` ([`WithdrawalKey`]). When the registry reloader serves a
//! new version, every standing withdrawal whose key is unchanged is applied to it, and the
//! derived revision names the new base. One whose tool was approved again (a new `approved_at`)
//! or removed is dropped, and logged as [`WITHDRAWAL_CLEARED_EVENT`] at INFO. A tool withdrawn
//! with its entry's reach check tool has no key of its own: its withdrawal stands while the
//! reach check tool's does, whatever its own approval, and is dropped with it, or when the tool
//! is removed. So a new approval of the reach check tool, or of the whole entry, clears the
//! entry's tools; one of another tool alone does not. A tool withdrawn for a cause of its own
//! keeps its own key either way. Each poll and each reach check still judge a tool withdrawn
//! with its reach check tool, as they judge a served one: one whose definition changes, that
//! the server no longer lists, or whose entry's reach is found wider, is withdrawn for that
//! cause of its own instead, so a new approval of the reach check tool does not serve it, and
//! a changed definition is withdrawn within the bound above. A reload that approves a new tool
//! on an entry whose reach check tool is withdrawn withdraws it at once, and logs it.
//! Withdrawals live in this replica's memory until then, or until it restarts (section 7): a
//! restarted replica withdraws a tool again only if its server still serves the changed
//! definition. Each replica checks for itself; nothing is passed between them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use connector_proxy::{
    CredentialFileError, ListError, ListedTool, ProbeCall, ProbeCredential, ProbeFinding,
    ProbeReport, ProxyConnector,
};
use gateway_core::{ConnectorName, PolicyRevision, ToolName};
use gateway_registry::{REPORTED_KIND, ReachCheck, Registry, definition_sha256};
use serde::Deserialize;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::bound::InProcessLimits;
use crate::deployment::ServerLimits;
use crate::policy::{LivePolicy, ServedPolicy};
use crate::reach::{ReachCaller, ReachSettings, ReachSettingsError, Reported, Verdict, compare};

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

/// What the line logged for a dropped withdrawal of a tool's own says.
const CLEARED_MESSAGE: &str =
    "a withdrawn tool's approval changed, so its withdrawal no longer stands";

/// The `event` field of the error logged for each probe that found a server open.
pub const SERVER_OPEN_EVENT: &str = "server_open";

/// The `event` field of the warning logged for each probe that showed no refusal.
pub const PROBE_NOT_SHOWN_EVENT: &str = "probe_not_shown";

/// The `event` field of the line logged for each reach check the server held: it refused the
/// canary.
pub const REACH_HELD_EVENT: &str = "reach_held";

/// The `event` field of the error logged for each reach check the server answered: its reach
/// is wider than recorded, and the entry's tools are withdrawn.
pub const REACH_MISMATCH_EVENT: &str = "reach_mismatch";

/// The `event` field of the warning logged for each reach check that showed nothing.
pub const REACH_FAILED_EVENT: &str = "reach_check_failed";

/// The deployment file's `[drift]` table.
///
/// ```toml
/// [drift]
/// interval_seconds = 300      # 300 if left out; 5 to 900
/// # The reach check: all three, needed while an entry has a reach_check.
/// reach_token_file = "/var/run/switchboard/tokens/registry"
/// reach_url = "http://127.0.0.1:8080/mcp/registry-reach"
/// reach_host = "gateway.switchboard.svc.cluster.local"
///
/// [drift.probe_credentials]   # one for each proxied server in the registry
/// mock-docs = "/var/run/switchboard/tokens/registry-probe"
/// ```
///
/// `probe_credentials` names, for each proxied server, the file holding the credential the
/// probe's third call presents: a stranger's (decision 0010). The gateway refuses to start
/// unless every server in the registry has one, and refuses one for a server the registry does
/// not name ([`probe_credentials`]).
///
/// `reach_token_file`, `reach_url` and `reach_host` set up the reach check
/// ([`ReachSettings`]): the registry's workload token, this replica's own listener and the
/// surface the registry is admitted to, and the `Host` to call it with, one of
/// `http.allowed_hosts`. They are given together or not at all, and may be left out only when
/// no registry entry has a reach check: otherwise the gateway refuses to start, naming the
/// entries ([`crate::start`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftSection {
    /// How often, in seconds, each proxied server's tool list is read: 5 to 900, and
    /// [`DEFAULT_DRIFT_INTERVAL`] if left out.
    #[serde(default)]
    pub interval_seconds: Option<u64>,
    /// Each proxied server's probe credential file, by server name.
    #[serde(default)]
    pub probe_credentials: BTreeMap<ConnectorName, PathBuf>,
    /// The file holding the registry's workload token, which the reach check presents.
    #[serde(default)]
    pub reach_token_file: Option<PathBuf>,
    /// This replica's own listener and the registry's surface, which the reach check calls.
    #[serde(default)]
    pub reach_url: Option<String>,
    /// The `Host` the reach check's call carries.
    #[serde(default)]
    pub reach_host: Option<String>,
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
    /// The reach check's fields were refused.
    #[error(transparent)]
    Reach(#[from] ReachSettingsError),
}

/// Why the probe credentials were refused.
#[derive(Debug, Error)]
pub enum ProbeCredentialError {
    /// A proxied server has no probe credential.
    #[error(
        "server `{0}` has no probe credential; give it a file under `[drift.probe_credentials]`"
    )]
    Missing(ConnectorName),
    /// A probe credential is given for a server the registry does not name.
    #[error(
        "`[drift.probe_credentials]` gives a file for server `{0}`, which the registry does not name"
    )]
    UnknownServer(ConnectorName),
    /// A probe credential file could not be read, or does not hold one token.
    #[error("the probe credential: {0}")]
    File(#[from] CredentialFileError),
}

/// Each proxied server's probe credential, by server name.
pub type ProbeCredentials = BTreeMap<ConnectorName, Arc<ProbeCredential>>;

/// The probe credential of each of `registry`'s servers, from the file `files` names for it,
/// each read and checked now. Refuses a server with no file and a file for a server the
/// registry does not name.
pub fn probe_credentials(
    registry: &Registry,
    files: &BTreeMap<ConnectorName, PathBuf>,
) -> Result<ProbeCredentials, ProbeCredentialError> {
    if let Some(unknown) = files
        .keys()
        .find(|server| !registry.servers().contains_key(*server))
    {
        return Err(ProbeCredentialError::UnknownServer(unknown.clone()));
    }
    registry
        .servers()
        .keys()
        .map(|server| {
            let path = files
                .get(server)
                .ok_or_else(|| ProbeCredentialError::Missing(server.clone()))?;
            let credential = ProbeCredential::load(server.clone(), path)?;
            Ok((server.clone(), Arc::new(credential)))
        })
        .collect()
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

    /// The reach check's settings `section` gives, from the deployment file's directory
    /// `base`, or `None` with no table or none of the fields. Refused unless all three are
    /// given, the URL is plain `http` with a host and a path, and the host is one of
    /// `allowed_hosts`.
    pub fn reach(
        section: Option<&Self>,
        allowed_hosts: &BTreeSet<String>,
        base: &std::path::Path,
    ) -> Result<Option<ReachSettings>, DriftError> {
        let Some(section) = section else {
            return Ok(None);
        };
        Ok(ReachSettings::from_fields(
            section.reach_token_file.as_deref(),
            section.reach_url.as_deref(),
            section.reach_host.as_deref(),
            allowed_hosts,
            base,
        )?)
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
    /// The server answered the reach check's canary, a call outside its entry's reach.
    ReachMismatch,
    /// The entry's reach check tool is withdrawn, so the entry's reach can no longer be
    /// checked.
    ReachCheckToolWithdrawn,
    /// The vendor's report of what the entry's credential reaches is not the recorded reach.
    ReachReportMismatch,
}

impl Cause {
    /// As the log line gives it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefinitionChanged => "definition changed",
            Self::NoLongerListed => "no longer listed",
            Self::ReachMismatch => "reach mismatch",
            Self::ReachCheckToolWithdrawn => "reach check tool withdrawn",
            Self::ReachReportMismatch => "reach report mismatch",
        }
    }

    /// What the log line says of it.
    fn message(self) -> &'static str {
        match self {
            Self::DefinitionChanged | Self::NoLongerListed => {
                "withdrew the tool from every surface: the server no longer serves its approved \
                 definition; approve it again, or remove it from the registry"
            }
            Self::ReachMismatch => {
                "withdrew the tool from every surface: its entry's server answered a call outside \
                 the entry's recorded reach; narrow the credential and approve it again, or \
                 remove it from the registry"
            }
            Self::ReachCheckToolWithdrawn => {
                "withdrew the tool from every surface: its entry's reach check tool is withdrawn, \
                 so the entry's reach can no longer be checked; approve the reach check tool \
                 again, or remove the entry's tools from the registry"
            }
            Self::ReachReportMismatch => {
                "withdrew the tool from every surface: the vendor's report of what its entry's \
                 credential reaches is not the entry's recorded reach; make the two agree and \
                 approve it again, or remove it from the registry"
            }
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
    /// Probes that found the server refused all three calls.
    pub probes_refused: u64,
    /// Probes that found the server open: it dispatched a call.
    pub probes_open: u64,
    /// Probes that showed neither.
    pub probes_not_shown: u64,
    /// Reach checks the server held: it refused the canary.
    pub reach_held: u64,
    /// Reach checks the server answered: its tools were withdrawn.
    pub reach_mismatch: u64,
    /// Reach checks that showed nothing.
    pub reach_failed: u64,
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
    /// Each server's reach check, as the loaded registry gives it.
    reach_checks: BTreeMap<ConnectorName, ReachCheck>,
    /// Each built-in entry's reach report, as the loaded registry gives it.
    reach_reports: BTreeMap<ConnectorName, ReportCheck>,
}

/// A built-in entry's reach report, as the drift pass checks it: the report's tool, the entry
/// that serves the tool, and the recorded reach the report is compared with, each repository by
/// its identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReportCheck {
    tool: ToolName,
    served_by: ConnectorName,
    reach: BTreeSet<String>,
}

/// Each reach report `registry` gives, by the entry it checks. The loader requires the entry's
/// reach to hold only repositories of its system, and the tool to be a reach-report entry's.
fn reach_reports(registry: &Registry) -> BTreeMap<ConnectorName, ReportCheck> {
    registry
        .connectors()
        .values()
        .filter_map(|entry| {
            let report = entry.reach_report.as_ref()?;
            let reach = entry
                .declaration
                .as_ref()?
                .reach
                .iter()
                .filter(|resource| {
                    resource.system == entry.system && resource.kind == REPORTED_KIND
                })
                .map(|resource| resource.identifier.clone())
                .collect();
            let served_by = registry
                .connectors()
                .values()
                .find(|other| other.reports_reach && other.tools.contains(&report.tool))?
                .name
                .clone();
            Some((
                entry.name.clone(),
                ReportCheck {
                    tool: report.tool.clone(),
                    served_by,
                    reach,
                },
            ))
        })
        .collect()
}

impl State {
    /// Whether `tool` is withdrawn for a cause of its own. A tool withdrawn only with its
    /// entry's reach check tool is still judged, by each poll and each reach check: a cause of
    /// its own found then withdraws it for that cause, so a new approval of the reach check
    /// tool alone does not serve it.
    fn withdrawn_on_its_own(&self, tool: &ToolName) -> bool {
        self.standing
            .get(tool)
            .is_some_and(|standing| standing.canary.is_none())
    }
}

/// Each reach check `registry` gives, by server.
fn reach_checks(registry: &Registry) -> BTreeMap<ConnectorName, ReachCheck> {
    registry
        .servers()
        .iter()
        .filter_map(|(name, server)| Some((name.clone(), server.reach_check.clone()?)))
        .collect()
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
    /// The entry's reach check tool, when the tool is withdrawn because that tool is
    /// ([`dependents`]); `None` when it is withdrawn for a cause of its own.
    canary: Option<ToolName>,
}

/// The tools withdrawn because their entry's reach check tool is (decision 0011, section 4,
/// noted on 2026-10-12): every tool approved on an entry whose reach check tool is withdrawn
/// for a cause of its own, other than that tool and those withdrawn for a cause of their own.
/// The entry can no longer be checked, so nothing is served under its credential. They follow
/// the reach check tool's withdrawal: they stand while it does, whatever their own approvals,
/// and go when it goes, unless a poll or a reach check has found a cause of their own since.
fn dependents(state: &State) -> BTreeMap<ToolName, Standing> {
    let own = |tool: &ToolName| state.withdrawn_on_its_own(tool);
    let mut dependents = BTreeMap::new();
    for (server, check) in &state.reach_checks {
        if !own(&check.tool) {
            continue;
        }
        for (tool, approved) in &state.approved {
            if approved.server != *server || *tool == check.tool || own(tool) {
                continue;
            }
            dependents.insert(
                tool.clone(),
                Standing {
                    key: approved.key.clone(),
                    server: server.clone(),
                    canary: Some(check.tool.clone()),
                },
            );
        }
    }
    dependents
}

/// Each tool `registry` approves, with its server, its upstream name and its key. A built-in
/// tool's server is its entry, and its upstream name its own: only a reach report withdraws one.
fn approved(registry: &Registry) -> BTreeMap<ToolName, Approved> {
    registry
        .approvals()
        .iter()
        .filter_map(|(tool, approval)| {
            let (server, upstream_name) = match registry.routes().get(tool) {
                Some(route) => (route.server.clone(), route.upstream_name.clone()),
                None => (
                    registry.built_in_tools().get(tool)?.clone(),
                    tool.as_str().to_owned(),
                ),
            };
            Some((
                tool.clone(),
                Approved {
                    server,
                    upstream_name,
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
                reach_checks: reach_checks(registry),
                reach_reports: reach_reports(registry),
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
    /// `registry` still approves, and the tools of each entry whose reach check tool that
    /// leaves withdrawn ([`dependents`]). The rest are dropped and logged, and a tool newly
    /// withdrawn with its entry's reach check tool is logged as a withdrawal. Returns the
    /// revision served.
    pub(crate) fn load(&self, registry: &Registry, policy: ServedPolicy) -> PolicyRevision {
        let mut state = self.state();
        state.base = Arc::new(policy);
        state.approved = approved(registry);
        state.reach_checks = reach_checks(registry);
        state.reach_reports = reach_reports(registry);
        let before = std::mem::take(&mut state.standing);
        let approved = state.approved.clone();
        state.standing = before
            .iter()
            .filter(|(tool, standing)| {
                standing.canary.is_none()
                    && approved
                        .get(*tool)
                        .is_some_and(|now| now.key == standing.key)
            })
            .map(|(tool, standing)| (tool.clone(), standing.clone()))
            .collect();
        let dependents = dependents(&state);
        state.standing.extend(dependents);
        let revision = self.serve(&state);
        let base = state.base.revision().clone();
        // A tool whose withdrawal ended, or changed from one of its own to its reach check
        // tool's, is cleared; one now withdrawn with its reach check tool, and not before, is
        // withdrawn.
        let canary = |standing: Option<&Standing>| standing.map(|standing| standing.canary.clone());
        let mut withdrawn = Vec::new();
        for (tool, was) in &before {
            let now = state.standing.get(tool);
            if canary(now) == canary(Some(was)) {
                continue;
            }
            let (reason, message) = if !approved.contains_key(tool) {
                ("no longer in the registry", CLEARED_MESSAGE)
            } else if was.canary.is_some() {
                (
                    "its entry's reach check tool is no longer withdrawn",
                    "the withdrawal of the tool's entry's reach check tool no longer stands, so \
                     neither does the tool's",
                )
            } else {
                ("approved again", CLEARED_MESSAGE)
            };
            tracing::info!(
                event = WITHDRAWAL_CLEARED_EVENT,
                tool = %tool,
                server = %was.server,
                reason,
                %revision,
                "{message}"
            );
        }
        for (tool, now) in &state.standing {
            if canary(before.get(tool)) != canary(Some(now)) {
                withdrawn.push(now.clone());
            }
        }
        drop(state);
        for standing in withdrawn {
            self.report_withdrawal(&standing, Cause::ReachCheckToolWithdrawn, &base, &revision);
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
    /// each that changed or is gone, for that cause, one withdrawn only with its entry's reach
    /// check tool included ([`State::withdrawn_on_its_own`]). A tool whose key is not the one
    /// in `started`, the keys when the poll began, is left for the next poll. A failed poll
    /// withdraws nothing.
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
        let state = self.state();
        let mut found = Vec::new();
        for (tool, approved) in &state.approved {
            if approved.server != *server || state.withdrawn_on_its_own(tool) {
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
        self.withdraw(state, server, found);
    }

    /// Withdraws each tool of `found`, all `server`'s, under `state`, for a cause of its own,
    /// in place of any withdrawal with its entry's reach check tool, and with an entry's reach
    /// check tool the entry's other tools ([`dependents`]), and logs and counts each.
    fn withdraw(
        &self,
        mut state: std::sync::MutexGuard<'_, State>,
        server: &ConnectorName,
        found: Vec<(WithdrawalKey, Cause)>,
    ) {
        if found.is_empty() {
            return;
        }
        let mut withdrawn = Vec::new();
        for (key, cause) in found {
            let standing = Standing {
                key: key.clone(),
                server: server.clone(),
                canary: None,
            };
            state.standing.insert(key.tool, standing.clone());
            withdrawn.push((standing, cause));
        }
        for (tool, standing) in dependents(&state) {
            if let std::collections::btree_map::Entry::Vacant(vacant) = state.standing.entry(tool) {
                vacant.insert(standing.clone());
                withdrawn.push((standing, Cause::ReachCheckToolWithdrawn));
            }
        }
        let revision = self.serve(&state);
        let base = state.base.revision().clone();
        drop(state);
        for (standing, cause) in withdrawn {
            self.report_withdrawal(&standing, cause, &base, &revision);
        }
    }

    /// Logs and counts the withdrawal of `standing`'s tool for `cause`, from `base`, which
    /// serves `revision`.
    fn report_withdrawal(
        &self,
        standing: &Standing,
        cause: Cause,
        base: &PolicyRevision,
        revision: &PolicyRevision,
    ) {
        let server = &standing.server;
        self.signals.count(server, |counts| counts.withdrawals += 1);
        tracing::error!(
            event = TOOL_WITHDRAWN_EVENT,
            tool = %standing.key.tool,
            %server,
            cause = cause.as_str(),
            reach_check_tool = standing.canary.as_ref().map(ToolName::as_str),
            base = %base,
            %revision,
            "{}",
            cause.message()
        );
    }

    /// `server`'s reach check, and whether its canary tool is served now: approved and not
    /// withdrawn. `None` when the registry gives the server none.
    fn reach_check(&self, server: &ConnectorName) -> Option<(ReachCheck, bool)> {
        let state = self.state();
        let check = state.reach_checks.get(server)?.clone();
        let served =
            state.approved.contains_key(&check.tool) && !state.standing.contains_key(&check.tool);
        Some((check, served))
    }

    /// Judges what `server`'s reach check came to (see the [module documentation](self)). A
    /// mismatch withdraws every tool approved on the server whose key is the one in `started`,
    /// the keys when the check began, and that is not withdrawn for a cause of its own already;
    /// one approved again since is left for the next check. Only a mismatch withdraws anything.
    fn judge_reach(
        &self,
        server: &ConnectorName,
        tool: &ToolName,
        started: &BTreeMap<ToolName, WithdrawalKey>,
        verdict: Verdict,
    ) {
        match verdict {
            Verdict::Held { row } => {
                self.signals.count(server, |counts| counts.reach_held += 1);
                tracing::info!(
                    event = REACH_HELD_EVENT,
                    %server,
                    %tool,
                    row = row.as_deref().unwrap_or("none"),
                    "the server refused the reach check's call outside its entry's reach"
                );
            }
            Verdict::Failed(reason) => {
                self.signals
                    .count(server, |counts| counts.reach_failed += 1);
                tracing::warn!(
                    event = REACH_FAILED_EVENT,
                    %server,
                    %tool,
                    %reason,
                    "the reach check showed nothing about the entry's reach; nothing is withdrawn"
                );
            }
            Verdict::Mismatch { row } => {
                self.signals
                    .count(server, |counts| counts.reach_mismatch += 1);
                let state = self.state();
                let found: Vec<(WithdrawalKey, Cause)> = state
                    .approved
                    .iter()
                    .filter(|(name, approved)| {
                        approved.server == *server
                            && !state.withdrawn_on_its_own(name)
                            && started.get(*name) == Some(&approved.key)
                    })
                    .map(|(_, approved)| (approved.key.clone(), Cause::ReachMismatch))
                    .collect();
                tracing::error!(
                    event = REACH_MISMATCH_EVENT,
                    %server,
                    %tool,
                    row = row.as_deref().unwrap_or("none"),
                    withdrawn = found.len(),
                    "the server answered the reach check's call outside its entry's recorded \
                     reach: its credential reaches more than was approved, so every tool of the \
                     entry is withdrawn"
                );
                self.withdraw(state, server, found);
            }
        }
    }
}

impl Withdrawals {
    /// The entries whose reach is checked against a vendor report, each with the entry that
    /// serves the report's tool.
    fn reported_entries(&self) -> Vec<(ConnectorName, ConnectorName)> {
        self.state()
            .reach_reports
            .iter()
            .map(|(entry, check)| (entry.clone(), check.served_by.clone()))
            .collect()
    }

    /// `entry`'s reach report, and whether its tool is served now: approved and not withdrawn.
    /// `None` when the registry gives the entry none.
    fn reach_report(&self, entry: &ConnectorName) -> Option<(ReportCheck, bool)> {
        let state = self.state();
        let check = state.reach_reports.get(entry)?.clone();
        let served =
            state.approved.contains_key(&check.tool) && !state.standing.contains_key(&check.tool);
        Some((check, served))
    }

    /// Judges what `entry`'s vendor report came to (see the [module documentation](self)). A
    /// report that differs from the recorded reach, either way, withdraws every tool approved on
    /// the entry whose key is the one in `started`, the keys when the check began, and that is
    /// not withdrawn for a cause of its own already. A failed report withdraws nothing.
    fn judge_report(
        &self,
        entry: &ConnectorName,
        check: &ReportCheck,
        started: &BTreeMap<ToolName, WithdrawalKey>,
        reported: Reported,
    ) {
        let tool = &check.tool;
        let (repositories, row) = match reported {
            Reported::Listed { repositories, row } => (repositories, row),
            Reported::Failed(reason) => {
                self.signals.count(entry, |counts| counts.reach_failed += 1);
                tracing::warn!(
                    event = REACH_FAILED_EVENT,
                    check = "vendor_report",
                    server = %entry,
                    %tool,
                    %reason,
                    "the vendor's report of the entry's reach could not be read; nothing is \
                     withdrawn, and the next check tries again"
                );
                return;
            }
        };
        let difference = compare(&check.reach, &repositories);
        if difference.is_empty() {
            self.signals.count(entry, |counts| counts.reach_held += 1);
            tracing::info!(
                event = REACH_HELD_EVENT,
                check = "vendor_report",
                server = %entry,
                %tool,
                row = row.as_deref().unwrap_or("none"),
                reported = repositories.len(),
                "the vendor's report of what the entry's credential reaches is its recorded reach"
            );
            return;
        }
        self.signals
            .count(entry, |counts| counts.reach_mismatch += 1);
        let state = self.state();
        let found: Vec<(WithdrawalKey, Cause)> = state
            .approved
            .iter()
            .filter(|(name, approved)| {
                approved.server == *entry
                    && !state.withdrawn_on_its_own(name)
                    && started.get(*name) == Some(&approved.key)
            })
            .map(|(_, approved)| (approved.key.clone(), Cause::ReachReportMismatch))
            .collect();
        let names = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(",");
        tracing::error!(
            event = REACH_MISMATCH_EVENT,
            check = "vendor_report",
            server = %entry,
            %tool,
            row = row.as_deref().unwrap_or("none"),
            added = names(&difference.added),
            dropped = names(&difference.dropped),
            withdrawn = found.len(),
            "the vendor's report of what the entry's credential reaches is not its recorded \
             reach: a repository was added or dropped without a new approval, so every tool of \
             the entry is withdrawn"
        );
        self.withdraw(state, entry, found);
    }
}

impl Withdrawals {
    /// Counts what `server`'s probe found, and logs it unless the server refused every call.
    /// An open server is logged at ERROR and its tools stay listed: withdrawing them would
    /// close the governed route and leave the open one (decision 0010). Nothing here touches
    /// what is served.
    fn report_probe(&self, server: &ConnectorName, report: &ProbeReport) {
        let calls = || {
            report
                .calls()
                .iter()
                .map(|(call, verdict)| format!("{call}: {verdict}"))
                .collect::<Vec<_>>()
                .join("; ")
        };
        match report.finding() {
            ProbeFinding::Refused => {
                self.signals
                    .count(server, |counts| counts.probes_refused += 1);
            }
            ProbeFinding::Open => {
                self.signals.count(server, |counts| counts.probes_open += 1);
                let dispatched: Vec<&str> = report
                    .dispatched()
                    .into_iter()
                    .map(ProbeCall::as_str)
                    .collect();
                tracing::error!(
                    event = SERVER_OPEN_EVENT,
                    %server,
                    dispatched = dispatched.join(","),
                    calls = calls(),
                    "the server dispatched a probe call for a tool that does not exist: it does \
                     not check its caller, so it can be reached around the gateway; its tools \
                     stay listed, and its owner and the register's owner must be told"
                );
            }
            ProbeFinding::NotShown => {
                self.signals
                    .count(server, |counts| counts.probes_not_shown += 1);
                tracing::warn!(
                    event = PROBE_NOT_SHOWN_EVENT,
                    %server,
                    calls = calls(),
                    "the probe could not show that the server refuses a caller it does not know"
                );
            }
        }
    }

    /// Counts a probe of `server` that could not be made for want of a probe credential, as
    /// not shown. The gateway refuses to start without one for every server, so only a pass
    /// built without them comes here.
    fn no_probe_credential(&self, server: &ConnectorName) {
        self.signals
            .count(server, |counts| counts.probes_not_shown += 1);
        tracing::warn!(
            event = PROBE_NOT_SHOWN_EVENT,
            %server,
            calls = "none: no probe credential is configured",
            "the probe could not show that the server refuses a caller it does not know"
        );
    }
}

/// The drift pass of one replica: each proxied server's connector and probe credential, the
/// withdrawals it makes, and how often it runs. See the [module documentation](self).
pub struct DriftPass {
    withdrawals: Arc<Withdrawals>,
    servers: BTreeMap<ConnectorName, Arc<ProxyConnector>>,
    probes: ProbeCredentials,
    interval: Duration,
    reach: Option<Reach>,
    /// Each in-process connector's call deadline, from the deployment file's
    /// `[connectors.<name>]`, which a reach report's call is given.
    report_deadlines: BTreeMap<ConnectorName, Duration>,
}

impl std::fmt::Debug for DriftPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftPass")
            .field("servers", &self.servers.keys().collect::<Vec<_>>())
            .field("interval", &self.interval)
            .field(
                "reach",
                &self.reach.as_ref().map(|reach| reach.caller.settings()),
            )
            .finish_non_exhaustive()
    }
}

impl DriftPass {
    /// A pass over `servers`, each the connector of the proxied server of that name, every
    /// `interval`, withdrawing into `withdrawals`, which the registry reloader
    /// ([`Reloader::withdrawals`](crate::reload::Reloader::withdrawals)) shares. Each poll
    /// probes its server with its credential in `probes` ([`probe_credentials`]).
    pub fn new(
        withdrawals: Arc<Withdrawals>,
        servers: BTreeMap<ConnectorName, Arc<ProxyConnector>>,
        probes: ProbeCredentials,
        interval: Duration,
    ) -> Self {
        Self {
            withdrawals,
            servers,
            probes,
            interval,
            reach: None,
            report_deadlines: BTreeMap::new(),
        }
    }

    /// The same pass, giving each reach report's call the deadline `bounds`, the deployment
    /// file's `[connectors.<name>]`, sets for the connector that serves the report's tool, or
    /// the default for one it does not name, plus the caller's allowance.
    pub fn with_report_deadlines(
        mut self,
        bounds: &BTreeMap<ConnectorName, InProcessLimits>,
    ) -> Self {
        self.report_deadlines = bounds
            .iter()
            .map(|(name, limits)| (name.clone(), limits.deadline))
            .collect();
        self
    }

    /// Each entry checked against a vendor report, as its check reaches it, when reach is
    /// checked.
    fn reporting(&self) -> Vec<Reporting> {
        let Some(reach) = &self.reach else {
            return Vec::new();
        };
        self.withdrawals
            .reported_entries()
            .into_iter()
            .map(|(entry, served_by)| Reporting {
                deadline: self
                    .report_deadlines
                    .get(&served_by)
                    .copied()
                    .unwrap_or_else(|| InProcessLimits::default().deadline),
                entry,
                caller: Arc::clone(&reach.caller),
            })
            .collect()
    }

    /// The same pass, checking each server's reach too (decision 0011, section 4) with
    /// `caller`, each check given its server's call deadline in `bounds`, or the default
    /// deadline for a server it does not name, plus the caller's allowance. The checks run in
    /// [`run`](Self::run) and [`reach_pass`](Self::reach_pass), never in [`pass`](Self::pass):
    /// they call the listener, which boot's first pass comes before.
    pub fn with_reach(
        mut self,
        caller: ReachCaller,
        bounds: &BTreeMap<ConnectorName, ServerLimits>,
    ) -> Self {
        let deadlines = self
            .servers
            .keys()
            .map(|server| {
                let deadline = bounds.get(server).copied().unwrap_or_default().deadline;
                (server.clone(), deadline)
            })
            .collect();
        self.reach = Some(Reach {
            caller: Arc::new(caller),
            deadlines,
        });
        self
    }

    /// Whether it checks each server's reach.
    pub fn checks_reach(&self) -> bool {
        self.reach.is_some()
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

    /// What one poll of `server` needs: its connector, its probe credential, and the reach
    /// check's caller and its deadline.
    fn entry(&self, server: &ConnectorName, connector: &Arc<ProxyConnector>) -> Entry {
        Entry {
            server: server.clone(),
            connector: Arc::clone(connector),
            probe: self.probes.get(server).cloned(),
            reach: self.reach.as_ref().map(|reach| {
                let deadline = reach
                    .deadlines
                    .get(server)
                    .copied()
                    .unwrap_or_else(|| ServerLimits::default().deadline);
                (Arc::clone(&reach.caller), deadline)
            }),
        }
    }

    /// Checks every server's reach once, all at once, and withdraws an entry whose server
    /// answered its canary; and every entry checked against a vendor report, withdrawing one
    /// whose report differs from its reach. Returns when every check has been judged. Without
    /// a caller ([`with_reach`](Self::with_reach)) it does nothing.
    pub async fn reach_pass(&self) {
        let mut checks = JoinSet::new();
        for (server, connector) in &self.servers {
            checks.spawn(check_reach(
                Arc::clone(&self.withdrawals),
                self.entry(server, connector),
            ));
        }
        for reporting in self.reporting() {
            checks.spawn(check_report(Arc::clone(&self.withdrawals), reporting));
        }
        while let Some(checked) = checks.join_next().await {
            if let Err(error) = checked {
                tracing::error!(%error, "a reach check's task failed");
            }
        }
    }

    /// Reads every server's tool list and probes it, all at once, and withdraws what changed.
    /// Returns when every poll has answered or failed, each within its server's call deadline.
    pub async fn pass(&self) {
        let mut polls = JoinSet::new();
        for (server, connector) in &self.servers {
            polls.spawn(poll(
                Arc::clone(&self.withdrawals),
                self.entry(server, connector),
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
    /// boot ran one already, before the listener was bound. With a reach caller, each server's
    /// reach is checked at once, since the binary starts this only once the listener is bound,
    /// and again at each tick unless the last check is still out. The checks run beside the
    /// schedule, so no poll waits for one. Each entry checked against a vendor report is
    /// checked on a schedule of its own, the same way.
    pub async fn run(self) {
        let mut entries = JoinSet::new();
        for reporting in self.reporting() {
            entries.spawn(report_every(
                Arc::clone(&self.withdrawals),
                reporting,
                self.interval,
            ));
        }
        for (server, connector) in &self.servers {
            entries.spawn(poll_every(
                Arc::clone(&self.withdrawals),
                self.entry(server, connector),
                self.interval,
            ));
        }
        while entries.join_next().await.is_some() {}
    }
}

/// The reach check's caller, and each server's call deadline.
struct Reach {
    caller: Arc<ReachCaller>,
    deadlines: BTreeMap<ConnectorName, Duration>,
}

/// One proxied server, as a poll reaches it.
#[derive(Clone)]
struct Entry {
    server: ConnectorName,
    connector: Arc<ProxyConnector>,
    probe: Option<Arc<ProbeCredential>>,
    /// The reach check's caller and the server's call deadline, when reach is checked.
    reach: Option<(Arc<ReachCaller>, Duration)>,
}

/// One built-in entry whose reach is checked against a vendor report, as its schedule reaches
/// it: the reach check's caller, and the call deadline of the report tool's connector.
#[derive(Clone)]
struct Reporting {
    entry: ConnectorName,
    caller: Arc<ReachCaller>,
    deadline: Duration,
}

/// Reads `reporting`'s vendor report and judges it against the approvals in force when it
/// began. A report tool that is not served now fails the check without a call: the gateway
/// would refuse it.
async fn check_report(withdrawals: Arc<Withdrawals>, reporting: Reporting) {
    let Some((check, served)) = withdrawals.reach_report(&reporting.entry) else {
        return;
    };
    let started = withdrawals.keys_on(&reporting.entry);
    let reported = if served {
        reporting
            .caller
            .report(&check.tool, reporting.deadline)
            .await
    } else {
        Reported::Failed(format!(
            "its tool `{}` is not served now, so no call was made",
            check.tool
        ))
    };
    withdrawals.judge_report(&reporting.entry, &check, &started, reported);
}

/// Checks `reporting`'s vendor report at once and again every `interval`, for ever, each check
/// in a task of its own. A tick that comes while the last check is still out makes none, so two
/// checks of one entry never run together, as [`poll_every`]'s reach checks do not.
async fn report_every(withdrawals: Arc<Withdrawals>, reporting: Reporting, interval: Duration) {
    let first = tokio::time::Instant::now() + interval;
    let mut every = tokio::time::interval_at(first, interval);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut checking = JoinSet::new();
    checking.spawn(check_report(Arc::clone(&withdrawals), reporting.clone()));
    loop {
        every.tick().await;
        while let Some(checked) = checking.try_join_next() {
            if let Err(error) = checked {
                tracing::error!(%error, server = %reporting.entry, "a reach report's task failed");
            }
        }
        if checking.is_empty() {
            checking.spawn(check_report(Arc::clone(&withdrawals), reporting.clone()));
        }
    }
}

/// Checks `entry`'s reach, if reach is checked and its registry entry has a reach check, and
/// judges it against the approvals in force when it began. A canary tool that is not served now
/// fails the check without a call: the gateway would refuse it.
async fn check_reach(withdrawals: Arc<Withdrawals>, entry: Entry) {
    let Some((caller, deadline)) = &entry.reach else {
        return;
    };
    let Some((check, served)) = withdrawals.reach_check(&entry.server) else {
        return;
    };
    let started = withdrawals.keys_on(&entry.server);
    let verdict = if served {
        caller.call(&check, *deadline).await
    } else {
        Verdict::Failed(format!(
            "its tool `{}` is not served now, so no call was made",
            check.tool
        ))
    };
    withdrawals.judge_reach(&entry.server, &check.tool, &started, verdict);
}

/// Reads `entry`'s tool list and judges it against the approvals in force when it began, and
/// probes the server beside it (decision 0013, section 5). The probe runs while the list is
/// read, so a poll takes no longer than one call deadline.
async fn poll(withdrawals: Arc<Withdrawals>, entry: Entry) {
    let started = withdrawals.keys_on(&entry.server);
    let probing = async {
        match &entry.probe {
            Some(credential) => Some(entry.connector.probe(credential).await),
            None => None,
        }
    };
    let (listed, probed) = tokio::join!(entry.connector.list_tools(), probing);
    withdrawals.judge(&entry.server, &started, listed);
    match probed {
        Some(report) => withdrawals.report_probe(&entry.server, &report),
        None => withdrawals.no_probe_credential(&entry.server),
    }
}

/// Polls `entry` every `interval`, the first an interval from now, for ever. A poll that runs
/// past the interval delays the next one, which starts when it ends; the next is never run
/// beside it. A poll takes at most the server's call deadline, and the gateway refuses to start
/// with an interval shorter than any server's ([`crate::start`]), so each poll ends by the next
/// tick and a change is withdrawn within one interval plus that deadline (decision 0013,
/// section 5). A poll whose task fails is logged, and the next runs as usual.
///
/// Its reach is checked at once, and again at each tick, each check in a task beside the
/// schedule, so no poll ever waits for one. A tick that comes while the last check is still out
/// makes no check of its own, so two checks of one entry never run together, and the next check
/// waits for a later tick. A check takes up to the call deadline plus
/// [`REACH_ALLOWANCE`](crate::reach::REACH_ALLOWANCE), timed from after its tick. Take a reach
/// that widens just after a check's canary was judged:
///
/// - With an interval longer than the deadline plus the allowance, as at the defaults, every
///   tick makes a check, and the reach is withdrawn within one interval plus the call deadline
///   and the allowance.
/// - With one no longer than that, as in the demos (10 s, with a 5 s deadline), a check can
///   still be out at the next tick, which then skips; one that runs to its limit always is. The
///   next check starts a second interval on, and the reach is withdrawn within two intervals
///   plus the deadline and the allowance (30 s in the demos).
/// - At a 5 s interval with a 5 s deadline, the second tick skips too, and it is withdrawn
///   within three intervals plus the deadline and the allowance (25 s).
///
/// In every case that is within one interval plus twice the sum of the deadline and the
/// allowance.
async fn poll_every(withdrawals: Arc<Withdrawals>, entry: Entry, interval: Duration) {
    let mut every = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Each in its own task, so a panic ends that poll or check alone; dropped with the set
    // when the pass is aborted. The checks run beside the schedule, never before a poll.
    let mut checking = JoinSet::new();
    checking.spawn(check_reach(Arc::clone(&withdrawals), entry.clone()));
    loop {
        every.tick().await;
        while let Some(checked) = checking.try_join_next() {
            if let Err(error) = checked {
                tracing::error!(%error, server = %entry.server, "a reach check's task failed");
            }
        }
        if checking.is_empty() {
            checking.spawn(check_reach(Arc::clone(&withdrawals), entry.clone()));
        }
        let mut one = JoinSet::new();
        one.spawn(poll(Arc::clone(&withdrawals), entry.clone()));
        if let Some(Err(error)) = one.join_next().await {
            tracing::error!(%error, server = %entry.server, "a drift poll's task failed");
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
                ..DriftSection::default()
            };
            assert_eq!(
                DriftSection::interval(Some(&section)),
                Ok(Duration::from_secs(seconds))
            );
        }
        for seconds in [0, 4, 901] {
            let section = DriftSection {
                interval_seconds: Some(seconds),
                ..DriftSection::default()
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
