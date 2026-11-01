//! Reconciliation of `unknown` receipts (decision 0009, "Reconciliation"; design section 11).
//!
//! Every instance works the queue of `unknown` receipts, so no separate deployment is needed.
//! [`Reconciler::run`] makes a [`pass`](Reconciler::pass) every `reconciliation.interval_seconds`
//! (see [`crate::deployment`]). Each pass reads up to [`RECONCILE_BATCH`] receipts due, the
//! longest reserved first. No receipt is due before its row's deadline has passed, in `unknown`
//! as well as `pending` ([`ReceiptQueue`]), so a call answered `unknown` that still runs has
//! until then to hold its receipt. For each receipt due, a pass:
//!
//! 1. Claims it, with a lease of `reconciliation.lease_seconds`, through the store. The claim is
//!    committed before anything else happens, so no lookup is made without it, and no lock or
//!    connection is held across a lookup. The store counts the claim in the same write. A
//!    receipt another instance holds is passed over, and so is one whose own call still runs
//!    past its deadline, which holds it ([`crate::bound`]). A receipt whose call still runs past
//!    its deadline in this instance's own process is passed over before it is claimed, whether
//!    or not that call's hold was written ([`LateCalls::runs`]).
//! 2. Hands it to a person at once when there is nothing to look in: its tool is settled by a
//!    person, so its receipt recorded no vendor target, or the call named no single resource of
//!    the declared kind; or its tool's connector registered no [`Lookup`] (the GitHub connector
//!    registers one for each entry serving a tool not classified `read`), or the tool is no
//!    longer approved; or its attempts are used up. Each claim is
//!    an attempt, whether or not the lookup made under it was recorded, so a store that fails
//!    to save lookups still lets a receipt be looked up at most `reconciliation.attempts`
//!    times.
//! 3. Otherwise asks the connector's lookup for the receipt's marker in its target, with the team
//!    the receipt recorded and the policy revision in force, and half the lease to answer, so
//!    the lookup ends while the lease is held. A lookup that takes longer is a failed one. The
//!    lookup is not a tool call and writes no audit row.
//! 4. Records the answer on the receipt, which the store moves only as
//!    [`LookupAnswer::settles`] says: a found effect settles it `completed` with the vendor's
//!    reference, an authoritative search that found nothing settles it `not_performed`, and any
//!    other answer leaves it `unknown`, for the next attempt once the lease has run out. The
//!    `reconciliation.attempts`-th lookup that settles nothing hands it to a person in the same
//!    write.
//!
//! Reconciliation only looks: nothing here sends, resends or retries a call, and a receipt leaves
//! `unknown` only for `completed` or `not_performed`, by a lookup. A receipt handed to a person
//! stays `unknown`, and is still counted by the open-row and unknown-receipt signals. Nothing
//! records a person's resolution yet (decision 0009, Still open 10).
//!
//! What a pass did is counted in [`ReconcileSignals`], which the metrics listener exports, and
//! a hand-off is logged as the event [`HANDED_TO_PERSON_EVENT`]. A store that cannot be read or
//! written is logged and counted, and the pass goes on to the next receipt; the next pass tries
//! again.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gateway_core::audit::AuditRowId;
use gateway_core::{
    ConnectorName, InstanceName, LeaseHolder, Lookup, LookupAnswer, LookupRequest, Receipt,
    ReceiptQueue, Recorded, ToolName,
};
use serde::Deserialize;
use thiserror::Error;

use crate::bound::LateCalls;
use crate::policy::LivePolicy;

/// How often a pass is made, unless the deployment file says otherwise: a minute. A receipt
/// becomes `unknown` only when a side effect's answer was lost or its row's deadline passed, so
/// a minute's wait costs little, and it keeps an idle instance's queries to the database rare.
pub const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
/// The shortest interval the deployment file may give.
pub const MIN_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// The longest interval the deployment file may give.
pub const MAX_RECONCILE_INTERVAL: Duration = Duration::from_secs(3600);

/// How long a claim holds a receipt, unless the deployment file says otherwise: two minutes,
/// twice the default interval. A lookup has half the lease, a minute, to answer, which covers a
/// vendor's search with room to record it; and a lookup that settles nothing leaves the lease to
/// run out, so one receipt is looked up at most once every two minutes, by any instance, which
/// gives a vendor's search index time to catch up between attempts.
pub const DEFAULT_RECONCILE_LEASE: Duration = Duration::from_secs(120);
/// The shortest lease the deployment file may give: a lookup then has 5 s.
pub const MIN_RECONCILE_LEASE: Duration = Duration::from_secs(10);
/// The longest lease the deployment file may give.
pub const MAX_RECONCILE_LEASE: Duration = Duration::from_secs(3600);

/// How many lookups a receipt gets before it is handed to a person, unless the deployment file
/// says otherwise: five. A vendor whose search is slow to show a new effect gets several
/// chances, and a person hears of one it never shows about 12 to 13 minutes after the receipt
/// became `unknown`, at the default interval and lease on one instance. The pass two minutes
/// after a claim usually finds its lease a moment short of running out, so one instance's
/// lookups land about three minutes apart; several instances bring that nearer two. That is an
/// estimate, assuming no backlog, lookups that answer promptly and saves that succeed. A pass
/// works through up to [`RECONCILE_BATCH`] receipts one at a time, and each lookup may take
/// half the lease, so a backlog or slow lookups can make it much longer. A lookup whose save
/// fails still uses up its attempt, since an attempt is counted when its claim is made, so a
/// failing store does not add lookups, though one that cannot record the hand-off leaves the
/// receipt unhanded until it can.
pub const DEFAULT_RECONCILE_ATTEMPTS: u32 = 5;
/// The most attempts the deployment file may give.
pub const MAX_RECONCILE_ATTEMPTS: u32 = 20;

/// The most receipts one pass works through. The rest wait for the next pass.
pub const RECONCILE_BATCH: usize = 50;

/// The event logged when a receipt is handed to a person.
pub const HANDED_TO_PERSON_EVENT: &str = "receipt_handed_to_person";
/// The event logged when a lookup settles a receipt.
pub const SETTLED_EVENT: &str = "receipt_settled_by_lookup";
/// The event logged when the store could not be read or written during a pass.
pub const RECONCILE_FAILED_EVENT: &str = "reconciliation_store_failed";

/// The `[reconciliation]` table of the deployment file. Every field may be left out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationSection {
    /// How often a pass is made, in seconds: 5 to 3600, and 60 if left out.
    #[serde(default)]
    pub interval_seconds: Option<u64>,
    /// How long a claim holds a receipt, in seconds: 10 to 3600, and 120 if left out.
    #[serde(default)]
    pub lease_seconds: Option<u64>,
    /// How many lookups a receipt gets before it is handed to a person: 1 to 20, and 5 if left
    /// out.
    #[serde(default)]
    pub attempts: Option<u32>,
}

/// Why the `[reconciliation]` table was refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReconcileSettingsError {
    /// The interval is out of range.
    #[error(
        "`reconciliation.interval_seconds` is {0}; it must be from {min} to {max}",
        min = MIN_RECONCILE_INTERVAL.as_secs(),
        max = MAX_RECONCILE_INTERVAL.as_secs()
    )]
    Interval(u64),
    /// The lease is out of range.
    #[error(
        "`reconciliation.lease_seconds` is {0}; it must be from {min} to {max}",
        min = MIN_RECONCILE_LEASE.as_secs(),
        max = MAX_RECONCILE_LEASE.as_secs()
    )]
    Lease(u64),
    /// The attempts are out of range.
    #[error("`reconciliation.attempts` is {0}; it must be from 1 to {MAX_RECONCILE_ATTEMPTS}")]
    Attempts(u32),
}

/// How reconciliation runs: how often, how long a claim holds a receipt, and how many lookups
/// a receipt gets before it is handed to a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileSettings {
    /// How often a pass is made.
    pub interval: Duration,
    /// How long a claim holds a receipt.
    pub lease: Duration,
    /// How many lookups a receipt gets.
    pub attempts: u32,
}

impl Default for ReconcileSettings {
    fn default() -> Self {
        Self {
            interval: DEFAULT_RECONCILE_INTERVAL,
            lease: DEFAULT_RECONCILE_LEASE,
            attempts: DEFAULT_RECONCILE_ATTEMPTS,
        }
    }
}

impl ReconcileSettings {
    /// How long a lookup may take: half the lease, so it ends while the lease is held, with time
    /// left to record what it found.
    pub fn lookup_deadline(&self) -> Duration {
        self.lease / 2
    }
}

impl ReconciliationSection {
    /// The settings `section` gives, with the default for each field left out, or why one is
    /// out of range.
    pub fn settings(section: Option<&Self>) -> Result<ReconcileSettings, ReconcileSettingsError> {
        let section = section.cloned().unwrap_or_default();
        let defaults = ReconcileSettings::default();
        let interval = section
            .interval_seconds
            .map(Duration::from_secs)
            .unwrap_or(defaults.interval);
        if !(MIN_RECONCILE_INTERVAL..=MAX_RECONCILE_INTERVAL).contains(&interval) {
            return Err(ReconcileSettingsError::Interval(interval.as_secs()));
        }
        let lease = section
            .lease_seconds
            .map(Duration::from_secs)
            .unwrap_or(defaults.lease);
        if !(MIN_RECONCILE_LEASE..=MAX_RECONCILE_LEASE).contains(&lease) {
            return Err(ReconcileSettingsError::Lease(lease.as_secs()));
        }
        let attempts = section.attempts.unwrap_or(defaults.attempts);
        if !(1..=MAX_RECONCILE_ATTEMPTS).contains(&attempts) {
            return Err(ReconcileSettingsError::Attempts(attempts));
        }
        Ok(ReconcileSettings {
            interval,
            lease,
            attempts,
        })
    }
}

/// What reconciliation has done since the instance started, for the metrics listener.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileCounts {
    /// Lookups that found the effect.
    pub found: u64,
    /// Authoritative searches that found nothing.
    pub not_found_authoritative: u64,
    /// Searches that found nothing and were not authoritative.
    pub not_found: u64,
    /// Lookups that failed or gave no answer in time.
    pub failed: u64,
    /// Receipts handed to a person.
    pub handed_to_person: u64,
    /// Reads and writes of the queue that failed.
    pub store_failures: u64,
}

#[derive(Debug, Default)]
struct Counters {
    found: AtomicU64,
    not_found_authoritative: AtomicU64,
    not_found: AtomicU64,
    failed: AtomicU64,
    handed_to_person: AtomicU64,
    store_failures: AtomicU64,
}

/// The counts a [`Reconciler`] keeps. Cheap to clone; clones share the counts.
#[derive(Clone, Debug, Default)]
pub struct ReconcileSignals(Arc<Counters>);

impl ReconcileSignals {
    /// The counts as they stand.
    pub fn counts(&self) -> ReconcileCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        ReconcileCounts {
            found: read(&self.0.found),
            not_found_authoritative: read(&self.0.not_found_authoritative),
            not_found: read(&self.0.not_found),
            failed: read(&self.0.failed),
            handed_to_person: read(&self.0.handed_to_person),
            store_failures: read(&self.0.store_failures),
        }
    }

    fn looked_up(&self, answer: &LookupAnswer) {
        let counter = match answer {
            LookupAnswer::Found { .. } => &self.0.found,
            LookupAnswer::NotFound {
                authoritative: true,
            } => &self.0.not_found_authoritative,
            LookupAnswer::NotFound { .. } => &self.0.not_found,
            LookupAnswer::Failed => &self.0.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn handed_to_person(&self) {
        self.0.handed_to_person.fetch_add(1, Ordering::Relaxed);
    }

    fn store_failed(&self) {
        self.0.store_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Why a receipt went to a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandOff {
    /// Its receipt recorded no vendor target.
    NoTarget,
    /// Its tool's connector has no lookup, or the tool is no longer approved.
    NoLookup,
    /// Its attempts are used up.
    AttemptsUsedUp,
}

impl HandOff {
    fn reason(self) -> &'static str {
        match self {
            HandOff::NoTarget => "no_target",
            HandOff::NoLookup => "no_lookup",
            HandOff::AttemptsUsedUp => "attempts_used_up",
        }
    }
}

/// What one pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Receipts due when the pass began.
    pub due: usize,
    /// Receipts this instance claimed.
    pub claimed: usize,
    /// Lookups made.
    pub looked_up: usize,
    /// Receipts a lookup settled.
    pub settled: usize,
    /// Receipts handed to a person.
    pub handed_to_person: usize,
}

/// One instance's reconciliation: the store's queue, the lookups registered for connectors, the
/// policy that says which connector each tool runs on, and its own lease holder. Made by
/// [`Gates::reconciler`](crate::Gates::reconciler).
pub struct Reconciler {
    queue: Arc<dyn ReceiptQueue>,
    policy: Arc<LivePolicy>,
    lookups: BTreeMap<ConnectorName, Arc<dyn Lookup>>,
    holder: LeaseHolder,
    settings: ReconcileSettings,
    signals: ReconcileSignals,
    late: Arc<LateCalls>,
}

impl fmt::Debug for Reconciler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconciler")
            .field("lookups", &self.lookups.keys().collect::<Vec<_>>())
            .field("holder", &self.holder)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Reconciler {
    pub(crate) fn new(
        queue: Arc<dyn ReceiptQueue>,
        policy: Arc<LivePolicy>,
        lookups: BTreeMap<ConnectorName, Arc<dyn Lookup>>,
        instance: &InstanceName,
        settings: ReconcileSettings,
        late: Arc<LateCalls>,
    ) -> Self {
        Self {
            queue,
            policy,
            lookups,
            holder: LeaseHolder::new(format!("{instance} {}", uuid::Uuid::now_v7())),
            settings,
            signals: ReconcileSignals::default(),
            late,
        }
    }

    /// Who this instance's leases are held by: the instance's name and a value of this process's
    /// own.
    pub fn holder(&self) -> &LeaseHolder {
        &self.holder
    }

    /// How it runs.
    pub fn settings(&self) -> ReconcileSettings {
        self.settings
    }

    /// What it has done, for the metrics listener.
    pub fn signals(&self) -> ReconcileSignals {
        self.signals.clone()
    }

    /// Makes a pass every interval, the first at once, for ever. Dropping or aborting its task
    /// mid-pass leaves at most one receipt claimed, which another instance takes once the lease
    /// runs out.
    pub async fn run(self) {
        let mut every = tokio::time::interval(self.settings.interval);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            self.pass().await;
        }
    }

    /// One pass over the receipts due. See the [module documentation](self).
    pub async fn pass(&self) -> PassReport {
        let mut report = PassReport::default();
        let due = match self.queue.due(RECONCILE_BATCH).await {
            Ok(due) => due,
            Err(error) => {
                self.store_failed("read the receipts due", None, &*error);
                return report;
            }
        };
        report.due = due.len();
        for receipt in &due {
            self.work(receipt, &mut report).await;
        }
        report
    }

    /// Claims `due`, then hands it to a person or looks it up and records what was found.
    async fn work(&self, due: &Receipt, report: &mut PassReport) {
        // Its own call still runs here: a lookup now could find nothing though the call may yet
        // act, so it is not claimed, even if that call's hold of it was not written.
        if self.late.runs(&due.row) {
            return;
        }
        // The lease is committed before anything else: no lookup is made without it.
        let claimed = match self
            .queue
            .claim(&due.row, &self.holder, self.settings.lease)
            .await
        {
            Ok(Some(claimed)) => claimed,
            Ok(None) => return,
            Err(error) => {
                self.store_failed("claim a receipt", Some(&due.row), &*error);
                return;
            }
        };
        report.claimed += 1;
        let (target, lookup) = match (&claimed.target, self.lookup_for(&claimed.tool)) {
            (None, _) => return self.hand_off(&claimed, HandOff::NoTarget, report).await,
            (Some(_), None) => return self.hand_off(&claimed, HandOff::NoLookup, report).await,
            (Some(target), Some(lookup)) => (target, lookup),
        };
        // Each claim is an attempt, this one included, whether or not the lookup made under an
        // earlier one was recorded: a store that fails to save lookups cannot let a receipt be
        // looked up without bound. A receipt claimed before claims were counted has its
        // recorded lookups for attempts.
        let attempts = self.settings.attempts;
        if claimed.lookups.len() >= usize::try_from(attempts).unwrap_or(usize::MAX)
            || claimed.claims > attempts
        {
            return self
                .hand_off(&claimed, HandOff::AttemptsUsedUp, report)
                .await;
        }
        // The revision in force: a lookup that asks a custodian for its read credential sends
        // it, and the custodian checks it against its own copy, as it does a call's.
        let revision = self.policy.current().revision().clone();
        let request = LookupRequest {
            marker: &claimed.row,
            target,
            tool: &claimed.tool,
            resources: &claimed.resources,
            team: claimed.team.as_ref(),
            revision: &revision,
        };
        let answer = tokio::time::timeout(self.settings.lookup_deadline(), lookup.look(request))
            .await
            .unwrap_or(LookupAnswer::Failed);
        report.looked_up += 1;
        self.signals.looked_up(&answer);
        match self
            .queue
            .record_lookup(&claimed.row, &self.holder, &answer, self.settings.attempts)
            .await
        {
            Ok(Recorded::Settled(state)) => {
                report.settled += 1;
                tracing::info!(
                    event = SETTLED_EVENT,
                    receipt = claimed.row.as_str(),
                    tool = claimed.tool.as_str(),
                    state = ?state,
                    "a lookup settled an unknown receipt"
                );
            }
            Ok(Recorded::HandedToPerson) => {
                self.handed_off(&claimed, HandOff::AttemptsUsedUp, report);
            }
            Ok(Recorded::Left) => {}
            Err(error) => self.store_failed("record a lookup", Some(&claimed.row), &*error),
        }
    }

    /// The lookup registered for the connector `tool` runs on now, if the tool is still
    /// approved and its connector registered one.
    fn lookup_for(&self, tool: &ToolName) -> Option<&Arc<dyn Lookup>> {
        let policy = self.policy.current();
        let connector = &policy.snapshot().tool(tool)?.connector;
        self.lookups.get(connector)
    }

    async fn hand_off(&self, claimed: &Receipt, why: HandOff, report: &mut PassReport) {
        match self.queue.hand_to_person(&claimed.row, &self.holder).await {
            Ok(()) => self.handed_off(claimed, why, report),
            Err(error) => {
                self.store_failed("hand a receipt to a person", Some(&claimed.row), &*error)
            }
        }
    }

    fn handed_off(&self, claimed: &Receipt, why: HandOff, report: &mut PassReport) {
        report.handed_to_person += 1;
        self.signals.handed_to_person();
        tracing::warn!(
            event = HANDED_TO_PERSON_EVENT,
            receipt = claimed.row.as_str(),
            tool = claimed.tool.as_str(),
            reason = why.reason(),
            lookups = claimed.lookups.len(),
            "an unknown receipt was handed to a person; it stays unknown until one settles it"
        );
    }

    fn store_failed(
        &self,
        what: &str,
        receipt: Option<&AuditRowId>,
        error: &(dyn std::error::Error + Send + Sync),
    ) {
        self.signals.store_failed();
        tracing::warn!(
            event = RECONCILE_FAILED_EVENT,
            what,
            receipt = receipt.map(AuditRowId::as_str),
            %error,
            "reconciliation could not reach the receipt store; the next pass tries again"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_setting_has_a_default_and_a_range() {
        assert_eq!(
            ReconciliationSection::settings(None),
            Ok(ReconcileSettings {
                interval: Duration::from_secs(60),
                lease: Duration::from_secs(120),
                attempts: 5,
            })
        );
        let given = |interval, lease, attempts| ReconciliationSection {
            interval_seconds: interval,
            lease_seconds: lease,
            attempts,
        };
        assert_eq!(
            ReconciliationSection::settings(Some(&given(Some(5), Some(10), Some(1)))),
            Ok(ReconcileSettings {
                interval: Duration::from_secs(5),
                lease: Duration::from_secs(10),
                attempts: 1,
            })
        );
        assert!(
            ReconciliationSection::settings(Some(&given(Some(3600), Some(3600), Some(20)))).is_ok()
        );
        for (section, refused) in [
            (
                given(Some(4), None, None),
                ReconcileSettingsError::Interval(4),
            ),
            (
                given(Some(3601), None, None),
                ReconcileSettingsError::Interval(3601),
            ),
            (given(None, Some(9), None), ReconcileSettingsError::Lease(9)),
            (
                given(None, Some(3601), None),
                ReconcileSettingsError::Lease(3601),
            ),
            (
                given(None, None, Some(0)),
                ReconcileSettingsError::Attempts(0),
            ),
            (
                given(None, None, Some(21)),
                ReconcileSettingsError::Attempts(21),
            ),
        ] {
            assert_eq!(
                ReconciliationSection::settings(Some(&section)),
                Err(refused)
            );
        }
        assert_eq!(
            ReconcileSettings::default().lookup_deadline(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn the_table_refuses_fields_it_does_not_know() {
        assert!(toml::from_str::<ReconciliationSection>("interval = 5").is_err());
        assert_eq!(
            toml::from_str::<ReconciliationSection>("attempts = 3").unwrap(),
            ReconciliationSection {
                attempts: Some(3),
                ..ReconciliationSection::default()
            }
        );
    }
}
