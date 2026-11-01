//! The gateway-level bound around a connector in the gateway's own process: a call deadline
//! and a result size bound, as a proxied server's connector has them, and the rate quotas
//! (decision 0014, sections 1 and 2, built with milestone 4's built-in connectors, #12).
//!
//! [`boot::check`](crate::boot::check) wraps every connector registered with
//! [`Wiring::connector`](crate::boot::Wiring::connector) in a [`Bounded`], so no such connector
//! runs without it. Its bounds are [`InProcessLimits`]: [`DEFAULT_IN_PROCESS_DEADLINE`] and
//! [`DEFAULT_IN_PROCESS_RESULT_BYTES`] unless the wiring sets others, within the ceilings of
//! decision 0014 ([`MAX_SERVER_DEADLINE`] and [`MAX_SERVER_RESULT_BYTES`]). The deployment
//! file's `[connectors.<name>]` sets them for a built-in connector
//! ([`crate::deployment`]). The deadline is the one each of the connector's rows includes in
//! its own.
//!
//! A call first takes its quotas ([`crate::quota`]): one over either is `refused`, with the
//! quota's sentence, and the connector is not called. Then the connector runs, raced against
//! the deadline; a result that is ready when the deadline passes is taken, not thrown away.
//! What happens past the bound follows decision 0011 and decision 0009's "Where a call runs":
//!
//! - **A tool classified `read`** that has not finished by the deadline is cancelled: its
//!   future is dropped, which stops it, and the call is an error of the kind
//!   `oversized_or_late_read`, with [`LATE`]. A read has no side effect to leave half done.
//! - **Any other tool, a side effect,** is never cancelled once it may have been sent. At the
//!   deadline the call is answered `unknown`, its row recorded as `unknown` and its receipt
//!   left `unknown`, and the caller is told not to repeat it. The connector's work is not
//!   dropped: it is moved, as it is, to a task of its own on the runtime, which runs it to its
//!   end and logs [`LATE_SIDE_EFFECT_EVENT`] with the outcome it came to. Reconciliation then
//!   settles the receipt by the connector's lookup, or hands it to a person, as for any
//!   `unknown` receipt, but not while the task runs: see [`LateCalls`]. A gateway shutting down
//!   waits for the task within its grace period ([`LateCalls::wait`]); one that stops while
//!   the task still runs leaves its receipt `unknown` all the same.
//! - **A result over the size bound,** counted as the bytes of its JSON text, is discarded:
//!   from a read, an error of the kind `oversized_or_late_read`, with [`TOO_LARGE`]; from any
//!   other tool, `unknown`, with its receipt `unknown`, since the side effect ran and its
//!   answer cannot be passed on. That holds for a result the vendor confirmed with a reference,
//!   too: the reference is logged, and reconciliation finds it again. Only a result is bounded:
//!   an error's message and a refusal's sentence are the connector's own.
//!
//! Nothing is cut short silently: each breach is logged once, as [`BOUND_BREACHED_EVENT`] with
//! its kind, `late` or `oversized`, and the vendor's reference when a side effect's oversized
//! result carried one, and counted in [`InProcessSignals`], which [`crate::metrics`] exports.
//!
//! **A late side effect holds its receipt.** Reconciliation looks a receipt up only under a
//! lease ([`gateway_core::reconcile`]), and a lookup that finds nothing while the side effect is
//! still on its way would settle the receipt `not_performed` though the call may yet act. So the
//! late side effect's task holds the receipt's lease itself, through the store's
//! [`ReceiptQueue::hold`], under a holder of this instance's own: once before the call is
//! answered, while the receipt is still `pending` within its row's deadline and so not due on
//! any instance; again every quarter of the lease while it runs; and once more when it ends. A
//! held receipt is not due, so no instance, this one or another, claims it or looks it up while
//! the task runs, and the first lookup comes at least a full lease after the side effect ended.
//! The queue, holder and lease are those of the instance's reconciliation, which
//! [`Gates::reconciler`](crate::Gates::reconciler) sets; an instance with no reconciliation
//! holds nothing. A hold that is not written, because the store fails, the hold's
//! [`HOLD_BUDGET`] runs out or another holder has the receipt, is logged as
//! [`LATE_SIDE_EFFECT_UNHELD_EVENT`] and tried again [`HOLD_RETRY`] later, not a quarter of a
//! lease later, and so on until one is written. Meanwhile this instance's own reconciliation
//! still never claims the receipt: it skips every receipt whose late side effect runs here
//! ([`LateCalls::runs`]). Another instance is kept off by the lease and, until the first hold
//! is written, by the row's deadline: no receipt is due on any instance before its row's
//! deadline has passed ([`ReceiptQueue`]), and that deadline includes the store's finish
//! deadline, so a first hold that is not written has most of that to be written again, as a
//! renewal that is not written has the rest of the lease. The guarantee across instances holds
//! only while this one can write to the store: an instance cut off from the store past its
//! row's deadline or its lease, or stopped, lets the receipt be looked up.
//!
//! Running a call needs a Tokio runtime, for the deadline's timer and the task a late side
//! effect moves to.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use gateway_core::audit::AuditRowId;
use gateway_core::{
    BoxFuture, Classification, Connector, ConnectorName, ErrorKind, LeaseHolder, ReceiptQueue,
    ToolCall, ToolName, ToolOutcome, VendorReference,
};
use serde_json::Value;
use tokio::sync::Notify;

use crate::deployment::{MAX_SERVER_DEADLINE, MAX_SERVER_RESULT_BYTES};
use crate::quota::{QuotaScope, Quotas, RateQuotas};

/// How long a call to a connector in the gateway's own process may take, unless configured
/// otherwise: the proxied servers' default.
pub const DEFAULT_IN_PROCESS_DEADLINE: Duration = Duration::from_secs(5);

/// The largest result a connector in the gateway's own process may give, in bytes of its JSON
/// text, unless configured otherwise: 1 MiB, decision 0014's ceiling. A built-in connector
/// reads a vendor's API itself and passes on what it chose to keep, so its result is not held
/// to a proxied server's 64 KiB; a deployment may set it lower.
pub const DEFAULT_IN_PROCESS_RESULT_BYTES: usize = 1024 * 1024;

/// The sentence for a read that did not finish by its deadline.
pub const LATE: &str =
    "This tool did not finish before the call's deadline, so the call was abandoned.";

/// The sentence for a read whose result was larger than its bound.
pub const TOO_LARGE: &str =
    "This tool's answer was larger than the gateway accepts, so it was discarded.";

/// The `event` field of the warning logged for each call past its bound, with `kind` (`late`
/// or `oversized`), the connector, the tool and the `outcome` the call was given (`error` for a
/// read, `unknown` for any other).
pub const BOUND_BREACHED_EVENT: &str = "in_process_bound_breached";

/// The `event` field of the warning logged when a side effect answered `unknown` at its
/// deadline comes to an end, with the `outcome` it came to: `ok`, `error`, `refused` or
/// `unknown`, and its vendor reference when it has one.
pub const LATE_SIDE_EFFECT_EVENT: &str = "in_process_late_side_effect_ended";

/// The `event` field of the warning logged for each call refused by a rate quota.
pub const OVER_QUOTA_EVENT: &str = "call_over_quota";

/// The `event` field of the error logged when a late side effect's task could not hold its
/// receipt's lease, with the `receipt`, and the `cause`: `store_failed`, `timed_out` or
/// `not_held` (another holder has it, or it is settled or handed to a person). Logged once for
/// each run of holds not written, at its first. Once the row's deadline or the last lease written
/// has passed, and until a hold is written again, another instance may look the receipt up
/// while the side effect may still act.
pub const LATE_SIDE_EFFECT_UNHELD_EVENT: &str = "in_process_late_side_effect_unheld";

/// How long one hold of a late side effect's receipt may take before it counts as not written.
/// The first is made before the call is answered, so this bounds how much later than its
/// deadline a late side effect is answered `unknown`.
pub const HOLD_BUDGET: Duration = Duration::from_secs(2);

/// How long a late side effect's task waits before trying again a hold of its receipt that was
/// not written. Until one is, only the row's deadline keeps another instance off the receipt,
/// so this is far shorter than the quarter of a lease between renewals.
pub const HOLD_RETRY: Duration = Duration::from_secs(1);

/// A connector in the gateway's own process's bounds on each call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InProcessLimits {
    /// How long a call may take.
    pub deadline: Duration,
    /// The largest result accepted, in bytes of its JSON text.
    pub max_result_bytes: usize,
}

impl Default for InProcessLimits {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_IN_PROCESS_DEADLINE,
            max_result_bytes: DEFAULT_IN_PROCESS_RESULT_BYTES,
        }
    }
}

impl InProcessLimits {
    /// Whether each bound is at least 1 and within decision 0014's ceilings.
    pub fn within_ceilings(&self) -> bool {
        !self.deadline.is_zero()
            && self.deadline <= MAX_SERVER_DEADLINE
            && self.max_result_bytes > 0
            && self.max_result_bytes <= MAX_SERVER_RESULT_BYTES
    }
}

/// The side effects answered `unknown` at their deadline that still run on tasks of their own,
/// for every connector in the gateway's own process, and how each holds its receipt's lease
/// while it runs. See the [module documentation](self).
#[derive(Default)]
pub struct LateCalls {
    holding: Mutex<Option<Holding>>,
    running: AtomicUsize,
    /// The receipt of each late side effect running, with how many run under it.
    rows: Mutex<HashMap<AuditRowId, usize>>,
    ended: Notify,
}

impl std::fmt::Debug for LateCalls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LateCalls")
            .field("running", &self.running())
            .finish_non_exhaustive()
    }
}

/// Where and how a late side effect's task holds its receipt.
#[derive(Clone)]
struct Holding {
    queue: Arc<dyn ReceiptQueue>,
    holder: LeaseHolder,
    lease: Duration,
}

impl LateCalls {
    /// From here on, each late side effect holds its receipt in `queue`, under `holder`, for
    /// `lease` at a time. [`Gates::reconciler`](crate::Gates::reconciler) calls this with its
    /// own queue and lease.
    pub fn hold_in(&self, queue: Arc<dyn ReceiptQueue>, holder: LeaseHolder, lease: Duration) {
        *self.holding.lock().unwrap_or_else(PoisonError::into_inner) = Some(Holding {
            queue,
            holder,
            lease,
        });
    }

    /// How many late side effects still run.
    pub fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }

    /// Whether a late side effect whose receipt is `row` still runs in this process. This
    /// instance's reconciliation never claims such a receipt, whether or not its lease is held.
    pub fn runs(&self, row: &AuditRowId) -> bool {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(row)
    }

    /// Waits, at most `within`, for every late side effect to end, and returns how many still
    /// run. Never cancels one: a gateway shutting down calls this within its grace period, and
    /// one still running when the grace runs out leaves its receipt `unknown`.
    pub async fn wait(&self, within: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let ended = self.ended.notified();
            tokio::pin!(ended);
            // Registered before the count is read, so an end in between is not missed.
            ended.as_mut().enable();
            let running = self.running();
            if running == 0 {
                return 0;
            }
            if tokio::time::timeout_at(deadline, ended).await.is_err() {
                return self.running();
            }
        }
    }

    fn holding(&self) -> Option<Holding> {
        self.holding
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Counts one late side effect, whose receipt is `row`, running until the returned guard
    /// is dropped.
    fn started(self: &Arc<Self>, row: &AuditRowId) -> Running {
        *self
            .rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(row.clone())
            .or_default() += 1;
        self.running.fetch_add(1, Ordering::SeqCst);
        Running(Arc::clone(self), row.clone())
    }
}

/// One late side effect running, counted until dropped, however its task ends.
struct Running(Arc<LateCalls>, AuditRowId);

impl Drop for Running {
    fn drop(&mut self) {
        {
            let mut rows = self.0.rows.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(count) = rows.get_mut(&self.1) {
                *count -= 1;
                if *count == 0 {
                    rows.remove(&self.1);
                }
            }
        }
        self.0.running.fetch_sub(1, Ordering::SeqCst);
        self.0.ended.notify_waiters();
    }
}

impl Holding {
    /// Holds the receipt `row` for a lease, within [`HOLD_BUDGET`], and returns whether the
    /// hold was written. A hold not written is logged when the last one, `held_before`, was
    /// written, so a run of them is logged once.
    async fn hold(
        &self,
        row: &AuditRowId,
        connector: &ConnectorName,
        tool: &ToolName,
        held_before: bool,
    ) -> bool {
        let held =
            tokio::time::timeout(HOLD_BUDGET, self.queue.hold(row, &self.holder, self.lease)).await;
        let cause = match held {
            Ok(Ok(true)) => return true,
            Ok(Ok(false)) => "not_held",
            Ok(Err(_)) => "store_failed",
            Err(_) => "timed_out",
        };
        if !held_before {
            return false;
        }
        tracing::error!(
            event = LATE_SIDE_EFFECT_UNHELD_EVENT,
            receipt = row.as_str(),
            connector = connector.as_str(),
            tool = tool.as_str(),
            cause,
            "a side effect answered unknown still runs, and its receipt's lease could not be \
             held; another instance may look it up before it ends"
        );
        false
    }

    /// Runs `running` to its end, holding the receipt `row` again every quarter of the lease
    /// meanwhile, and once more when it ends, so the first lookup waits a full lease after it.
    /// `held` is whether the hold made before the call was answered was written. A hold not
    /// written is tried again [`HOLD_RETRY`] later, until one is.
    async fn while_running(
        &self,
        row: &AuditRowId,
        connector: &ConnectorName,
        tool: &ToolName,
        held: bool,
        running: Pin<Box<dyn Future<Output = ToolOutcome> + Send + 'static>>,
    ) -> ToolOutcome {
        let every = self.lease / 4;
        let mut held = held;
        let renewing = async {
            loop {
                tokio::time::sleep(if held { every } else { HOLD_RETRY }).await;
                held = self.hold(row, connector, tool, held).await;
            }
        };
        let outcome = tokio::select! {
            biased;
            outcome = running => outcome,
            () = renewing => unreachable!("holding again never ends"),
        };
        self.hold(row, connector, tool, held).await;
        outcome
    }
}

/// A connector in the gateway's own process, behind its quotas, deadline and size bound. See
/// the [module documentation](self).
pub struct Bounded {
    name: ConnectorName,
    inner: Arc<dyn Connector>,
    limits: InProcessLimits,
    quotas: Quotas,
    signals: Arc<InProcessSignals>,
    late: Arc<LateCalls>,
}

impl std::fmt::Debug for Bounded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bounded")
            .field("name", &self.name)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Bounded {
    /// `inner`, the connector `name`, held to `limits` and `quotas`, counting in `signals`,
    /// with its late side effects among `late`.
    pub fn new(
        name: ConnectorName,
        inner: Arc<dyn Connector>,
        limits: InProcessLimits,
        quotas: RateQuotas,
        signals: Arc<InProcessSignals>,
        late: Arc<LateCalls>,
    ) -> Self {
        Self {
            name,
            inner,
            limits,
            quotas: Quotas::new(quotas),
            signals,
            late,
        }
    }

    /// A call refused by the quota of `scope`, counted and logged. Nothing is sent.
    fn over_quota(&self, scope: QuotaScope, tool: &ToolName) -> BoxFuture<'_, ToolOutcome> {
        self.signals.over_quota(scope);
        tracing::warn!(
            event = OVER_QUOTA_EVENT,
            scope = scope.name(),
            server = self.name.as_str(),
            tool = tool.as_str(),
            "refused a call: it is over a rate quota, and it was not sent"
        );
        let sentence = scope.sentence(self.name.as_str(), tool.as_str());
        Box::pin(std::future::ready(ToolOutcome::Refused(sentence)))
    }

    /// What a call past its bound is given: an error of the kind `oversized_or_late_read` with
    /// `sentence` for a read, `unknown` for any other. Counted and logged once, with the
    /// vendor's `reference` for a side effect the vendor confirmed.
    fn breached(
        &self,
        breach: Breach,
        read: bool,
        tool: &ToolName,
        reference: Option<&VendorReference>,
    ) -> ToolOutcome {
        self.signals.breached(breach);
        let outcome = if read {
            ToolOutcome::error(ErrorKind::OversizedOrLateRead, breach.sentence())
        } else {
            ToolOutcome::Unknown
        };
        tracing::warn!(
            event = BOUND_BREACHED_EVENT,
            kind = breach.name(),
            connector = self.name.as_str(),
            tool = tool.as_str(),
            outcome = if read { "error" } else { "unknown" },
            deadline_ms = u64::try_from(self.limits.deadline.as_millis()).unwrap_or(u64::MAX),
            max_result_bytes = self.limits.max_result_bytes,
            reference = reference.map(VendorReference::as_str),
            "a call to a connector in the gateway's own process went past its bound; a vendor \
             reference it confirmed is left to reconciliation"
        );
        outcome
    }

    /// `outcome`, the connector's own, unless its result is over the size bound.
    fn sized(&self, outcome: ToolOutcome, read: bool, tool: &ToolName) -> ToolOutcome {
        let result = match &outcome {
            ToolOutcome::Ok(result)
            | ToolOutcome::Completed(result, _)
            | ToolOutcome::Reached(result, _) => result,
            ToolOutcome::Error(..) | ToolOutcome::Refused(_) | ToolOutcome::Unknown => {
                return outcome;
            }
        };
        if fits(result, self.limits.max_result_bytes) {
            return outcome;
        }
        let reference = match &outcome {
            ToolOutcome::Completed(_, reference) => Some(reference),
            _ => None,
        };
        self.breached(Breach::Oversized, read, tool, reference)
    }
}

impl Connector for Bounded {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let tool = call.tool().name.clone();
        let read = call.tool().classification == Classification::Read;
        if let Err(scope) = self.quotas.take(call.call().caller.principal.get().team()) {
            return self.over_quota(scope, &tool);
        }
        let inner = Arc::clone(&self.inner);
        let row = call.row().clone();
        // The connector's work owns what it uses, so a late side effect can be moved to a task
        // of its own and run to its end.
        let mut running: Pin<Box<dyn Future<Output = ToolOutcome> + Send + 'static>> =
            Box::pin(async move { inner.run(call).await });
        Box::pin(async move {
            let runtime = tokio::runtime::Handle::current();
            let deadline = tokio::time::sleep(self.limits.deadline);
            tokio::select! {
                // A result that is ready when the deadline passes is taken.
                biased;
                outcome = &mut running => return self.sized(outcome, read, &tool),
                () = deadline => {}
            }
            if !read {
                // A side effect is never cancelled once it may have been sent (decision 0009,
                // "Where a call runs"): it runs to its end on a task of its own, holding its
                // receipt so that no instance looks it up meanwhile. It is counted as running
                // first, so this instance's reconciliation skips its receipt from here on. The
                // first hold is made before the answer, while the receipt is still pending
                // within its row's deadline and so not due anywhere.
                let connector = self.name.clone();
                let late_tool = tool.clone();
                let counted = self.late.started(&row);
                let holding = self.late.holding();
                let held = match &holding {
                    Some(holding) => holding.hold(&row, &connector, &late_tool, true).await,
                    None => false,
                };
                runtime.spawn(async move {
                    let _counted = counted;
                    let outcome = match &holding {
                        Some(holding) => {
                            holding
                                .while_running(&row, &connector, &late_tool, held, running)
                                .await
                        }
                        None => running.await,
                    };
                    let reference = match &outcome {
                        ToolOutcome::Completed(_, reference) => Some(format!("{reference:?}")),
                        _ => None,
                    };
                    tracing::warn!(
                        event = LATE_SIDE_EFFECT_EVENT,
                        connector = connector.as_str(),
                        tool = late_tool.as_str(),
                        outcome = outcome_name(&outcome),
                        reference,
                        "a side effect answered unknown at its deadline has ended; its receipt \
                         stays unknown until reconciliation settles it"
                    );
                });
            }
            // A read's work is dropped here, which cancels it.
            self.breached(Breach::Late, read, &tool, None)
        })
    }
}

/// The name of `outcome` as a row records it.
fn outcome_name(outcome: &ToolOutcome) -> &'static str {
    match outcome {
        ToolOutcome::Ok(_) | ToolOutcome::Completed(..) | ToolOutcome::Reached(..) => "ok",
        ToolOutcome::Error(..) => "error",
        ToolOutcome::Refused(_) => "refused",
        ToolOutcome::Unknown => "unknown",
    }
}

/// Whether `value`'s JSON text is at most `bound` bytes. Stops counting once it is over.
fn fits(value: &Value, bound: usize) -> bool {
    struct Counter {
        bytes: usize,
        bound: usize,
    }
    impl io::Write for Counter {
        fn write(&mut self, written: &[u8]) -> io::Result<usize> {
            self.bytes = self.bytes.saturating_add(written.len());
            if self.bytes > self.bound {
                return Err(io::Error::other("over the bound"));
            }
            Ok(written.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Counter { bytes: 0, bound }, value).is_ok()
}

/// How a call went past its bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Breach {
    Late,
    Oversized,
}

impl Breach {
    fn name(self) -> &'static str {
        match self {
            Self::Late => "late",
            Self::Oversized => "oversized",
        }
    }

    fn sentence(self) -> &'static str {
        match self {
            Self::Late => LATE,
            Self::Oversized => TOO_LARGE,
        }
    }
}

/// What every connector in the gateway's own process counts, summed over them. Every count is
/// an atomic, so nothing on a call's path waits to count it.
#[derive(Debug, Default)]
pub struct InProcessSignals {
    over_quota_server: AtomicU64,
    over_quota_team: AtomicU64,
    late: AtomicU64,
    oversized: AtomicU64,
}

impl InProcessSignals {
    fn over_quota(&self, scope: QuotaScope) {
        match scope {
            QuotaScope::Server => &self.over_quota_server,
            QuotaScope::Team => &self.over_quota_team,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    fn breached(&self, breach: Breach) {
        match breach {
            Breach::Late => &self.late,
            Breach::Oversized => &self.oversized,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// The counts as they stand. Each is read on its own.
    pub fn counts(&self) -> InProcessCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        InProcessCounts {
            over_quota_server: read(&self.over_quota_server),
            over_quota_team: read(&self.over_quota_team),
            late: read(&self.late),
            oversized: read(&self.oversized),
        }
    }
}

/// A snapshot of [`InProcessSignals`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InProcessCounts {
    /// Calls a connector's own quota refused.
    pub over_quota_server: u64,
    /// Calls a team's quota on a connector refused.
    pub over_quota_team: u64,
    /// Calls not finished by their deadline: reads cancelled, and side effects answered
    /// `unknown`.
    pub late: u64,
    /// Calls whose result was over its size bound.
    pub oversized: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_result_fits_when_its_json_text_is_at_most_the_bound() {
        let value = json!({"text": "abc"});
        let bytes = serde_json::to_vec(&value).unwrap_or_default().len();
        assert!(fits(&value, bytes));
        assert!(!fits(&value, bytes - 1));
    }

    #[test]
    fn the_defaults_are_within_the_ceilings_and_zero_or_past_them_is_not() {
        assert!(InProcessLimits::default().within_ceilings());
        let over = |deadline: u64, bytes: usize| InProcessLimits {
            deadline: Duration::from_secs(deadline),
            max_result_bytes: bytes,
        };
        assert!(over(60, 1024 * 1024).within_ceilings());
        assert!(!over(61, 1).within_ceilings());
        assert!(!over(0, 1).within_ceilings());
        assert!(!over(1, 1024 * 1024 + 1).within_ceilings());
        assert!(!over(1, 0).within_ceilings());
    }
}
