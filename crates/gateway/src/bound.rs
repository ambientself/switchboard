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
//!   `unknown` receipt. The task lives as long as the process: a gateway that stops while one
//!   runs leaves its receipt `unknown` all the same.
//! - **A result over the size bound,** counted as the bytes of its JSON text, is discarded:
//!   from a read, an error of the kind `oversized_or_late_read`, with [`TOO_LARGE`]; from any
//!   other tool, `unknown`, with its receipt `unknown`, since the side effect ran and its
//!   answer cannot be passed on. That holds for a result the vendor confirmed with a reference,
//!   too: the reference is logged, and reconciliation finds it again. Only a result is bounded:
//!   an error's message and a refusal's sentence are the connector's own.
//!
//! Nothing is cut short silently: each breach is logged, as [`BOUND_BREACHED_EVENT`] with its
//! kind, `late` or `oversized`, and counted in [`InProcessSignals`], which
//! [`crate::metrics`] exports.
//!
//! Running a call needs a Tokio runtime, for the deadline's timer and the task a late side
//! effect moves to.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gateway_core::{
    BoxFuture, Classification, Connector, ConnectorName, ErrorKind, ToolCall, ToolName, ToolOutcome,
};
use serde_json::Value;

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

/// A connector in the gateway's own process, behind its quotas, deadline and size bound. See
/// the [module documentation](self).
pub struct Bounded {
    name: ConnectorName,
    inner: Arc<dyn Connector>,
    limits: InProcessLimits,
    quotas: Quotas,
    signals: Arc<InProcessSignals>,
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
    /// `inner`, the connector `name`, held to `limits` and `quotas`, counting in `signals`.
    pub fn new(
        name: ConnectorName,
        inner: Arc<dyn Connector>,
        limits: InProcessLimits,
        quotas: RateQuotas,
        signals: Arc<InProcessSignals>,
    ) -> Self {
        Self {
            name,
            inner,
            limits,
            quotas: Quotas::new(quotas),
            signals,
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
    /// `sentence` for a read, `unknown` for any other. Counted and logged.
    fn breached(&self, breach: Breach, read: bool, tool: &ToolName) -> ToolOutcome {
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
            "a call to a connector in the gateway's own process went past its bound"
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
        if let ToolOutcome::Completed(_, reference) = &outcome {
            tracing::warn!(
                event = BOUND_BREACHED_EVENT,
                connector = self.name.as_str(),
                tool = tool.as_str(),
                reference = ?reference,
                "a side effect the vendor confirmed gave a result over its bound; it is answered \
                 unknown, and its reference is left to reconciliation"
            );
        }
        self.breached(Breach::Oversized, read, tool)
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
                // "Where a call runs"): it runs to its end on a task of its own.
                let connector = self.name.clone();
                let late_tool = tool.clone();
                runtime.spawn(async move {
                    let outcome = running.await;
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
            self.breached(Breach::Late, read, &tool)
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
