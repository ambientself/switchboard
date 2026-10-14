//! [`PgAuditStore`]: the core's [`AuditStore`] on Postgres.

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use deadpool_postgres::{
    ClientWrapper, Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod, Transaction,
};
use gateway_core::audit::{
    AuditRowId, Completion, ErrorKind, ListRecord, RowCompletion, StoreError,
};
use gateway_core::receipt::{ReceiptRequest, Reservation};
use gateway_core::{AuditRecord, AuditStore, BoxFuture, Receipt, VendorReference};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{CancelToken, Socket};

use crate::columns::{
    AnswerRow, BeginRow, FinishRow, ListRow, ReceiptRow, answers, earlier_receipt,
};
use crate::stats::{BeginFailures, GivenUpCauses, LatencyCounter, PoolStats, StoreStats};

/// Why a row could not be written. Returned to the core boxed, as its [`StoreError`]; a test
/// can downcast it.
#[derive(Debug, Error)]
pub enum PgAuditError {
    /// Begin was handed a record that already has a completion.
    #[error("begin writes the first half of an audit row, and this record is already complete")]
    CompleteAtBegin,
    /// A value could not be put in its column.
    #[error("an audit column could not be written: {0}")]
    Column(&'static str),
    /// A text value holds U+0000, which Postgres text and jsonb cannot store. The record is
    /// refused rather than written with another character in its place, so a row written is
    /// always exactly its record.
    #[error(
        "the audit column {column} would hold U+0000, which Postgres cannot store, so the row is not written"
    )]
    Nul {
        /// The column.
        column: &'static str,
    },
    /// A text value is longer than its column may hold: a refusal's sentence over
    /// [`MAX_OUTCOME_SENTENCE_BYTES`](crate::MAX_OUTCOME_SENTENCE_BYTES) at finish. The
    /// completion is refused rather than written cut short, as one holding U+0000 is, so a row
    /// written is always exactly its record.
    #[error(
        "the audit column {column} would hold {bytes} bytes, more than the {cap} it may hold, so \
         it is not written"
    )]
    TooLong {
        /// The column.
        column: &'static str,
        /// The value's length, in bytes.
        bytes: usize,
        /// The most the column may hold, in bytes.
        cap: usize,
    },
    /// The row would hold more than its bound, counted as the bytes of the values the store
    /// sends (decision 0014, section 7): [`MAX_BEGUN_ROW_BYTES`](crate::MAX_BEGUN_ROW_BYTES)
    /// for a call row at begin, which leaves room for its completion within
    /// [`MAX_ROW_BYTES`](crate::MAX_ROW_BYTES), and `MAX_ROW_BYTES` for a list row. The record
    /// is refused, naming the row's largest column.
    #[error(
        "the audit row would hold {bytes} bytes, more than the {bound} it may hold, so it is not \
         written; its largest column is {column}"
    )]
    RowTooLarge {
        /// The row's largest column.
        column: &'static str,
        /// The row's size, as the bound counts it.
        bytes: usize,
        /// The most the row may hold.
        bound: usize,
    },
    /// No connection could be had.
    #[error("no connection to the audit database: {0}")]
    Pool(#[from] PoolError),
    /// A pool could not be built.
    #[error("the audit database pool could not be built: {0}")]
    Build(#[from] deadpool_postgres::BuildError),
    /// The database refused or failed the statement.
    #[error("the audit database did not write the row: {}", describe(.0))]
    Database(#[from] tokio_postgres::Error),
    /// Begin named a row the table already holds, with another decision. The stored row
    /// stands. Only the decision is compared, because the gateway's role can read no more.
    #[error("audit row {row} was already begun, with another decision")]
    BegunDifferently {
        /// The row begin named.
        row: String,
    },
    /// Begin or list named a row the table already holds, of the other kind: a list row for a
    /// begin, or a call row for a list. The stored row stands.
    #[error("audit row {row} is already stored, as a row of another kind")]
    OtherKind {
        /// The row begin or list named.
        row: String,
    },
    /// Finish was handed a `duplicate`, which only begin writes, as the answer to a reused key.
    /// Nothing is sent.
    #[error("a `duplicate` is written at begin, as the answer to a reused key, never by finish")]
    DuplicateAtFinish,
    /// Finish was handed what only a call that reserved a receipt has, `unknown` or a vendor
    /// reference, for a row that reserved none. Nothing is written: a read reports neither.
    #[error("audit row {row} reserved no receipt, so {what}; nothing was written")]
    NoReceipt {
        /// The row finish named.
        row: String,
        /// What it cannot have.
        what: &'static str,
    },
    /// Begin with a receipt was handed a denial. A denial reserves nothing, and nothing is
    /// written.
    #[error("audit row {row} records a denial, which reserves no receipt; nothing was written")]
    ReceiptForDenial {
        /// The row begin named.
        row: String,
    },
    /// A retried begin with a receipt found its row stored with no receipt and no answer: it
    /// was begun without one.
    #[error("audit row {row} was begun with no receipt")]
    BegunWithoutReceipt {
        /// The row begin named.
        row: String,
    },
    /// A retried begin with a receipt found its row's receipt already left `pending`: its call
    /// has run, or has been settled without running, and must not run again.
    #[error("audit row {row}'s receipt has left pending, so its call must not run again")]
    ReceiptSettled {
        /// The row begin named.
        row: String,
    },
    /// A retried begin with a receipt found its row written complete with something other than
    /// an answer from the earlier receipt under its key.
    #[error("audit row {row} is already complete, with no answer to its key's earlier receipt")]
    AnsweredDifferently {
        /// The row begin named.
        row: String,
    },
    /// Begin with a receipt found its key neither free to reserve nor held by a receipt it
    /// could read: two reservations of the key were each undone in turn.
    #[error("audit row {row}'s key could not be reserved, nor its earlier receipt read")]
    KeyContended {
        /// The row begin named.
        row: String,
    },
    /// A value read back from a receipt is not one the store writes.
    #[error("the audit database holds {0} that the store does not write")]
    Unreadable(&'static str),
    /// The test told the store to lose this begin's confirmation after it committed.
    #[cfg(test)]
    #[error("the test lost this begin's confirmation after its row was written")]
    ConfirmationLost,
    /// Finish named a row the table does not hold.
    #[error("audit row {row} does not exist")]
    NoSuchRow {
        /// The row finish named.
        row: String,
    },
    /// The row was completed before, with a different outcome, sentence, error kind or
    /// latency. The first completion stands.
    #[error("audit row {row} is already complete, with a different completion")]
    CompletedDifferently {
        /// The row finish named.
        row: String,
    },
    /// The update that completes the row matched nothing, and the row read just after has no
    /// completion: the update did not see the row, whose insert committed after it looked. The
    /// task completing a failed begin's row, whose insert may commit late, tries again; a
    /// finish, whose row was begun before it, gives up.
    #[error(
        "audit row {row} has no completion, and the update that would have written one did not find it"
    )]
    NotCompleted {
        /// The row finish named.
        row: String,
    },
    /// Begin did not have a connection and a committed row within its budget. The call is
    /// refused. If the insert was sent, the store asked the server to cancel it, but a cancel
    /// is best effort: the row may still have been written, as decision 0009 allows for a
    /// begin reported as failed. The store then completes an allowed row as `error`.
    #[error("the audit row was not written within the begin budget of {budget:?}")]
    BeginBudget {
        /// The budget that ran out.
        budget: Duration,
    },
    /// Finish did not complete the row within the answer budget. The store keeps trying, on a
    /// task of its own, until its deadline.
    #[error(
        "audit row {row} was not completed within the answer budget of {budget:?}; the store is still trying"
    )]
    AnswerBudget {
        /// The row finish named.
        row: String,
        /// The budget that ran out.
        budget: Duration,
    },
    /// One attempt to complete a row took as long as the answer budget, and was cancelled.
    #[error("an attempt to complete an audit row took too long and was cancelled")]
    AttemptTimedOut,
    /// Finish kept trying until its deadline, and the row is still not complete.
    #[error("audit row {row} was not completed by the finish deadline: {last}")]
    Deadline {
        /// The row finish named.
        row: String,
        /// Why the last attempt failed.
        last: Box<PgAuditError>,
    },
    /// The task completing the row stopped without saying how it ended.
    #[error("the task completing audit row {row} stopped without a result")]
    FinishTaskLost {
        /// The row finish named.
        row: String,
    },
    /// The open rows were not counted within their time limit. The store asked the server to
    /// cancel the query.
    #[error("the open audit rows were not counted within {budget:?}")]
    OpenRowsTimedOut {
        /// The time limit that ran out.
        budget: Duration,
    },
    /// The receipts in `unknown` were not counted within their time limit. The store asked the
    /// server to cancel the query.
    #[error("the receipts in unknown were not counted within {budget:?}")]
    UnknownReceiptsTimedOut {
        /// The time limit that ran out.
        budget: Duration,
    },
}

impl PgAuditError {
    /// Whether trying again could succeed: the database could not be reached, the connection
    /// broke, the server is short of something, shutting down or read-only, a lock was not had
    /// in time, or an attempt took too long. A refusal by the database itself, a missing row
    /// or a different completion is final; only the task completing a failed begin's row waits
    /// for a missing one.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {
                true
            }
            #[cfg(test)]
            Self::ConfirmationLost => true,
            Self::Database(error) => match error.code() {
                // Connection exception, transaction rollback (serialization, deadlock),
                // insufficient resources, operator intervention, system error. Then a server
                // that has become read-only, as the old primary does in a failover, and a lock
                // not had within lock_timeout.
                Some(code) => {
                    matches!(code.code().get(..2), Some("08" | "40" | "53" | "57" | "58"))
                        || matches!(code.code(), "25006" | "55P03")
                }
                None => {
                    error.is_closed()
                        || std::error::Error::source(error)
                            .is_some_and(|source| source.is::<std::io::Error>())
                }
            },
            _ => false,
        }
    }
}

/// A database error with the server's own message and SQLSTATE, which `tokio_postgres` leaves
/// out of its `Display`.
pub(crate) fn describe(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => error.to_string(),
    }
}

/// How many connections the begin and finish pools may hold.
///
/// Finish has a pool of its own, so a surge of begins cannot starve the writes that close
/// rows. The defaults are provisional; decision 0009 leaves pool sizes to Q12. The open-row
/// query has a third pool, of [`OPEN_ROWS_POOL_SIZE`] connection, which is not set here. So a
/// store opens at most `begin + finish + 1` connections: 21 with the defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSizes {
    /// Connections for begin.
    pub begin: usize,
    /// Connections for finish.
    pub finish: usize,
}

impl Default for PoolSizes {
    fn default() -> Self {
        Self {
            begin: 16,
            finish: 4,
        }
    }
}

/// How long the store waits. The defaults are the provisional 2 s, 2 s and 30 s of decision
/// 0009 point 9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    /// Begin, from asking for a connection to the committed row. Past it, begin fails and the
    /// core refuses the call.
    pub begin: Duration,
    /// How long finish holds the caller's answer while it completes the row. Past it, finish
    /// fails, so the core answers a refusal with the audit-failure sentence, and the store
    /// keeps trying. Also the most one attempt may take.
    pub answer: Duration,
    /// How long, from the call to finish, the store keeps trying to complete the row.
    pub finish_deadline: Duration,
}

impl Budgets {
    /// The longest a finish, or the completion of a failed begin's row, stays in flight: the
    /// finish deadline, and then one answer budget for the last attempt to complete a failed
    /// begin's row, which is made at the deadline itself. A gateway shutting down waits this
    /// long for [`PgAuditStore::finishes`] to show none in flight, since none starts once it
    /// stops taking calls.
    #[must_use]
    pub fn shutdown_wait(&self) -> Duration {
        self.finish_deadline + self.answer
    }
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            begin: Duration::from_secs(2),
            answer: Duration::from_secs(2),
            finish_deadline: Duration::from_secs(30),
        }
    }
}

/// What has become of the finishes a store was given, and of the allowed rows whose begin
/// failed after its insert was executed, which the store completes as `error` on the finish
/// pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinishCounts {
    /// Still trying to complete their row.
    pub in_flight: usize,
    /// Stopped without completing their row: the deadline passed, the database or the store
    /// refused, or the task was dropped before it ended. Each such row, if it was written,
    /// keeps an empty outcome. A failed begin's row whose last attempt got no answer, or a
    /// refusal, is counted here even if its insert never committed: the store cannot tell.
    pub given_up: u64,
    /// Failed begins whose row the last attempt, made at the finish deadline, found missing:
    /// the insert had not committed by then, so there was nothing to complete. Not given up,
    /// and not reported.
    pub never_written: u64,
}

/// What the store counts, in atomics, so nothing on the begin or finish path waits to count.
#[derive(Default)]
struct Counters {
    in_flight: AtomicUsize,
    given_up: GivenUpCounters,
    never_written: AtomicU64,
    begin_failures: BeginFailureCounters,
    answers_released: AtomicU64,
    begin_latency: LatencyCounter,
    finish_latency: LatencyCounter,
}

/// [`GivenUpCauses`], as it is counted.
#[derive(Default)]
struct GivenUpCounters {
    deadline: AtomicU64,
    completed_differently: AtomicU64,
    no_such_row: AtomicU64,
    task_lost: AtomicU64,
    other: AtomicU64,
}

impl GivenUpCounters {
    /// Counts one finish given up because of `error`.
    fn count(&self, error: &PgAuditError) {
        let cause = match error {
            PgAuditError::Deadline { .. } => &self.deadline,
            PgAuditError::CompletedDifferently { .. } => &self.completed_differently,
            PgAuditError::NoSuchRow { .. } => &self.no_such_row,
            PgAuditError::FinishTaskLost { .. } => &self.task_lost,
            _ => &self.other,
        };
        cause.fetch_add(1, Ordering::SeqCst);
    }

    fn snapshot(&self) -> GivenUpCauses {
        GivenUpCauses {
            deadline: self.deadline.load(Ordering::SeqCst),
            completed_differently: self.completed_differently.load(Ordering::SeqCst),
            no_such_row: self.no_such_row.load(Ordering::SeqCst),
            task_lost: self.task_lost.load(Ordering::SeqCst),
            other: self.other.load(Ordering::SeqCst),
        }
    }
}

/// Why a begin failed, as [`BeginFailures`] counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BeginCause {
    BudgetExceeded,
    PoolTimeout,
    DatabaseError,
    ValueRefused,
}

/// [`BeginFailures`], as it is counted.
#[derive(Default)]
struct BeginFailureCounters {
    budget_exceeded: AtomicU64,
    pool_timeout: AtomicU64,
    database_error: AtomicU64,
    value_refused: AtomicU64,
}

impl BeginFailureCounters {
    fn count(&self, cause: BeginCause) {
        let counter = match cause {
            BeginCause::BudgetExceeded => &self.budget_exceeded,
            BeginCause::PoolTimeout => &self.pool_timeout,
            BeginCause::DatabaseError => &self.database_error,
            BeginCause::ValueRefused => &self.value_refused,
        };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn snapshot(&self) -> BeginFailures {
        BeginFailures {
            budget_exceeded: self.budget_exceeded.load(Ordering::SeqCst),
            pool_timeout: self.pool_timeout.load(Ordering::SeqCst),
            database_error: self.database_error.load(Ordering::SeqCst),
            value_refused: self.value_refused.load(Ordering::SeqCst),
        }
    }
}

/// Counts how long it was alive in a latency histogram when dropped, so a step whose caller
/// stops waiting for it is counted too.
struct Timed<'a> {
    histogram: &'a LatencyCounter,
    started: Instant,
}

impl<'a> Timed<'a> {
    fn start(histogram: &'a LatencyCounter) -> Self {
        Self {
            histogram,
            started: Instant::now(),
        }
    }
}

impl Drop for Timed<'_> {
    fn drop(&mut self) {
        self.histogram.record(self.started.elapsed());
    }
}

/// A begin or list that failed, with whether its last attempt had a connection: a budget that
/// ran out without one ran out getting a connection from the pool, whether waiting for a
/// permit or opening a new connection.
struct InsertFailed {
    error: PgAuditError,
    connected: bool,
}

impl InsertFailed {
    fn cause(&self) -> BeginCause {
        begin_cause(&self.error, self.connected)
    }
}

/// Why a begin failed with `error`; `connected` tells a budget that ran out before the last
/// attempt had a connection, whether waiting for a pool permit or opening a new connection,
/// from one that ran out with one in hand. Those two ways of having no connection are not told
/// apart, so a database that never answers counts as a pool timeout, as a pool too small for
/// the load does (#155).
fn begin_cause(error: &PgAuditError, connected: bool) -> BeginCause {
    match error {
        PgAuditError::BeginBudget { .. } if !connected => BeginCause::PoolTimeout,
        PgAuditError::BeginBudget { .. } => BeginCause::BudgetExceeded,
        PgAuditError::Pool(PoolError::Timeout(_)) => BeginCause::PoolTimeout,
        PgAuditError::Nul { .. }
        | PgAuditError::TooLong { .. }
        | PgAuditError::RowTooLarge { .. }
        | PgAuditError::Column(_)
        | PgAuditError::CompleteAtBegin => BeginCause::ValueRefused,
        _ => BeginCause::DatabaseError,
    }
}

/// How many of a pool's connections are open and in use. Reads the pool's status, which takes
/// the pool's own lock for a moment.
fn pool_stats(pool: &Pool) -> PoolStats {
    let status = pool.status();
    PoolStats {
        in_use: status.size.saturating_sub(status.available),
        size: status.size,
        max_size: status.max_size,
    }
}

/// A finish that stopped without completing its row, which keeps an empty outcome. Decision
/// 0009 makes each one a telemetry event naming the row and the outcome's kind. A row whose
/// begin failed after its insert was executed, and which the store could not complete as
/// `error`, is reported the same way, with the outcome `error`.
#[derive(Debug)]
pub struct GivenUp<'a> {
    /// The row finish named.
    pub row: &'a AuditRowId,
    /// The outcome it was to record: `ok`, `error` or `refused`.
    pub outcome: &'static str,
    /// Why it stopped: [`PgAuditError::Deadline`] when the deadline passed,
    /// [`PgAuditError::CompletedDifferently`] when the row already had another completion,
    /// [`PgAuditError::NoSuchRow`] when the row is not there,
    /// [`PgAuditError::FinishTaskLost`] when its task was dropped before it ended, as when the
    /// runtime shuts down, a completion the row cannot hold, or another refusal by the
    /// database. [`StoreStats::finishes_given_up`] counts each by the same causes.
    pub error: &'a PgAuditError,
}

/// What the store calls for each finish that gives up.
type Report = Arc<dyn Fn(GivenUp<'_>) + Send + Sync>;

/// Counts one finish in flight until dropped.
struct InFlight(Arc<Counters>);

impl InFlight {
    fn start(counters: &Arc<Counters>) -> Self {
        counters.in_flight.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counters))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Settles one finish: counts it in flight until dropped, and counts and reports it if it gives
/// up. A finish dropped before it was settled, because its task was dropped with the runtime,
/// gives up too, so no finish ends without a trace.
struct Settle {
    in_flight: InFlight,
    report: Report,
    row: AuditRowId,
    outcome: &'static str,
    settled: bool,
}

impl Settle {
    fn settle(mut self, result: &Result<(), PgAuditError>) {
        self.settled = true;
        if let Err(error) = result {
            self.give_up(error);
        }
    }

    /// Settles the completion of a failed begin's row that never appeared: nothing was
    /// written, so nothing is left open, and nothing is reported.
    fn never_written(mut self) {
        self.settled = true;
        self.in_flight
            .0
            .never_written
            .fetch_add(1, Ordering::SeqCst);
    }

    fn give_up(&self, error: &PgAuditError) {
        self.in_flight.0.given_up.count(error);
        (self.report)(GivenUp {
            row: &self.row,
            outcome: self.outcome,
            error,
        });
    }
}

impl Drop for Settle {
    fn drop(&mut self) {
        if !self.settled {
            self.give_up(&PgAuditError::FinishTaskLost {
                row: self.row.as_str().to_owned(),
            });
        }
    }
}

/// Asks the server to stop whatever a connection is running, over a connection of its own.
type Canceller = Arc<dyn Fn(CancelToken) -> BoxFuture<'static, ()> + Send + Sync>;

/// Every session the store opens commits synchronously, whatever the server, database or role
/// sets as its default: begin must not return before its row is durable. And it looks names up
/// in `pg_catalog` alone, then its own temporary schema, so a function, operator or type
/// another role made in a schema a database or role default puts first cannot stand in for
/// the catalog's own, in the store's statements or in the boot checks.
///
/// The settings travel in the startup packet's `options`, which a pooler may drop, so the boot
/// check reads each back from the session.
pub(crate) const SESSION_SETTINGS: &[(&str, &str)] = &[
    ("synchronous_commit", "on"),
    ("search_path", "pg_catalog,pg_temp"),
];

/// [`SESSION_SETTINGS`] as startup options.
const SESSION_OPTIONS: &str = "-c synchronous_commit=on -c search_path=pg_catalog,pg_temp";

/// The first pause between attempts to write or complete a row; each pause after doubles, up
/// to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_millis(50);
const LONGEST_PAUSE: Duration = Duration::from_secs(1);

/// The pause after `pause`.
fn longer(pause: Duration) -> Duration {
    (pause * 2).min(LONGEST_PAUSE)
}

/// How long a request to cancel a statement may take before the store stops asking.
pub(crate) const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// How long [`PgAuditStore::open_rows`] has, from asking for a connection to its answer.
pub(crate) const OPEN_ROWS_TIMEOUT: Duration = Duration::from_secs(2);

/// The connections [`PgAuditStore::open_rows`] has, in a pool of its own, so a query held up
/// for its whole time limit never takes a connection a finish could use. The gateway's poll
/// asks one query at a time, so a second connection would never be used, and the size is
/// fixed rather than a [`PoolSizes`] setting.
pub const OPEN_ROWS_POOL_SIZE: usize = 1;

/// The open rows (decision 0009, "Open rows"): allowed rows of kind `call` with no completion
/// past their deadline, by the database's clock. A denial and a list row are never open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenRows {
    /// How many rows are open.
    pub count: u64,
    /// The earliest deadline among them, or `None` when none is open.
    pub oldest_deadline: Option<SystemTime>,
}

/// The receipts in `unknown` (design section 11, "Signals"): those in the state `unknown`, and
/// those still `pending` past their row's deadline, which read as `unknown` wherever they are
/// read, by the database's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownReceipts {
    /// How many receipts are in `unknown`.
    pub count: u64,
    /// When the oldest of them was reserved, by the database's clock, or `None` when none is.
    /// Its age is the time since.
    pub oldest_reserved: Option<SystemTime>,
}

/// The query [`PgAuditStore::unknown_receipts`] runs: the receipts in `unknown`, and those
/// `pending` past their row's deadline by the database's clock, counted, with the earliest time
/// one of them was reserved. Every column it reads is one the gateway's role may select.
pub(crate) const UNKNOWN_RECEIPTS: &str =
    "SELECT count(*), min(r.reserved_at) FROM switchboard_audit.receipts r
         JOIN switchboard_audit.call_rows c ON c.id = r.row_id
     WHERE r.state = 'unknown' OR (r.state = 'pending' AND c.deadline < clock_timestamp())";

/// The SQLSTATE of the trigger `receipt_moves` refusing a move by the call only because its
/// row's deadline has passed, by the database's clock as it writes.
pub(crate) const RECEIPT_PAST_DEADLINE: &str = "SB001";

/// The core's [`AuditStore`] on Postgres, writing to `switchboard_audit.call_rows`.
///
/// Connect it as [`GATEWAY_ROLE`](crate::GATEWAY_ROLE), and call
/// [`check_at_boot`](Self::check_at_boot) before serving. The gateway chooses each row's
/// identifier, and the database sets both its times.
///
/// - Begin inserts the first half of a row and returns once the insert is committed. It has
///   [`Budgets::begin`], counted from asking for a connection. An attempt that fails in a way
///   trying again could fix, such as a broken connection or a server that has become
///   read-only, discards its connection, and begin tries again on a new one, under the same
///   identifier, after a pause that doubles each time and never runs past the budget. A retry
///   that finds the row stored with the same decision has found its own row, written by an
///   attempt whose confirmation was lost, and succeeds. Past the budget, begin fails, so the
///   core refuses the call, and the store asks the server to cancel an insert still running,
///   which stops one still waiting, for example on a lock.
/// - A begin reported as failed may still have written its row (decision 0009): an insert
///   that commits before its cancel arrives, or one whose confirmation was lost with its
///   connection. So when an allowed call's begin fails, and any of its attempts executed an
///   insert and then ran out of budget or failed in a way that trying again could fix, the
///   store completes the row as `error` with a latency of 0, on a task of its own on the
///   finish pool, until [`Budgets::finish_deadline`]. A later attempt's error, of whatever
///   kind, does not undo that. An attempt that never got as far as executing its insert, for
///   example one whose statement was still being prepared, counts for nothing. The error
///   that trying again could fix may be an explicit refusal, such as a read-only server's:
///   it starts the task too. Nothing ran, so the row overstates what ran rather than
///   understate it. The insert may still commit, so that task alone tries again while the
///   row is missing. It keeps trying until the deadline, each attempt ending by it, and
///   makes its last attempt at the deadline itself, with its full [`Budgets::answer`], so it
///   ends at most one answer budget after the deadline: [`Budgets::shutdown_wait`]. Only that
///   last attempt's answer ends the task. An earlier attempt may have found the row missing
///   just before the insert committed, so its answer does not stand for the deadline, however
///   late it came. A row the last attempt found missing had not been written by the deadline,
///   and is counted in [`FinishCounts::never_written`]. A row that could not be completed is
///   given up and reported, as a finish is, and so is one whose last attempt got no answer:
///   a database that stays unreachable, locked or read-only past the deadline leaves the
///   store unable to tell, so a refusal that lasts that long is reported even when no row
///   was written. A denial needs nothing: it is a complete record, which the
///   table's trigger never lets be completed. Nor does a list row, which is written complete.
/// - List writes a row of kind `list`, complete, with begin's pool, budget and handling of
///   an identifier already stored: a list row under it is this list's own, and a call row is
///   an error.
/// - Begin with a receipt, for an allowed call of a tool not classified `read`, is begin with
///   the same pool, budget and retries, in one transaction: the reuse check, then the row
///   open with its receipt reserved `pending`, or the row complete with the answer to its
///   reused key. The unique index on a key in its scope decides between two begins at once,
///   and the one that loses is answered from the other's receipt. A row it finds stored is a
///   retried begin's, answered as its receipt or the answer it was written with say: see
///   `found`. Nothing before the commit can write a row, so a begin with a receipt counts as
///   possibly written only once its commit was sent.
/// - Finish writes the completion columns of a row that has none, on a task of its own, in one
///   transaction with the move of the receipt the row reserved, if it reserved one, while the
///   row's deadline has not passed by the database's clock. After it, the row is completed and
///   the receipt left `pending`. It
///   waits for that task for [`Budgets::answer`], and fails if the row is not complete by
///   then. The task keeps trying, while the failure is one that trying again could fix, until
///   [`Budgets::finish_deadline`]. An attempt that fails that way gives up its connection,
///   so the next makes a new one: after a failover, an old connection may be to a server
///   that has become read-only. An identical completion written again is accepted, and a
///   different one is an error, so the first completion stands and retrying is safe. The
///   table's trigger holds the same rule for every role.
/// - A row is exactly its record, or it is not written. Begin refuses a record with U+0000 in
///   any text value, which Postgres cannot store, with [`PgAuditError::Nul`], so the core
///   refuses the call. Begin refuses a row over
///   [`MAX_BEGUN_ROW_BYTES`](crate::MAX_BEGUN_ROW_BYTES), and list one over
///   [`MAX_ROW_BYTES`](crate::MAX_ROW_BYTES), with [`PgAuditError::RowTooLarge`], naming its
///   largest column. Finish refuses a completion it cannot write exactly: a refusal sentence
///   holding U+0000, one longer than
///   [`MAX_OUTCOME_SENTENCE_BYTES`](crate::MAX_OUTCOME_SENTENCE_BYTES) with
///   [`PgAuditError::TooLong`], naming the column and the cap, or a latency past its column's
///   range. It sends nothing and fails at once; the finish is given up, counted under `other`
///   in [`StoreStats::finishes_given_up`] and reported, and the row keeps no completion, so
///   the open-row query counts it once its deadline passes. The core answers a refused call
///   whose finish failed with the audit-failure sentence. So a finished call row is within
///   `MAX_ROW_BYTES` too.
///
/// If the caller stops waiting for finish, its task still completes the row. If the runtime
/// drops the task first, the finish is counted and reported as given up. So is the task that
/// completes a failed begin's row, which [`finishes`](Self::finishes) counts in flight, so a
/// gateway shutting down waits for it too.
///
/// Must be used inside a Tokio runtime: finish, and a begin that fails after executing its
/// insert, spawn their tasks there.
pub struct PgAuditStore {
    pub(crate) begin: Pool,
    pub(crate) finish: Pool,
    /// The open-row query's own pool, of [`OPEN_ROWS_POOL_SIZE`].
    pub(crate) open_rows_pool: Pool,
    budgets: Budgets,
    cancel: Canceller,
    counters: Arc<Counters>,
    given_up: Report,
    /// Whether every begin from now on loses its confirmation after it commits, as the
    /// contract suite's runner tells it to.
    #[cfg(test)]
    pub(crate) lose_confirmations: AtomicBool,
}

impl PgAuditStore {
    /// A store that connects with `config` and `tls`, opening connections as they are first
    /// needed, with the default [`Budgets`]. Nothing connects here, so a database that is down
    /// is found by the first call, or by [`check_at_boot`](Self::check_at_boot).
    ///
    /// It has three pools: begin's and finish's, of `sizes`, and the open-row query's, of
    /// [`OPEN_ROWS_POOL_SIZE`]. Each session in each of them sets `synchronous_commit` to `on`
    /// and `search_path` to `pg_catalog, pg_temp`, after any options `config` carries.
    pub fn connect<T>(
        config: tokio_postgres::Config,
        tls: T,
        sizes: PoolSizes,
    ) -> Result<Self, PgAuditError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let mut config = config;
        let options = match config.get_options() {
            Some(existing) if !existing.is_empty() => format!("{existing} {SESSION_OPTIONS}"),
            _ => SESSION_OPTIONS.to_owned(),
        };
        config.options(options);
        let pool = |size: usize| {
            let manager = Manager::from_config(
                config.clone(),
                tls.clone(),
                ManagerConfig {
                    recycling_method: RecyclingMethod::Fast,
                },
            );
            Pool::builder(manager).max_size(size).build()
        };
        let begin = pool(sizes.begin)?;
        let finish = pool(sizes.finish)?;
        let open_rows_pool = pool(OPEN_ROWS_POOL_SIZE)?;
        let cancel: Canceller = Arc::new(move |token: CancelToken| {
            let tls = tls.clone();
            Box::pin(async move {
                // Best effort: if the cancel request fails, or the server does not answer it in
                // time, the statement runs to its end.
                let _ = tokio::time::timeout(CANCEL_WAIT, token.cancel_query(tls)).await;
            })
        });
        Ok(Self {
            begin,
            finish,
            open_rows_pool,
            budgets: Budgets::default(),
            cancel,
            counters: Arc::default(),
            given_up: Arc::new(|_| {}),
            #[cfg(test)]
            lose_confirmations: AtomicBool::new(false),
        })
    }

    /// The same store with `budgets` in place of the defaults.
    #[must_use]
    pub fn with_budgets(self, budgets: Budgets) -> Self {
        Self { budgets, ..self }
    }

    /// The same store, calling `report` for each finish that gives up, whether or not its
    /// caller is still waiting, so the gateway can make the telemetry event that names the row.
    /// Called on the finish's own task, so it must not block. By default nothing is called,
    /// and the finish is only counted in [`finishes`](Self::finishes).
    #[must_use]
    pub fn on_given_up(self, report: impl Fn(GivenUp<'_>) + Send + Sync + 'static) -> Self {
        Self {
            given_up: Arc::new(report),
            ..self
        }
    }

    /// The budgets this store keeps.
    pub fn budgets(&self) -> Budgets {
        self.budgets
    }

    /// How many finishes, and completions of failed begins' rows, are still trying, how many
    /// gave up, and how many found no row to complete. A gateway shutting down can wait for
    /// `in_flight` to reach zero; `given_up` is for its telemetry.
    pub fn finishes(&self) -> FinishCounts {
        FinishCounts {
            in_flight: self.counters.in_flight.load(Ordering::SeqCst),
            given_up: self.counters.given_up.snapshot().total(),
            never_written: self.counters.never_written.load(Ordering::SeqCst),
        }
    }

    /// What the store has counted since it was made, for the gateway's telemetry (decision
    /// 0009): begin failures by cause, answers released before their row was complete,
    /// finishes given up by cause, failed begins' rows never written, finishes in flight, the
    /// latency of begin and of finish, and the connections of the begin, finish and open-row
    /// pools. The counts are atomics, each read on its own; the pools' figures come from their
    /// status, which takes each pool's lock for a moment. Nothing here waits on the database.
    pub fn stats(&self) -> StoreStats {
        let finishes = self.finishes();
        StoreStats {
            begin_failures: self.counters.begin_failures.snapshot(),
            answers_released_before_finish: self.counters.answers_released.load(Ordering::SeqCst),
            finishes_given_up: self.counters.given_up.snapshot(),
            begins_never_committed: finishes.never_written,
            finishes_in_flight: finishes.in_flight,
            begin_latency: self.counters.begin_latency.snapshot(),
            finish_latency: self.counters.finish_latency.snapshot(),
            begin_pool: pool_stats(&self.begin),
            finish_pool: pool_stats(&self.finish),
            open_rows_pool: pool_stats(&self.open_rows_pool),
        }
    }

    /// Counts the open rows, and finds the earliest deadline among them, through the view
    /// `switchboard_audit.open_call_rows`. Runs on a pool of its own, of
    /// [`OPEN_ROWS_POOL_SIZE`], so a query held up never delays a finish. It has 2 s in all,
    /// from asking for its connection to the answer; past that, it fails, and if the query has
    /// started, asks the server to cancel it. Reads only: nothing marks a row abandoned or
    /// writes its outcome.
    pub async fn open_rows(&self) -> Result<OpenRows, PgAuditError> {
        let (count, oldest_deadline) = self
            .count_apart(
                "SELECT count(*), min(deadline) FROM switchboard_audit.open_call_rows",
                |budget| PgAuditError::OpenRowsTimedOut { budget },
            )
            .await?;
        Ok(OpenRows {
            count,
            oldest_deadline,
        })
    }

    /// Counts the receipts in `unknown`, and finds when the oldest of them was reserved: those
    /// in the state `unknown`, and those still `pending` past their row's deadline, by the
    /// database's clock (design section 11, "Signals"). As [`open_rows`](Self::open_rows), on
    /// the open-row query's pool of its own, within 2 s in all, and asking the server to cancel
    /// a query that runs past them. Reads only.
    pub async fn unknown_receipts(&self) -> Result<UnknownReceipts, PgAuditError> {
        let (count, oldest_reserved) = self
            .count_apart(UNKNOWN_RECEIPTS, |budget| {
                PgAuditError::UnknownReceiptsTimedOut { budget }
            })
            .await?;
        Ok(UnknownReceipts {
            count,
            oldest_reserved,
        })
    }

    /// Runs `query`, which answers one count and one time, on the open-row query's pool, within
    /// [`OPEN_ROWS_TIMEOUT`] from asking for the connection; past it, fails with what
    /// `timed_out` makes, and if the query has started, asks the server to cancel it.
    async fn count_apart(
        &self,
        query: &str,
        timed_out: impl Fn(Duration) -> PgAuditError,
    ) -> Result<(u64, Option<SystemTime>), PgAuditError> {
        let budget = OPEN_ROWS_TIMEOUT;
        let deadline = Instant::now() + budget;
        let client = timeout_at(deadline, self.open_rows_pool.get())
            .await
            .map_err(|_| timed_out(budget))??;
        let answer = timeout_at(deadline, client.query_one(query, &[])).await;
        match answer {
            Ok(row) => {
                let row = row?;
                let count: i64 = row.get(0);
                // count(*) is never negative.
                Ok((u64::try_from(count).unwrap_or_default(), row.get(1)))
            }
            Err(_) => {
                abandon(client, &self.cancel);
                Err(timed_out(budget))
            }
        }
    }

    /// The error a committed begin ends with when the test told this store to lose every begin's
    /// confirmation: its insert was sent, and its answer counts as not had. `None` otherwise,
    /// and always outside the crate's own tests.
    #[cfg(test)]
    fn confirmation_lost(&self, sent: &mut bool) -> Option<PgAuditError> {
        if !self.lose_confirmations.load(Ordering::SeqCst) {
            return None;
        }
        *sent = true;
        Some(PgAuditError::ConfirmationLost)
    }

    #[cfg(not(test))]
    fn confirmation_lost(&self, _sent: &mut bool) -> Option<PgAuditError> {
        None
    }

    /// Writes a call row's first half, with a receipt or the answer to its key or without
    /// either, or a list row, within the begin budget, on the begin pool, trying again by
    /// identifier while the failure is one that trying again could fix. What a begin with a
    /// receipt did is returned; for any other, `None`.
    async fn insert(&self, row: Insert) -> Result<Option<Reservation>, InsertFailed> {
        let deadline = Instant::now() + self.budgets.begin;
        // Whether an attempt executed its insert and ended without an answer, or with an error
        // trying again could fix, so that the row may exist. That error may be an explicit
        // refusal, such as a read-only server's. Once set it stays set: what a later attempt
        // finds does not undo an insert that may have committed.
        let mut may_be_written = false;
        let mut pause = FIRST_PAUSE;
        let failed = loop {
            let mut sent = false;
            let mut connected = false;
            let error = match self
                .insert_once(&row, deadline, &mut sent, &mut connected)
                .await
            {
                Ok(inserted) => match self.confirmation_lost(&mut sent) {
                    None => return Ok(inserted),
                    Some(lost) => lost,
                },
                Err(error) => error,
            };
            let unanswered =
                error.is_transient() || matches!(error, PgAuditError::BeginBudget { .. });
            may_be_written |= sent && unanswered;
            let failed = InsertFailed { error, connected };
            if !failed.error.is_transient() {
                break failed;
            }
            // The same row again, under the same identifier: if the last attempt committed,
            // the next finds that row rather than write a second.
            let now = Instant::now();
            sleep_until((now + pause).min(deadline)).await;
            if Instant::now() >= deadline {
                break failed;
            }
            pause = longer(pause);
        };
        // A denial is a complete record, and a list row is written complete: neither is left
        // open.
        if may_be_written
            && let Insert::Call(call) | Insert::WithReceipt { row: call, .. } = &row
            && call.decision == "allow"
        {
            self.complete_lost_begin(AuditRowId::new(call.id.clone()));
        }
        Err(failed)
    }

    /// One attempt at [`insert`](Self::insert), ending by `deadline`. Sets `connected` once it
    /// has a connection from the pool, and `sent` as the insert itself goes out, after its
    /// statement is prepared: a prepare cannot commit a row.
    async fn insert_once(
        &self,
        row: &Insert,
        deadline: Instant,
        sent: &mut bool,
        connected: &mut bool,
    ) -> Result<Option<Reservation>, PgAuditError> {
        let budget = self.budgets.begin;
        let mut client = timeout_at(deadline, self.begin.get())
            .await
            .map_err(|_| PgAuditError::BeginBudget { budget })??;
        *connected = true;
        let inserted = timeout_at(deadline, insert_on(&mut client, row, sent)).await;
        match inserted {
            Ok(Err(error)) if error.is_transient() => {
                // A failure trying again could fix may be the connection's own: one that found
                // the server read-only, as the old primary is after a failover, stays so. The
                // next attempt makes a new connection rather than fail on this one.
                drop(Object::take(client));
                Err(error)
            }
            Ok(inserted) => inserted,
            Err(_) => {
                abandon(client, &self.cancel);
                Err(PgAuditError::BeginBudget { budget })
            }
        }
    }

    /// Completes `row`, whose begin failed after its insert was executed, as `error` of the kind
    /// `other` with a latency of 0, as the core gives up a guard, on a task of its own on the
    /// finish pool, until the finish deadline. Counted in flight until it ends.
    fn complete_lost_begin(&self, row: AuditRowId) {
        let settle = Settle {
            in_flight: InFlight::start(&self.counters),
            report: Arc::clone(&self.given_up),
            row: row.clone(),
            outcome: "error",
            settled: false,
        };
        let task = Retry {
            pool: self.finish.clone(),
            cancel: Arc::clone(&self.cancel),
            row: row.as_str().to_owned(),
            // As the core gives up a guard: an error of the kind `other`, which settles a
            // receipt the row reserved as `not_performed`, since nothing ran.
            finish: FinishRow {
                outcome: "error",
                outcome_sentence: None,
                error_kind: Some(FinishRow::error_kind_name(ErrorKind::Other)),
                latency_ms: 0,
                settles: "not_performed",
                reference: None,
            },
            attempt: self.budgets.answer,
            deadline: Instant::now() + self.budgets.finish_deadline,
            row_may_commit: true,
        };
        tokio::spawn(async move {
            match task.run().await {
                Err(PgAuditError::Deadline { last, .. })
                    if matches!(*last, PgAuditError::NoSuchRow { .. }) =>
                {
                    settle.never_written();
                }
                result => settle.settle(&result),
            }
        });
    }

    /// Completes `row` in one attempt, on a connection from the finish pool, with no budget.
    /// For tests, which cannot make the core's completion for a row of their own choosing.
    #[cfg(test)]
    pub(crate) async fn complete(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> Result<(), PgAuditError> {
        let mut client = self.finish.get().await?;
        complete_on(
            &mut client,
            row.as_str(),
            &FinishRow::from_completion(completion)?,
        )
        .await
    }

    /// Finish with no vendor reference, for tests, which cannot make the core's completion for
    /// a row of their own choosing.
    #[cfg(test)]
    pub(crate) async fn finish_within_budget(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> Result<(), PgAuditError> {
        self.finish_with_reference(row, completion, None).await
    }

    /// Finish, as [`AuditStore::finish`] describes it, with the vendor's `reference` for the
    /// row's receipt.
    async fn finish_with_reference(
        &self,
        row: &AuditRowId,
        completion: &Completion,
        reference: Option<&VendorReference>,
    ) -> Result<(), PgAuditError> {
        let _timed = Timed::start(&self.counters.finish_latency);
        let started = Instant::now();
        let settle = Settle {
            in_flight: InFlight::start(&self.counters),
            report: Arc::clone(&self.given_up),
            row: row.clone(),
            outcome: FinishRow::outcome_of(completion),
            settled: false,
        };
        let finish = match FinishRow::from_completion(completion)
            .and_then(|finish| finish.with_reference(reference))
        {
            Ok(finish) => finish,
            Err(error) => {
                let result = Err(error);
                settle.settle(&result);
                return result;
            }
        };
        let task = Retry {
            pool: self.finish.clone(),
            cancel: Arc::clone(&self.cancel),
            row: row.as_str().to_owned(),
            finish,
            attempt: self.budgets.answer,
            deadline: started + self.budgets.finish_deadline,
            row_may_commit: false,
        };
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let result = task.run().await;
            settle.settle(&result);
            // The caller may have stopped waiting, after the answer budget.
            let _ = sender.send(result);
        });
        let answer_by = started + self.budgets.answer;
        match timeout_at(answer_by, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PgAuditError::FinishTaskLost {
                row: row.as_str().to_owned(),
            }),
            Err(_) => {
                // The caller has its answer, and the task goes on trying.
                self.counters
                    .answers_released
                    .fetch_add(1, Ordering::SeqCst);
                Err(PgAuditError::AnswerBudget {
                    row: row.as_str().to_owned(),
                    budget: self.budgets.answer,
                })
            }
        }
    }

    /// Begin, counted: its latency, whether it succeeds or fails, and the cause of a failure.
    async fn begin_counted(
        &self,
        row: &AuditRowId,
        record: &AuditRecord,
    ) -> Result<(), PgAuditError> {
        self.begin_counted_with(row, record, None).await.map(|_| ())
    }

    /// Begin, with a receipt to reserve or not, counted: its latency, whether it succeeds or
    /// fails, and the cause of a failure.
    async fn begin_counted_with(
        &self,
        row: &AuditRowId,
        record: &AuditRecord,
        receipt: Option<&ReceiptRequest>,
    ) -> Result<Option<Reservation>, PgAuditError> {
        let _timed = Timed::start(&self.counters.begin_latency);
        let insert = BeginRow::from_record(row, record, &self.budgets).and_then(|begun| {
            Ok(match receipt {
                None => Insert::Call(Box::new(begun)),
                Some(request) => Insert::WithReceipt {
                    receipt: Box::new(ReceiptRow::from_request(row, request)?),
                    request: Box::new(request.clone()),
                    row: Box::new(begun),
                },
            })
        });
        let begun = match insert {
            Ok(insert) => self.insert(insert).await,
            Err(error) => Err(InsertFailed {
                error,
                connected: false,
            }),
        };
        if let Err(failed) = &begun {
            self.counters.begin_failures.count(failed.cause());
        }
        begun.map_err(|failed| failed.error)
    }
}

/// What [`PgAuditStore::insert`] writes.
enum Insert {
    /// The first half of a call row, for begin. Each is boxed: they differ much in size.
    Call(Box<BeginRow>),
    /// The first half of an allowed call row of a tool not classified `read`, and the receipt
    /// it reserves, or the answer to its key, in one transaction: begin with a receipt.
    WithReceipt {
        row: Box<BeginRow>,
        receipt: Box<ReceiptRow>,
        request: Box<ReceiptRequest>,
    },
    /// A list row, complete.
    List(Box<ListRow>),
}

/// Writes `row`, as begin, begin with a receipt, or list. Sets `sent` just before the insert,
/// or the transaction holding it, may commit: from then on it may have, whatever answer comes
/// back, or none.
async fn insert_on(
    client: &mut ClientWrapper,
    row: &Insert,
    sent: &mut bool,
) -> Result<Option<Reservation>, PgAuditError> {
    match row {
        Insert::Call(row) => begin_on(client, row, sent).await.map(|()| None),
        Insert::WithReceipt {
            row,
            receipt,
            request,
        } => begin_with_receipt_on(client, row, receipt, request, sent)
            .await
            .map(Some),
        Insert::List(row) => list_on(client, row, sent).await.map(|()| None),
    }
}

/// Begins an allowed call of a tool not classified `read` (decision 0009, part 2), in one
/// transaction:
///
/// 1. The reuse check: a receipt for the key in its scope reserved under another row. One
///    under this row is passed over, so a retried begin never refuses itself.
/// 2. With none, the row is inserted open and the receipt reserved under it. If another begin
///    reserved the key since the check, the unique index has made this reservation wait for
///    that one to commit and then insert nothing: the transaction is undone, and made again
///    from the check, which now finds that receipt.
/// 3. With one, the row is inserted complete, with the answer to the reused key, and nothing is
///    reserved.
///
/// A row already stored under the identifier is a retried begin's, and is answered as
/// [`found`] says. Sets `sent` just before the transaction commits: nothing before that can
/// have written a row.
async fn begin_with_receipt_on(
    client: &mut ClientWrapper,
    row: &BeginRow,
    receipt: &ReceiptRow,
    request: &ReceiptRequest,
    sent: &mut bool,
) -> Result<Reservation, PgAuditError> {
    if row.decision != "allow" {
        return Err(PgAuditError::ReceiptForDenial {
            row: row.id.clone(),
        });
    }
    // At most twice: the second time, the check finds the receipt that the first lost to.
    for _ in 0..2 {
        let transaction = client.transaction().await?;
        let earlier = reuse_check(&transaction, receipt, request).await?;
        let Some(earlier) = earlier else {
            let statement = transaction.prepare_cached(BeginRow::INSERT).await?;
            let inserted = transaction.execute(&statement, &row.parameters()).await?;
            if inserted == 0 {
                return found(&transaction, row, request, None).await;
            }
            let statement = transaction.prepare_cached(ReceiptRow::RESERVE).await?;
            let reserved = transaction
                .execute(&statement, &receipt.parameters())
                .await?;
            if reserved == 1 {
                *sent = true;
                transaction.commit().await?;
                return Ok(Reservation::Reserved);
            }
            // Another begin holds the key now: this row is not written open.
            transaction.rollback().await?;
            continue;
        };
        let reuse = gateway_core::Reuse::answer(request, &earlier);
        let answer = AnswerRow::from_reuse(&reuse)?;
        let statement = transaction
            .prepare_cached(BeginRow::INSERT_ANSWERED)
            .await?;
        let inserted = transaction
            .execute(&statement, &row.answered_parameters(&answer))
            .await?;
        if inserted == 0 {
            return found(&transaction, row, request, Some(&earlier)).await;
        }
        *sent = true;
        transaction.commit().await?;
        return Ok(Reservation::Reused(reuse));
    }
    Err(PgAuditError::KeyContended {
        row: row.id.clone(),
    })
}

/// The reuse check, in `transaction`: the receipt for `receipt`'s key in its scope reserved
/// under a row other than its own, if there is one, as [`Reuse::answer`](gateway_core::Reuse::answer)
/// reads it. Each statement in a transaction at read committed sees what had committed when it
/// began, so a check made after a reservation that lost its key sees the receipt it lost to.
async fn reuse_check(
    transaction: &Transaction<'_>,
    receipt: &ReceiptRow,
    request: &ReceiptRequest,
) -> Result<Option<Receipt>, PgAuditError> {
    let (query, parameters) = receipt.earlier();
    let statement = transaction.prepare_cached(query).await?;
    transaction
        .query_opt(&statement, &parameters)
        .await?
        .map(|earlier| earlier_receipt(request, &earlier))
        .transpose()
}

/// What a begin with a receipt answers for a row already stored under its identifier, which an
/// earlier attempt wrote, or something else did. Read in `transaction`, which writes nothing:
///
/// - A row of another kind or decision is refused, as at a begin without a receipt.
/// - A row the reuse check answered, from the receipt `earlier`, is answered with the answer it
///   was written with: the one of the five for that receipt whose completion it holds,
///   whatever has become of the receipt since. A row holding none of them is refused.
/// - Otherwise its own receipt decides: [`Reservation::Reserved`] while it is `pending`, and
///   refused once it has left `pending`, since its call has run or has been settled without
///   running. A row with no receipt was begun without one, and is refused.
async fn found(
    transaction: &Transaction<'_>,
    row: &BeginRow,
    request: &ReceiptRequest,
    earlier: Option<&Receipt>,
) -> Result<Reservation, PgAuditError> {
    let id = || row.id.clone();
    let statement = transaction.prepare_cached(BeginRow::STORED).await?;
    let Some(stored) = transaction.query_opt(&statement, &[&row.id]).await? else {
        return Err(PgAuditError::NoSuchRow { row: id() });
    };
    let decision: Option<String> = stored.try_get(0)?;
    match decision {
        None => return Err(PgAuditError::OtherKind { row: id() }),
        Some(decision) if decision != row.decision => {
            return Err(PgAuditError::BegunDifferently { row: id() });
        }
        Some(_) => {}
    }
    if let Some(earlier) = earlier {
        let outcome: Option<String> = stored.try_get(1)?;
        let sentence: Option<String> = stored.try_get(2)?;
        let latency_ms: Option<i64> = stored.try_get(3)?;
        let duplicate_of: Option<String> = stored.try_get(4)?;
        for reuse in answers(request, earlier) {
            let answer = AnswerRow::from_reuse(&reuse)?;
            if answer.is(
                outcome.as_deref(),
                sentence.as_deref(),
                latency_ms,
                duplicate_of.as_deref(),
            ) {
                return Ok(Reservation::Reused(reuse));
            }
        }
        return Err(PgAuditError::AnsweredDifferently { row: id() });
    }
    let statement = transaction.prepare_cached(ReceiptRow::STATE).await?;
    match transaction.query_opt(&statement, &[&row.id]).await? {
        None => Err(PgAuditError::BegunWithoutReceipt { row: id() }),
        Some(own) if own.try_get::<_, &str>(0)? == "pending" => Ok(Reservation::Reserved),
        Some(_) => Err(PgAuditError::ReceiptSettled { row: id() }),
    }
}

/// Inserts the first half of a row under its identifier, unless that row is already stored.
/// A row already stored with the same decision is this begin's own, written by an earlier
/// attempt, which is success; one with another decision is not, and nor is a list row, which
/// has none.
async fn begin_on(
    client: &ClientWrapper,
    row: &BeginRow,
    sent: &mut bool,
) -> Result<(), PgAuditError> {
    let statement = client.prepare_cached(BeginRow::INSERT).await?;
    *sent = true;
    let inserted = client.execute(&statement, &row.parameters()).await?;
    if inserted == 1 {
        return Ok(());
    }
    let statement = client.prepare_cached(BeginRow::DECISION).await?;
    let Some(stored) = client.query_opt(&statement, &[&row.id]).await? else {
        // Nothing was inserted and nothing is stored: the gateway's role cannot delete, so
        // only another role could have removed it in between.
        return Err(PgAuditError::NoSuchRow {
            row: row.id.clone(),
        });
    };
    let decision: Option<String> = stored.try_get(0)?;
    let Some(decision) = decision else {
        return Err(PgAuditError::OtherKind {
            row: row.id.clone(),
        });
    };
    if decision == row.decision {
        Ok(())
    } else {
        Err(PgAuditError::BegunDifferently {
            row: row.id.clone(),
        })
    }
}

/// Inserts a list row under its identifier, unless that row is already stored. A list row
/// already stored is this list's own, written by an earlier attempt, which is success; a call
/// row is not.
async fn list_on(
    client: &ClientWrapper,
    row: &ListRow,
    sent: &mut bool,
) -> Result<(), PgAuditError> {
    let statement = client.prepare_cached(ListRow::INSERT).await?;
    *sent = true;
    let inserted = client.execute(&statement, &row.parameters()).await?;
    if inserted == 1 {
        return Ok(());
    }
    let statement = client.prepare_cached(ListRow::KIND).await?;
    let Some(stored) = client.query_opt(&statement, &[&row.id]).await? else {
        return Err(PgAuditError::NoSuchRow {
            row: row.id.clone(),
        });
    };
    let kind: String = stored.try_get(0)?;
    if kind == "list" {
        Ok(())
    } else {
        Err(PgAuditError::OtherKind {
            row: row.id.clone(),
        })
    }
}

/// Writes the completion of `row` if it has none, and otherwise checks the one it has.
async fn complete_on(
    client: &mut ClientWrapper,
    row: &str,
    finish: &FinishRow,
) -> Result<(), PgAuditError> {
    match complete_in_transaction(client, row, finish).await {
        // The row's deadline passed between the settle's own test of it and the trigger's, by
        // the database's clock, and the trigger refused the move. Made again, the settle finds
        // the deadline passed, and completes the row with its receipt left `pending`.
        Err(PgAuditError::Database(error))
            if error.code().map(|code| code.code()) == Some(RECEIPT_PAST_DEADLINE) =>
        {
            complete_in_transaction(client, row, finish).await
        }
        completed => completed,
    }
}

/// [`complete_on`], once, in one transaction: the row's completion, and the move of the receipt
/// it reserved, if it reserved one, to the state the outcome settles it in, with the vendor's
/// reference, while it is `pending` and the row's deadline has not passed
/// ([`ReceiptRow::SETTLE`]). A receipt already settled, or past the deadline, is left as it
/// is, and the row is completed all the same. `unknown`, or a reference, for a row that
/// reserved no receipt is refused, and nothing is written.
///
/// The settle is made whenever the update completed the row, not only when the first read
/// found a receipt: at read committed each statement sees what had committed when it began, so
/// a lost begin whose row and receipt commit after that read and before the update has its row
/// completed here, and its receipt is seen by the settle. For a row with no receipt the settle
/// matches nothing.
async fn complete_in_transaction(
    client: &mut ClientWrapper,
    row: &str,
    finish: &FinishRow,
) -> Result<(), PgAuditError> {
    let transaction = client.transaction().await?;
    let statement = transaction.prepare_cached(ReceiptRow::STATE).await?;
    let reserved = transaction.query_opt(&statement, &[&row]).await?.is_some();
    if !reserved {
        let what = if finish.outcome == "unknown" {
            Some("its outcome cannot be unknown")
        } else if finish.reference.is_some() {
            Some("it has no vendor reference to keep")
        } else {
            None
        };
        if let Some(what) = what {
            return Err(PgAuditError::NoReceipt {
                row: row.to_owned(),
                what,
            });
        }
    }
    let statement = transaction.prepare_cached(FinishRow::UPDATE).await?;
    let updated = transaction
        .execute(
            &statement,
            &[
                &row,
                &finish.outcome,
                &finish.outcome_sentence,
                &finish.error_kind,
                &finish.latency_ms,
            ],
        )
        .await?;
    if updated == 1 {
        let statement = transaction.prepare_cached(ReceiptRow::SETTLE).await?;
        transaction
            .execute(&statement, &[&row, &finish.settles, &finish.reference])
            .await?;
        transaction.commit().await?;
        return Ok(());
    }
    // Nothing matched: the row is missing, or already complete. A retried finish whose
    // first attempt was written finds its own completion, which is success. Nothing is written,
    // and the transaction is undone as it is dropped.
    let statement = transaction.prepare_cached(FinishRow::SELECT).await?;
    let Some(existing) = transaction.query_opt(&statement, &[&row]).await? else {
        return Err(PgAuditError::NoSuchRow {
            row: row.to_owned(),
        });
    };
    let outcome: Option<String> = existing.try_get(0)?;
    let outcome_sentence: Option<String> = existing.try_get(1)?;
    let error_kind: Option<String> = existing.try_get(2)?;
    let latency_ms: Option<i64> = existing.try_get(3)?;
    match outcome {
        Some(outcome)
            if finish.is(
                &outcome,
                outcome_sentence.as_deref(),
                error_kind.as_deref(),
                latency_ms,
            ) =>
        {
            Ok(())
        }
        Some(_) => Err(PgAuditError::CompletedDifferently {
            row: row.to_owned(),
        }),
        // The update and this select each see what had committed when they began, so a row
        // whose insert committed in between is seen here and was not seen by the update.
        None => Err(PgAuditError::NotCompleted {
            row: row.to_owned(),
        }),
    }
}

/// Gives up on a connection whose statement ran out of time: asks the server to cancel the
/// statement, so that one still waiting does not go on to write after the caller was told it
/// failed, and takes the connection out of its pool, so no later call waits behind it. The
/// cancel does not wait, and does not undo a statement that has already finished.
fn abandon(client: Object, cancel: &Canceller) {
    tokio::spawn(cancel(client.cancel_token()));
    drop(Object::take(client));
}

/// The task that completes one row, trying again until its deadline.
struct Retry {
    pool: Pool,
    cancel: Canceller,
    row: String,
    finish: FinishRow,
    attempt: Duration,
    deadline: Instant,
    /// The row's begin failed after executing its insert, which may yet commit. So a missing
    /// row is waited for, and attempts go on until the deadline, each ending by it, and then
    /// one more at the deadline itself, which the deadline does not cut short. For a finish
    /// the row was begun, and a missing one is final.
    row_may_commit: bool,
}

impl Retry {
    async fn run(self) -> Result<(), PgAuditError> {
        let mut pause = FIRST_PAUSE;
        loop {
            let started = Instant::now();
            // A completion of a failed begin's row makes its last attempt at the deadline, with
            // its full answer budget: an insert that committed by then is completed, and the
            // task ends with that attempt's own answer, so a row never written is told apart
            // from one that could not be completed. Every attempt before it, like each of a
            // finish's, ends by the deadline, so the task ends at most one answer budget after
            // the deadline.
            let last = self.row_may_commit && started >= self.deadline;
            let by = if last {
                started + self.attempt
            } else {
                (started + self.attempt).min(self.deadline)
            };
            let error = match self.once(by).await {
                Ok(()) => return Ok(()),
                // A failed begin's row may commit late: it is missing, or the update did not
                // see it.
                Err(
                    error @ (PgAuditError::NoSuchRow { .. } | PgAuditError::NotCompleted { .. }),
                ) if self.row_may_commit => error,
                Err(error) if !error.is_transient() => return Err(error),
                Err(error) => error,
            };
            let deadline_passed = || PgAuditError::Deadline {
                row: self.row.clone(),
                last: Box::new(error),
            };
            // Only the attempt started at the deadline ends a completion of a failed begin's
            // row. An earlier one that found the row missing may have looked just before the
            // insert committed, however late its answer came, so the attempt at the deadline
            // still follows it.
            if last {
                return Err(deadline_passed());
            }
            sleep_until((Instant::now() + pause).min(self.deadline)).await;
            // A finish stops when an attempt or a pause reaches its deadline: an attempt started
            // there would be cut short at once.
            if !self.row_may_commit && Instant::now() >= self.deadline {
                return Err(deadline_passed());
            }
            pause = longer(pause);
        }
    }

    /// One attempt, which ends by `by`.
    async fn once(&self, by: Instant) -> Result<(), PgAuditError> {
        let mut client = timeout_at(by, self.pool.get())
            .await
            .map_err(|_| PgAuditError::AttemptTimedOut)??;
        let completed = timeout_at(by, complete_on(&mut client, &self.row, &self.finish)).await;
        match completed {
            Ok(Err(error)) if error.is_transient() => {
                // The next attempt makes a connection of its own. This one may be to a server
                // that has become a read-only standby, which every attempt on it would find.
                drop(Object::take(client));
                Err(error)
            }
            Ok(completed) => completed,
            Err(_) => {
                abandon(client, &self.cancel);
                Err(PgAuditError::AttemptTimedOut)
            }
        }
    }
}

impl AuditStore for PgAuditStore {
    fn begin<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.begin_counted(row, record)
                .await
                .map_err(StoreError::from)
        })
    }

    fn begin_with_receipt<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
        receipt: &'a ReceiptRequest,
    ) -> BoxFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(async move {
            match self.begin_counted_with(row, record, Some(receipt)).await {
                Ok(Some(reservation)) => Ok(reservation),
                Ok(None) => Err(StoreError::from("a begin with a receipt reserved nothing")),
                Err(error) => Err(StoreError::from(error)),
            }
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.finish_with_reference(
                completion.row(),
                completion.completion(),
                completion.reference(),
            )
            .await
            .map_err(StoreError::from)
        })
    }

    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let row = ListRow::from_record(row, record)?;
            self.insert(Insert::List(Box::new(row)))
                .await
                .map(|_| ())
                .map_err(|failed| StoreError::from(failed.error))
        })
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn the_default_budgets_are_two_two_and_thirty_seconds() {
        assert_eq!(
            Budgets::default(),
            Budgets {
                begin: Duration::from_secs(2),
                answer: Duration::from_secs(2),
                finish_deadline: Duration::from_secs(30),
            }
        );
    }

    #[test]
    fn the_session_options_set_each_session_setting() {
        let spelled: Vec<String> = SESSION_SETTINGS
            .iter()
            .map(|(name, value)| format!("-c {name}={value}"))
            .collect();
        assert_eq!(SESSION_OPTIONS, spelled.join(" "));
    }

    #[test]
    fn only_failures_that_trying_again_could_fix_are_retried() {
        assert!(PgAuditError::AttemptTimedOut.is_transient());
        for final_error in [
            PgAuditError::NoSuchRow { row: "r".into() },
            PgAuditError::CompletedDifferently { row: "r".into() },
            PgAuditError::NotCompleted { row: "r".into() },
            PgAuditError::BegunDifferently { row: "r".into() },
            PgAuditError::Pool(PoolError::Closed),
            PgAuditError::Column("x"),
        ] {
            assert!(!final_error.is_transient(), "{final_error}");
        }
    }

    /// A loopback port that refuses connections, held for as long as this lives. Keep it for
    /// as long as the test connects to the port: once it is dropped, nothing holds the port for
    /// this test, and another test in the same binary may listen on it.
    #[must_use = "the port is held only while this lives"]
    struct ClosedPort {
        port: u16,
        _held: socket2::Socket,
        _peer: std::net::TcpStream,
    }

    /// A port on this machine that nothing listens on. A port that was only read and released
    /// could be taken meanwhile by another test's server, which would then answer this test's
    /// connections (#179). So a socket holds it: bound to it without SO_REUSEADDR, and
    /// connected to a peer of its own. A connection to a port with no listener is refused, on
    /// Linux and macOS alike; a socket bound and never listening would do on Linux, but macOS
    /// drops a connection to one. While it lives, Linux lets no other socket bind the port.
    /// macOS still lets one that sets SO_REUSEADDR bind it by number, but it hands out the
    /// ports for port 0, which the tests' servers bind, in order, and skips this one.
    fn closed_port() -> ClosedPort {
        use socket2::{Domain, Protocol, Type};
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let held = socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let any: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        held.bind(&any.into()).unwrap();
        held.connect(&peer.local_addr().unwrap().into()).unwrap();
        let (accepted, _) = peer.accept().unwrap();
        let port = held
            .local_addr()
            .unwrap()
            .as_socket()
            .expect("an IPv4 address")
            .port();
        ClosedPort {
            port,
            _held: held,
            _peer: accepted,
        }
    }

    /// #179: a closed port refuses connections, and stays reserved while its guard lives: no
    /// socket that does not set SO_REUSEADDR can bind it, and on Linux, where CI runs, not
    /// even one that does, as std's and tokio's listeners do for the tests' servers.
    #[test]
    fn a_closed_port_refuses_connections_and_stays_reserved_while_held() {
        let closed = closed_port();
        let address: std::net::SocketAddr = ([127, 0, 0, 1], closed.port).into();
        let error =
            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "{error}"
        );
        let plain =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        assert!(
            plain.bind(&address.into()).is_err(),
            "another socket bound the held port {}",
            closed.port
        );
        if cfg!(target_os = "linux") {
            assert!(
                std::net::TcpListener::bind(address).is_err(),
                "a listener bound the held port {}",
                closed.port
            );
        }
    }

    /// A server that answers a client's startup as if it had logged it in, and then says
    /// nothing more.
    async fn server_that_lets_anyone_in() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let length = socket.read_u32().await.unwrap();
            let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
            socket.read_exact(&mut startup).await.unwrap();
            // AuthenticationOk, then ReadyForQuery.
            socket
                .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                .await
                .unwrap();
            let mut rest = Vec::new();
            let _ = socket.read_to_end(&mut rest).await;
        });
        port
    }

    #[tokio::test]
    async fn a_connection_that_broke_or_was_never_made_is_retried() {
        // No SQLSTATE: the connection to the server was closed.
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(server_that_lets_anyone_in().await)
            .user("nobody")
            .ssl_mode(tokio_postgres::config::SslMode::Disable);
        let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        drop(connection);
        let closed = client.simple_query("SELECT 1").await.unwrap_err();
        assert!(closed.is_closed() && closed.code().is_none(), "{closed}");
        assert!(PgAuditError::Database(closed).is_transient());

        // No SQLSTATE: the socket failed.
        let closed = closed_port();
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(closed.port).user("nobody");
        let Err(refused) = config.connect(tokio_postgres::NoTls).await else {
            panic!("a port nothing listens on took a connection");
        };
        assert!(
            !refused.is_closed() && refused.code().is_none(),
            "{refused}"
        );
        assert!(PgAuditError::Database(refused).is_transient());
    }

    /// A server that takes each connection and closes it at once, keeping when it took each.
    async fn server_that_closes_every_connection() -> (u16, Arc<std::sync::Mutex<Vec<Instant>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                kept.lock().unwrap().push(Instant::now());
                drop(socket);
            }
        });
        (port, accepted)
    }

    /// While every attempt fails at once, finish pauses between attempts for twice as long each
    /// time, but never longer than [`LONGEST_PAUSE`], so a database back near the deadline is
    /// still tried; and no pause runs past the deadline, so finish gives up at it. Needs no
    /// server: the one here closes every connection it takes.
    #[tokio::test]
    async fn finish_pauses_at_most_the_longest_pause_and_gives_up_at_its_deadline() {
        let (port, accepted) = server_that_closes_every_connection().await;
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(port).user("nobody");
        // The last attempt before the deadline comes about 4.55 s in, after pauses of 50, 100,
        // 200, 400 and 800 ms and then 1 s each. A pause after it that ran its full second
        // would end 0.75 s past the deadline.
        let deadline = Duration::from_millis(4800);
        let given_up_at = Arc::new(std::sync::Mutex::new(None));
        let kept = Arc::clone(&given_up_at);
        let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())
            .unwrap()
            .with_budgets(Budgets {
                answer: Duration::from_millis(500),
                finish_deadline: deadline,
                ..Budgets::default()
            })
            .on_given_up(move |_| *kept.lock().unwrap() = Some(Instant::now()));
        let row = AuditRowId::new("00000000-0000-4000-8000-000000000000");
        let completion = Completion {
            outcome: gateway_core::audit::Outcome::Ok,
            latency_ms: 1,
        };

        let started = Instant::now();
        let error = store
            .finish_within_budget(&row, &completion)
            .await
            .unwrap_err();
        assert!(
            matches!(error, PgAuditError::AnswerBudget { .. }),
            "{error}"
        );
        while store.finishes().in_flight > 0 {
            assert!(started.elapsed() < deadline + Duration::from_secs(3));
            sleep_until(Instant::now() + Duration::from_millis(10)).await;
        }
        let given_up = given_up_at.lock().unwrap().unwrap() - started;
        assert!(given_up >= deadline, "{given_up:?}");
        assert!(
            given_up < deadline + Duration::from_millis(350),
            "gave up {given_up:?} after it began"
        );

        let accepted = accepted.lock().unwrap().clone();
        assert!(accepted.len() >= 9, "{} attempts", accepted.len());
        for pair in accepted.windows(2) {
            let pause = pair[1] - pair[0];
            assert!(
                pause < LONGEST_PAUSE + Duration::from_millis(300),
                "a pause of {pause:?} between attempts"
            );
        }
    }

    /// A finish whose task is dropped with its runtime, before it ends, is counted and
    /// reported as given up, as the gateway's telemetry needs. Needs no server: the store
    /// keeps trying a port nothing listens on.
    #[test]
    fn a_finish_dropped_with_its_runtime_is_reported() {
        let closed = closed_port();
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(closed.port).user("nobody");
        let reports = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = Arc::clone(&reports);
        let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())
            .unwrap()
            .with_budgets(Budgets {
                answer: Duration::from_millis(100),
                finish_deadline: Duration::from_secs(600),
                ..Budgets::default()
            })
            .on_given_up(move |given_up| {
                kept.lock().unwrap().push((
                    given_up.row.as_str().to_owned(),
                    given_up.outcome,
                    given_up.error.to_string(),
                ));
            });
        let row = AuditRowId::new("00000000-0000-4000-8000-000000000000");
        let completion = Completion {
            outcome: gateway_core::audit::Outcome::Error {
                error_kind: ErrorKind::Other,
            },
            latency_ms: 1,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(store.finish_within_budget(&row, &completion))
            .unwrap_err();
        assert!(
            matches!(error, PgAuditError::AnswerBudget { .. }),
            "{error}"
        );
        assert_eq!(
            store.finishes(),
            FinishCounts {
                in_flight: 1,
                given_up: 0,
                never_written: 0
            }
        );

        drop(runtime);
        assert_eq!(
            store.finishes(),
            FinishCounts {
                in_flight: 0,
                given_up: 1,
                never_written: 0
            }
        );
        assert_eq!(
            store.stats().finishes_given_up,
            GivenUpCauses {
                task_lost: 1,
                ..GivenUpCauses::default()
            }
        );
        let lost = PgAuditError::FinishTaskLost {
            row: row.as_str().to_owned(),
        };
        assert_eq!(
            reports.lock().unwrap().clone(),
            vec![(row.as_str().to_owned(), "error", lost.to_string())]
        );
    }

    /// The begin budget of the stores below, which never write a row: long enough that an
    /// attempt on a connection that breaks at once, and the pause after it, end well inside it.
    const BEGIN_BUDGET: Duration = Duration::from_secs(1);

    /// A server that takes each connection and never says anything, so opening a connection
    /// to it never ends, as to a database behind a blackholed address. Told to, it first lets
    /// one connection in, as [`server_that_lets_anyone_in`] does, and closes it when the client
    /// first sends anything more, so that connection breaks. Counts the connections it took,
    /// and holds the silent ones open.
    async fn server_that_never_answers(break_one_first: bool) -> (u16, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let kept = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut silent = Vec::new();
            while let Ok((mut socket, _)) = listener.accept().await {
                let first = kept.fetch_add(1, Ordering::SeqCst) == 0;
                if !(first && break_one_first) {
                    silent.push(socket);
                    continue;
                }
                let length = socket.read_u32().await.unwrap();
                let mut startup = vec![0; usize::try_from(length).unwrap() - 4];
                socket.read_exact(&mut startup).await.unwrap();
                // AuthenticationOk, then ReadyForQuery.
                socket
                    .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                    .await
                    .unwrap();
                let _ = socket.read_u8().await;
                drop(socket);
            }
        });
        (port, accepted)
    }

    /// A store whose pools connect to `port` on this machine, with [`BEGIN_BUDGET`].
    fn store_at(port: u16) -> PgAuditStore {
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(port).user("nobody");
        PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())
            .unwrap()
            .with_budgets(Budgets {
                begin: BEGIN_BUDGET,
                ..Budgets::default()
            })
    }

    /// Begins an allowed read through the core, as the gateway does, on a store that cannot
    /// write it, and returns the begin failures the store counted. The test fails if the begin
    /// succeeds, or has not ended by five times its budget.
    async fn failed_begin(store: &PgAuditStore) -> BeginFailures {
        use gateway_core::audit::{self, RequestMetadata};
        use gateway_core::{CallContext, RequestedTool, decide};
        use gateway_testkit::{
            Caller, Fixture, FixtureConnector, READ_TOOL, SURFACE_ALL, TEAM_A_DOCUMENT, row_start,
        };
        let fixture = Fixture::new().unwrap();
        let arguments = serde_json::json!({ "document": TEAM_A_DOCUMENT });
        let context = CallContext {
            resources: FixtureConnector::resources_of(READ_TOOL, &arguments),
            caller: fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap(),
            tool: RequestedTool::new(READ_TOOL),
            key: None,
        };
        let decision = decide(&fixture.policy, &context);
        let begin = audit::begin(
            store,
            row_start(),
            decision,
            arguments,
            RequestMetadata::default(),
        );
        let Ok(Err(_)) = tokio::time::timeout(BEGIN_BUDGET * 5, begin).await else {
            panic!("the begin succeeded, or did not end");
        };
        store.stats().begin_failures
    }

    /// A begin against a database that never answers counts one pool timeout, the same as a
    /// begin that waited for a pool permit: its budget ran out opening a new connection,
    /// before it had one. Needs no server: the one here takes the connection and says nothing.
    #[tokio::test]
    async fn a_begin_against_a_database_that_never_answers_counts_one_pool_timeout() {
        let (port, accepted) = server_that_never_answers(false).await;
        let store = store_at(port);
        assert_eq!(
            failed_begin(&store).await,
            BeginFailures {
                pool_timeout: 1,
                ..BeginFailures::default()
            }
        );
        // The begin was opening a connection, not waiting for a permit: the server took one.
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    /// A begin against a database that refuses each connection counts one database error, not
    /// a pool timeout: each attempt failed at once, with an error. Needs no server: nothing
    /// listens on the port.
    #[tokio::test]
    async fn a_begin_against_a_database_that_refuses_connections_counts_one_database_error() {
        let closed = closed_port();
        let store = store_at(closed.port);
        assert_eq!(
            failed_begin(&store).await,
            BeginFailures {
                database_error: 1,
                ..BeginFailures::default()
            }
        );
    }

    /// A begin whose connection breaks, and whose next attempt then runs past the budget
    /// opening a new one, counts one pool timeout: the connection that broke was taken out of
    /// the pool, and what counts is whether the last attempt had a connection. Needs no
    /// server: the one here lets the first connection in, breaks it at the begin's first
    /// statement, and says nothing on the next.
    #[tokio::test]
    async fn a_begin_whose_reconnect_runs_past_its_budget_counts_one_pool_timeout() {
        let (port, accepted) = server_that_never_answers(true).await;
        let store = store_at(port);
        assert_eq!(
            failed_begin(&store).await,
            BeginFailures {
                pool_timeout: 1,
                ..BeginFailures::default()
            }
        );
        // The first connection broke, and the begin's second attempt opened another.
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }
}
