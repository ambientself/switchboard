//! [`PgAuditStore`]: the core's [`AuditStore`] on Postgres.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use deadpool_postgres::{
    ClientWrapper, Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod,
};
use gateway_core::audit::{AuditRowId, Completion, ListRecord, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{CancelToken, Socket};

use crate::columns::{BeginRow, FinishRow, ListRow};

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
    /// Finish named a row the table does not hold.
    #[error("audit row {row} does not exist")]
    NoSuchRow {
        /// The row finish named.
        row: String,
    },
    /// The row was completed before, with a different outcome or latency. The first
    /// completion stands.
    #[error("audit row {row} is already complete, with a different completion")]
    CompletedDifferently {
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

/// How many connections each pool may hold.
///
/// Finish has a pool of its own, so a surge of begins cannot starve the writes that close
/// rows. The defaults are provisional; decision 0009 leaves pool sizes to Q12.
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

#[derive(Default)]
struct Counters {
    in_flight: AtomicUsize,
    given_up: AtomicU64,
    never_written: AtomicU64,
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
    /// database.
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
        self.in_flight.0.given_up.fetch_add(1, Ordering::SeqCst);
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

/// The open rows (decision 0009, "Open rows"): allowed rows of kind `call` with no completion
/// past their deadline, by the database's clock. A denial and a list row are never open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenRows {
    /// How many rows are open.
    pub count: u64,
    /// The earliest deadline among them, or `None` when none is open.
    pub oldest_deadline: Option<SystemTime>,
}

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
/// - Finish writes the completion columns of a row that has none, on a task of its own. It
///   waits for that task for [`Budgets::answer`], and fails if the row is not complete by
///   then. The task keeps trying, while the failure is one that trying again could fix, until
///   [`Budgets::finish_deadline`]. An attempt that fails that way gives up its connection,
///   so the next makes a new one: after a failover, an old connection may be to a server
///   that has become read-only. An identical completion written again is accepted, and a
///   different one is an error, so the first completion stands and retrying is safe. The
///   table's trigger holds the same rule for every role.
/// - A row is exactly its record, or it is not written. Begin refuses a record with U+0000 in
///   any text value, which Postgres cannot store, with [`PgAuditError::Nul`], so the core
///   refuses the call; finish refuses a refusal sentence with one, or a latency past its
///   column's range, and gives up.
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
    budgets: Budgets,
    cancel: Canceller,
    counters: Arc<Counters>,
    given_up: Report,
}

impl PgAuditStore {
    /// A store that connects with `config` and `tls`, opening connections as they are first
    /// needed, with the default [`Budgets`]. Nothing connects here, so a database that is down
    /// is found by the first call, or by [`check_at_boot`](Self::check_at_boot).
    ///
    /// Each session sets `synchronous_commit` to `on` and `search_path` to
    /// `pg_catalog, pg_temp`, after any options `config` carries.
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
            budgets: Budgets::default(),
            cancel,
            counters: Arc::default(),
            given_up: Arc::new(|_| {}),
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
            given_up: self.counters.given_up.load(Ordering::SeqCst),
            never_written: self.counters.never_written.load(Ordering::SeqCst),
        }
    }

    /// Counts the open rows, and finds the earliest deadline among them, through the view
    /// `switchboard_audit.open_call_rows`. Runs on the finish pool, within 2 s from asking for a
    /// connection; past that, it asks the server to cancel the query and fails. Reads only:
    /// nothing marks a row abandoned or writes its outcome.
    pub async fn open_rows(&self) -> Result<OpenRows, PgAuditError> {
        let budget = OPEN_ROWS_TIMEOUT;
        let deadline = Instant::now() + budget;
        let client = timeout_at(deadline, self.finish.get())
            .await
            .map_err(|_| PgAuditError::OpenRowsTimedOut { budget })??;
        let query = client.query_one(
            "SELECT count(*), min(deadline) FROM switchboard_audit.open_call_rows",
            &[],
        );
        match timeout_at(deadline, query).await {
            Ok(row) => {
                let row = row?;
                let count: i64 = row.get(0);
                Ok(OpenRows {
                    // count(*) is never negative.
                    count: u64::try_from(count).unwrap_or_default(),
                    oldest_deadline: row.get(1),
                })
            }
            Err(_) => {
                abandon(client, &self.cancel);
                Err(PgAuditError::OpenRowsTimedOut { budget })
            }
        }
    }

    /// Writes a call row's first half, or a list row, within the begin budget, on the begin
    /// pool, trying again by identifier while the failure is one that trying again could fix.
    async fn insert(&self, row: Insert) -> Result<(), PgAuditError> {
        let deadline = Instant::now() + self.budgets.begin;
        // Whether an attempt executed its insert and ended without an answer, or with an error
        // trying again could fix, so that the row may exist. That error may be an explicit
        // refusal, such as a read-only server's. Once set it stays set: what a later attempt
        // finds does not undo an insert that may have committed.
        let mut may_be_written = false;
        let mut pause = FIRST_PAUSE;
        let failed = loop {
            let mut sent = false;
            let error = match self.insert_once(&row, deadline, &mut sent).await {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            let unanswered =
                error.is_transient() || matches!(error, PgAuditError::BeginBudget { .. });
            may_be_written |= sent && unanswered;
            if !error.is_transient() {
                break error;
            }
            // The same row again, under the same identifier: if the last attempt committed,
            // the next finds that row rather than write a second.
            let now = Instant::now();
            sleep_until((now + pause).min(deadline)).await;
            if Instant::now() >= deadline {
                break error;
            }
            pause = longer(pause);
        };
        // A denial is a complete record, and a list row is written complete: neither is left
        // open.
        if may_be_written
            && let Insert::Call(call) = &row
            && call.decision == "allow"
        {
            self.complete_lost_begin(AuditRowId::new(call.id.clone()));
        }
        Err(failed)
    }

    /// One attempt at [`insert`](Self::insert), ending by `deadline`. Sets `sent` as the insert
    /// itself goes out, after its statement is prepared: a prepare cannot commit a row.
    async fn insert_once(
        &self,
        row: &Insert,
        deadline: Instant,
        sent: &mut bool,
    ) -> Result<(), PgAuditError> {
        let budget = self.budgets.begin;
        let client = timeout_at(deadline, self.begin.get())
            .await
            .map_err(|_| PgAuditError::BeginBudget { budget })??;
        match timeout_at(deadline, insert_on(&client, row, sent)).await {
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

    /// Completes `row`, whose begin failed after its insert was executed, as `error` with a
    /// latency of 0, on a task of its own on the finish pool, until the finish deadline.
    /// Counted in flight until it ends.
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
            finish: FinishRow {
                outcome: "error",
                outcome_sentence: None,
                latency_ms: 0,
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
        let client = self.finish.get().await?;
        complete_on(
            &client,
            row.as_str(),
            &FinishRow::from_completion(completion)?,
        )
        .await
    }

    pub(crate) async fn finish_within_budget(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> Result<(), PgAuditError> {
        let started = Instant::now();
        let settle = Settle {
            in_flight: InFlight::start(&self.counters),
            report: Arc::clone(&self.given_up),
            row: row.clone(),
            outcome: FinishRow::outcome_of(completion),
            settled: false,
        };
        let finish = match FinishRow::from_completion(completion) {
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
            Err(_) => Err(PgAuditError::AnswerBudget {
                row: row.as_str().to_owned(),
                budget: self.budgets.answer,
            }),
        }
    }
}

/// What [`PgAuditStore::insert`] writes.
enum Insert {
    /// The first half of a call row, for begin.
    Call(BeginRow),
    /// A list row, complete.
    List(ListRow),
}

/// Writes `row`, as begin or list. Sets `sent` just before the insert is executed: from then
/// on it may commit, whatever answer comes back, or none.
async fn insert_on(
    client: &ClientWrapper,
    row: &Insert,
    sent: &mut bool,
) -> Result<(), PgAuditError> {
    match row {
        Insert::Call(row) => begin_on(client, row, sent).await,
        Insert::List(row) => list_on(client, row, sent).await,
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
    client: &ClientWrapper,
    row: &str,
    finish: &FinishRow,
) -> Result<(), PgAuditError> {
    let statement = client.prepare_cached(FinishRow::UPDATE).await?;
    let updated = client
        .execute(
            &statement,
            &[
                &row,
                &finish.outcome,
                &finish.outcome_sentence,
                &finish.latency_ms,
            ],
        )
        .await?;
    if updated == 1 {
        return Ok(());
    }
    // Nothing matched: the row is missing, or already complete. A retried finish whose
    // first attempt was written finds its own completion, which is success.
    let statement = client.prepare_cached(FinishRow::SELECT).await?;
    let Some(existing) = client.query_opt(&statement, &[&row]).await? else {
        return Err(PgAuditError::NoSuchRow {
            row: row.to_owned(),
        });
    };
    let outcome: Option<String> = existing.try_get(0)?;
    let outcome_sentence: Option<String> = existing.try_get(1)?;
    let latency_ms: Option<i64> = existing.try_get(2)?;
    match outcome {
        Some(outcome) if finish.is(&outcome, outcome_sentence.as_deref(), latency_ms) => Ok(()),
        _ => Err(PgAuditError::CompletedDifferently {
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
                Err(error @ PgAuditError::NoSuchRow { .. }) if self.row_may_commit => error,
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
        let client = timeout_at(by, self.pool.get())
            .await
            .map_err(|_| PgAuditError::AttemptTimedOut)??;
        match timeout_at(by, complete_on(&client, &self.row, &self.finish)).await {
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
            let row = BeginRow::from_record(row, record, &self.budgets)?;
            self.insert(Insert::Call(row))
                .await
                .map_err(StoreError::from)
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.finish_within_budget(completion.row(), completion.completion())
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
            self.insert(Insert::List(row))
                .await
                .map_err(StoreError::from)
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
            PgAuditError::BegunDifferently { row: "r".into() },
            PgAuditError::Pool(PoolError::Closed),
            PgAuditError::Column("x"),
        ] {
            assert!(!final_error.is_transient(), "{final_error}");
        }
    }

    /// A port on this machine that nothing listens on.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
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
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(closed_port()).user("nobody");
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
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(closed_port()).user("nobody");
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
            outcome: gateway_core::audit::Outcome::Error,
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
        let lost = PgAuditError::FinishTaskLost {
            row: row.as_str().to_owned(),
        };
        assert_eq!(
            reports.lock().unwrap().clone(),
            vec![(row.as_str().to_owned(), "error", lost.to_string())]
        );
    }
}
