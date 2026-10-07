//! [`PgAuditStore`]: the core's [`AuditStore`] on Postgres.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use deadpool_postgres::{
    ClientWrapper, Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod,
};
use gateway_core::audit::{AuditRowId, Completion, Outcome, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::{CancelToken, Socket};

use crate::columns::{BeginRow, FinishRow};

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
    /// No connection could be had.
    #[error("no connection to the audit database: {0}")]
    Pool(#[from] PoolError),
    /// A pool could not be built.
    #[error("the audit database pool could not be built: {0}")]
    Build(#[from] deadpool_postgres::BuildError),
    /// The database refused or failed the statement.
    #[error("the audit database did not write the row: {}", describe(.0))]
    Database(#[from] tokio_postgres::Error),
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
    /// refused. The store asked the server to cancel the insert, if it was sent; if it commits
    /// anyway, the store completes an allowed row as `error`.
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
}

impl PgAuditError {
    /// Whether trying again could succeed: the database could not be reached, the connection
    /// broke, the server is short of something or shutting down, or an attempt took too long.
    /// A refusal by the database itself, a missing row or a different completion is final.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::Pool(PoolError::Backend(_) | PoolError::Timeout(_)) | Self::AttemptTimedOut => {
                true
            }
            Self::Database(error) => match error.code() {
                // Connection exception, transaction rollback (serialization, deadlock),
                // insufficient resources, operator intervention, system error.
                Some(code) => {
                    matches!(code.code().get(..2), Some("08" | "40" | "53" | "57" | "58"))
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

impl Default for Budgets {
    fn default() -> Self {
        Self {
            begin: Duration::from_secs(2),
            answer: Duration::from_secs(2),
            finish_deadline: Duration::from_secs(30),
        }
    }
}

/// What has become of the finishes a store was given.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinishCounts {
    /// Still trying to complete their row.
    pub in_flight: usize,
    /// Stopped without completing their row: the deadline passed, or the database refused.
    /// Each such row keeps an empty outcome.
    pub given_up: u64,
}

#[derive(Default)]
struct Counters {
    in_flight: AtomicUsize,
    given_up: AtomicU64,
}

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

/// Asks the server to stop whatever a connection is running, over a connection of its own.
type Canceller = Arc<dyn Fn(CancelToken) -> BoxFuture<'static, ()> + Send + Sync>;

/// Every session the store opens commits synchronously, whatever the server, database or role
/// sets as its default: begin must not return before its row is durable.
const SESSION_OPTIONS: &str = "-c synchronous_commit=on";

/// The first pause between attempts to complete a row; each pause after doubles, up to
/// [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_millis(50);
const LONGEST_PAUSE: Duration = Duration::from_secs(1);

/// How long a request to cancel a statement may take before the store stops asking.
const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// The `event` field of the error the store logs each time it stops trying to write a row
/// and counts it in [`FinishCounts::given_up`] (decision 0009: a finish not written by its
/// deadline is a telemetry event naming the row).
///
/// - `stage = "finish"`: completing a row failed. It names the `row` and the `outcome` that was
///   not written, and `cause` says why. Past the finish deadline the row stays open.
/// - `stage = "begin"`: an insert that ran past the begin budget had no answer by the finish
///   deadline, so there is no row identifier to name. If it commits, the row stays open.
pub const GIVEN_UP_EVENT: &str = "audit_row_given_up";

/// The core's [`AuditStore`] on Postgres, writing to `switchboard_audit.call_rows`.
///
/// Connect it as [`GATEWAY_ROLE`](crate::GATEWAY_ROLE), and call
/// [`check_at_boot`](Self::check_at_boot) before serving. The database assigns each row its
/// identifier and both its times.
///
/// - Begin inserts the first half of a row and returns once the insert is committed. It has
///   [`Budgets::begin`], counted from asking for a connection. Past it, begin fails, so the
///   core refuses the call, and the store asks the server to cancel the insert and discards
///   the connection. An allowed row that commits anyway is completed as `error`, since
///   nothing ran.
/// - Finish writes the completion columns of a row that has none, on a task of its own. It
///   waits for that task for [`Budgets::answer`], and fails if the row is not complete by
///   then. The task keeps trying, while the failure is one that trying again could fix, until
///   [`Budgets::finish_deadline`]. An identical completion written again is accepted, and a
///   different one is an error, so the first completion stands and retrying is safe. The
///   table's trigger holds the same rule for every role.
///
/// If the caller stops waiting for finish, its task still completes the row.
///
/// Must be used inside a Tokio runtime: finish spawns its task there.
pub struct PgAuditStore {
    pub(crate) begin: Pool,
    pub(crate) finish: Pool,
    budgets: Budgets,
    cancel: Canceller,
    counters: Arc<Counters>,
}

impl PgAuditStore {
    /// A store that connects with `config` and `tls`, opening connections as they are first
    /// needed, with the default [`Budgets`]. Nothing connects here, so a database that is down
    /// is found by the first call, or by [`check_at_boot`](Self::check_at_boot).
    ///
    /// Each session sets `synchronous_commit` to `on`, after any options `config` carries.
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
        })
    }

    /// The same store with `budgets` in place of the defaults.
    #[must_use]
    pub fn with_budgets(self, budgets: Budgets) -> Self {
        Self { budgets, ..self }
    }

    /// The same store, except that it never asks the server to cancel a statement. A server
    /// that is paused cannot act on a cancellation before it commits; this stands in for one.
    #[cfg(test)]
    pub(crate) fn without_cancelling(self) -> Self {
        Self {
            cancel: Arc::new(|_| Box::pin(async {})),
            ..self
        }
    }

    /// The budgets this store keeps.
    pub fn budgets(&self) -> Budgets {
        self.budgets
    }

    /// How many finishes are still trying, and how many gave up. A gateway shutting down can
    /// wait for `in_flight` to reach zero; `given_up` is for its telemetry.
    pub fn finishes(&self) -> FinishCounts {
        FinishCounts {
            in_flight: self.counters.in_flight.load(Ordering::SeqCst),
            given_up: self.counters.given_up.load(Ordering::SeqCst),
        }
    }

    /// Begin: inserts the first half of a row within the begin budget.
    ///
    /// The insert runs on a task of its own. When the budget runs out, begin fails and asks the
    /// server to cancel the insert. A server that is stalled rather than down, such as one
    /// paused or behind a lock, may not act on the cancellation before the insert commits, so
    /// the task keeps waiting for the insert's answer until the finish deadline. If the insert
    /// committed an allowed row after all, the task completes it as `error`: the call was
    /// refused, so nothing ran (decision 0009, What begin guarantees). A denied row is complete
    /// as it is. An insert with no answer by the deadline is counted as given up, and its row,
    /// if it ever commits, stays open.
    async fn insert(&self, record: &AuditRecord) -> Result<AuditRowId, PgAuditError> {
        let row = BeginRow::from_record(record)?;
        let budget = self.budgets.begin;
        let started = Instant::now();
        let deadline = started + budget;
        let client = timeout_at(deadline, self.begin.get())
            .await
            .map_err(|_| PgAuditError::BeginBudget { budget })??;
        let token = client.cancel_token();
        let nothing_ran = Completion {
            outcome: Outcome::Error,
            latency_ms: 0,
        };
        let mut late = self.retry(
            String::new(),
            FinishRow::from_completion(&nothing_ran),
            started,
        );
        let allowed = row.decision == "allow";
        let counters = Arc::clone(&self.counters);
        let (sender, mut receiver) = oneshot::channel();
        tokio::spawn(async move {
            let Ok(inserted) = timeout_at(late.deadline, insert_on(&client, &row)).await else {
                // No answer by the deadline. Begin failed long ago; if the row commits after
                // this, nothing completes it.
                abandon(client, &late.cancel);
                counters.given_up.fetch_add(1, Ordering::SeqCst);
                // There is no row identifier to name: the insert never answered.
                tracing::error!(
                    event = GIVEN_UP_EVENT,
                    stage = "begin",
                    decision = if allowed { "allow" } else { "deny" },
                    "an audit row's insert had no answer by the finish deadline; if it commits, \
                     nothing completes it"
                );
                return;
            };
            let Err(inserted) = sender.send(inserted) else {
                // Begin had the answer in time.
                return;
            };
            // Begin had already failed. The connection's last statement was cancelled or
            // answered late, so it does not go back to its pool.
            std::mem::drop(Object::take(client));
            match inserted {
                Ok(committed) if allowed => {
                    late.row = committed.as_str().to_owned();
                    let _ = late.run_counted(InFlight::start(&counters)).await;
                }
                // A denial, or no row at all: the insert failed or was cancelled.
                _ => {}
            }
        });
        match timeout_at(deadline, &mut receiver).await {
            Ok(Ok(inserted)) => inserted,
            Ok(Err(_)) => Err(PgAuditError::BeginBudget { budget }),
            Err(_) => {
                // Closing first means an answer is either taken here or handed back to the
                // task, never lost between the two.
                receiver.close();
                if let Ok(inserted) = receiver.try_recv() {
                    return inserted;
                }
                tokio::spawn(self.cancel.as_ref()(token));
                Err(PgAuditError::BeginBudget { budget })
            }
        }
    }

    /// The task that completes `row` with `finish` on the finish pool, trying again until the
    /// finish deadline counted from `started`.
    fn retry(&self, row: String, finish: FinishRow, started: Instant) -> Retry {
        Retry {
            pool: self.finish.clone(),
            cancel: Arc::clone(&self.cancel),
            row,
            finish,
            attempt: self.budgets.answer,
            deadline: started + self.budgets.finish_deadline,
        }
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
            &FinishRow::from_completion(completion),
        )
        .await
    }

    pub(crate) async fn finish_within_budget(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> Result<(), PgAuditError> {
        let started = Instant::now();
        let task = self.retry(
            row.as_str().to_owned(),
            FinishRow::from_completion(completion),
            started,
        );
        let (sender, receiver) = oneshot::channel();
        let in_flight = InFlight::start(&self.counters);
        tokio::spawn(async move {
            let result = task.run_counted(in_flight).await;
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

/// Inserts the first half of a row and returns the identifier the database assigned.
async fn insert_on(client: &ClientWrapper, row: &BeginRow) -> Result<AuditRowId, PgAuditError> {
    let statement = client.prepare_cached(BeginRow::INSERT).await?;
    let inserted = client.query_one(&statement, &row.parameters()).await?;
    Ok(AuditRowId::new(inserted.try_get::<_, String>(0)?))
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
/// statement, so it does not go on to write after the caller was told it failed, and takes the
/// connection out of its pool, so no later call waits behind it.
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
}

impl Retry {
    /// [`run`](Self::run), counted in flight until it ends. If it fails, it is counted as given
    /// up and logged as [`GIVEN_UP_EVENT`], naming the row and the completion that was not
    /// written (decision 0009, What finish guarantees).
    async fn run_counted(self, in_flight: InFlight) -> Result<(), PgAuditError> {
        let row = self.row.clone();
        let outcome = self.finish.outcome;
        let result = self.run().await;
        if let Err(cause) = &result {
            in_flight.0.given_up.fetch_add(1, Ordering::SeqCst);
            tracing::error!(
                event = GIVEN_UP_EVENT,
                stage = "finish",
                row = row.as_str(),
                outcome,
                %cause,
                "an audit row's completion was not written, and the store has stopped trying"
            );
        }
        drop(in_flight);
        result
    }

    async fn run(self) -> Result<(), PgAuditError> {
        let mut pause = FIRST_PAUSE;
        loop {
            let last = match self.once().await {
                Ok(()) => return Ok(()),
                Err(error) if !error.is_transient() => return Err(error),
                Err(error) => error,
            };
            let now = Instant::now();
            if now >= self.deadline {
                return Err(PgAuditError::Deadline {
                    row: self.row,
                    last: Box::new(last),
                });
            }
            sleep_until((now + pause).min(self.deadline)).await;
            pause = (pause * 2).min(LONGEST_PAUSE);
        }
    }

    /// One attempt, bounded by the answer budget and by the deadline.
    async fn once(&self) -> Result<(), PgAuditError> {
        let by = (Instant::now() + self.attempt).min(self.deadline);
        let client = timeout_at(by, self.pool.get())
            .await
            .map_err(|_| PgAuditError::AttemptTimedOut)??;
        match timeout_at(by, complete_on(&client, &self.row, &self.finish)).await {
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
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        Box::pin(async move { self.insert(record).await.map_err(StoreError::from) })
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
    fn only_failures_that_trying_again_could_fix_are_retried() {
        assert!(PgAuditError::AttemptTimedOut.is_transient());
        for final_error in [
            PgAuditError::NoSuchRow { row: "r".into() },
            PgAuditError::CompletedDifferently { row: "r".into() },
            PgAuditError::Pool(PoolError::Closed),
            PgAuditError::Column("x"),
        ] {
            assert!(!final_error.is_transient(), "{final_error}");
        }
    }
}
