//! [`PgAuditStore`]: the core's [`AuditStore`] on Postgres.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use deadpool_postgres::{
    ClientWrapper, Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod,
};
use gateway_core::audit::{AuditRowId, Completion, RowCompletion, StoreError};
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
    /// refused. If the insert was sent, the store asked the server to cancel it, but a cancel
    /// is best effort: the row may still have been written, as decision 0009 allows for a
    /// begin reported as failed.
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
    /// broke, the server is short of something, shutting down or read-only, a lock was not had
    /// in time, or an attempt took too long. A refusal by the database itself, a missing row
    /// or a different completion is final.
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

/// A finish that stopped without completing its row, which keeps an empty outcome. Decision
/// 0009 makes each one a telemetry event naming the row and the outcome's kind.
#[derive(Debug)]
pub struct GivenUp<'a> {
    /// The row finish named.
    pub row: &'a AuditRowId,
    /// The outcome it was to record: `ok`, `error` or `refused`.
    pub outcome: &'static str,
    /// Why it stopped: [`PgAuditError::Deadline`] when the deadline passed,
    /// [`PgAuditError::CompletedDifferently`] when the row already had another completion,
    /// [`PgAuditError::NoSuchRow`] when the row is not there, or another refusal by the
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
pub(crate) const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// The core's [`AuditStore`] on Postgres, writing to `switchboard_audit.call_rows`.
///
/// Connect it as [`GATEWAY_ROLE`](crate::GATEWAY_ROLE), and call
/// [`check_at_boot`](Self::check_at_boot) before serving. The database assigns each row its
/// identifier and both its times.
///
/// - Begin inserts the first half of a row and returns once the insert is committed. It has
///   [`Budgets::begin`], counted from asking for a connection. Past it, begin fails, so the
///   core refuses the call, and the connection is discarded. The store asks the server to
///   cancel the insert, which stops one still waiting, for example on a lock. One that has
///   already committed, or commits before the cancel arrives, stays: a begin reported as
///   failed may still have written its row (decision 0009). Until that row is completed as
///   `error` (design section 17), it keeps an empty outcome.
/// - Finish writes the completion columns of a row that has none, on a task of its own. It
///   waits for that task for [`Budgets::answer`], and fails if the row is not complete by
///   then. The task keeps trying, while the failure is one that trying again could fix, until
///   [`Budgets::finish_deadline`]. An attempt that fails that way gives up its connection,
///   so the next makes a new one: after a failover, an old connection may be to a server
///   that has become read-only. An identical completion written again is accepted, and a
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
    given_up: Report,
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

    /// How many finishes are still trying, and how many gave up. A gateway shutting down can
    /// wait for `in_flight` to reach zero; `given_up` is for its telemetry.
    pub fn finishes(&self) -> FinishCounts {
        FinishCounts {
            in_flight: self.counters.in_flight.load(Ordering::SeqCst),
            given_up: self.counters.given_up.load(Ordering::SeqCst),
        }
    }

    async fn insert(&self, record: &AuditRecord) -> Result<AuditRowId, PgAuditError> {
        let row = BeginRow::from_record(record)?;
        let budget = self.budgets.begin;
        let deadline = Instant::now() + budget;
        let client = timeout_at(deadline, self.begin.get())
            .await
            .map_err(|_| PgAuditError::BeginBudget { budget })??;
        match timeout_at(deadline, insert_on(&client, &row)).await {
            Ok(inserted) => inserted,
            Err(_) => {
                abandon(client, &self.cancel);
                Err(PgAuditError::BeginBudget { budget })
            }
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
        let task = Retry {
            pool: self.finish.clone(),
            cancel: Arc::clone(&self.cancel),
            row: row.as_str().to_owned(),
            finish: FinishRow::from_completion(completion),
            attempt: self.budgets.answer,
            deadline: started + self.budgets.finish_deadline,
        };
        let (sender, receiver) = oneshot::channel();
        let in_flight = InFlight::start(&self.counters);
        let report = Arc::clone(&self.given_up);
        let named = row.clone();
        let outcome = task.finish.outcome;
        tokio::spawn(async move {
            let result = task.run().await;
            if let Err(error) = &result {
                in_flight.0.given_up.fetch_add(1, Ordering::SeqCst);
                report(GivenUp {
                    row: &named,
                    outcome,
                    error,
                });
            }
            drop(in_flight);
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
}

impl Retry {
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
}
