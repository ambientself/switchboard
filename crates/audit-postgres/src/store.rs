//! [`PgAuditStore`]: the core's [`AuditStore`] on Postgres.

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use gateway_core::audit::{AuditRowId, Completion, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};
use thiserror::Error;
use tokio_postgres::Socket;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};

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
    Pool(#[from] deadpool_postgres::PoolError),
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

/// Every session the store opens commits synchronously, whatever the server, database or role
/// sets as its default: begin must not return before its row is durable.
const SESSION_OPTIONS: &str = "-c synchronous_commit=on";

/// The core's [`AuditStore`] on Postgres, writing to `switchboard_audit.call_rows`.
///
/// Connect it as [`GATEWAY_ROLE`](crate::GATEWAY_ROLE). The database assigns each row its
/// identifier and both its times. Begin inserts the first half of a row and returns once the
/// insert is committed. Finish writes the completion columns of a row that has none; an
/// identical completion written again is accepted, and a different one is an error, so the
/// first completion stands. The table's trigger holds the same rule for every role.
///
/// Neither operation has a time limit of its own yet: a connection is waited for, and a
/// statement runs, until the database answers.
pub struct PgAuditStore {
    pub(crate) begin: Pool,
    pub(crate) finish: Pool,
}

impl PgAuditStore {
    /// A store that connects with `config` and `tls`, opening connections as they are first
    /// needed. Nothing connects here, so a database that is down is found by the first call.
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
        Ok(Self {
            begin: pool(sizes.begin)?,
            finish: pool(sizes.finish)?,
        })
    }

    async fn insert(&self, record: &AuditRecord) -> Result<AuditRowId, PgAuditError> {
        let row = BeginRow::from_record(record)?;
        let client = self.begin.get().await?;
        let statement = client.prepare_cached(BeginRow::INSERT).await?;
        let inserted = client.query_one(&statement, &row.parameters()).await?;
        Ok(AuditRowId::new(inserted.try_get::<_, String>(0)?))
    }

    /// Completes `row`. Reached from outside the crate only through [`AuditStore::finish`],
    /// which takes a completion only the core can make.
    pub(crate) async fn complete(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> Result<(), PgAuditError> {
        let finish = FinishRow::from_completion(completion);
        let client = self.finish.get().await?;
        let statement = client.prepare_cached(FinishRow::UPDATE).await?;
        let updated = client
            .execute(
                &statement,
                &[
                    &row.as_str(),
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
        let Some(existing) = client.query_opt(&statement, &[&row.as_str()]).await? else {
            return Err(PgAuditError::NoSuchRow {
                row: row.as_str().to_owned(),
            });
        };
        let outcome: Option<String> = existing.try_get(0)?;
        let outcome_sentence: Option<String> = existing.try_get(1)?;
        let latency_ms: Option<i64> = existing.try_get(2)?;
        match outcome {
            Some(outcome) if finish.is(&outcome, outcome_sentence.as_deref(), latency_ms) => Ok(()),
            _ => Err(PgAuditError::CompletedDifferently {
                row: row.as_str().to_owned(),
            }),
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
            self.complete(completion.row(), completion.completion())
                .await
                .map_err(StoreError::from)
        })
    }
}
