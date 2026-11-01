//! The queue of `unknown` receipts on Postgres (decision 0009, "Reconciliation"): the core's
//! [`ReceiptQueue`] on `switchboard_audit.receipts` and `switchboard_audit.receipt_lookups`.
//!
//! Every statement runs on the open-row query's pool of its own, so reconciliation never takes a
//! connection a begin or a finish could use, and each has the open-row query's 2 s, from asking
//! for the connection to the answer; past it, the store asks the server to cancel what is
//! running, and the statement fails. Every time is the database's.
//!
//! - [`due`](ReceiptQueue::due) reads the receipts whose row's deadline has passed that read as
//!   `unknown` (the state `unknown`, or `pending`), not handed to a person, whose lease is free,
//!   and their lookups. It reads only.
//! - [`claim`](ReceiptQueue::claim) sets a lease and counts the claim in one statement,
//!   committed when it returns, and only on a receipt still due: of two claims at once, the
//!   second waits for the first's row lock, finds the lease taken, and claims nothing. No lock
//!   or connection is held after it returns, so none is held across a lookup.
//! - [`hold`](ReceiptQueue::hold) sets a lease for the call that reserved the receipt, in one
//!   statement, on a receipt `pending` or `unknown` and not handed to a person whose lease is
//!   free or already the holder's. Like a claim, it waits for another's row lock and then
//!   judges the lease again.
//! - [`record_lookup`](ReceiptQueue::record_lookup) appends the lookup and moves the receipt in
//!   one transaction, holding the receipt's row lock from the check of the lease to the commit.
//! - [`hand_to_person`](ReceiptQueue::hand_to_person) records the hand-off in one statement.
//!
//! The triggers hold the same rules for every role: `lookup_appends` appends a lookup only to a
//! receipt in `unknown` not handed to a person, as the next attempt, and never lets one be
//! changed or removed; `receipt_moves` lets reconciliation settle a receipt only on a lookup
//! recorded on it that establishes the state, writes a lease only on a receipt `pending` or
//! `unknown` not yet handed to a person, writes a hand-off or a claim only on a receipt in
//! `unknown` not yet handed to a person, and raises the count of claims by one at a time.

use std::time::{Duration, SystemTime};

use deadpool_postgres::Object;
use gateway_core::audit::{AuditRowId, StoreError};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{
    ArgumentDigest, BoxFuture, IdempotencyKey, LeaseHolder, LookupAnswer, LookupRecord, Receipt,
    ReceiptQueue, ReceiptState, Recorded, Resource, ToolName, ToolUseId, VendorReference,
};
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};

use crate::columns::receipt_state;
use crate::store::{OPEN_ROWS_TIMEOUT, PgAuditError, PgAuditStore, abandon};

/// The most receipts [`due`](ReceiptQueue::due) reads at once, whatever it is asked for.
pub const MAX_DUE: usize = 1000;

/// The columns of a receipt reconciliation reads, from the table aliased `r`, in the order
/// `receipt_from` reads them.
macro_rules! receipt_columns {
    () => {
        "r.row_id::text, r.principal_issuer, r.principal_subject, r.delegation_scope,
         r.idempotency_key, r.tool, r.tool_use_id, r.digest, r.resources, r.resources_omitted,
         r.state, r.established_by, r.established_person, r.reference, r.target_system,
         r.target_kind, r.target_identifier, r.handed_to_person_at, r.claims"
    };
}

/// A receipt reads as `unknown`, by the database's clock: the state `unknown`, or `pending`
/// past its row's deadline. `r` is the receipt and `c` its row.
macro_rules! reads_as_unknown {
    () => {
        "(r.state = 'unknown' OR (r.state = 'pending' AND c.deadline < clock_timestamp()))"
    };
}

/// A receipt's row's deadline has passed, by the database's clock: before it, a receipt the
/// call answered `unknown` may still have its call running, a side effect whose first hold of
/// the lease is not written yet. `c` is the row.
macro_rules! past_deadline {
    () => {
        "c.deadline < clock_timestamp()"
    };
}

/// The receipts due, the longest reserved first: past their row's deadline, reading as
/// `unknown`, not handed to a person, with a free lease. `$1` is the limit.
pub(crate) const DUE: &str = concat!(
    "SELECT ",
    receipt_columns!(),
    " FROM switchboard_audit.receipts r
         JOIN switchboard_audit.call_rows c ON c.id = r.row_id
     WHERE ",
    past_deadline!(),
    " AND ",
    reads_as_unknown!(),
    " AND r.handed_to_person_at IS NULL
         AND (r.lease_until IS NULL OR r.lease_until <= clock_timestamp())
     ORDER BY r.reserved_at, r.row_id
     LIMIT $1"
);

/// Claims the receipt `$1` for the holder `$2`, for `$3` microseconds from now, only while it
/// is due, and counts the claim. Returns the receipt, or no row.
pub(crate) const CLAIM: &str = concat!(
    "UPDATE switchboard_audit.receipts r
         SET lease_holder = $2,
             lease_until = clock_timestamp() + $3::bigint * interval '1 microsecond',
             claims = r.claims + 1
     FROM switchboard_audit.call_rows c
     WHERE r.row_id = ($1::text)::uuid AND c.id = r.row_id AND ",
    past_deadline!(),
    " AND ",
    reads_as_unknown!(),
    " AND r.handed_to_person_at IS NULL
         AND (r.lease_until IS NULL OR r.lease_until <= clock_timestamp())
     RETURNING ",
    receipt_columns!()
);

/// Holds the receipt `$1` for the holder `$2`, for `$3` microseconds from now, for the call
/// that reserved it: while it is `pending` or `unknown`, not handed to a person, and its lease
/// is free or already `$2`'s. Counts no claim. Updates one row, or none.
pub(crate) const HOLD: &str = "UPDATE switchboard_audit.receipts r
    SET lease_holder = $2,
        lease_until = clock_timestamp() + $3::bigint * interval '1 microsecond'
    WHERE r.row_id = ($1::text)::uuid AND r.state IN ('pending', 'unknown')
        AND r.handed_to_person_at IS NULL
        AND (r.lease_until IS NULL OR r.lease_until <= clock_timestamp() OR r.lease_holder = $2)";

/// The lookups of the receipts `$1`, by attempt.
pub(crate) const LOOKUPS: &str = "SELECT row_id::text, result, authoritative, reference,
        looked_up_at
    FROM switchboard_audit.receipt_lookups
    WHERE row_id::text = ANY($1::text[])
    ORDER BY row_id, attempt";

/// Locks the receipt `$1` while the holder `$2` holds its lease and it reads as `unknown`, not
/// handed to a person. No row otherwise.
pub(crate) const HELD: &str = concat!(
    "SELECT r.row_id FROM switchboard_audit.receipts r
         JOIN switchboard_audit.call_rows c ON c.id = r.row_id
     WHERE r.row_id = ($1::text)::uuid AND r.lease_holder = $2
         AND r.lease_until > clock_timestamp() AND r.handed_to_person_at IS NULL AND ",
    reads_as_unknown!(),
    " FOR UPDATE OF r"
);

/// How many lookups the receipt `$1` has.
pub(crate) const MADE: &str =
    "SELECT count(*) FROM switchboard_audit.receipt_lookups WHERE row_id = ($1::text)::uuid";

/// Appends a lookup to the receipt `$1` as attempt `$2`, with its result `$3`, whether it was
/// authoritative `$4` and a found effect's reference `$5`.
pub(crate) const APPEND: &str = "INSERT INTO switchboard_audit.receipt_lookups
        (row_id, attempt, result, authoritative, reference)
    VALUES (($1::text)::uuid, $2, $3, $4, $5)";

/// Settles the receipt `$1` as `$2`, established by reconciliation, with the reference `$3`.
pub(crate) const SETTLE: &str = "UPDATE switchboard_audit.receipts
    SET state = $2, established_by = 'reconciliation', reference = $3
    WHERE row_id = ($1::text)::uuid";

/// Hands the receipt `$1` to a person; the trigger sets the time.
pub(crate) const HAND_OFF: &str = "UPDATE switchboard_audit.receipts
    SET handed_to_person_at = clock_timestamp()
    WHERE row_id = ($1::text)::uuid";

/// Hands the receipt `$1` to a person while the holder `$2` holds its lease and it reads as
/// `unknown`, not handed to a person already.
pub(crate) const HAND_OFF_HELD: &str = concat!(
    "UPDATE switchboard_audit.receipts r
         SET handed_to_person_at = clock_timestamp()
     FROM switchboard_audit.call_rows c
     WHERE r.row_id = ($1::text)::uuid AND c.id = r.row_id AND r.lease_holder = $2
         AND r.lease_until > clock_timestamp() AND r.handed_to_person_at IS NULL AND ",
    reads_as_unknown!()
);

/// The error for a column that holds `what` in a form the store does not write.
fn unreadable<E>(what: &'static str) -> impl FnOnce(E) -> PgAuditError {
    move |_| PgAuditError::Unreadable(what)
}

/// A receipt from the columns `receipt_columns!` names, in its order, with `lookups`.
pub(crate) fn receipt_from(
    row: &tokio_postgres::Row,
    lookups: Vec<LookupRecord>,
) -> Result<Receipt, PgAuditError> {
    let text = |at: usize| row.try_get::<_, Option<String>>(at);
    let required = |at: usize, what: &'static str| -> Result<String, PgAuditError> {
        text(at)?.ok_or(PgAuditError::Unreadable(what))
    };
    let resources = match row.try_get::<_, Value>(8)? {
        named @ Value::Array(_) => json!({ "named": named }),
        other => other,
    };
    let established_by = match required(11, "a receipt's establishment")?.as_str() {
        "call" => EstablishedBy::Call,
        "reconciliation" => EstablishedBy::Reconciliation,
        "person" => serde_json::from_value(json!({"by": "person", "person": text(12)?}))
            .map_err(unreadable("a receipt's person"))?,
        _ => return Err(PgAuditError::Unreadable("a receipt's establishment")),
    };
    let target = match (text(14)?, text(15)?, text(16)?) {
        (Some(system), Some(kind), Some(identifier)) => Some(Resource {
            system,
            kind,
            identifier,
        }),
        (None, None, None) => None,
        _ => return Err(PgAuditError::Unreadable("a receipt's target")),
    };
    Ok(Receipt {
        row: AuditRowId::new(required(0, "a receipt's row")?),
        scope: serde_json::from_value(json!({
            "principal": {"issuer": text(1)?, "subject": text(2)?},
            "delegation": text(3)?,
        }))
        .map_err(unreadable("a receipt's scope"))?,
        key: IdempotencyKey::parse(&required(4, "a receipt's key")?)
            .map_err(unreadable("a receipt's key"))?,
        tool: ToolName::parse(&required(5, "a receipt's tool")?)
            .map_err(unreadable("a receipt's tool"))?,
        tool_use_id: text(6)?.map(ToolUseId::new),
        digest: ArgumentDigest::try_from(required(7, "a receipt's digest")?)
            .map_err(unreadable("a receipt's digest"))?,
        resources: serde_json::from_value(resources)
            .map_err(unreadable("a receipt's resources"))?,
        resources_omitted: usize::try_from(row.try_get::<_, i64>(9)?)
            .map_err(unreadable("a receipt's count of resources left out"))?,
        state: receipt_state(&required(10, "a receipt's state")?)?,
        established_by,
        reference: text(13)?.map(VendorReference::new),
        target,
        lookups,
        handed_to_person: row.try_get::<_, Option<SystemTime>>(17)?,
        claims: u32::try_from(row.try_get::<_, i32>(18)?)
            .map_err(unreadable("a receipt's count of claims"))?,
    })
}

/// A lookup, from the columns [`LOOKUPS`] reads after the receipt's identifier.
pub(crate) fn lookup_from(row: &tokio_postgres::Row) -> Result<LookupRecord, PgAuditError> {
    let result: String = row.try_get(1)?;
    let authoritative: bool = row.try_get(2)?;
    let reference: Option<String> = row.try_get(3)?;
    let answer = match (result.as_str(), reference) {
        ("found", Some(reference)) => LookupAnswer::Found {
            reference: VendorReference::new(reference),
        },
        ("not_found", None) => LookupAnswer::NotFound { authoritative },
        ("failed", None) => LookupAnswer::Failed,
        _ => return Err(PgAuditError::Unreadable("a lookup's result")),
    };
    Ok(LookupRecord {
        at: row.try_get(4)?,
        answer,
    })
}

/// Reads the lookups of the receipts `rows` on `client` and returns the receipts with them.
async fn with_lookups(
    client: &Object,
    rows: Vec<tokio_postgres::Row>,
) -> Result<Vec<Receipt>, PgAuditError> {
    let ids = rows
        .iter()
        .map(|row| row.try_get::<_, String>(0))
        .collect::<Result<Vec<_>, _>>()?;
    let lookups = client.query(LOOKUPS, &[&ids]).await?;
    rows.iter()
        .map(|row| {
            let id: String = row.try_get(0)?;
            let made = lookups
                .iter()
                .filter(|lookup| lookup.try_get::<_, String>(0).is_ok_and(|of| of == id))
                .map(lookup_from)
                .collect::<Result<Vec<_>, _>>()?;
            receipt_from(row, made)
        })
        .collect()
}

/// `duration` in whole microseconds, as a `bigint` holds it; a longer one is held as the
/// longest.
fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// The identifier of the row `id`, as the statements take it, or why it cannot be one.
fn row_text(id: &AuditRowId) -> String {
    id.as_str().to_owned()
}

impl PgAuditStore {
    /// Runs `work` on a connection of the open-row query's pool, within [`OPEN_ROWS_TIMEOUT`]
    /// from asking for the connection; past it, fails, and asks the server to cancel what is
    /// running. A transaction `work` left open is rolled back when its connection is dropped.
    async fn apart<T>(
        &self,
        work: impl AsyncFnOnce(&mut Object) -> Result<T, PgAuditError>,
    ) -> Result<T, PgAuditError> {
        let budget = OPEN_ROWS_TIMEOUT;
        let deadline = Instant::now() + budget;
        let mut client = timeout_at(deadline, self.open_rows_pool.get())
            .await
            .map_err(|_| PgAuditError::ReconciliationTimedOut { budget })??;
        match timeout_at(deadline, work(&mut client)).await {
            Ok(done) => done,
            Err(_) => {
                abandon(client, &self.cancel);
                Err(PgAuditError::ReconciliationTimedOut { budget })
            }
        }
    }
}

impl ReceiptQueue for PgAuditStore {
    fn due<'a>(&'a self, limit: usize) -> BoxFuture<'a, Result<Vec<Receipt>, StoreError>> {
        Box::pin(async move {
            let limit = i64::try_from(limit.min(MAX_DUE)).unwrap_or_default();
            self.apart(async |client: &mut Object| {
                let rows = client.query(DUE, &[&limit]).await?;
                with_lookups(client, rows).await
            })
            .await
            .map_err(StoreError::from)
        })
    }

    fn claim<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        lease: Duration,
    ) -> BoxFuture<'a, Result<Option<Receipt>, StoreError>> {
        Box::pin(async move {
            let id = row_text(row);
            let holder = holder.as_str();
            let lease = micros(lease);
            self.apart(async |client: &mut Object| {
                // One statement, in a transaction of its own: committed when it answers.
                let claimed = client.query(CLAIM, &[&id, &holder, &lease]).await?;
                Ok(with_lookups(client, claimed).await?.pop())
            })
            .await
            .map_err(StoreError::from)
        })
    }

    fn record_lookup<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        answer: &'a LookupAnswer,
        attempts: u32,
    ) -> BoxFuture<'a, Result<Recorded, StoreError>> {
        Box::pin(async move {
            let id = row_text(row);
            let holder = holder.as_str();
            let answer = answer.recorded();
            self.apart(async |client: &mut Object| {
                let transaction = client.transaction().await?;
                if transaction
                    .query_opt(HELD, &[&id, &holder])
                    .await?
                    .is_none()
                {
                    return Err(PgAuditError::LeaseNotHeld { row: id.clone() });
                }
                let made: i64 = transaction.query_one(MADE, &[&id]).await?.try_get(0)?;
                if made >= i64::from(attempts) {
                    return Err(PgAuditError::AttemptsUsedUp {
                        row: id.clone(),
                        attempts,
                    });
                }
                let attempt = i32::try_from(made + 1)
                    .map_err(|_| PgAuditError::Column("a lookup's attempt"))?;
                let reference = answer.reference().map(VendorReference::as_str);
                if reference.is_some_and(|reference| reference.contains('\0')) {
                    return Err(PgAuditError::Nul {
                        column: "reference",
                    });
                }
                transaction
                    .execute(
                        APPEND,
                        &[
                            &id,
                            &attempt,
                            &answer.result(),
                            &answer.authoritative(),
                            &reference,
                        ],
                    )
                    .await?;
                let recorded = match answer.settles() {
                    Some(settled) => {
                        let state = match settled {
                            ReceiptState::Completed => "completed",
                            ReceiptState::NotPerformed => "not_performed",
                            ReceiptState::Pending | ReceiptState::Unknown => {
                                return Err(PgAuditError::Column("a lookup's settlement"));
                            }
                        };
                        transaction
                            .execute(SETTLE, &[&id, &state, &reference])
                            .await?;
                        Recorded::Settled(settled)
                    }
                    None if made + 1 >= i64::from(attempts) => {
                        transaction.execute(HAND_OFF, &[&id]).await?;
                        Recorded::HandedToPerson
                    }
                    None => Recorded::Left,
                };
                transaction.commit().await?;
                Ok(recorded)
            })
            .await
            .map_err(StoreError::from)
        })
    }

    fn hold<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        lease: Duration,
    ) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let id = row_text(row);
            let holder = holder.as_str();
            let lease = micros(lease);
            self.apart(async |client: &mut Object| {
                // One statement, in a transaction of its own: committed when it answers.
                Ok(client.execute(HOLD, &[&id, &holder, &lease]).await? == 1)
            })
            .await
            .map_err(StoreError::from)
        })
    }

    fn hand_to_person<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let id = row_text(row);
            let holder = holder.as_str();
            self.apart(async |client: &mut Object| {
                match client.execute(HAND_OFF_HELD, &[&id, &holder]).await? {
                    0 => Err(PgAuditError::LeaseNotHeld { row: id.clone() }),
                    _ => Ok(()),
                }
            })
            .await
            .map_err(StoreError::from)
        })
    }
}
