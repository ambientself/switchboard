//! Receipts in Postgres (decision 0009, part 2): what the trigger `receipt_moves`, the grants
//! and the transaction of a begin with a receipt hold, beyond what the contract suite's item 6
//! tries through the core, and the count of receipts in `unknown`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::audit::{self, Begun, Completion, Outcome, RequestMetadata, RowStart};
use gateway_core::receipt::{EstablishedBy, may_move};
use gateway_core::{
    BoxFuture, CallContext, Connector, IdempotencyKey, ReceiptState, RequestedTool, Reuse,
    ToolCall, ToolOutcome, ToolUseId, VendorReference, decide,
};
use gateway_testkit::{
    Caller, DRAFT_TOOL, Fixture, FixtureConnector, SURFACE_ALL, TEAM_A_DOCUMENT, fresh_key,
    row_start,
};
use serde_json::{Value, json};
use tokio_postgres::Client;

use super::schema::{complete, denied, insert, insert_row, list};
use super::{GATEWAY_ROLE, INSUFFICIENT_PRIVILEGE, TestDatabase, code, message};
use crate::{MIGRATIONS, OWNER_ROLE, PgAuditError, PgAuditStore, PoolSizes, migrate};

const STATES: [(&str, ReceiptState); 4] = [
    ("pending", ReceiptState::Pending),
    ("completed", ReceiptState::Completed),
    ("not_performed", ReceiptState::NotPerformed),
    ("unknown", ReceiptState::Unknown),
];

/// A fresh UUID from the database, as SQL may hold it inline.
pub(super) async fn fresh_id(client: &Client) -> String {
    client
        .query_one("SELECT gen_random_uuid()::text", &[])
        .await
        .unwrap()
        .get(0)
}

/// Writes, as the superuser with every trigger off, an allowed call row `id` whose deadline is
/// an hour past or an hour to come, and a receipt under it in `state`, with the key `key`.
pub(super) async fn receipt_in(admin: &Client, id: &str, key: &str, state: &str, past: bool) {
    let deadline = if past {
        "clock_timestamp() - interval '1 hour'"
    } else {
        "clock_timestamp() + interval '1 hour'"
    };
    let row = insert(&[
        ("id", &format!("'{id}'")),
        ("begun_at", "clock_timestamp() - interval '2 hours'"),
        ("deadline", deadline),
    ]);
    admin
        .batch_execute(&format!(
            "BEGIN;
             SET LOCAL session_replication_role = replica;
             {row};
             INSERT INTO switchboard_audit.receipts (
                 row_id, reserved_at, principal_issuer, principal_subject, idempotency_key,
                 tool, digest, resources, resources_omitted, state
             ) VALUES (
                 '{id}', clock_timestamp(), 'https://issuer.fixture.test', 'sandbox', '{key}',
                 'fixture__draft', repeat('a', 64), '[]', 0, '{state}'
             );
             COMMIT;"
        ))
        .await
        .unwrap();
}

/// Records on the receipt `id`, as the superuser with every trigger off, a lookup that found
/// the effect with the reference `found-1` and an authoritative search that found nothing: the
/// lookups that establish `completed` and `not_performed` by reconciliation.
pub(super) async fn evidence_on(admin: &Client, id: &str) {
    admin
        .batch_execute(&format!(
            "BEGIN;
             SET LOCAL session_replication_role = replica;
             INSERT INTO switchboard_audit.receipt_lookups
                 (row_id, attempt, looked_up_at, result, authoritative, reference)
             VALUES ('{id}', 1, clock_timestamp(), 'found', true, 'found-1'),
                    ('{id}', 2, clock_timestamp(), 'not_found', true, NULL);
             COMMIT;"
        ))
        .await
        .unwrap();
}

/// The trigger allows exactly the moves the core's `may_move` allows: every state to every
/// state, by the call, by reconciliation and by a person, before and after the row's deadline,
/// each tried as the gateway's role. A move by the call refused only because the deadline has
/// passed carries the SQLSTATE the store reads as that. A move by reconciliation is tried with
/// the lookups that establish either state recorded on the receipt, which migration 0009
/// requires; `tests/reconcile.rs` tries it without them.
#[tokio::test]
async fn the_receipt_trigger_allows_exactly_the_moves_the_core_allows() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let person = EstablishedBy::Person {
        person: "someone@example.test".into(),
    };
    let mut tried = 0;
    for (from_name, from) in STATES {
        for (to_name, to) in STATES {
            for (by_name, by) in [
                ("call", EstablishedBy::Call),
                ("reconciliation", EstablishedBy::Reconciliation),
                ("person", person.clone()),
            ] {
                for past in [false, true] {
                    let id = fresh_id(&admin).await;
                    receipt_in(&admin, &id, &format!("key-{tried}"), from_name, past).await;
                    let named = if by_name == "person" {
                        "'someone@example.test'"
                    } else {
                        "NULL"
                    };
                    let reference = if by_name == "reconciliation" {
                        evidence_on(&admin, &id).await;
                        "'found-1'"
                    } else {
                        "NULL"
                    };
                    let moved = gateway
                        .execute(
                            &format!(
                                "UPDATE switchboard_audit.receipts
                                 SET state = '{to_name}', established_by = '{by_name}',
                                     established_person = {named}, reference = {reference}
                                 WHERE row_id = '{id}'"
                            ),
                            &[],
                        )
                        .await;
                    let case = format!("{from_name} to {to_name} by {by_name}, past: {past}");
                    if may_move(from, to, &by, past) {
                        assert_eq!(moved.unwrap(), 1, "{case}");
                    } else {
                        let error = moved.expect_err(&case);
                        let past_deadline =
                            from == ReceiptState::Pending && by == EstablishedBy::Call && past;
                        assert_eq!(
                            code(&error) == Some("SB001"),
                            past_deadline,
                            "{case}: {}",
                            message(&error)
                        );
                    }
                    tried += 1;
                }
            }
        }
    }
    assert_eq!(tried, 96);
}

/// A receipt is reserved `pending`, by its call, with no reference, at the database's time, and
/// a move writes nothing but the state, how it was established and the reference: for every
/// role, the owner included. The gateway's role cannot delete a receipt or write any other
/// column of one.
#[tokio::test]
async fn the_receipt_trigger_and_grants_refuse_every_other_write() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let reserve = |id: &str, extra: &str, value: &str| {
        format!(
            "INSERT INTO switchboard_audit.receipts (
                 row_id, principal_issuer, principal_subject, idempotency_key, tool, digest,
                 resources, resources_omitted{extra}
             ) VALUES (
                 '{id}', 'https://issuer.fixture.test', 'sandbox', 'key-{id}', 'fixture__draft',
                 repeat('a', 64), '[]', 0{value}
             )"
        )
    };
    let id = insert_row(&owner, &insert(&[])).await;
    for (column, value) in [
        ("state", "'completed'"),
        ("established_by", "'reconciliation'"),
        ("reference", "'PR-7'"),
    ] {
        let error = owner
            .execute(
                &reserve(&id, &format!(", {column}"), &format!(", {value}")),
                &[],
            )
            .await
            .unwrap_err();
        assert!(
            message(&error).contains("is reserved pending, by its call, with no reference"),
            "{column}: {}",
            message(&error)
        );
    }
    owner
        .execute(
            &reserve(&id, ", reserved_at", ", '2000-01-01T00:00:00Z'"),
            &[],
        )
        .await
        .unwrap();
    let recent: bool = owner
        .query_one(
            &format!(
                "SELECT reserved_at > clock_timestamp() - interval '1 minute'
                 FROM switchboard_audit.receipts WHERE row_id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(recent, "the time of reservation is the database's");
    for assignment in [
        "tool = 'fixture__other'",
        "idempotency_key = 'another'",
        "principal_subject = 'someone-else'",
        "reserved_at = now()",
        "digest = repeat('b', 64)",
    ] {
        let error = owner
            .execute(
                &format!(
                    "UPDATE switchboard_audit.receipts SET state = 'completed', {assignment}
                     WHERE row_id = '{id}'"
                ),
                &[],
            )
            .await
            .unwrap_err();
        assert!(
            message(&error).contains("may be written"),
            "{assignment}: {}",
            message(&error)
        );
    }

    for statement in [
        format!("DELETE FROM switchboard_audit.receipts WHERE row_id = '{id}'"),
        format!("UPDATE switchboard_audit.receipts SET tool = 'x' WHERE row_id = '{id}'"),
        "TRUNCATE switchboard_audit.receipts".to_owned(),
        reserve(&fresh_id(&owner).await, ", state", ", 'pending'"),
        reserve(&fresh_id(&owner).await, ", reserved_at", ", now()"),
    ] {
        let error = gateway.execute(&statement, &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{statement}");
    }
}

/// A side effect allowed for team A: a proposal on its own document, carrying `key`.
fn proposal(
    fixture: &Fixture,
    text: &str,
    key: &IdempotencyKey,
) -> (gateway_core::Decision, Value) {
    let arguments = json!({"document": TEAM_A_DOCUMENT, "text": text});
    let context = CallContext {
        caller: fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(DRAFT_TOOL),
        resources: FixtureConnector::resources_of(DRAFT_TOOL, &arguments),
        key: Some(key.clone()),
        currency: gateway_core::Currency::NotAsked,
    };
    let decision = decide(&fixture.policy, &context);
    assert!(decision.is_allowed(), "{decision:?}");
    (decision, arguments)
}

/// Begins team A's proposal under `key`, as the row `start` names.
pub(super) async fn begin(
    store: &PgAuditStore,
    fixture: &Fixture,
    start: &RowStart,
    text: &str,
    key: &IdempotencyKey,
) -> Result<Begun, audit::AuditFailure> {
    let (decision, arguments) = proposal(fixture, text, key);
    audit::begin(
        store,
        start.clone(),
        decision,
        arguments,
        RequestMetadata {
            tool_use_id: Some(ToolUseId::new(key.as_str())),
            claimed_team: None,
        },
    )
    .await
}

/// How many call rows the table holds under `id`, read as the superuser.
async fn rows_under(admin: &Client, id: &str) -> i64 {
    admin
        .query_one(
            &format!("SELECT count(*) FROM switchboard_audit.call_rows WHERE id::text = '{id}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// The reservation is in the begin's own transaction: a receipt the database refuses leaves no
/// row, so nothing is left open and nothing runs.
#[tokio::test]
async fn a_reservation_the_database_refuses_leaves_no_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    let fixture = Fixture::new().unwrap();
    admin
        .batch_execute(
            "CREATE FUNCTION public.refuse_receipts() RETURNS trigger LANGUAGE plpgsql
                 AS $$BEGIN RAISE EXCEPTION 'the test refuses this receipt'; END$$;
             CREATE TRIGGER refuse_receipts BEFORE INSERT ON switchboard_audit.receipts
                 FOR EACH ROW EXECUTE FUNCTION public.refuse_receipts();",
        )
        .await
        .unwrap();
    let start = row_start();
    let begun = begin(&store, &fixture, &start, "Refused.", &fresh_key()).await;
    assert!(begun.is_err(), "{begun:?}");
    assert_eq!(rows_under(&admin, start.row.as_str()).await, 0);
    assert_eq!(
        store.finishes().in_flight,
        0,
        "nothing was left to complete"
    );

    admin
        .batch_execute("DROP TRIGGER refuse_receipts ON switchboard_audit.receipts")
        .await
        .unwrap();
    let begun = begin(&store, &fixture, &start, "Refused.", &fresh_key()).await;
    assert!(matches!(begun, Ok(Begun::Allowed(_))), "{begun:?}");
    assert_eq!(rows_under(&admin, start.row.as_str()).await, 1);
}

/// A connector that answers every call with one outcome.
struct Answers(ToolOutcome);

impl Connector for Answers {
    fn run(&self, _call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(std::future::ready(self.0.clone()))
    }
}

/// A retried begin of a reused key's row answers what the row was written with, though the
/// earlier receipt has moved since: a call answered while the earlier one was `pending` is
/// answered so again once it is `completed`. A new call under the key is a `duplicate`, with
/// the earlier receipt's reference.
#[tokio::test]
async fn a_retried_begin_answers_what_its_row_was_written_with() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db.store(PoolSizes::default());
    let fixture = Fixture::new().unwrap();
    let key = fresh_key();
    let first = row_start();
    let Ok(Begun::Allowed(guard)) = begin(&store, &fixture, &first, "Once.", &key).await else {
        panic!("the first call was not begun as allowed");
    };
    let second = row_start();
    let may_have = Reuse::MayHaveHappened {
        key: key.clone(),
        receipt: first.row.clone(),
    };
    for _ in 0..2 {
        match begin(&store, &fixture, &second, "Once.", &key).await {
            Ok(Begun::Reused(reused)) => assert_eq!(reused.reuse(), &may_have),
            other => panic!("the second call was not answered from the receipt: {other:?}"),
        }
    }
    let connector = Answers(ToolOutcome::Completed(
        json!({"draft": "d-1"}),
        VendorReference::new("d-1"),
    ));
    let finished = audit::finish(&store, audit::run(&connector, guard).await, 3).await;
    assert!(finished.failure().is_none(), "{:?}", finished.failure());

    match begin(&store, &fixture, &second, "Once.", &key).await {
        Ok(Begun::Reused(reused)) => assert_eq!(reused.reuse(), &may_have),
        other => panic!("the retried second call was answered otherwise: {other:?}"),
    }
    match begin(&store, &fixture, &row_start(), "Once.", &key).await {
        Ok(Begun::Reused(reused)) => assert_eq!(
            reused.reuse(),
            &Reuse::Duplicate {
                key: key.clone(),
                receipt: first.row.clone(),
                reference: Some(VendorReference::new("d-1")),
            }
        ),
        other => panic!("a third call was not a duplicate: {other:?}"),
    }
}

/// Finish refuses `unknown` for a row that reserved no receipt, and writes nothing: a read
/// never reports it.
#[tokio::test]
async fn unknown_for_a_row_with_no_receipt_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let store = db.store(PoolSizes::default());
    let id = insert_row(&gateway, &insert(&[])).await;
    let refused = store
        .complete(
            &gateway_core::audit::AuditRowId::new(id.clone()),
            &Completion {
                outcome: Outcome::Unknown,
                latency_ms: 2,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(PgAuditError::NoReceipt { .. })),
        "{refused:?}"
    );
    let admin = db.admin().await;
    let outcome: Option<String> = admin
        .query_one(
            &format!("SELECT outcome FROM switchboard_audit.call_rows WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(outcome, None);
}

/// Moves the deadline of the row `id` to its time at begin, which is past, as the superuser.
async fn pass_deadline(admin: &Client, id: &str) {
    admin
        .batch_execute(&format!(
            "BEGIN;
             SET LOCAL session_replication_role = replica;
             UPDATE switchboard_audit.call_rows SET deadline = begun_at WHERE id = '{id}';
             COMMIT;"
        ))
        .await
        .unwrap();
}

/// The receipts in `unknown` are those in the state `unknown` and those still `pending` past
/// their row's deadline; not one `pending` before it, nor one settled. The oldest is the
/// earliest reserved of them, by the database's clock.
#[tokio::test]
async fn the_receipts_in_unknown_are_counted_with_the_oldest() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    let fixture = Fixture::new().unwrap();
    assert_eq!(
        store.unknown_receipts().await.unwrap(),
        crate::UnknownReceipts {
            count: 0,
            oldest_reserved: None
        }
    );
    let mut guards = Vec::new();
    let mut rows = Vec::new();
    for text in ["pending, past", "unknown", "pending", "completed"] {
        let start = row_start();
        let Ok(Begun::Allowed(guard)) = begin(&store, &fixture, &start, text, &fresh_key()).await
        else {
            panic!("{text} was not begun as allowed");
        };
        guards.push(guard);
        rows.push(start.row);
    }
    pass_deadline(&admin, rows[0].as_str()).await;
    let mut guards = guards.into_iter();
    let _pending_past_its_deadline = guards.next().unwrap();
    let unknown = guards.next().unwrap();
    let _pending = guards.next().unwrap();
    let completed = guards.next().unwrap();
    for (guard, outcome) in [
        (unknown, ToolOutcome::Unknown),
        (completed, ToolOutcome::Ok(json!({}))),
    ] {
        let finished = audit::finish(&store, audit::run(&Answers(outcome), guard).await, 1).await;
        assert!(finished.failure().is_none(), "{:?}", finished.failure());
    }

    let oldest: i64 = admin
        .query_one(
            &format!(
                "SELECT (extract(epoch FROM min(reserved_at)) * 1000000)::bigint
                 FROM switchboard_audit.receipts
                 WHERE row_id IN ('{}', '{}')",
                rows[0].as_str(),
                rows[1].as_str()
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let found = store.unknown_receipts().await.unwrap();
    assert_eq!(found.count, 2);
    assert_eq!(
        found.oldest_reserved,
        Some(UNIX_EPOCH + Duration::from_micros(u64::try_from(oldest).unwrap()))
    );
    assert!(found.oldest_reserved.unwrap() <= SystemTime::now() + Duration::from_secs(60));
}

/// The first column of every row `sql` reads.
async fn values(client: &Client, sql: &str) -> Vec<Value> {
    client
        .query(sql, &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// Migration 0008 is additive: rows written before it keep every value they had, and none of
/// them names a receipt.
#[tokio::test]
async fn the_receipts_migration_keeps_the_rows_already_written() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
        .await
        .unwrap();
    owner
        .batch_execute(
            "CREATE SCHEMA switchboard_audit;
             CREATE TABLE switchboard_audit.migrations (
                 version    integer     PRIMARY KEY,
                 name       text        NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await
        .unwrap();
    for migration in &MIGRATIONS[..7] {
        owner.batch_execute(migration.sql).await.unwrap();
        owner
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await
            .unwrap();
    }
    for outcome in ["ok", "error", "refused"] {
        let id = insert_row(&owner, &insert(&[])).await;
        let completed = if outcome == "refused" {
            owner
                .execute(
                    &format!(
                        "UPDATE switchboard_audit.call_rows
                         SET outcome = 'refused', outcome_sentence = 'No.', latency_ms = 1
                         WHERE id = '{id}'"
                    ),
                    &[],
                )
                .await
        } else {
            complete(&owner, &id, outcome).await
        };
        assert_eq!(completed.unwrap(), 1, "{outcome}");
    }
    insert_row(&owner, &insert(&[])).await;
    insert_row(&owner, &denied()).await;
    insert_row(&owner, &list(&[])).await;
    let before = values(
        &owner,
        "SELECT to_jsonb(r) FROM switchboard_audit.call_rows r ORDER BY id",
    )
    .await;

    assert_eq!(migrate(&mut owner).await.unwrap(), vec![8, 9]);
    let after = values(
        &owner,
        "SELECT to_jsonb(r) - 'duplicate_of' FROM switchboard_audit.call_rows r ORDER BY id",
    )
    .await;
    assert_eq!(after, before);
    let named: i64 = owner
        .query_one(
            "SELECT count(*) FROM switchboard_audit.call_rows WHERE duplicate_of IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(named, 0);
}
