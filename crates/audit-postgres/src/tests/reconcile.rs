//! Reconciliation in Postgres (decision 0009, "Reconciliation"): what migration 0009's
//! triggers and grants hold for every role, beyond what the contract suite's item 7 tries
//! through the store. A lookup is appended to a receipt in `unknown` as its next attempt, with
//! the database's time, and never changed or removed; reconciliation settles a receipt only on
//! a lookup recorded on it that establishes the state; a lease is written only on a receipt not
//! yet settled or handed to a person, and a hand-off and a count of claims only on one in
//! `unknown`; a hand-off is never undone, and the count of claims rises by one at a time; and
//! of two claims sent at once on two connections, the second waits for the first and claims
//! nothing (migration 0012).

use std::time::Duration;

use tokio_postgres::Client;

use super::receipts::{evidence_on, fresh_id, receipt_in};
use super::{GATEWAY_ROLE, INSUFFICIENT_PRIVILEGE, TestDatabase, code, message};
use crate::OWNER_ROLE;
use crate::reconcile::CLAIM;

/// A receipt in `state`, as [`receipt_in`] writes one, with its row's deadline to come unless
/// `past`.
async fn receipt(admin: &Client, state: &str, past: bool) -> String {
    let id = fresh_id(admin).await;
    receipt_in(admin, &id, &format!("key-{id}"), state, past).await;
    id
}

/// Appends a lookup to `id` as `client`, as attempt `attempt`, with `result`, whether it was
/// authoritative and a reference.
async fn append(
    client: &Client,
    id: &str,
    attempt: i32,
    result: &str,
    authoritative: bool,
    reference: Option<&str>,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            &format!(
                "INSERT INTO switchboard_audit.receipt_lookups
                     (row_id, attempt, result, authoritative, reference)
                 VALUES ('{id}', $1, $2, $3, $4)"
            ),
            &[&attempt, &result, &authoritative, &reference],
        )
        .await
}

/// Settles `id` as `state` by reconciliation, with `reference`, as `client`.
async fn settle(
    client: &Client,
    id: &str,
    state: &str,
    reference: Option<&str>,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            &format!(
                "UPDATE switchboard_audit.receipts
                 SET state = $1, established_by = 'reconciliation', reference = $2
                 WHERE row_id = '{id}'"
            ),
            &[&state, &reference],
        )
        .await
}

fn refused_with(result: Result<u64, tokio_postgres::Error>, words: &str) {
    let error = result.expect_err(words);
    assert!(
        message(&error).contains(words),
        "{words}: {}",
        message(&error)
    );
}

/// Reconciliation settles a receipt only on a lookup recorded on it that establishes the
/// state: no lookup, a failed one, or a search that was not authoritative establishes nothing;
/// `completed` needs a found effect with the same reference, and `not_performed` an
/// authoritative search that found nothing. For every role, the owner included.
#[tokio::test]
async fn reconciliation_settles_a_receipt_only_on_a_lookup_that_establishes_it() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let only_on = "by reconciliation only on a lookup recorded on it that establishes it";

    for client in [&gateway, &owner] {
        let id = receipt(&admin, "unknown", false).await;
        refused_with(settle(client, &id, "completed", Some("r-1")).await, only_on);
        refused_with(settle(client, &id, "not_performed", None).await, only_on);
        append(client, &id, 1, "failed", false, None).await.unwrap();
        refused_with(settle(client, &id, "completed", Some("r-1")).await, only_on);
        append(client, &id, 2, "not_found", false, None)
            .await
            .unwrap();
        refused_with(settle(client, &id, "not_performed", None).await, only_on);
        append(client, &id, 3, "found", true, Some("r-1"))
            .await
            .unwrap();
        refused_with(settle(client, &id, "completed", Some("r-2")).await, only_on);
        assert_eq!(
            settle(client, &id, "completed", Some("r-1")).await.unwrap(),
            1
        );

        let id = receipt(&admin, "pending", true).await;
        append(client, &id, 1, "not_found", true, None)
            .await
            .unwrap();
        assert_eq!(settle(client, &id, "not_performed", None).await.unwrap(), 1);
    }
}

/// A lookup is appended to a receipt that reads as `unknown` and has not been handed to a
/// person, as its next attempt, with the database's time; it is never changed or removed, by
/// the owner or by the gateway's role, which holds no privilege to try.
#[tokio::test]
async fn a_lookup_is_appended_as_the_next_attempt_and_never_changed_or_removed() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;

    let id = receipt(&admin, "unknown", false).await;
    refused_with(
        append(&gateway, &id, 2, "failed", false, None).await,
        "so the next is attempt 1, not 2",
    );
    append(&gateway, &id, 1, "failed", false, None)
        .await
        .unwrap();
    refused_with(
        append(&gateway, &id, 1, "failed", false, None).await,
        "so the next is attempt 2, not 1",
    );
    // The time is the database's, whatever an insert carries.
    owner
        .execute(
            &format!(
                "INSERT INTO switchboard_audit.receipt_lookups
                     (row_id, attempt, looked_up_at, result, authoritative)
                 VALUES ('{id}', 2, '2000-01-01T00:00:00Z', 'failed', false)"
            ),
            &[],
        )
        .await
        .unwrap();
    let recent: bool = owner
        .query_one(
            &format!(
                "SELECT bool_and(looked_up_at > clock_timestamp() - interval '1 minute')
                 FROM switchboard_audit.receipt_lookups WHERE row_id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(recent, "a lookup's time is the database's");
    // A lookup's shape: a found effect has a reference and is authoritative; nothing else has
    // a reference; a failed lookup is not authoritative.
    for (result, authoritative, reference) in [
        ("found", true, None),
        ("found", false, Some("r-1")),
        ("not_found", true, Some("r-1")),
        ("failed", true, None),
    ] {
        assert!(
            append(&gateway, &id, 3, result, authoritative, reference)
                .await
                .is_err(),
            "{result}, {authoritative}, {reference:?}"
        );
    }

    let never_changed = "is never changed or removed";
    for change in [
        format!(
            "UPDATE switchboard_audit.receipt_lookups SET result = 'not_found'
             WHERE row_id = '{id}'"
        ),
        format!("DELETE FROM switchboard_audit.receipt_lookups WHERE row_id = '{id}'"),
    ] {
        refused_with(owner.execute(&change, &[]).await, never_changed);
        let error = gateway.execute(&change, &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{change}");
    }
    let lookups: i64 = owner
        .query_one(
            &format!(
                "SELECT count(*) FROM switchboard_audit.receipt_lookups WHERE row_id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(lookups, 2);

    // Only on a receipt that reads as unknown, not handed to a person.
    let not_unknown = "is not in unknown, or was handed to a person";
    for (state, past) in [
        ("pending", false),
        ("completed", true),
        ("not_performed", true),
    ] {
        let other = receipt(&admin, state, past).await;
        refused_with(
            append(&gateway, &other, 1, "failed", false, None).await,
            not_unknown,
        );
    }
    let handed = receipt(&admin, "unknown", false).await;
    gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.receipts SET handed_to_person_at = clock_timestamp()
                 WHERE row_id = '{handed}'"
            ),
            &[],
        )
        .await
        .unwrap();
    refused_with(
        append(&gateway, &handed, 1, "failed", false, None).await,
        not_unknown,
    );
}

/// A lease is written only on a receipt not yet settled or handed to a person: `pending`, within
/// its row's deadline or past it, or `unknown`, as the call that reserved it holds it while its
/// side effect runs on (migration 0012). A hand-off is written only on a receipt that reads as
/// `unknown` and has not been handed to a person; it takes the database's time and is never
/// undone, and once it is made reconciliation settles nothing. A receipt is reserved with
/// neither. The gateway's role cannot write a receipt's target, nor a lookup's time.
#[tokio::test]
async fn a_lease_is_written_only_on_a_receipt_not_settled_and_a_hand_off_only_in_unknown() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let lease = |id: &str| {
        format!(
            "UPDATE switchboard_audit.receipts
             SET lease_holder = 'instance-a', lease_until = clock_timestamp() + interval '1 minute'
             WHERE row_id = '{id}'"
        )
    };
    let hand_off = |id: &str| {
        format!(
            "UPDATE switchboard_audit.receipts SET handed_to_person_at = clock_timestamp()
             WHERE row_id = '{id}'"
        )
    };
    let not_unknown = "is not in unknown, or was handed to a person";
    let settled = "is settled, or was handed to a person, so its lease is not written";

    let unknown = receipt(&admin, "unknown", false).await;
    assert_eq!(gateway.execute(&lease(&unknown), &[]).await.unwrap(), 1);
    let past = receipt(&admin, "pending", true).await;
    assert_eq!(gateway.execute(&lease(&past), &[]).await.unwrap(), 1);
    let pending = receipt(&admin, "pending", false).await;
    assert_eq!(gateway.execute(&lease(&pending), &[]).await.unwrap(), 1);
    refused_with(gateway.execute(&hand_off(&pending), &[]).await, not_unknown);
    for (state, past) in [("completed", true), ("not_performed", false)] {
        let other = receipt(&admin, state, past).await;
        refused_with(gateway.execute(&lease(&other), &[]).await, settled);
        refused_with(owner.execute(&lease(&other), &[]).await, settled);
        refused_with(gateway.execute(&hand_off(&other), &[]).await, not_unknown);
    }

    // A hand-off takes the database's time and is never undone.
    let handed = receipt(&admin, "unknown", false).await;
    evidence_on(&admin, &handed).await;
    gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.receipts
                 SET handed_to_person_at = '2000-01-01T00:00:00Z' WHERE row_id = '{handed}'"
            ),
            &[],
        )
        .await
        .unwrap();
    let recent: bool = gateway
        .query_one(
            &format!(
                "SELECT handed_to_person_at > clock_timestamp() - interval '1 minute'
                 FROM switchboard_audit.receipts WHERE row_id = '{handed}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(recent, "a hand-off's time is the database's");
    for client in [&gateway, &owner] {
        refused_with(
            client
                .execute(
                    &format!(
                        "UPDATE switchboard_audit.receipts SET handed_to_person_at = NULL
                         WHERE row_id = '{handed}'"
                    ),
                    &[],
                )
                .await,
            not_unknown,
        );
        refused_with(client.execute(&lease(&handed), &[]).await, settled);
        refused_with(
            settle(client, &handed, "completed", Some("found-1")).await,
            "was handed to a person, so reconciliation no longer settles it",
        );
    }

    // A receipt is reserved with no lease and not handed to anyone.
    let row = receipt(&admin, "unknown", false).await;
    admin
        .execute(
            &format!("DELETE FROM switchboard_audit.receipts WHERE row_id = '{row}'"),
            &[],
        )
        .await
        .unwrap();
    for (column, value) in [
        (
            "lease_holder, lease_until",
            "'instance-a', clock_timestamp()",
        ),
        ("handed_to_person_at", "clock_timestamp()"),
        ("claims", "1"),
    ] {
        refused_with(
            owner
                .execute(
                    &format!(
                        "INSERT INTO switchboard_audit.receipts (
                             row_id, principal_issuer, principal_subject, idempotency_key, tool,
                             digest, resources, resources_omitted, {column}
                         ) VALUES (
                             '{row}', 'https://issuer.fixture.test', 'sandbox', 'key-{row}',
                             'fixture__draft', repeat('a', 64), '[]', 0, {value}
                         )"
                    ),
                    &[],
                )
                .await,
            "is reserved with no lease, no claim and not handed to a person",
        );
    }

    // What the gateway's role may not write at all.
    for change in [
        format!(
            "UPDATE switchboard_audit.receipts SET target_identifier = 'elsewhere'
             WHERE row_id = '{unknown}'"
        ),
        format!(
            "UPDATE switchboard_audit.receipt_lookups SET looked_up_at = clock_timestamp()
             WHERE row_id = '{unknown}'"
        ),
        format!(
            "INSERT INTO switchboard_audit.receipt_lookups
                 (row_id, attempt, looked_up_at, result, authoritative)
             VALUES ('{unknown}', 1, clock_timestamp(), 'failed', false)"
        ),
    ] {
        let error = gateway.execute(&change, &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{change}");
    }
}

/// A claim is counted only on a receipt in `unknown` not handed to a person, and only one at a
/// time, for every role: the count cannot jump, fall or be written on a receipt `pending`
/// within its row's deadline, settled or handed off (migration 0012).
#[tokio::test]
async fn a_claim_is_counted_one_at_a_time_and_only_in_unknown() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let count = |id: &str, claims: &str| {
        format!("UPDATE switchboard_audit.receipts SET claims = {claims} WHERE row_id = '{id}'")
    };
    let one_more = "counts one claim more than";
    let not_unknown = "is not in unknown, or was handed to a person";

    let unknown = receipt(&admin, "unknown", false).await;
    assert_eq!(
        gateway
            .execute(&count(&unknown, "claims + 1"), &[])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        gateway
            .execute(&count(&unknown, "claims + 1"), &[])
            .await
            .unwrap(),
        1
    );
    for client in [&gateway, &owner] {
        refused_with(
            client.execute(&count(&unknown, "claims + 2"), &[]).await,
            one_more,
        );
        refused_with(
            client.execute(&count(&unknown, "claims - 1"), &[]).await,
            one_more,
        );
        refused_with(client.execute(&count(&unknown, "0"), &[]).await, one_more);
    }
    let claims: i32 = admin
        .query_one(
            &format!("SELECT claims FROM switchboard_audit.receipts WHERE row_id = '{unknown}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(claims, 2);
    let past = receipt(&admin, "pending", true).await;
    assert_eq!(
        gateway
            .execute(&count(&past, "claims + 1"), &[])
            .await
            .unwrap(),
        1
    );
    for (state, past) in [
        ("pending", false),
        ("completed", true),
        ("not_performed", false),
    ] {
        let other = receipt(&admin, state, past).await;
        refused_with(
            gateway.execute(&count(&other, "claims + 1"), &[]).await,
            not_unknown,
        );
    }
    gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.receipts SET handed_to_person_at = clock_timestamp()
                 WHERE row_id = '{unknown}'"
            ),
            &[],
        )
        .await
        .unwrap();
    refused_with(
        gateway.execute(&count(&unknown, "claims + 1"), &[]).await,
        not_unknown,
    );
}

/// A recorded lookup is never changed, even into what would pass as the next attempt: moving
/// the last lookup to the next attempt's number and making it an authoritative search that
/// found nothing, which would let reconciliation settle the receipt `not_performed` on a lookup
/// never made, is refused by the trigger `lookup_appends` as a change, for the owner, and the
/// lookup and the receipt stay as they were.
#[tokio::test]
async fn a_recorded_lookup_is_never_changed_even_into_the_next_attempt() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;

    let id = receipt(&admin, "unknown", false).await;
    append(&gateway, &id, 1, "failed", false, None)
        .await
        .unwrap();
    refused_with(
        owner
            .execute(
                &format!(
                    "UPDATE switchboard_audit.receipt_lookups
                     SET attempt = 2, result = 'not_found', authoritative = true
                     WHERE row_id = '{id}' AND attempt = 1"
                ),
                &[],
            )
            .await,
        "is never changed or removed",
    );
    refused_with(
        settle(&owner, &id, "not_performed", None).await,
        "by reconciliation only on a lookup recorded on it that establishes it",
    );
    let lookup: (i32, String, bool) = owner
        .query_one(
            &format!(
                "SELECT attempt, result, authoritative FROM switchboard_audit.receipt_lookups
                 WHERE row_id = '{id}'"
            ),
            &[],
        )
        .await
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(lookup, (1, "failed".to_owned(), false));
}

/// Two claims of one receipt sent at once, on two connections of the gateway's role, never both
/// win: the first takes the receipt's row lock in a transaction still open, the second waits
/// for it, as the database shows, and once the first commits the second finds the lease taken
/// and claims nothing. The receipt is held by the first and counts one claim.
#[tokio::test]
async fn two_claims_sent_at_once_never_both_win() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let first = db.connect_as(GATEWAY_ROLE).await;
    let second = db.connect_as(GATEWAY_ROLE).await;
    let lease: i64 = 60_000_000;

    for round in 0..3 {
        let id = receipt(&admin, "unknown", true).await;
        first.batch_execute("BEGIN").await.unwrap();
        let won = first
            .query(CLAIM, &[&id, &"instance-first", &lease])
            .await
            .unwrap();
        assert_eq!(won.len(), 1, "round {round}: the first claim did not win");
        let waiting = {
            let id = id.clone();
            let second = &second;
            async move {
                second
                    .query(CLAIM, &[&id, &"instance-second", &lease])
                    .await
            }
        };
        let blocked = async {
            // The second claim waits for the first's row lock.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let waits: i64 = admin
                    .query_one(
                        "SELECT count(*) FROM pg_stat_activity
                         WHERE datname = current_database() AND wait_event_type = 'Lock'
                             AND query LIKE 'UPDATE switchboard_audit.receipts r%'",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                if waits == 1 {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "round {round}: the second claim never waited for the first"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            first.batch_execute("COMMIT").await.unwrap();
        };
        let (lost, ()) = tokio::join!(waiting, blocked);
        assert_eq!(
            lost.unwrap().len(),
            0,
            "round {round}: both claims sent at once won"
        );
        let (holder, claims): (String, i32) = admin
            .query_one(
                &format!(
                    "SELECT lease_holder, claims FROM switchboard_audit.receipts
                     WHERE row_id = '{id}'"
                ),
                &[],
            )
            .await
            .map(|row| (row.get(0), row.get(1)))
            .unwrap();
        assert_eq!(
            (holder.as_str(), claims),
            ("instance-first", 1),
            "round {round}"
        );
    }
}
