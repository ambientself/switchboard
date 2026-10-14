//! Reconciliation in Postgres (decision 0009, "Reconciliation"): what migration 0009's
//! triggers and grants hold for every role, beyond what the contract suite's item 7 tries
//! through the store. A lookup is appended to a receipt in `unknown` as its next attempt, with
//! the database's time, and never changed or removed; reconciliation settles a receipt only on
//! a lookup recorded on it that establishes the state; a lease and a hand-off are written only
//! on a receipt in `unknown`, and a hand-off is never undone.

use tokio_postgres::Client;

use super::receipts::{evidence_on, fresh_id, receipt_in};
use super::{GATEWAY_ROLE, INSUFFICIENT_PRIVILEGE, TestDatabase, code, message};
use crate::OWNER_ROLE;

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

/// A lease and a hand-off are written only on a receipt that reads as `unknown` and has not
/// been handed to a person; a hand-off takes the database's time and is never undone, and once
/// it is made reconciliation settles nothing. A receipt is reserved with neither. The gateway's
/// role cannot write a receipt's target, nor a lookup's time.
#[tokio::test]
async fn a_lease_and_a_hand_off_are_written_only_on_a_receipt_in_unknown() {
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
    let not_unknown = "is not in unknown, or was handed to a person";

    let unknown = receipt(&admin, "unknown", false).await;
    assert_eq!(gateway.execute(&lease(&unknown), &[]).await.unwrap(), 1);
    let past = receipt(&admin, "pending", true).await;
    assert_eq!(gateway.execute(&lease(&past), &[]).await.unwrap(), 1);
    for (state, past) in [
        ("pending", false),
        ("completed", true),
        ("not_performed", false),
    ] {
        let other = receipt(&admin, state, past).await;
        refused_with(gateway.execute(&lease(&other), &[]).await, not_unknown);
        refused_with(owner.execute(&lease(&other), &[]).await, not_unknown);
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
        refused_with(client.execute(&lease(&handed), &[]).await, not_unknown);
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
            "is reserved with no lease and not handed to a person",
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
