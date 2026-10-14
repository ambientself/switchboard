//! The audit store contract suite on the Postgres store, in the slow loop: the same functions
//! the testkit runs on its in-memory store. Rows are read back as the server's superuser, since
//! the gateway's role cannot read who called what.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::audit::{AuditRowId, RowKind};
use gateway_core::{AuditStore, Receipt};
use gateway_testkit::StoreBudgets;
use gateway_testkit::contract::{self, ContractStore, StoredRecord, StoredRow};
use serde_json::{Value, json};
use tokio_postgres::Client;

use super::TestDatabase;
use crate::{Budgets, PgAuditStore, PoolSizes};

/// Budgets other than the defaults, so a store that ignores the ones it was given is caught,
/// each with a part millisecond, which the store drops from the allowance.
const BUDGETS: Budgets = Budgets {
    begin: Duration::from_micros(3_000_400),
    answer: Duration::from_micros(2_500_300),
    finish_deadline: Duration::from_micros(45_000_700),
};

/// The Postgres store, and a superuser session on its database to read rows back.
struct Postgres {
    store: PgAuditStore,
    admin: Client,
}

impl ContractStore for Postgres {
    fn store(&self) -> &dyn AuditStore {
        &self.store
    }

    async fn stored(&self, row: &AuditRowId) -> Option<StoredRow> {
        // By the identifier's text, so an identifier that is not a UUID finds nothing rather
        // than failing the cast.
        let row = self
            .admin
            .query_opt(
                "SELECT kind, instance, allowance_ms, tool_use_id, deployment, surface, profile,
                        tool, connector, classification, resources, resources_omitted,
                        decision, reason, sentence, policy_revision,
                        proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
                        proved_delegation_team, claimed_acting_person, claimed_team,
                        outcome, outcome_sentence, error_kind, latency_ms, listed_tools,
                        listed_omitted, credential_mode, credential_principal,
                        (extract(epoch FROM begun_at) * 1000000)::bigint AS begun_at_micros,
                        deadline IS NOT NULL AS deadline_set,
                        (extract(epoch FROM deadline - begun_at) * 1000000)::bigint
                            AS deadline_micros
                 FROM switchboard_audit.call_rows WHERE id::text = $1",
                &[&row.as_str()],
            )
            .await
            .unwrap()?;
        let text = |column: &str| row.get::<_, Option<String>>(column);
        let mut principal = json!({
            "id": {"issuer": text("proved_issuer"), "subject": text("proved_subject")},
            "kind": text("proved_kind"),
        });
        match text("proved_kind").as_deref() {
            Some("workload") => principal["team"] = json!(text("proved_team")),
            _ => principal["groups"] = json!(row.get::<_, Option<Vec<String>>>("proved_groups")),
        }
        let completion = text("outcome").map(|outcome| {
            let mut completion = json!({
                "outcome": outcome,
                "latency_ms": row.get::<_, Option<i64>>("latency_ms"),
            });
            if let Some(sentence) = text("outcome_sentence") {
                completion["sentence"] = json!(sentence);
            }
            if let Some(error_kind) = text("error_kind") {
                completion["error_kind"] = json!(error_kind);
            }
            completion
        });
        let kind = match text("kind").as_deref() {
            Some("call") => RowKind::Call,
            Some("list") => RowKind::List,
            other => panic!("a row of kind {other:?}"),
        };
        let record = match kind {
            RowKind::Call => {
                let resources = match row.get::<_, Option<Value>>("resources") {
                    Some(Value::String(unknown)) => json!(unknown),
                    // A reach, `{"reach": entry}`, is the record's own form of it.
                    Some(reach @ Value::Object(_)) => reach,
                    named => json!({ "named": named }),
                };
                // Both columns or neither; a row with one would fail to read back.
                let credential = match (text("credential_mode"), text("credential_principal")) {
                    (None, None) => Value::Null,
                    (mode, principal) => json!({ "mode": mode, "principal": principal }),
                };
                // The table holds the allowance, which is the store's budgets, each in whole
                // milliseconds, and the call deadline. The budgets are worked out here, not
                // with the store's own arithmetic, so a store that leaves one out is caught.
                let budgets_ms = u64::try_from(
                    BUDGETS.begin.as_millis()
                        + BUDGETS.finish_deadline.as_millis()
                        + BUDGETS.answer.as_millis(),
                )
                .unwrap();
                let allowance = row
                    .get::<_, Option<i64>>("allowance_ms")
                    .map(|allowance| u64::try_from(allowance).unwrap());
                let call_deadline_ms =
                    allowance.map(|allowance| allowance.checked_sub(budgets_ms).unwrap());
                StoredRecord::Call(
                    serde_json::from_value(json!({
                        "kind": "call",
                        "instance": text("instance"),
                        "call_deadline_ms": call_deadline_ms,
                        "tool_use_id": text("tool_use_id"),
                        "deployment": text("deployment"),
                        "surface": text("surface"),
                        "profile": text("profile"),
                        "tool": text("tool"),
                        "connector": text("connector"),
                        "classification": text("classification"),
                        "resources": resources,
                        "resources_omitted": row.get::<_, Option<i64>>("resources_omitted"),
                        "decision": text("decision"),
                        "reason": text("reason"),
                        "sentence": text("sentence"),
                        "policy_revision": text("policy_revision"),
                        "proved_principal": principal,
                        "proved_delegation_team": text("proved_delegation_team"),
                        "claimed_acting_person": text("claimed_acting_person"),
                        "claimed_team": text("claimed_team"),
                        "credential": credential,
                        "completion": completion,
                    }))
                    .unwrap(),
                )
            }
            RowKind::List => StoredRecord::List(
                serde_json::from_value(json!({
                    "instance": text("instance"),
                    "deployment": text("deployment"),
                    "surface": text("surface"),
                    "profile": text("profile"),
                    "policy_revision": text("policy_revision"),
                    "proved_principal": principal,
                    "proved_delegation_team": text("proved_delegation_team"),
                    "claimed_acting_person": text("claimed_acting_person"),
                    "claimed_team": text("claimed_team"),
                    "tools": row.get::<_, Option<Value>>("listed_tools"),
                    "tools_omitted": row.get::<_, Option<i64>>("listed_omitted"),
                }))
                .unwrap(),
            ),
        };
        Some(StoredRow {
            record,
            kind,
            completion: completion.map(|completion| serde_json::from_value(completion).unwrap()),
            begun_at: row
                .get::<_, Option<i64>>("begun_at_micros")
                .map(micros_since_epoch),
            deadline_set: row.get("deadline_set"),
            deadline_after_begin: row
                .get::<_, Option<i64>>("deadline_micros")
                .map(|micros| Duration::from_micros(u64::try_from(micros).unwrap())),
        })
    }

    fn budgets(&self) -> StoreBudgets {
        StoreBudgets {
            begin: BUDGETS.begin,
            answer: BUDGETS.answer,
            finish_deadline: BUDGETS.finish_deadline,
        }
    }

    /// The database's clock, which `set_times` reads for a row's time at begin.
    async fn now(&self) -> SystemTime {
        let now = self
            .admin
            .query_one(
                "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
                &[],
            )
            .await
            .unwrap();
        micros_since_epoch(now.get(0))
    }

    /// The store keeps no receipts yet, so the functions that read them are not run here: see
    /// [`NOT_YET_ON_POSTGRES`].
    async fn receipts(&self) -> Vec<Receipt> {
        panic!("{NOT_YET_ON_POSTGRES}")
    }

    /// As [`receipts`](Self::receipts): only item 6's functions lose confirmations.
    fn lose_every_begin_confirmation(&self) {
        panic!("{NOT_YET_ON_POSTGRES}")
    }
}

/// A time Postgres gave in whole microseconds since the epoch.
fn micros_since_epoch(micros: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(u64::try_from(micros).unwrap())
}

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let Some(db) = TestDatabase::create().await else {
                    return;
                };
                let postgres = Postgres {
                    store: db.store(PoolSizes::default()).with_budgets(BUDGETS),
                    admin: db.admin().await,
                };
                contract::$name(&postgres).await;
            }
        )*
    };
}

contract!(
    begin_is_ok_only_once_stored_and_idempotent_by_identifier,
    the_stored_row_is_exactly_the_record,
    a_record_the_store_cannot_hold_is_refused_and_leaves_no_row,
    a_call_row_over_begins_bound_is_refused_naming_its_largest_column,
    a_list_row_over_the_bound_is_refused_naming_its_largest_column,
    a_refusal_sentence_over_the_cap_is_refused_at_finish_and_leaves_the_row_open,
    a_reach_is_stored_as_the_entry_it_names,
    a_credential_identity_is_stored_as_begin_was_given_it,
    a_repeated_begin_compares_the_decision_and_not_the_reach_or_credential,
    finish_completes_once_accepts_an_identical_repeat_and_refuses_a_different_one,
    finish_touches_only_the_completion,
    an_error_is_stored_with_its_kind_and_a_repeat_must_match_it,
    the_deadline_is_the_begin_time_plus_begin_budget_call_deadline_finish_deadline_and_answer_budget,
    a_list_row_is_stored_complete_with_no_deadline,
    a_call_record_of_kind_list_is_refused_at_begin_and_leaves_no_row,
);

/// Why item 6 of the contract suite, receipts, is not run against Postgres: the store keeps
/// none yet (#55), and refuses every begin that would reserve one, so nothing runs. Each of
/// its functions is listed below, ignored with this reason, so that `cargo test` reports each
/// as not run rather than leaving it out. The package that stores receipts in Postgres runs
/// them.
const NOT_YET_ON_POSTGRES: &str = "the Postgres store keeps no receipts yet (#55), so item 6 of the contract suite is not run against it";

macro_rules! not_yet_on_postgres {
    ($($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            #[ignore = "the Postgres store keeps no receipts yet (#55)"]
            async fn $name() {
                let Some(db) = TestDatabase::create().await else {
                    return;
                };
                let postgres = Postgres {
                    store: db.store(PoolSizes::default()).with_budgets(BUDGETS),
                    admin: db.admin().await,
                };
                contract::$name(&postgres).await;
            }
        )*
    };
}

not_yet_on_postgres!(
    a_receipt_is_reserved_with_its_row_or_not_at_all,
    a_receipt_moves_with_its_finish,
    a_key_is_unique_in_its_scope_under_concurrent_calls,
    two_delegations_under_one_principal_may_use_the_same_key,
    a_begin_retried_after_a_lost_confirmation_finds_its_own_receipt_and_runs_once,
    a_begin_whose_confirmation_is_lost_on_every_attempt_leaves_its_row_error_and_its_receipt_not_performed,
    each_receipt_state_is_answered_by_the_first_line_of_the_reuse_table_that_matches,
);
