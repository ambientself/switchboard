//! The audit store contract suite on the Postgres store, in the slow loop: the same functions
//! the testkit runs on its in-memory store. Rows are read back as the server's superuser, since
//! the gateway's role cannot read who called what.

use std::time::Duration;

use gateway_core::AuditStore;
use gateway_core::audit::{AuditRowId, RowKind};
use gateway_testkit::StoreBudgets;
use gateway_testkit::contract::{self, ContractStore, StoredRecord, StoredRow};
use serde_json::{Value, json};
use tokio_postgres::Client;

use super::TestDatabase;
use crate::{Budgets, PgAuditStore, PoolSizes};

/// Budgets other than the defaults, so a store that ignores the ones it was given is caught.
const BUDGETS: Budgets = Budgets {
    begin: Duration::from_secs(3),
    answer: Duration::from_secs(2),
    finish_deadline: Duration::from_secs(45),
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
                        outcome, outcome_sentence, latency_ms, listed_tools, listed_omitted,
                        begun_at IS NOT NULL AS begun_at_set,
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
                    named => json!({ "named": named }),
                };
                // The table holds the allowance, which is the store's budgets and the call
                // deadline. The budgets are worked out here, not with the store's own
                // arithmetic, so a store that leaves one out is caught.
                let budgets_ms =
                    u64::try_from((BUDGETS.begin + BUDGETS.finish_deadline).as_millis()).unwrap();
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
            begun_at_set: row.get("begun_at_set"),
            deadline_set: row.get("deadline_set"),
            deadline_after_begin: row
                .get::<_, Option<i64>>("deadline_micros")
                .map(|micros| Duration::from_micros(u64::try_from(micros).unwrap())),
        })
    }

    fn budgets(&self) -> StoreBudgets {
        StoreBudgets {
            begin: BUDGETS.begin,
            finish_deadline: BUDGETS.finish_deadline,
        }
    }
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
    finish_completes_once_accepts_an_identical_repeat_and_refuses_a_different_one,
    finish_touches_only_the_completion,
    the_deadline_is_the_begin_time_plus_begin_budget_call_deadline_and_finish_deadline,
    a_list_row_is_stored_complete_with_no_deadline,
);
