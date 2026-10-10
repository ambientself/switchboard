//! The audit store contract suite on the in-memory store, in the per-change loop. The Postgres
//! store runs the same functions in its own crate's tests.

use std::time::{Duration, SystemTime};

use gateway_core::AuditStore;
use gateway_core::audit::AuditRowId;
use gateway_testkit::contract::{ContractStore, StoredRow};
use gateway_testkit::{InMemoryAuditStore, StoreBudgets, block_on, contract};

/// Budgets other than the defaults, so a store that ignores the ones it was given is caught.
const BUDGETS: StoreBudgets = StoreBudgets {
    begin: Duration::from_secs(3),
    finish_deadline: Duration::from_secs(45),
};

/// The in-memory store given [`BUDGETS`]. It answers the suite with [`BUDGETS`], not with the
/// budgets the store holds, so a store that ignored them would fail the deadline cases.
struct InMemory {
    store: InMemoryAuditStore,
}

impl ContractStore for InMemory {
    fn store(&self) -> &dyn AuditStore {
        &self.store
    }

    async fn stored(&self, row: &AuditRowId) -> Option<StoredRow> {
        ContractStore::stored(&self.store, row).await
    }

    fn budgets(&self) -> StoreBudgets {
        BUDGETS
    }

    async fn now(&self) -> SystemTime {
        ContractStore::now(&self.store).await
    }
}

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                block_on(contract::$name(&InMemory {
                    store: InMemoryAuditStore::new().with_budgets(BUDGETS),
                }));
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
