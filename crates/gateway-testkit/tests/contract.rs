//! The audit store contract suite on the in-memory store, in the per-change loop. The Postgres
//! store runs the same functions in its own crate's tests.

use std::time::Duration;

use gateway_testkit::{InMemoryAuditStore, StoreBudgets, block_on, contract};

/// Budgets other than the defaults, so a store that ignores the ones it was given is caught.
const BUDGETS: StoreBudgets = StoreBudgets {
    begin: Duration::from_secs(3),
    finish_deadline: Duration::from_secs(45),
};

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                block_on(contract::$name(&InMemoryAuditStore::new().with_budgets(BUDGETS)));
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
