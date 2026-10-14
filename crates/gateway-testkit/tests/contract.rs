//! The audit store contract suite on the in-memory store, in the per-change loop. The Postgres
//! store runs the same functions in its own crate's tests.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gateway_core::audit::AuditRowId;
use gateway_core::{AuditStore, Receipt};
use gateway_identity::Clock;
use gateway_testkit::contract::{ContractStore, StoredRow};
use gateway_testkit::{
    FIXTURE_NOW, FixedClock, InMemoryAuditStore, StoreBudgets, block_on, contract,
};

/// Budgets other than the defaults, so a store that ignores the ones it was given is caught,
/// each with a part millisecond, which the store drops as Postgres's does.
const BUDGETS: StoreBudgets = StoreBudgets {
    begin: Duration::from_micros(3_000_400),
    answer: Duration::from_micros(2_500_300),
    finish_deadline: Duration::from_micros(45_000_700),
};

/// The in-memory store given [`BUDGETS`] and a clock a day past [`FIXTURE_NOW`], where the
/// store's default clock reads. It answers the suite with [`BUDGETS`] and that clock, not with
/// anything the store holds, so a store that ignored either would fail the deadline and time
/// cases. The day is a whole multiple of 16 seconds, so the deadline-end case still lands
/// exactly on the end of what a Postgres time holds.
struct InMemory {
    store: InMemoryAuditStore,
    clock: Arc<FixedClock>,
}

impl InMemory {
    fn new() -> Self {
        let clock = Arc::new(FixedClock::at(FIXTURE_NOW + 86_400));
        Self {
            store: InMemoryAuditStore::new()
                .with_budgets(BUDGETS)
                .with_clock(clock.clone()),
            clock,
        }
    }
}

impl ContractStore for InMemory {
    fn store(&self) -> &dyn AuditStore {
        &self.store
    }

    async fn stored(&self, row: &AuditRowId) -> Option<StoredRow> {
        contract::stored_in_memory(&self.store, row)
    }

    fn budgets(&self) -> StoreBudgets {
        BUDGETS
    }

    async fn now(&self) -> SystemTime {
        self.clock.now()
    }

    async fn receipts(&self) -> Vec<Receipt> {
        self.store.receipts()
    }

    fn lose_every_begin_confirmation(&self) {
        self.store.lose_all_begin_confirmations();
    }
}

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                block_on(contract::$name(&InMemory::new()));
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
    a_receipt_is_reserved_with_its_row_or_not_at_all,
    a_receipt_moves_with_its_finish,
    a_key_is_unique_in_its_scope_under_concurrent_calls,
    two_delegations_under_one_principal_may_use_the_same_key,
    a_begin_retried_after_a_lost_confirmation_finds_its_own_receipt_and_runs_once,
    a_begin_whose_confirmation_is_lost_on_every_attempt_leaves_its_row_error_and_its_receipt_not_performed,
    each_receipt_state_is_answered_by_the_first_line_of_the_reuse_table_that_matches,
);
