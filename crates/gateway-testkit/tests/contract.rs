//! The audit store contract suite on the in-memory store, in the per-change loop. The Postgres
//! store runs the same functions in its own crate's tests.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use gateway_core::audit::AuditRowId;
use gateway_core::{AuditStore, Receipt, ReceiptAttribution, ReceiptQueue};
use gateway_identity::Clock;
use gateway_testkit::contract::{ContractStore, StoredRow};
use gateway_testkit::{
    FIXTURE_NOW, InMemoryAuditStore, SteppableClock, StoreBudgets, block_on, contract,
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
/// exactly on the end of what a Postgres time holds. The clock moves only when a function
/// passes a row's deadline.
struct InMemory {
    store: InMemoryAuditStore,
    clock: Arc<SteppableClock>,
}

impl InMemory {
    fn new() -> Self {
        let clock = Arc::new(SteppableClock::at(FIXTURE_NOW + 86_400));
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
        self.store.held_receipts()
    }

    fn lose_every_begin_confirmation(&self) {
        self.store.lose_all_begin_confirmations();
    }

    async fn pass_deadline(&self, row: &AuditRowId) {
        let Some(deadline) = self.store.deadline(row) else {
            panic!("the row {} has no deadline", row.as_str());
        };
        let to_go = deadline
            .duration_since(self.clock.now())
            .unwrap_or_default();
        self.clock.advance(to_go + Duration::from_millis(1));
    }

    fn queue(&self) -> &dyn ReceiptQueue {
        &self.store
    }

    fn attribution(&self) -> &dyn ReceiptAttribution {
        &self.store
    }

    async fn pass_lease(&self, row: &AuditRowId) {
        let Some(until) = self.store.lease_until(row) else {
            panic!("the receipt {} was never leased", row.as_str());
        };
        let to_go = until.duration_since(self.clock.now()).unwrap_or_default();
        self.clock.advance(to_go);
    }

    fn late_finish_disagreements(&self) -> u64 {
        self.store.late_finish_disagreements()
    }

    async fn lost_begins_given_up(&self) -> u64 {
        self.store.lost_begins_given_up()
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
    a_delegation_and_its_currency_are_stored_as_begin_was_given_them,
    an_unverified_delegation_denied_before_check_3_is_stored_as_that_denial_alone,
    a_delegation_of_the_wrong_shape_is_refused_and_leaves_no_row,
    an_exception_is_stored_on_an_allowed_write_and_refused_elsewhere,
    a_repeated_begin_compares_the_decision_and_not_the_reach_or_credential,
    finish_completes_once_accepts_an_identical_repeat_and_refuses_a_different_one,
    finish_touches_only_the_completion,
    an_error_is_stored_with_its_kind_and_a_repeat_must_match_it,
    what_a_self_scoped_tool_reached_replaces_its_unknown_resources_at_finish,
    a_report_of_what_was_reached_from_another_tool_is_stored_as_an_error,
    the_deadline_is_the_begin_time_plus_begin_budget_call_deadline_finish_deadline_and_answer_budget,
    a_list_row_is_stored_complete_with_no_deadline,
    a_call_record_of_kind_list_is_refused_at_begin_and_leaves_no_row,
    a_receipt_is_reserved_with_its_row_or_not_at_all,
    a_receipt_moves_with_its_finish,
    a_late_finish_completes_its_row_and_leaves_its_receipt_pending,
    a_key_is_unique_in_its_scope_under_concurrent_calls,
    two_delegations_under_one_principal_may_use_the_same_key,
    a_key_scope_over_its_cap_is_refused_at_begin_and_one_at_it_is_reserved,
    a_begin_retried_after_a_lost_confirmation_finds_its_own_receipt_and_runs_once,
    a_retried_begin_of_a_receipt_pending_past_its_deadline_is_refused_and_runs_nothing,
    a_begin_whose_confirmation_is_lost_on_every_attempt_leaves_its_row_error_and_its_receipt_not_performed,
    a_reused_keys_begin_whose_confirmation_is_lost_keeps_its_answer_and_gives_nothing_up,
    a_retried_begin_of_a_duplicate_answers_with_the_earlier_receipts_reference,
    each_receipt_state_is_answered_by_the_first_line_of_the_reuse_table_that_matches,
    a_receipt_records_the_vendor_target_its_settlement_takes,
    two_claimants_never_both_hold_a_receipts_lease,
    an_ended_lease_can_be_claimed_again,
    the_number_of_attempts_is_bounded,
    an_authoritative_empty_search_settles_not_performed_and_no_other_does,
    a_found_effect_settles_completed_with_its_reference,
    a_lookup_record_is_append_only,
    a_receipt_settled_by_reconciliation_is_not_moved_by_a_late_finish,
    each_claim_is_counted_as_an_attempt,
    a_receipt_held_for_its_call_is_not_due_and_no_one_else_claims_it,
    an_unknown_receipt_is_not_due_before_its_rows_deadline,
    // Attribution.
    an_attribution_read_finds_only_the_principals_completed_receipt_of_its_tool_target_and_reference,
);
