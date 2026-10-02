// A denied row cannot be completed: a store's `finish` takes a `RowCompletion`, which only
// `audit::finish` makes, from a call that ran.

use gateway_core::AuditStore;
use gateway_core::audit::{Completion, Outcome, Refusal};

fn complete(store: &dyn AuditStore, refusal: &Refusal) {
    let completion = Completion {
        outcome: Outcome::Ok,
        latency_ms: 0,
    };
    let _ = store.finish(refusal.row(), &completion);
}

fn main() {}
