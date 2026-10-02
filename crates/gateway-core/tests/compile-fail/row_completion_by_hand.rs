// Nor can the completion a store's `finish` takes be built by hand.

use gateway_core::audit::{Completion, Outcome, Refusal, RowCompletion};

fn forge(refusal: &Refusal) -> RowCompletion {
    RowCompletion {
        row: refusal.row().clone(),
        completion: Completion {
            outcome: Outcome::Ok,
            latency_ms: 0,
        },
    }
}

fn main() {}
