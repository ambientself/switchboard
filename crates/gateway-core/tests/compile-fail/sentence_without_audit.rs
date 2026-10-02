// A denial's sentence cannot be had from the decision: only from the refusal that the audit
// begin step returns once the row is written.

use gateway_core::Decision;

fn answer_unrecorded(decision: &Decision) -> Option<String> {
    decision.reason().map(|reason| reason.sentence())
}

fn main() {}
