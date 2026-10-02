// One decision begins one row: it cannot be copied to begin two.

use gateway_core::Decision;

fn copy(decision: &Decision) -> Decision {
    decision.clone()
}

fn main() {}
