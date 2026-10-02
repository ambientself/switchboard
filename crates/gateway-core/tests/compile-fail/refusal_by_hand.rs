// A refusal cannot be built by hand, so a sentence cannot be answered without its row.

use gateway_core::Reason;
use gateway_core::audit::{AuditRowId, Refusal};

fn forge(reason: Reason) -> Refusal {
    Refusal {
        row: AuditRowId::new("never written"),
        reason,
        sentence: "Allowed after all.".to_owned(),
    }
}

fn main() {}
