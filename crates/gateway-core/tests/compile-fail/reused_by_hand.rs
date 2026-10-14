// Nor can the answer to a reused key, so no call is answered from a receipt without its row.

use gateway_core::Reuse;
use gateway_core::audit::{AuditRowId, Reused};

fn forge(reuse: Reuse) -> Reused {
    Reused {
        row: AuditRowId::new("never written"),
        reuse,
    }
}

fn main() {}
