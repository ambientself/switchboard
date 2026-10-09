// A `tools/list` cannot be answered without its row: `Listed` comes only from `listed`, which
// writes the row first.

use gateway_core::ApprovedTool;
use gateway_core::audit::{AuditRowId, Listed};

fn skip_audit(tools: Vec<ApprovedTool>) -> Listed {
    Listed {
        row: AuditRowId::new("never written"),
        tools,
    }
}

fn main() {}
