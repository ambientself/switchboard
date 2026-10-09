// A `Listed` cannot be made without its row: it comes only from `listed`, which writes the row
// first. This does not stop a path answering `tools/list` from a list it holds without calling
// `listed`; the path's tests hold that.

use gateway_core::ApprovedTool;
use gateway_core::audit::{AuditRowId, Listed};

fn skip_audit(tools: Vec<ApprovedTool>) -> Listed {
    Listed {
        row: AuditRowId::new("never written"),
        tools,
    }
}

fn main() {}
