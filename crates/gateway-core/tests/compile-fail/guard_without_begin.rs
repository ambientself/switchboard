// A guard cannot be built by hand, so the audit begin step cannot be skipped by making one.

use gateway_core::audit::AuditRowId;
use gateway_core::{ApprovedTool, AuditGuard, CallContext};

fn skip_audit(call: CallContext, tool: ApprovedTool) -> AuditGuard {
    AuditGuard {
        row: AuditRowId::new("never written"),
        call,
        tool,
    }
}

fn main() {}
