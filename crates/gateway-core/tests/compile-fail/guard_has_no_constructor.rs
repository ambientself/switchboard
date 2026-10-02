// Nor by a constructor.

use gateway_core::audit::AuditRowId;
use gateway_core::{ApprovedTool, AuditGuard, CallContext};

fn skip_audit(call: CallContext, tool: ApprovedTool) -> AuditGuard {
    AuditGuard::new(AuditRowId::new("never written"), call, tool)
}

fn main() {}
