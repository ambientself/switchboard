// A connector cannot be called directly, around the audited path: it takes a `ToolCall`,
// which only `audit::run` can make, by consuming a guard.

use gateway_core::{AuditGuard, CallContext, Connector, ToolCall};

fn bypass(connector: &dyn Connector, guard: AuditGuard, call: CallContext) {
    let _ = connector.run(guard);
    let tool = call.caller.surface.clone();
    let _ = connector.run(ToolCall::new(call, tool, serde_json::Value::Null));
}

fn main() {}
