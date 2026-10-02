// Nor can what `run` returns be made up.

use gateway_core::audit::Ran;
use gateway_core::{AuditGuard, ToolOutcome};

fn made_up(guard: AuditGuard) -> Ran {
    Ran {
        row: guard.row().clone(),
        outcome: ToolOutcome::Ok(serde_json::Value::Null),
    }
}

fn main() {}
