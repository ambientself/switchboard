// A row cannot be finished for a call that never ran: `finish` takes what `run` returns.

use gateway_core::audit::{self, Finished};
use gateway_core::{AuditGuard, AuditStore};

async fn skip_run(store: &dyn AuditStore, guard: AuditGuard) -> Finished {
    audit::finish(store, guard, 0).await
}

fn main() {}
