// A guard given up cannot also be run: giving it up consumes it.

use gateway_core::audit::{self, GaveUp, Ran};
use gateway_core::{AuditGuard, AuditStore, Connector};

async fn both(store: &dyn AuditStore, connector: &dyn Connector, guard: AuditGuard) -> (GaveUp, Ran) {
    let gave_up = audit::give_up(store, guard).await;
    let ran = audit::run(connector, guard).await;
    (gave_up, ran)
}

fn main() {}
