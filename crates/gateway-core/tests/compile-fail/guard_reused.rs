// One guard runs one call, once.

use gateway_core::audit::{self, Ran};
use gateway_core::{AuditGuard, Connector};

async fn twice(connector: &dyn Connector, guard: AuditGuard) -> (Ran, Ran) {
    let first = audit::run(connector, guard).await;
    let second = audit::run(connector, guard).await;
    (first, second)
}

fn main() {}
