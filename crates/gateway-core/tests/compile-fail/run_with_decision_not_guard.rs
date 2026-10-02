// An allowed decision is not enough to run a tool: running needs the guard that only the
// audit begin step hands out.

use gateway_core::audit::{self, Ran};
use gateway_core::{Connector, Decision};

async fn run(connector: &dyn Connector, decision: Decision) -> Ran {
    audit::run(connector, decision).await
}

fn main() {}
