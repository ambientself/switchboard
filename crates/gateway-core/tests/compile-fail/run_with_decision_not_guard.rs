// An allowed decision is not enough to run a tool: running needs the guard that only the
// audit begin step hands out.

use gateway_core::{Connector, Decision};

async fn run<C: Connector>(connector: &C, decision: &Decision, arguments: &serde_json::Value) -> C::Output {
    connector.run(decision, arguments).await
}

fn main() {}
