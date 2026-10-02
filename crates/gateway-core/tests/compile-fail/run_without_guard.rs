// A tool cannot be run with no guard at all.

use gateway_core::Connector;

async fn run<C: Connector>(connector: &C, arguments: &serde_json::Value) -> C::Output {
    connector.run(arguments).await
}

fn main() {}
