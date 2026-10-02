// A tool cannot be run with no guard at all.

use gateway_core::audit::{self, Ran};
use gateway_core::Connector;

async fn run(connector: &dyn Connector) -> Ran {
    audit::run(connector).await
}

fn main() {}
