//! The gateway on the testkit's fakes, for development and for tests.
//!
//! Plan #26 section 7: the demo and the end-to-end tests start the gateway the same way.
//!
//! - [`start_fixture_gateway`] runs the real `gateway` (boot gates, request path, HTTP server)
//!   on `127.0.0.1`, wired to the testkit's world: two [`LocalIssuer`]s on the system clock,
//!   the fixture policy, the [`FixtureConnector`] with its [`FakeCredentialSource`], an
//!   [`InMemoryAuditStore`] and the fixture's tool definitions. The [`FixtureGateway`] it
//!   returns hands back every fake, so a test can switch a failure on and read what happened.
//! - [`AuditPrinter`] is an audit store that prints each row as a JSON line as it is written.
//! - [`fixture_config`] and [`catalog_data`] are the fixture world as gateway configuration.
//!
//! Nothing here belongs in a running gateway: it depends on the testkit, whose keys are
//! generated in process and whose credentials are labelled dummies.
//!
//! [`LocalIssuer`]: gateway_testkit::LocalIssuer
//! [`FixtureConnector`]: gateway_testkit::FixtureConnector
//! [`FakeCredentialSource`]: gateway_testkit::FakeCredentialSource
//! [`InMemoryAuditStore`]: gateway_testkit::InMemoryAuditStore

#![forbid(unsafe_code)]

mod printer;
mod start;
mod world;

pub use printer::AuditPrinter;
pub use start::{
    DevError, FixtureGateway, LISTEN_HOST, Options, start_fixture_gateway,
    start_fixture_gateway_with,
};
pub use world::{
    ALLOWED_HOSTS, DEPLOYMENT, FixtureResources, catalog, catalog_data, fixture_config,
};
