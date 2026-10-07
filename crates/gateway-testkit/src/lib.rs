//! Fakes and fixtures for testing the gateway with no network, no database and no real
//! credential: everything a test, or a local development binary, needs to stand in for the
//! outside world.
//!
//! Each fake can be told to fail, and each way it fails has a test in this crate that shows it:
//!
//! - [`InMemoryAuditStore`] keeps rows in order, can fail or hold `begin` and `finish`.
//! - [`FakeCredentialSource`] issues labelled dummy credentials, records every request, and
//!   can refuse or be unavailable.
//! - [`FixtureConnector`] serves a read tool, a write tool and a scope-checking tool, records
//!   every call, and can fail or hang.
//! - [`LocalIssuer`] generates a key pair when built, gives its public keys as the JWKS
//!   document an issuer serves, and signs tokens a test can break in any one way;
//!   [`FixedClock`] and [`SteppableClock`] say what time it is.
//! - [`Fixture`] puts them together with a policy snapshot, two teams, a user group, two
//!   surfaces and one resource limit per team, and builds a [`CallerContext`] for each of the
//!   callers it knows by proving a token through the real verifier.
//!
//! The libraries here are runtime-agnostic: a [`Gate`] holds a fake without a sleep, and
//! [`block_on`] and [`poll_once`] are enough executor to drive the core's futures, so none of
//! this needs an async runtime. Nothing here belongs in a running gateway.
//!
//! [`CallerContext`]: gateway_core::CallerContext

#![forbid(unsafe_code)]

mod audit;
mod clock;
mod connector;
mod credentials;
mod exec;
mod fixture;
mod gate;
mod issuer;

pub use audit::InMemoryAuditStore;
pub use clock::{FIXTURE_NOW, FixedClock, SteppableClock};
pub use connector::{
    CONNECTOR, DOCUMENT_ARGUMENT, FORBIDDEN_DOCUMENT, FixtureConnector, READ_TOOL, RESOURCE_KIND,
    RESOURCE_SYSTEM, ReceivedCall, SCOPED_READ_TOOL, WRITE_TOOL, WriteRecord, document,
};
pub use credentials::{CredentialRequest, FakeCredentialSource};
pub use exec::{block_on, poll_once};
pub use fixture::*;
pub use gate::{Gate, GateWait};
pub use issuer::{
    DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME, DEFAULT_TOKEN_LIFETIME, IssuerError, LocalIssuer,
    TokenBuilder,
};
