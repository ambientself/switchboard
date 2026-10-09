//! Fakes and fixtures for testing the gateway with no network, no database and no real
//! credential: everything a test, or a local development binary, needs to stand in for the
//! outside world.
//!
//! Each fake can be told to fail, and each way it fails has a test in this crate that shows it:
//!
//! - [`InMemoryAuditStore`] keeps rows in order under the identifier begin was given, sets
//!   each row's deadline from its own clock as the Postgres store does, can fail or hold
//!   `begin` and `finish`, and [`row_start`] makes a fresh identifier for a test.
//! - [`FakeCredentialSource`] issues labelled dummy credentials, records every request, and
//!   can refuse or be unavailable.
//! - [`FixtureConnector`] serves a read tool, a `propose` tool that acts only on drafts it
//!   opened, a direct-write tool that every profile denies, and a scope-checking tool. It
//!   records every call, and can fail or hang.
//! - [`LocalIssuer`] generates a key pair when built, gives its public keys as the JWKS
//!   document an issuer serves, and signs tokens a test can break in any one way;
//!   [`FixedClock`] and [`SteppableClock`] say what time it is.
//! - [`Fixture`] puts them together with a policy snapshot, two teams, two user groups, two
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

pub use audit::{
    FIXTURE_CALL_DEADLINE_MS, FIXTURE_INSTANCE, InMemoryAuditStore, StoreBudgets, row_start,
};
pub use clock::{FIXTURE_NOW, FixedClock, SteppableClock};
pub use connector::{
    CONNECTOR, DOCUMENT_ARGUMENT, DRAFT_ARGUMENT, DRAFT_REFUSAL, DRAFT_TOOL, FORBIDDEN_DOCUMENT,
    FOREIGN_DRAFT, FixtureConnector, READ_TOOL, RESOURCE_KIND, RESOURCE_SYSTEM, ReceivedCall,
    SCOPE_REFUSAL, SCOPED_READ_TOOL, WRITE_TOOL, WriteRecord, document,
};
pub use credentials::{CredentialRequest, FakeCredentialSource};
pub use exec::{block_on, poll_once};
pub use fixture::*;
pub use gate::{Gate, GateWait};
pub use issuer::{
    DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME, DEFAULT_TOKEN_LIFETIME, IssuerError, LocalIssuer,
    TokenBuilder,
};
