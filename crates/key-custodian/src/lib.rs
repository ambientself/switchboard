//! The key custodian (design section 9): the one process that holds the GitHub App's private
//! key, and the client the gateway asks it with.
//!
//! The gateway never reads the key. It asks the custodian, over a Unix socket, for an
//! installation token for one call: the team, the tool, the repositories, the permission set
//! and the policy revision the call was decided under ([`TokenRequest`]). The custodian checks
//! the request against its own copy of policy, generated from the same registry file as the
//! gateway's snapshot ([`policy`]), so a compromised gateway cannot widen its own requests. It
//! limits each team's rate, asks GitHub for a token narrowed to exactly what was asked for,
//! limits the token's lifetime, and keeps its own record.
//!
//! - [`start`] reads the configuration, the key and the registry file, and serves the socket
//!   ([`server`]). The binary is `switchboard-custodian`.
//! - [`CustodianClient`] is the client. It is in this crate so that the GitHub connector can
//!   depend on it; nothing in the client reads the key.
//! - `fake`, behind the `test-support` feature, is a fake GitHub App API for the tests.
//!
//! # Where a tool's permission set is stated
//!
//! On its connector entry, not its approval: a built-in entry of system `github` in the
//! registry's `[[connectors]]` states `permissions` and the `tools` it serves (see
//! [`gateway_registry::BuiltInEntry`]). Decision 0011 gives each entry exactly one credential
//! and registers a system with several permission sets as several entries, so the set belongs
//! to the credential, and so to the entry. A request may ask for any subset of its tool's set,
//! each permission at or below its stated level.
//!
//! # The rate limit
//!
//! Each team has a token bucket of [`rate::DEFAULT_BURST`] requests, refilled at
//! [`rate::DEFAULT_PER_MINUTE`] a minute, taken only by requests that pass the policy check.
//! The defaults are provisional. A token is asked for per call, and an agent's turn makes a
//! handful of GitHub calls, so 30 a minute with a burst of 10 serves a team's normal use with
//! room to spare. What the bucket bounds is how many tokens a compromised gateway can get for
//! one team: at the sustained rate, 1,800 an hour, each narrowed to that team's repositories.
//! It does not bound the calls each token makes. GitHub's own limits do that: an installation's
//! tokens share its primary REST limit, which GitHub documents as 5,000 requests an hour. Both
//! values are configurable.
//!
//! # What "limits lifetime" means
//!
//! A token handed out expires after the configured lifetime, five minutes by default, or at
//! GitHub's own expiry if that is sooner; it is never handed out for longer than GitHub issued
//! it. When the lifetime ends first, the custodian revokes the token at that moment through
//! GitHub's revoke endpoint (`DELETE /installation/token`), so a token taken from a compromised
//! gateway stops working then, not at GitHub's hour. A token still outstanding when the
//! custodian stops is not revoked, and lapses at GitHub's expiry.

#![forbid(unsafe_code)]

pub mod client;
pub mod clock;
#[cfg(feature = "test-support")]
pub mod fake;
pub mod github;
pub mod metrics;
pub mod policy;
pub mod protocol;
pub mod rate;
pub mod record;
pub mod server;
pub mod start;

pub use client::{ClientError, CustodianClient, Token};
pub use policy::{CustodianPolicy, PolicyCell, PolicyError};
pub use protocol::{Answer, Failure, MAX_REPOSITORIES, Refusal, Secret, TokenRequest};
pub use start::{Config, Running, StartError, start};
