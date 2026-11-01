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
//! - [`start()`] reads the configuration, the key and the registry file, and serves the socket
//!   ([`server`]). The binary is `switchboard-custodian`, which starts through
//!   [`start_process`]: that also refuses a `peer_uid` that is the custodian's own UID.
//! - [`CustodianClient`] is the client. It is in this crate so that the GitHub connector can
//!   depend on it; nothing in the client reads the key.
//! - `fake`, behind the `test-support` feature, is a fake GitHub App API for the tests.
//!
//! # Features
//!
//! `client` is the client and `server` the custodian itself: the key, the GitHub App client,
//! the policy check, the socket, the record and the metrics. Both are on by default. The
//! GitHub connector turns the defaults off and asks for `client` alone, so the gateway links
//! the client and the wire protocol ([`protocol`]) and none of the server's code or
//! dependencies (`tests/packaging.rs` checks the gateway's build). The `switchboard-custodian`
//! binary needs `server`.
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
//! gateway stops working then, not at GitHub's hour, as long as GitHub accepts the revocation.
//!
//! Two cases leave a token working past its lifetime, each until GitHub's expiry at most, an
//! hour after it was issued:
//!
//! - GitHub does not accept the revocation (a timeout, a 5xx, a rate-limit answer). The
//!   custodian counts and logs each failed attempt and tries again with a growing wait, from
//!   one second up to a minute, until GitHub accepts or the token reaches GitHub's expiry. So
//!   during an outage of GitHub's revoke endpoint the token works until the first attempt
//!   after the outage ends.
//! - The custodian stops. A graceful stop revokes every token the custodian still keeps, within
//!   a deadline, ten seconds by default (see [`server`]). A token whose revocation GitHub does
//!   not accept by then is logged and works on; so does every token when the custodian is
//!   killed rather than stopped.
//!
//! # Which revision a request carries
//!
//! The revision the call was decided under: the one in the gateway's
//! `Decision::policy_revision`. While the gateway's drift check has withdrawn tools, that is a
//! derived revision, `{base}+withdrawn:{names}` (decision 0013), which no registry file holds.
//! The custodian checks the base, the part before the first `+`, which the registry loader
//! refuses in a revision of its own. A withdrawal only removes tools from what the gateway
//! serves, and the gateway asks for no token for a tool it does not serve, so the base's copy is
//! the one to check against. The record keeps the whole revision the request carried.
//!
//! # The custodian checks less of the file than the gateway
//!
//! The custodian loads the registry file with the gateway's loader and nothing else (see
//! [`policy`]). A file the loader refuses, the custodian refuses too. A file the loader accepts
//! but the gateway's reload refuses (a changed server or route, a boot gate that fails, bytes
//! that are not UTF-8) is served by the custodian and not by the gateway. If that file names a
//! new revision, the two hold different revisions, and every request is refused as
//! `stale_revision` until they agree again: until the gateway restarts on the file, or the file
//! is fixed. This fails closed.

#![forbid(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod clock;
#[cfg(feature = "test-support")]
pub mod fake;
#[cfg(feature = "server")]
pub mod github;
#[cfg(feature = "server")]
pub mod metrics;
#[cfg(feature = "server")]
pub mod policy;
pub mod protocol;
#[cfg(feature = "server")]
pub mod rate;
#[cfg(feature = "server")]
pub mod record;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod start;

#[cfg(feature = "client")]
pub use client::{ClientError, CustodianClient, Token};
#[cfg(feature = "server")]
pub use policy::{CustodianPolicy, PolicyCell, PolicyError};
pub use protocol::{Answer, Failure, MAX_REPOSITORIES, Refusal, Secret, TokenRequest};
#[cfg(feature = "server")]
pub use server::Stopped;
#[cfg(feature = "server")]
pub use start::{Config, Running, StartError, start, start_process};
