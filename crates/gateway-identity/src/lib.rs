//! The gateway's identity verifier.
//!
//! Turns a signed token into a proved [`Principal`](gateway_core::Principal), following
//! section 7 of the design: a fixed list of issuers per deployment, each with its accepted
//! audiences, kind, one signing algorithm, keys and lifetime ceiling; strict, offline
//! verification; and one opaque failure outward with the cause kept for the log.
//!
//! It performs no network I/O. Keys are supplied as JWK sets: in configuration at boot, and
//! through [`Identity::replace_keys`] while the gateway runs, which puts a new set for one
//! issuer in force only if it passes every check a set gets at boot. Fetching sets from an
//! issuer's own host is a later change that belongs in its own crate beside this one. Time comes
//! from a [`Clock`], so tests choose what time it is.
//!
//! - [`TokenVerifier`] is the [`Verifier`](gateway_core::Verifier) for principals: the place
//!   proof is created, and the code to read when reviewing it.
//! - [`Identity`] is the gate the HTTP layer holds, with its three states: [`Verification`]
//!   is `proved`, `disabled` or `failed`, and `disabled` is only reachable from
//!   [`IdentityConfig::Disabled`]. [`KeysReplaced`] is what a replacement changed, for the
//!   log.
//! - [`VerifyError`] says which check refused, for logs. [`IdentityFailure`] is what the
//!   verifier returns, and displays as the one sentence a caller may read. Beside the cause it
//!   holds a [`ClaimedCaller`]: the issuer and subject the token claimed, escaped and capped,
//!   for the identity-failure event.

#![forbid(unsafe_code)]

mod clock;
mod config;
mod error;
mod identity;
mod verifier;

pub use clock::{Clock, SystemClock};
pub use config::{
    ConfigError, DEFAULT_GROUPS_CLAIM, IdentityConfig, IssuerConfig, IssuerKind, MAX_LEEWAY,
    MIN_RSA_BITS, SigningAlgorithm,
};
pub use error::{Claim, ClaimedCaller, IdentityFailure, MAX_CLAIMED, VerifyError};
pub use identity::{Identity, KeysReplaced, Verification, VerificationState};
pub use verifier::{MAX_TOKEN_BYTES, TokenVerifier};
