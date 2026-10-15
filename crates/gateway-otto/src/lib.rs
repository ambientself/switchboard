//! The Otto adapter: what is specific to Otto, confined to one crate the core does not depend
//! on (design section 1).
//!
//! This holds the turn-grant verifier of decision 0012, its key configuration and the mapping
//! of Otto's tool names. The gateway turns a [`VerifiedGrant`] into the core's delegation, and
//! a [`GrantFailure`] into a delegation that is present and unverified, which check 3 denies.
//!
//! - [`format`](mod@format) holds the `v3` format's constants and its key ID. The format is
//!   specified in `docs/turn-grant-format.md`, which Otto's owners implement from.
//! - [`GrantKeys`] is the checked configuration: per issuer, a current key and at most one
//!   previous key with an absolute end instant, and whether `pod` and `egress` are required.
//!   [`KeyConfigError`] has one variant for each refusal.
//! - [`ToolMapping`] maps Otto's bare tool names to this gateway's, one to one.
//! - [`GrantVerifier`] checks a grant as presented, in the decision's order, against a clock
//!   it is given. A failure is a [`FailureKind`] and, only once the signature verified, the
//!   grant's [`GrantDigest`]: nothing from the claims.
//! - `minter`, with the `test-support` feature, signs grants for tests.

#![forbid(unsafe_code)]

pub mod format;
mod keys;
#[cfg(feature = "test-support")]
pub mod minter;
mod tools;
mod verify;

pub use format::KeyId;
pub use keys::{GrantKeys, IssuerConfig, IssuerName, KeyConfigError, PreviousKeyConfig};
pub use tools::{MappingError, ToolMapping};
pub use verify::{Egress, FailureKind, GrantDigest, GrantFailure, GrantVerifier, VerifiedGrant};
