//! The three states of verification, and the front that reaches them.

use std::fmt;
use std::sync::Arc;

use gateway_core::{Principal, Proved};

use crate::clock::Clock;
use crate::config::{ConfigError, IdentityConfig};
use crate::error::{IdentityFailure, VerifyError};
use crate::verifier::TokenVerifier;

/// What checking a caller came to. Design section 7: an incident review must be able to tell
/// "we were not checking" from "someone tried and was refused".
#[derive(Debug)]
pub enum Verification {
    /// The token verified; the principal is proved.
    Proved(Proved<Principal>),
    /// Checking was explicitly turned off in configuration. There is no principal, and nothing
    /// was proved.
    Disabled,
    /// Checking was on and the caller was refused, or presented nothing.
    Failed(IdentityFailure),
}

/// A [`Verification`] without its contents: the value to record beside a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationState {
    /// See [`Verification::Proved`].
    Proved,
    /// See [`Verification::Disabled`].
    Disabled,
    /// See [`Verification::Failed`].
    Failed,
}

impl VerificationState {
    /// The state's name as it is recorded: `proved`, `disabled` or `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationState::Proved => "proved",
            VerificationState::Disabled => "disabled",
            VerificationState::Failed => "failed",
        }
    }
}

impl fmt::Display for VerificationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Verification {
    /// Which of the three this is.
    pub fn state(&self) -> VerificationState {
        match self {
            Verification::Proved(_) => VerificationState::Proved,
            Verification::Disabled => VerificationState::Disabled,
            Verification::Failed(_) => VerificationState::Failed,
        }
    }
}

/// The gateway's identity gate: verifies a caller's token, or, if configuration says so, does
/// not.
///
/// Built only from an [`IdentityConfig`], which states one or the other, so
/// [`Verification::Disabled`] comes from this type only when [`IdentityConfig::Disabled`] was
/// written.
pub struct Identity {
    verifier: Option<TokenVerifier>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("verifier", &self.verifier)
            .finish()
    }
}

impl Identity {
    /// Builds the gate, refusing configuration that is incomplete or contradictory.
    pub fn new(config: IdentityConfig, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        let verifier = match config {
            IdentityConfig::Enforce(issuers) => Some(TokenVerifier::new(issuers, clock)?),
            IdentityConfig::Disabled => None,
        };
        Ok(Self { verifier })
    }

    /// Checks the token a caller presented, if it presented one.
    pub fn check(&self, token: Option<&str>) -> Verification {
        let Some(verifier) = &self.verifier else {
            return Verification::Disabled;
        };
        let Some(token) = token else {
            return Verification::Failed(IdentityFailure::new(VerifyError::MissingToken));
        };
        match Proved::verify(verifier, token) {
            Ok(principal) => Verification::Proved(principal),
            Err(failure) => Verification::Failed(failure),
        }
    }
}
