//! The three states of verification, and the front that reaches them.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use gateway_core::{Issuer, Principal, Proved};
use jsonwebtoken::jwk::JwkSet;

use crate::clock::Clock;
use crate::config::{ConfigError, IdentityConfig, IssuerConfig};
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
///
/// An enforcing gate's keys can be replaced while it runs, one issuer at a time, with
/// [`Identity::replace_keys`]. Its issuers, and everything else about them, are fixed when it is
/// built.
pub struct Identity {
    gate: Option<Enforcing>,
}

/// An enforcing gate: the configuration the verifier in use was built from, and that verifier.
struct Enforcing {
    /// The issuers the verifier in use was built from. Also what serialises replacements: a
    /// replacement holds this lock from reading the configuration to storing the new one, so
    /// two replacements for different issuers cannot each undo the other.
    issuers: Mutex<Vec<IssuerConfig>>,
    /// The verifier in use. A check clones the `Arc` under the read lock and verifies outside
    /// it; a replacement holds the write lock only to store a verifier already built.
    verifier: RwLock<Arc<TokenVerifier>>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verifier = self.gate.as_ref().map(Enforcing::current);
        f.debug_struct("Identity")
            .field("verifier", &verifier)
            .finish()
    }
}

/// What replacing an issuer's keys changed, for the log: the `kid`s in the new set that were not
/// in the old one, and the reverse.
///
/// Read from the sets as supplied, so a key left out because it cannot verify still counts as
/// in its set, and a `kid` kept with a different key is in neither list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeysReplaced {
    /// Key IDs in the new set that were not in the old one.
    pub added: BTreeSet<String>,
    /// Key IDs in the old set that are not in the new one. A token naming one is refused from
    /// now on.
    pub removed: BTreeSet<String>,
}

impl KeysReplaced {
    fn between(before: &JwkSet, after: &JwkSet) -> Self {
        let kids = |set: &JwkSet| -> BTreeSet<String> {
            set.keys
                .iter()
                .filter_map(|key| key.common.key_id.clone())
                .collect()
        };
        let (before, after) = (kids(before), kids(after));
        Self {
            added: after.difference(&before).cloned().collect(),
            removed: before.difference(&after).cloned().collect(),
        }
    }
}

impl Enforcing {
    fn new(issuers: Vec<IssuerConfig>, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        let verifier = TokenVerifier::new(issuers.clone(), Arc::clone(&clock))?;
        Ok(Self {
            issuers: Mutex::new(issuers),
            verifier: RwLock::new(Arc::new(verifier)),
            clock,
        })
    }

    /// The verifier in use. The read lock is held only to clone the `Arc`.
    fn current(&self) -> Arc<TokenVerifier> {
        // A panic while a lock was held cannot leave a half-written value behind: each lock
        // guards a value that is only ever replaced whole. So a poisoned lock is read as it is.
        Arc::clone(&self.verifier.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn replace_keys(&self, issuer: &Issuer, keys: JwkSet) -> Result<KeysReplaced, ConfigError> {
        let mut issuers = self.issuers.lock().unwrap_or_else(PoisonError::into_inner);
        let index = issuers
            .iter()
            .position(|config| config.issuer == *issuer)
            .ok_or_else(|| ConfigError::UnknownIssuerForKeys(issuer.clone()))?;
        let mut next = issuers.clone();
        let before = std::mem::replace(&mut next[index].keys, keys);
        let replaced = KeysReplaced::between(&before, &next[index].keys);
        // The whole verifier is built again, so a key gets every check here that it gets at
        // boot, and a set that would not boot is refused with the error it would boot with.
        // Nothing is stored until the build has succeeded.
        let verifier = TokenVerifier::new(next.clone(), Arc::clone(&self.clock))?;
        *self
            .verifier
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(verifier);
        *issuers = next;
        Ok(replaced)
    }
}

impl Identity {
    /// Builds the gate, refusing configuration that is incomplete or contradictory.
    pub fn new(config: IdentityConfig, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        let gate = match config {
            IdentityConfig::Enforce(issuers) => Some(Enforcing::new(issuers, clock)?),
            IdentityConfig::Disabled => None,
        };
        Ok(Self { gate })
    }

    /// Checks the token a caller presented, if it presented one.
    ///
    /// Verifies against the keys in force when the check starts. A replacement that lands while
    /// it runs applies from the next check.
    pub fn check(&self, token: Option<&str>) -> Verification {
        let Some(gate) = &self.gate else {
            return Verification::Disabled;
        };
        let Some(token) = token else {
            return Verification::Failed(IdentityFailure::new(VerifyError::MissingToken));
        };
        let verifier = gate.current();
        match Proved::verify(verifier.as_ref(), token) {
            Ok(principal) => Verification::Proved(principal),
            Err(failure) => Verification::Failed(failure),
        }
    }

    /// Replaces the keys of one configured issuer while the gate runs.
    ///
    /// The caller names the issuer, because the caller knows where the set came from; nothing in
    /// a token chooses it. The gate's configuration, with this issuer's keys replaced, is
    /// checked exactly as it is at boot: every key needs a `kid` no other key in the set has,
    /// keys that cannot verify the issuer's algorithm are left out, an RSA key must be long
    /// enough and usable, and at least one key must be left. Only if all of that passes are the
    /// new keys put in force, for every check that starts afterwards. On any error the keys in
    /// use stay in use, and so does the configuration later replacements build on.
    ///
    /// Refused with [`ConfigError::UnknownIssuerForKeys`] for an issuer that is not configured,
    /// and with [`ConfigError::KeysWhileDisabled`] when identity checking is disabled.
    pub fn replace_keys(&self, issuer: &Issuer, keys: JwkSet) -> Result<KeysReplaced, ConfigError> {
        let Some(gate) = &self.gate else {
            return Err(ConfigError::KeysWhileDisabled(issuer.clone()));
        };
        gate.replace_keys(issuer, keys)
    }
}
