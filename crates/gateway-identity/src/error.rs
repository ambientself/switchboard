//! Why a token was refused: in detail for logs, and in one opaque form for the caller. Beside
//! both, what the token claimed, for the identity-failure event.

use std::fmt;

use gateway_core::{Claimed, IDENTITY_FAILURE, escape};
use thiserror::Error;

/// The longest a claimed issuer or subject is kept, in characters after escaping, before it is
/// cut short and marked with `…`.
pub const MAX_CLAIMED: usize = 256;

/// A claim a check names. Displays as a noun phrase that ends in "claim", so a message reads
/// the same whether the claim has a fixed name or, like the groups claim, a configured one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// `iss`.
    Issuer,
    /// `sub`.
    Subject,
    /// `aud`.
    Audience,
    /// `exp`.
    ExpiresAt,
    /// `nbf`.
    NotBefore,
    /// `iat`.
    IssuedAt,
    /// The claim a user issuer's groups are read from.
    Groups,
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Claim::Issuer => "`iss` claim",
            Claim::Subject => "`sub` claim",
            Claim::Audience => "`aud` claim",
            Claim::ExpiresAt => "`exp` claim",
            Claim::NotBefore => "`nbf` claim",
            Claim::IssuedAt => "`iat` claim",
            Claim::Groups => "groups claim",
        })
    }
}

/// Which check refused a token. For operators' logs and for tests; never for the caller, who
/// reads [`IDENTITY_FAILURE`] whatever happened.
///
/// No variant carries a value taken from the token, so a refusal cannot put attacker-chosen
/// text into a log line. What it gives up is the offending issuer or `kid` by name. The issuer
/// and subject the token claimed are kept beside it instead, escaped and capped, in
/// [`ClaimedCaller`], and the token is still in the request's own log.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The caller presented no token, with checking on.
    #[error("no token was presented")]
    MissingToken,
    /// The token is larger than any token this gateway accepts.
    #[error("the token is too large")]
    TokenTooLarge,
    /// The token is not three dot-separated parts with a JSON header and JSON claims.
    #[error("the token is malformed")]
    MalformedToken,
    /// The token has no `iss`, or one that is not a string.
    #[error("the token names no issuer")]
    MissingIssuer,
    /// The token's issuer is not one of the configured issuers.
    #[error("the token's issuer is not configured")]
    UnknownIssuer,
    /// The header's `alg` is not the issuer's configured algorithm, including `none`.
    #[error("the token's algorithm is not the one its issuer is configured with")]
    AlgorithmNotAllowed,
    /// The header has a `crit` member, which names extensions this verifier would have to
    /// understand. It understands none.
    #[error("the token's header names critical extensions")]
    CriticalHeader,
    /// The header has no `kid`.
    #[error("the token names no key id")]
    MissingKeyId,
    /// The header's `kid` is not one of the issuer's keys.
    #[error("the token's key id is not one of its issuer's keys")]
    UnknownKeyId,
    /// The key could not be used to verify, so no token under it can be accepted.
    #[error("the issuer's key could not be used to verify a signature")]
    UnusableKey,
    /// The signature does not match the token under the named key.
    #[error("the token's signature does not verify")]
    BadSignature,
    /// A claim a check needs is missing.
    #[error("the token has no {0}")]
    MissingClaim(Claim),
    /// A claim is present but not the type or shape the check needs.
    #[error("the token's {0} is malformed")]
    MalformedClaim(Claim),
    /// `exp` is in the past, beyond the leeway.
    #[error("the token has expired")]
    Expired,
    /// `nbf` is in the future, beyond the leeway.
    #[error("the token is not yet valid")]
    NotYetValid,
    /// `aud` names none of the issuer's accepted audiences.
    #[error("the token is not for an audience this issuer is accepted for")]
    AudienceMismatch,
    /// `exp` is before `iat`.
    #[error("the token expires before it was issued")]
    ExpiresBeforeIssue,
    /// `exp - iat` is more than the issuer's maximum lifetime.
    #[error("the token lives longer than its issuer's ceiling")]
    LifetimeTooLong,
    /// `iat` is in the future, beyond the leeway. Without this a token could be issued for a
    /// window that starts later and still pass the ceiling.
    #[error("the token was issued in the future")]
    IssuedInFuture,
    /// A workload token's subject is not in the issuer's subject table. Only ever reported
    /// after the signature has verified.
    #[error("the token's subject is not in the issuer's subject table")]
    UnknownSubject,
}

/// A refusal of a caller's identity. Displays as the one opaque sentence, whatever the cause;
/// the cause is [`detail`](IdentityFailure::detail), and what the token claimed is
/// [`claimed`](IdentityFailure::claimed).
///
/// Its `Debug` output includes the detail, because logs are what that is for: never put a
/// `{:?}` of this into a response. It leaves out what the token claimed, which is for the
/// identity-failure event only. The caller's text is [`outward`](IdentityFailure::outward), or
/// this value's `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityFailure {
    detail: VerifyError,
    claimed: ClaimedCaller,
}

impl IdentityFailure {
    /// A refusal with nothing claimed: there was no token.
    pub(crate) fn new(detail: VerifyError) -> Self {
        Self::claiming(detail, ClaimedCaller::default())
    }

    /// A refusal of a token that claimed `claimed`.
    pub(crate) fn claiming(detail: VerifyError, claimed: ClaimedCaller) -> Self {
        Self { detail, claimed }
    }

    /// Which check refused, for the log.
    pub fn detail(&self) -> &VerifyError {
        &self.detail
    }

    /// The issuer and subject the token claimed, for the identity-failure event (decision
    /// 0009). Nothing in them was verified.
    pub fn claimed(&self) -> &ClaimedCaller {
        &self.claimed
    }

    /// The one sentence a caller reads for every identity failure.
    pub fn outward(&self) -> &'static str {
        IDENTITY_FAILURE
    }
}

impl fmt::Debug for IdentityFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityFailure")
            .field("detail", &self.detail)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for IdentityFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(IDENTITY_FAILURE)
    }
}

impl std::error::Error for IdentityFailure {}

/// The issuer and subject a refused token claimed, read from its payload whatever check refused
/// it. Nothing in them was verified.
///
/// Decision 0009: the identity-failure event records them, escaped and capped, and never the
/// token. [`VerifyError`] still carries nothing from the token, so these are the only values
/// from it a refusal gives out. Each is escaped as sentences and audit rows are, by
/// [`gateway_core::escape`], and cut at [`MAX_CLAIMED`] characters before it is kept, so the
/// text the token held is never stored here as it was.
///
/// Each is `None` when the token had no such claim or one that is not a string, and both are
/// `None` when there was no token, it was too large to read, or its payload is not a JSON
/// object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaimedCaller {
    issuer: Option<Claimed<String>>,
    subject: Option<Claimed<String>>,
}

impl ClaimedCaller {
    /// Escapes and caps what a token claimed.
    pub(crate) fn new(issuer: Option<&str>, subject: Option<&str>) -> Self {
        let kept = |text: &str| Claimed::new(escape(text, MAX_CLAIMED));
        Self {
            issuer: issuer.map(kept),
            subject: subject.map(kept),
        }
    }

    /// The `iss` claim, escaped and capped.
    pub fn issuer(&self) -> Option<&Claimed<String>> {
        self.issuer.as_ref()
    }

    /// The `sub` claim, escaped and capped.
    pub fn subject(&self) -> Option<&Claimed<String>> {
        self.subject.as_ref()
    }
}
