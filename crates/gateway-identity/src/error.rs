//! Why a token was refused: in detail for logs, and in one opaque form for the caller.

use std::fmt;

use gateway_core::IDENTITY_FAILURE;
use thiserror::Error;

/// A claim a check names.
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
            Claim::Issuer => "iss",
            Claim::Subject => "sub",
            Claim::Audience => "aud",
            Claim::ExpiresAt => "exp",
            Claim::NotBefore => "nbf",
            Claim::IssuedAt => "iat",
            Claim::Groups => "the groups claim",
        })
    }
}

/// Which check refused a token. For operators' logs and for tests; never for the caller, who
/// reads [`IDENTITY_FAILURE`] whatever happened.
///
/// No variant carries a value taken from the token, so a refusal cannot put attacker-chosen
/// text into a log line. What it gives up is the offending issuer or `kid` by name; the token
/// is still in the request's own log.
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
    #[error("the token has no {0} claim")]
    MissingClaim(Claim),
    /// A claim is present but not the type or shape the check needs.
    #[error("the token's {0} claim is malformed")]
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
/// the cause is [`detail`](IdentityFailure::detail).
///
/// Its `Debug` output includes the detail, because logs are what that is for: never put a
/// `{:?}` of this into a response. The caller's text is [`outward`](IdentityFailure::outward),
/// or this value's `Display`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFailure {
    detail: VerifyError,
}

impl IdentityFailure {
    pub(crate) fn new(detail: VerifyError) -> Self {
        Self { detail }
    }

    /// Which check refused, for the log.
    pub fn detail(&self) -> &VerifyError {
        &self.detail
    }

    /// The one sentence a caller reads for every identity failure.
    pub fn outward(&self) -> &'static str {
        IDENTITY_FAILURE
    }
}

impl fmt::Display for IdentityFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(IDENTITY_FAILURE)
    }
}

impl std::error::Error for IdentityFailure {}
