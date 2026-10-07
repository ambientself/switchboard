//! What a deployment configures: a fixed list of issuers, or an explicit decision not to check.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use gateway_core::{Issuer, Subject, TeamId};
use jsonwebtoken::jwk::JwkSet;
use thiserror::Error;

/// The claim a user issuer's groups are read from unless configuration names another.
pub const DEFAULT_GROUPS_CLAIM: &str = "groups";

/// The most leeway an issuer may be configured with.
///
/// Leeway is for skew between clocks that are kept in time. Five minutes is the usual allowance
/// (Kerberos uses it), and a clock further out than that is broken, not skewed. Every second of
/// leeway is a second added to every token's life, and a leeway as long as the lifetime ceiling
/// would turn the time checks off without anyone having said so.
pub const MAX_LEEWAY: Duration = Duration::from_secs(300);

/// The smallest RSA modulus accepted, in bits. Keys shorter than this have been retired for
/// signatures since 2013 (NIST SP 800-131A), and identity providers publish 2048-bit keys or
/// longer.
pub const MIN_RSA_BITS: usize = 2048;

/// The one signing algorithm an issuer's tokens may use. Deliberately only two: a token's
/// header never chooses its algorithm, the issuer's configuration does, and there is no
/// `none` and no HMAC to choose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256; keys are RSA.
    Rs256,
    /// ECDSA with P-256 and SHA-256; keys are on the P-256 curve.
    Es256,
}

impl SigningAlgorithm {
    /// The algorithm's name as a token's `alg` header writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningAlgorithm::Rs256 => "RS256",
            SigningAlgorithm::Es256 => "ES256",
        }
    }

    pub(crate) fn jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            SigningAlgorithm::Rs256 => jsonwebtoken::Algorithm::RS256,
            SigningAlgorithm::Es256 => jsonwebtoken::Algorithm::ES256,
        }
    }
}

/// What an issuer's tokens are about, and the facts that come with that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssuerKind {
    /// A workload issuer, such as a Kubernetes cluster. A token's subject must be in this
    /// table, which maps it to the team the manifest says it belongs to.
    Workload {
        /// Subject to team. A subject not listed is refused, after its signature is checked.
        subjects: BTreeMap<Subject, TeamId>,
    },
    /// A user issuer, such as the company identity provider. Groups come from a claim.
    User {
        /// The claim holding the user's groups: an array of strings.
        groups_claim: String,
    },
}

impl IssuerKind {
    /// A user issuer that reads groups from the claim named [`DEFAULT_GROUPS_CLAIM`].
    pub fn user() -> Self {
        IssuerKind::User {
            groups_claim: DEFAULT_GROUPS_CLAIM.to_owned(),
        }
    }
}

/// One issuer a deployment trusts.
///
/// The fields are what design section 7 lists: the issuer string, exact match; its accepted
/// audiences; its kind; one signing algorithm; its keys, supplied directly; a ceiling on token
/// lifetime; and a leeway for clock skew. Nothing here is a URL, because nothing in this crate
/// fetches anything.
#[derive(Clone, Debug, PartialEq)]
pub struct IssuerConfig {
    /// The issuer, matched exactly against a token's `iss`.
    pub issuer: Issuer,
    /// The audiences this deployment accepts for this issuer. A token must name at least one.
    pub audiences: BTreeSet<String>,
    /// Workload or user, with what each needs.
    pub kind: IssuerKind,
    /// The algorithm this issuer signs with. A token whose header says another is refused.
    pub algorithm: SigningAlgorithm,
    /// The verification keys. Every key needs a `kid`, which a token must name. A key that
    /// cannot verify this issuer's signatures, such as an encryption key published in the same
    /// set, is left out, and a token naming it is refused; the issuer is refused only if no key
    /// can verify.
    pub keys: JwkSet,
    /// The longest a token may live: `exp - iat` may not exceed it.
    pub max_lifetime: Duration,
    /// Clock skew tolerated on `exp`, `nbf` and `iat`. At most [`MAX_LEEWAY`].
    pub leeway: Duration,
}

/// Whether to verify callers, and against which issuers.
///
/// A deployment states one or the other. There is no default and no way to leave both out:
/// an unconfigured gate is a configuration the caller has to construct on purpose, which is
/// what lets "we were not checking" be told from "someone tried and was refused" later.
#[derive(Clone, Debug, PartialEq)]
pub enum IdentityConfig {
    /// Verify every caller against these issuers. An empty list is refused.
    Enforce(Vec<IssuerConfig>),
    /// Checking was explicitly turned off. The only way a verification can be `disabled`.
    Disabled,
}

/// Why identity configuration was refused. Raised when the verifier is built, so a deployment
/// with bad identity configuration does not start.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// Enforcement was asked for with no issuer to enforce against.
    #[error("identity checking is on but no issuer is configured")]
    NoIssuers,
    /// Two entries name the same issuer, so which one a token belongs to is ambiguous.
    #[error("issuer `{0}` is configured more than once")]
    DuplicateIssuer(Issuer),
    /// A second user issuer. Group names are not qualified by issuer, so a group name used by
    /// two identity providers would admit the members of both (decision 0006). One user
    /// issuer per deployment until that is settled.
    #[error(
        "user issuers `{first}` and `{second}` are both configured; group names are not \
         qualified by issuer, so a deployment has at most one"
    )]
    SecondUserIssuer {
        /// The user issuer listed first.
        first: Issuer,
        /// The one listed after it.
        second: Issuer,
    },
    /// An issuer string that can never match a token.
    #[error("an issuer is configured with an empty name")]
    EmptyIssuer,
    /// An issuer with no audience would accept nothing, or if loosened, everything.
    #[error("issuer `{0}` has no accepted audience")]
    NoAudience(Issuer),
    /// An issuer with a zero ceiling would refuse every token.
    #[error("issuer `{0}` has a maximum token lifetime of zero")]
    NoLifetime(Issuer),
    /// A leeway over [`MAX_LEEWAY`], which would stretch every token's life.
    #[error("issuer `{0}` has a leeway of more than {max} seconds", max = MAX_LEEWAY.as_secs())]
    LeewayTooLarge(Issuer),
    /// A workload issuer with no subjects would refuse every token.
    #[error("workload issuer `{0}` has no subjects")]
    NoSubjects(Issuer),
    /// A user issuer that reads groups from a claim with no name.
    #[error("user issuer `{0}` has an empty groups claim name")]
    EmptyGroupsClaim(Issuer),
    /// An issuer with no key could never verify a signature.
    #[error("issuer `{0}` has no keys")]
    NoKeys(Issuer),
    /// A key with no `kid`, which a token could not name.
    #[error("issuer `{0}` has a key with no `kid`")]
    KeyWithoutId(Issuer),
    /// Two keys with one `kid`.
    #[error("issuer `{issuer}` has two keys with `kid` `{kid}`")]
    DuplicateKeyId {
        /// The issuer.
        issuer: Issuer,
        /// The repeated `kid`.
        kid: String,
    },
    /// No key in the issuer's set can verify its signatures: this is the first one. It is not
    /// of the kind, or on the curve, the issuer's algorithm needs, or it declares itself for
    /// another algorithm, use or operation, or it is not a key at all.
    #[error("issuer `{issuer}` key `{kid}` cannot verify {algorithm} signatures")]
    KeyDoesNotFit {
        /// The issuer.
        issuer: Issuer,
        /// The key.
        kid: String,
        /// The algorithm the issuer is configured with.
        algorithm: &'static str,
    },
    /// No key in the issuer's set can verify its signatures, and the first is an RSA key
    /// shorter than [`MIN_RSA_BITS`].
    #[error(
        "issuer `{issuer}` key `{kid}` is a {bits}-bit RSA key, shorter than {} bits",
        MIN_RSA_BITS
    )]
    WeakKey {
        /// The issuer.
        issuer: Issuer,
        /// The key.
        kid: String,
        /// The length of its modulus.
        bits: usize,
    },
}
