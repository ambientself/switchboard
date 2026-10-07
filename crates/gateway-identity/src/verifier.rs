//! The token verifier: the one place in this crate that makes a proved principal.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_core::{GroupId, Principal, PrincipalId, PrincipalKind, Verifier};
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{DecodingKey, Validation};
use serde_json::{Map, Value};

use crate::clock::{Clock, unix_seconds};
use crate::config::{
    ConfigError, IssuerConfig, IssuerKind, MAX_LEEWAY, MIN_RSA_BITS, SigningAlgorithm,
};
use crate::error::{Claim, IdentityFailure, VerifyError};

/// The largest token accepted, in bytes. Larger than any token an identity provider issues for
/// a user with many groups, and small enough that parsing one is not a way to spend the
/// gateway's time.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

type Claims = Map<String, Value>;

/// One configured issuer, with its keys decoded once at construction.
struct Entry {
    issuer: gateway_core::Issuer,
    audiences: BTreeSet<String>,
    kind: IssuerKind,
    algorithm: SigningAlgorithm,
    keys: BTreeMap<String, DecodingKey>,
    max_lifetime: u64,
    leeway: u64,
}

/// Verifies signed tokens against a fixed list of issuers and produces proved principals.
///
/// Implements [`Verifier`] for [`Principal`], so [`Proved::verify`](gateway_core::Proved::verify)
/// over a token's text is the way a proved principal comes to exist. Everything a token could
/// say about how it should be checked is ignored: the issuer's entry, which only
/// configuration can add to, chooses the keys and the algorithm, and no URL in a token is ever
/// followed.
pub struct TokenVerifier {
    issuers: BTreeMap<String, Entry>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for TokenVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenVerifier")
            .field("issuers", &self.issuers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl TokenVerifier {
    /// Builds a verifier from a non-empty list of issuers, refusing configuration that could
    /// never verify anything or that is ambiguous. A deployment with such configuration does
    /// not start.
    ///
    /// At most one issuer may be a user issuer, because group names are not qualified by issuer
    /// (decision 0006).
    pub fn new(issuers: Vec<IssuerConfig>, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        if issuers.is_empty() {
            return Err(ConfigError::NoIssuers);
        }
        let mut entries = BTreeMap::new();
        let mut user_issuer: Option<gateway_core::Issuer> = None;
        for config in issuers {
            let name = config.issuer.as_str().to_owned();
            let entry = Entry::new(config)?;
            let user = matches!(entry.kind, IssuerKind::User { .. }).then(|| entry.issuer.clone());
            if entries.insert(name.clone(), entry).is_some() {
                return Err(ConfigError::DuplicateIssuer(name.as_str().into()));
            }
            if let Some(second) = user
                && let Some(first) = user_issuer.replace(second.clone())
            {
                return Err(ConfigError::SecondUserIssuer { first, second });
            }
        }
        Ok(Self {
            issuers: entries,
            clock,
        })
    }

    fn verify_token(&self, token: &str) -> Result<Principal, VerifyError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(VerifyError::TokenTooLarge);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| header_error(token))?;
        let entry = self.entry_named_by(token)?;

        // The header's `alg` is compared with the issuer's configured one and never used to
        // choose anything: a token cannot ask to be checked more loosely.
        if header.alg != entry.algorithm.jwt() {
            return Err(VerifyError::AlgorithmNotAllowed);
        }
        // `crit` names header parameters a verifier must understand to accept the token (RFC
        // 7515 section 4.1.11). This verifier understands none, so a token carrying `crit` is
        // refused whatever it lists, even nothing.
        if carries_crit(token) {
            return Err(VerifyError::CriticalHeader);
        }
        let kid = header.kid.as_deref().ok_or(VerifyError::MissingKeyId)?;
        let key = entry.keys.get(kid).ok_or(VerifyError::UnknownKeyId)?;

        let claims = verify_signature(token, entry.algorithm, key)?;

        let now = unix_seconds(self.clock.as_ref());
        let expires_at = check_not_expired(&claims, now, entry.leeway)?;
        check_not_early(&claims, now, entry.leeway)?;
        check_audience(&claims, &entry.audiences)?;
        check_lifetime(&claims, expires_at, now, entry)?;
        let subject = subject_of(&claims)?;

        // Everything below depends on the subject, so it comes after everything above: the
        // signature in particular. A caller guessing at subjects therefore pays for a
        // signature check on every guess, right or wrong, and cannot tell from the work done
        // or the answer given which subjects exist (design section 7).
        let kind = match &entry.kind {
            IssuerKind::Workload { subjects } => {
                let team = subjects
                    .get(&subject)
                    .ok_or(VerifyError::UnknownSubject)?
                    .clone();
                PrincipalKind::Workload { team }
            }
            IssuerKind::User { groups_claim } => PrincipalKind::User {
                groups: groups_of(&claims, groups_claim)?,
            },
        };
        Ok(Principal {
            // The configured issuer, keyed with the subject. Equal to the token's `iss` by
            // construction, since that is how the entry was found.
            id: PrincipalId {
                issuer: entry.issuer.clone(),
                subject,
            },
            kind,
        })
    }

    /// The configured issuer a token names, from its `iss` claim read before any signature is
    /// checked.
    ///
    /// The unverified claim is used for exactly one thing: choosing among entries that
    /// configuration already holds. It cannot add an issuer, and nothing else from the token
    /// reaches the choice of keys or algorithm. If the claim is forged the signature check
    /// that follows fails under that issuer's keys.
    fn entry_named_by(&self, token: &str) -> Result<&Entry, VerifyError> {
        let unverified: Claims = jsonwebtoken::dangerous::insecure_decode_claims(token)
            .map_err(|_| VerifyError::MalformedToken)?;
        let issuer = unverified
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(VerifyError::MissingIssuer)?;
        self.issuers.get(issuer).ok_or(VerifyError::UnknownIssuer)
    }
}

impl Verifier for TokenVerifier {
    /// The token as the caller presented it, without a `Bearer ` prefix.
    type Evidence = str;
    type Fact = Principal;
    type Error = IdentityFailure;

    fn verify(&self, token: &str) -> Result<Principal, IdentityFailure> {
        self.verify_token(token).map_err(IdentityFailure::new)
    }
}

impl Entry {
    fn new(config: IssuerConfig) -> Result<Self, ConfigError> {
        let issuer = config.issuer.clone();
        if issuer.as_str().is_empty() {
            return Err(ConfigError::EmptyIssuer);
        }
        if config.audiences.is_empty() || config.audiences.iter().any(String::is_empty) {
            return Err(ConfigError::NoAudience(issuer));
        }
        let max_lifetime = config.max_lifetime.as_secs();
        if max_lifetime == 0 {
            return Err(ConfigError::NoLifetime(issuer));
        }
        if config.leeway > MAX_LEEWAY {
            return Err(ConfigError::LeewayTooLarge(issuer));
        }
        match &config.kind {
            IssuerKind::Workload { subjects } if subjects.is_empty() => {
                return Err(ConfigError::NoSubjects(issuer));
            }
            IssuerKind::User { groups_claim } if groups_claim.is_empty() => {
                return Err(ConfigError::EmptyGroupsClaim(issuer));
            }
            _ => {}
        }
        // A set may hold keys that cannot verify this issuer's signatures, such as the
        // encryption key an identity provider publishes beside its signing keys. Those are left
        // out, so a token naming one is refused as naming an unknown key, and the issuer is
        // refused only if no key is left, or there were none. Every key still needs a `kid`
        // that no other key in the set has, so which key a token names is never in doubt.
        let mut kids = BTreeSet::new();
        let mut keys = BTreeMap::new();
        let mut first_unfit = None;
        for jwk in &config.keys.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or_else(|| ConfigError::KeyWithoutId(issuer.clone()))?;
            if !kids.insert(kid.clone()) {
                return Err(ConfigError::DuplicateKeyId { issuer, kid });
            }
            match decoding_key(jwk, config.algorithm) {
                Ok(decoded) => {
                    keys.insert(kid, decoded);
                }
                Err(unfit) => {
                    first_unfit.get_or_insert((kid, unfit));
                }
            }
        }
        if keys.is_empty() {
            return Err(match first_unfit {
                Some((kid, unfit)) => unfit.error(issuer, kid, config.algorithm),
                None => ConfigError::NoKeys(issuer),
            });
        }
        Ok(Self {
            issuer,
            audiences: config.audiences,
            kind: config.kind,
            algorithm: config.algorithm,
            keys,
            max_lifetime,
            leeway: config.leeway.as_secs(),
        })
    }
}

/// Why a key in an issuer's set was left out.
enum Unfit {
    /// Not of the kind the algorithm needs, declared for something else, or not a key.
    DoesNotFit,
    /// An RSA key with a modulus of this many bits, fewer than [`MIN_RSA_BITS`].
    Weak(usize),
    /// An RSA key the crypto backend refuses to build, for this reason.
    UnusableRsa(String),
}

impl Unfit {
    /// The configuration error that reports this key.
    fn error(
        self,
        issuer: gateway_core::Issuer,
        kid: String,
        algorithm: SigningAlgorithm,
    ) -> ConfigError {
        match self {
            Unfit::DoesNotFit => ConfigError::KeyDoesNotFit {
                issuer,
                kid,
                algorithm: algorithm.as_str(),
            },
            Unfit::Weak(bits) => ConfigError::WeakKey { issuer, kid, bits },
            Unfit::UnusableRsa(reason) => ConfigError::UnusableRsaKey {
                issuer,
                kid,
                reason,
            },
        }
    }
}

/// The key a JWK gives for verifying `algorithm` signatures, or why it gives none.
fn decoding_key(jwk: &Jwk, algorithm: SigningAlgorithm) -> Result<DecodingKey, Unfit> {
    if !key_fits(jwk, algorithm) {
        return Err(Unfit::DoesNotFit);
    }
    if let AlgorithmParameters::RSA(params) = &jwk.algorithm {
        let bits = modulus_bits(&params.n).ok_or(Unfit::DoesNotFit)?;
        if bits < MIN_RSA_BITS {
            return Err(Unfit::Weak(bits));
        }
        rsa_key_usable(&params.n, &params.e)?;
    }
    DecodingKey::from_jwk(jwk).map_err(|_| Unfit::DoesNotFit)
}

/// The length in bits of an RSA modulus written as base64url, not counting leading zeros.
/// `None` if it is not base64url, or is zero.
fn modulus_bits(n: &str) -> Option<usize> {
    let bytes = URL_SAFE_NO_PAD.decode(n).ok()?;
    let mut significant = bytes.iter().skip_while(|&&byte| byte == 0);
    let top = significant.next()?;
    let unused = usize::try_from(top.leading_zeros()).ok()?;
    Some((significant.count() + 1) * 8 - unused)
}

/// Builds the public key the crypto backend builds from `n` and `e` each time it verifies an
/// RS256 signature, and refuses the key if the backend would.
///
/// `DecodingKey::from_jwk` keeps `n` and `e` as bytes and checks nothing about them. The
/// backend, `jsonwebtoken`'s pure-Rust one, calls `RsaPublicKey::new` on every verify, which
/// refuses a modulus over 4096 bits or even, and an exponent that is even, under 2 or over
/// 2^33 - 1. `jsonwebtoken` reports that as `InvalidSignature`, the same as a forgery, so a key
/// it refuses would fail every token under it as [`VerifyError::BadSignature`]. Calling the same
/// constructor here, from the same crate, refuses that key when it is configured instead.
fn rsa_key_usable(n: &str, e: &str) -> Result<(), Unfit> {
    let n = URL_SAFE_NO_PAD.decode(n).map_err(|_| Unfit::DoesNotFit)?;
    let e = URL_SAFE_NO_PAD.decode(e).map_err(|_| Unfit::DoesNotFit)?;
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .map(|_| ())
    .map_err(|error| Unfit::UnusableRsa(error.to_string()))
}

/// Whether a JWK is of the kind `algorithm` needs, and does not say it is for something else.
fn key_fits(jwk: &Jwk, algorithm: SigningAlgorithm) -> bool {
    let shape = match (&jwk.algorithm, algorithm) {
        (AlgorithmParameters::RSA(_), SigningAlgorithm::Rs256) => true,
        (AlgorithmParameters::EllipticCurve(params), SigningAlgorithm::Es256) => {
            params.curve == EllipticCurve::P256
        }
        _ => false,
    };
    let declared_algorithm = match (jwk.common.key_algorithm, algorithm) {
        (None, _) => true,
        (Some(KeyAlgorithm::RS256), SigningAlgorithm::Rs256) => true,
        (Some(KeyAlgorithm::ES256), SigningAlgorithm::Es256) => true,
        (Some(_), _) => false,
    };
    let declared_use = matches!(
        jwk.common.public_key_use,
        None | Some(PublicKeyUse::Signature)
    );
    // `key_ops`, when present, must include verifying: a key listed only for encrypting, or
    // only for signing, is not one a verifier should use.
    let declared_operations = jwk
        .common
        .key_operations
        .as_ref()
        .is_none_or(|operations| operations.contains(&KeyOperations::Verify));
    shape && declared_algorithm && declared_use && declared_operations
}

/// Why `jsonwebtoken` could not parse a token's header.
///
/// It only knows the algorithms it implements, so `none`, or anything else it does not
/// recognise, fails to parse. That is a refusal of the algorithm, not of the token's shape, and
/// the log should say so: an `alg` of `none` is an attack, not a typo.
fn header_error(token: &str) -> VerifyError {
    let mut parts = token.split('.');
    let (header, three_parts) = (parts.next(), parts.count() == 2);
    // Only an `alg` that is a string `jsonwebtoken` does not know is the algorithm's fault; a
    // header it cannot parse for another reason is just malformed.
    let unknown_algorithm = three_parts
        && header
            .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|header| header.get("alg").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|alg| alg.parse::<jsonwebtoken::Algorithm>().is_err());
    if unknown_algorithm {
        VerifyError::AlgorithmNotAllowed
    } else {
        VerifyError::MalformedToken
    }
}

/// Whether a token's header has a `crit` member, of any value. Read from the header's JSON
/// rather than from `jsonwebtoken`'s parse of it, which reads a `crit` of `null` as no `crit`.
/// A header that cannot be read is counted as having one, so this can only refuse.
fn carries_crit(token: &str) -> bool {
    token
        .split('.')
        .next()
        .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
        .and_then(|bytes| serde_json::from_slice::<Map<String, Value>>(&bytes).ok())
        .is_none_or(|header| header.contains_key("crit"))
}

/// Checks the signature under `key` and returns the claims it covers.
///
/// Every time and audience check in `jsonwebtoken` is switched off here: it reads the system
/// clock, which this crate must not, so those checks are made below against the injected
/// clock. What is left of `decode` is the signature, and the parse of what the signature
/// covers.
///
/// An ES256 signature is malleable: given a valid `(r, s)`, anyone can write `(r, n - s)`,
/// which also verifies, so one set of claims has two token strings. Nothing in the gateway
/// keys on a token's string: no cache, replay check or audit record holds it, and the
/// principal comes from the claims, which are the same under both. So both forms are accepted.
/// Anything that later keys on the token itself (a replay cache, a record of tokens seen) must
/// first require the low-s form, or key on the claims instead.
fn verify_signature(
    token: &str,
    algorithm: SigningAlgorithm,
    key: &DecodingKey,
) -> Result<Claims, VerifyError> {
    let mut validation = Validation::new(algorithm.jwt());
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    match jsonwebtoken::decode::<Claims>(token, key, &validation) {
        Ok(data) => Ok(data.claims),
        Err(error) => Err(match error.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => VerifyError::BadSignature,
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => VerifyError::AlgorithmNotAllowed,
            jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey
            | jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_)
            | jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => VerifyError::UnusableKey,
            _ => VerifyError::MalformedToken,
        }),
    }
}

/// A date claim: a whole number of seconds. A fractional date is refused rather than rounded
/// in either direction.
fn date(claims: &Claims, name: &str, claim: Claim) -> Result<u64, VerifyError> {
    match claims.get(name) {
        None => Err(VerifyError::MissingClaim(claim)),
        Some(value) => value.as_u64().ok_or(VerifyError::MalformedClaim(claim)),
    }
}

/// `exp` is required, and the token is valid while the time is before it, plus leeway.
fn check_not_expired(claims: &Claims, now: u64, leeway: u64) -> Result<u64, VerifyError> {
    let expires_at = date(claims, "exp", Claim::ExpiresAt)?;
    if now >= expires_at.saturating_add(leeway) {
        return Err(VerifyError::Expired);
    }
    Ok(expires_at)
}

/// `nbf` is optional, and when present (even as `null`, which is then malformed) the token is
/// valid from it, less leeway.
fn check_not_early(claims: &Claims, now: u64, leeway: u64) -> Result<(), VerifyError> {
    if !claims.contains_key("nbf") {
        return Ok(());
    }
    let not_before = date(claims, "nbf", Claim::NotBefore)?;
    if not_before > now.saturating_add(leeway) {
        return Err(VerifyError::NotYetValid);
    }
    Ok(())
}

/// `aud` is a string or an array of strings, and at least one must be accepted.
fn check_audience(claims: &Claims, accepted: &BTreeSet<String>) -> Result<(), VerifyError> {
    let named: Vec<&str> = match claims.get("aud") {
        None => return Err(VerifyError::MissingClaim(Claim::Audience)),
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many
            .iter()
            .map(Value::as_str)
            .collect::<Option<_>>()
            .ok_or(VerifyError::MalformedClaim(Claim::Audience))?,
        Some(_) => return Err(VerifyError::MalformedClaim(Claim::Audience)),
    };
    if named.iter().any(|audience| accepted.contains(*audience)) {
        Ok(())
    } else {
        Err(VerifyError::AudienceMismatch)
    }
}

/// `iat` is required, and the time from it to `exp` may not exceed the issuer's ceiling.
fn check_lifetime(
    claims: &Claims,
    expires_at: u64,
    now: u64,
    entry: &Entry,
) -> Result<(), VerifyError> {
    let issued_at = date(claims, "iat", Claim::IssuedAt)?;
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(VerifyError::ExpiresBeforeIssue)?;
    if lifetime > entry.max_lifetime {
        return Err(VerifyError::LifetimeTooLong);
    }
    if issued_at > now.saturating_add(entry.leeway) {
        return Err(VerifyError::IssuedInFuture);
    }
    Ok(())
}

/// `sub` is required: a non-empty string.
fn subject_of(claims: &Claims) -> Result<gateway_core::Subject, VerifyError> {
    match claims.get("sub") {
        None => Err(VerifyError::MissingClaim(Claim::Subject)),
        Some(Value::String(subject)) if !subject.is_empty() => Ok(subject.as_str().into()),
        Some(_) => Err(VerifyError::MalformedClaim(Claim::Subject)),
    }
}

/// A user's groups: the named claim, an array of strings. A missing claim is refused, because
/// a token that says nothing about groups is not evidence of having none; an empty array is a
/// user in no group.
fn groups_of(claims: &Claims, name: &str) -> Result<BTreeSet<GroupId>, VerifyError> {
    match claims.get(name) {
        None => Err(VerifyError::MissingClaim(Claim::Groups)),
        Some(Value::Array(groups)) => groups
            .iter()
            .map(|group| group.as_str().map(GroupId::from))
            .collect::<Option<_>>()
            .ok_or(VerifyError::MalformedClaim(Claim::Groups)),
        Some(_) => Err(VerifyError::MalformedClaim(Claim::Groups)),
    }
}
