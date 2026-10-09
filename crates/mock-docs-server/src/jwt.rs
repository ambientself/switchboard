//! The JWT mode: the server accepts one subject's tokens, signed by a key in a fixed set.
//!
//! In the kind deployment the gateway calls with its projected ServiceAccount token, and the
//! server checks it against the cluster's signing keys (decision 0010). A token is accepted
//! only if all of these hold:
//!
//! - its header names RS256 and a `kid` that is in the set. There is no fallback to the only
//!   key, and the key a header embeds is never used;
//! - the signature verifies under that key;
//! - `exp` is present and has not passed, give or take [`LEEWAY_SECONDS`], and `nbf`, if
//!   present, has come;
//! - `iss` is exactly the configured issuer, and `aud` contains the configured audience;
//! - `sub` is exactly the one configured subject.
//!
//! The subject is compared last, after the issuer and audience, so a token that is wrong in
//! both is refused as `wrong_audience`: it was never meant for this server. Keys are read once,
//! at start; a rotation of the cluster's signing key needs a restart.

use std::collections::BTreeMap;
use std::fmt;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

/// How far past `exp`, or before `nbf`, a token is still taken, for clocks that differ.
pub const LEEWAY_SECONDS: u64 = 30;

/// Why a request was refused in the JWT mode. Logged as [`Refusal::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request carried no bearer token.
    NoBearer,
    /// The bearer is not a JWT whose header and claims parse, or its algorithm is `none`.
    Malformed,
    /// The header names no `kid`, or one not in the set.
    UnknownKey,
    /// The algorithm is not RS256, or the signature does not verify under the named key.
    BadSignature,
    /// `iss` is missing or not exactly the configured issuer.
    WrongIssuer,
    /// `aud` is missing or does not contain the configured audience.
    WrongAudience,
    /// `exp` has passed.
    Expired,
    /// `nbf` has not come yet.
    NotYetValid,
    /// `sub` is missing or not the configured subject.
    WrongSubject,
}

impl Refusal {
    /// The name the log line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoBearer => "no_bearer",
            Self::Malformed => "malformed",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongSubject => "wrong_subject",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Checks bearer tokens against one issuer, audience and subject and a fixed set of RSA keys.
#[derive(Clone)]
pub struct JwtVerifier {
    issuer: String,
    audience: String,
    subject: String,
    keys: BTreeMap<String, DecodingKey>,
}

impl JwtVerifier {
    /// A verifier for tokens from `issuer`, for `audience`, about `subject`, signed by a key in
    /// `jwks`: a JWK set as JSON, in the shape a Kubernetes API server's `/openid/v1/jwks`
    /// returns. Every key must be an RSA key with a `kid` of its own; a key that declares an
    /// algorithm must declare RS256, and one that declares a use must declare `sig`.
    pub fn new(issuer: &str, audience: &str, subject: &str, jwks: &str) -> Result<Self, String> {
        let set: JwkSet =
            serde_json::from_str(jwks).map_err(|error| format!("not a JWK set: {error}"))?;
        if set.keys.is_empty() {
            return Err("the JWK set holds no keys".to_owned());
        }
        let mut keys = BTreeMap::new();
        for jwk in &set.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or_else(|| "a key has no kid".to_owned())?;
            if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
                return Err(format!("key {kid} is not an RSA key"));
            }
            if jwk
                .common
                .key_algorithm
                .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)
            {
                return Err(format!("key {kid} is not for RS256"));
            }
            if jwk
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|key_use| *key_use != PublicKeyUse::Signature)
            {
                return Err(format!("key {kid} is not for signatures"));
            }
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|error| format!("key {kid} is not usable: {error}"))?;
            if keys.insert(kid.clone(), key).is_some() {
                return Err(format!("two keys have the kid {kid}"));
            }
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            subject: subject.to_owned(),
            keys,
        })
    }

    /// The issuer accepted.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audience a token must name.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The one subject accepted.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The key IDs in the set, in order.
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    /// Verifies `token`. On success, the subject, which is the configured one; nothing is read
    /// from the token's claims before its signature has verified.
    pub fn verify(&self, token: &str) -> Result<String, Refusal> {
        // An algorithm `jsonwebtoken` does not know, `none` among them, fails here.
        let header = jsonwebtoken::decode_header(token).map_err(|_| Refusal::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(Refusal::BadSignature);
        }
        let key = header
            .kid
            .as_deref()
            .and_then(|kid| self.keys.get(kid))
            .ok_or(Refusal::UnknownKey)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = LEEWAY_SECONDS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // `jsonwebtoken` checks the signature first, then exp, nbf, iss and aud. The subject is
        // not given to it: it would check that before the issuer and audience.
        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, key, &validation)
            .map_err(|error| refusal(error.kind()))?
            .claims;
        // `jsonwebtoken` also takes an array of issuers that includes this one.
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(Refusal::WrongIssuer);
        }
        match claims.get("sub").and_then(Value::as_str) {
            Some(subject) if subject == self.subject => Ok(subject.to_owned()),
            _ => Err(Refusal::WrongSubject),
        }
    }
}

fn refusal(kind: &ErrorKind) -> Refusal {
    match kind {
        ErrorKind::InvalidSignature => Refusal::BadSignature,
        ErrorKind::ExpiredSignature => Refusal::Expired,
        ErrorKind::ImmatureSignature => Refusal::NotYetValid,
        ErrorKind::InvalidIssuer => Refusal::WrongIssuer,
        ErrorKind::InvalidAudience => Refusal::WrongAudience,
        ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => Refusal::WrongIssuer,
        ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => Refusal::WrongAudience,
        _ => Refusal::Malformed,
    }
}

impl fmt::Debug for JwtVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("subject", &self.subject)
            .field("key_ids", &self.key_ids())
            .finish()
    }
}
