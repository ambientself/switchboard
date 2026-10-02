//! A token issuer for tests: keys generated when it is built, tokens signed on request, and
//! every part of a token adjustable so a test can make the one broken token it needs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gateway_identity::{IssuerConfig, IssuerKind, SigningAlgorithm};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::{Map, Value, json};
use thiserror::Error;

/// How long a default token lives, in seconds.
pub const DEFAULT_TOKEN_LIFETIME: u64 = 600;
/// The ceiling [`LocalIssuer::config`] sets, in seconds.
pub const DEFAULT_MAX_LIFETIME: u64 = 3600;
/// The leeway [`LocalIssuer::config`] sets, in seconds.
pub const DEFAULT_LEEWAY: u64 = 30;

/// Why an issuer could not be built.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("could not generate a signing key: {0}")]
pub struct IssuerError(String);

fn jwt_algorithm(algorithm: SigningAlgorithm) -> Algorithm {
    match algorithm {
        SigningAlgorithm::Rs256 => Algorithm::RS256,
        SigningAlgorithm::Es256 => Algorithm::ES256,
    }
}

fn key_algorithm(algorithm: SigningAlgorithm) -> KeyAlgorithm {
    match algorithm {
        SigningAlgorithm::Rs256 => KeyAlgorithm::RS256,
        SigningAlgorithm::Es256 => KeyAlgorithm::ES256,
    }
}

/// An issuer with a freshly generated key pair.
///
/// The key pair is made when the issuer is built, from the operating system's randomness, and
/// is never written anywhere: no key is checked in, and two issuers never share one. An RSA
/// key takes a second or so to generate, so a test file that needs several shares them.
pub struct LocalIssuer {
    issuer: String,
    algorithm: SigningAlgorithm,
    key_id: String,
    key: EncodingKey,
    jwk: Jwk,
}

impl LocalIssuer {
    /// An issuer named `issuer` that signs with `algorithm`, with a new key pair.
    pub fn new(issuer: &str, algorithm: SigningAlgorithm) -> Result<Self, IssuerError> {
        let error =
            |what: &str, detail: &dyn std::fmt::Display| IssuerError(format!("{what}: {detail}"));
        let key = match algorithm {
            SigningAlgorithm::Es256 => {
                let secret = p256::SecretKey::random(&mut OsRng);
                let der = secret
                    .to_pkcs8_der()
                    .map_err(|source| error("encoding an EC key", &source))?;
                EncodingKey::from_ec_der(der.as_bytes())
            }
            SigningAlgorithm::Rs256 => {
                let secret = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
                    .map_err(|source| error("generating an RSA key", &source))?;
                let der = secret
                    .to_pkcs1_der()
                    .map_err(|source| error("encoding an RSA key", &source))?;
                EncodingKey::from_rsa_der(der.as_bytes())
            }
        };
        let mut jwk = Jwk::from_encoding_key(&key, jwt_algorithm(algorithm))
            .map_err(|source| error("deriving the public key", &source))?;
        // The thumbprint names the key by its contents, so two issuers never share a key id by
        // accident and a test that wants them to must say so.
        let thumbprint = jwk
            .thumbprint(ThumbprintHash::SHA256)
            .map_err(|source| error("naming the key", &source))?;
        let key_id = thumbprint.chars().take(16).collect::<String>();
        jwk.common.key_id = Some(key_id.clone());
        jwk.common.key_algorithm = Some(key_algorithm(algorithm));
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        Ok(Self {
            issuer: issuer.to_owned(),
            algorithm,
            key_id,
            key,
            jwk,
        })
    }

    /// The issuer string tokens carry in `iss`.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The algorithm this issuer signs with.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The `kid` of this issuer's key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public half of the key, as a JWK set: what a deployment is configured with.
    pub fn jwk_set(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.jwk.clone()],
        }
    }

    /// An issuer entry for `gateway-identity` that trusts this issuer's key, accepts
    /// `audiences`, and allows tokens of up to [`DEFAULT_MAX_LIFETIME`] seconds with
    /// [`DEFAULT_LEEWAY`] seconds of leeway. Every field is public, so a test changes the one
    /// it is about.
    pub fn config(&self, kind: IssuerKind, audiences: &[&str]) -> IssuerConfig {
        IssuerConfig {
            issuer: self.issuer.as_str().into(),
            audiences: audiences
                .iter()
                .map(|audience| (*audience).to_owned())
                .collect(),
            kind,
            algorithm: self.algorithm,
            keys: self.jwk_set(),
            max_lifetime: Duration::from_secs(DEFAULT_MAX_LIFETIME),
            leeway: Duration::from_secs(DEFAULT_LEEWAY),
        }
    }

    /// A valid workload token for `subject`, issued at `now`: `aud` is `audience`, `nbf` and
    /// `iat` are `now`, and `exp` is [`DEFAULT_TOKEN_LIFETIME`] seconds later.
    pub fn workload_token(
        &self,
        subject: &str,
        audience: &str,
        now: SystemTime,
    ) -> TokenBuilder<'_> {
        let at = seconds(now);
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(self.issuer));
        claims.insert("sub".into(), json!(subject));
        claims.insert("aud".into(), json!(audience));
        claims.insert("iat".into(), json!(at));
        claims.insert("nbf".into(), json!(at));
        claims.insert("exp".into(), json!(at + DEFAULT_TOKEN_LIFETIME));
        let mut header = Map::new();
        header.insert("alg".into(), json!(self.algorithm.as_str()));
        header.insert("kid".into(), json!(self.key_id));
        header.insert("typ".into(), json!("JWT"));
        TokenBuilder {
            issuer: self,
            header,
            claims,
            signing: Signing::Issuer,
        }
    }

    /// A valid user token for `subject` in `groups`, in the `groups` claim.
    pub fn user_token(
        &self,
        subject: &str,
        audience: &str,
        groups: &[&str],
        now: SystemTime,
    ) -> TokenBuilder<'_> {
        self.workload_token(subject, audience, now)
            .claim("groups", json!(groups))
    }
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

enum Signing<'a> {
    /// The issuer's own key and algorithm.
    Issuer,
    /// Another issuer's key, so the signature is well formed and wrong.
    Other(&'a LocalIssuer),
    /// An HMAC over the signing input with this secret: the algorithm-confusion attack.
    Hmac(Vec<u8>),
    /// The right key, with one character of the signature changed.
    Corrupted,
    /// No signature at all.
    Unsigned,
}

/// A token being built. Starts valid, and each method breaks or changes one thing.
///
/// Claims and header fields are plain JSON, so a test can write what the types would not let it:
/// an `exp` that is a string, a `groups` that is an object, an `alg` of `none`.
#[must_use = "a token builder does nothing until `build`"]
pub struct TokenBuilder<'a> {
    issuer: &'a LocalIssuer,
    header: Map<String, Value>,
    claims: Map<String, Value>,
    signing: Signing<'a>,
}

impl<'a> TokenBuilder<'a> {
    /// Sets a claim, replacing any value it had.
    pub fn claim(mut self, name: &str, value: Value) -> Self {
        self.claims.insert(name.to_owned(), value);
        self
    }

    /// Removes a claim.
    pub fn without_claim(mut self, name: &str) -> Self {
        self.claims.remove(name);
        self
    }

    /// Sets `iss`.
    pub fn issuer(self, issuer: &str) -> Self {
        self.claim("iss", json!(issuer))
    }

    /// Sets `sub`.
    pub fn subject(self, subject: &str) -> Self {
        self.claim("sub", json!(subject))
    }

    /// Sets `aud` to one audience.
    pub fn audience(self, audience: &str) -> Self {
        self.claim("aud", json!(audience))
    }

    /// Sets `aud` to an array of audiences.
    pub fn audiences(self, audiences: &[&str]) -> Self {
        self.claim("aud", json!(audiences))
    }

    /// Sets `iat`, in seconds since the epoch.
    pub fn issued_at(self, at: u64) -> Self {
        self.claim("iat", json!(at))
    }

    /// Sets `nbf`, in seconds since the epoch.
    pub fn not_before(self, at: u64) -> Self {
        self.claim("nbf", json!(at))
    }

    /// Sets `exp`, in seconds since the epoch.
    pub fn expires_at(self, at: u64) -> Self {
        self.claim("exp", json!(at))
    }

    /// Sets `exp` to `lifetime` seconds after the token's current `iat`.
    pub fn lifetime(self, lifetime: u64) -> Self {
        let issued = self.claims.get("iat").and_then(Value::as_u64).unwrap_or(0);
        self.expires_at(issued + lifetime)
    }

    /// Sets a header field.
    pub fn header(mut self, name: &str, value: Value) -> Self {
        self.header.insert(name.to_owned(), value);
        self
    }

    /// Sets the header's `alg` to this text, which need not name an algorithm anyone supports.
    /// The signature is whatever [`signed_by`](Self::signed_by) and its relatives say, so the
    /// header can claim one algorithm over a signature made another way.
    pub fn alg(self, alg: &str) -> Self {
        self.header("alg", json!(alg))
    }

    /// Sets the header's `kid`.
    pub fn kid(self, kid: &str) -> Self {
        self.header("kid", json!(kid))
    }

    /// Removes the header's `kid`.
    pub fn without_kid(mut self) -> Self {
        self.header.remove("kid");
        self
    }

    /// Signs with `other`'s key and algorithm instead: a well-formed signature that does not
    /// verify under this issuer's key.
    pub fn signed_by(mut self, other: &'a LocalIssuer) -> Self {
        self.signing = Signing::Other(other);
        self
    }

    /// Signs with HMAC-SHA256 under `secret`, and sets the header's `alg` to `HS256`.
    pub fn hmac_signed(mut self, secret: &[u8]) -> Self {
        self.signing = Signing::Hmac(secret.to_vec());
        self.alg("HS256")
    }

    /// Signs correctly, then changes one character of the signature.
    pub fn corrupt_signature(mut self) -> Self {
        self.signing = Signing::Corrupted;
        self
    }

    /// Leaves the signature empty, and sets the header's `alg` to `none`.
    pub fn unsigned(mut self) -> Self {
        self.signing = Signing::Unsigned;
        self.alg("none")
    }

    /// The token as it would be presented: three dot-separated parts.
    pub fn build(self) -> String {
        let encode = |object: &Map<String, Value>| {
            URL_SAFE_NO_PAD.encode(Value::Object(object.clone()).to_string())
        };
        let signing_input = format!("{}.{}", encode(&self.header), encode(&self.claims));
        let signature = match &self.signing {
            Signing::Issuer => sign(&self.issuer.key, self.issuer.algorithm, &signing_input),
            Signing::Other(other) => sign(&other.key, other.algorithm, &signing_input),
            Signing::Hmac(secret) => jsonwebtoken::crypto::sign(
                signing_input.as_bytes(),
                &EncodingKey::from_secret(secret),
                Algorithm::HS256,
            )
            .unwrap_or_default(),
            Signing::Corrupted => corrupt(&sign(
                &self.issuer.key,
                self.issuer.algorithm,
                &signing_input,
            )),
            Signing::Unsigned => String::new(),
        };
        format!("{signing_input}.{signature}")
    }
}

fn sign(key: &EncodingKey, algorithm: SigningAlgorithm, signing_input: &str) -> String {
    // An empty signature if signing somehow fails: it verifies as nothing, which is a safe
    // way for a test token to be wrong.
    jsonwebtoken::crypto::sign(signing_input.as_bytes(), key, jwt_algorithm(algorithm))
        .unwrap_or_default()
}

/// The signature with its first character swapped for a different base64url character.
fn corrupt(signature: &str) -> String {
    let mut characters = signature.chars();
    let swapped = match characters.next() {
        Some('A') => 'B',
        Some(_) => 'A',
        None => 'A',
    };
    std::iter::once(swapped).chain(characters).collect()
}
