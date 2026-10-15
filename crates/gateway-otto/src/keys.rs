//! The grant keys a deployment configures: per issuer, a current key and at most one previous
//! key with an absolute end instant, and whether the issuer's grants must carry `pod` and
//! `egress` (decision 0012, Keys).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::format::KeyId;

/// The DER of an Ed25519 SubjectPublicKeyInfo (RFC 8410) up to the key itself: SEQUENCE,
/// AlgorithmIdentifier { id-Ed25519 }, BIT STRING with no unused bits.
pub(crate) const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const END: &str = "-----END PUBLIC KEY-----";

/// The name of an issuer: an Otto environment's control plane, which holds the private key.
/// The audit row records it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerName(String);

impl IssuerName {
    /// The name as configured.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One issuer, as the deployment configures it.
#[derive(Clone, Debug)]
pub struct IssuerConfig {
    /// The issuer's name, recorded on every row its grants verify for.
    pub name: String,
    /// The text of the current key's file: one Ed25519 public key in PEM (`PUBLIC KEY`).
    pub current_key: String,
    /// The key being rotated away from, if any.
    pub previous_key: Option<PreviousKeyConfig>,
    /// Whether this issuer's grants must carry `pod`, which must then equal the caller's pod
    /// UID.
    pub require_pod: bool,
    /// Whether this issuer's grants must carry `egress`.
    pub require_egress: bool,
}

/// The key an issuer is rotating away from.
#[derive(Clone, Debug)]
pub struct PreviousKeyConfig {
    /// The text of the key's file, as for the current key.
    pub key: String,
    /// The absolute instant the key retires. From then on its grants are refused, whenever the
    /// gateway started. Required: a previous key with no end would never retire.
    pub retires_at: Option<SystemTime>,
}

/// Why grant-key configuration was refused. Each refusal is its own variant.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeyConfigError {
    /// No issuer is configured, so no grant could verify.
    #[error("no turn-grant issuer is configured")]
    NoIssuers,
    /// An issuer has an empty name.
    #[error("a turn-grant issuer is configured with an empty name")]
    EmptyIssuerName,
    /// Two issuers have the same name.
    #[error("turn-grant issuer `{0}` is configured more than once")]
    DuplicateIssuer(String),
    /// A key file holds private key material. The gateway holds public keys only.
    #[error("a key file of turn-grant issuer `{0}` holds private key material")]
    PrivateKeyMaterial(String),
    /// A key file is not one Ed25519 public key in PEM, or the key is not a canonical encoding
    /// of a point on the curve.
    #[error("a key file of turn-grant issuer `{0}` is not one Ed25519 public key in PEM")]
    NotAPublicKey(String),
    /// A key is of small order, so a signature under it could verify for many messages.
    #[error("a key of turn-grant issuer `{0}` is of small order")]
    SmallOrderKey(String),
    /// An issuer's previous key is its current key.
    #[error("turn-grant issuer `{0}` has the same key as its current and previous key")]
    KeyRepeated(String),
    /// One key is configured under two issuers.
    #[error("turn-grant key `{key_id}` is configured under issuers `{first}` and `{second}`")]
    KeyUnderTwoIssuers {
        /// The key's ID.
        key_id: KeyId,
        /// The issuer it was configured under first.
        first: String,
        /// The other issuer.
        second: String,
    },
    /// A previous key has no end instant.
    #[error("the previous key of turn-grant issuer `{0}` has no end instant")]
    PreviousKeyWithoutEnd(String),
}

/// An issuer's settings, shared by its keys.
#[derive(Clone, Debug)]
pub(crate) struct Issuer {
    pub(crate) name: IssuerName,
    pub(crate) require_pod: bool,
    pub(crate) require_egress: bool,
}

/// One configured key.
#[derive(Clone, Debug)]
pub(crate) struct Key {
    pub(crate) key: VerifyingKey,
    pub(crate) issuer: usize,
    /// When the key retires; `None` for a current key.
    pub(crate) retires_at: Option<SystemTime>,
}

/// The configured grant keys, checked: what the verifier holds.
#[derive(Clone, Debug)]
pub struct GrantKeys {
    pub(crate) issuers: Vec<Issuer>,
    pub(crate) keys: BTreeMap<KeyId, Key>,
}

impl GrantKeys {
    /// Checks the configuration and builds the keys from it.
    pub fn new(config: &[IssuerConfig]) -> Result<Self, KeyConfigError> {
        if config.is_empty() {
            return Err(KeyConfigError::NoIssuers);
        }
        let mut issuers: Vec<Issuer> = Vec::with_capacity(config.len());
        let mut names = BTreeSet::new();
        let mut keys: BTreeMap<KeyId, Key> = BTreeMap::new();
        for issuer in config {
            if issuer.name.is_empty() {
                return Err(KeyConfigError::EmptyIssuerName);
            }
            if !names.insert(issuer.name.as_str()) {
                return Err(KeyConfigError::DuplicateIssuer(issuer.name.clone()));
            }
            let index = issuers.len();
            let mut configured = vec![(
                public_key(&issuer.current_key, &issuer.name)?,
                None::<SystemTime>,
            )];
            if let Some(previous) = &issuer.previous_key {
                let key = public_key(&previous.key, &issuer.name)?;
                let Some(retires_at) = previous.retires_at else {
                    return Err(KeyConfigError::PreviousKeyWithoutEnd(issuer.name.clone()));
                };
                configured.push((key, Some(retires_at)));
            }
            for (key, retires_at) in configured {
                let key_id = KeyId::of(key.as_bytes());
                if let Some(existing) = keys.get(&key_id) {
                    if existing.issuer == index {
                        return Err(KeyConfigError::KeyRepeated(issuer.name.clone()));
                    }
                    return Err(KeyConfigError::KeyUnderTwoIssuers {
                        key_id,
                        first: issuers[existing.issuer].name.0.clone(),
                        second: issuer.name.clone(),
                    });
                }
                keys.insert(
                    key_id,
                    Key {
                        key,
                        issuer: index,
                        retires_at,
                    },
                );
            }
            issuers.push(Issuer {
                name: IssuerName(issuer.name.clone()),
                require_pod: issuer.require_pod,
                require_egress: issuer.require_egress,
            });
        }
        Ok(Self { issuers, keys })
    }

    /// The ID of every configured key, with its issuer and its end instant (`None` for a
    /// current key), for the boot log.
    pub fn key_ids(&self) -> impl Iterator<Item = (&KeyId, &IssuerName, Option<SystemTime>)> {
        self.keys
            .iter()
            .map(|(id, key)| (id, &self.issuers[key.issuer].name, key.retires_at))
    }
}

/// Reads one Ed25519 public key from a key file's text.
fn public_key(text: &str, issuer: &str) -> Result<VerifyingKey, KeyConfigError> {
    // Any PEM private key, whatever its kind: PKCS#8, encrypted, OpenSSH, SEC1 or PKCS#1.
    if text.contains("PRIVATE KEY") {
        return Err(KeyConfigError::PrivateKeyMaterial(issuer.to_owned()));
    }
    let not_a_key = || KeyConfigError::NotAPublicKey(issuer.to_owned());
    let body = text
        .trim()
        .strip_prefix(BEGIN)
        .and_then(|rest| rest.strip_suffix(END))
        .ok_or_else(not_a_key)?;
    let body: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = STANDARD.decode(body).map_err(|_| not_a_key())?;
    // A PKCS#8 PrivateKeyInfo is a SEQUENCE whose first member is its version, an INTEGER; a
    // SubjectPublicKeyInfo starts with a SEQUENCE. Private key DER under a public label is
    // still private key material.
    if is_private_key_info(&der) {
        return Err(KeyConfigError::PrivateKeyMaterial(issuer.to_owned()));
    }
    let bytes: [u8; 32] = der
        .strip_prefix(&SPKI_PREFIX)
        .and_then(|key| key.try_into().ok())
        .ok_or_else(not_a_key)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| not_a_key())?;
    // One key, one encoding, so one key ID: a non-canonical encoding of a point would give the
    // same key a second ID and slip past the check for a repeated key.
    if key.to_edwards().compress().to_bytes() != bytes {
        return Err(not_a_key());
    }
    if key.is_weak() {
        return Err(KeyConfigError::SmallOrderKey(issuer.to_owned()));
    }
    Ok(key)
}

/// Whether DER bytes start as a PKCS#8 PrivateKeyInfo does: a SEQUENCE (short or long length
/// form) whose first member is an INTEGER.
fn is_private_key_info(der: &[u8]) -> bool {
    let Some((&0x30, rest)) = der.split_first() else {
        return false;
    };
    let Some((&length, rest)) = rest.split_first() else {
        return false;
    };
    let skip = if length & 0x80 == 0 {
        0
    } else {
        usize::from(length & 0x7f)
    };
    rest.get(skip) == Some(&0x02)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_info_is_told_from_a_public_key() {
        assert!(is_private_key_info(&[0x30, 0x2e, 0x02, 0x01, 0x00]));
        assert!(is_private_key_info(&[0x30, 0x81, 0x80, 0x02, 0x01]));
        assert!(!is_private_key_info(&SPKI_PREFIX));
        assert!(!is_private_key_info(&[]));
        assert!(!is_private_key_info(&[0x30]));
    }
}
