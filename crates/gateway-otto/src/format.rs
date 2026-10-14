//! The `v3` turn-grant format: its constants, the key ID, the bytes a signature covers, and the
//! two base64url engines. [docs/turn-grant-format.md] is the specification; this module and it
//! must agree, and `tests/format_doc.rs` checks the document's example against this code.
//!
//! [docs/turn-grant-format.md]: https://github.com/ambientself/switchboard/blob/main/docs/turn-grant-format.md

use std::borrow::Borrow;
use std::fmt;

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use sha2::{Digest, Sha256};

/// The format version: the first part of every grant. Neither Otto's `v1` HMAC grants nor its
/// model broker's `v2` tokens.
pub const VERSION: &str = "v3";

/// The domain prefix of the bytes a grant's signature covers. It ends in a NUL byte.
pub const SIGNING_DOMAIN: &[u8] = b"otto/gateway-turn-grant/v3\0";

/// The domain prefix of the bytes a key ID is the hash of. It ends in a NUL byte.
pub const KEY_ID_DOMAIN: &[u8] = b"otto/gateway-turn-grant/kid/v3\0";

/// How many bytes of the SHA-256 a key ID keeps.
pub const KEY_ID_BYTES: usize = 16;

/// The longest grant verified, in bytes, as presented. Longer is refused as malformed.
pub const MAX_GRANT_BYTES: usize = 8192;

/// Clock leeway, in seconds, on `iat` and `exp`: what Otto's gateway allows on ServiceAccount
/// tokens (decision 0012).
pub const LEEWAY_SECONDS: i64 = 30;

/// The most `exp − iat` may be, in seconds: 15 minutes, Otto's default execution timeout
/// (decision 0012). Raised here before Otto raises its timeouts past it.
pub const MAX_LIFETIME_SECONDS: i64 = 15 * 60;

/// The HTTP header a grant is sent in.
pub const HEADER: &str = "X-Otto-Turn-Grant";

/// Canonical unpadded base64url: what every part is encoded with, and what a decoded part must
/// re-encode to.
pub(crate) const CANONICAL: GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Base64url that accepts padding and non-zero trailing bits. Parts are decoded with this, and
/// the canonical-encoding check then requires each to re-encode to the bytes presented. The
/// check is one place, in the decision's order (after the signature), and not spread across
/// decoders.
pub(crate) const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// A key's ID: the first [`KEY_ID_BYTES`] bytes of SHA-256 over [`KEY_ID_DOMAIN`] and the
/// 32-byte public key, in canonical unpadded base64url (22 characters).
///
/// Derived from the key, so a key cannot be filed under the wrong ID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// The key ID of an Ed25519 public key, given as its 32 bytes.
    pub fn of(public_key: &[u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(KEY_ID_DOMAIN);
        hash.update(public_key);
        let digest = hash.finalize();
        Self(CANONICAL.encode(&digest[..KEY_ID_BYTES]))
    }

    /// The ID as it appears in a grant.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Lets the verifier look a grant's key ID up without allocating. `KeyId` orders, compares and
// hashes exactly as its string does, as `Borrow` requires.
impl Borrow<str> for KeyId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

/// The bytes a grant's signature covers: [`SIGNING_DOMAIN`], then the version, key ID and
/// encoded claims as they appear in the grant, joined by `.`.
pub fn signed_bytes(version: &[u8], key_id: &[u8], claims: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(SIGNING_DOMAIN.len() + version.len() + key_id.len() + claims.len() + 2);
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(version);
    message.push(b'.');
    message.extend_from_slice(key_id);
    message.push(b'.');
    message.extend_from_slice(claims);
    message
}

/// The order of the Ed25519 group, ℓ = 2^252 + 27742317777372353535851937790883648493, in
/// little-endian bytes.
pub(crate) const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Whether a signature's S, its last 32 bytes read as a little-endian integer, is below the
/// group order. `ed25519-dalek` refuses a larger S too, unless something in the build turns on
/// its `legacy_compatibility` feature; this check does not depend on that, and reports the
/// signature as non-canonical rather than as a bad signature.
pub(crate) fn s_is_canonical(signature: &[u8; 64]) -> bool {
    for index in (0..32).rev() {
        let byte = signature[32 + index];
        if byte != GROUP_ORDER[index] {
            return byte < GROUP_ORDER[index];
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_s(s: [u8; 32]) -> [u8; 64] {
        let mut signature = [0; 64];
        signature[32..].copy_from_slice(&s);
        signature
    }

    #[test]
    fn s_must_be_below_the_group_order() {
        let mut below = GROUP_ORDER;
        below[0] -= 1;
        assert!(s_is_canonical(&with_s(below)));
        assert!(s_is_canonical(&with_s([0; 32])));
        assert!(!s_is_canonical(&with_s(GROUP_ORDER)));
        let mut above = GROUP_ORDER;
        above[0] += 1;
        assert!(!s_is_canonical(&with_s(above)));
        assert!(!s_is_canonical(&with_s([0xff; 32])));
        // Only the high bytes differ: the comparison runs from the most significant byte.
        let mut high = [0; 32];
        high[31] = 0x0f;
        high[0] = 0xff;
        assert!(s_is_canonical(&with_s(high)));
    }

    #[test]
    fn a_key_id_is_22_canonical_characters() {
        let id = KeyId::of(&[7; 32]);
        assert_eq!(id.as_str().len(), 22);
        assert_ne!(id, KeyId::of(&[8; 32]));
        let decoded = CANONICAL.decode(id.as_str()).unwrap();
        assert_eq!(CANONICAL.encode(decoded), id.as_str());
    }
}
