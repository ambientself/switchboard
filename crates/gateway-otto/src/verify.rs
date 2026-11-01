//! The turn-grant verifier: a grant as presented in, a [`VerifiedGrant`] or a [`GrantFailure`]
//! out, in the order decision 0012 sets.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::Signature;
use gateway_core::{Claimed, DeploymentName, Person, PodUid, Principal, Proved, TeamId, ToolName};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::format::{
    CANONICAL, KeyId, LEEWAY_SECONDS, LENIENT, MAX_GRANT_BYTES, MAX_LIFETIME_SECONDS, VERSION,
    s_is_canonical, signed_bytes,
};
use crate::keys::{GrantKeys, IssuerName};
use crate::tools::ToolMapping;

/// Which check a grant failed: the kinds design section 11 counts. Closed: nothing else is a
/// reason a grant fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FailureKind {
    /// The first part is not this format's version.
    Version,
    /// The key ID names no configured key.
    UnknownKey,
    /// The key ID names a previous key whose end instant has passed.
    RetiredKey,
    /// A part is not canonical unpadded base64url, the signature is not 64 bytes, or its S is
    /// not below the group order.
    Encoding,
    /// The signature does not verify under the key.
    Signature,
    /// The grant is not four parts, is too long, or its claims are not what the format
    /// requires.
    Malformed,
    /// `exp` is not after now minus the leeway.
    Expired,
    /// `iat` is later than now plus the leeway.
    NotYetValid,
    /// `exp − iat` is over the ceiling.
    LifetimeOverCeiling,
    /// `aud` does not include this deployment.
    WrongAudience,
    /// `pod` is required for the issuer and does not equal the caller's proved pod UID.
    WrongPod,
}

impl FailureKind {
    /// Every kind, in the order of the checks.
    pub const ALL: [FailureKind; 11] = [
        FailureKind::Version,
        FailureKind::UnknownKey,
        FailureKind::RetiredKey,
        FailureKind::Encoding,
        FailureKind::Signature,
        FailureKind::Malformed,
        FailureKind::WrongAudience,
        FailureKind::NotYetValid,
        FailureKind::Expired,
        FailureKind::LifetimeOverCeiling,
        FailureKind::WrongPod,
    ];

    /// The kind's name, for a log line or a counter's label: the name the audit row records
    /// for the core's failure of the same kind.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::Version => "version",
            FailureKind::UnknownKey => "unknown_key",
            FailureKind::RetiredKey => "retired_key",
            FailureKind::Encoding => "encoding",
            FailureKind::Signature => "signature",
            FailureKind::Malformed => "malformed",
            FailureKind::Expired => "expired",
            FailureKind::NotYetValid => "not_yet_valid",
            FailureKind::LifetimeOverCeiling => "lifetime_over_ceiling",
            FailureKind::WrongAudience => "wrong_audience",
            FailureKind::WrongPod => "wrong_pod",
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The SHA-256 of a grant as presented. Strict encoding makes it one value per grant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantDigest([u8; 32]);

impl GrantDigest {
    /// The digest of `grant`, exactly as presented.
    pub fn of(grant: &[u8]) -> Self {
        Self(Sha256::digest(grant).into())
    }

    /// The digest's bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for GrantDigest {
    /// Lowercase hexadecimal, 64 characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for GrantDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantDigest({self})")
    }
}

/// Why a grant was not verified: which check failed and, only for a binding's failure (the
/// audience, the lifetime or the pod), its digest. Nothing from the grant's claims, so neither
/// its Debug nor its Display can show any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("turn grant refused: {kind}")]
pub struct GrantFailure {
    kind: FailureKind,
    digest: Option<GrantDigest>,
}

impl GrantFailure {
    /// Which check failed.
    pub fn kind(&self) -> FailureKind {
        self.kind
    }

    /// The grant's digest, for a binding's failure; `None` for any other. A grant refused for
    /// its encoding or its claims' shape has no digest though its signature verified: decision
    /// 0012 records a digest only once the signature verified and a binding then failed.
    pub fn digest(&self) -> Option<GrantDigest> {
        self.digest
    }
}

/// The turn's egress setting (decision 0010): sealed, or open through Otto's proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Egress {
    /// The turn has no egress.
    Sealed,
    /// The turn's egress is open through Otto's proxy.
    Open,
}

/// A grant that passed every check. Only the verifier makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    issuer: IssuerName,
    key_id: KeyId,
    digest: GrantDigest,
    team: TeamId,
    tools: BTreeSet<ToolName>,
    epoch: u64,
    session: String,
    turn: String,
    execution: String,
    actor: Claimed<Person>,
    pod: Option<PodUid>,
    egress: Option<Egress>,
}

impl VerifiedGrant {
    /// The issuer whose key verified the grant.
    pub fn issuer(&self) -> &IssuerName {
        &self.issuer
    }
    /// The ID of the key that verified it.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    /// The grant's digest.
    pub fn digest(&self) -> GrantDigest {
        self.digest
    }
    /// The team the turn runs for (`team`). Check 3 compares it with the proved team.
    pub fn team(&self) -> &TeamId {
        &self.team
    }
    /// The grant's tools under this gateway's names, with every name the mapping lacks
    /// dropped. What check 4 sees.
    pub fn tools(&self) -> &BTreeSet<ToolName> {
        &self.tools
    }
    /// The fencing epoch of the control plane that drove the turn (`epoch`).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The session (`sid`).
    pub fn session(&self) -> &str {
        &self.session
    }
    /// The turn (`tid`).
    pub fn turn(&self) -> &str {
        &self.turn
    }
    /// The execution (`eid`).
    pub fn execution(&self) -> &str {
        &self.execution
    }
    /// The acting human (`actor`): what the control plane attests, not proof that they acted.
    pub fn actor(&self) -> &Claimed<Person> {
        &self.actor
    }
    /// The sandbox pod's UID (`pod`), if the grant carries one. Equal to the caller's proved
    /// pod UID when the issuer requires it.
    pub fn pod(&self) -> Option<&PodUid> {
        self.pod.as_ref()
    }
    /// The turn's egress setting (`egress`), if the grant carries one.
    pub fn egress(&self) -> Option<Egress> {
        self.egress
    }
}

/// The turn-grant verifier for one deployment.
#[derive(Clone, Debug)]
pub struct GrantVerifier {
    keys: GrantKeys,
    deployment: DeploymentName,
    tools: ToolMapping,
}

impl GrantVerifier {
    /// A verifier for grants presented at `deployment`, under `keys`, mapping tool names with
    /// `tools`.
    pub fn new(keys: GrantKeys, deployment: DeploymentName, tools: ToolMapping) -> Self {
        Self {
            keys,
            deployment,
            tools,
        }
    }

    /// Verifies `grant`, exactly as presented, for a call from `caller` at `now`.
    ///
    /// The checks run in decision 0012's order, and the first that fails is the answer: the
    /// version, before anything else is read; the key ID; the signature, before the claims are
    /// decoded; canonical encoding; the claims' shape; then the bindings. The clock is `now`, never read here.
    pub fn verify(
        &self,
        grant: &[u8],
        caller: &Proved<Principal>,
        now: SystemTime,
    ) -> Result<VerifiedGrant, GrantFailure> {
        let refuse = |kind| GrantFailure { kind, digest: None };

        // 1. The version.
        let version = grant.split(|byte| *byte == b'.').next().unwrap_or_default();
        if version != VERSION.as_bytes() {
            return Err(refuse(FailureKind::Version));
        }
        if grant.len() > MAX_GRANT_BYTES {
            return Err(refuse(FailureKind::Malformed));
        }
        let parts: Vec<&[u8]> = grant.split(|byte| *byte == b'.').collect();
        let [version, key_id, claims, signature] = parts[..] else {
            return Err(refuse(FailureKind::Malformed));
        };

        // 2. The key ID: a configured key, not retired. Configured IDs are canonical, so one
        // that is not cannot match.
        let (key_id, key) = std::str::from_utf8(key_id)
            .ok()
            .and_then(|id| self.keys.keys.get_key_value(id))
            .ok_or(refuse(FailureKind::UnknownKey))?;
        if key.retires_at.is_some_and(|retires_at| now >= retires_at) {
            return Err(refuse(FailureKind::RetiredKey));
        }

        // 3. The signature, before the claims are decoded.
        let signature_bytes: [u8; 64] = LENIENT
            .decode(signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(refuse(FailureKind::Encoding))?;
        if !s_is_canonical(&signature_bytes) {
            return Err(refuse(FailureKind::Encoding));
        }
        key.key
            .verify_strict(
                &signed_bytes(version, key_id.as_str().as_bytes(), claims),
                &Signature::from_bytes(&signature_bytes),
            )
            .map_err(|_| refuse(FailureKind::Signature))?;

        // From here the signature verified. Only a binding's failure, once the claims are read,
        // carries the digest; canonical encoding and the claims' shape are refused with nothing
        // of the grant, as the checks before the signature are.
        let digest = GrantDigest::of(grant);
        let bind = |kind| GrantFailure {
            kind,
            digest: Some(digest),
        };

        // 4. Canonical encoding: each decoded part re-encodes to the bytes presented.
        let claims_bytes = LENIENT
            .decode(claims)
            .map_err(|_| refuse(FailureKind::Encoding))?;
        if CANONICAL.encode(signature_bytes).as_bytes() != signature
            || CANONICAL.encode(&claims_bytes).as_bytes() != claims
        {
            return Err(refuse(FailureKind::Encoding));
        }

        // 5. The claims' shape.
        let issuer = &self.keys.issuers[key.issuer];
        let claims = Claims::parse(&claims_bytes, issuer.require_pod, issuer.require_egress)
            .ok_or(refuse(FailureKind::Malformed))?;

        // 6. The bindings: the audience, the lifetime and the pod.
        if !claims.aud.iter().any(|aud| aud == self.deployment.as_str()) {
            return Err(bind(FailureKind::WrongAudience));
        }
        let now = unix_seconds(now);
        if i128::from(claims.iat) > now + i128::from(LEEWAY_SECONDS) {
            return Err(bind(FailureKind::NotYetValid));
        }
        if i128::from(claims.exp) <= now - i128::from(LEEWAY_SECONDS) {
            return Err(bind(FailureKind::Expired));
        }
        if i128::from(claims.exp) - i128::from(claims.iat) > i128::from(MAX_LIFETIME_SECONDS) {
            return Err(bind(FailureKind::LifetimeOverCeiling));
        }
        if issuer.require_pod && claims.pod.as_ref() != caller.get().pod() {
            return Err(bind(FailureKind::WrongPod));
        }

        Ok(VerifiedGrant {
            issuer: issuer.name.clone(),
            key_id: key_id.clone(),
            digest,
            team: TeamId::new(claims.team),
            tools: self.tools.map(claims.tools.iter().map(String::as_str)),
            epoch: claims.epoch,
            session: claims.sid,
            turn: claims.tid,
            execution: claims.eid,
            actor: Claimed::new(Person::new(claims.actor)),
            pod: claims.pod,
            egress: claims.egress,
        })
    }
}

/// Whole seconds since the Unix epoch. A clock before the epoch reads as the epoch, so every
/// grant issued after it is not yet valid: a broken clock refuses grants rather than admitting
/// them.
fn unix_seconds(now: SystemTime) -> i128 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i128::from(elapsed.as_secs()))
}

/// The claims of a grant whose signature verified, checked for shape.
struct Claims {
    aud: Vec<String>,
    iat: i64,
    exp: i64,
    team: String,
    tools: Vec<String>,
    epoch: u64,
    sid: String,
    tid: String,
    eid: String,
    actor: String,
    pod: Option<PodUid>,
    egress: Option<Egress>,
}

/// The claims as JSON gives them. Every member is optional here so that a missing one and a
/// mistyped one are both refused by [`Claims::parse`], and none may be `null`. A member this
/// format names may not appear twice; any other member is ignored.
#[derive(Deserialize)]
struct Wire {
    #[serde(default, deserialize_with = "present")]
    aud: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    iat: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    exp: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    team: Option<String>,
    #[serde(default, deserialize_with = "present")]
    tools: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    epoch: Option<i64>,
    #[serde(default, deserialize_with = "present")]
    sid: Option<String>,
    #[serde(default, deserialize_with = "present")]
    tid: Option<String>,
    #[serde(default, deserialize_with = "present")]
    eid: Option<String>,
    #[serde(default, deserialize_with = "present")]
    actor: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pod: Option<PodUid>,
    #[serde(default, deserialize_with = "egress_setting")]
    egress: Option<Egress>,
}

/// A member that is present is its value, never `null`. With `default`, an absent one is `None`.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// An egress setting that is present is the string `sealed` or `open`. A derived enum would
/// also read the externally tagged form, such as `{"sealed": null}`, which the format does not
/// allow.
fn egress_setting<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Egress>, D::Error> {
    match String::deserialize(deserializer)?.as_str() {
        "sealed" => Ok(Some(Egress::Sealed)),
        "open" => Ok(Some(Egress::Open)),
        other => Err(serde::de::Error::unknown_variant(
            other,
            &["sealed", "open"],
        )),
    }
}

impl Claims {
    fn parse(bytes: &[u8], require_pod: bool, require_egress: bool) -> Option<Self> {
        // The claims are a JSON object. A derived struct would also read an array of the values
        // in field order, so anything that does not open with `{` is refused before parsing.
        let opening = bytes
            .iter()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'));
        if opening != Some(&b'{') {
            return None;
        }
        let wire: Wire = serde_json::from_slice(bytes).ok()?;
        let text = |value: Option<String>| value.filter(|value| !value.is_empty());
        let tools = wire
            .tools
            .filter(|tools| !tools.is_empty() && tools.iter().all(|tool| !tool.is_empty()))?;
        let claims = Claims {
            aud: wire.aud?,
            iat: wire.iat.filter(|iat| *iat >= 0)?,
            exp: wire.exp.filter(|exp| *exp >= 0)?,
            team: text(wire.team)?,
            tools,
            epoch: wire
                .epoch
                .filter(|epoch| *epoch > 0)
                .and_then(|epoch| u64::try_from(epoch).ok())?,
            sid: text(wire.sid)?,
            tid: text(wire.tid)?,
            eid: text(wire.eid)?,
            actor: text(wire.actor)?,
            pod: wire.pod,
            egress: wire.egress,
        };
        if require_pod && claims.pod.is_none() {
            return None;
        }
        if require_egress && claims.egress.is_none() {
            return None;
        }
        Some(claims)
    }
}
