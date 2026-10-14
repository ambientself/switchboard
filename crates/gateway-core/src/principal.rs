//! Principals and delegations: what a verifier establishes about a caller.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::names::{
    DelegationIssuer, ExecutionId, GroupId, Issuer, KeyId, Person, PodUid, SessionId, Subject,
    TeamId, ToolName, TurnId,
};
use crate::proof::{Claimed, Proved};
use crate::receipt::{DelegationKeyScope, sha256_from_hex, sha256_to_hex};

/// The key of a principal: its issuer and its subject, together.
///
/// A subject alone identifies nothing, because two issuers can use the same subject for
/// different callers. Equality, ordering and hashing all include the issuer, so a principal
/// from one cluster can never be mistaken for one from another.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalId {
    /// The issuer that vouched for the subject.
    pub issuer: Issuer,
    /// The subject, as that issuer names it.
    pub subject: Subject,
}

/// What kind of caller a principal is, and the facts that come with that kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PrincipalKind {
    /// A workload, such as a service account, mapped to one team by the team manifest.
    Workload {
        /// The team the manifest maps this workload to.
        team: TeamId,
        /// The UID of the pod the workload runs in, when its token proves one: a Kubernetes
        /// projected ServiceAccount token names its pod in its signed `kubernetes.io` claim
        /// (decision 0012). `None` for a token that names no pod.
        ///
        /// No decision reads it, and the audit row records it. A turn grant will be bound to it
        /// by the turn-grant verifier, before the decision (#22).
        ///
        /// Absent in JSON is `None`; present, it must be a pod UID, and `null` is refused.
        #[serde(
            default,
            deserialize_with = "present_pod",
            skip_serializing_if = "Option::is_none"
        )]
        pod: Option<PodUid>,
    },
    /// A person, signed in through an identity provider.
    User {
        /// The groups the identity provider says the user belongs to.
        groups: BTreeSet<GroupId>,
    },
}

/// A pod that is present in JSON: a pod UID, never `null`. With `default`, an absent pod is
/// `None`.
fn present_pod<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PodUid>, D::Error> {
    PodUid::deserialize(deserializer).map(Some)
}

/// The caller as the gateway proved it: who issued the token, the subject it names, and
/// either a workload's team, with its pod when the token proves one, or a user's groups.
///
/// A `Principal` on its own is only a description. It becomes something policy may act on
/// once it is wrapped in [`Proved`](crate::Proved), which only a verifier can do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// The issuer and subject that identify this principal.
    pub id: PrincipalId,
    /// Whether this is a workload or a user, with the facts each carries.
    #[serde(flatten)]
    pub kind: PrincipalKind,
}

impl Principal {
    /// The workload's team, or `None` for a user.
    pub fn team(&self) -> Option<&TeamId> {
        match &self.kind {
            PrincipalKind::Workload { team, .. } => Some(team),
            PrincipalKind::User { .. } => None,
        }
    }

    /// The workload's pod UID, if its token proves one; `None` for a user.
    pub fn pod(&self) -> Option<&PodUid> {
        match &self.kind {
            PrincipalKind::Workload { pod, .. } => pod.as_ref(),
            PrincipalKind::User { .. } => None,
        }
    }

    /// The user's groups; empty for a workload.
    pub fn groups(&self) -> impl Iterator<Item = &GroupId> {
        let groups = match &self.kind {
            PrincipalKind::Workload { .. } => None,
            PrincipalKind::User { groups } => Some(groups),
        };
        groups.into_iter().flatten()
    }
}

/// A verified statement that the principal is acting for someone, such as Otto's turn grant.
///
/// The statement is verified, so a delegation is held as `Proved<Delegation>`. The person it
/// names is not: the control plane that signed it attests to the person, which is not proof
/// that the person acted, so the person stays a [`Claimed`] value inside it and is recorded in
/// the claimed columns of the audit record.
///
/// Besides the person, the team and the tools, which the decision function reads, a delegation
/// carries what identifies it on the audit row (decision 0012): its issuer, digest and key, the
/// session, turn and execution it was issued for, the epoch of the control plane that issued
/// it, and the turn's egress setting. The decision function reads none of these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// The person the principal is acting for.
    pub acting_person: Claimed<Person>,
    /// The team the delegation was issued for. It must agree with the principal's team.
    pub team: TeamId,
    /// The tools the delegation permits. Always present, so a delegation always narrows: there
    /// is no value that means "every tool on the surface", and an empty set permits no tool at
    /// all (decision 0006, check 4).
    pub tools: BTreeSet<ToolName>,
    /// The issuer whose key verified the delegation's signature, by the name configuration
    /// gives that key.
    pub issuer: DelegationIssuer,
    /// The SHA-256 of the delegation as presented, which strict encoding makes one value per
    /// delegation, so that rows can be matched on it.
    pub digest: DelegationDigest,
    /// The key the signature verified under.
    pub key_id: KeyId,
    /// The session the delegation was issued in.
    pub session: SessionId,
    /// The turn the delegation was issued for.
    pub turn: TurnId,
    /// The execution the turn belongs to.
    pub execution: ExecutionId,
    /// The fencing epoch of the control plane that issued the delegation. The currency check
    /// relies on the issuing control plane to say whether it still holds (decision 0012,
    /// "Currency"); the core only records it.
    pub epoch: u64,
    /// The turn's egress setting, when the delegation carries one. It is recorded, and no check
    /// decides on it (decision 0012, "The egress setting is recorded, not enforced").
    #[serde(default)]
    pub egress: Option<Egress>,
}

impl Delegation {
    /// The delegation's identifying fields, which scope an idempotency key with the principal
    /// (decision 0009, "The key"): its session, execution and turn, as decision 0009's Still
    /// open 8 recommends. Provisional: which of a grant's fields scope a key is for Otto's
    /// owners to agree, and this changes if they choose otherwise.
    ///
    /// Written as a JSON array of the three, so two different sets of fields never give the
    /// same scope.
    pub fn key_scope(&self) -> DelegationKeyScope {
        let fields = [
            self.session.as_str(),
            self.execution.as_str(),
            self.turn.as_str(),
        ];
        DelegationKeyScope::new(serde_json::Value::from(fields.to_vec()).to_string())
    }
}

/// The SHA-256 of a delegation as it was presented: for a turn grant, of the grant's bytes.
/// Written as 64 lowercase hex digits.
///
/// Not a claim: it says which delegation was presented, not anything the delegation says, so a
/// row may record it for a delegation whose signature verified and whose bindings did not
/// (decision 0012, "Failures").
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DelegationDigest([u8; 32]);

/// A string that is not 64 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("not a delegation digest: a digest is 64 lowercase hex digits")]
pub struct InvalidDelegationDigest;

impl DelegationDigest {
    /// The digest of `presented`, the delegation's bytes exactly as the request carried them.
    pub fn of(presented: &[u8]) -> Self {
        Self(Sha256::digest(presented).into())
    }

    /// Reads a digest written as 64 lowercase hex digits.
    pub fn parse(value: &str) -> Result<Self, InvalidDelegationDigest> {
        sha256_from_hex(value)
            .map(Self)
            .ok_or(InvalidDelegationDigest)
    }

    /// The digest as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        sha256_to_hex(&self.0)
    }
}

impl fmt::Debug for DelegationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DelegationDigest({})", self.to_hex())
    }
}

impl TryFrom<String> for DelegationDigest {
    type Error = InvalidDelegationDigest;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DelegationDigest> for String {
    fn from(digest: DelegationDigest) -> Self {
        digest.to_hex()
    }
}

/// A turn's egress setting (decision 0010): sealed, or open through the issuing platform's
/// proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Egress {
    /// The turn has no network egress but the governed path.
    Sealed,
    /// The turn's egress is open, through the platform's proxy.
    Open,
}

impl Egress {
    /// The setting's name, as the audit row records it.
    pub fn as_str(self) -> &'static str {
        match self {
            Egress::Sealed => "sealed",
            Egress::Open => "open",
        }
    }
}

/// Which of the delegation verifier's checks a delegation failed (decision 0012, "Failures").
///
/// A closed set, which an adapter's verifier maps its own failures into, so the core depends on
/// nothing a verifier defines. It is recorded on the audit row, logged and counted, and never
/// returned to the caller: check 3 denies every failure with one sentence. It is not a reason
/// kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationFailure {
    /// The format version is not the one this gateway verifies.
    Version,
    /// The key the delegation names is not configured.
    UnknownKey,
    /// The key the delegation names was retired at its end instant.
    RetiredKey,
    /// A part is not in the canonical encoding.
    Encoding,
    /// The signature does not verify.
    Signature,
    /// The signature verified, and the claims are not well formed: a field missing or empty,
    /// or of the wrong type.
    Malformed,
    /// The delegation expired.
    Expired,
    /// The delegation was issued later than now, beyond the leeway.
    NotYetValid,
    /// The delegation's lifetime is longer than the ceiling.
    LifetimeOverCeiling,
    /// The delegation is not for the deployment that received the call.
    WrongAudience,
    /// The delegation is bound to another pod than the one the caller proved.
    WrongPod,
}

impl DelegationFailure {
    /// Every failure.
    pub const ALL: [DelegationFailure; 11] = [
        DelegationFailure::Version,
        DelegationFailure::UnknownKey,
        DelegationFailure::RetiredKey,
        DelegationFailure::Encoding,
        DelegationFailure::Signature,
        DelegationFailure::Malformed,
        DelegationFailure::Expired,
        DelegationFailure::NotYetValid,
        DelegationFailure::LifetimeOverCeiling,
        DelegationFailure::WrongAudience,
        DelegationFailure::WrongPod,
    ];

    /// The failure's name, as the audit row records it.
    pub fn as_str(self) -> &'static str {
        match self {
            DelegationFailure::Version => "version",
            DelegationFailure::UnknownKey => "unknown_key",
            DelegationFailure::RetiredKey => "retired_key",
            DelegationFailure::Encoding => "encoding",
            DelegationFailure::Signature => "signature",
            DelegationFailure::Malformed => "malformed",
            DelegationFailure::Expired => "expired",
            DelegationFailure::NotYetValid => "not_yet_valid",
            DelegationFailure::LifetimeOverCeiling => "lifetime_over_ceiling",
            DelegationFailure::WrongAudience => "wrong_audience",
            DelegationFailure::WrongPod => "wrong_pod",
        }
    }

    /// Whether the failure is of a binding, found only once the signature verified: the
    /// audience, the lifetime or the pod. Only such a failure may carry the delegation's
    /// digest (decision 0012, "Failures").
    pub fn follows_signature(self) -> bool {
        matches!(
            self,
            DelegationFailure::Expired
                | DelegationFailure::NotYetValid
                | DelegationFailure::LifetimeOverCeiling
                | DelegationFailure::WrongAudience
                | DelegationFailure::WrongPod
        )
    }
}

impl fmt::Display for DelegationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A delegation the request carried that did not verify (decisions 0009 and 0012): which check
/// it failed and, only when its signature verified, its digest. It carries nothing from the
/// delegation's claims, so nothing from them can reach a decision, a sentence, a row or a log
/// line through it.
///
/// The verifier passes one on rather than refusing the request, and check 3 denies it, so that
/// one place decides and a deny row is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedDelegation {
    failure: DelegationFailure,
    digest: Option<DelegationDigest>,
}

/// A digest offered with a failure found before the delegation's signature verified.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("a delegation that failed `{0}` has no verified signature, so it has no digest to record")]
pub struct DigestBeforeSignature(pub DelegationFailure);

impl UnverifiedDelegation {
    /// A delegation that failed `failure`, recorded with no digest.
    pub fn new(failure: DelegationFailure) -> Self {
        Self {
            failure,
            digest: None,
        }
    }

    /// A delegation whose signature verified and which then failed `failure`, a binding, with
    /// its digest. Refused for a failure found before the signature verified, which has no
    /// digest to record: see [`DelegationFailure::follows_signature`].
    pub fn after_signature(
        failure: DelegationFailure,
        digest: DelegationDigest,
    ) -> Result<Self, DigestBeforeSignature> {
        if !failure.follows_signature() {
            return Err(DigestBeforeSignature(failure));
        }
        Ok(Self {
            failure,
            digest: Some(digest),
        })
    }

    /// Which check the delegation failed.
    pub fn failure(&self) -> DelegationFailure {
        self.failure
    }

    /// The delegation's digest, set only when its signature verified.
    pub fn digest(&self) -> Option<&DelegationDigest> {
        self.digest.as_ref()
    }
}

/// A delegation the request carried: verified, or not. The call context holds an
/// `Option<PresentedDelegation>`, so a delegation is absent, present and verified, or present
/// and unverified (decision 0006, amended on 2026-10-07).
// One is made per call, and a verified delegation is the usual case, so boxing it would add an
// allocation to most calls to save space on the rarer one.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentedDelegation {
    /// The delegation verified.
    Verified(Proved<Delegation>),
    /// The delegation did not verify. Check 3 denies it.
    Unverified(UnverifiedDelegation),
}

impl PresentedDelegation {
    /// The delegation, if it verified.
    pub fn verified(&self) -> Option<&Proved<Delegation>> {
        match self {
            PresentedDelegation::Verified(delegation) => Some(delegation),
            PresentedDelegation::Unverified(_) => None,
        }
    }

    /// What failed, if it did not verify.
    pub fn unverified(&self) -> Option<&UnverifiedDelegation> {
        match self {
            PresentedDelegation::Verified(_) => None,
            PresentedDelegation::Unverified(unverified) => Some(unverified),
        }
    }
}

impl From<Proved<Delegation>> for PresentedDelegation {
    fn from(delegation: Proved<Delegation>) -> Self {
        PresentedDelegation::Verified(delegation)
    }
}

impl From<UnverifiedDelegation> for PresentedDelegation {
    fn from(unverified: UnverifiedDelegation) -> Self {
        PresentedDelegation::Unverified(unverified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn a_delegation_must_list_its_tools() {
        let parse = |json: &str| serde_json::from_str::<Delegation>(json);
        let base = format!(
            r#""acting_person": "requester@example.test", "team": "payments", "issuer": "otto-test", "digest": "{DIGEST}", "key_id": "key-1", "session": "s", "turn": "t", "execution": "e", "epoch": 1"#
        );
        assert!(
            parse(&format!("{{{base}}}")).is_err(),
            "a missing tool list was accepted"
        );
        assert!(
            parse(&format!(r#"{{{base}, "tools": null}}"#)).is_err(),
            "a null tool list was accepted"
        );
        let empty = parse(&format!(r#"{{{base}, "tools": []}}"#)).ok();
        assert_eq!(
            empty.map(|delegation| delegation.tools),
            Some(BTreeSet::new())
        );
    }

    fn delegation(session: &str, execution: &str, turn: &str) -> Delegation {
        Delegation {
            acting_person: Claimed::new("requester@example.test".into()),
            team: "payments".into(),
            tools: BTreeSet::new(),
            issuer: "otto-test".into(),
            digest: DelegationDigest::of(b"grant"),
            key_id: "key-1".into(),
            session: session.into(),
            turn: turn.into(),
            execution: execution.into(),
            epoch: 1,
            egress: None,
        }
    }

    #[test]
    fn a_key_scope_tells_every_session_execution_and_turn_apart() {
        let scope = |session, execution, turn| delegation(session, execution, turn).key_scope();
        assert_eq!(scope("s", "e", "t").as_str(), r#"["s","e","t"]"#);
        assert_eq!(scope("s", "e", "t"), scope("s", "e", "t"));
        // A separator inside one field cannot make two sets of fields alike.
        assert_ne!(scope("s\",\"e", "x", "t"), scope("s", "e\",\"x", "t"));
        assert_ne!(scope("s", "e", "t"), scope("s", "e", "u"));
        assert_ne!(scope("s", "e", "t"), scope("s", "f", "t"));
        assert_ne!(scope("s", "e", "t"), scope("r", "e", "t"));
    }

    #[test]
    fn a_digest_is_sha256_written_in_lowercase_hex() {
        let digest = DelegationDigest::of(b"test");
        assert_eq!(digest.to_hex(), DIGEST);
        assert_eq!(DelegationDigest::parse(DIGEST), Ok(digest));
        assert_eq!(serde_json::to_value(digest).unwrap(), DIGEST);
        let long = format!("{DIGEST}0");
        for malformed in [&DIGEST.to_uppercase(), &DIGEST[1..], "", &long] {
            assert!(DelegationDigest::parse(malformed).is_err(), "{malformed}");
        }
    }

    /// Only a binding, found once the signature verified, carries the delegation's digest
    /// (decision 0012, "Failures").
    #[test]
    fn only_a_failure_after_the_signature_carries_a_digest() {
        let digest = DelegationDigest::of(b"grant");
        let after: Vec<DelegationFailure> = DelegationFailure::ALL
            .into_iter()
            .filter(|failure| failure.follows_signature())
            .collect();
        assert_eq!(
            after,
            [
                DelegationFailure::Expired,
                DelegationFailure::NotYetValid,
                DelegationFailure::LifetimeOverCeiling,
                DelegationFailure::WrongAudience,
                DelegationFailure::WrongPod,
            ]
        );
        for failure in DelegationFailure::ALL {
            let unverified = UnverifiedDelegation::after_signature(failure, digest);
            if failure.follows_signature() {
                assert_eq!(unverified.unwrap().digest(), Some(&digest), "{failure}");
            } else {
                assert_eq!(unverified, Err(DigestBeforeSignature(failure)));
            }
            let plain = UnverifiedDelegation::new(failure);
            assert_eq!((plain.failure(), plain.digest()), (failure, None));
        }
    }

    #[test]
    fn a_failure_and_an_egress_setting_are_written_as_their_names() {
        for failure in DelegationFailure::ALL {
            assert_eq!(serde_json::to_value(failure).unwrap(), failure.as_str());
        }
        for egress in [Egress::Sealed, Egress::Open] {
            assert_eq!(serde_json::to_value(egress).unwrap(), egress.as_str());
        }
    }

    #[test]
    fn a_workload_without_a_pod_reads_and_writes_as_before() {
        let json = r#"{"id": {"issuer": "https://cluster.example.test", "subject": "sa"}, "kind": "workload", "team": "payments"}"#;
        let principal: Principal = serde_json::from_str(json).unwrap();
        assert_eq!(
            principal.kind,
            PrincipalKind::Workload {
                team: "payments".into(),
                pod: None
            }
        );
        assert_eq!(principal.pod(), None);
        let written = serde_json::to_value(&principal).unwrap();
        assert_eq!(written.get("pod"), None, "{written}");
    }

    #[test]
    fn a_pod_in_json_must_be_a_pod_uid() {
        let parse = |pod: &str| {
            serde_json::from_str::<Principal>(&format!(
                r#"{{"id": {{"issuer": "https://cluster.example.test", "subject": "sa"}}, "kind": "workload", "team": "payments", "pod": {pod}}}"#
            ))
        };
        let uid = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let principal = parse(&format!(r#""{uid}""#)).unwrap();
        assert_eq!(principal.pod().map(PodUid::as_str), Some(uid));
        let written = serde_json::to_value(&principal).unwrap();
        assert_eq!(written["pod"], uid);
        for malformed in [
            r#""0F8FAD5B-D9CB-469F-A165-70867728950E""#,
            r#""""#,
            r#""pod-name""#,
            "7",
            "null",
            r#"{"uid": "0f8fad5b-d9cb-469f-a165-70867728950e"}"#,
        ] {
            assert!(
                parse(malformed).is_err(),
                "a pod of {malformed} was accepted"
            );
        }
    }

    #[test]
    fn a_user_has_no_pod() {
        let user = Principal {
            id: PrincipalId {
                issuer: "https://idp.example.test".into(),
                subject: "person@example.test".into(),
            },
            kind: PrincipalKind::User {
                groups: BTreeSet::new(),
            },
        };
        assert_eq!(user.pod(), None);
    }

    #[test]
    fn principals_compare_by_issuer_as_well_as_subject() {
        let id = |issuer: &str| PrincipalId {
            issuer: issuer.into(),
            subject: "system:serviceaccount:otto:sandbox".into(),
        };
        assert_ne!(
            id("https://cluster-a.example.test"),
            id("https://cluster-b.example.test")
        );
    }
}
