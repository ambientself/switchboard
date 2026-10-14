//! Principals and delegations: what a verifier establishes about a caller.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::names::{GroupId, Issuer, Person, PodUid, Subject, TeamId, ToolName};
use crate::proof::Claimed;
use crate::receipt::DelegationKeyScope;

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
        /// No decision reads it. A turn grant will be bound to it (#22).
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
    /// The delegation's identifying fields, which scope an idempotency key with the principal
    /// (decision 0009, "The key"): for Otto, its session and turn. `None` until the turn-grant
    /// verifier fills it from the grant's verified fields (#22), so until then a key is scoped
    /// to the principal alone.
    #[serde(default)]
    pub key_scope: Option<DelegationKeyScope>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delegation_must_list_its_tools() {
        let parse = |json: &str| serde_json::from_str::<Delegation>(json);
        let base = r#""acting_person": "requester@example.test", "team": "payments""#;
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
