//! Principals and delegations: what a verifier establishes about a caller.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use crate::names::{GroupId, Issuer, Person, Subject, TeamId, ToolName};
use crate::proof::Claimed;

/// The key of a principal: its issuer and its subject, together.
///
/// A subject alone identifies nothing, because two issuers can use the same subject for
/// different callers. Equality, ordering and hashing all include the issuer, so a principal
/// from one cluster can never be mistaken for one from another.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    },
    /// A person, signed in through an identity provider.
    User {
        /// The groups the identity provider says the user belongs to.
        groups: BTreeSet<GroupId>,
    },
}

/// The caller as the gateway proved it: who issued the token, the subject it names, and
/// either a workload's team or a user's groups.
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
            PrincipalKind::Workload { team } => Some(team),
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
    /// The tools the delegation permits, if it narrows them. `None` narrows nothing; an empty
    /// set permits no tool at all.
    ///
    /// Required when deserialized, even though it is optional: a missing list would otherwise
    /// read as `None`, which narrows nothing, so a dropped field would widen access.
    #[serde(deserialize_with = "present")]
    pub tools: Option<BTreeSet<ToolName>>,
}

/// Deserializes an `Option` that must be written out, as `null` or a value. Naming a
/// `deserialize_with` function is what stops serde treating a missing `Option` as `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delegation_must_say_whether_it_narrows_tools() {
        let parse = |json: &str| serde_json::from_str::<Delegation>(json);
        let base = r#""acting_person": "requester@example.test", "team": "payments""#;
        assert!(
            parse(&format!("{{{base}}}")).is_err(),
            "a missing tool list was accepted"
        );
        let unlimited = parse(&format!(r#"{{{base}, "tools": null}}"#)).ok();
        assert_eq!(unlimited.map(|delegation| delegation.tools), Some(None));
        let narrowed = parse(&format!(r#"{{{base}, "tools": []}}"#)).ok();
        assert_eq!(
            narrowed.map(|delegation| delegation.tools),
            Some(Some(BTreeSet::new()))
        );
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
