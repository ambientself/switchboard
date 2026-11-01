//! Reconciliation of `unknown` receipts (decision 0009, "Reconciliation"): how a tool's approval
//! says an `unknown` receipt is settled, the vendor target a lookup looks in, what a lookup
//! answers and what that answer settles, and the interfaces a lookup and a store implement.
//!
//! Reconciliation only looks. A [`Lookup`] finds the effect by the marker the gateway attached
//! to the request, the receipt's identifier, and never sends anything that could cause one. It
//! is not a tool call and writes no audit row. What it answers moves a receipt only as
//! [`LookupAnswer::settles`] says: a found effect settles it `completed` with the vendor's
//! reference, and a search that finds nothing settles it `not_performed` only when the vendor
//! documents that search as complete and current. Any other answer is recorded on the receipt
//! and leaves it `unknown`, for the next attempt.
//!
//! A [`ReceiptQueue`] is the store's side: the receipts due a lookup, a short lease that one
//! instance claims a receipt with, committed before any lookup is made and counted against the
//! receipt's attempts, the lookups made, appended and never changed, and the hand-off to a
//! person once the attempts are used up or when there is nothing to look in. A receipt handed
//! to a person stays `unknown`. How a person records a resolution is not built (decision 0009,
//! Still open 10).
//!
//! The same lease keeps a receipt from being looked up while its own call may still act: a side
//! effect answered `unknown` at its deadline runs on in a task of its own, never cancelled once
//! sent (decision 0009, "Where a call runs"), and that task [holds](ReceiptQueue::hold) its
//! receipt's lease until it ends. A held receipt is not due, on any instance.

use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::audit::{AuditRowId, MAX_RECORDED_IDENTIFIER, RecordedResources, StoreError};
use crate::connector::BoxFuture;
use crate::names::{PolicyRevision, TeamId, ToolName};
use crate::policy::{Resource, Resources};
use crate::receipt::{Receipt, ReceiptState, VendorReference};
use crate::sentences;

/// How an `unknown` receipt of a tool is settled, declared on the approval of every tool not
/// classified `read` (decision 0009, "Reconciliation"). The loader refuses an approval of such
/// a tool that declares neither, and a `read` tool that declares one: a read has no receipt.
///
/// Written in policy data as `"person"`, or as `{"lookup": {"system": ..., "kind": ...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Settlement {
    /// By a lookup by marker, in the vendor target: the one resource the call names of this
    /// system and kind, such as a repository or a Jira project.
    Lookup(TargetKind),
    /// By a person, at once. A `propose` tool may be approved so: a duplicate proposal is a
    /// second draft or comment, which a person sees before acting on it.
    Person,
}

/// The system and kind of resource a lookup looks in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetKind {
    /// The system, such as `github`.
    pub system: String,
    /// The kind of thing within the system, such as `repository`.
    pub kind: String,
}

impl Settlement {
    /// The vendor target of a call that names `resources`, as a receipt records it at begin:
    /// for a tool settled by a lookup, the one resource of the declared system and kind that
    /// the call names, or that its connector entry's reach holds. `None` for a tool settled by
    /// a person; and for a lookup when the call names no such resource, names more than one,
    /// its resources are unknown, or the resource is longer than a receipt records whole (a
    /// system or kind past [`MAX_RENDERED`](crate::MAX_RENDERED) characters, an identifier
    /// past [`MAX_RECORDED_IDENTIFIER`]) or holds U+0000. A receipt with no target has nothing
    /// to look in, so it goes to a person at once.
    pub fn target(&self, resources: &Resources) -> Option<Resource> {
        match self {
            Settlement::Person => None,
            Settlement::Lookup(declared) => declared.find(named(resources)),
        }
    }
}

impl TargetKind {
    /// The one resource of this system and kind in `resources`, if there is exactly one and a
    /// receipt can record it whole.
    fn find(&self, resources: &[Resource]) -> Option<Resource> {
        let mut matching = resources
            .iter()
            .filter(|resource| resource.system == self.system && resource.kind == self.kind);
        let first = matching.next()?;
        if matching.any(|other| other != first) {
            return None;
        }
        let whole = first.system.chars().count() <= sentences::MAX_RENDERED
            && first.kind.chars().count() <= sentences::MAX_RENDERED
            && first.identifier.chars().count() <= MAX_RECORDED_IDENTIFIER
            && ![&first.system, &first.kind, &first.identifier]
                .iter()
                .any(|text| text.contains('\0'));
        whole.then(|| first.clone())
    }
}

/// The resources a call names, or the reach it names as a whole: what a target is found in.
fn named(resources: &Resources) -> &[Resource] {
    match resources {
        Resources::Named(named) => named,
        Resources::Reach { resources, .. } => resources,
        Resources::Unknown => &[],
    }
}

/// What a lookup found (decision 0009, "Reconciliation").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result", deny_unknown_fields)]
pub enum LookupAnswer {
    /// The effect, found by its marker, with the vendor's reference for it: a pull request
    /// number, a comment identifier. A match by the marker is conclusive.
    Found {
        /// The vendor's reference.
        reference: VendorReference,
    },
    /// Nothing carries the marker.
    NotFound {
        /// Whether the vendor documents the search as complete and current. Only then does
        /// finding nothing establish that nothing took effect.
        authoritative: bool,
    },
    /// The lookup could not be made, or gave no answer in time.
    Failed,
}

impl LookupAnswer {
    /// The state this answer settles an `unknown` receipt in: `completed` for a found effect,
    /// and `not_performed` for an authoritative search that found nothing. `None` for every
    /// other answer, which leaves the receipt `unknown`: a search that finds nothing proves
    /// nothing unless the vendor says it is complete and current.
    pub fn settles(&self) -> Option<ReceiptState> {
        match self {
            LookupAnswer::Found { .. } => Some(ReceiptState::Completed),
            LookupAnswer::NotFound {
                authoritative: true,
            } => Some(ReceiptState::NotPerformed),
            LookupAnswer::NotFound { .. } | LookupAnswer::Failed => None,
        }
    }

    /// Whether the answer is authoritative: a found effect is, a failed lookup is not, and a
    /// search that found nothing is as the lookup says.
    pub fn authoritative(&self) -> bool {
        match self {
            LookupAnswer::Found { .. } => true,
            LookupAnswer::NotFound { authoritative } => *authoritative,
            LookupAnswer::Failed => false,
        }
    }

    /// The result's name, as a store and the signals record it: `found`, `not_found` or
    /// `failed`.
    pub fn result(&self) -> &'static str {
        match self {
            LookupAnswer::Found { .. } => "found",
            LookupAnswer::NotFound { .. } => "not_found",
            LookupAnswer::Failed => "failed",
        }
    }

    /// The vendor's reference, for a found effect.
    pub fn reference(&self) -> Option<&VendorReference> {
        match self {
            LookupAnswer::Found { reference } => Some(reference),
            _ => None,
        }
    }

    /// The answer as a receipt records it: a found effect's reference escaped and capped, as
    /// a finish's is, since it comes from the vendor's answer.
    pub fn recorded(&self) -> LookupAnswer {
        match self {
            LookupAnswer::Found { reference } => LookupAnswer::Found {
                reference: reference.recorded(),
            },
            other => other.clone(),
        }
    }
}

/// One lookup, as a receipt records it: when the store wrote it, by its own clock, and what it
/// found. A lookup record is never changed or removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRecord {
    /// When it was recorded, by the store's clock.
    pub at: SystemTime,
    /// What it found.
    pub answer: LookupAnswer,
}

/// Who holds a receipt's lease: one gateway instance's reconciliation, named by the instance
/// and a value of its own, so two processes under one instance name never share a lease.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseHolder(String);

impl LeaseHolder {
    /// Wraps the holder's name.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LeaseHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a lookup is given: the receipt's identifier, which is the marker the gateway attached
/// to the request, the vendor target the receipt recorded, the tool, the resources the call
/// named, as its row records them, the team the receipt recorded, and the policy revision in
/// force, which a lookup that asks a custodian for its read credential sends with the team.
/// Never the call's arguments: a lookup has nothing to send but a search.
#[derive(Clone, Copy, Debug)]
pub struct LookupRequest<'a> {
    /// The receipt's identifier: the marker.
    pub marker: &'a AuditRowId,
    /// Where to look.
    pub target: &'a Resource,
    /// The tool whose effect is looked for.
    pub tool: &'a ToolName,
    /// The resources the call named.
    pub resources: &'a RecordedResources,
    /// The proved principal's team, as the receipt recorded it at begin: `None` for a person,
    /// and for a receipt reserved before receipts recorded it.
    pub team: Option<&'a TeamId>,
    /// The revision of the policy in force when the lookup is made.
    pub revision: &'a PolicyRevision,
}

/// A connector's lookup by marker (decision 0009, "Reconciliation").
///
/// An implementation searches the vendor target for the marker and answers what it found. It
/// must never send anything that could cause an effect: no write, no retry of the call, no
/// vendor idempotency key, which would mean sending the request again. It is not a tool call,
/// and writes no audit row. It answers [`LookupAnswer::NotFound`] as authoritative only for a
/// search the vendor documents as complete and current, and [`LookupAnswer::Failed`] for
/// anything it could not complete. A lookup that asks a custodian for its read credential asks
/// for it narrowed to the receipt's team and target, under the revision in force, and fails
/// when the receipt recorded no team.
pub trait Lookup: Send + Sync {
    /// Looks for the effect `request` names.
    fn look<'a>(&'a self, request: LookupRequest<'a>) -> BoxFuture<'a, LookupAnswer>;
}

/// What [`ReceiptQueue::record_lookup`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// The lookup settled the receipt, established by reconciliation, in this state.
    Settled(ReceiptState),
    /// The lookup was recorded and the receipt left `unknown`, for the next attempt.
    Left,
    /// The lookup was recorded, settled nothing, and used up the last attempt, so the receipt
    /// was handed to a person in the same write. It stays `unknown`.
    HandedToPerson,
}

/// The queue of `unknown` receipts, as a store keeps it for reconciliation (decision 0009,
/// "Reconciliation"). Every instance works it, so there is no separate deployment. Times are
/// the store's: database time for Postgres.
///
/// A receipt is due when it reads as `unknown` (the state `unknown`, or `pending` past its
/// row's deadline), has not been handed to a person, and its lease is free: never set, or
/// ended. A receipt is held by the holder that claimed it, or that [holds](Self::hold) it for
/// its call, until its lease ends. Ending a lease early is not offered: a lease runs out, which
/// also spaces one receipt's attempts.
pub trait ReceiptQueue: Send + Sync {
    /// Up to `limit` receipts due, the longest reserved first, as they are now, with the
    /// lookups made so far. Reads only: nothing is claimed.
    fn due<'a>(&'a self, limit: usize) -> BoxFuture<'a, Result<Vec<Receipt>, StoreError>>;

    /// Claims the receipt reserved under `row` for `holder`, for `lease` from now, if it is
    /// still due, counts the claim in its [`claims`](Receipt::claims) in the same write, and
    /// returns it as it is then. The claim is committed when this returns, and not before, so
    /// no lookup is made before it and no lock or connection is held across one. Of two claims
    /// at once, at most one succeeds. `None`, counting nothing, when the receipt is not due:
    /// settled, handed to a person, or held under a lease that has not ended.
    fn claim<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        lease: Duration,
    ) -> BoxFuture<'a, Result<Option<Receipt>, StoreError>>;

    /// Appends `answer` to the lookups of the receipt reserved under `row`, as the next
    /// attempt, with the store's time, and in the same write moves the receipt as the answer
    /// [`settles`](LookupAnswer::settles) it, established by reconciliation, with a found
    /// effect's reference; or, when it settles nothing and it is the `attempts`-th lookup,
    /// hands the receipt to a person.
    ///
    /// Refused, writing nothing, unless `holder` holds the receipt's lease now, the receipt
    /// still reads as `unknown` and has not been handed to a person, and fewer than `attempts`
    /// lookups are recorded. A lookup record is never changed or removed.
    fn record_lookup<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        answer: &'a LookupAnswer,
        attempts: u32,
    ) -> BoxFuture<'a, Result<Recorded, StoreError>>;

    /// Holds the receipt reserved under `row` for `holder`, for `lease` from now, on behalf of
    /// the call that reserved it: a side effect answered `unknown` at its deadline that runs on
    /// in a task of its own, which may still act. A held receipt is not due, so no instance
    /// claims it or looks it up while it is held. The task holds it again before the lease
    /// ends, for as long as it runs.
    ///
    /// Sets the lease when it is free or `holder` holds it already, while the receipt is
    /// `pending`, within its row's deadline or past it, or `unknown`, and has not been handed
    /// to a person. Counts no claim. Returns whether `holder` holds it when this returns:
    /// `false`, writing nothing, when another holder's lease has not ended, or the receipt is
    /// settled or handed to a person, or there is none under `row`.
    fn hold<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        lease: Duration,
    ) -> BoxFuture<'a, Result<bool, StoreError>>;

    /// Hands the receipt reserved under `row` to a person, recording when, by the store's
    /// clock. It stays `unknown`, and is no longer due. Refused, writing nothing, unless
    /// `holder` holds its lease now and it still reads as `unknown` and has not been handed to
    /// a person.
    fn hand_to_person<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::names::ConnectorName;

    fn resource(system: &str, kind: &str, identifier: &str) -> Resource {
        Resource {
            system: system.into(),
            kind: kind.into(),
            identifier: identifier.into(),
        }
    }

    fn lookup_in(system: &str, kind: &str) -> Settlement {
        Settlement::Lookup(TargetKind {
            system: system.into(),
            kind: kind.into(),
        })
    }

    #[test]
    fn a_settlement_is_written_as_person_or_a_lookup_in_a_kind() {
        assert_eq!(
            serde_json::from_value::<Settlement>(json!("person")).unwrap(),
            Settlement::Person
        );
        assert_eq!(
            serde_json::from_value::<Settlement>(
                json!({"lookup": {"system": "github", "kind": "repository"}})
            )
            .unwrap(),
            lookup_in("github", "repository")
        );
        for refused in [
            json!("lookup"),
            json!("nobody"),
            json!({"lookup": {"system": "github"}}),
            json!({"lookup": {"system": "github", "kind": "repository", "more": 1}}),
        ] {
            assert!(
                serde_json::from_value::<Settlement>(refused.clone()).is_err(),
                "{refused} was read"
            );
        }
    }

    /// The target is the one resource of the declared system and kind; none for a person, for
    /// none or several such resources, for unknown resources, or for one a receipt cannot hold
    /// whole.
    #[test]
    fn the_target_is_the_one_resource_of_the_declared_kind() {
        let repository = resource("github", "repository", "example-org/payments-api");
        let other = resource("github", "repository", "example-org/ledger");
        let issue = resource("github", "issue", "7");
        let settlement = lookup_in("github", "repository");
        let named = |resources: &[&Resource]| {
            Resources::Named(resources.iter().map(|&resource| resource.clone()).collect())
        };

        assert_eq!(
            settlement.target(&named(&[&issue, &repository])),
            Some(repository.clone())
        );
        assert_eq!(
            settlement.target(&named(&[&repository, &repository])),
            Some(repository.clone()),
            "the same resource named twice is one"
        );
        assert_eq!(
            Settlement::Person.target(&named(&[&repository])),
            None,
            "a tool settled by a person has no target"
        );
        assert_eq!(settlement.target(&named(&[&issue])), None);
        assert_eq!(settlement.target(&named(&[&repository, &other])), None);
        assert_eq!(settlement.target(&Resources::Unknown), None);
        assert_eq!(
            settlement.target(&Resources::Reach {
                entry: ConnectorName::new("github"),
                resources: vec![repository.clone()],
            }),
            Some(repository.clone())
        );

        let longest = "i".repeat(MAX_RECORDED_IDENTIFIER);
        let whole = resource("github", "repository", &longest);
        assert_eq!(settlement.target(&named(&[&whole])), Some(whole.clone()));
        let too_long = resource("github", "repository", &format!("{longest}i"));
        assert_eq!(settlement.target(&named(&[&too_long])), None);
        let nul = resource("github", "repository", "a\0b");
        assert_eq!(settlement.target(&named(&[&nul])), None);
        let long_kind = "k".repeat(sentences::MAX_RENDERED + 1);
        assert_eq!(
            lookup_in("github", &long_kind).target(&named(&[&resource("github", &long_kind, "x")])),
            None
        );
    }

    /// Found settles `completed`, an authoritative search that found nothing `not_performed`,
    /// and nothing else settles anything.
    #[test]
    fn only_a_found_effect_or_an_authoritative_empty_search_settles() {
        let found = LookupAnswer::Found {
            reference: VendorReference::new("PR-7"),
        };
        assert_eq!(found.settles(), Some(ReceiptState::Completed));
        assert!(found.authoritative());
        assert_eq!(
            LookupAnswer::NotFound {
                authoritative: true
            }
            .settles(),
            Some(ReceiptState::NotPerformed)
        );
        let empty = LookupAnswer::NotFound {
            authoritative: false,
        };
        assert_eq!(empty.settles(), None, "an empty search proves nothing");
        assert!(!empty.authoritative());
        assert_eq!(LookupAnswer::Failed.settles(), None);
        assert!(!LookupAnswer::Failed.authoritative());
        assert_eq!(
            [
                found.result(),
                empty.result(),
                LookupAnswer::Failed.result()
            ],
            ["found", "not_found", "failed"]
        );
    }

    #[test]
    fn a_found_reference_is_recorded_escaped_and_capped() {
        let long = format!("PR\n{}", "7".repeat(400));
        let recorded = LookupAnswer::Found {
            reference: VendorReference::new(long),
        }
        .recorded();
        let reference = recorded.reference().unwrap().as_str();
        assert!(reference.starts_with("PR\\n7"), "{reference}");
        assert!(reference.ends_with('…'), "{reference}");
        assert_eq!(reference.chars().count(), sentences::MAX_RENDERED + 1);
        assert_eq!(
            LookupAnswer::Failed.recorded(),
            LookupAnswer::Failed,
            "only a reference is changed"
        );
    }
}
