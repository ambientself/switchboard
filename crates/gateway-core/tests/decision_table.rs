//! Runs every case in `decision_table.json` and reports every case that fails, by name.
//!
//! Each case goes the whole way a call goes: decided, then begun against an in-memory audit
//! store. The sentence checked is the one on the [`Refusal`](gateway_core::audit::Refusal),
//! because that is the only place a denial's sentence can be had, and every column of the row
//! is checked against what the case says.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::audit::{self, Begun, DecisionKind, MAX_RECORDED_RESOURCES, RequestMetadata};
use gateway_core::{
    AuditRecord, CallContext, CallerContext, Claimed, Classification, Currency, CurrencyAnswer,
    Delegation, DelegationDigest, DelegationFailure, DeploymentName, Egress, ExceptionName,
    IdempotencyKey, Person, PolicySnapshot, PresentedDelegation, Principal, ProfileName,
    ReasonKind, ReceiptState, RequestedTool, Resource, Resources, SnapshotData, SurfaceName,
    TeamId, ToolName, UnverifiedDelegation, WasProved, decide, list_tools,
};
use serde::Deserialize;

use common::MemoryStore;

const TABLE: &str = include_str!("decision_table.json");

/// Fewer than this and the table has lost cases without anyone deciding to remove them.
const MINIMUM_CASES: usize = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    #[allow(dead_code)]
    about: String,
    deployment: DeploymentName,
    principals: BTreeMap<String, Principal>,
    delegations: BTreeMap<String, TableDelegation>,
    snapshots: BTreeMap<String, SnapshotData>,
    cases: Vec<Case>,
    lists: Vec<ListCase>,
}

/// A delegation as the table writes it: one that verified, with its person, team and tools, or
/// one that did not, with the check it failed and, after a verified signature, its digest.
#[derive(Deserialize)]
#[serde(untagged)]
enum TableDelegation {
    Unverified(TableUnverified),
    Verified(TableVerified),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableUnverified {
    unverified: DelegationFailure,
    #[serde(default)]
    digest: Option<DelegationDigest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableVerified {
    acting_person: Claimed<Person>,
    team: TeamId,
    tools: BTreeSet<ToolName>,
}

impl TableDelegation {
    /// The delegation as its verifier would present it. A verified one is issued for the turn
    /// named like it, under a test key, and its digest is of its name; the narrow ones carry no
    /// egress setting, and the rest a sealed one.
    fn presented(self, name: &str) -> PresentedDelegation {
        match self {
            TableDelegation::Unverified(TableUnverified {
                unverified,
                digest: None,
            }) => UnverifiedDelegation::new(unverified).into(),
            TableDelegation::Unverified(TableUnverified {
                unverified,
                digest: Some(digest),
            }) => UnverifiedDelegation::after_signature(unverified, digest)
                .unwrap_or_else(|error| panic!("delegation `{name}`: {error}"))
                .into(),
            TableDelegation::Verified(TableVerified {
                acting_person,
                team,
                tools,
            }) => common::presented(&Delegation {
                acting_person,
                team,
                tools,
                issuer: "otto-test".into(),
                digest: DelegationDigest::of(name.as_bytes()),
                key_id: "key-1".into(),
                session: "session-1".into(),
                turn: name.into(),
                execution: "execution-1".into(),
                epoch: 7,
                egress: (!name.ends_with("narrow")).then_some(Egress::Sealed),
            }),
        }
    }
}

/// Who is calling, where and under which profile: the fields a decision case and a list case
/// share. Repeated in each rather than flattened, because serde cannot refuse unknown fields
/// through `flatten`, and a misspelt `delegation` would otherwise silently become none.
struct Caller<'a> {
    snapshot: &'a str,
    principal: &'a str,
    delegation: Option<&'a str>,
    profile: &'a ProfileName,
    surface: &'a SurfaceName,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    snapshot: String,
    principal: String,
    delegation: Option<String>,
    profile: ProfileName,
    surface: SurfaceName,
    tool: RequestedTool,
    resources: Resources,
    /// The call's idempotency key. A call of a tool not classified `read` needs one.
    #[serde(default)]
    key: Option<IdempotencyKey>,
    /// What the control plane answered when asked whether the turn is current. Absent when it
    /// was not asked.
    #[serde(default)]
    currency: Option<CurrencyAnswer>,
    expect: Expected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCase {
    name: String,
    snapshot: String,
    principal: String,
    delegation: Option<String>,
    profile: ProfileName,
    surface: SurfaceName,
    expect: Vec<ToolName>,
}

impl Case {
    fn caller(&self) -> Caller<'_> {
        Caller {
            snapshot: &self.snapshot,
            principal: &self.principal,
            delegation: self.delegation.as_deref(),
            profile: &self.profile,
            surface: &self.surface,
        }
    }
}

impl ListCase {
    fn caller(&self) -> Caller<'_> {
        Caller {
            snapshot: &self.snapshot,
            principal: &self.principal,
            delegation: self.delegation.as_deref(),
            profile: &self.profile,
            surface: &self.surface,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
enum Expected {
    /// Allowed; by the exception named, when check 5 needed one (decision 0011, section 9).
    /// The decision names it, and the row records it.
    Allow {
        #[serde(default)]
        exception: Option<ExceptionName>,
    },
    Deny {
        reason: ReasonKind,
        sentence: String,
    },
}

struct World {
    deployment: DeploymentName,
    principals: BTreeMap<String, Principal>,
    delegations: BTreeMap<String, PresentedDelegation>,
    snapshots: BTreeMap<String, PolicySnapshot>,
    profiles: BTreeMap<String, Vec<ProfileName>>,
}

impl World {
    /// Builds the caller's context the way the gateway will: the principal and delegation
    /// through a verifier. The profile is only named; the decision finds it in the snapshot.
    fn caller(&self, caller: Caller<'_>) -> Result<(&PolicySnapshot, CallerContext), String> {
        let snapshot = self
            .snapshots
            .get(caller.snapshot)
            .ok_or_else(|| format!("no snapshot `{}`", caller.snapshot))?;
        let principal = self
            .principals
            .get(caller.principal)
            .ok_or_else(|| format!("no principal `{}`", caller.principal))?;
        let delegation = match caller.delegation {
            None => None,
            Some(name) => Some(
                self.delegations
                    .get(name)
                    .ok_or_else(|| format!("no delegation `{name}`"))?,
            ),
        };
        Ok((
            snapshot,
            CallerContext {
                principal: common::proved(principal),
                delegation: delegation.cloned(),
                profile: caller.profile.clone(),
                surface: caller.surface.clone(),
                deployment: self.deployment.clone(),
            },
        ))
    }
}

fn load() -> (World, Vec<Case>, Vec<ListCase>) {
    let table: Table = serde_json::from_str(TABLE).expect("decision_table.json does not parse");
    let profiles = table
        .snapshots
        .iter()
        .map(|(name, data)| {
            let names = data.profiles.iter().map(|profile| profile.name.clone());
            (name.clone(), names.collect())
        })
        .collect();
    let snapshots = table
        .snapshots
        .into_iter()
        .map(|(name, data)| {
            let snapshot = PolicySnapshot::new(data)
                .unwrap_or_else(|error| panic!("snapshot `{name}` is invalid: {error}"));
            (name, snapshot)
        })
        .collect();
    let world = World {
        deployment: table.deployment,
        principals: table.principals,
        delegations: table
            .delegations
            .into_iter()
            .map(|(name, delegation)| {
                let presented = delegation.presented(&name);
                (name, presented)
            })
            .collect(),
        snapshots,
        profiles,
    };
    (world, table.cases, table.lists)
}

/// The row a case should leave, built from the case and the world, not from the decision.
fn expected_row(
    world: &World,
    snapshot: &PolicySnapshot,
    case: &Case,
    metadata: &RequestMetadata,
) -> AuditRecord {
    let principal = &world.principals[&case.principal];
    let presented = case
        .delegation
        .as_ref()
        .map(|name| &world.delegations[name]);
    let delegation = presented
        .and_then(PresentedDelegation::verified)
        .map(|delegation| delegation.get());
    let served = case
        .tool
        .name()
        .ok()
        .and_then(|name| snapshot.surface(&case.surface)?.tools.get(&name).cloned())
        .and_then(|name| snapshot.tool(&name).cloned());
    let (decision, reason, sentence, exception) = match &case.expect {
        Expected::Allow { exception } => (DecisionKind::Allow, None, None, exception.clone()),
        Expected::Deny { reason, sentence } => (
            DecisionKind::Deny,
            Some(*reason),
            Some(sentence.clone()),
            None,
        ),
    };
    // A failure is recorded only on the row check 3 denied for it: a call denied before
    // check 3 records that denial alone.
    let failure = presented
        .and_then(PresentedDelegation::unverified)
        .filter(|_| reason == Some(ReasonKind::DelegationUnverified));
    let row = serde_json::json!({
        "kind": "call",
        "instance": common::INSTANCE,
        "call_deadline_ms": common::CALL_DEADLINE_MS,
        "tool_use_id": metadata.tool_use_id,
        "deployment": world.deployment,
        // Every requested surface and tool in the table is printable ASCII apart from the
        // escaping cases, whose rows are checked by `hostile_requests_are_escaped_in_the_row`.
        "surface": escape(case.surface.as_str()),
        "profile": case.profile,
        "tool": escape(case.tool.as_str()),
        "connector": served.as_ref().map(|tool| tool.connector.clone()),
        "classification": served.as_ref().map(|tool| tool.classification),
        // Each resource once, in the order first named. No case names more distinct resources
        // than a row records, so none are omitted; a case that did would be refused here.
        "resources": match &case.resources {
            Resources::Unknown => serde_json::json!("unknown"),
            // A reach is recorded by its entry, never as the list.
            Resources::Reach { entry, .. } => serde_json::json!({ "reach": entry }),
            Resources::Named(named) => {
                let mut distinct: Vec<&Resource> = Vec::new();
                for resource in named {
                    if !distinct.contains(&resource) {
                        distinct.push(resource);
                    }
                }
                assert!(
                    distinct.len() <= MAX_RECORDED_RESOURCES,
                    "case `{}` names more distinct resources than a row records",
                    case.name
                );
                serde_json::json!({ "named": distinct.iter().map(|resource| serde_json::json!({
                    "system": escape(&resource.system),
                    "kind": escape(&resource.kind),
                    "identifier": escape(&resource.identifier),
                })).collect::<Vec<_>>() })
            }
        },
        "resources_omitted": 0,
        "decision": decision,
        "reason": reason,
        "sentence": sentence,
        "policy_revision": snapshot.revision(),
        "proved_principal": principal,
        "proved_delegation_team": delegation.map(|delegation| &delegation.team),
        "claimed_acting_person": delegation.map(|delegation| &delegation.acting_person),
        "claimed_team": metadata.claimed_team,
        // Every value the table gives a delegation is printable ASCII, so nothing is escaped.
        "delegation": delegation.map(|delegation| serde_json::json!({
            "digest": delegation.digest,
            "issuer": delegation.issuer,
            "key_id": delegation.key_id,
            "session": delegation.session,
            "turn": delegation.turn,
            "execution": delegation.execution,
            "epoch": delegation.epoch,
            "egress": delegation.egress,
        })),
        // A delegation that did not verify leaves which check it failed and, after a verified
        // signature, its digest: nothing from its claims.
        "delegation_failure": failure.map(|failure| serde_json::json!({
            "failure": failure.failure(),
            "digest": failure.digest(),
        })),
        "currency": case.currency,
        // Only an allowed call records the exception that let it past check 5; every denial,
        // one that passed check 5 by an exception included, records none.
        "allowed_by_exception": exception,
        // The identity the served tool's entry states, if it has one.
        "credential": served
            .as_ref()
            .and_then(|tool| snapshot.entry(&tool.connector))
            .map(|entry| serde_json::json!({
                "mode": entry.credential,
                "principal": entry.principal,
            })),
        "completion": null,
    });
    serde_json::from_value(row).expect("the expected row does not deserialize")
}

/// The table's own escaping, written out independently of the crate's: the only characters
/// the table uses that need it are backslashes, newlines and backticks.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('\n', "\\n")
}

#[test]
fn every_decision_case_holds() {
    let (world, cases, _) = load();
    let failures = check_cases(&world, &cases);
    assert!(
        failures.is_empty(),
        "{} of {} decision cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// A call can name any number of resources, and a row records at most
/// [`MAX_RECORDED_RESOURCES`] distinct ones. The decision is not bounded the same way: these
/// cases, made from the table's own, name a resource many times over and put the one outside
/// the limit past the most a row records. Each is checked like a table case, row included.
#[test]
fn resources_past_what_a_row_records_are_still_decided() {
    let (world, cases, _) = load();
    let find = |name: &str| {
        cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("the table has no case `{name}`"))
    };
    let allowed = find("otto read inside the team's limit is allowed");
    let outside = find("another team's repository is outside the limit");
    let named = |case: &Case| match &case.resources {
        Resources::Named(named) if named.len() == 1 => named[0].clone(),
        _ => panic!("case `{}` does not name one resource", case.name),
    };
    let (inside, beyond) = (named(allowed), named(outside));
    let padded = vec![inside.clone(); MAX_RECORDED_RESOURCES * 2];

    let mut repeated = padded.clone();
    repeated.push(inside.clone());
    let mut denied = padded.clone();
    denied.push(beyond.clone());
    let mut denied_then_more = padded;
    denied_then_more.extend([beyond.clone(), inside, beyond]);

    let made: Vec<Case> = [
        (
            allowed,
            "a resource repeated past what a row records is allowed",
            repeated,
        ),
        (
            outside,
            "a resource outside the limit is denied past what a row records",
            denied,
        ),
        (
            outside,
            "a resource outside the limit is denied however much follows it",
            denied_then_more,
        ),
    ]
    .into_iter()
    .map(|(from, name, resources)| Case {
        name: name.to_owned(),
        resources: Resources::Named(resources),
        ..from.clone()
    })
    .collect();
    let failures = check_cases(&world, &made);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Runs each case the whole way, and describes every one that fails.
fn check_cases(world: &World, cases: &[Case]) -> Vec<String> {
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let (snapshot, caller) = match world.caller(case.caller()) {
            Ok(found) => found,
            Err(error) => {
                failures.push(format!("case `{}`: {error}", case.name));
                continue;
            }
        };
        let call = CallContext {
            caller,
            tool: case.tool.clone(),
            resources: case.resources.clone(),
            key: case.key.clone(),
            currency: case.currency.map_or(Currency::NotAsked, Currency::Asked),
        };
        let decision = decide(snapshot, &call);
        if decision.policy_revision() != snapshot.revision() {
            failures.push(format!("case `{}`: wrong policy revision", case.name));
        }
        let exception = decision.exception().cloned();
        let metadata = RequestMetadata {
            tool_use_id: Some(format!("toolu-{index}").as_str().into()),
            claimed_team: Some(Claimed::new(TeamId::from("claimed-team"))),
        };
        let store = MemoryStore::default();
        // As the gateway does: the credential identity from the snapshot the decision was made
        // from.
        let start = audit::RowStart {
            credential: audit::credential_identity(snapshot, &decision),
            ..common::start()
        };
        let begun = common::ready(audit::begin(
            &store,
            start,
            decision,
            serde_json::json!({"case": index}),
            metadata.clone(),
        ))
        .expect("the in-memory store refused a row");
        let got = match &begun {
            Begun::Allowed(_) => Expected::Allow { exception },
            Begun::Denied(refusal) => {
                if let Some(exception) = exception {
                    failures.push(format!(
                        "case `{}`: a denial names exception `{exception}`",
                        case.name
                    ));
                }
                Expected::Deny {
                    reason: refusal.reason().kind(),
                    sentence: refusal.sentence().to_owned(),
                }
            }
            Begun::Reused(reused) => {
                failures.push(format!(
                    "case `{}`: a fresh store answered a reused key: {reused:?}",
                    case.name
                ));
                continue;
            }
        };
        if got != case.expect {
            failures.push(format!(
                "case `{}`:\n    expected {:?}\n    got      {:?}",
                case.name, case.expect, got
            ));
            continue;
        }
        let rows = store.rows();
        let want = expected_row(world, snapshot, case, &metadata);
        if rows != [want.clone()] {
            failures.push(format!(
                "case `{}`: the audit row is wrong\n    expected {want:?}\n    got      {rows:?}",
                case.name
            ));
        }
        // An allowed side effect reserves one `pending` receipt, under its row and for its key,
        // and nothing else reserves any: a denial uses up no key.
        let side_effect = matches!(case.expect, Expected::Allow { .. })
            && want
                .classification
                .is_some_and(|classification| classification != Classification::Read);
        let receipts = store.receipts();
        let reserved = match receipts.as_slice() {
            [] => false,
            [receipt] => {
                receipt.row == store.ids()[0]
                    && Some(&receipt.key) == case.key.as_ref()
                    && receipt.state == ReceiptState::Pending
            }
            _ => true,
        };
        if reserved != side_effect || receipts.len() > 1 {
            failures.push(format!(
                "case `{}`: a side effect: {side_effect}; receipts: {receipts:?}",
                case.name
            ));
        }
    }
    failures
}

#[test]
fn every_list_case_holds() {
    let (world, _, lists) = load();
    assert!(!lists.is_empty(), "the table has no tools/list cases");
    let mut failures = Vec::new();
    for case in &lists {
        let (snapshot, caller) = match world.caller(case.caller()) {
            Ok(found) => found,
            Err(error) => {
                failures.push(format!("list `{}`: {error}", case.name));
                continue;
            }
        };
        let got: Vec<ToolName> = list_tools(snapshot, &caller)
            .into_iter()
            .map(|tool| tool.name.clone())
            .collect();
        if got != case.expect {
            failures.push(format!(
                "list `{}`:\n    expected {:?}\n    got      {:?}",
                case.name, case.expect, got
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} list cases failed:\n{}",
        failures.len(),
        lists.len(),
        failures.join("\n")
    );
}

/// The table is only evidence if it covers what it claims to: every kind of reason, every
/// profile, allows as well as denials, an allow by an exception, and enough cases.
#[test]
fn the_table_covers_every_reason_and_profile() {
    let (world, cases, _) = load();
    assert!(
        cases.len() >= MINIMUM_CASES,
        "the table has {} cases; it should have at least {MINIMUM_CASES}",
        cases.len()
    );

    let names: BTreeSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "two cases share a name");

    let reasons: BTreeSet<ReasonKind> = cases
        .iter()
        .filter_map(|case| match case.expect {
            Expected::Deny { reason, .. } => Some(reason),
            Expected::Allow { .. } => None,
        })
        .collect();
    let missing: Vec<_> = ReasonKind::ALL
        .into_iter()
        .filter(|kind| !reasons.contains(kind))
        .collect();
    assert!(missing.is_empty(), "no case expects {missing:?}");
    assert!(
        cases
            .iter()
            .any(|case| case.expect == Expected::Allow { exception: None }),
        "no case expects allow"
    );
    assert!(
        cases
            .iter()
            .any(|case| matches!(&case.expect, Expected::Allow { exception: Some(_) })),
        "no case expects an allow by an exception"
    );

    for (snapshot, profiles) in &world.profiles {
        for profile in profiles {
            let used = cases
                .iter()
                .any(|case| &case.snapshot == snapshot && &case.profile == profile);
            assert!(
                used,
                "no case uses profile `{profile}` of snapshot `{snapshot}`"
            );
        }
    }
}

/// `WasProved` is what a row reads back as; the expected row is built through JSON, so make
/// sure that conversion means what the comparison assumes.
#[test]
fn an_expected_row_reads_proved_columns_as_was_proved() {
    let (world, cases, _) = load();
    let case = &cases[0];
    let (snapshot, _) = world.caller(case.caller()).unwrap();
    let row = expected_row(&world, snapshot, case, &RequestMetadata::default());
    let principal: &Principal = row.proved_principal.get();
    assert_eq!(principal, &world.principals[&case.principal]);
    let _: Option<WasProved<TeamId>> = row.proved_delegation_team;
}
