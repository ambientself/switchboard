//! Runs every case in `decision_table.json` and reports every case that fails, by name.
//!
//! Each case goes the whole way a call goes: decided, then begun against an in-memory audit
//! store. The sentence checked is the one on the [`Refusal`](gateway_core::audit::Refusal),
//! because that is the only place a denial's sentence can be had, and every column of the row
//! is checked against what the case says.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::audit::{self, Begun, DecisionKind, RequestMetadata};
use gateway_core::{
    AuditRecord, CallContext, CallerContext, Claimed, Delegation, DeploymentName, PolicySnapshot,
    Principal, ProfileName, ReasonKind, RequestedTool, Resources, SnapshotData, SurfaceName,
    TeamId, ToolName, WasProved, decide, list_tools,
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
    delegations: BTreeMap<String, Delegation>,
    snapshots: BTreeMap<String, SnapshotData>,
    cases: Vec<Case>,
    lists: Vec<ListCase>,
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

#[derive(Deserialize)]
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

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
enum Expected {
    Allow,
    Deny {
        reason: ReasonKind,
        sentence: String,
    },
}

struct World {
    deployment: DeploymentName,
    principals: BTreeMap<String, Principal>,
    delegations: BTreeMap<String, Delegation>,
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
                delegation: delegation.map(common::proved),
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
        delegations: table.delegations,
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
    let delegation = case
        .delegation
        .as_ref()
        .map(|name| &world.delegations[name]);
    let served = case
        .tool
        .name()
        .ok()
        .and_then(|name| snapshot.surface(&case.surface)?.tools.get(&name).cloned())
        .and_then(|name| snapshot.tool(&name).cloned());
    let (decision, reason, sentence) = match &case.expect {
        Expected::Allow => (DecisionKind::Allow, None, None),
        Expected::Deny { reason, sentence } => {
            (DecisionKind::Deny, Some(*reason), Some(sentence.clone()))
        }
    };
    let row = serde_json::json!({
        "tool_use_id": metadata.tool_use_id,
        "deployment": world.deployment,
        // Every requested surface and tool in the table is printable ASCII apart from the
        // escaping cases, whose rows are checked by `hostile_requests_are_escaped_in_the_row`.
        "surface": escape(case.surface.as_str()),
        "profile": case.profile,
        "tool": escape(case.tool.as_str()),
        "connector": served.as_ref().map(|tool| tool.connector.clone()),
        "classification": served.as_ref().map(|tool| tool.classification),
        "decision": decision,
        "reason": reason,
        "sentence": sentence,
        "policy_revision": snapshot.revision(),
        "proved_principal": principal,
        "proved_delegation_team": delegation.map(|delegation| &delegation.team),
        "claimed_acting_person": delegation.map(|delegation| &delegation.acting_person),
        "claimed_team": metadata.claimed_team,
        "completion": null,
    });
    serde_json::from_value(row).expect("the expected row does not deserialize")
}

/// The table's own escaping, written out independently of the crate's: the only characters
/// the table uses that need it are newlines and backticks.
fn escape(text: &str) -> String {
    text.replace('`', "\\`").replace('\n', "\\n")
}

#[test]
fn every_decision_case_holds() {
    let (world, cases, _) = load();
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
        };
        let decision = decide(snapshot, &call);
        if decision.policy_revision() != snapshot.revision() {
            failures.push(format!("case `{}`: wrong policy revision", case.name));
        }
        let metadata = RequestMetadata {
            tool_use_id: Some(format!("toolu-{index}").as_str().into()),
            claimed_team: Some(Claimed::new(TeamId::from("claimed-team"))),
        };
        let store = MemoryStore::default();
        let begun = common::ready(audit::begin(
            &store,
            decision,
            serde_json::json!({"case": index}),
            metadata.clone(),
        ))
        .expect("the in-memory store refused a row");
        let got = match &begun {
            Begun::Allowed(_) => Expected::Allow,
            Begun::Denied(refusal) => Expected::Deny {
                reason: refusal.reason().kind(),
                sentence: refusal.sentence().to_owned(),
            },
        };
        if got != case.expect {
            failures.push(format!(
                "case `{}`:\n    expected {:?}\n    got      {:?}",
                case.name, case.expect, got
            ));
            continue;
        }
        let rows = store.rows();
        let want = expected_row(&world, snapshot, case, &metadata);
        if rows != [want.clone()] {
            failures.push(format!(
                "case `{}`: the audit row is wrong\n    expected {want:?}\n    got      {rows:?}",
                case.name
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} decision cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
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
/// profile, allows as well as denials, and enough cases.
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
            Expected::Allow => None,
        })
        .collect();
    let missing: Vec<_> = ReasonKind::ALL
        .into_iter()
        .filter(|kind| !reasons.contains(kind))
        .collect();
    assert!(missing.is_empty(), "no case expects {missing:?}");
    assert!(
        cases.iter().any(|case| case.expect == Expected::Allow),
        "no case expects allow"
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
