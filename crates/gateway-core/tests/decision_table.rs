//! Runs every case in `decision_table.json` and reports every case that fails, by name.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use gateway_core::{
    CallContext, CallerContext, Delegation, DeploymentName, PolicySnapshot, Principal, ProfileName,
    ReasonKind, Resources, SnapshotData, SurfaceName, ToolName, Verdict, decide, list_tools,
};
use serde::Deserialize;

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
    tool: ToolName,
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
    /// through a verifier, the profile selected from the snapshot.
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
        let profile = snapshot
            .profile(caller.profile)
            .ok_or_else(|| format!("no profile `{}`", caller.profile))?;
        Ok((
            snapshot,
            CallerContext {
                principal: common::proved(principal),
                delegation: delegation.map(common::proved),
                profile: profile.clone(),
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

fn observed(verdict: &Verdict) -> Expected {
    match verdict {
        Verdict::Allow(_) => Expected::Allow,
        Verdict::Deny { reason, .. } => Expected::Deny {
            reason: reason.kind(),
            sentence: reason.sentence(),
        },
    }
}

#[test]
fn every_decision_case_holds() {
    let (world, cases, _) = load();
    let mut failures = Vec::new();
    for case in &cases {
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
        let got = observed(decision.verdict());
        if got != case.expect {
            failures.push(format!(
                "case `{}`:\n    expected {:?}\n    got      {:?}",
                case.name, case.expect, got
            ));
        }
        if decision.policy_revision() != snapshot.revision() {
            failures.push(format!("case `{}`: wrong policy revision", case.name));
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
