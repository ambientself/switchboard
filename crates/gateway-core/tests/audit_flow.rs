//! The audited path, begin to finish, against an in-memory store.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::sync::{Arc, Mutex};

use gateway_core::audit::{
    self, Answer, AuditFailure, Begun, Completion, DecisionKind, MAX_RECORDED_IDENTIFIER,
    MAX_RECORDED_RESOURCES, Outcome, RecordedResource, RecordedResources, RequestMetadata,
};
use gateway_core::{
    ApprovedTool, AuditRecord, AuditStore, BoxFuture, CallContext, CallerContext, Claimed,
    Classification, Connector, ConnectorName, Decision, Delegation, PolicySnapshot, Principal,
    PrincipalId, PrincipalKind, PrincipalRestriction, Profile, Reason, ReasonKind, RequestedTool,
    Resource, ResourceDeclaration, ResourceLimits, ResourceProblem, Resources, SnapshotData,
    Surface, TeamId, ToolCall, ToolOutcome, decide,
};
use serde_json::json;

use common::{MemoryStore, tool_name};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// A connector that records each call it was given, and answers with a fixed outcome.
struct RecordingConnector {
    outcome: ToolOutcome,
    calls: Mutex<Vec<(String, serde_json::Value)>>,
}

impl RecordingConnector {
    fn answering(outcome: ToolOutcome) -> Self {
        Self {
            outcome,
            calls: Mutex::default(),
        }
    }

    fn calls(&self) -> Vec<(String, serde_json::Value)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Connector for RecordingConnector {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        self.calls
            .lock()
            .unwrap()
            .push((call.tool().name.to_string(), call.arguments().clone()));
        Box::pin(ready(self.outcome.clone()))
    }
}

fn tool(name: &str, classification: Classification) -> ApprovedTool {
    ApprovedTool {
        name: tool_name(name),
        classification,
        connector: "fixture".into(),
        resources: ResourceDeclaration::NoResources,
    }
}

fn surface(name: &str, tools: &[&str]) -> Surface {
    Surface {
        name: name.into(),
        tools: tools.iter().map(|&tool| tool_name(tool)).collect(),
        teams: ["payments".into()].into(),
        groups: BTreeSet::new(),
        principals: PrincipalRestriction::AnyInTeamsAndGroups,
    }
}

/// `fixture__elsewhere` is approved, on a surface other than `fixture`, unless `elsewhere` is
/// false, in which case it is approved nowhere.
fn snapshot_with(elsewhere: bool) -> PolicySnapshot {
    let mut tools = vec![
        tool("fixture__read", Classification::Read),
        tool("fixture__propose", Classification::Propose),
    ];
    let mut surfaces = vec![surface("fixture", &["fixture__read", "fixture__propose"])];
    if elsewhere {
        tools.push(tool("fixture__elsewhere", Classification::Read));
        surfaces.push(surface("other", &["fixture__elsewhere"]));
    }
    PolicySnapshot::new(SnapshotData {
        revision: "audit-1".into(),
        tools,
        surfaces,
        profiles: vec![Profile {
            name: "readers".into(),
            classifications: [Classification::Read].into(),
            requires_delegation: true,
        }],
        limits: limits(),
    })
    .unwrap()
}

fn snapshot() -> PolicySnapshot {
    snapshot_with(true)
}

/// A GitHub repository named `org/{name}`.
fn repository(name: &str) -> Resource {
    Resource {
        system: "github".into(),
        kind: "repository".into(),
        identifier: format!("org/{name}"),
    }
}

/// How many repositories the payments team may reach: more than a row records.
const PERMITTED: usize = 100;

/// The payments team may reach `org/repo-0` to `org/repo-99`, and nothing else.
fn limits() -> ResourceLimits {
    ResourceLimits {
        teams: [(
            TeamId::new("payments"),
            (0..PERMITTED)
                .map(|n| repository(&format!("repo-{n}")))
                .collect(),
        )]
        .into(),
        groups: BTreeMap::new(),
    }
}

fn principal() -> Principal {
    Principal {
        id: PrincipalId {
            issuer: "https://cluster-a.example.test".into(),
            subject: "system:serviceaccount:otto:sandbox-payments".into(),
        },
        kind: PrincipalKind::Workload {
            team: "payments".into(),
        },
    }
}

fn call(tool: &str) -> CallContext {
    let delegation = Delegation {
        acting_person: Claimed::new("requester@example.test".into()),
        team: "payments".into(),
        tools: ["fixture__read", "fixture__propose", "fixture__elsewhere"]
            .map(tool_name)
            .into(),
    };
    CallContext {
        caller: CallerContext {
            principal: common::proved(&principal()),
            delegation: Some(common::proved(&delegation)),
            profile: "readers".into(),
            surface: "fixture".into(),
            deployment: "test".into(),
        },
        tool: RequestedTool::new(tool),
        resources: Resources::Named(Vec::new()),
    }
}

fn metadata() -> RequestMetadata {
    RequestMetadata {
        tool_use_id: Some("toolu_fixture_1".into()),
        claimed_team: Some(Claimed::new(TeamId::new("search"))),
    }
}

fn begin(store: &dyn AuditStore, decision: Decision) -> Begun {
    common::ready(audit::begin(
        store,
        common::start(),
        decision,
        json!({"path": "README.md"}),
        metadata(),
    ))
    .unwrap()
}

fn allowed(store: &dyn AuditStore, tool: &str) -> gateway_core::AuditGuard {
    match begin(store, decide(&snapshot(), &call(tool))) {
        Begun::Allowed(guard) => guard,
        Begun::Denied(refusal) => panic!("expected a guard, got {refusal:?}"),
    }
}

fn denied(store: &dyn AuditStore, decision: Decision) -> audit::Refusal {
    match begin(store, decision) {
        Begun::Denied(refusal) => refusal,
        Begun::Allowed(guard) => panic!("expected a refusal, got {guard:?}"),
    }
}

#[test]
fn an_allowed_call_runs_its_own_arguments_once_and_completes_its_row() {
    let store = MemoryStore::default();
    let connector = RecordingConnector::answering(ToolOutcome::Ok(json!({"text": "hello"})));

    let guard = allowed(&store, "fixture__read");
    let rows = store.rows();
    assert_eq!(
        rows.len(),
        1,
        "the row must exist before the guard is handed out"
    );
    assert_eq!(rows[0].decision, DecisionKind::Allow);
    assert_eq!(rows[0].reason, None);
    assert_eq!(rows[0].sentence, None);
    assert_eq!(
        rows[0].completion, None,
        "the outcome is empty until finish"
    );
    assert_eq!(guard.tool().name.as_str(), "fixture__read");
    assert_eq!(store.ids(), vec![guard.row().clone()]);

    let ran = common::ready(audit::run(&connector, guard));
    assert_eq!(
        connector.calls(),
        vec![("fixture__read".to_owned(), json!({"path": "README.md"}))]
    );
    let finished = common::ready(audit::finish(&store, ran, 12));
    assert_eq!(finished.answer(), &Answer::Ok(json!({"text": "hello"})));
    assert!(finished.failure().is_none());
    assert_eq!(
        store.rows()[0].completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 12,
        })
    );
}

#[test]
fn finish_completes_the_row_its_call_began_and_no_other() {
    let store = MemoryStore::default();
    let connector = RecordingConnector::answering(ToolOutcome::Error("upstream 503".into()));
    let first = allowed(&store, "fixture__read");
    let second = allowed(&store, "fixture__read");
    let third = allowed(&store, "fixture__read");
    let ran = common::ready(audit::run(&connector, second));
    let finished = common::ready(audit::finish(&store, ran, 7));
    assert_eq!(finished.answer(), &Answer::Error("upstream 503".into()));
    let completions: Vec<_> = store.rows().into_iter().map(|row| row.completion).collect();
    assert_eq!(
        completions,
        vec![
            None,
            Some(Completion {
                outcome: Outcome::Error,
                latency_ms: 7,
            }),
            None,
        ]
    );
    drop((first, third));
}

#[test]
fn a_denial_returns_exactly_the_sentence_its_row_holds_and_is_never_completed() {
    let store = MemoryStore::default();
    let refusal = denied(&store, decide(&snapshot(), &call("fixture__propose")));
    let rows = store.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision, DecisionKind::Deny);
    assert_eq!(rows[0].reason, Some(ReasonKind::ClassificationNotPermitted));
    assert_eq!(rows[0].classification, Some(Classification::Propose));
    assert_eq!(rows[0].connector, Some(ConnectorName::from("fixture")));
    assert_eq!(rows[0].sentence.as_deref(), Some(refusal.sentence()));
    assert_eq!(
        refusal.sentence(),
        "Tool `fixture__propose` is classified `propose`, which profile `readers` does not permit. Choose a tool whose classification this profile permits."
    );
    assert_eq!(rows[0].completion, None);
    assert_eq!(store.ids(), vec![refusal.row().clone()]);
}

#[test]
fn an_unknown_tool_and_a_tool_on_another_surface_read_the_same_and_record_apart() {
    let (on_another, unknown) = (MemoryStore::default(), MemoryStore::default());
    let first = denied(
        &on_another,
        decide(&snapshot_with(true), &call("fixture__elsewhere")),
    );
    let second = denied(
        &unknown,
        decide(&snapshot_with(false), &call("fixture__elsewhere")),
    );
    assert_eq!(first.sentence().as_bytes(), second.sentence().as_bytes());
    assert_eq!(
        first.sentence(),
        "Tool `fixture__elsewhere` is not available on surface `fixture`. Call `tools/list` to see the tools this surface serves."
    );
    assert_eq!(on_another.last().reason, Some(ReasonKind::ToolNotOnSurface));
    assert_eq!(unknown.last().reason, Some(ReasonKind::UnknownTool));
    for row in [on_another.last(), unknown.last()] {
        assert_eq!(
            row.classification, None,
            "a tool the surface does not serve"
        );
        assert_eq!(row.connector, None);
        assert_eq!(row.tool, "fixture__elsewhere");
    }
}

#[test]
fn a_store_that_cannot_begin_refuses_an_allowed_call() {
    let store = MemoryStore {
        fail_begin: true,
        ..MemoryStore::default()
    };
    let decision = decide(&snapshot(), &call("fixture__read"));
    assert!(decision.is_allowed());
    let failure: AuditFailure = common::ready(audit::begin(
        &store,
        common::start(),
        decision,
        json!({}),
        metadata(),
    ))
    .expect_err("a store that cannot write must refuse the call");
    assert_eq!(failure.sentence(), AUDIT_FAILURE);
    assert_ne!(failure.sentence(), gateway_core::IDENTITY_FAILURE);
    assert!(store.rows().is_empty());
}

#[test]
fn a_store_that_cannot_begin_withholds_a_denial_too() {
    let store = MemoryStore {
        fail_begin: true,
        ..MemoryStore::default()
    };
    let decision = decide(&snapshot(), &call("fixture__propose"));
    assert!(!decision.is_allowed());
    let failure = common::ready(audit::begin(
        &store,
        common::start(),
        decision,
        json!({}),
        metadata(),
    ))
    .expect_err("a denial with no row must not be answered with its sentence");
    assert_eq!(failure.sentence(), AUDIT_FAILURE);
}

#[test]
fn proved_and_claimed_values_are_separate_columns() {
    let store = MemoryStore::default();
    let _guard = allowed(&store, "fixture__read");
    let row = serde_json::to_value(store.last()).unwrap();

    assert_eq!(row["proved_principal"]["team"], "payments");
    assert_eq!(
        row["proved_principal"]["id"]["issuer"],
        "https://cluster-a.example.test"
    );
    assert_eq!(row["proved_delegation_team"], "payments");
    assert_eq!(row["claimed_acting_person"], "requester@example.test");
    assert_eq!(row["claimed_team"], "search");
    assert_eq!(row["tool_use_id"], "toolu_fixture_1");
    assert_eq!(row["deployment"], "test");
    assert_eq!(row["surface"], "fixture");
    assert_eq!(row["profile"], "readers");
    assert_eq!(row["connector"], "fixture");
    assert_eq!(row["classification"], "read");
    assert_eq!(row["policy_revision"], "audit-1");
    assert_eq!(row["completion"], serde_json::Value::Null);
}

#[test]
fn a_connector_refusal_reaches_the_caller_only_as_its_row_records_it() {
    let store = MemoryStore::default();
    let sentence = "Repository `example-org/other` is outside the scope of team `payments`.";
    let connector = RecordingConnector::answering(ToolOutcome::Refused(sentence.into()));
    let ran = common::ready(audit::run(&connector, allowed(&store, "fixture__read")));
    let finished = common::ready(audit::finish(&store, ran, 3));
    assert_eq!(finished.answer(), &Answer::Refused(sentence.into()));
    let row = store.last();
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Refused {
                sentence: sentence.into(),
            },
            latency_ms: 3,
        })
    );
}

#[test]
fn begin_writes_the_row_under_the_identifier_it_is_given_once() {
    let store = MemoryStore::default();
    let start = common::start();
    let begin_again = |decision| {
        common::ready(audit::begin(
            &store,
            start.clone(),
            decision,
            json!({}),
            metadata(),
        ))
    };
    let Ok(Begun::Allowed(guard)) = begin_again(decide(&snapshot(), &call("fixture__read"))) else {
        panic!("expected a guard");
    };
    assert_eq!(guard.row(), &start.row);
    let Ok(Begun::Allowed(retried)) = begin_again(decide(&snapshot(), &call("fixture__read")))
    else {
        panic!("a retried begin with the same decision must succeed");
    };
    assert_eq!(retried.row(), &start.row);
    assert_eq!(store.ids(), vec![start.row.clone()], "one row, not two");

    let refused = begin_again(decide(&snapshot(), &call("fixture__propose")));
    assert!(
        matches!(refused, Err(ref failure) if failure.sentence() == AUDIT_FAILURE),
        "a begin with a known identifier and another decision must fail"
    );
    assert_eq!(store.rows().len(), 1);
    assert_eq!(
        store.last().decision,
        DecisionKind::Allow,
        "the first row stands"
    );
}

#[test]
fn the_test_store_accepts_an_identical_second_completion_and_refuses_a_different_one() {
    let store = MemoryStore::default();
    let start = common::start();
    // Each pass begins the same row, which a retried begin may, runs and finishes it.
    let finish_again = |latency_ms| {
        let connector = RecordingConnector::answering(ToolOutcome::Ok(json!(1)));
        let decision = decide(&snapshot(), &call("fixture__read"));
        let Ok(Begun::Allowed(guard)) = common::ready(audit::begin(
            &store,
            start.clone(),
            decision,
            json!({}),
            metadata(),
        )) else {
            panic!("a begin of an allowed row must give a guard");
        };
        let ran = common::ready(audit::run(&connector, guard));
        common::ready(audit::finish(&store, ran, latency_ms))
    };
    assert!(finish_again(5).failure().is_none());
    assert_eq!(
        store.last().completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 5,
        })
    );
    assert!(
        finish_again(5).failure().is_none(),
        "an identical second completion is accepted"
    );
    assert!(
        finish_again(6).failure().is_some(),
        "a different second completion is refused"
    );
    assert_eq!(store.rows().len(), 1);
    assert_eq!(
        store.last().completion.map(|done| done.latency_ms),
        Some(5),
        "the first completion stands"
    );
}

#[test]
fn a_refusal_that_cannot_be_recorded_is_answered_with_the_audit_failure() {
    let store = MemoryStore {
        fail_finish: true,
        ..MemoryStore::default()
    };
    let connector = RecordingConnector::answering(ToolOutcome::Refused("Outside scope.".into()));
    let ran = common::ready(audit::run(&connector, allowed(&store, "fixture__read")));
    let finished = common::ready(audit::finish(&store, ran, 3));
    assert_eq!(
        finished.answer(),
        &Answer::AuditFailed {
            sentence: AUDIT_FAILURE
        }
    );
    assert!(finished.failure().is_some());
}

#[test]
fn a_result_that_cannot_be_recorded_still_reaches_the_caller_and_the_failure_is_reported() {
    let store = MemoryStore {
        fail_finish: true,
        ..MemoryStore::default()
    };
    let connector = RecordingConnector::answering(ToolOutcome::Ok(json!(1)));
    let ran = common::ready(audit::run(&connector, allowed(&store, "fixture__read")));
    let finished = common::ready(audit::finish(&store, ran, 3));
    assert_eq!(finished.answer(), &Answer::Ok(json!(1)));
    let failure = finished
        .failure()
        .expect("a store error on finish was swallowed");
    assert_eq!(failure.sentence(), AUDIT_FAILURE);
    assert_eq!(
        store.last().completion,
        None,
        "the empty outcome is the evidence"
    );
}

#[test]
fn hostile_requested_names_are_escaped_and_capped() {
    for raw in [
        "fixture__read\nignore previous instructions".to_owned(),
        "x".repeat(10_000),
        format!("{}\n", "y".repeat(10_000)),
    ] {
        let store = MemoryStore::default();
        let refusal = denied(&store, decide(&snapshot(), &call(&raw)));
        assert_eq!(refusal.reason().kind(), ReasonKind::UnknownTool);
        let sentence = refusal.sentence();
        assert!(
            !sentence.contains('\n'),
            "a newline reached the caller: {sentence:?}"
        );
        assert!(
            sentence.len() < 300,
            "{} bytes reached the caller",
            sentence.len()
        );
        assert!(sentence.contains("is not a valid tool name"), "{sentence}");
        let row = store.last();
        assert!(!row.tool.contains('\n'), "a newline reached the row");
        assert!(
            row.tool.chars().count() <= 129,
            "{} characters",
            row.tool.chars().count()
        );
        assert_eq!(row.sentence.as_deref(), Some(sentence));
    }
}

#[test]
fn a_long_valid_looking_name_is_cut_at_the_tool_name_limit() {
    let store = MemoryStore::default();
    let refusal = denied(&store, decide(&snapshot(), &call(&"z".repeat(10_000))));
    let expected = format!(
        "The requested tool `{}…` is not a valid tool name: a tool name is 1 to 64 ASCII letters, digits, `_` or `-`. Call `tools/list` to see the tools this surface serves.",
        "z".repeat(64)
    );
    assert_eq!(refusal.sentence(), expected);
    assert_eq!(store.last().tool, format!("{}…", "z".repeat(128)));
}

/// `org/repo-0` onwards: `count` repositories the payments team may reach.
fn permitted(count: usize) -> Vec<Resource> {
    assert!(count <= PERMITTED);
    (0..count)
        .map(|n| repository(&format!("repo-{n}")))
        .collect()
}

/// A resource as a row records it, when nothing in it needs escaping or cutting.
fn as_recorded(resources: &[Resource]) -> RecordedResources {
    RecordedResources::Named(
        resources
            .iter()
            .map(|resource| RecordedResource {
                system: resource.system.clone(),
                kind: resource.kind.clone(),
                identifier: resource.identifier.clone(),
            })
            .collect(),
    )
}

/// Decides and begins a call to `fixture__read` naming `resources`. Returns the refusal, if it
/// was denied, and what its row records.
fn record_call(resources: Resources) -> (Option<audit::Refusal>, RecordedResources, usize) {
    let store = MemoryStore::default();
    let mut call = call("fixture__read");
    call.resources = resources;
    let refusal = match begin(&store, decide(&snapshot(), &call)) {
        Begun::Allowed(_) => None,
        Begun::Denied(refusal) => Some(refusal),
    };
    let row = store.last();
    (refusal, row.resources, row.resources_omitted)
}

/// The identifier a single named resource is recorded with, and its system and kind.
fn record_one(resource: Resource) -> RecordedResource {
    match record_call(Resources::Named(vec![resource])).1 {
        RecordedResources::Named(mut recorded) if recorded.len() == 1 => recorded.remove(0),
        recorded => panic!("one named resource was recorded as {recorded:?}"),
    }
}

#[test]
fn a_row_records_the_resources_its_call_named() {
    let (refusal, recorded, omitted) = record_call(Resources::Unknown);
    assert_eq!(
        refusal.map(|refusal| refusal.reason().kind()),
        Some(ReasonKind::ResourceOutsideLimit)
    );
    assert_eq!((recorded, omitted), (RecordedResources::Unknown, 0));

    let (refusal, recorded, omitted) = record_call(Resources::Named(Vec::new()));
    assert!(refusal.is_none());
    assert_eq!((recorded, omitted), (as_recorded(&[]), 0));

    // The most a row records, written as a number: the constant is what is under test, so
    // comparing it with itself would prove nothing.
    let most = 64;
    assert_eq!(MAX_RECORDED_RESOURCES, most);
    let exactly = permitted(most);
    let (refusal, recorded, omitted) = record_call(Resources::Named(exactly.clone()));
    assert!(refusal.is_none());
    assert_eq!(
        (recorded, omitted),
        (as_recorded(&exactly), 0),
        "a call naming exactly the most a row records loses none"
    );

    let mut many = permitted(most + 6);
    many.reverse();
    let (refusal, recorded, omitted) = record_call(Resources::Named(many.clone()));
    assert!(refusal.is_none());
    assert_eq!(
        (recorded, omitted),
        (as_recorded(&many[..most]), 6),
        "the first named are kept, in the order named, and the rest counted"
    );
}

/// Naming one resource many times cannot push another off the row: a repeat is recorded once
/// and not counted.
#[test]
fn a_repeated_resource_is_recorded_once() {
    let [first, second, third] = [0, 1, 2].map(|n| repository(&format!("repo-{n}")));
    let mut named = vec![first.clone(); MAX_RECORDED_RESOURCES];
    named.push(second.clone());
    named.extend(vec![first.clone(); 10]);
    named.push(third.clone());
    named.push(second.clone());
    let (refusal, recorded, omitted) = record_call(Resources::Named(named));
    assert!(refusal.is_none());
    assert_eq!(
        (recorded, omitted),
        (as_recorded(&[first, second, third]), 0)
    );

    let outside = repository("outside");
    let mut named = vec![repository("repo-0"); 200];
    named.push(outside.clone());
    let (refusal, recorded, omitted) = record_call(Resources::Named(named));
    let refusal = refusal.expect("a resource outside the limit was allowed");
    assert!(refusal.sentence().contains("`org/outside`"), "{refusal:?}");
    assert_eq!(
        (recorded, omitted),
        (as_recorded(&[repository("repo-0"), outside]), 0)
    );
}

/// The decision checks every resource a call names, however many: one outside the limit is
/// denied wherever it falls. The row always records the resource the denial names, taking the
/// place of the last one kept when it falls past them.
#[test]
fn a_resource_outside_the_limit_is_denied_and_recorded_wherever_it_falls() {
    let outside = repository("outside");
    for position in [0, 3, 62, 63, 64, 65, 99, PERMITTED] {
        let mut named = permitted(PERMITTED);
        named.insert(position, outside.clone());
        let (refusal, recorded, omitted) = record_call(Resources::Named(named.clone()));

        let refusal = refusal.unwrap_or_else(|| panic!("allowed at position {position}"));
        match refusal.reason() {
            Reason::ResourceOutsideLimit(ResourceProblem::Outside { resource, .. }) => {
                assert_eq!(resource, &outside, "position {position}");
            }
            reason => panic!("position {position}: denied for {reason:?}"),
        }
        assert!(
            refusal.sentence().contains("`org/outside`"),
            "position {position}: {}",
            refusal.sentence()
        );

        let mut expected = named[..MAX_RECORDED_RESOURCES].to_vec();
        if position >= MAX_RECORDED_RESOURCES {
            expected[MAX_RECORDED_RESOURCES - 1] = outside.clone();
        }
        assert_eq!(
            (recorded, omitted),
            (
                as_recorded(&expected),
                PERMITTED + 1 - MAX_RECORDED_RESOURCES
            ),
            "position {position}"
        );
    }

    let (refusal, _, _) = record_call(Resources::Named(permitted(PERMITTED)));
    assert!(
        refusal.is_none(),
        "every resource is within the limit, past the cap as well"
    );
}

#[test]
fn recorded_values_are_escaped_reversibly() {
    let named = |identifier: &str| Resource {
        identifier: identifier.into(),
        ..repository("")
    };
    assert_eq!(record_one(named("org/a\nb`c")).identifier, "org/a\\nb\\`c");
    assert_eq!(record_one(named("org/a\\nb")).identifier, "org/a\\\\nb");
    assert_eq!(record_one(named("caf\u{e9}")).identifier, "caf\\u{e9}");
    let mut distinct = BTreeSet::new();
    for raw in [
        "a\nb", "a\\nb", "a\\\\nb", "a`b", "a\\`b", "\u{e9}", "\\u{e9}",
    ] {
        assert!(
            distinct.insert(record_one(named(raw)).identifier),
            "{raw:?} is recorded like another identifier"
        );
    }

    let recorded = record_one(Resource {
        system: "git\rhub".into(),
        kind: "repo`sit\\ory".into(),
        identifier: "org/a".into(),
    });
    assert_eq!(recorded.system, "git\\rhub");
    assert_eq!(recorded.kind, "repo\\`sit\\\\ory");
}

/// Each identifier length checked in `docs/systems.md` fits whole; only a longer one is cut.
#[test]
fn recorded_values_are_capped() {
    let named = |identifier: String| Resource {
        identifier,
        ..repository("")
    };
    let longest_github = format!("{}/{}", "o".repeat(39), "r".repeat(100));
    assert_eq!(
        record_one(named(longest_github.clone())).identifier,
        longest_github,
        "the longest GitHub repository name is cut"
    );
    // The longest AWS ARN, written as a number: the constant is what is under test, so
    // comparing it with itself would prove nothing.
    let longest_arn = 2048;
    assert_eq!(MAX_RECORDED_IDENTIFIER, longest_arn);
    for (raw, recorded) in [
        ("x".repeat(longest_arn), "x".repeat(longest_arn)),
        (
            "x".repeat(longest_arn + 1),
            format!("{}…", "x".repeat(longest_arn)),
        ),
        (
            format!("{}\n", "x".repeat(longest_arn - 1)),
            format!("{}…", "x".repeat(longest_arn - 1)),
        ),
    ] {
        assert_eq!(record_one(named(raw)).identifier, recorded);
    }

    for (raw, recorded) in [
        ("s".repeat(128), "s".repeat(128)),
        ("s".repeat(129), format!("{}…", "s".repeat(128))),
    ] {
        let resource = record_one(Resource {
            system: raw.clone(),
            kind: raw,
            identifier: "org/a".into(),
        });
        assert_eq!(resource.system, recorded);
        assert_eq!(resource.kind, recorded);
    }
}

#[test]
fn the_record_serializes_under_pinned_names_and_reads_back() {
    let pins = [
        (json!(RecordedResources::Unknown), json!("unknown")),
        (
            json!(as_recorded(&[repository("a")])),
            json!({"named": [{"system": "github", "kind": "repository", "identifier": "org/a"}]}),
        ),
        (json!(DecisionKind::Allow), json!("allow")),
        (json!(DecisionKind::Deny), json!("deny")),
        (
            json!(Completion {
                outcome: Outcome::Ok,
                latency_ms: 5
            }),
            json!({"outcome": "ok", "latency_ms": 5}),
        ),
        (
            json!(Completion {
                outcome: Outcome::Error,
                latency_ms: 6
            }),
            json!({"outcome": "error", "latency_ms": 6}),
        ),
        (
            json!(Completion {
                outcome: Outcome::Refused {
                    sentence: "No.".into()
                },
                latency_ms: 7
            }),
            json!({"outcome": "refused", "sentence": "No.", "latency_ms": 7}),
        ),
    ];
    for (got, want) in pins {
        assert_eq!(got, want);
    }

    let store = MemoryStore::default();
    let connector = RecordingConnector::answering(ToolOutcome::Refused("No.".into()));
    let ran = common::ready(audit::run(&connector, allowed(&store, "fixture__read")));
    let _ = common::ready(audit::finish(&store, ran, 7));
    let _ = denied(&store, decide(&snapshot(), &call("fixture__propose")));
    let mut named = permitted(MAX_RECORDED_RESOURCES + 3);
    named.insert(1, repository("a\\b\n`c\u{e9}"));
    let mut resourceful = call("fixture__read");
    resourceful.resources = Resources::Named(named);
    let _ = denied(&store, decide(&snapshot(), &resourceful));
    let row = store.last();
    assert_eq!(row.resources_omitted, 4);
    assert!(
        matches!(&row.resources, RecordedResources::Named(recorded)
            if recorded[1].identifier == "org/a\\\\b\\n\\`c\\u{e9}"),
        "{:?}",
        row.resources
    );
    for row in store.rows() {
        let text = serde_json::to_string(&row).unwrap();
        let back: AuditRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(back, row);
    }
    let mut unknown = serde_json::to_value(store.last()).unwrap();
    unknown["extra"] = json!(1);
    assert!(serde_json::from_value::<AuditRecord>(unknown).is_err());
    let mut unknown = serde_json::to_value(store.last()).unwrap();
    unknown["resources"]["named"][0]["extra"] = json!(1);
    assert!(
        serde_json::from_value::<AuditRecord>(unknown).is_err(),
        "a recorded resource with a field it does not have was read"
    );
}

/// Connectors of different kinds in one registry, and one store behind an `Arc`: what the
/// next slice's server state will hold.
#[test]
fn connectors_and_stores_work_as_trait_objects() {
    let store: Arc<dyn AuditStore> = Arc::new(MemoryStore::default());
    let mut registry: BTreeMap<ConnectorName, Box<dyn Connector>> = BTreeMap::new();
    registry.insert(
        "fixture".into(),
        Box::new(RecordingConnector::answering(ToolOutcome::Ok(json!("a")))),
    );
    registry.insert(
        "other".into(),
        Box::new(RecordingConnector::answering(ToolOutcome::Ok(json!("b")))),
    );
    let guard = match begin(store.as_ref(), decide(&snapshot(), &call("fixture__read"))) {
        Begun::Allowed(guard) => guard,
        Begun::Denied(refusal) => panic!("{refusal:?}"),
    };
    let connector = registry[&guard.tool().connector].as_ref();
    let ran = common::ready(audit::run(connector, guard));
    let finished = common::ready(audit::finish(store.as_ref(), ran, 1));
    assert_eq!(finished.answer(), &Answer::Ok(json!("a")));
}
