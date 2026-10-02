//! The audit begin step, the guard, and the record it writes, against an in-memory store.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::future::{Future, ready};
use std::sync::Mutex;

use gateway_core::audit::{
    self, AuditFailure, AuditRowId, Begun, Completion, DecisionKind, Outcome, RequestMetadata,
};
use gateway_core::{
    ApprovedTool, AuditGuard, AuditRecord, AuditStore, CallContext, CallerContext, Claimed,
    Classification, Connector, Delegation, PolicySnapshot, Principal, PrincipalId, PrincipalKind,
    Profile, ReasonKind, Resources, SnapshotData, Surface, TeamId, decide, sentences,
};

#[derive(Debug, thiserror::Error)]
#[error("the store is down")]
struct StoreDown;

#[derive(Default)]
struct MemoryStore {
    down: bool,
    rows: Mutex<Vec<AuditRecord>>,
}

impl MemoryStore {
    fn rows(&self) -> Vec<AuditRecord> {
        self.rows.lock().unwrap().clone()
    }
}

impl AuditStore for MemoryStore {
    type Error = StoreDown;

    fn begin(
        &self,
        record: &AuditRecord,
    ) -> impl Future<Output = Result<AuditRowId, StoreDown>> + Send {
        let result = if self.down {
            Err(StoreDown)
        } else {
            let mut rows = self.rows.lock().unwrap();
            rows.push(record.clone());
            Ok(AuditRowId::new((rows.len() - 1).to_string()))
        };
        ready(result)
    }

    fn finish(
        &self,
        row: &AuditRowId,
        completion: &Completion,
    ) -> impl Future<Output = Result<(), StoreDown>> + Send {
        let index: usize = row.as_str().parse().unwrap();
        self.rows.lock().unwrap()[index].completion = Some(completion.clone());
        ready(Ok(()))
    }
}

/// A connector that records which tool it was asked to run.
#[derive(Default)]
struct RecordingConnector {
    ran: Mutex<Vec<ApprovedTool>>,
}

impl Connector for RecordingConnector {
    type Output = ();

    fn run(
        &self,
        guard: &AuditGuard,
        _arguments: &serde_json::Value,
    ) -> impl Future<Output = ()> + Send {
        self.ran.lock().unwrap().push(guard.tool().clone());
        ready(())
    }
}

fn tool(name: &str, classification: Classification) -> ApprovedTool {
    ApprovedTool {
        name: name.into(),
        classification,
        connector: "fixture".into(),
        declares_resources: false,
        checks_own_scope: false,
    }
}

fn snapshot() -> PolicySnapshot {
    PolicySnapshot::new(SnapshotData {
        revision: "audit-1".into(),
        tools: vec![
            tool("fixture__read", Classification::Read),
            tool("fixture__write", Classification::Write),
        ],
        surfaces: vec![Surface {
            name: "fixture".into(),
            tools: ["fixture__read".into(), "fixture__write".into()].into(),
            teams: ["payments".into()].into(),
            groups: BTreeSet::new(),
            subjects: None,
        }],
        profiles: vec![],
        limits: Default::default(),
    })
    .unwrap()
}

fn call(tool: &str) -> CallContext {
    let principal = Principal {
        id: PrincipalId {
            issuer: "https://cluster-a.example.test".into(),
            subject: "system:serviceaccount:otto:sandbox-payments".into(),
        },
        kind: PrincipalKind::Workload {
            team: "payments".into(),
        },
    };
    let delegation = Delegation {
        acting_person: Claimed::new("requester@example.test".into()),
        team: "payments".into(),
        tools: None,
    };
    CallContext {
        caller: CallerContext {
            principal: common::proved(&principal),
            delegation: Some(common::proved(&delegation)),
            profile: Profile {
                name: "readers".into(),
                classifications: [Classification::Read].into(),
                requires_delegation: true,
            },
            surface: "fixture".into(),
            deployment: "test".into(),
        },
        tool: tool.into(),
        resources: Resources::Named(Vec::new()),
    }
}

fn metadata() -> RequestMetadata {
    RequestMetadata {
        tool_use_id: Some("toolu_fixture_1".into()),
        claimed_team: Some(Claimed::new(TeamId::new("search"))),
    }
}

#[test]
fn an_allowed_call_writes_its_row_before_the_guard_exists_and_runs_the_decided_tool() {
    let store = MemoryStore::default();
    let connector = RecordingConnector::default();
    let decision = decide(&snapshot(), &call("fixture__read"));
    assert!(decision.is_allowed());

    let begun = common::ready(audit::begin(&store, decision, metadata())).unwrap();
    let Begun::Allowed(guard) = begun else {
        panic!("an allowed decision did not produce a guard: {begun:?}");
    };
    let rows = store.rows();
    assert_eq!(
        rows.len(),
        1,
        "the row must exist before the guard is handed out"
    );
    let row = &rows[0];
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(row.reason, None);
    assert_eq!(row.sentence, None);
    assert_eq!(row.classification, Some(Classification::Read));
    assert_eq!(row.completion, None, "the outcome is empty until finish");
    assert_eq!(row.policy_revision.as_str(), "audit-1");
    assert_eq!(guard.tool().name.as_str(), "fixture__read");

    common::ready(connector.run(&guard, &serde_json::json!({})));
    assert_eq!(
        connector.ran.lock().unwrap().clone(),
        vec![guard.tool().clone()]
    );

    let completion = Completion {
        outcome: Outcome::Ok,
        latency_ms: 12,
    };
    common::ready(audit::finish(&store, guard, completion.clone())).unwrap();
    assert_eq!(store.rows()[0].completion, Some(completion));
}

#[test]
fn a_denial_returns_exactly_the_sentence_its_row_holds() {
    let store = MemoryStore::default();
    let decision = decide(&snapshot(), &call("fixture__write"));
    let expected = decision.reason().unwrap().sentence();

    let begun = common::ready(audit::begin(&store, decision, metadata())).unwrap();
    let Begun::Denied(refusal) = begun else {
        panic!("a denied decision produced a guard: {begun:?}");
    };
    let rows = store.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision, DecisionKind::Deny);
    assert_eq!(rows[0].reason, Some(ReasonKind::ClassificationNotPermitted));
    assert_eq!(rows[0].classification, Some(Classification::Write));
    assert_eq!(rows[0].sentence.as_deref(), Some(refusal.sentence()));
    assert_eq!(refusal.sentence(), expected);
    assert_eq!(refusal.row(), &AuditRowId::new("0"));
}

#[test]
fn a_denial_for_an_unknown_tool_records_no_classification() {
    let store = MemoryStore::default();
    let decision = decide(&snapshot(), &call("fixture__missing"));
    let begun = common::ready(audit::begin(&store, decision, metadata())).unwrap();
    assert!(matches!(begun, Begun::Denied(_)));
    let rows = store.rows();
    assert_eq!(rows[0].reason, Some(ReasonKind::UnknownTool));
    assert_eq!(rows[0].classification, None);
    assert_eq!(rows[0].connector, None);
    assert_eq!(rows[0].tool.as_str(), "fixture__missing");
}

#[test]
fn an_audit_failure_refuses_the_call_with_its_own_sentence() {
    let store = MemoryStore {
        down: true,
        ..MemoryStore::default()
    };
    let decision = decide(&snapshot(), &call("fixture__read"));
    assert!(decision.is_allowed());
    let failure: AuditFailure = common::ready(audit::begin(&store, decision, metadata()))
        .expect_err("a store that cannot write must refuse the call");
    assert_eq!(failure.sentence(), sentences::AUDIT_FAILURE);
    assert_ne!(failure.sentence(), sentences::IDENTITY_FAILURE);
    assert!(store.rows().is_empty());
}

#[test]
fn proved_and_claimed_values_are_separate_columns() {
    let store = MemoryStore::default();
    let decision = decide(&snapshot(), &call("fixture__read"));
    let begun = common::ready(audit::begin(&store, decision, metadata())).unwrap();
    assert!(matches!(begun, Begun::Allowed(_)));
    let row = serde_json::to_value(&store.rows()[0]).unwrap();

    assert_eq!(row["proved_principal"]["team"], "payments");
    assert_eq!(
        row["proved_principal"]["id"]["issuer"],
        "https://cluster-a.example.test"
    );
    assert_eq!(row["proved_delegation_team"], "payments");
    assert_eq!(row["claimed_acting_person"], "requester@example.test");
    assert_eq!(row["claimed_team"], "search");
    assert_eq!(row["tool_use_id"], "toolu_fixture_1");
    assert_eq!(row["decision"], "allow");
    assert_eq!(row["classification"], "read");
    assert_eq!(row["completion"], serde_json::Value::Null);
}

#[test]
fn a_connector_refusal_is_recorded_on_the_same_row() {
    let store = MemoryStore::default();
    let decision = decide(&snapshot(), &call("fixture__read"));
    let Begun::Allowed(guard) = common::ready(audit::begin(&store, decision, metadata())).unwrap()
    else {
        panic!("expected a guard");
    };
    let refused = Completion {
        outcome: Outcome::Refused {
            sentence: "Repository `example-org/other` is outside team `payments`'s scope.".into(),
        },
        latency_ms: 3,
    };
    common::ready(audit::finish(&store, guard, refused)).unwrap();
    let rows = store.rows();
    assert_eq!(rows.len(), 1);
    let row = serde_json::to_value(&rows[0]).unwrap();
    assert_eq!(row["completion"]["outcome"], "refused");
    assert_eq!(row["decision"], "allow");
}
