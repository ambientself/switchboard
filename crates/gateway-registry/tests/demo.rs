//! The demo registry loads, says what the demo needs, and decides through the core as the demo
//! expects: each team reads its own project and is denied the other's, by check 6.
//!
//! Real proof: the principals come from tokens the testkit's local issuer signs and the
//! identity crate verifies. The demo file names the kind cluster's issuer; these tests swap in
//! the testkit's workload issuer, which is the only change.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use gateway_core::{
    CallContext, CallerContext, Classification, CredentialMode, EntryKind, Narrowing, ReasonKind,
    Resource, ResourceDeclaration, ResourceProblem, Resources, ToolName, Verdict, decide,
    list_tools,
};
use gateway_registry::{Credential, Destination, Registry, binding_sha256};
use gateway_testkit::{Caller, DEPLOYMENT, Fixture, WORKLOAD_ISSUER};
use serde_json::{Map, Value, json};

const DEMO: &str = include_str!("../demo/registry.toml");
const KIND_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

fn tool(name: &str) -> ToolName {
    ToolName::parse(name).unwrap()
}

fn project(identifier: &str) -> Resource {
    Resource {
        system: "docs".into(),
        kind: "project".into(),
        identifier: identifier.into(),
    }
}

/// Each team's entry: its server name, which is also its system and its surface, its team, its
/// team's project and the other team's.
const ENTRIES: [(&str, &str, &str, &str); 2] = [
    ("docs-team-a", "team-a", "atlas", "borealis"),
    ("docs-team-b", "team-b", "borealis", "atlas"),
];

#[test]
fn the_demo_registry_loads_from_its_file() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/registry.toml");
    let registry = Registry::load(&path).unwrap();
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.revision().as_str(), "demo-10");
    assert_eq!(registry.servers().len(), 2);

    for (entry, team, own, other) in ENTRIES {
        // One surface per team, serving only its own entry's tools.
        let surface = snapshot.surface(&entry.into()).unwrap();
        let expected = [
            tool(&format!("{entry}__list_documents")),
            tool(&format!("{entry}__read_document")),
        ];
        assert_eq!(surface.tools, expected.iter().cloned().collect());
        assert_eq!(surface.teams, [team.into()].into_iter().collect());
        for name in &expected {
            let approved = snapshot.tool(name).unwrap();
            assert_eq!(approved.classification, Classification::Read);
            assert_eq!(approved.connector.as_str(), entry);
            assert_eq!(approved.resources, ResourceDeclaration::Declared);
            let definition = &registry.definitions()[name];
            assert!(definition.read_only);
            assert_eq!(definition.input_schema["type"], "object");
            assert_eq!(registry.routes()[name].server.as_str(), entry);
        }
        assert_eq!(
            registry.routes()[&tool(&format!("{entry}__read_document"))].upstream_name,
            "read_document"
        );

        // Each entry presents its own credential. The identity is the mock server's Service
        // name, the same for both, and every approval binds its own entry.
        let server = &registry.servers()[&entry.into()];
        assert_eq!(server.system, entry);
        assert_eq!(
            server.credential,
            Credential {
                mode: CredentialMode::TeamServiceIdentity,
                reference: format!("{entry}-credential"),
                principal: entry.into(),
            }
        );
        assert_eq!(server.identity, "mock-docs.mock-docs.svc.cluster.local");
        assert_eq!(server.destination, Destination::InCluster);

        // Each entry reaches its team's project alone, unnarrowed, with a recorded test, and
        // the reach check calls its list tool for the other team's project.
        let entry_record = snapshot.entry(&entry.into()).unwrap();
        assert_eq!(entry_record.kind, EntryKind::Proxied);
        assert_eq!(entry_record.narrowing, Narrowing::None);
        assert_eq!(entry_record.permits, Classification::Read);
        assert_eq!(entry_record.reach, [project(own)].into_iter().collect());
        assert_eq!(entry_record.reach_tested_on.as_deref(), Some("2026-10-12"));
        let check = server.reach_check.as_ref().unwrap();
        assert_eq!(check.tool, tool(&format!("{entry}__list_documents")));
        assert_eq!(
            Value::Object(check.arguments.clone()),
            json!({"project": other})
        );
        for name in &expected {
            assert_eq!(
                registry.approvals()[name].binding_sha256,
                binding_sha256(server)
            );
        }
    }

    let limits = snapshot.limits();
    assert_eq!(
        limits.teams[&"team-a".into()],
        [project("atlas")].into_iter().collect()
    );
    assert_eq!(
        limits.teams[&"team-b".into()],
        [project("borealis")].into_iter().collect()
    );

    // The reach check's surface: each entry's canary tool, its reach_check's, for team
    // `registry` and, of it, only the registry's own ServiceAccount. Its limit holds both
    // projects, each entry's reach and the other's canary.
    let reach = snapshot.surface(&"registry-reach".into()).unwrap();
    let canaries: Vec<ToolName> = ENTRIES
        .iter()
        .map(|(entry, ..)| {
            let check = registry.servers()[&(*entry).into()]
                .reach_check
                .clone()
                .unwrap();
            assert_eq!(check.tool, tool(&format!("{entry}__list_documents")));
            check.tool
        })
        .collect();
    assert_eq!(reach.tools, canaries.into_iter().collect());
    assert_eq!(reach.teams, ["registry".into()].into_iter().collect());
    assert_eq!(
        serde_json::to_value(&reach.principals).unwrap(),
        json!({"only": [{"issuer": KIND_ISSUER, "subject": "system:serviceaccount:switchboard:registry"}]})
    );
    assert_eq!(
        limits.teams[&"registry".into()],
        [project("atlas"), project("borealis")]
            .into_iter()
            .collect()
    );
}

/// The demo file with the testkit's workload issuer in place of the cluster's: in its profile
/// rule, and in the one principal the reach check's surface admits.
fn registry() -> Registry {
    assert_eq!(DEMO.matches(KIND_ISSUER).count(), 2);
    Registry::from_toml_str(&DEMO.replace(KIND_ISSUER, WORKLOAD_ISSUER)).unwrap()
}

/// `who` calling on `surface`.
fn caller_on(registry: &Registry, fixture: &Fixture, who: Caller, surface: &str) -> CallerContext {
    let principal = fixture.principal(who).unwrap();
    CallerContext {
        profile: registry.select_profile(principal.get()).unwrap(),
        principal,
        delegation: None,
        surface: surface.into(),
        deployment: DEPLOYMENT.into(),
    }
}

/// `who`, team A or team B, calling on its own team's surface.
fn caller(registry: &Registry, fixture: &Fixture, who: Caller) -> CallerContext {
    let surface = match who {
        Caller::TeamB => "docs-team-b",
        _ => "docs-team-a",
    };
    caller_on(registry, fixture, who, surface)
}

fn arguments(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// Runs the gateway's order for one call: the adapter, then the decision.
fn call(registry: &Registry, caller: &CallerContext, name: &str, args: Value) -> Verdict {
    let resources = registry.adapters()[&tool(name)].resources(&arguments(args));
    decide(
        registry.snapshot(),
        &CallContext {
            caller: caller.clone(),
            tool: name.into(),
            resources,
            key: None,
            currency: gateway_core::Currency::NotAsked,
        },
    )
    .verdict()
    .clone()
}

fn denial(verdict: &Verdict) -> Option<ReasonKind> {
    match verdict {
        Verdict::Allow(_) => None,
        Verdict::Deny { reason, .. } => Some(reason.kind()),
    }
}

#[test]
fn each_team_reads_its_own_project_and_is_denied_the_other() {
    let registry = registry();
    let fixture = Fixture::new().unwrap();
    for (who, entry, own, other) in [
        (Caller::TeamA, "docs-team-a", "atlas", "borealis"),
        (Caller::TeamB, "docs-team-b", "borealis", "atlas"),
    ] {
        let caller = caller(&registry, &fixture, who);
        for name in [
            format!("{entry}__list_documents"),
            format!("{entry}__read_document"),
        ] {
            let name = name.as_str();
            let allowed = call(
                &registry,
                &caller,
                name,
                json!({"project": own, "document": "plan"}),
            );
            assert_eq!(denial(&allowed), None, "{who:?} {name} {own}");

            let denied = call(
                &registry,
                &caller,
                name,
                json!({"project": other, "document": "plan"}),
            );
            match denied {
                Verdict::Deny {
                    reason:
                        gateway_core::Reason::ResourceOutsideLimit(ResourceProblem::Outside {
                            resource,
                            ..
                        }),
                    ..
                } => assert_eq!(resource, project(other)),
                other => panic!("{who:?} {name}: expected a resource denial, got {other:?}"),
            }
        }
    }
}

#[test]
fn a_call_that_names_no_project_is_denied_as_naming_none() {
    let registry = registry();
    let fixture = Fixture::new().unwrap();
    let caller = caller(&registry, &fixture, Caller::TeamA);
    for args in [
        json!({}),
        json!({"document": "plan"}),
        json!({"project": 7}),
        json!({"project": null}),
        json!({"project": ["atlas"]}),
        json!({"project": ""}),
    ] {
        let verdict = call(
            &registry,
            &caller,
            "docs-team-a__read_document",
            args.clone(),
        );
        assert!(
            matches!(
                verdict,
                Verdict::Deny {
                    reason: gateway_core::Reason::ResourceOutsideLimit(
                        ResourceProblem::NoneNamed { .. }
                    ),
                    ..
                }
            ),
            "{args}: {verdict:?}"
        );
    }
}

#[test]
fn tools_list_shows_each_team_its_own_entrys_tools_with_their_definitions() {
    let registry = registry();
    let fixture = Fixture::new().unwrap();
    for (who, entry) in [
        (Caller::TeamA, "docs-team-a"),
        (Caller::TeamB, "docs-team-b"),
    ] {
        let caller = caller(&registry, &fixture, who);
        let listed: Vec<&str> = list_tools(registry.snapshot(), &caller)
            .into_iter()
            .map(|approved| registry.definitions()[&approved.name].name.as_str())
            .collect();
        assert_eq!(
            listed,
            [
                format!("{entry}__list_documents"),
                format!("{entry}__read_document")
            ]
        );
    }
}

#[test]
fn neither_team_may_use_the_other_teams_surface() {
    let registry = registry();
    let fixture = Fixture::new().unwrap();
    for (who, other) in [
        (Caller::TeamA, "docs-team-b"),
        (Caller::TeamB, "docs-team-a"),
    ] {
        let caller = caller_on(&registry, &fixture, who, other);
        assert!(
            list_tools(registry.snapshot(), &caller).is_empty(),
            "{who:?}"
        );
        let verdict = call(
            &registry,
            &caller,
            &format!("{other}__read_document"),
            json!({"project": "atlas", "document": "plan"}),
        );
        assert_eq!(
            denial(&verdict),
            Some(ReasonKind::SurfaceNotPermitted),
            "{who:?}: {verdict:?}"
        );
    }
}

#[test]
fn a_user_gets_no_profile_from_the_demo_rules() {
    let registry = registry();
    let fixture = Fixture::new().unwrap();
    let user = fixture.principal(Caller::UserInGroupG).unwrap();
    assert!(registry.select_profile(user.get()).is_err());
}

#[test]
fn an_undeclared_argument_fails_the_check_before_forwarding() {
    let registry = registry();
    let adapter = &registry.adapters()[&tool("docs-team-a__read_document")];
    assert!(
        adapter
            .check_arguments(&json!({"project": "atlas", "document": "plan"}))
            .is_ok()
    );
    let refused = adapter.check_arguments(&json!({
        "project": "atlas", "document": "plan", "other_project": "borealis"
    }));
    assert_eq!(
        refused.map_err(|error| error.to_string()),
        Err(
            "the arguments to `docs-team-a__read_document` carry `/other_project`, which its approved schema does not declare"
                .to_owned()
        )
    );
    // The adapter alone does not see the extra argument: draft 0011 has the argument check
    // refuse it after the row is begun, with outcome `error`, and never forward it.
    let resources = adapter.resources(&arguments(json!({
        "project": "atlas", "document": "plan", "other_project": "borealis"
    })));
    assert_eq!(resources, Resources::Named(vec![project("atlas")]));
}
