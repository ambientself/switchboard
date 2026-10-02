//! The fixture's policy and callers are what the doc comments say they are, and every kind of
//! denial the decision function makes is reachable from it by changing one thing about a call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use gateway_core::{
    CallContext, Classification, PolicySnapshot, Principal, PrincipalId, PrincipalKind, ReasonKind,
    RequestedTool, ResourceDeclaration, ToolName, Verifier, decide, list_tools,
};
use gateway_identity::{SigningAlgorithm, VerifyError};
use gateway_testkit::{
    AUDIENCE, Caller, DEPLOYMENT, Fixture, FixtureConnector, GROUP_G, PROFILE_TEAM_A,
    PROFILE_TEAM_B, PROFILE_USER, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A,
    TEAM_A_DOCUMENT, TEAM_A_SUBJECT, TEAM_B, TEAM_B_DOCUMENT, UNKNOWN_PROFILE, USER_ISSUER,
    USER_SUBJECT, WORKLOAD_ISSUER, WRITE_TOOL, policy, policy_data,
};
use serde_json::{Value, json};

fn fixture() -> Fixture {
    Fixture::new().unwrap()
}

fn tool(name: &str) -> ToolName {
    ToolName::parse(name).unwrap()
}

#[test]
fn the_policy_loads_through_the_validated_path_and_has_the_shape_the_fixture_promises() {
    let snapshot = policy().unwrap();
    // The same data through `SnapshotData` is the same snapshot: there is one validated path.
    let data = serde_json::from_value(policy_data()).unwrap();
    assert_eq!(PolicySnapshot::new(data).unwrap(), snapshot);

    for (name, classification, resources) in [
        (
            READ_TOOL,
            Classification::Read,
            ResourceDeclaration::Declared,
        ),
        (
            WRITE_TOOL,
            Classification::Write,
            ResourceDeclaration::Declared,
        ),
        (
            SCOPED_READ_TOOL,
            Classification::Read,
            ResourceDeclaration::ChecksOwnScope,
        ),
    ] {
        let approved = snapshot.tool(&tool(name)).unwrap();
        assert_eq!(approved.classification, classification, "{name}");
        assert_eq!(approved.resources, resources, "{name}");
        assert_eq!(approved.connector.as_str(), "fixture");
    }
    let surface = |name: &str| snapshot.surface(&name.into()).unwrap();
    assert_eq!(surface(SURFACE_READ).tools.len(), 2);
    assert_eq!(surface(SURFACE_ALL).tools.len(), 3);
    assert_eq!(surface(SURFACE_READ).groups.len(), 1);
    assert!(surface(SURFACE_ALL).groups.is_empty());

    let limits = snapshot.limits();
    assert_eq!(limits.teams.len(), 2, "one resource limit per team");
    assert!(limits.teams.values().all(|allowed| allowed.len() == 1));
    assert_eq!(limits.groups.len(), 1);
    assert_eq!(snapshot.revision().as_str(), "fixture-1");
}

#[test]
fn each_caller_is_proved_through_the_real_verifier_with_the_identity_policy_expects() {
    let fixture = fixture();
    let team_a = fixture.team_a_workload(SURFACE_ALL).unwrap();
    let principal = team_a.principal.get();
    assert_eq!(
        principal.id,
        PrincipalId {
            issuer: WORKLOAD_ISSUER.into(),
            subject: TEAM_A_SUBJECT.into()
        }
    );
    assert_eq!(
        principal.kind,
        PrincipalKind::Workload {
            team: TEAM_A.into()
        }
    );
    assert_eq!(
        (
            team_a.profile.as_str(),
            team_a.surface.as_str(),
            team_a.deployment.as_str()
        ),
        (PROFILE_TEAM_A, SURFACE_ALL, DEPLOYMENT)
    );
    assert!(team_a.delegation.is_none());

    let team_b = fixture.team_b_workload(SURFACE_READ).unwrap();
    assert_eq!(
        team_b.principal.get().team().map(|team| team.as_str()),
        Some(TEAM_B)
    );
    assert_eq!(team_b.profile.as_str(), PROFILE_TEAM_B);

    let user = fixture.user_in_group_g(SURFACE_READ).unwrap();
    assert_eq!(
        user.principal.get().id,
        PrincipalId {
            issuer: USER_ISSUER.into(),
            subject: USER_SUBJECT.into()
        }
    );
    assert_eq!(
        user.principal
            .get()
            .groups()
            .map(|group| group.as_str())
            .collect::<Vec<_>>(),
        [GROUP_G]
    );
    assert_eq!(user.profile.as_str(), PROFILE_USER);
}

#[test]
fn the_fixture_works_with_rsa_issuers_too() {
    let fixture =
        Fixture::with_algorithms(SigningAlgorithm::Rs256, SigningAlgorithm::Rs256).unwrap();
    assert!(fixture.team_a_workload(SURFACE_ALL).is_ok());
    assert!(fixture.user_in_group_g(SURFACE_READ).is_ok());
}

#[test]
fn the_fixtures_clock_decides_whether_its_tokens_verify() {
    let fixture = fixture();
    let token = fixture.token(Caller::TeamA);
    assert!(fixture.verifier().verify(&token).is_ok());
    fixture.clock.advance(Duration::from_secs(3600));
    assert_eq!(
        fixture.verifier().verify(&token).unwrap_err().detail(),
        &VerifyError::Expired
    );
    // A token minted at the new time is fine.
    assert!(fixture.team_a_workload(SURFACE_ALL).is_ok());
    assert_eq!(AUDIENCE, "switchboard-fixture");
}

#[test]
fn the_identity_gate_over_the_fixture_proves_its_tokens_and_refuses_others() {
    let fixture = fixture();
    let gate = fixture.identity().unwrap();
    let token = fixture.token(Caller::UserInGroupG);
    assert!(matches!(
        gate.check(Some(&token)),
        gateway_identity::Verification::Proved(_)
    ));
    assert!(matches!(
        gate.check(Some("nope")),
        gateway_identity::Verification::Failed(_)
    ));
}

#[test]
fn a_principal_the_fixture_does_not_know_gets_a_profile_the_snapshot_does_not_hold() {
    let stranger = |issuer: &str, kind: PrincipalKind| Principal {
        id: PrincipalId {
            issuer: issuer.into(),
            subject: "x".into(),
        },
        kind,
    };
    for principal in [
        stranger(
            WORKLOAD_ISSUER,
            PrincipalKind::Workload {
                team: "team-c".into(),
            },
        ),
        stranger(
            "https://elsewhere.test",
            PrincipalKind::Workload {
                team: TEAM_A.into(),
            },
        ),
        stranger(
            USER_ISSUER,
            PrincipalKind::User {
                groups: ["group-h".into()].into(),
            },
        ),
        stranger(
            USER_ISSUER,
            PrincipalKind::User {
                groups: Default::default(),
            },
        ),
    ] {
        assert_eq!(
            Fixture::select_profile(&principal).as_str(),
            UNKNOWN_PROFILE,
            "{principal:?}"
        );
        assert!(
            policy()
                .unwrap()
                .profile(&Fixture::select_profile(&principal))
                .is_none()
        );
    }
}

/// One call, changed one way at a time from an allowed one, reaches each denial.
#[test]
fn every_kind_of_denial_the_decision_function_makes_is_reachable_from_the_fixture() {
    let fixture = fixture();
    let decide_for = |caller: Caller, surface: &str, tool: &str, arguments: Value| {
        let call = CallContext {
            caller: fixture.caller_context(caller, surface).unwrap(),
            tool: RequestedTool::new(tool),
            resources: FixtureConnector::resources_of(tool, &arguments),
        };
        decide(&fixture.policy, &call)
    };
    let own = |caller: Caller| json!({"document": caller.own_document()});

    // Allowed: each caller, on a surface that serves the tool, reading its own document.
    for (caller, surface, name) in [
        (Caller::TeamA, SURFACE_ALL, READ_TOOL),
        (Caller::TeamA, SURFACE_ALL, WRITE_TOOL),
        (Caller::TeamB, SURFACE_ALL, READ_TOOL),
        (Caller::UserInGroupG, SURFACE_READ, READ_TOOL),
        (Caller::TeamA, SURFACE_READ, SCOPED_READ_TOOL),
        (Caller::UserInGroupG, SURFACE_READ, SCOPED_READ_TOOL),
    ] {
        let decision = decide_for(caller, surface, name, own(caller));
        assert!(
            decision.is_allowed(),
            "{caller:?} {surface} {name}: {:?}",
            decision.reason()
        );
    }
    // The scoped tool is allowed with a document nobody's limit names, because it checks its
    // own scope when it runs.
    assert!(
        decide_for(
            Caller::TeamB,
            SURFACE_ALL,
            SCOPED_READ_TOOL,
            json!({"document": "restricted-notes"})
        )
        .is_allowed()
    );

    let denied = |caller, surface, name, arguments| {
        decide_for(caller, surface, name, arguments)
            .reason()
            .map(|reason| reason.kind())
    };
    use ReasonKind::*;
    assert_eq!(
        denied(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamB)),
        Some(ClassificationNotPermitted)
    );
    assert_eq!(
        denied(Caller::TeamA, SURFACE_READ, WRITE_TOOL, own(Caller::TeamA)),
        Some(ToolNotOnSurface)
    );
    assert_eq!(
        denied(
            Caller::UserInGroupG,
            SURFACE_ALL,
            READ_TOOL,
            own(Caller::UserInGroupG)
        ),
        Some(SurfaceNotPermitted)
    );
    assert_eq!(
        denied(
            Caller::TeamA,
            "no-such-surface",
            READ_TOOL,
            own(Caller::TeamA)
        ),
        Some(SurfaceNotPermitted)
    );
    assert_eq!(
        denied(
            Caller::TeamA,
            SURFACE_ALL,
            "fixture__no_such_tool",
            own(Caller::TeamA)
        ),
        Some(UnknownTool)
    );
    assert_eq!(
        denied(
            Caller::TeamA,
            SURFACE_ALL,
            "not a tool name",
            own(Caller::TeamA)
        ),
        Some(UnknownTool)
    );
    assert_eq!(
        denied(
            Caller::TeamB,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_A_DOCUMENT})
        ),
        Some(ResourceOutsideLimit)
    );
    assert_eq!(
        denied(
            Caller::TeamA,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_B_DOCUMENT})
        ),
        Some(ResourceOutsideLimit)
    );
    assert_eq!(
        denied(Caller::TeamA, SURFACE_ALL, READ_TOOL, json!({})),
        Some(ResourceOutsideLimit)
    );
    // A call whose profile the snapshot does not hold: the context is built by hand, since the
    // fixture's helpers always select a known one.
    let mut caller = fixture.team_a_workload(SURFACE_ALL).unwrap();
    caller.profile = UNKNOWN_PROFILE.into();
    let call = CallContext {
        caller,
        tool: RequestedTool::new(READ_TOOL),
        resources: FixtureConnector::resources_of(READ_TOOL, &own(Caller::TeamA)),
    };
    assert_eq!(
        decide(&fixture.policy, &call)
            .reason()
            .map(|reason| reason.kind()),
        Some(ProfileUnknown)
    );
}

#[test]
fn tools_list_shows_each_caller_what_its_surface_and_profile_allow() {
    let fixture = fixture();
    let listed = |caller: Caller, surface: &str| -> Vec<String> {
        let context = fixture.caller_context(caller, surface).unwrap();
        let mut names: Vec<String> = list_tools(&fixture.policy, &context)
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        listed(Caller::TeamA, SURFACE_ALL),
        [READ_TOOL, SCOPED_READ_TOOL, WRITE_TOOL]
    );
    assert_eq!(
        listed(Caller::TeamB, SURFACE_ALL),
        [READ_TOOL, SCOPED_READ_TOOL],
        "team B's profile does not permit writes"
    );
    assert_eq!(
        listed(Caller::UserInGroupG, SURFACE_READ),
        [READ_TOOL, SCOPED_READ_TOOL]
    );
    assert!(listed(Caller::UserInGroupG, SURFACE_ALL).is_empty());
}
