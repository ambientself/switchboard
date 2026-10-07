//! Tool calls end to end: the fixture gateway on a loopback port in this process, driven over
//! HTTP, with what reached the connector, the credential source and the audit store read back.
//!
//! Issue #26's list: a denied call never reaches the connector, an audit begin that fails
//! refuses the call, an audit finish that fails does not undo a success, and a scope refusal is
//! recorded as refused. Then plan #26's tests 12 to 15: a client that goes away, the tool-use
//! identifier, the two teams' documents, and a tool that fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use gateway_core::audit::{DecisionKind, Outcome, RecordedResource, RecordedResources};
use gateway_core::{ReasonKind, ToolUseId};
use gateway_dev::{FixtureGateway, start_fixture_gateway};
use gateway_mcp::{Era, TOOL_USE_ID_META};
use gateway_testkit::{
    AUDIENCE, Caller, DRAFT_ARGUMENT, DRAFT_REFUSAL, DRAFT_TOOL, FORBIDDEN_DOCUMENT, FOREIGN_DRAFT,
    GROUP_G, GROUP_G_DOCUMENT, GROUP_REVIEW, READ_TOOL, RESOURCE_KIND, RESOURCE_SYSTEM,
    SCOPE_REFUSAL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, TEAM_A, TEAM_A_DOCUMENT, TEAM_B,
    TEAM_B_DOCUMENT, USER_SUBJECT, WRITE_TOOL,
};
use serde_json::{Value, json};
use support::{
    AUDIT_FAILURE, Answer, PATIENCE, Request, call, call_params, client, document, eventually,
};

const ERAS: [Era; 2] = [Era::Legacy, Era::Modern];

/// `token`'s holder calls `tool` on `surface` in `era`.
async fn call_as(
    gateway: &FixtureGateway,
    token: &str,
    era: Era,
    surface: &str,
    tool: &str,
    arguments: Value,
) -> Answer {
    Request::in_era(
        era,
        &gateway.url(surface),
        "tools/call",
        call_params(tool, arguments),
    )
    .bearer(token)
    .send()
    .await
}

/// A token for the fixture's user, in `groups`.
fn user_in(gateway: &FixtureGateway, groups: &[&str]) -> String {
    gateway
        .user_issuer()
        .user_token(USER_SUBJECT, AUDIENCE, groups, gateway.clock().now())
        .build()
}

fn outcome(gateway: &FixtureGateway, row: usize) -> Option<Outcome> {
    gateway
        .store()
        .row(row)
        .unwrap()
        .completion
        .map(|completion| completion.outcome)
}

// --- A denied call never reaches the connector -----------------------------------------------

/// One denied call: who, where, what, and the kind of reason its row must hold.
struct Denial {
    kind: ReasonKind,
    token: String,
    surface: &'static str,
    tool: &'static str,
    arguments: Value,
    /// Text the sentence must name.
    names: &'static str,
}

fn denials(gateway: &FixtureGateway) -> Vec<Denial> {
    let team_a = gateway.token(Caller::TeamA);
    let team_b = gateway.token(Caller::TeamB);
    let user = gateway.token(Caller::UserInGroupG);
    vec![
        // Check 0: a user whose two groups select two profiles gets none the policy holds.
        Denial {
            kind: ReasonKind::ProfileUnknown,
            token: user_in(gateway, &[GROUP_G, GROUP_REVIEW]),
            surface: SURFACE_READ,
            tool: READ_TOOL,
            arguments: document(GROUP_G_DOCUMENT),
            names: "profile",
        },
        // And so does one in a group no rule names.
        Denial {
            kind: ReasonKind::ProfileUnknown,
            token: user_in(gateway, &["group-unlisted"]),
            surface: SURFACE_READ,
            tool: READ_TOOL,
            arguments: document(GROUP_G_DOCUMENT),
            names: "profile",
        },
        // Check 1: users may not use the surface that serves the draft and write tools.
        Denial {
            kind: ReasonKind::SurfaceNotPermitted,
            token: user.clone(),
            surface: SURFACE_ALL,
            tool: READ_TOOL,
            arguments: document(GROUP_G_DOCUMENT),
            names: SURFACE_ALL,
        },
        // A surface nobody configured.
        Denial {
            kind: ReasonKind::SurfaceNotPermitted,
            token: team_a.clone(),
            surface: "no-such-surface",
            tool: READ_TOOL,
            arguments: document(TEAM_A_DOCUMENT),
            names: "no-such-surface",
        },
        // Check 2: a tool nobody approved, and an approved one this surface does not serve.
        Denial {
            kind: ReasonKind::UnknownTool,
            token: team_a.clone(),
            surface: SURFACE_READ,
            tool: "fixture__delete",
            arguments: document(TEAM_A_DOCUMENT),
            names: "fixture__delete",
        },
        Denial {
            kind: ReasonKind::ToolNotOnSurface,
            token: team_a.clone(),
            surface: SURFACE_READ,
            tool: WRITE_TOOL,
            arguments: document(TEAM_A_DOCUMENT),
            names: WRITE_TOOL,
        },
        // Check 5: team B's profile only reads, so it may not propose.
        Denial {
            kind: ReasonKind::ClassificationNotPermitted,
            token: team_b.clone(),
            surface: SURFACE_ALL,
            tool: DRAFT_TOOL,
            arguments: document(TEAM_B_DOCUMENT),
            names: DRAFT_TOOL,
        },
        // And a direct write is denied in every profile: to team B, and to team A, whose
        // profile may propose.
        Denial {
            kind: ReasonKind::ClassificationNotPermitted,
            token: team_b,
            surface: SURFACE_ALL,
            tool: WRITE_TOOL,
            arguments: document(TEAM_B_DOCUMENT),
            names: "denied in every profile",
        },
        Denial {
            kind: ReasonKind::ClassificationNotPermitted,
            token: team_a.clone(),
            surface: SURFACE_ALL,
            tool: WRITE_TOOL,
            arguments: document(TEAM_A_DOCUMENT),
            names: "denied in every profile",
        },
        // Check 6: another team's document, and no document at all.
        Denial {
            kind: ReasonKind::ResourceOutsideLimit,
            token: team_a.clone(),
            surface: SURFACE_READ,
            tool: READ_TOOL,
            arguments: document(TEAM_B_DOCUMENT),
            names: TEAM_B_DOCUMENT,
        },
        Denial {
            kind: ReasonKind::ResourceOutsideLimit,
            token: team_a,
            surface: SURFACE_READ,
            tool: READ_TOOL,
            arguments: json!({}),
            names: READ_TOOL,
        },
    ]
}

#[tokio::test]
async fn a_denied_call_never_reaches_the_connector_and_its_row_holds_its_answer() {
    let gateway = start_fixture_gateway().await.unwrap();
    let cases = denials(&gateway);
    let mut sentences = Vec::new();
    for era in ERAS {
        for case in &cases {
            let position = gateway.store().rows().len();
            let answer = call_as(
                &gateway,
                &case.token,
                era,
                case.surface,
                case.tool,
                case.arguments.clone(),
            )
            .await;
            let sentence = answer.denial();
            let what = format!("{:?} in {era}: {sentence}", case.kind);
            assert!(sentence.contains(case.names), "{what}");

            let row = gateway.store().row(position).expect(&what);
            assert_eq!(row.decision, DecisionKind::Deny, "{what}");
            assert_eq!(row.reason, Some(case.kind), "{what}");
            assert_eq!(row.sentence.as_deref(), Some(sentence.as_str()), "{what}");
            assert_eq!(row.completion, None, "{what}");
            sentences.push((case.kind, sentence));
        }
    }
    assert_eq!(gateway.store().rows().len(), 2 * cases.len());
    assert_eq!(gateway.store().finish_attempts(), 0);
    assert_eq!(gateway.connector().received(), Vec::new());
    assert_eq!(gateway.connector().writes(), Vec::new());
    assert_eq!(gateway.credentials().requests(), Vec::new());

    // Every kind of reason the fixture can reach without a delegation is covered.
    for kind in ReasonKind::ALL {
        let needs_a_delegation = matches!(
            kind,
            ReasonKind::ToolNotInDelegation | ReasonKind::DelegationDisagrees
        );
        assert_eq!(
            sentences.iter().any(|(reached, _)| *reached == kind),
            !needs_a_delegation,
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_tool_and_a_tool_on_another_surface_read_the_same_but_are_recorded_apart() {
    let gateway = start_fixture_gateway().await.unwrap();
    // An approved tool that only the other surface serves, then a name nobody approved.
    let on_another = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_READ,
        WRITE_TOOL,
        document(TEAM_A_DOCUMENT),
    )
    .await
    .denial();
    let unknown = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_READ,
        "fixture__wrote",
        document(TEAM_A_DOCUMENT),
    )
    .await
    .denial();
    assert_eq!(on_another.replace(WRITE_TOOL, "fixture__wrote"), unknown);
    let rows = gateway.store().rows();
    assert_eq!(rows[0].reason, Some(ReasonKind::ToolNotOnSurface));
    assert_eq!(rows[1].reason, Some(ReasonKind::UnknownTool));
    assert_eq!(gateway.connector().received(), Vec::new());
}

// --- An audit begin that fails refuses the call ----------------------------------------------

#[tokio::test]
async fn an_audit_begin_that_fails_refuses_the_call_and_nothing_runs() {
    let gateway = start_fixture_gateway().await.unwrap();
    for era in ERAS {
        gateway.store().fail_next_begin();
        let answer = call(
            &gateway,
            Caller::TeamA,
            era,
            SURFACE_READ,
            READ_TOOL,
            document(TEAM_A_DOCUMENT),
        )
        .await;
        assert_eq!(answer.denial(), AUDIT_FAILURE, "{era}");
    }
    assert_eq!(gateway.store().begin_attempts(), 2);
    assert_eq!(gateway.store().rows(), Vec::new());
    assert_eq!(gateway.connector().received(), Vec::new());
    assert_eq!(gateway.credentials().requests(), Vec::new());

    // The next call, with the store working again, runs and is recorded.
    let (is_error, _) = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_READ,
        READ_TOOL,
        document(TEAM_A_DOCUMENT),
    )
    .await
    .tool_result();
    assert!(!is_error);
    assert_eq!(gateway.store().rows().len(), 1);
}

#[tokio::test]
async fn while_audit_begins_fail_a_call_that_would_be_denied_gets_the_audit_sentence() {
    let gateway = start_fixture_gateway().await.unwrap();
    gateway.store().fail_all_begins();
    for (caller, surface, tool, arguments) in [
        (
            Caller::TeamA,
            SURFACE_READ,
            READ_TOOL,
            document(TEAM_B_DOCUMENT),
        ),
        (
            Caller::TeamB,
            SURFACE_ALL,
            WRITE_TOOL,
            document(TEAM_B_DOCUMENT),
        ),
        (
            Caller::TeamA,
            SURFACE_READ,
            READ_TOOL,
            document(TEAM_A_DOCUMENT),
        ),
    ] {
        let answer = call(&gateway, caller, Era::Modern, surface, tool, arguments).await;
        assert_eq!(answer.denial(), AUDIT_FAILURE);
    }
    assert_eq!(gateway.store().begin_attempts(), 3);
    assert_eq!(gateway.store().rows(), Vec::new());
    assert_eq!(gateway.connector().received(), Vec::new());
}

// --- An audit finish that fails does not undo a success --------------------------------------

#[tokio::test]
async fn an_audit_finish_that_fails_does_not_undo_a_success() {
    let gateway = start_fixture_gateway().await.unwrap();
    for (position, era) in ERAS.into_iter().enumerate() {
        gateway.store().fail_next_finish();
        let answer = call(
            &gateway,
            Caller::TeamA,
            era,
            SURFACE_READ,
            READ_TOOL,
            document(TEAM_A_DOCUMENT),
        )
        .await;
        let (is_error, result) = answer.tool_result();
        assert!(!is_error, "{era}: {result}");
        assert_eq!(result["structuredContent"]["tool"], json!(READ_TOOL));
        assert_eq!(
            result["structuredContent"]["echo"],
            document(TEAM_A_DOCUMENT)
        );

        // The row says the call was allowed, and stays without an outcome: the evidence that
        // the gateway ran a call and could not record how it went.
        let row = gateway.store().row(position).unwrap();
        assert_eq!(row.decision, DecisionKind::Allow, "{era}");
        assert_eq!(row.completion, None, "{era}");
    }
    assert_eq!(gateway.connector().received().len(), 2);
    assert_eq!(gateway.store().finish_attempts(), 2);
}

// --- A scope refusal is recorded as refused --------------------------------------------------

#[tokio::test]
async fn a_scope_refusal_is_answered_as_a_denial_and_recorded_as_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    for (position, era) in ERAS.into_iter().enumerate() {
        let answer = call(
            &gateway,
            Caller::TeamA,
            era,
            SURFACE_READ,
            SCOPED_READ_TOOL,
            document(FORBIDDEN_DOCUMENT),
        )
        .await;
        assert_eq!(answer.denial(), SCOPE_REFUSAL, "{era}");

        // The decision allowed it; the connector refused it, after it was handed the call.
        let row = gateway.store().row(position).unwrap();
        assert_eq!(row.decision, DecisionKind::Allow, "{era}");
        assert_eq!(row.reason, None);
        assert_eq!(row.sentence, None);
        assert_eq!(
            row.completion.map(|completion| completion.outcome),
            Some(Outcome::Refused {
                sentence: SCOPE_REFUSAL.to_owned()
            }),
            "{era}"
        );
    }
    assert_eq!(gateway.connector().received().len(), 2);

    // The same tool serves a document in the caller's scope.
    let (is_error, _) = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_READ,
        SCOPED_READ_TOOL,
        document(TEAM_A_DOCUMENT),
    )
    .await
    .tool_result();
    assert!(!is_error);
    assert_eq!(outcome(&gateway, 2), Some(Outcome::Ok));
}

#[tokio::test]
async fn a_scope_refusal_whose_finish_fails_gets_the_audit_sentence() {
    let gateway = start_fixture_gateway().await.unwrap();
    gateway.store().fail_next_finish();
    let answer = call(
        &gateway,
        Caller::TeamB,
        Era::Modern,
        SURFACE_READ,
        SCOPED_READ_TOOL,
        document(FORBIDDEN_DOCUMENT),
    )
    .await;
    // A refusal the log does not hold is not passed on as if it were recorded.
    assert_eq!(answer.denial(), AUDIT_FAILURE);
    assert_eq!(outcome(&gateway, 0), None);
    assert_eq!(gateway.connector().received().len(), 1);
}

// --- A client that goes away -----------------------------------------------------------------

#[tokio::test]
async fn a_call_whose_client_goes_away_still_completes_its_row() {
    let gateway = start_fixture_gateway().await.unwrap();
    let gate = gateway.connector().hang_next();
    let request = Request::in_era(
        Era::Legacy,
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .bearer(&gateway.token(Caller::TeamA));
    let sending = tokio::spawn(async move { request.send_on(&client()).await });

    eventually("the call reaching the connector", || gate.waiting() == 1).await;
    // The row was written before the tool ran.
    let row = gateway.store().row(0).unwrap();
    assert_eq!((row.decision, row.completion), (DecisionKind::Allow, None));

    // The client goes away while the tool runs: its request, its client and its connection
    // are dropped.
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(200)).await;
    gate.open();
    eventually("the row's completion", || outcome(&gateway, 0).is_some()).await;
    assert_eq!(outcome(&gateway, 0), Some(Outcome::Ok));
    assert_eq!(gateway.store().finish_attempts(), 1);
    assert_eq!(gateway.connector().received().len(), 1);
}

#[tokio::test]
async fn shutting_down_waits_for_a_call_in_flight_and_answers_it() {
    let gateway = start_fixture_gateway().await.unwrap();
    let store = gateway.store().clone();
    let gate = gateway.connector().hang_next();
    let request = Request::in_era(
        Era::Modern,
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .bearer(&gateway.token(Caller::TeamA));
    let sending = tokio::spawn(request.send());
    eventually("the call reaching the connector", || gate.waiting() == 1).await;

    let stopping = tokio::spawn(gateway.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!stopping.is_finished(), "stopped with a call in flight");
    gate.open();
    let (is_error, _) = sending.await.unwrap().tool_result();
    assert!(!is_error);
    tokio::time::timeout(PATIENCE, stopping)
        .await
        .expect("the server stopped in time")
        .unwrap()
        .unwrap();
    assert_eq!(
        store.row(0).unwrap().completion.map(|c| c.outcome),
        Some(Outcome::Ok)
    );
}

#[tokio::test]
async fn shutting_down_waits_for_a_call_whose_client_has_gone_to_complete_its_row() {
    let gateway = start_fixture_gateway().await.unwrap();
    let store = gateway.store().clone();
    let gate = gateway.connector().hang_next();
    let request = Request::in_era(
        Era::Legacy,
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .bearer(&gateway.token(Caller::TeamA));
    let sending = tokio::spawn(async move { request.send_on(&client()).await });
    eventually("the call reaching the connector", || gate.waiting() == 1).await;
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // No connection is open, but a call is still running. A process that exits once the
    // server returns would leave its row open for good.
    let stopping = tokio::spawn(gateway.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !stopping.is_finished(),
        "stopped while a call was still running"
    );
    gate.open();
    tokio::time::timeout(PATIENCE, stopping)
        .await
        .expect("the server stopped in time")
        .unwrap()
        .unwrap();
    assert_eq!(
        store.row(0).unwrap().completion.map(|c| c.outcome),
        Some(Outcome::Ok),
        "the row was not complete when the server returned"
    );
}

#[tokio::test]
async fn no_answer_is_sent_until_the_row_is_finished() {
    let gateway = start_fixture_gateway().await.unwrap();
    let held = gateway.store().hold_finishes();
    let request = Request::in_era(
        Era::Modern,
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    )
    .bearer(&gateway.token(Caller::TeamA));
    let sending = tokio::spawn(request.send());

    eventually("the finish being held", || held.waiting() == 1).await;
    // The tool has run and the row is begun, but not finished, and nothing has been answered.
    assert_eq!(gateway.connector().received().len(), 1);
    assert_eq!(outcome(&gateway, 0), None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !sending.is_finished(),
        "answered before the row was finished"
    );

    held.open();
    let answer = sending.await.unwrap();
    let (is_error, _) = answer.tool_result();
    assert!(!is_error);
    assert_eq!(outcome(&gateway, 0), Some(Outcome::Ok));
}

// --- The tool-use identifier -----------------------------------------------------------------

#[tokio::test]
async fn the_callers_tool_use_identifier_lands_on_the_row_only_within_its_bound() {
    let gateway = start_fixture_gateway().await.unwrap();
    let longest = format!("toolu_{}", "a".repeat(gateway::MAX_TOOL_USE_ID - 6));
    let cases = [
        ("toolu_01AbCdEf", Some("toolu_01AbCdEf")),
        (longest.as_str(), Some(longest.as_str())),
        (&*format!("{longest}b"), None),
        ("toolu_01\nforged row", None),
        ("toolu_01\u{1b}[31m", None),
        ("toolu_é", None),
        ("", None),
    ];
    let mut position = 0;
    for era in ERAS {
        for (sent, kept) in &cases {
            let params = json!({
                "name": READ_TOOL,
                "arguments": document(TEAM_A_DOCUMENT),
                "_meta": {TOOL_USE_ID_META: sent},
            });
            let answer = Request::in_era(era, &gateway.url(SURFACE_READ), "tools/call", params)
                .bearer(&gateway.token(Caller::TeamA))
                .send()
                .await;
            // An identifier out of bounds is dropped; the call still runs.
            let (is_error, _) = answer.tool_result();
            assert!(!is_error, "{sent:?}");
            let row = gateway.store().row(position).unwrap();
            assert_eq!(row.tool_use_id, kept.map(ToolUseId::new), "{era}: {sent:?}");
            position += 1;
        }
    }

    // A denied call carries it too.
    let params = json!({
        "name": READ_TOOL,
        "arguments": document(TEAM_B_DOCUMENT),
        "_meta": {TOOL_USE_ID_META: "toolu_denied"},
    });
    Request::in_era(
        Era::Legacy,
        &gateway.url(SURFACE_READ),
        "tools/call",
        params,
    )
    .bearer(&gateway.token(Caller::TeamA))
    .send()
    .await
    .denial();
    let row = gateway.store().row(position).unwrap();
    assert_eq!(row.decision, DecisionKind::Deny);
    assert_eq!(row.tool_use_id, Some(ToolUseId::new("toolu_denied")));
}

#[tokio::test]
async fn calls_made_at_once_each_get_their_own_row_and_answer() {
    let gateway = start_fixture_gateway().await.unwrap();
    let mut calls = Vec::new();
    for n in 0..40 {
        let caller = if n % 2 == 0 {
            Caller::TeamA
        } else {
            Caller::TeamB
        };
        let era = ERAS[n % 4 / 2];
        // Every third call names the other team's document.
        let allowed = n % 3 != 0;
        let target = if allowed {
            caller.own_document()
        } else if caller == Caller::TeamA {
            TEAM_B_DOCUMENT
        } else {
            TEAM_A_DOCUMENT
        };
        let tool_use_id = format!("toolu_{n:02}");
        let params = json!({
            "name": READ_TOOL,
            "arguments": document(target),
            "_meta": {TOOL_USE_ID_META: tool_use_id},
        });
        let request = Request::in_era(era, &gateway.url(SURFACE_READ), "tools/call", params)
            .bearer(&gateway.token(caller));
        calls.push((tool_use_id, allowed, tokio::spawn(request.send())));
    }

    let rows = {
        let mut answers = Vec::new();
        for (tool_use_id, allowed, sending) in calls {
            answers.push((tool_use_id, allowed, sending.await.unwrap()));
        }
        let rows = gateway.store().rows();
        assert_eq!(rows.len(), answers.len());
        for (tool_use_id, allowed, answer) in answers {
            let row = rows
                .iter()
                .find(|row| row.tool_use_id == Some(ToolUseId::new(tool_use_id.clone())))
                .unwrap_or_else(|| panic!("no row for {tool_use_id}"));
            if allowed {
                let (is_error, _) = answer.tool_result();
                assert!(!is_error, "{tool_use_id}");
                assert_eq!(row.decision, DecisionKind::Allow, "{tool_use_id}");
                assert_eq!(
                    row.completion.as_ref().map(|c| c.outcome.clone()),
                    Some(Outcome::Ok),
                    "{tool_use_id}"
                );
            } else {
                assert_eq!(row.decision, DecisionKind::Deny, "{tool_use_id}");
                assert_eq!(row.sentence, Some(answer.denial()), "{tool_use_id}");
            }
        }
        rows
    };
    let allowed = rows
        .iter()
        .filter(|row| row.decision == DecisionKind::Allow)
        .count();
    assert_eq!(gateway.connector().received().len(), allowed);
    assert_eq!(gateway.credentials().requests().len(), allowed);
}

// --- The two teams' documents ----------------------------------------------------------------

#[tokio::test]
async fn each_team_reads_its_own_document_with_its_own_credential_and_is_denied_the_other() {
    let gateway = start_fixture_gateway().await.unwrap();
    for (caller, team, own, other) in [
        (Caller::TeamA, TEAM_A, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT),
        (Caller::TeamB, TEAM_B, TEAM_B_DOCUMENT, TEAM_A_DOCUMENT),
    ] {
        for era in ERAS {
            let before = gateway.credentials().requests().len();
            let (is_error, result) = call(
                &gateway,
                caller,
                era,
                SURFACE_READ,
                READ_TOOL,
                document(own),
            )
            .await
            .tool_result();
            assert!(!is_error, "{result}");
            let credential = result["structuredContent"]["credential"].as_str().unwrap();
            assert!(
                credential.starts_with(&format!("fake-credential-for-fixture-{team}-")),
                "{credential}"
            );
            let requests = gateway.credentials().requests();
            assert_eq!(requests.len(), before + 1);
            assert_eq!(requests[before].team, Some(team.into()));

            let sentence = call(
                &gateway,
                caller,
                era,
                SURFACE_READ,
                READ_TOOL,
                document(other),
            )
            .await
            .denial();
            assert!(sentence.contains(&format!("`{other}`")), "{sentence}");
            assert!(sentence.contains(&format!("team `{team}`")), "{sentence}");
            assert_eq!(gateway.credentials().requests().len(), before + 1);
        }
    }
    // Two allowed reads a team, and nothing else, reached the connector.
    let received = gateway.connector().received();
    assert_eq!(received.len(), 4);
    for call in received {
        let expected = if call.team == Some(TEAM_A.into()) {
            TEAM_A_DOCUMENT
        } else {
            TEAM_B_DOCUMENT
        };
        assert_eq!(call.arguments, document(expected));
    }
    // Each row records the document its call named, the allowed and the denied alike.
    let rows = gateway.store().rows();
    assert_eq!(rows.len(), 8);
    for (n, row) in rows.iter().enumerate() {
        let (own, other) = if n < 4 {
            (TEAM_A_DOCUMENT, TEAM_B_DOCUMENT)
        } else {
            (TEAM_B_DOCUMENT, TEAM_A_DOCUMENT)
        };
        let (decision, named) = if n % 2 == 0 {
            (DecisionKind::Allow, own)
        } else {
            (DecisionKind::Deny, other)
        };
        assert_eq!(row.decision, decision, "row {n}");
        assert_eq!(
            (&row.resources, row.resources_omitted),
            (
                &RecordedResources::Named(vec![RecordedResource {
                    system: RESOURCE_SYSTEM.to_owned(),
                    kind: RESOURCE_KIND.to_owned(),
                    identifier: named.to_owned(),
                }]),
                0
            ),
            "row {n}"
        );
    }
}

// --- A proposal -----------------------------------------------------------------------------

#[tokio::test]
async fn team_a_proposes_and_revises_its_own_draft_and_a_foreign_draft_is_refused() {
    let gateway = start_fixture_gateway().await.unwrap();
    let draft = |extra: Value| {
        let mut arguments = document(TEAM_A_DOCUMENT);
        arguments
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        arguments
    };
    let (is_error, opened) = call(
        &gateway,
        Caller::TeamA,
        Era::Modern,
        SURFACE_ALL,
        DRAFT_TOOL,
        draft(json!({"text": "A first proposal."})),
    )
    .await
    .tool_result();
    assert!(!is_error, "{opened}");
    assert_eq!(opened["structuredContent"]["draft"], json!("draft-1"));

    let (is_error, revised) = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_ALL,
        DRAFT_TOOL,
        draft(json!({DRAFT_ARGUMENT: "draft-1", "text": "A second try."})),
    )
    .await
    .tool_result();
    assert!(!is_error, "{revised}");
    assert_eq!(revised["structuredContent"]["draft"], json!("draft-1"));

    // A draft a person opened is refused by the tool when it runs, and recorded as refused.
    let sentence = call(
        &gateway,
        Caller::TeamA,
        Era::Modern,
        SURFACE_ALL,
        DRAFT_TOOL,
        draft(json!({DRAFT_ARGUMENT: FOREIGN_DRAFT})),
    )
    .await
    .denial();
    assert_eq!(sentence, DRAFT_REFUSAL);

    let rows = gateway.store().rows();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.decision == DecisionKind::Allow));
    assert_eq!(outcome(&gateway, 0), Some(Outcome::Ok));
    assert_eq!(outcome(&gateway, 1), Some(Outcome::Ok));
    assert_eq!(
        outcome(&gateway, 2),
        Some(Outcome::Refused {
            sentence: DRAFT_REFUSAL.to_owned()
        })
    );
    let writes = gateway.connector().writes();
    assert_eq!(writes.len(), 2, "the refused revision wrote nothing");
    assert!(writes.iter().all(|write| write.tool == DRAFT_TOOL));
    assert!(
        writes.iter().all(|write| write
            .credential
            .starts_with("fake-credential-for-fixture-team-a-")),
        "{writes:?}"
    );
}

// --- A tool that fails -----------------------------------------------------------------------

#[tokio::test]
async fn a_tool_that_fails_is_a_result_with_is_error_and_is_recorded_as_an_error() {
    let gateway = start_fixture_gateway().await.unwrap();
    gateway.connector().fail_next();
    let (is_error, result) = call(
        &gateway,
        Caller::TeamA,
        Era::Modern,
        SURFACE_READ,
        READ_TOOL,
        document(TEAM_A_DOCUMENT),
    )
    .await
    .tool_result();
    assert!(is_error, "{result}");
    assert_eq!(
        result["content"],
        json!([{"type": "text", "text": "the fixture connector was told to fail"}])
    );
    assert_eq!(result["resultType"], json!("complete"));
    assert_eq!(outcome(&gateway, 0), Some(Outcome::Error));

    // A credential the source refuses is the tool failing too, not a policy denial.
    gateway.credentials().refuse_next();
    let (is_error, result) = call(
        &gateway,
        Caller::TeamA,
        Era::Legacy,
        SURFACE_READ,
        READ_TOOL,
        document(TEAM_A_DOCUMENT),
    )
    .await
    .tool_result();
    assert!(is_error, "{result}");
    assert_eq!(result.get("resultType"), None, "a legacy result: {result}");
    assert_eq!(outcome(&gateway, 1), Some(Outcome::Error));
    assert_eq!(gateway.connector().received().len(), 2);
}
