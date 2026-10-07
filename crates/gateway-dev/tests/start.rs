//! Starting the fixture gateway: it serves on loopback, proves the fixture's callers on the
//! clock it is given, records their calls, and honours each option.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use gateway::{AUDIT_DISABLED_NOTE, IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE};
use gateway_core::audit::{DecisionKind, Outcome};
use gateway_dev::{DEPLOYMENT, Options, start_fixture_gateway, start_fixture_gateway_with};
use gateway_mcp::DENIAL_CODE;
use gateway_testkit::{
    Caller, DRAFT_TOOL, READ_TOOL, SURFACE_ALL, SURFACE_READ, SteppableClock, TEAM_A_DOCUMENT,
    WRITE_TOOL,
};
use serde_json::json;
use support::{legacy, post};

fn read(document: &str) -> serde_json::Value {
    legacy(
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {"document": document}}),
    )
}

#[tokio::test]
async fn the_fixture_gateway_serves_a_call_on_loopback_and_records_it() {
    let gateway = start_fixture_gateway().await.unwrap();
    assert!(
        gateway.address().ip().is_loopback(),
        "{}",
        gateway.address()
    );
    assert_ne!(gateway.address().port(), 0);
    assert_eq!(
        gateway.url(SURFACE_READ),
        format!("http://{}/mcp/{SURFACE_READ}", gateway.address())
    );

    let token = gateway.token(Caller::TeamA);
    let (status, body) = post(
        &gateway.url(SURFACE_READ),
        Some(&token),
        &read(TEAM_A_DOCUMENT),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], json!(false), "{body}");

    let received = gateway.connector().received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].tool, READ_TOOL);
    assert_eq!(gateway.credentials().requests().len(), 1);
    let rows = gateway.store().rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].deployment.as_str(), DEPLOYMENT);
    assert_eq!(rows[0].decision, DecisionKind::Allow);
    assert_eq!(
        rows[0].completion.as_ref().map(|c| c.outcome.clone()),
        Some(Outcome::Ok)
    );

    gateway.shutdown().await.unwrap();
}

#[tokio::test]
async fn each_fixture_caller_is_proved_and_gets_its_own_profile() {
    let gateway = start_fixture_gateway().await.unwrap();
    // Team A's profile may propose; team B's and the user's may not, and the user has no
    // access to the surface that serves the draft tool. No profile may write.
    let tools = |caller| {
        let token = gateway.token(caller);
        let url = gateway.url(SURFACE_ALL);
        async move {
            let (status, body) = post(&url, Some(&token), &legacy("tools/list", json!({}))).await;
            assert_eq!(status, 200, "{body}");
            body["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tool| tool["name"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };
    let team_a = tools(Caller::TeamA).await;
    assert!(team_a.contains(&DRAFT_TOOL.to_owned()), "{team_a:?}");
    assert!(!team_a.contains(&WRITE_TOOL.to_owned()), "{team_a:?}");
    let team_b = tools(Caller::TeamB).await;
    assert!(team_b.contains(&READ_TOOL.to_owned()), "{team_b:?}");
    assert!(!team_b.contains(&DRAFT_TOOL.to_owned()), "{team_b:?}");
    assert!(!team_b.contains(&WRITE_TOOL.to_owned()), "{team_b:?}");
    assert_eq!(tools(Caller::UserInGroupG).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_broken_token_is_refused_and_nothing_runs() {
    let gateway = start_fixture_gateway().await.unwrap();
    let token = gateway
        .token_builder(Caller::TeamA)
        .audience("someone-else")
        .build();
    let (status, body) = post(
        &gateway.url(SURFACE_READ),
        Some(&token),
        &read(TEAM_A_DOCUMENT),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"]["code"], json!(DENIAL_CODE));
    assert!(gateway.connector().received().is_empty());
    assert_eq!(gateway.store().begin_attempts(), 0);
}

#[tokio::test]
async fn tokens_are_issued_and_verified_on_the_clock_given() {
    let clock = SteppableClock::default();
    let gateway = start_fixture_gateway_with(Options::new().clock(Arc::new(clock.clone())))
        .await
        .unwrap();
    // The fixture's clock is in 2027, far from the system's: a token issued on it is accepted
    // only if the gateway verifies on it too.
    let token = gateway.token(Caller::TeamA);
    let url = gateway.url(SURFACE_READ);
    let (status, body) = post(&url, Some(&token), &legacy("tools/list", json!({}))).await;
    assert_eq!(status, 200, "{body}");

    clock.advance(Duration::from_secs(2 * 3600));
    let (status, _) = post(&url, Some(&token), &legacy("tools/list", json!({}))).await;
    assert_eq!(status, 401, "the token outlived its expiry");
}

#[tokio::test]
async fn with_identity_disabled_every_call_is_refused_and_initialize_says_so() {
    let gateway = start_fixture_gateway_with(Options::new().identity_disabled())
        .await
        .unwrap();
    let url = gateway.url(SURFACE_READ);

    let (status, body) = post(&url, None, &legacy("initialize", json!({}))).await;
    assert_eq!(status, 200, "{body}");
    let instructions = body["result"]["instructions"].as_str().unwrap();
    assert!(
        instructions.contains(IDENTITY_DISABLED_NOTE),
        "{instructions}"
    );

    let (status, body) = post(&url, None, &read(TEAM_A_DOCUMENT)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["error"]["message"], json!(IDENTITY_DISABLED));
    assert!(gateway.connector().received().is_empty());
    assert_eq!(gateway.store().begin_attempts(), 0);
}

#[tokio::test]
async fn with_audit_disabled_a_call_runs_with_no_row_and_initialize_says_so() {
    let gateway = start_fixture_gateway_with(Options::new().audit_disabled())
        .await
        .unwrap();
    let url = gateway.url(SURFACE_READ);
    let token = gateway.token(Caller::TeamA);

    let (_, body) = post(&url, Some(&token), &legacy("initialize", json!({}))).await;
    let instructions = body["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains(AUDIT_DISABLED_NOTE), "{instructions}");

    let (status, body) = post(&url, Some(&token), &read(TEAM_A_DOCUMENT)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(gateway.connector().received().len(), 1);
    assert_eq!(gateway.store().begin_attempts(), 0);
}

#[tokio::test]
async fn a_gateway_that_is_shut_down_stops_listening() {
    let gateway = start_fixture_gateway().await.unwrap();
    let address = gateway.address();
    gateway.shutdown().await.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn a_port_that_is_taken_is_an_error() {
    let first = start_fixture_gateway().await.unwrap();
    let second = start_fixture_gateway_with(Options::new().port(first.address().port())).await;
    assert!(
        matches!(second, Err(gateway_dev::DevError::Io(_))),
        "{second:?}"
    );
}
