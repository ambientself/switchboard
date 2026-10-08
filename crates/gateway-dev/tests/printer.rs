//! The audit printer: a line for each thing the store does, after it does it, and the store's
//! result passed on unchanged.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use gateway_dev::{Options, start_fixture_gateway_with};
use gateway_mcp::DENIAL_CODE;
use gateway_testkit::{Caller, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT};
use serde_json::{Value, json};
use support::{Lines, legacy, post};

fn read(document: &str) -> Value {
    legacy(
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {"document": document}}),
    )
}

#[tokio::test]
async fn each_row_is_printed_as_it_is_begun_and_finished() {
    let lines = Lines::default();
    let gateway =
        start_fixture_gateway_with(Options::new().print_audit_to(Box::new(lines.clone())))
            .await
            .unwrap();
    let url = gateway.url(SURFACE_READ);
    let token = gateway.token(Caller::TeamA);
    post(&url, Some(&token), &read(TEAM_A_DOCUMENT)).await;
    post(&url, Some(&token), &read(TEAM_B_DOCUMENT)).await;

    let rows = gateway.store().rows();
    let printed = lines.json();
    assert_eq!(printed.len(), 3, "{printed:?}");
    assert_eq!(printed[0]["audit"], json!("begun"));
    assert_eq!(printed[0]["row"], json!("0"));
    assert_eq!(
        printed[0]["record"]["decision"],
        json!("allow"),
        "{printed:?}"
    );
    assert_eq!(printed[1]["audit"], json!("finished"));
    assert_eq!(printed[1]["row"], json!("0"));
    assert_eq!(printed[1]["completion"]["outcome"], json!("ok"));
    assert_eq!(printed[2]["audit"], json!("begun"));
    assert_eq!(printed[2]["row"], json!("1"));
    // A denied row is printed as the store holds it, sentence and all, and is never finished.
    assert_eq!(
        printed[2]["record"],
        serde_json::to_value(&rows[1]).unwrap()
    );
    assert!(
        printed[2]["record"]["sentence"]
            .as_str()
            .unwrap()
            .contains(TEAM_B_DOCUMENT)
    );
}

#[tokio::test]
async fn a_begin_that_fails_still_refuses_the_call() {
    let lines = Lines::default();
    let gateway =
        start_fixture_gateway_with(Options::new().print_audit_to(Box::new(lines.clone())))
            .await
            .unwrap();
    gateway.store().fail_next_begin();
    let token = gateway.token(Caller::TeamA);
    let (status, body) = post(
        &gateway.url(SURFACE_READ),
        Some(&token),
        &read(TEAM_A_DOCUMENT),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["error"]["code"], json!(DENIAL_CODE), "{body}");
    assert!(
        gateway.connector().received().is_empty(),
        "the call ran with no row"
    );
    assert!(gateway.store().rows().is_empty());
    let printed = lines.json();
    assert_eq!(printed.len(), 1, "{printed:?}");
    assert_eq!(printed[0]["audit"], json!("begin_failed"));
}

#[tokio::test]
async fn a_finish_that_fails_is_printed_and_the_answer_stands() {
    let lines = Lines::default();
    let gateway =
        start_fixture_gateway_with(Options::new().print_audit_to(Box::new(lines.clone())))
            .await
            .unwrap();
    gateway.store().fail_next_finish();
    let token = gateway.token(Caller::TeamA);
    let (status, body) = post(
        &gateway.url(SURFACE_READ),
        Some(&token),
        &read(TEAM_A_DOCUMENT),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(gateway.store().rows()[0].completion, None);
    let printed = lines.json();
    let events: Vec<&Value> = printed.iter().map(|line| &line["audit"]).collect();
    assert_eq!(events, [&json!("begun"), &json!("finish_failed")]);
    assert_eq!(printed[1]["row"], json!("0"));
}
