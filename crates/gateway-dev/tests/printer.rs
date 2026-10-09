//! The audit printer: a line for each thing the store does, after it does it, and the store's
//! result passed on unchanged.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use gateway_dev::{Options, start_fixture_gateway_with};
use gateway_mcp::DENIAL_CODE;
use gateway_testkit::{Caller, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT};
use serde_json::{Value, json};
use support::{Lines, legacy, post};

/// Whether `id` is a UUIDv7 as the gateway writes one: lowercase and hyphenated, with version
/// 7 and the RFC 9562 variant.
fn is_uuid_v7(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.iter().map(|group| group.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|group| group.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
        && groups[2].starts_with('7')
        && groups[3].starts_with(['8', '9', 'a', 'b'])
}

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
    let first = printed[0]["row"].as_str().unwrap();
    assert!(is_uuid_v7(first), "{first}");
    assert_eq!(
        printed[0]["record"]["decision"],
        json!("allow"),
        "{printed:?}"
    );
    assert_eq!(printed[0]["record"]["instance"], json!("switchboard-dev"));
    assert_eq!(printed[0]["record"]["kind"], json!("call"));
    assert_eq!(printed[1]["audit"], json!("finished"));
    assert_eq!(
        printed[1]["row"],
        json!(first),
        "finish names the row begin wrote"
    );
    assert_eq!(printed[1]["completion"]["outcome"], json!("ok"));
    assert_eq!(printed[2]["audit"], json!("begun"));
    let second = printed[2]["row"].as_str().unwrap();
    assert!(is_uuid_v7(second), "{second}");
    assert_ne!(first, second, "each call has a row of its own");
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
    let row = printed[0]["row"].as_str().unwrap();
    assert!(
        is_uuid_v7(row),
        "a failed begin names the row it was for: {row}"
    );
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
    assert_eq!(
        printed[1]["row"], printed[0]["row"],
        "the failed finish names the row begin wrote"
    );
}

/// A list row is printed once it is written, and a list that fails is printed as failed. Until
/// the path writes list rows (#40), the printer is driven directly.
#[tokio::test]
async fn a_list_row_is_printed_as_it_is_written() {
    use std::sync::Arc;

    use gateway_core::AuditStore;
    use gateway_core::audit::{self, ListRecord};
    use gateway_dev::AuditPrinter;
    use gateway_testkit::{Fixture, InMemoryAuditStore, SURFACE_ALL, row_start};

    let lines = Lines::default();
    let store = Arc::new(InMemoryAuditStore::new());
    let printer = AuditPrinter::new(store.clone(), Box::new(lines.clone()));
    let fixture = Fixture::new().unwrap();
    let caller = fixture.team_a_workload(SURFACE_ALL).unwrap();
    let list = |start| {
        audit::listed(
            &printer as &dyn AuditStore,
            start,
            &caller,
            fixture.policy.revision().clone(),
            gateway_core::list_tools(&fixture.policy, &caller),
            None,
        )
    };
    let start = row_start();
    let _ = list(start.clone()).await.unwrap();
    store.fail_next_begin();
    let failed = row_start();
    assert!(list(failed.clone()).await.is_err());

    let printed = lines.json();
    assert_eq!(printed.len(), 2, "{printed:?}");
    assert_eq!(printed[0]["audit"], json!("listed"));
    assert_eq!(printed[0]["row"], json!(start.row.as_str()));
    let (_, record) = store.list_rows().pop().unwrap();
    assert_eq!(
        serde_json::from_value::<ListRecord>(printed[0]["record"].clone()).unwrap(),
        record
    );
    assert_eq!(printed[1]["audit"], json!("list_failed"));
    assert_eq!(printed[1]["row"], json!(failed.row.as_str()));
}
