//! The custodian reloads its copy of policy as the gateway reloads the registry, and checks
//! each request against the copy it holds at the time.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{World, registry, request, write_file};
use gateway_core::PolicyRevision;
use key_custodian::{ClientError, Refusal};

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..60 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the custodian did not reload");
}

#[tokio::test]
async fn a_new_revision_is_served_and_the_old_one_refused() {
    let world = World::new().await;
    world.client.token(&request()).await.unwrap();
    write_file(&world.registry, &registry("r2"), 0o644);
    until(|| {
        world
            .running()
            .counters()
            .render()
            .contains("switchboard_custodian_policy_reloads_total{result=\"loaded\"} 1")
    })
    .await;
    let error = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Refused {
                reason: Refusal::StaleRevision,
                ..
            }
        ),
        "{error:?}"
    );
    let mut current = request();
    current.revision = PolicyRevision::new("r2");
    world.client.token(&current).await.unwrap();
    let lines = world.record.lines();
    assert_eq!(lines[1]["checked_revision"], "r2");
    assert_eq!(lines[2]["checked_revision"], "r2");
}

#[tokio::test]
async fn a_changed_policy_under_the_same_revision_is_refused() {
    let world = World::new().await;
    // team-a loses borealis, but the revision stays r1.
    let narrowed = registry("r1").replace(
        "  { system = \"github\", kind = \"repository\", identifier = \"example-org/borealis\" },\n",
        "",
    );
    assert_ne!(narrowed, registry("r1"));
    write_file(&world.registry, &narrowed, 0o644);
    until(|| {
        world
            .running()
            .counters()
            .render()
            .contains("switchboard_custodian_policy_reloads_total{result=\"refused\"} 1")
    })
    .await;
    let mut borealis = request();
    borealis.repositories = vec!["example-org/borealis".into()];
    world.client.token(&borealis).await.unwrap();
}

#[tokio::test]
async fn a_file_that_does_not_load_keeps_the_copy_served() {
    let world = World::new().await;
    write_file(&world.registry, "revision = \"r2\"\n", 0o644);
    until(|| {
        world
            .running()
            .counters()
            .render()
            .contains("switchboard_custodian_policy_reloads_total{result=\"refused\"} 1")
    })
    .await;
    world.client.token(&request()).await.unwrap();
}

#[tokio::test]
async fn a_github_entry_listing_a_tool_of_another_system_keeps_the_copy_served() {
    let world = World::new().await;
    let text = registry("r2").replace(
        r#"tools = ["github__propose"]"#,
        r#"tools = ["github__propose", "docs__write"]"#,
    );
    assert_ne!(text, registry("r2"));
    write_file(&world.registry, &text, 0o644);
    until(|| {
        world
            .running()
            .counters()
            .render()
            .contains("switchboard_custodian_policy_reloads_total{result=\"refused\"} 1")
    })
    .await;
    // Still r1: the request at r1 is served, and r2 is stale.
    world.client.token(&request()).await.unwrap();
    let mut next = request();
    next.revision = PolicyRevision::new("r2");
    let error = world.client.token(&next).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Refused {
                reason: Refusal::StaleRevision,
                ..
            }
        ),
        "{error:?}"
    );
}
