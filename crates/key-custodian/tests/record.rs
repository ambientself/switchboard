//! The custodian's record, its counters, and what leaves the process: the record never holds a
//! token, and nothing a client receives, nor the record nor the metrics, holds the key.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{ACCOUNT, KEY, World, big_repositories, request};
use gateway_core::{PolicyRevision, TeamId};
use key_custodian::fake::Behaviour;

#[tokio::test]
async fn the_record_has_a_line_per_request_and_no_token() {
    let world = World::new().await;
    let first = world.client.token(&request()).await.unwrap();
    let second = world.client.token(&request()).await.unwrap();
    let mut stale = request();
    stale.revision = PolicyRevision::new("r0");
    world.client.token(&stale).await.unwrap_err();
    let mut big = request();
    big.team = TeamId::new("big");
    big.repositories = big_repositories(65);
    world.client.token(&big).await.unwrap();

    let text = world.record.text();
    for token in [first.expose(), second.expose()] {
        assert!(!text.contains(token), "the record holds a token");
    }
    for issued in world.fake.issued() {
        assert!(!text.contains(&issued.token));
    }
    assert!(
        !text.contains("ghs_"),
        "nothing like a token is in the record"
    );

    let lines = world.record.lines();
    assert_eq!(lines.len(), 4);
    let line = &lines[0];
    assert_eq!(line["outcome"], "issued");
    assert!(line["reason"].is_null());
    assert_eq!(line["team"], "team-a");
    assert_eq!(line["tool"], "github__get_issue");
    assert_eq!(line["repository_count"], 1);
    assert_eq!(
        line["repositories"],
        serde_json::json!([format!("{ACCOUNT}/atlas")])
    );
    assert_eq!(line["permissions"], serde_json::json!({ "issues": "read" }));
    assert_eq!(line["revision"], "r1");
    assert_eq!(line["checked_revision"], "r1");
    assert_eq!(line["expires_at"], first.expires_at());
    assert!(line["peer_uid"].is_u64());
    assert!(line["at"].is_u64());

    assert_eq!(lines[2]["outcome"], "refused");
    assert_eq!(lines[2]["reason"], "stale_revision");
    assert_eq!(lines[2]["revision"], "r0");
    assert_eq!(lines[2]["checked_revision"], "r1");

    // Past 64 repositories a line counts them and lists none.
    assert_eq!(lines[3]["repository_count"], 65);
    assert!(lines[3]["repositories"].is_null());
}

#[tokio::test]
async fn the_counters_count_each_outcome() {
    let world = World::new().await;
    world.client.token(&request()).await.unwrap();
    let mut stale = request();
    stale.revision = PolicyRevision::new("r0");
    world.client.token(&stale).await.unwrap_err();
    world.fake.set_behaviour(Behaviour::Fail);
    world.client.token(&request()).await.unwrap_err();
    let metrics = world.metrics().await;
    for series in [
        "switchboard_custodian_requests_total{outcome=\"issued\",reason=\"\"} 1",
        "switchboard_custodian_requests_total{outcome=\"refused\",reason=\"stale_revision\"} 1",
        "switchboard_custodian_requests_total{outcome=\"refused\",reason=\"peer\"} 0",
        "switchboard_custodian_requests_total{outcome=\"failed\",reason=\"vendor_failed\"} 1",
        "switchboard_custodian_revocations_total{result=\"revoked\"} 0",
        "switchboard_custodian_policy_reloads_total{result=\"loaded\"} 0",
    ] {
        assert!(
            metrics.contains(series),
            "{series} missing from:\n{metrics}"
        );
    }
}

/// The key's base64 lines, each long enough that finding one anywhere means the key leaked.
fn key_lines() -> Vec<String> {
    let lines: Vec<String> = KEY
        .private_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() >= 40)
        .map(str::to_owned)
        .collect();
    assert!(lines.len() > 10, "the key's PEM has no body");
    lines
}

#[tokio::test]
async fn the_key_never_leaves_the_custodian() {
    let world = World::new().await;
    let mut received: Vec<u8> = Vec::new();
    let line = |request: &key_custodian::TokenRequest| {
        let mut line = serde_json::to_vec(request).unwrap();
        line.push(b'\n');
        line
    };
    // An issued token, a refusal, a malformed line, and each of GitHub's failures.
    received.extend(world.raw(&line(&request())).await);
    let mut stale = request();
    stale.revision = PolicyRevision::new("r0");
    received.extend(world.raw(&line(&stale)).await);
    received.extend(world.raw(b"not json\n").await);
    for behaviour in [Behaviour::Refuse(401), Behaviour::Fail, Behaviour::Widen] {
        world.fake.set_behaviour(behaviour);
        received.extend(world.raw(&line(&request())).await);
    }
    let received = String::from_utf8(received).unwrap();
    assert!(received.contains("\"issued\""), "{received}");
    let record = world.record.text();
    let metrics = world.metrics().await;
    for key_line in key_lines() {
        for (place, text) in [
            ("an answer", &received),
            ("the record", &record),
            ("the metrics", &metrics),
        ] {
            assert!(!text.contains(&key_line), "{place} holds part of the key");
        }
    }
    assert!(!received.contains("PRIVATE KEY"));
}
