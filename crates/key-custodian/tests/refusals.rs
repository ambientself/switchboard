//! Each refusal: what the custodian's copy of policy refuses, a peer with the wrong
//! credentials, and the rate limit. A refused request never reaches GitHub.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{ACCOUNT, World, big_repositories, my_uid, request};
use gateway_core::{ErrorKind, PolicyRevision, TeamId, ToolName};
use gateway_registry::Access;
use key_custodian::{ClientError, Refusal, TokenRequest};

fn refused(error: &ClientError) -> Refusal {
    match error {
        ClientError::Refused { reason, .. } => *reason,
        other => panic!("not a refusal: {other:?}"),
    }
}

/// A case: what it is, the edit to a request within policy, and the refusal it must get.
type Case = (&'static str, fn(&mut TokenRequest), Refusal);

#[tokio::test]
async fn each_request_outside_policy_is_refused_with_its_reason() {
    let world = World::new().await;
    let cases: Vec<Case> = vec![
        (
            "a repository outside the team's limit",
            |request| request.repositories = vec![format!("{ACCOUNT}/cosmos")],
            Refusal::RepositoryOutsideLimit,
        ),
        (
            "a repository the team holds under another system",
            |request| request.repositories = vec![format!("{ACCOUNT}/hidden")],
            Refusal::RepositoryOutsideLimit,
        ),
        (
            "one repository inside the limit and one outside",
            |request| {
                request.repositories.push(format!("{ACCOUNT}/secret"));
            },
            Refusal::RepositoryOutsideLimit,
        ),
        (
            "a repository in the limit on another account",
            |request| request.repositories = vec!["other-org/elsewhere".into()],
            Refusal::OtherAccount,
        ),
        (
            "a permission outside the tool's set",
            |request| {
                request
                    .permissions
                    .insert("administration".into(), Access::Read);
            },
            Refusal::PermissionOutsideTool,
        ),
        (
            "a permission above its level in the tool's set",
            |request| {
                request.permissions.insert("issues".into(), Access::Write);
            },
            Refusal::PermissionOutsideTool,
        ),
        (
            "more than 500 repositories",
            |request| {
                request.team = TeamId::new("big");
                request.repositories = big_repositories(501);
            },
            Refusal::TooManyRepositories,
        ),
        (
            "an unknown team",
            |request| request.team = TeamId::new("team-z"),
            Refusal::UnknownTeam,
        ),
        (
            "an unknown tool",
            |request| request.tool = ToolName::parse("github__delete_repo").unwrap(),
            Refusal::UnknownTool,
        ),
        (
            "a tool of another system's entry",
            |request| request.tool = ToolName::parse("jira__get_issue").unwrap(),
            Refusal::UnknownTool,
        ),
        (
            "a stale revision",
            |request| request.revision = PolicyRevision::new("r0"),
            Refusal::StaleRevision,
        ),
        (
            "a stale revision the gateway derived by withdrawing tools",
            |request| request.revision = PolicyRevision::new("r0+withdrawn:docs__read"),
            Refusal::StaleRevision,
        ),
        (
            "a revision that only begins with the custodian's",
            |request| request.revision = PolicyRevision::new("r10"),
            Refusal::StaleRevision,
        ),
        (
            "a revision with no base",
            |request| request.revision = PolicyRevision::new("+withdrawn:docs__read"),
            Refusal::Malformed,
        ),
        (
            "no repositories",
            |request| request.repositories.clear(),
            Refusal::NoRepositories,
        ),
        (
            "no permissions",
            |request| request.permissions.clear(),
            Refusal::NoPermissions,
        ),
        (
            "a repository named twice",
            |request| request.repositories.push(format!("{ACCOUNT}/atlas")),
            Refusal::Malformed,
        ),
        (
            "a repository not written owner/name",
            |request| request.repositories = vec!["atlas".into()],
            Refusal::Malformed,
        ),
        (
            "a permission that is not a name",
            |request| {
                request.permissions = BTreeMap::from([("Issues".into(), Access::Read)]);
            },
            Refusal::Malformed,
        ),
    ];
    for (case, edit, want) in &cases {
        let mut asked = request();
        edit(&mut asked);
        let error = world.client.token(&asked).await.unwrap_err();
        assert_eq!(refused(&error), *want, "{case}: {error}");
        assert_eq!(error.error_kind(), ErrorKind::CustodianRefusal, "{case}");
    }
    assert_eq!(
        world.fake.token_requests(),
        0,
        "no refused request reached GitHub"
    );
    let reasons: Vec<String> = world
        .record
        .lines()
        .iter()
        .map(|line| line["reason"].as_str().unwrap().to_owned())
        .collect();
    let wanted: Vec<&str> = cases.iter().map(|(_, _, want)| want.as_str()).collect();
    assert_eq!(reasons, wanted, "one record line per request");
}

#[tokio::test]
async fn exactly_500_repositories_are_asked_for() {
    let world = World::new().await;
    let mut asked = request();
    asked.team = TeamId::new("big");
    asked.repositories = big_repositories(500);
    world.client.token(&asked).await.unwrap();
    let issued = world.fake.issued();
    assert_eq!(issued[0].asked_repositories.as_ref().unwrap().len(), 500);
}

#[tokio::test]
async fn a_line_that_is_not_a_request_is_refused() {
    let world = World::new().await;
    for line in [
        &b"not json\n"[..],
        b"{}\n",
        br#"{"team":"team-a","tool":"github__get_issue","repositories":[],"permissions":{},"revision":"r1","extra":1}"#,
    ] {
        let answer: serde_json::Value = serde_json::from_slice(&world.raw(line).await).unwrap();
        assert_eq!(answer["refused"]["reason"], "malformed", "{line:?}");
    }
    assert_eq!(world.fake.token_requests(), 0);
}

#[tokio::test]
async fn a_peer_with_other_credentials_is_refused_and_not_read() {
    // The socket is served to another UID; this test's process is a stranger to it. The UID is
    // read from the kernel: SO_PEERCRED on Linux, getpeereid on macOS, through Tokio, so the
    // test is the same on both.
    let world = World::with(|config| config.peer_uid = my_uid() + 1).await;
    let error = world.client.token(&request()).await.unwrap_err();
    assert_eq!(refused(&error), Refusal::Peer);
    assert_eq!(world.fake.token_requests(), 0);
    let lines = world.record.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["reason"], "peer");
    assert_eq!(lines[0]["peer_uid"], my_uid());
    assert!(lines[0]["team"].is_null(), "nothing the peer sent was read");

    // The same request from the UID it serves is issued.
    let world = World::new().await;
    world.client.token(&request()).await.unwrap();
}

#[tokio::test]
async fn each_team_is_limited_to_its_rate() {
    let world = World::with(|config| {
        config.limits.requests_per_minute = 1;
        config.limits.burst = 2;
    })
    .await;
    world.client.token(&request()).await.unwrap();
    world.client.token(&request()).await.unwrap();
    let error = world.client.token(&request()).await.unwrap_err();
    assert_eq!(refused(&error), Refusal::RateLimited);
    assert_eq!(world.fake.issued().len(), 2);

    // Another team has its own bucket.
    let mut other = request();
    other.team = TeamId::new("team-b");
    other.repositories = vec![format!("{ACCOUNT}/cosmos")];
    world.client.token(&other).await.unwrap();

    // A refused request takes nothing from the bucket: team-b's second and last request.
    let mut outside = other.clone();
    outside.repositories = vec![format!("{ACCOUNT}/atlas")];
    for _ in 0..3 {
        let error = world.client.token(&outside).await.unwrap_err();
        assert_eq!(refused(&error), Refusal::RepositoryOutsideLimit);
    }
    world.client.token(&other).await.unwrap();
    let error = world.client.token(&other).await.unwrap_err();
    assert_eq!(refused(&error), Refusal::RateLimited);
}
