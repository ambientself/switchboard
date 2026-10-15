//! Tokens issued within policy: narrowed exactly, never handed out for longer than GitHub
//! issued them, revoked at the end of their lifetime; and what comes back when GitHub does not
//! give one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use common::{ACCOUNT, OTHER_KEY, World, request, write_file};
use gateway_core::{ErrorKind, ToolName};
use gateway_registry::Access;
use key_custodian::clock;
use key_custodian::fake::Behaviour;
use key_custodian::{ClientError, Failure};

#[tokio::test]
async fn a_request_within_policy_gets_a_token_narrowed_exactly() {
    let world = World::new().await;
    let mut asked = request();
    asked.tool = ToolName::parse("github__get_file").unwrap();
    asked.repositories = vec![format!("{ACCOUNT}/atlas"), format!("{ACCOUNT}/borealis")];
    asked.permissions = BTreeMap::from([
        ("contents".to_owned(), Access::Read),
        ("issues".to_owned(), Access::Read),
    ]);
    let token = world.client.token(&asked).await.unwrap();

    let issued = world.fake.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(token.expose(), issued[0].token);
    assert_eq!(
        issued[0].asked_repositories,
        Some(vec!["atlas".to_owned(), "borealis".to_owned()]),
        "GitHub is asked for exactly the repositories requested"
    );
    assert_eq!(
        issued[0].asked_permissions,
        Some(BTreeMap::from([
            ("contents".to_owned(), "read".to_owned()),
            ("issues".to_owned(), "read".to_owned()),
        ])),
        "GitHub is asked for exactly the permissions requested"
    );
    assert_eq!(
        issued[0].repositories,
        BTreeSet::from(["atlas".to_owned(), "borealis".to_owned()])
    );
    // The default lifetime is five minutes, well inside GitHub's hour.
    let now = clock::now();
    assert!(token.expires_at() <= now + 300, "{}", token.expires_at());
    assert!(
        token.expires_at() + 5 >= now + 300,
        "{}",
        token.expires_at()
    );
    assert!(token.expires_at() < issued[0].expires_at);
}

#[tokio::test]
async fn a_propose_tool_may_ask_for_write_within_its_set() {
    let world = World::new().await;
    let mut asked = request();
    asked.tool = ToolName::parse("github__propose").unwrap();
    asked.permissions = BTreeMap::from([
        ("contents".to_owned(), Access::Write),
        ("pull_requests".to_owned(), Access::Read),
    ]);
    world.client.token(&asked).await.unwrap();
    assert_eq!(
        world.fake.issued()[0].asked_permissions,
        Some(BTreeMap::from([
            ("contents".to_owned(), "write".to_owned()),
            ("pull_requests".to_owned(), "read".to_owned()),
        ]))
    );
}

#[tokio::test]
async fn a_token_shows_nothing_of_itself() {
    let world = World::new().await;
    let token = world.client.token(&request()).await.unwrap();
    let secret = token.expose().to_owned();
    assert!(!format!("{token:?}").contains(&secret));
    assert!(!format!("{token}").contains(&secret));
    assert!(format!("{token:?}").contains("redacted"));
}

#[tokio::test]
async fn a_token_is_revoked_when_its_lifetime_ends() {
    let world = World::with(|config| config.limits.token_lifetime_seconds = 1).await;
    let before = clock::now();
    let token = world.client.token(&request()).await.unwrap();
    assert!(token.expires_at() <= before + 2, "{}", token.expires_at());
    for _ in 0..40 {
        if !world.fake.revoked().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(world.fake.revoked(), vec![token.expose().to_owned()]);
    assert!(
        clock::now() >= token.expires_at(),
        "revoked at its expiry, not before"
    );
    assert!(
        world
            .metrics()
            .await
            .contains("switchboard_custodian_revocations_total{result=\"revoked\"} 1")
    );
}

#[tokio::test]
async fn a_token_is_never_handed_out_for_longer_than_github_issued_it() {
    let world = World::new().await;
    world.fake.set_behaviour(Behaviour::ExpireIn(30));
    let token = world.client.token(&request()).await.unwrap();
    assert_eq!(token.expires_at(), world.fake.issued()[0].expires_at);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        world.fake.revoked().is_empty(),
        "GitHub's own expiry ends it; nothing to revoke"
    );
}

#[tokio::test]
async fn a_token_broader_than_asked_is_revoked_and_not_handed_out() {
    let world = World::new().await;
    world.fake.set_behaviour(Behaviour::Widen);
    let error = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Failed {
                reason: Failure::Widened,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.error_kind(), ErrorKind::Other);
    let issued = world.fake.issued();
    assert_eq!(issued.len(), 1);
    assert!(issued[0].repositories.contains("secret"));
    assert_eq!(world.fake.revoked(), vec![issued[0].token.clone()]);
}

#[tokio::test]
async fn githubs_refusal_failure_and_silence_each_come_back_typed() {
    let world = World::new().await;
    world.fake.set_behaviour(Behaviour::Refuse(422));
    let refused = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            refused,
            ClientError::Failed {
                reason: Failure::VendorRefused,
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(refused.error_kind(), ErrorKind::VendorRefusal);

    world.fake.set_behaviour(Behaviour::Fail);
    let failed = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            failed,
            ClientError::Failed {
                reason: Failure::VendorFailed,
                ..
            }
        ),
        "{failed:?}"
    );
    assert_eq!(failed.error_kind(), ErrorKind::Other);

    world.fake.set_behaviour(Behaviour::Hang);
    let silent = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            silent,
            ClientError::Failed {
                reason: Failure::VendorTimeout,
                ..
            }
        ),
        "{silent:?}"
    );
    assert!(world.fake.issued().is_empty());
    let outcomes: Vec<String> = world
        .record
        .lines()
        .iter()
        .map(|line| format!("{} {}", line["outcome"], line["reason"]))
        .collect();
    assert_eq!(
        outcomes,
        [
            r#""failed" "vendor_refused""#,
            r#""failed" "vendor_failed""#,
            r#""failed" "vendor_timeout""#,
        ]
    );
}

#[tokio::test]
async fn the_fake_refuses_a_jwt_the_app_did_not_sign() {
    // A custodian whose key file holds a key GitHub does not know for the App.
    let world = World::with(|config| {
        let dir = config.socket.parent().unwrap().to_owned();
        let other = dir.join("other-key.pem");
        write_file(&other, &OTHER_KEY.private_pem, 0o600);
        config.github.key_file = other;
    })
    .await;
    let error = world.client.token(&request()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Failed {
                reason: Failure::VendorRefused,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(world.fake.jwt_refusals(), 1);
    assert!(world.fake.issued().is_empty());

    // The same request with the App's own key is accepted.
    let world = World::new().await;
    world.client.token(&request()).await.unwrap();
    assert_eq!(world.fake.jwt_refusals(), 0);
}
