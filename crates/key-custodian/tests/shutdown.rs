//! A graceful stop revokes the tokens the custodian still keeps, within a deadline, and says
//! what it could not revoke.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{World, request};
use key_custodian::Stopped;
use key_custodian::clock;
use key_custodian::fake::Behaviour;

/// How long a test lets a stop take before it calls the stop unbounded.
const OUTER: Duration = Duration::from_secs(8);

async fn stop(world: &mut World, deadline: Duration) -> Stopped {
    let running = world.running.take().unwrap();
    tokio::time::timeout(OUTER, running.stop_within(deadline))
        .await
        .expect("the stop was not bounded by its deadline")
}

#[tokio::test]
async fn a_stop_revokes_every_token_still_working() {
    let mut world = World::new().await;
    // One within its five minutes, revoked at their end had the custodian kept running; and one
    // GitHub issued for less, which nothing would have revoked.
    let first = world.client.token(&request()).await.unwrap();
    world.fake.set_behaviour(Behaviour::ExpireIn(60));
    let second = world.client.token(&request()).await.unwrap();
    assert!(world.fake.revoked().is_empty());
    let socket = world.running().socket().to_owned();

    let stopped = stop(&mut world, Duration::from_secs(5)).await;
    assert!(!socket.exists(), "the socket is removed");
    assert_eq!(
        stopped,
        Stopped {
            revoked: 2,
            not_revoked: 0,
            in_flight: 0
        }
    );
    let mut revoked = world.fake.revoked();
    revoked.sort();
    let mut handed = vec![first.expose().to_owned(), second.expose().to_owned()];
    handed.sort();
    assert_eq!(revoked, handed);
}

#[tokio::test]
async fn a_token_already_revoked_is_not_revoked_again_at_the_stop() {
    let mut world = World::with(|config| config.limits.token_lifetime_seconds = 1).await;
    let token = world.client.token(&request()).await.unwrap();
    for _ in 0..40 {
        if !world.fake.revoked().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(world.fake.revoked(), vec![token.expose().to_owned()]);
    let attempts = world.fake.revocation_attempts().len();
    let stopped = stop(&mut world, Duration::from_secs(5)).await;
    assert_eq!(stopped, Stopped::default());
    assert_eq!(world.fake.revocation_attempts().len(), attempts);
}

#[tokio::test]
async fn a_revocation_github_fails_at_the_stop_is_tried_again_within_the_deadline() {
    let mut world = World::new().await;
    let token = world.client.token(&request()).await.unwrap();
    world.fake.fail_revocations(1);
    let stopped = stop(&mut world, Duration::from_secs(4)).await;
    assert_eq!(stopped.revoked, 1);
    assert_eq!(stopped.not_revoked, 0);
    assert_eq!(world.fake.revoked(), vec![token.expose().to_owned()]);
    assert_eq!(world.fake.revocation_attempts().len(), 2);
}

#[tokio::test]
async fn a_stop_github_does_not_answer_ends_at_its_deadline() {
    // GitHub may take ten seconds to answer a revocation; the stop gives up at its own
    // deadline, and says the token is not revoked.
    let mut world = World::with(|config| config.github.deadline_seconds = 10).await;
    world.client.token(&request()).await.unwrap();
    world.fake.hang_revocations(true);
    let started = Instant::now();
    let stopped = stop(&mut world, Duration::from_secs(1)).await;
    let took = started.elapsed();
    assert!(took < Duration::from_millis(2500), "{took:?}");
    assert_eq!(
        stopped,
        Stopped {
            revoked: 0,
            not_revoked: 1,
            in_flight: 0
        }
    );
    assert!(world.fake.revoked().is_empty());
    assert!(!world.fake.revocation_attempts().is_empty());
}

#[tokio::test]
async fn a_token_past_githubs_expiry_is_not_revoked_at_the_stop() {
    let mut world = World::new().await;
    world.fake.set_behaviour(Behaviour::ExpireIn(1));
    let token = world.client.token(&request()).await.unwrap();
    while clock::now() < token.expires_at() + 1 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stopped = stop(&mut world, Duration::from_secs(2)).await;
    assert_eq!(stopped, Stopped::default());
    assert!(world.fake.revocation_attempts().is_empty());
}

#[tokio::test]
async fn a_stop_with_a_request_in_flight_ends_at_its_deadline() {
    // GitHub does not answer the token request, and would be given ten seconds.
    let mut world = World::with(|config| config.github.deadline_seconds = 10).await;
    world.fake.set_behaviour(Behaviour::Hang);
    let client = world.client.clone();
    let asking = tokio::spawn(async move { client.token(&request()).await });
    while world.fake.token_requests() == 0 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let started = Instant::now();
    let stopped = stop(&mut world, Duration::from_secs(1)).await;
    let took = started.elapsed();
    assert!(took < Duration::from_millis(2500), "{took:?}");
    assert_eq!(
        stopped,
        Stopped {
            revoked: 0,
            not_revoked: 0,
            in_flight: 1
        }
    );
    asking.abort();
}
