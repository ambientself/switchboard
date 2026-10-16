//! No GitHub token in the logs: the gateway's, the GitHub connector's and the key custodian's,
//! through a success, a custodian refusal and each vendor error, while the fake GitHub API
//! echoes the token it was sent in every error.
//!
//! A test binary of its own, because it installs a log subscriber for its thread: `tracing`
//! caches whether anything listens at each call site, and tests running alongside on other
//! threads, with no subscriber, could make it cache "nothing does".
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use std::sync::{Arc, Mutex};

use connector_github::fake::Mode;
use github_world::{ACCOUNT, GET_FILE, GET_ISSUE, Options, World};
use serde_json::json;

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn no_log_line_holds_a_github_token() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    // This test's runtime runs every task on this thread: the gateway's, the custodian's and
    // the fakes'.
    let _logging = tracing::subscriber::set_default(subscriber);

    let world = World::new().await;
    world.rest.file("atlas", "x.txt", "x");
    let file = json!({"owner": ACCOUNT, "repo": "atlas", "path": "x.txt"});
    world.team_a(GET_FILE, file.clone()).await.ok();
    for mode in [
        Mode::Status(403),
        Mode::Status(404),
        Mode::RateLimited,
        Mode::Status(500),
        Mode::Status(401),
    ] {
        world.rest.set_mode(mode);
        let issue = json!({"owner": ACCOUNT, "repo": "atlas", "number": 7});
        world.team_a(GET_ISSUE, issue).await.tool_error();
    }
    let refused = World::with(Options {
        custodian_revision: Some("r0"),
        ..Options::default()
    })
    .await;
    refused.team_a(GET_FILE, file).await.tool_error();

    let tokens = world.tokens();
    assert_eq!(
        tokens.len(),
        6,
        "a token for each call that reached the custodian"
    );
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("the key custodian gave no GitHub token"),
        "the refusal is logged: {logs}"
    );
    for token in &tokens {
        assert!(!logs.contains(token.as_str()), "a token was logged");
    }
    // Nor any part of one past GitHub's prefix.
    for token in &tokens {
        assert!(!logs.contains(&token[4..20]), "part of a token was logged");
    }
}
