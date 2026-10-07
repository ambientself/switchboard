//! The tokens file: one token for each fixture caller, valid at the gateway for as long as the
//! issuers allow, readable by its owner only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::path::PathBuf;

use gateway_dev::start_fixture_gateway;
use gateway_dev::tokens::{REMINT_EVERY, TOKEN_LIFETIME_SECS, write_tokens};
use gateway_testkit::{DEFAULT_MAX_LIFETIME, SURFACE_ALL, SURFACE_READ};
use serde_json::{Value, json};
use support::{legacy, post};

/// A fresh directory under the system's temporary directory for one test.
fn scratch(test: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("gateway-dev-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

/// The claims of a JWT, read without checking it.
fn claims(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn every_token_in_the_file_is_accepted_and_lives_as_long_as_allowed() {
    let gateway = start_fixture_gateway().await.unwrap();
    let directory = scratch("accepted");
    let path = directory.join("nested/tokens.json");
    write_tokens(&path, &gateway).unwrap();

    let document: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        document["urls"][SURFACE_READ],
        json!(gateway.url(SURFACE_READ))
    );
    assert_eq!(
        document["urls"][SURFACE_ALL],
        json!(gateway.url(SURFACE_ALL))
    );
    assert!(
        document["note"]
            .as_str()
            .unwrap()
            .contains("not credentials")
    );
    for caller in ["team_a", "team_b", "user"] {
        let token = document[caller].as_str().unwrap();
        let claims = claims(token);
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            TOKEN_LIFETIME_SECS
        );
        assert_eq!(claims["exp"], document["expires_at"]);
        let (status, body) = post(
            &gateway.url(SURFACE_READ),
            Some(token),
            &legacy("tools/list", json!({})),
        )
        .await;
        assert_eq!(status, 200, "{caller}: {body}");
    }
    assert!(!path.with_extension("json.partial").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn tokens_live_as_long_as_the_issuers_allow_and_are_written_again_well_before_they_expire() {
    assert_eq!(TOKEN_LIFETIME_SECS, DEFAULT_MAX_LIFETIME);
    assert!(REMINT_EVERY.as_secs() * 2 <= TOKEN_LIFETIME_SECS);
}

#[cfg(unix)]
#[tokio::test]
async fn only_the_owner_may_read_the_file_even_when_it_was_there_before() {
    use std::os::unix::fs::PermissionsExt;

    let gateway = start_fixture_gateway().await.unwrap();
    let directory = scratch("private");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("tokens.json");
    for leftover in [&path, &directory.join("tokens.json.partial")] {
        std::fs::write(leftover, "{}").unwrap();
        std::fs::set_permissions(leftover, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    write_tokens(&path, &gateway).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    std::fs::remove_dir_all(directory).unwrap();
}
