//! The custodian refuses to start without a key it alone can read, or with a socket others
//! could reach.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;

use common::{World, my_uid, registry, write_file};
use key_custodian::{Config, PolicyError, StartError};

#[tokio::test]
async fn no_key_refuses_to_start() {
    let (error, _) = World::try_with(|config| {
        config.github.key_file = config.socket.with_file_name("missing.pem");
    })
    .await
    .err()
    .unwrap();
    assert!(matches!(error, StartError::NoKey(_)), "{error}");
}

#[tokio::test]
async fn an_unreadable_key_refuses_to_start() {
    let (error, _) = World::try_with(|config| {
        std::fs::set_permissions(
            &config.github.key_file,
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
    })
    .await
    .err()
    .unwrap();
    if my_uid() == 0 {
        // Root reads a file whatever its mode; the mode check above it still holds.
        return;
    }
    assert!(matches!(error, StartError::KeyUnreadable(_)), "{error}");
}

#[tokio::test]
async fn a_key_others_can_read_refuses_to_start() {
    for mode in [0o644, 0o640, 0o604, 0o610] {
        let (error, _) = World::try_with(|config| {
            std::fs::set_permissions(
                &config.github.key_file,
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
        })
        .await
        .err()
        .unwrap();
        assert!(
            matches!(error, StartError::KeyOpen { mode: found, .. } if found == mode),
            "{mode:o}: {error}"
        );
    }
}

#[tokio::test]
async fn a_file_that_is_not_a_key_refuses_to_start() {
    for text in [
        "",
        "not a key",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ] {
        let (error, _) = World::try_with(|config| {
            write_file(&config.github.key_file, text, 0o600);
        })
        .await
        .err()
        .unwrap();
        assert!(
            matches!(error, StartError::KeyInvalid(_)),
            "{text:?}: {error}"
        );
    }
}

#[tokio::test]
async fn a_socket_others_could_reach_refuses_to_start() {
    for mode in [0o666, 0o604, 0o602, 0o601] {
        let (error, socket) = World::try_with(|config| config.socket_mode = mode)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, StartError::SocketMode(found) if found == mode),
            "{mode:o}: {error}"
        );
        assert!(!socket.exists(), "no socket is made");
    }
}

#[tokio::test]
async fn a_stale_socket_is_replaced_by_one_of_the_configured_mode() {
    let world = World::with(|config| {
        // An earlier run's socket, left behind with a mode open to anyone.
        drop(std::os::unix::net::UnixListener::bind(&config.socket).unwrap());
        std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o777)).unwrap();
        config.socket_mode = 0o600;
    })
    .await;
    let metadata = std::fs::symlink_metadata(world.running().socket()).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn something_other_than_a_socket_at_its_path_refuses_to_start() {
    let (error, socket) = World::try_with(|config| {
        write_file(&config.socket, "left here", 0o600);
    })
    .await
    .err()
    .unwrap();
    assert!(matches!(error, StartError::SocketPathTaken(_)), "{error}");
    let _ = socket;
}

#[tokio::test]
async fn a_registry_that_does_not_load_refuses_to_start() {
    let (error, _) = World::try_with(|config| {
        write_file(&config.registry, "revision = \"r1\"\n", 0o644);
    })
    .await
    .err()
    .unwrap();
    assert!(matches!(error, StartError::Policy(_)), "{error}");
}

#[tokio::test]
async fn a_github_entry_listing_a_tool_of_another_system_refuses_to_start() {
    // The loader accepts each of these on a built-in entry; the custodian does not.
    for tool in ["docs__read", "githubber__read", "github__"] {
        let (error, socket) = World::try_with(|config| {
            let text = registry("r1").replace(
                r#"tools = ["github__get_issue", "github__get_file"]"#,
                &format!(r#"tools = ["github__get_issue", "github__get_file", "{tool}"]"#),
            );
            write_file(&config.registry, &text, 0o644);
        })
        .await
        .err()
        .unwrap();
        assert!(
            matches!(
                &error,
                StartError::Policy(PolicyError::ToolOutsideSystem { tool: found, .. })
                    if found.as_str() == tool
            ),
            "{tool}: {error}"
        );
        assert!(!socket.exists(), "{tool}: no socket is made");
    }
}

#[tokio::test]
async fn an_api_url_must_be_https_or_loopback() {
    for url in [
        "http://api.github.com",
        "https://api.github.com/v3",
        "ftp://127.0.0.1",
    ] {
        let (error, _) = World::try_with(|config| config.github.api_url = url.into())
            .await
            .err()
            .unwrap();
        assert!(matches!(error, StartError::Api(_)), "{url}: {error}");
    }
    let (error, _) =
        World::try_with(|config| config.github.api_url = "https://api.github.com".into())
            .await
            .err()
            .unwrap();
    assert!(
        matches!(error, StartError::Api(_)),
        "https needs a CA file: {error}"
    );
}

#[test]
fn the_configuration_file_parses_with_its_defaults() {
    let config = Config::from_toml_str(
        r#"
socket = "/run/switchboard-custodian/custodian.sock"
peer_uid = 10001
registry = "/etc/switchboard/registry/registry.toml"

[github]
api_url = "https://api.github.com"
ca_file = "/etc/ssl/certs/ca-certificates.crt"
app_id = "123456"
installation_id = 7890
account = "example-org"
key_file = "/run/secrets/github-app/private-key.pem"
"#,
    )
    .unwrap();
    assert_eq!(config.socket_mode, 0o660);
    assert_eq!(config.registry_poll_seconds, 5);
    assert_eq!(config.github.deadline_seconds, 10);
    assert_eq!(config.limits.requests_per_minute, 30);
    assert_eq!(config.limits.burst, 10);
    assert_eq!(config.limits.token_lifetime_seconds, 300);
    assert!(Config::from_toml_str("socket = \"/x\"\nunknown = 1\n").is_err());
}

#[tokio::test]
async fn a_limit_out_of_range_refuses_to_start() {
    let cases: [fn(&mut Config); 4] = [
        |config| config.limits.token_lifetime_seconds = 3601,
        |config| config.limits.token_lifetime_seconds = 0,
        |config| config.limits.burst = 0,
        |config| config.limits.requests_per_minute = 0,
    ];
    for adjust in cases {
        let (error, _) = World::try_with(adjust).await.err().unwrap();
        assert!(matches!(error, StartError::Limit { .. }), "{error}");
    }
}
