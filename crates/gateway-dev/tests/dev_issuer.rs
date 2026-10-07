//! The Compose demo's development issuer: the keys file it writes verifies the tokens it signs,
//! it signs only for the subjects it was started with, and `switchboard-dev issuer` runs it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use gateway_core::PrincipalKind;
use gateway_dev::issuer::{DevIssuer, TOKEN_LIFETIME_SECS};
use gateway_identity::{
    IdentityConfig, IssuerConfig, IssuerKind, SigningAlgorithm, SystemClock, Verification,
    VerifyError,
};
use serde_json::Value;

const ISSUER: &str = "https://dev-issuer.switchboard.test";
const TEAM_A: &str = "workload:team-a:mock-workload";
const STRANGER: &str = "workload:team-a:stranger";
const BINARY: &str = env!("CARGO_BIN_EXE_switchboard-dev");

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("dev-issuer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// An identity gate that trusts the keys in `keys_file` and maps team A's subject only.
fn identity(keys_file: &std::path::Path) -> gateway_identity::Identity {
    let keys = serde_json::from_str(&std::fs::read_to_string(keys_file).unwrap()).unwrap();
    let config = IssuerConfig {
        issuer: ISSUER.into(),
        audiences: BTreeSet::from(["switchboard".to_owned()]),
        kind: IssuerKind::Workload {
            subjects: BTreeMap::from([(TEAM_A.into(), "team-a".into())]),
        },
        algorithm: SigningAlgorithm::Rs256,
        keys,
        max_lifetime: Duration::from_secs(3600),
        leeway: Duration::from_secs(30),
    };
    gateway_identity::Identity::new(IdentityConfig::Enforce(vec![config]), Arc::new(SystemClock))
        .unwrap()
}

async fn get(address: SocketAddr, path: &str) -> (u16, String) {
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{address}{path}"))
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

#[tokio::test]
async fn its_keys_file_verifies_the_tokens_it_signs_for_its_subjects_only() {
    let directory = scratch("library");
    let keys_file = directory.join("shared/jwks.json");
    let issuer = DevIssuer::new(
        ISSUER,
        BTreeSet::from([TEAM_A.to_owned(), STRANGER.to_owned()]),
    )
    .unwrap();
    issuer.write_keys(&keys_file).unwrap();
    let written = std::fs::read_to_string(&keys_file).unwrap();
    assert!(!directory.join("shared/jwks.json.partial").exists());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(gateway_dev::issuer::serve(listener, issuer));
    let identity = identity(&keys_file);

    assert_eq!(get(address, "/healthz").await, (200, "ok".to_owned()));
    let (status, served) = get(address, "/jwks.json").await;
    assert_eq!(status, 200);
    assert_eq!(served.trim(), written.trim());

    let (status, token) = get(
        address,
        &format!("/token?subject={TEAM_A}&audience=switchboard"),
    )
    .await;
    assert_eq!(status, 200, "{token}");
    let Verification::Proved(principal) = identity.check(Some(&token)) else {
        panic!("the dev issuer's token did not verify against its keys file");
    };
    assert_eq!(principal.get().id.subject.as_str(), TEAM_A);
    assert_eq!(
        principal.get().kind,
        PrincipalKind::Workload {
            team: "team-a".into()
        }
    );
    let claims: Value =
        serde_json::from_slice(&base64_decode(token.split('.').nth(1).unwrap())).unwrap();
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        TOKEN_LIFETIME_SECS
    );

    // A subject it signs for that the gateway's manifest does not list: signed, then refused.
    let (status, stranger) = get(
        address,
        &format!("/token?subject={STRANGER}&audience=switchboard"),
    )
    .await;
    assert_eq!(status, 200);
    let Verification::Failed(failure) = identity.check(Some(&stranger)) else {
        panic!("the stranger was proved");
    };
    assert_eq!(failure.detail(), &VerifyError::UnknownSubject);
    // Another audience: signed, then refused.
    let (_, other) = get(
        address,
        &format!("/token?subject={TEAM_A}&audience=not-switchboard"),
    )
    .await;
    let Verification::Failed(failure) = identity.check(Some(&other)) else {
        panic!("a token for another audience was proved");
    };
    assert_eq!(failure.detail(), &VerifyError::AudienceMismatch);

    // A subject it was not started with is never signed.
    let (status, said) = get(
        address,
        "/token?subject=workload:team-b:mock-workload&audience=switchboard",
    )
    .await;
    assert_eq!(status, 403, "{said}");
    for bad in [
        "/token",
        "/token?subject=x",
        "/token?subject=x&audience=a&lifetime=9",
    ] {
        assert_eq!(get(address, bad).await.0, 400, "{bad}");
    }
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .unwrap()
}

#[test]
fn the_subcommand_refuses_to_start_without_what_it_needs() {
    for arguments in [
        &["issuer"][..],
        &[
            "issuer",
            "--listen=127.0.0.1:0",
            "--issuer=x",
            "--keys-out=/tmp/k",
        ],
        &[
            "issuer",
            "--listen=127.0.0.1:0",
            "--issuer=x",
            "--subject=s",
        ],
        &[
            "issuer",
            "--listen=nowhere",
            "--issuer=x",
            "--keys-out=/tmp/k",
            "--subject=s",
        ],
        &[
            "issuer",
            "--listen=127.0.0.1:0",
            "--issuer=x",
            "--keys-out=/tmp/k",
            "--subject=s",
            "--subject=s",
        ],
        &[
            "issuer",
            "--listen=127.0.0.1:0",
            "--issuer=x",
            "--keys-out=/tmp/k",
            "--subject=s",
            "--port=1",
        ],
    ] {
        let output = Command::new(BINARY).args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("usage:"),
            "{arguments:?}"
        );
    }
}

#[tokio::test]
async fn the_subcommand_writes_its_keys_and_serves_tokens() {
    let directory = scratch("binary");
    let keys_file = directory.join("jwks.json");
    let mut child = Command::new(BINARY)
        .args([
            "issuer",
            "--listen=127.0.0.1:0",
            &format!("--issuer={ISSUER}"),
        ])
        .arg(format!("--keys-out={}", keys_file.display()))
        .args(["--subject", TEAM_A])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(ready["event"], "dev_issuer_ready");
    assert_eq!(ready["issuer"], ISSUER);
    let address: SocketAddr = ready["listen"].as_str().unwrap().parse().unwrap();

    let (status, token) = get(
        address,
        &format!("/token?subject={TEAM_A}&audience=switchboard"),
    )
    .await;
    assert_eq!(status, 200);
    assert!(matches!(
        identity(&keys_file).check(Some(&token)),
        Verification::Proved(_)
    ));
    let issued: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(issued["event"], "token_issued");
    assert!(!issued.to_string().contains(&token), "the token was logged");

    let _ = child.kill();
    let _ = child.wait();
}
