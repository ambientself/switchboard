//! The settings the binary reads from its environment, and the binary itself: it refuses to
//! start on missing or contradictory settings, and serves and logs when they are right.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use mock_docs_server::{AcceptedCredential, ConfigError, DEFAULT_TOOLS, Settings, ToolName};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A dummy credential, made up for these tests. It is not a secret anywhere.
const TOKEN: &str = "dummy-gateway-credential-for-tests";

fn sha256_hex(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn settings(vars: &[(&str, &str)]) -> Result<Settings, ConfigError> {
    let vars: HashMap<String, String> = vars
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    Settings::from_vars(|name| vars.get(name).cloned())
}

/// A file holding `contents`, in a directory of its own for this test.
fn token_file(test: &str, contents: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("mock-docs-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("token");
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn exactly_one_credential_must_be_configured() {
    let digest = sha256_hex(TOKEN);
    let file = token_file("both", TOKEN);
    let file = file.to_str().unwrap();
    assert_eq!(settings(&[]).unwrap_err(), ConfigError::NoCredential);
    assert_eq!(
        settings(&[
            ("MOCK_DOCS_TOKEN_FILE", file),
            ("MOCK_DOCS_TOKEN_SHA256", &digest)
        ])
        .unwrap_err(),
        ConfigError::TwoCredentials
    );
    for vars in [
        [("MOCK_DOCS_TOKEN_FILE", file)],
        [("MOCK_DOCS_TOKEN_SHA256", &digest)],
    ] {
        let accepted = settings(&vars).unwrap().config.accepted;
        assert!(accepted.accepts(TOKEN));
        assert!(!accepted.accepts("dummy-workload-token-for-tests"));
        assert!(!accepted.accepts(""));
    }
}

#[test]
fn the_digest_must_be_64_hex_digits_in_either_case() {
    let digest = sha256_hex(TOKEN);
    let upper = digest.to_uppercase();
    assert!(
        settings(&[("MOCK_DOCS_TOKEN_SHA256", &upper)])
            .unwrap()
            .config
            .accepted
            .accepts(TOKEN)
    );
    for bad in [
        &digest[..62],
        &format!("{digest}00"),
        &format!("{}zz", &digest[..62]),
        "",
        TOKEN,
    ] {
        assert_eq!(
            settings(&[("MOCK_DOCS_TOKEN_SHA256", bad)]).unwrap_err(),
            ConfigError::BadDigest,
            "{bad}"
        );
    }
}

#[test]
fn a_token_file_loses_its_trailing_newline_and_must_not_be_empty() {
    let file = token_file("newline", &format!("{TOKEN}\n"));
    let accepted = settings(&[("MOCK_DOCS_TOKEN_FILE", file.to_str().unwrap())])
        .unwrap()
        .config
        .accepted;
    assert_eq!(accepted, AcceptedCredential::token(TOKEN));
    assert!(!accepted.accepts(&format!("{TOKEN}\n")));

    let empty = token_file("empty", " \n");
    assert_eq!(
        settings(&[("MOCK_DOCS_TOKEN_FILE", empty.to_str().unwrap())]).unwrap_err(),
        ConfigError::EmptyToken
    );
    let missing = empty.with_file_name("missing");
    assert!(matches!(
        settings(&[("MOCK_DOCS_TOKEN_FILE", missing.to_str().unwrap())]),
        Err(ConfigError::TokenFile(_))
    ));
}

#[test]
fn defaults_listen_on_8080_offer_two_tools_and_wait_ten_seconds() {
    let digest = sha256_hex(TOKEN);
    let settings = settings(&[("MOCK_DOCS_TOKEN_SHA256", &digest)]).unwrap();
    assert_eq!(settings.listen.to_string(), "0.0.0.0:8080");
    assert_eq!(settings.admin_listen, None);
    assert_eq!(settings.config.tools, DEFAULT_TOOLS);
    assert_eq!(settings.config.slow, Duration::from_secs(10));
}

#[test]
fn each_setting_is_read_and_a_bad_one_refused() {
    let digest = sha256_hex(TOKEN);
    let read = settings(&[
        ("MOCK_DOCS_TOKEN_SHA256", &digest),
        ("MOCK_DOCS_LISTEN", "127.0.0.1:18081"),
        ("MOCK_DOCS_ADMIN_LISTEN", "127.0.0.1:18082"),
        ("MOCK_DOCS_TOOLS", " read_document , search_documents"),
        ("MOCK_DOCS_SLOW_MS", "250"),
    ])
    .unwrap();
    assert_eq!(read.listen.to_string(), "127.0.0.1:18081");
    assert_eq!(read.admin_listen.unwrap().to_string(), "127.0.0.1:18082");
    assert_eq!(
        read.config.tools,
        [ToolName::ReadDocument, ToolName::SearchDocuments]
    );
    assert_eq!(read.config.slow, Duration::from_millis(250));

    let empty = settings(&[("MOCK_DOCS_TOKEN_SHA256", &digest), ("MOCK_DOCS_TOOLS", "")]).unwrap();
    assert!(empty.config.tools.is_empty());

    for (name, value) in [
        ("MOCK_DOCS_LISTEN", "localhost"),
        ("MOCK_DOCS_ADMIN_LISTEN", ""),
        ("MOCK_DOCS_TOOLS", "read_document,delete_document"),
        ("MOCK_DOCS_TOOLS", "read_document,read_document"),
        ("MOCK_DOCS_SLOW_MS", "ten"),
    ] {
        assert!(
            settings(&[("MOCK_DOCS_TOKEN_SHA256", &digest), (name, value)]).is_err(),
            "{name}={value}"
        );
    }
}

// --- The binary ----------------------------------------------------------------------------

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mock-docs-server"));
    for (name, _) in std::env::vars() {
        if name.starts_with("MOCK_DOCS_") {
            command.env_remove(name);
        }
    }
    command
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_binary_refuses_to_start_without_a_credential() {
    let output = binary()
        .env("MOCK_DOCS_LISTEN", "127.0.0.1:0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let line: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(line["event"], "boot_refused");
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn the_binary_serves_and_logs_each_request_as_json() {
    let mut child = Killed(
        binary()
            .env("MOCK_DOCS_TOKEN_SHA256", sha256_hex(TOKEN))
            .env("MOCK_DOCS_LISTEN", "127.0.0.1:0")
            .env("MOCK_DOCS_TOOLS", "read_document")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
    let boot: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(boot["event"], "boot");
    assert_eq!(boot["tools"], json!(["read_document"]));
    assert_eq!(boot["accepted_sha256"], sha256_hex(TOKEN)[..12]);
    assert_eq!(boot["admin_listen"], Value::Null);
    let url = format!("http://{}/mcp", boot["listen"].as_str().unwrap());

    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let refused = client.post(&url).json(&body).send().await.unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    let answer: Value = client
        .post(&url)
        .bearer_auth(TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(answer["result"]["tools"][0]["name"], "read_document");

    let first: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    let second: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(
        (&first["bearer_sha256"], &first["accepted"]),
        (&Value::Null, &json!(false))
    );
    assert_eq!(second["bearer_sha256"], sha256_hex(TOKEN)[..12]);
    assert_eq!(second["accepted"], true);
}
