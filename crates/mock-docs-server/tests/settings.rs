//! The settings the binary reads from its environment, and the binary itself: it refuses to
//! start on missing or contradictory settings, and serves and logs when they are right.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use mock_docs_server::{
    AcceptedCredential, ConfigError, Credential, DEFAULT_TOOLS, Settings, ToolName,
};
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

/// The static credential the settings accept. Panics on an error or in the JWT mode.
fn accepted(settings: Result<Settings, ConfigError>) -> AcceptedCredential {
    match settings.unwrap().config.accepted {
        Credential::Static(accepted) => accepted,
        Credential::Jwt(verifier) => panic!("expected the static mode, not {verifier:?}"),
    }
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
    let digest_file = token_file("digest", &format!("{digest}\n"));
    let digest_file = digest_file.to_str().unwrap();
    assert_eq!(settings(&[]).unwrap_err(), ConfigError::NoCredential);
    for two in [
        [
            ("MOCK_DOCS_TOKEN_FILE", file),
            ("MOCK_DOCS_TOKEN_SHA256", &digest),
        ],
        [
            ("MOCK_DOCS_TOKEN_FILE", file),
            ("MOCK_DOCS_TOKEN_SHA256_FILE", digest_file),
        ],
        [
            ("MOCK_DOCS_TOKEN_SHA256", &digest),
            ("MOCK_DOCS_TOKEN_SHA256_FILE", digest_file),
        ],
    ] {
        assert_eq!(
            settings(&two).unwrap_err(),
            ConfigError::TwoCredentials,
            "{two:?}"
        );
    }
    for vars in [
        [("MOCK_DOCS_TOKEN_FILE", file)],
        [("MOCK_DOCS_TOKEN_SHA256", &digest)],
        [("MOCK_DOCS_TOKEN_SHA256_FILE", digest_file)],
    ] {
        let accepted = accepted(settings(&vars));
        assert!(accepted.accepts(TOKEN));
        assert!(!accepted.accepts("dummy-workload-token-for-tests"));
        assert!(!accepted.accepts(""));
    }
}

#[test]
fn the_digest_must_be_64_hex_digits_in_either_case() {
    let digest = sha256_hex(TOKEN);
    let upper = digest.to_uppercase();
    assert!(accepted(settings(&[("MOCK_DOCS_TOKEN_SHA256", &upper)])).accepts(TOKEN));
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
fn a_digest_file_must_hold_64_hex_digits() {
    let digest = sha256_hex(TOKEN);
    // Holding the token itself, not its hash, is refused rather than hashed.
    for (name, contents) in [
        ("token-not-digest", TOKEN),
        ("short", &digest[..62]),
        ("empty", ""),
    ] {
        let path = token_file(name, contents);
        assert_eq!(
            settings(&[("MOCK_DOCS_TOKEN_SHA256_FILE", path.to_str().unwrap())]).unwrap_err(),
            ConfigError::BadDigest,
            "{name}"
        );
    }
    assert!(matches!(
        settings(&[("MOCK_DOCS_TOKEN_SHA256_FILE", "/nonexistent/digest")]).unwrap_err(),
        ConfigError::TokenFile(_)
    ));
}

/// A digest that differs from the token's in one byte, at either end or in the middle, does not
/// accept the token: every byte is compared.
#[test]
fn every_byte_of_the_digest_counts() {
    let digest = sha256_hex(TOKEN);
    for position in [0, 31, 63] {
        let mut changed = digest.clone().into_bytes();
        changed[position] = if changed[position] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let changed = String::from_utf8(changed).unwrap();
        let accepted = AcceptedCredential::sha256_hex(&changed).unwrap();
        assert!(!accepted.accepts(TOKEN), "digest changed at {position}");
    }
}

#[test]
fn a_token_file_loses_its_trailing_newline_and_must_not_be_empty() {
    let file = token_file("newline", &format!("{TOKEN}\n"));
    let accepted = accepted(settings(&[(
        "MOCK_DOCS_TOKEN_FILE",
        file.to_str().unwrap(),
    )]));
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

// --- The JWT mode's settings -------------------------------------------------------------

const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

/// An RSA public key in JWK form, with `changes` applied; a `null` removes a member. The
/// modulus is a few made-up bytes, not a key: configuration does not check its length, and
/// nothing is verified here.
fn jwk(changes: Value) -> Value {
    let mut jwk = json!({
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key-1",
        "n": "YSBtYWRlLXVwIG1vZHVsdXMsIG5vdCBhIGtleQ", "e": "AQAB",
    });
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            jwk.as_object_mut().unwrap().remove(name);
        } else {
            jwk[name] = value.clone();
        }
    }
    jwk
}

const JWT_VARS: [&str; 4] = [
    "MOCK_DOCS_JWT_ISSUER",
    "MOCK_DOCS_JWT_AUDIENCE",
    "MOCK_DOCS_JWT_SUBJECT",
    "MOCK_DOCS_JWKS_FILE",
];

/// The four JWT variables, with the JWK set file holding `jwks`.
fn jwt_settings(test: &str, jwks: &str) -> Result<Settings, ConfigError> {
    let path = token_file(&format!("jwks-{test}"), jwks);
    settings(&[
        ("MOCK_DOCS_JWT_ISSUER", ISSUER),
        ("MOCK_DOCS_JWT_AUDIENCE", "mock-docs"),
        (
            "MOCK_DOCS_JWT_SUBJECT",
            "system:serviceaccount:switchboard:gateway",
        ),
        ("MOCK_DOCS_JWKS_FILE", path.to_str().unwrap()),
    ])
}

#[test]
fn the_jwt_settings_give_the_jwt_mode() {
    let jwks =
        json!({"keys": [jwk(json!({})), jwk(json!({"kid": "key-2", "use": null, "alg": null}))]});
    let Credential::Jwt(verifier) = jwt_settings("good", &jwks.to_string())
        .unwrap()
        .config
        .accepted
    else {
        panic!("not the JWT mode");
    };
    assert_eq!(verifier.issuer(), ISSUER);
    assert_eq!(verifier.audience(), "mock-docs");
    assert_eq!(
        verifier.subject(),
        "system:serviceaccount:switchboard:gateway"
    );
    assert_eq!(verifier.key_ids(), ["key-1", "key-2"]);
}

#[test]
fn a_static_credential_and_any_jwt_setting_together_are_refused() {
    let digest = sha256_hex(TOKEN);
    let file = token_file("static-and-jwt", TOKEN);
    let file = file.to_str().unwrap();
    for (static_var, static_value) in [
        ("MOCK_DOCS_TOKEN_FILE", file),
        ("MOCK_DOCS_TOKEN_SHA256", &digest),
        ("MOCK_DOCS_TOKEN_SHA256_FILE", file),
    ] {
        let mut vars: Vec<(&str, &str)> = JWT_VARS.iter().map(|name| (*name, "x")).collect();
        vars.push((static_var, static_value));
        assert_eq!(
            settings(&vars).unwrap_err(),
            ConfigError::StaticAndJwt,
            "{vars:?}"
        );
        for jwt_var in JWT_VARS {
            assert_eq!(
                settings(&[(static_var, static_value), (jwt_var, "x")]).unwrap_err(),
                ConfigError::StaticAndJwt,
                "{static_var} and {jwt_var}"
            );
        }
    }
}

#[test]
fn the_jwt_settings_must_all_be_set_and_not_empty() {
    for missing in JWT_VARS {
        let without: Vec<(&str, &str)> = JWT_VARS
            .iter()
            .filter(|name| **name != missing)
            .map(|name| (*name, "x"))
            .collect();
        assert_eq!(
            settings(&without).unwrap_err(),
            ConfigError::JwtIncomplete(missing),
            "without {missing}"
        );
        let empty: Vec<(&str, &str)> = JWT_VARS
            .iter()
            .map(|name| (*name, if *name == missing { " " } else { "x" }))
            .collect();
        assert_eq!(
            settings(&empty).unwrap_err(),
            ConfigError::JwtIncomplete(missing),
            "{missing} empty"
        );
    }
}

#[test]
fn the_jwk_set_must_hold_rs256_signing_keys_each_with_its_own_kid() {
    let set = |keys: Vec<Value>| json!({ "keys": keys }).to_string();
    for (name, jwks) in [
        ("not-json", "{".to_owned()),
        ("not-a-set", json!([jwk(json!({}))]).to_string()),
        ("no-keys", set(vec![])),
        ("no-kid", set(vec![jwk(json!({"kid": null}))])),
        ("one-kid-twice", set(vec![jwk(json!({})), jwk(json!({}))])),
        ("rs512", set(vec![jwk(json!({"alg": "RS512"}))])),
        ("encryption", set(vec![jwk(json!({"use": "enc"}))])),
        (
            "elliptic-curve",
            set(vec![json!({
                "kty": "EC", "crv": "P-256", "kid": "key-1",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            })]),
        ),
        (
            "symmetric",
            set(vec![json!({"kty": "oct", "kid": "key-1", "k": "ZHVtbXk"})]),
        ),
    ] {
        assert!(
            matches!(jwt_settings(name, &jwks), Err(ConfigError::Jwks(_))),
            "{name}"
        );
    }
    let missing = settings(&[
        ("MOCK_DOCS_JWT_ISSUER", ISSUER),
        ("MOCK_DOCS_JWT_AUDIENCE", "mock-docs"),
        (
            "MOCK_DOCS_JWT_SUBJECT",
            "system:serviceaccount:switchboard:gateway",
        ),
        ("MOCK_DOCS_JWKS_FILE", "/nonexistent/jwks.json"),
    ]);
    assert!(matches!(missing, Err(ConfigError::Jwks(_))));
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
    assert_eq!(boot["mode"], "static");
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
    // The JWT mode's fields are not in the static mode's lines.
    for line in [&first, &second] {
        assert!(line.get("caller").is_none(), "{line}");
        assert!(line.get("refusal").is_none(), "{line}");
    }
}

#[test]
fn the_binary_refuses_to_start_with_a_static_credential_and_jwt_settings() {
    let output = binary()
        .env("MOCK_DOCS_TOKEN_SHA256", sha256_hex(TOKEN))
        .env("MOCK_DOCS_JWT_ISSUER", ISSUER)
        .env("MOCK_DOCS_JWT_AUDIENCE", "mock-docs")
        .env(
            "MOCK_DOCS_JWT_SUBJECT",
            "system:serviceaccount:switchboard:gateway",
        )
        .env("MOCK_DOCS_JWKS_FILE", "/nonexistent/jwks.json")
        .env("MOCK_DOCS_LISTEN", "127.0.0.1:0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let line: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(line["event"], "boot_refused");
    assert!(output.stdout.is_empty());
}
