//! The JWT mode over real HTTP on loopback: the one subject's token is accepted, and every
//! other token is refused with a 401 and the reason in the log, without logging anything the
//! token claims.
//!
//! The tokens are minted here, with RSA keys generated once per run. No key is checked in, and
//! the gateway's own test issuer is not used: the mock server shares no code with the gateway.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mock_docs_server::{Config, Credential, Running, Settings, start};
use reqwest::StatusCode;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
const AUDIENCE: &str = "mock-docs";
const SUBJECT: &str = "system:serviceaccount:switchboard:gateway";
/// Another workload's subject: a valid token from the trusted issuer, for anyone else.
const OTHER_SUBJECT: &str = "system:serviceaccount:team-atlas:workload";
const KID: &str = "test-signing-key";

/// A key pair made for this run.
struct Key {
    encoding: EncodingKey,
    /// The public key as a JWK, without a `kid`.
    jwk: Value,
    /// The public key's PKCS#1 DER bytes, for the HS256 confusion attempt.
    public_der: Vec<u8>,
}

fn key() -> Key {
    let secret = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let public = secret.to_public_key();
    let encode = |bytes: Vec<u8>| URL_SAFE_NO_PAD.encode(bytes);
    Key {
        encoding: EncodingKey::from_rsa_der(secret.to_pkcs1_der().unwrap().as_bytes()),
        jwk: json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": encode(public.n().to_bytes_be()),
            "e": encode(public.e().to_bytes_be()),
        }),
        public_der: public.to_pkcs1_der().unwrap().as_bytes().to_vec(),
    }
}

/// The key the server trusts.
fn signing() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(key)
}

/// A key the server has never seen.
fn stranger() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(key)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The claims of the gateway's token: right issuer, audience and subject, valid for an hour.
fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "sub": SUBJECT,
        "iat": now(),
        "nbf": now(),
        "exp": now() + 3600,
    })
}

/// `claims` with `changes` applied; a `null` removes the claim.
fn claims_with(changes: Value) -> Value {
    let mut claims = claims();
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
    }
    claims
}

fn sign(algorithm: Algorithm, kid: Option<&str>, key: &EncodingKey, claims: &Value) -> String {
    let mut header = Header::new(algorithm);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, key).unwrap()
}

/// A token signed RS256 by the trusted key, under its kid.
fn token(claims: &Value) -> String {
    sign(Algorithm::RS256, Some(KID), &signing().encoding, claims)
}

/// A token with `"alg": "none"` and no signature.
fn unsigned(claims: &Value) -> String {
    let part = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
    format!(
        "{}.{}.",
        part(json!({"alg": "none", "typ": "JWT", "kid": KID})),
        part(claims.clone())
    )
}

/// The trusted key set, in the shape a Kubernetes API server's `/openid/v1/jwks` returns.
fn jwks() -> String {
    let mut jwk = signing().jwk.clone();
    jwk["kid"] = json!(KID);
    json!({ "keys": [jwk] }).to_string()
}

/// A file holding `contents`, in a directory of its own for this test.
fn file(test: &str, name: &str, contents: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("mock-docs-jwt-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// The JWT mode's settings, read as the binary reads them.
fn jwt_vars(jwks_file: &str) -> HashMap<String, String> {
    [
        ("MOCK_DOCS_JWT_ISSUER", ISSUER),
        ("MOCK_DOCS_JWT_AUDIENCE", AUDIENCE),
        ("MOCK_DOCS_JWT_SUBJECT", SUBJECT),
        ("MOCK_DOCS_JWKS_FILE", jwks_file),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

async fn server(test: &str) -> Running {
    let jwks_file = file(test, "jwks.json", &jwks());
    let vars = jwt_vars(jwks_file.to_str().unwrap());
    let settings = Settings::from_vars(|name| vars.get(name).cloned()).unwrap();
    let Credential::Jwt(verifier) = settings.config.accepted else {
        panic!("the JWT settings did not give the JWT mode");
    };
    assert_eq!(verifier.key_ids(), [KID]);
    start(Config::new(verifier)).await.unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn prefix(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()[..12]
        .to_owned()
}

/// `tools/list` with `bearer` as the `Authorization` header's token, if any.
async fn list(server: &Running, bearer: Option<&str>) -> reqwest::Response {
    let mut request = client()
        .post(server.url())
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    request.send().await.unwrap()
}

#[tokio::test]
async fn the_gateways_token_is_accepted_and_its_subject_logged() {
    let server = server("accepted").await;
    let token = token(&claims());
    let response = list(&server, Some(&token)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().await.unwrap();
    assert_eq!(answer["result"]["tools"][0]["name"], "list_documents");

    let lines = server.log_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(line["accepted"], true, "{line}");
    assert_eq!(line["caller"], SUBJECT, "{line}");
    assert_eq!(line["refusal"], Value::Null, "{line}");
    assert_eq!(line["bearer_sha256"], prefix(&token), "{line}");
    assert_eq!(line["rpc_method"], "tools/list", "{line}");
    assert!(!line.to_string().contains(&token), "{line}");
}

/// Clocks differ: a token a little past `exp`, or a little before `nbf`, is still taken. An
/// audience may be a single string too.
#[tokio::test]
async fn small_clock_differences_and_a_single_audience_are_accepted() {
    let server = server("leeway").await;
    for (name, claims) in [
        ("exp 10 s ago", claims_with(json!({"exp": now() - 10}))),
        ("nbf 10 s ahead", claims_with(json!({"nbf": now() + 10}))),
        ("no nbf", claims_with(json!({"nbf": null}))),
        (
            "audience as a string",
            claims_with(json!({"aud": AUDIENCE})),
        ),
        (
            "two audiences",
            claims_with(json!({"aud": ["another-service", AUDIENCE]})),
        ),
    ] {
        let response = list(&server, Some(&token(&claims))).await;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
    }
}

#[tokio::test]
async fn every_other_token_gets_a_401_and_its_refusal_in_the_log() {
    let server = server("refused").await;
    let cases: Vec<(&str, Option<String>, &str)> = vec![
        ("no bearer", None, "no_bearer"),
        (
            "a bearer that is not a JWT",
            Some("not-a-jwt".to_owned()),
            "malformed",
        ),
        (
            "another subject from the trusted issuer, for this audience",
            Some(token(&claims_with(json!({"sub": OTHER_SUBJECT})))),
            "wrong_subject",
        ),
        (
            "no subject",
            Some(token(&claims_with(json!({"sub": null})))),
            "wrong_subject",
        ),
        (
            "another audience",
            Some(token(&claims_with(
                json!({"aud": ["https://kubernetes.default.svc"]}),
            ))),
            "wrong_audience",
        ),
        (
            "no audience",
            Some(token(&claims_with(json!({"aud": null})))),
            "wrong_audience",
        ),
        // A workload's own token: meant for the cluster, about the workload. It was never for
        // this server, so it is refused for its audience, not its subject.
        (
            "another audience and another subject",
            Some(token(&claims_with(
                json!({"aud": ["https://kubernetes.default.svc"], "sub": OTHER_SUBJECT}),
            ))),
            "wrong_audience",
        ),
        (
            "another issuer",
            Some(token(&claims_with(
                json!({"iss": "https://issuer.example"}),
            ))),
            "wrong_issuer",
        ),
        (
            "the issuer among others",
            Some(token(&claims_with(
                json!({"iss": [ISSUER, "https://issuer.example"]}),
            ))),
            "wrong_issuer",
        ),
        (
            "no issuer",
            Some(token(&claims_with(json!({"iss": null})))),
            "wrong_issuer",
        ),
        (
            "expired beyond the leeway",
            Some(token(&claims_with(json!({"exp": now() - 45})))),
            "expired",
        ),
        (
            "no expiry",
            Some(token(&claims_with(json!({"exp": null})))),
            "malformed",
        ),
        (
            "not valid before a time beyond the leeway",
            Some(token(&claims_with(json!({"nbf": now() + 45})))),
            "not_yet_valid",
        ),
        (
            "signed by a key the server does not trust, under the trusted kid",
            Some(sign(
                Algorithm::RS256,
                Some(KID),
                &stranger().encoding,
                &claims(),
            )),
            "bad_signature",
        ),
        (
            "signed by the trusted key under an unknown kid",
            Some(sign(
                Algorithm::RS256,
                Some("another-key"),
                &signing().encoding,
                &claims(),
            )),
            "unknown_key",
        ),
        (
            "signed by the trusted key with no kid",
            Some(sign(Algorithm::RS256, None, &signing().encoding, &claims())),
            "unknown_key",
        ),
        ("alg none", Some(unsigned(&claims())), "malformed"),
        (
            "HS256 keyed with the trusted public key's bytes",
            Some(sign(
                Algorithm::HS256,
                Some(KID),
                &EncodingKey::from_secret(&signing().public_der),
                &claims(),
            )),
            "bad_signature",
        ),
    ];
    for (name, bearer, refusal) in &cases {
        let before = server.log_lines().len();
        let response = list(&server, bearer.as_deref()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        let lines = server.log_lines();
        assert_eq!(lines.len(), before + 1, "{name}: {lines:?}");
        let line = &lines[before];
        assert_eq!(line["accepted"], false, "{name}: {line}");
        assert_eq!(line["refusal"], *refusal, "{name}: {line}");
        assert_eq!(line["caller"], Value::Null, "{name}: {line}");
        assert_eq!(
            line["bearer_sha256"],
            json!(bearer.as_deref().map(prefix)),
            "{name}: {line}"
        );
        // Refused from the headers: the body was never read (tests/loopback.rs shows it is not
        // even waited for).
        assert!(line.get("rpc_method").is_none(), "{name}: {line}");
        // Nothing the token says is logged, nor the token itself.
        let text = line.to_string();
        for claimed in [
            OTHER_SUBJECT,
            "https://issuer.example",
            "kubernetes.default.svc",
        ] {
            assert!(!text.contains(claimed), "{name}: {line}");
        }
        if let Some(bearer) = bearer {
            assert!(!text.contains(bearer.as_str()), "{name}: {line}");
        }
    }
}

#[tokio::test]
async fn the_admin_endpoint_takes_the_same_verification() {
    let server = server("admin").await;
    let other = token(&claims_with(json!({"sub": OTHER_SUBJECT})));
    let refused = client()
        .put(server.admin_url())
        .bearer_auth(&other)
        .json(&json!({"tools": ["read_document"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let line = server.log_lines().pop().unwrap();
    assert_eq!(
        (&line["event"], &line["refusal"], &line["caller"]),
        (&json!("admin"), &json!("wrong_subject"), &Value::Null),
        "{line}"
    );

    let accepted = client()
        .get(server.admin_url())
        .bearer_auth(token(&claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let line = server.log_lines().pop().unwrap();
    assert_eq!(
        (&line["caller"], &line["refusal"]),
        (&json!(SUBJECT), &Value::Null),
        "{line}"
    );
}

// --- The binary ----------------------------------------------------------------------------

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn the_binary_boots_in_the_jwt_mode_and_says_so() {
    let jwks_file = file("binary", "jwks.json", &jwks());
    let mut command = Command::new(env!("CARGO_BIN_EXE_mock-docs-server"));
    for (name, _) in std::env::vars() {
        if name.starts_with("MOCK_DOCS_") {
            command.env_remove(name);
        }
    }
    let mut child = Killed(
        command
            .envs(jwt_vars(jwks_file.to_str().unwrap()))
            .env("MOCK_DOCS_LISTEN", "127.0.0.1:0")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
    let boot: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(boot["event"], "boot", "{boot}");
    assert_eq!(boot["mode"], "jwt", "{boot}");
    assert_eq!(boot["issuer"], ISSUER, "{boot}");
    assert_eq!(boot["audience"], AUDIENCE, "{boot}");
    assert_eq!(boot["subject"], SUBJECT, "{boot}");
    assert_eq!(boot["key_ids"], json!([KID]), "{boot}");
    assert!(boot.get("accepted_sha256").is_none(), "{boot}");

    let url = format!("http://{}/mcp", boot["listen"].as_str().unwrap());
    let response = client()
        .post(&url)
        .bearer_auth(token(&claims()))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let line: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(line["caller"], SUBJECT, "{line}");
}
