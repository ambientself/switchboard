//! The fetcher depends on nothing outside this allowlist, and on one crypto backend.
//!
//! An allowlist, in the style of the identity crate's test of the same name. Adding a dependency
//! means adding it here in the same change, where a reviewer sees it. There is no TLS client
//! yet: an `https` source is refused when it is built.
//!
//! The manifest is read as Cargo reads it, through `cargo metadata`, so every dependency that
//! is not a dev-dependency is checked, under the package it resolves to.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 9] = [
    "gateway-core",
    "http-body-util",
    "hyper",
    "hyper-util",
    "jsonwebtoken",
    "serde_json",
    "thiserror",
    "tokio",
    "url",
];

/// Every dependency of this crate that is not a dev-dependency, as `cargo metadata` gives it.
fn built_with() -> Vec<Value> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let package = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == json!(env!("CARGO_PKG_NAME")))
        .unwrap();
    package["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|dependency| dependency["kind"] != json!("dev"))
        .cloned()
        .collect()
}

#[test]
fn the_fetcher_depends_only_on_allowed_crates() {
    let dependencies: Vec<String> = built_with()
        .iter()
        .map(|dependency| dependency["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(!dependencies.is_empty(), "found no dependencies");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "issuer-keys must not depend on {unexpected:?}"
    );
}

#[test]
fn the_fetcher_selects_the_identity_crates_one_crypto_backend() {
    let jsonwebtoken: Vec<Value> = built_with()
        .into_iter()
        .filter(|dependency| dependency["name"] == json!("jsonwebtoken"))
        .collect();
    assert_eq!(jsonwebtoken.len(), 1, "{jsonwebtoken:?}");
    assert_eq!(
        jsonwebtoken[0]["uses_default_features"],
        json!(false),
        "{jsonwebtoken:?}"
    );
    assert_eq!(
        jsonwebtoken[0]["features"],
        json!(["rust_crypto"]),
        "{jsonwebtoken:?}"
    );
    assert!(
        !MANIFEST.contains("aws_lc_rs") && !MANIFEST.contains("aws-lc-rs"),
        "two backends make jsonwebtoken panic on first use"
    );
}

/// The workspace's lock file: which packages the build uses.
const LOCK: &str = include_str!("../../../Cargo.lock");

/// The fetcher and the identity crate must agree on the set's type, so `replace_keys` takes
/// what `fetch` returns. That holds while the build has one `jsonwebtoken`.
#[test]
fn the_build_has_one_jsonwebtoken() {
    let entries = LOCK
        .split("[[package]]")
        .filter(|entry| entry.lines().any(|line| line == r#"name = "jsonwebtoken""#))
        .count();
    assert_eq!(entries, 1);
}
