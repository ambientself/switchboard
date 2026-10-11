//! The fetcher depends on nothing outside this allowlist, and on one crypto backend.
//!
//! An allowlist, in the style of the identity crate's test of the same name. Adding a dependency
//! means adding it here in the same change, where a reviewer sees it. The TLS client is rustls
//! with ring, and the lock file holds no other crypto provider for it.
//!
//! The manifest is read as Cargo reads it, through `cargo metadata`, so every dependency that
//! is not a dev-dependency is checked, under the package it resolves to.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 11] = [
    "gateway-core",
    "http-body-util",
    "hyper",
    "hyper-rustls",
    "hyper-util",
    "jsonwebtoken",
    "rustls",
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

/// The TLS client's crates, with their default features off and ring named as the provider.
/// Their defaults would build in the other provider, which this crate never uses.
#[test]
fn the_tls_client_selects_ring_with_default_features_off() {
    let dependencies = built_with();
    for (name, features) in [
        ("rustls", json!(["ring", "std", "tls12"])),
        ("hyper-rustls", json!(["http1", "ring", "tls12"])),
    ] {
        let found: Vec<&Value> = dependencies
            .iter()
            .filter(|dependency| dependency["name"] == json!(name))
            .collect();
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        assert_eq!(found[0]["uses_default_features"], json!(false), "{found:?}");
        assert_eq!(found[0]["features"], features, "{found:?}");
    }
}

/// No package in the build is the other crypto provider rustls can use, or its C library.
#[test]
fn the_lock_file_holds_no_aws_lc() {
    for name in ["aws-lc-rs", "aws-lc-sys"] {
        let line = format!("name = \"{name}\"");
        assert!(
            !LOCK.lines().any(|entry| entry == line),
            "the lock file holds {name}"
        );
    }
}
