//! Verification is offline: this crate depends on nothing that opens a socket.
//!
//! An allowlist, as in the core's test of the same name. Fetching and caching keys over HTTP is
//! a later change and belongs in a crate of its own beside this one; adding a dependency here
//! means adding it to this list in the same change, where a reviewer sees it.
//!
//! The manifest is read as Cargo reads it, through `cargo metadata`, so every dependency that
//! is not a dev-dependency is checked: normal and build dependencies, those under a
//! `[target.…]` table however its header is spelled, and each under the package it resolves to,
//! not the name the manifest gives it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 6] = [
    "gateway-core",
    "base64",
    "jsonwebtoken",
    "rsa",
    "serde_json",
    "thiserror",
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

/// The packages this crate is built with, by the names they are published under.
fn packages() -> Vec<String> {
    built_with()
        .iter()
        .map(|dependency| dependency["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_identity_crate_depends_only_on_allowed_crates() {
    let dependencies = packages();
    assert!(!dependencies.is_empty(), "found no dependencies");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway-identity must not depend on {unexpected:?}; verification performs no network I/O"
    );
}

#[test]
fn the_identity_crate_selects_exactly_one_crypto_backend() {
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
        !MANIFEST.contains("aws_lc_rs"),
        "two backends make jsonwebtoken panic on first use"
    );
}
