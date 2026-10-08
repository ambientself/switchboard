//! What a running gateway is built from: an allowlist, as in the core's and identity's tests of
//! the same name.
//!
//! The testkit's fakes and the MCP SDK (`rmcp`) are for tests only. The testkit says nothing in
//! it belongs in a running gateway, and decision 0007 uses the SDK only as a test client, so
//! both stay in `[dev-dependencies]`. Adding a dependency here means adding it to this list in
//! the same change, where a reviewer sees it.
//!
//! The manifest is read as Cargo reads it, through `cargo metadata`, so every dependency that
//! is not a dev-dependency is checked: normal and build dependencies, those under a
//! `[target.…]` table however its header is spelled, and each under the package it resolves to,
//! not the name the manifest gives it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

const ALLOWED: [&str; 14] = [
    "axum",
    "gateway-core",
    "gateway-identity",
    "gateway-mcp",
    "http",
    "http-body-util",
    "hyper",
    "hyper-util",
    "serde",
    "serde_json",
    "thiserror",
    "tokio",
    "tracing",
    "tracing-subscriber",
];

/// Never in a running gateway, whatever else the allowlist comes to hold.
const TEST_ONLY: [&str; 2] = ["gateway-testkit", "rmcp"];

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

/// The package a dependency resolves to.
fn package(dependency: &Value) -> &str {
    dependency["name"].as_str().unwrap()
}

#[test]
fn the_gateway_depends_only_on_allowed_crates() {
    let dependencies = built_with();
    assert!(!dependencies.is_empty(), "found no dependencies");
    let unexpected: Vec<&Value> = dependencies
        .iter()
        .filter(|dependency| !ALLOWED.contains(&package(dependency)))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway must not depend on {unexpected:?}; add it to the allowlist if it belongs in a \
         running gateway"
    );
}

#[test]
fn test_tools_are_never_dependencies_of_the_gateway() {
    assert!(ALLOWED.iter().all(|name| !TEST_ONLY.contains(name)));
    for dependency in built_with() {
        assert!(
            !TEST_ONLY.contains(&package(&dependency)),
            "`{}` is a test tool and must stay in [dev-dependencies]: {dependency}",
            package(&dependency)
        );
    }
}
