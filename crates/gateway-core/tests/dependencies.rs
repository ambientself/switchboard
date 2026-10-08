//! The core performs no I/O, which starts with depending on nothing that does.
//!
//! An allowlist rather than a denylist of HTTP, MCP, database and async-runtime crates: a
//! denylist only names the crates someone thought of. Adding a dependency to the core means
//! adding it here, in the same change, where a reviewer sees it.
//!
//! The manifest is read as Cargo reads it, through `cargo metadata`, so every dependency that
//! is not a dev-dependency is checked: normal and build dependencies, those under a
//! `[target.…]` table however its header is spelled, and each under the package it resolves to,
//! not the name the manifest gives it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

const ALLOWED: [&str; 3] = ["serde", "serde_json", "thiserror"];

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
fn the_core_depends_only_on_allowed_crates() {
    let dependencies = packages();
    assert!(!dependencies.is_empty(), "found no dependencies");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway-core must not depend on {unexpected:?}; the core performs no I/O"
    );
}
