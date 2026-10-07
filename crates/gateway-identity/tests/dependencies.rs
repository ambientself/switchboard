//! Verification is offline: this crate depends on nothing that opens a socket.
//!
//! An allowlist, as in the core's test of the same name. Fetching and caching keys over HTTP is
//! a later change and belongs in a crate of its own beside this one; adding a dependency here
//! means adding it to this list in the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 5] = [
    "gateway-core",
    "base64",
    "jsonwebtoken",
    "serde_json",
    "thiserror",
];

fn section(name: &str) -> Vec<String> {
    let header = format!("[{name}]");
    MANIFEST
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split(['=', '.']).next().unwrap().trim().to_owned())
        .collect()
}

#[test]
fn the_identity_crate_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
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
    let manifest = MANIFEST;
    assert!(manifest.contains("default-features = false, features = [\"rust_crypto\"]"));
    assert!(
        !manifest.contains("aws_lc_rs"),
        "two backends make jsonwebtoken panic on first use"
    );
    for kind in ["build-dependencies", "target", "dependencies."] {
        assert!(
            !manifest.contains(&format!("[{kind}")),
            "gateway-identity has a [{kind}] section, which this test does not check"
        );
    }
}
