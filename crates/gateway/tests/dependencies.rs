//! What a running gateway is built from: an allowlist, as in the core's and identity's tests of
//! the same name.
//!
//! The testkit's fakes and the MCP SDK (`rmcp`) are for tests only. The testkit says nothing in
//! it belongs in a running gateway, and decision 0007 uses the SDK only as a test client, so
//! both stay in `[dev-dependencies]`. Adding a dependency here means adding it to this list in
//! the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 12] = [
    "axum",
    "gateway-core",
    "gateway-identity",
    "gateway-mcp",
    "http",
    "http-body-util",
    "serde",
    "serde_json",
    "thiserror",
    "tokio",
    "tracing",
    "tracing-subscriber",
];

/// Never in a running gateway, whatever else the allowlist comes to hold.
const TEST_ONLY: [&str; 2] = ["gateway-testkit", "rmcp"];

/// The crate names in one `[section]` of the manifest.
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
fn the_gateway_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
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
    let dependencies = section("dependencies");
    for name in TEST_ONLY {
        assert!(
            !dependencies.iter().any(|dependency| dependency == name),
            "`{name}` is a test tool and must stay in [dev-dependencies]"
        );
    }
}

#[test]
fn the_gateway_has_no_other_kind_of_dependency() {
    for kind in ["build-dependencies", "target", "dependencies."] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "gateway has a [{kind}] section, which this test does not check"
        );
    }
}
