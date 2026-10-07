//! The adapter is pure functions: no async runtime, no HTTP server, and no policy core.
//!
//! An allowlist, as in the core's and the identity crate's tests of the same name. The
//! `gateway` crate maps between this crate's types and the core's, so a protocol type cannot
//! reach a policy decision except through it. Adding a dependency here means adding it to this
//! list in the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 3] = ["base64", "http", "serde_json"];

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
fn the_adapter_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway-mcp must not depend on {unexpected:?}; it is pure functions over protocol types"
    );
}

#[test]
fn the_manifest_has_no_section_this_test_does_not_read() {
    for kind in ["build-dependencies", "target", "dependencies."] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "gateway-mcp has a [{kind}] section, which this test does not check"
        );
    }
}
