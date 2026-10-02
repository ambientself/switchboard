//! The core performs no I/O, which starts with depending on nothing that does.
//!
//! An allowlist rather than a denylist of HTTP, MCP, database and async-runtime crates: a
//! denylist only names the crates someone thought of. Adding a dependency to the core means
//! adding it here, in the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 3] = ["serde", "serde_json", "thiserror"];

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
fn the_core_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway-core must not depend on {unexpected:?}; the core performs no I/O"
    );
}

#[test]
fn the_core_has_no_other_kind_of_dependency() {
    for kind in ["build-dependencies", "target", "dependencies."] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "gateway-core has a [{kind}] section, which this test does not check"
        );
    }
}
