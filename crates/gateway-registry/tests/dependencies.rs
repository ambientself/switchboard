//! The registry crate reads a file and builds data. It depends on nothing that opens a socket,
//! runs async code or talks to a database, and never on the testkit: the gateway links this
//! crate, and the gateway must not link test fakes.
//!
//! An allowlist, as in the core's test of the same name: adding a dependency means adding it
//! here in the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 6] = [
    "gateway-core",
    "serde",
    "serde_json",
    "sha2",
    "thiserror",
    "toml",
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
fn the_registry_crate_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "gateway-registry must not depend on {unexpected:?}"
    );
    for kind in ["build-dependencies", "target", "dependencies."] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "gateway-registry has a [{kind}] section, which this test does not check"
        );
    }
}
