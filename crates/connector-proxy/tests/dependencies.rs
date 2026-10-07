//! The connector runs inside the gateway, so it never links the test fakes or the identity
//! crate: a caller reaches it already proved, inside the core's `ToolCall`. It depends on
//! nothing outside this allowlist. Adding a dependency means adding it here in the same change,
//! where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 7] = [
    "gateway-core",
    "http-body-util",
    "hyper",
    "hyper-util",
    "serde_json",
    "thiserror",
    "tokio",
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
fn the_connector_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "connector-proxy must not depend on {unexpected:?}"
    );
}

#[test]
fn the_test_fakes_are_only_a_dev_dependency() {
    assert!(section("dev-dependencies").contains(&"gateway-testkit".to_owned()));
    for kind in ["build-dependencies", "target"] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "[{kind}...] would bypass this check"
        );
    }
}
