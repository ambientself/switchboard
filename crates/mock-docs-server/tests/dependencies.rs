//! The mock server plays a third party, so it shares no code with the gateway: it depends on no
//! `gateway-*` crate, and on nothing outside this allowlist. Adding a dependency means adding
//! it here in the same change, where a reviewer sees it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

const MANIFEST: &str = include_str!("../Cargo.toml");

const ALLOWED: [&str; 5] = ["axum", "jsonwebtoken", "serde_json", "sha2", "tokio"];

/// `jsonwebtoken` exactly as `gateway-identity` has it: only the pure-Rust backend. It panics
/// on first use if both backends are enabled anywhere in the build, and another feature set
/// would also change `Cargo.lock`.
const JSONWEBTOKEN: &str =
    r#"jsonwebtoken = { version = "11", default-features = false, features = ["rust_crypto"] }"#;

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
fn the_mock_server_depends_only_on_allowed_crates() {
    let dependencies = section("dependencies");
    assert!(!dependencies.is_empty(), "found no [dependencies] section");
    let unexpected: Vec<&String> = dependencies
        .iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "mock-docs-server must not depend on {unexpected:?}"
    );
}

#[test]
fn no_gateway_crate_appears_anywhere_in_the_manifest() {
    let named: Vec<&str> = MANIFEST
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.contains("gateway-"))
        .collect();
    assert!(
        named.is_empty(),
        "the mock server must not use the gateway's crates: {named:?}"
    );
    for kind in ["build-dependencies", "target"] {
        assert!(
            !MANIFEST.contains(&format!("[{kind}")),
            "the manifest has a [{kind}] section, which this test does not check"
        );
    }
}

#[test]
fn jsonwebtoken_has_the_same_single_backend_as_the_gateways_verifier() {
    let identity = include_str!("../../gateway-identity/Cargo.toml");
    for (crate_name, manifest) in [
        ("mock-docs-server", MANIFEST),
        ("gateway-identity", identity),
    ] {
        let lines: Vec<&str> = manifest
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("jsonwebtoken"))
            .collect();
        assert_eq!(lines, [JSONWEBTOKEN], "{crate_name}");
    }
}
