//! The release `switchboard` is never a development build (decision 0009, design section 12).
//!
//! A build with the gateway's `test-support` feature is exempt from the receipt-store gate, so
//! it serves tools not classified `read` with no receipt store. Cargo unifies features across
//! the packages of one build, and crates/gateway-dev turns `test-support` on, so a workspace
//! build of `switchboard` would be one. deploy/Dockerfile builds it on its own, with `-p gateway`
//! and no features, and copies it out before anything else is built; CI builds it with the same
//! command and checks that the binary refuses a `propose` tool. These tests pin the command in
//! both places, and the feature's absence from the gateway's defaults.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::read;
use serde_json::{Value, json};

/// The one command that builds the release `switchboard`.
const RELEASE_BUILD: &str = "cargo build --release --locked -p gateway --bin switchboard";

/// Every `cargo build` command in the Dockerfile's build stage, without the shell's `; \`.
fn dockerfile_builds(dockerfile: &str) -> Vec<String> {
    dockerfile
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo build"))
        .map(|line| {
            line.trim_end_matches('\\')
                .trim()
                .trim_end_matches(';')
                .to_owned()
        })
        .collect()
}

#[test]
fn the_dockerfile_builds_switchboard_alone_with_no_features() {
    let dockerfile = read("deploy/Dockerfile");
    let builds = dockerfile_builds(&dockerfile);
    assert_eq!(
        builds,
        [
            RELEASE_BUILD,
            "cargo build --release --locked -p gateway-dev -p mock-docs-server --bins",
        ],
        "{dockerfile}"
    );
    for build in &builds {
        for unified in ["--workspace", "--all", "--features", "-F", "--all-features"] {
            assert!(
                !build
                    .split_whitespace()
                    .any(|word| word == unified || word.starts_with(&format!("{unified}="))),
                "`{build}` would build with other packages' features or its own: {unified}"
            );
        }
    }
}

#[test]
fn the_image_takes_switchboard_as_built_before_anything_else() {
    let dockerfile = read("deploy/Dockerfile");
    let lines: Vec<&str> = dockerfile.lines().map(str::trim).collect();
    let built = lines
        .iter()
        .position(|line| line.starts_with(RELEASE_BUILD))
        .expect("the Dockerfile does not build switchboard");
    assert_eq!(
        lines[built + 1],
        "cp target/release/switchboard /out/release/switchboard; \\",
        "switchboard is not copied out as soon as it is built"
    );
    assert!(
        lines.contains(&"cp /out/release/switchboard /out/bin/; \\"),
        "the image does not take switchboard from its staging path"
    );
    // The loop copies every other binary from target/release, which the second build may have
    // rebuilt; switchboard must not be one of them.
    assert!(
        lines.contains(&"if [ \"${bin}\" = switchboard ]; then \\"),
        "{dockerfile}"
    );
}

#[test]
fn ci_checks_the_binary_the_dockerfile_builds() {
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.lines()
            .any(|line| line.trim() == format!("run: {RELEASE_BUILD}")),
        "CI does not build switchboard with the Dockerfile's command"
    );
    assert!(ci.contains("target/release/switchboard \\\n"), "{ci}");
    assert!(
        ci.contains("--config=deploy/ci/receipt-gate/gateway.toml"),
        "{ci}"
    );
    assert!(
        ci.contains("no receipt store is configured' receipt-gate-stderr.txt"),
        "CI does not check the refusal is the receipt-store gate's"
    );
    let registry = read("deploy/ci/receipt-gate/registry/registry.toml");
    assert!(
        registry.contains("classification = \"propose\""),
        "{registry}"
    );
    assert!(
        registry.contains("tools = [\"docs__propose_document\"]"),
        "{registry}"
    );
}

#[test]
fn test_support_is_not_a_default_feature_of_the_gateway() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .current_dir(common::repo())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    let gateway = packages
        .iter()
        .find(|package| package["name"] == json!("gateway"))
        .unwrap();
    assert_eq!(gateway["features"]["test-support"], json!([]));
    let defaults = gateway["features"]["default"].as_array();
    assert!(
        defaults.is_none_or(|defaults| defaults.is_empty()),
        "the gateway has default features: {defaults:?}"
    );
    // Only dev-dependencies of the gateway itself turn the feature on, and they are not built
    // by `cargo build -p gateway`.
    for dependency in gateway["dependencies"].as_array().unwrap() {
        if dependency["kind"] != json!("dev") {
            assert_ne!(dependency["name"], json!("gateway"), "{dependency}");
        }
    }
}
