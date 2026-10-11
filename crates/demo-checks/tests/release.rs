//! The release `switchboard` is never a development build (decision 0009, design section 12).
//!
//! A build with the gateway's `test-support` feature is exempt from the receipt-store gate, so
//! it serves tools not classified `read` with no receipt store, and it accepts the identity and
//! audit opt-outs (decision 0014). Cargo unifies features across the packages of one build, and
//! crates/gateway-dev turns `test-support` on, so a workspace build of `switchboard` would be
//! one. deploy/Dockerfile builds it on its own, with `-p gateway` and no features, and copies it
//! out before anything else is built; CI builds it with the same command and checks that the
//! binary refuses a `propose` tool and each opt-out. These tests pin the command in both
//! places, the three configurations CI starts it with and the refusal each must name, and the
//! feature's absence from the gateway's defaults.
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

/// Each configuration CI starts the release binary with, the stderr file its step writes, and
/// the start of the refusal it must name.
const REFUSALS: [(&str, &str, &str); 3] = [
    (
        "receipt-gate",
        "receipt-gate-stderr.txt",
        "refused to start: tool `docs__propose_document` is classified `propose` and served on a \
         surface, but no receipt store is configured",
    ),
    (
        "identity-disabled",
        "identity-disabled-stderr.txt",
        "refused to start: identity is disabled, which only a development build allows",
    ),
    (
        "audit-disabled",
        "audit-disabled-stderr.txt",
        "refused to start: audit is disabled, which only a development build allows",
    ),
];

#[test]
fn ci_checks_each_refusal_of_the_release_binary() {
    let ci = read(".github/workflows/ci.yml");
    for (config, stderr, refusal) in REFUSALS {
        assert!(
            ci.contains(&format!(
                "--config=deploy/ci/{config}/gateway.toml 2> {stderr}\n"
            )),
            "CI does not start switchboard with deploy/ci/{config}"
        );
        assert!(
            ci.contains(&format!("grep -qF '{refusal}"))
                && ci.contains(&format!("' {stderr}; then")),
            "CI does not check the refusal of deploy/ci/{config}: {refusal}"
        );
    }
    // The database every configuration names is never reached: port 9, on loopback.
    assert!(
        ci.contains(
            "SWITCHBOARD_CI_DATABASE_URL: postgres://switchboard_gateway:not-a-password@127.0.0.1:9/"
        ),
        "{ci}"
    );
}

#[test]
fn the_configurations_differ_only_in_what_ci_expects_refused() {
    let file = |config: &str| read(&format!("deploy/ci/{config}/gateway.toml"));
    // Each opts out of exactly one gate, or none, and names the database CI never reaches.
    let receipt = file("receipt-gate");
    assert!(
        receipt.contains("[identity]\nmode = \"enforce\"\n"),
        "{receipt}"
    );
    assert!(
        receipt.contains("[audit]\nmode = \"postgres\"\n"),
        "{receipt}"
    );
    let identity = file("identity-disabled");
    assert!(
        identity.contains("[identity]\nmode = \"disabled\"\n"),
        "{identity}"
    );
    assert!(
        identity.contains("[audit]\nmode = \"postgres\"\n"),
        "{identity}"
    );
    let audit = file("audit-disabled");
    assert!(
        audit.contains("[identity]\nmode = \"enforce\"\n"),
        "{audit}"
    );
    assert!(audit.contains("[audit]\nmode = \"disabled\"\n"), "{audit}");
    for text in [&receipt, &identity] {
        assert!(
            text.contains("url_env = \"SWITCHBOARD_CI_DATABASE_URL\""),
            "{text}"
        );
    }
    // The opt-out configurations serve nothing, so the opt-out is the only refusal.
    for config in ["identity-disabled", "audit-disabled"] {
        let registry = read(&format!("deploy/ci/{config}/registry/registry.toml"));
        for empty in ["servers = []", "tools = []", "surfaces = []"] {
            assert!(registry.contains(empty), "{config}: {registry}");
        }
    }
    // The keys are public only: no private parameter of an EC or RSA key.
    for config in ["receipt-gate", "audit-disabled"] {
        let keys: Value =
            serde_json::from_str(&read(&format!("deploy/ci/{config}/jwks.json"))).unwrap();
        for key in keys["keys"].as_array().unwrap() {
            for private in ["d", "p", "q", "dp", "dq", "qi"] {
                assert!(key.get(private).is_none(), "{config}: {key}");
            }
        }
    }
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
