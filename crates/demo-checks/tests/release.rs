//! The release `switchboard` is never a development build (decision 0009, design section 12).
//!
//! A build with the gateway's `test-support` feature is exempt from the receipt-store gate, so
//! it serves tools not classified `read` with no receipt store, it accepts the identity and
//! audit opt-outs (decision 0014) and turn-grant checking off (decision 0012), and, through
//! connector-proxy's own `test-support`, it may reach a server on loopback (decision 0013,
//! section 3). Cargo unifies features across the
//! packages of one build, and crates/gateway-dev turns `test-support` on, so a workspace build
//! of `switchboard` would be one. deploy/Dockerfile builds it on its own, with `-p gateway` and
//! no features, and copies it out before anything else is built; CI builds it with the same
//! command and checks that the binary refuses each opt-out and a server on loopback, which only
//! a development build accepts, and a proxied `propose` tool as its registry loads (decision
//! 0011, rule 2). The receipt-store gate cannot be reached from a registry until built-in
//! connectors exist: rule 2 refuses every proxied tool not classified `read` first. These tests
//! pin the command in both places, the five configurations CI starts it with and the refusal
//! each must name, and the feature's absence from the defaults.
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
        ci.contains("--config=deploy/ci/proxied-propose/gateway.toml"),
        "{ci}"
    );
    assert!(
        ci.contains("classified `propose`' proxied-propose-stderr.txt"),
        "CI does not check the refusal is rule 2's"
    );
    let registry = read("deploy/ci/proxied-propose/registry/registry.toml");
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
const REFUSALS: [(&str, &str, &str); 5] = [
    (
        "proxied-propose",
        "proxied-propose-stderr.txt",
        "refused to start: rule 2: tool `docs__propose_document` is proxied through entry \
         `mock-docs` and classified `propose`",
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
    (
        "grants-disabled",
        "grants-disabled-stderr.txt",
        "refused to start: turn-grant checking is disabled, which only a development build \
         allows",
    ),
    (
        "loopback-destination",
        "loopback-destination-stderr.txt",
        "refused to start: server `mock-docs`: the gateway does not connect to 127.0.0.1, a \
         loopback address",
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
    let proxied = file("proxied-propose");
    assert!(
        proxied.contains("[identity]\nmode = \"enforce\"\n"),
        "{proxied}"
    );
    assert!(
        proxied.contains("[audit]\nmode = \"postgres\"\n"),
        "{proxied}"
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
    let grants = file("grants-disabled");
    assert!(
        grants.contains("[identity]\nmode = \"enforce\"\n"),
        "{grants}"
    );
    assert!(
        grants.contains("[audit]\nmode = \"postgres\"\n"),
        "{grants}"
    );
    assert!(
        grants.contains("[grants]\nmode = \"disabled\"\n"),
        "{grants}"
    );
    for text in [&proxied, &identity, &audit] {
        assert!(!text.contains("[grants]"), "{text}");
    }
    let loopback = file("loopback-destination");
    assert!(
        loopback.contains("[identity]\nmode = \"enforce\"\n"),
        "{loopback}"
    );
    assert!(
        loopback.contains("[audit]\nmode = \"postgres\"\n"),
        "{loopback}"
    );
    for text in [&proxied, &identity, &grants, &loopback] {
        assert!(
            text.contains("url_env = \"SWITCHBOARD_CI_DATABASE_URL\""),
            "{text}"
        );
    }
    // The opt-out configurations serve nothing, so the opt-out is the only refusal.
    for config in ["identity-disabled", "audit-disabled", "grants-disabled"] {
        let registry = read(&format!("deploy/ci/{config}/registry/registry.toml"));
        for empty in ["servers = []", "tools = []", "surfaces = []"] {
            assert!(registry.contains(empty), "{config}: {registry}");
        }
    }
    // The loopback configuration's one server is an in-cluster entry on loopback, serving a
    // read tool, so where it is reached is the only refusal.
    let registry = read("deploy/ci/loopback-destination/registry/registry.toml");
    for line in [
        "address = \"http://127.0.0.1:9/mcp\"",
        "destination = \"in_cluster\"",
        "classification = \"read\"",
    ] {
        assert!(registry.contains(line), "{line}: {registry}");
    }
    // Its entry has a reach check, so the configuration gives the reach settings, without which
    // the gateway would refuse to start for that instead.
    assert!(registry.contains("[servers.reach_check]"), "{registry}");
    assert!(
        loopback.contains("[drift]\nreach_token_file = "),
        "{loopback}"
    );
    // The keys are public only: no private parameter of an EC or RSA key.
    for config in [
        "proxied-propose",
        "audit-disabled",
        "grants-disabled",
        "loopback-destination",
    ] {
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
    // It turns on only connector-proxy's own, which alone lets a proxied server's connector
    // reach loopback, and connector-github's `loopback`, which alone lets the GitHub connector
    // reach a fake GitHub API there.
    assert_eq!(
        gateway["features"]["test-support"],
        json!(["connector-github/loopback", "connector-proxy/test-support"])
    );
    let connector = packages
        .iter()
        .find(|package| package["name"] == json!("connector-proxy"))
        .unwrap();
    assert_eq!(connector["features"]["test-support"], json!([]));
    let defaults = connector["features"]["default"].as_array();
    assert!(
        defaults.is_none_or(|defaults| defaults.is_empty()),
        "connector-proxy has default features: {defaults:?}"
    );
    let github = packages
        .iter()
        .find(|package| package["name"] == json!("connector-github"))
        .unwrap();
    assert_eq!(github["features"]["loopback"], json!([]));
    let defaults = github["features"]["default"].as_array();
    assert!(
        defaults.is_none_or(|defaults| defaults.is_empty()),
        "connector-github has default features: {defaults:?}"
    );
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
            if dependency["name"] == json!("connector-proxy")
                || dependency["name"] == json!("connector-github")
                || dependency["name"] == json!("gateway-otto")
            {
                assert_eq!(dependency["features"], json!([]), "{dependency}");
            }
        }
    }
}
