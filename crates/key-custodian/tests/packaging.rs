//! The gateway links the custodian's client and nothing of its server.
//!
//! The GitHub connector depends on this crate for [`key_custodian::CustodianClient`], with the
//! `client` feature alone. Everything that reads the key, signs a JWT, calls GitHub or serves the
//! socket is behind `server`. These tests ask Cargo, as `cargo tree` resolves the gateway's own
//! build (normal and build dependencies only, as `cargo build -p gateway --bin switchboard`
//! builds it), which features this crate has there and what it pulls in.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// What only the server uses: none of these may be a dependency of this crate in the gateway.
const SERVER_ONLY: [&str; 10] = [
    "axum",
    "http-body-util",
    "hyper",
    "hyper-rustls",
    "hyper-util",
    "jsonwebtoken",
    "rustls",
    "toml",
    "tracing",
    "tracing-subscriber",
];

/// `cargo tree` for `package`'s own build, offline, with `arguments` added.
fn tree(package: &str, arguments: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = std::process::Command::new(cargo)
        .args([
            "tree",
            "--locked",
            "--offline",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"),
            "--target",
            "all",
            "-e",
            "normal,build",
            "-p",
            package,
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The features this crate has in `package`'s build, from each line that names it.
fn features_in(package: &str) -> Vec<String> {
    let text = tree(
        package,
        &[
            "-e",
            "features",
            "--prefix",
            "none",
            "--format",
            "{p} [{f}]",
        ],
    );
    let found: Vec<String> = text
        .lines()
        .filter(|line| line.starts_with("key-custodian v"))
        .map(|line| {
            let start = line.rfind('[').unwrap();
            let end = line.rfind(']').unwrap();
            line[start + 1..end].to_owned()
        })
        .collect();
    assert!(
        !found.is_empty(),
        "key-custodian is not in {package}'s build:\n{text}"
    );
    found
}

/// This crate's direct dependencies in `package`'s build.
fn dependencies_in(package: &str) -> Vec<String> {
    let text = tree(package, &["--prefix", "depth", "--format", "{p}"]);
    let mut found = Vec::new();
    let mut under: Option<usize> = None;
    for line in text.lines() {
        let digits = line.bytes().take_while(u8::is_ascii_digit).count();
        let depth: usize = line[..digits].parse().unwrap();
        let name = line[digits..].split_whitespace().next().unwrap_or("");
        match under {
            Some(at) if depth == at + 1 => found.push(name.to_owned()),
            Some(at) if depth <= at => under = None,
            _ => {}
        }
        if under.is_none() && name == "key-custodian" && !line.ends_with("(*)") {
            under = Some(depth);
        }
    }
    assert!(
        !found.is_empty(),
        "key-custodian has no dependencies in {package}'s build:\n{text}"
    );
    found
}

#[test]
fn the_gateway_builds_this_crate_with_the_client_alone() {
    for package in ["gateway", "connector-github"] {
        for features in features_in(package) {
            assert_eq!(features, "client", "in {package}'s build");
        }
    }
}

#[test]
fn the_gateway_links_none_of_the_servers_dependencies() {
    for package in ["gateway", "connector-github"] {
        let dependencies = dependencies_in(package);
        for name in SERVER_ONLY {
            assert!(
                !dependencies.iter().any(|found| found == name),
                "key-custodian pulls `{name}` into {package}'s build: {dependencies:?}"
            );
        }
    }
}

#[test]
fn the_custodians_own_build_has_its_server() {
    // The same reading of the custodian's own build finds the server and what it uses, so the
    // tests above would see them in the gateway's.
    let features = features_in("key-custodian");
    assert!(
        features.iter().all(|found| found.contains("server")),
        "{features:?}"
    );
    let dependencies = dependencies_in("key-custodian");
    for name in SERVER_ONLY {
        assert!(
            dependencies.iter().any(|found| found == name),
            "{name}: {dependencies:?}"
        );
    }
}
