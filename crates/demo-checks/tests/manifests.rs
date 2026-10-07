//! The Compose file and the kind manifests hold to what the demo claims. Read as text, with no
//! YAML parser: each check names the exact lines it relies on, so a change to them has to
//! change the test too, on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::read;
use sha2::{Digest, Sha256};

/// The block of a top-level Compose service: its lines up to the next service.
fn compose_service(compose: &str, name: &str) -> String {
    let header = format!("  {name}:");
    let mut lines = compose.lines().skip_while(|line| *line != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("no service `{name}` in compose.yaml"));
    let rest = lines.take_while(|line| {
        line.is_empty() || line.starts_with("    ") || line.trim_start().starts_with('#')
    });
    std::iter::once(first)
        .chain(rest)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The YAML documents of a multi-document file that contain `marker`.
fn documents_with<'a>(text: &'a str, marker: &str) -> Vec<&'a str> {
    text.split("\n---\n")
        .filter(|doc| doc.contains(marker))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn only_the_gateway_is_published_and_only_on_loopback() {
    let compose = read("deploy/compose/compose.yaml");
    let gateway = compose_service(&compose, "gateway");
    assert!(
        gateway.contains("    ports:\n      - \"127.0.0.1:18080:8080\"\n"),
        "{gateway}"
    );
    for service in ["postgres", "migrate", "dev-issuer", "mock-docs", "workload"] {
        let block = compose_service(&compose, service);
        assert!(
            !block.contains("ports:"),
            "service `{service}` publishes a port:\n{block}"
        );
    }
    // Every published port in the file is the gateway's.
    assert_eq!(compose.matches("ports:").count(), 1, "{compose}");
}

#[test]
fn the_workload_runs_only_under_the_demo_profile() {
    let compose = read("deploy/compose/compose.yaml");
    assert!(compose_service(&compose, "workload").contains("    profiles: [demo]"));
}

#[test]
fn the_mock_docs_server_admits_only_the_gateway() {
    let policies = read("deploy/kind/policy/networkpolicies.yaml");
    let only_gateway = documents_with(&policies, "name: only-gateway");
    assert_eq!(only_gateway.len(), 1, "{policies}");
    let spec = only_gateway[0].split_once("spec:\n").expect("a spec").1;
    let spec: String = spec
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        spec.trim_end(),
        "  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: switchboard
          podSelector:
            matchLabels:
              app: gateway
      ports:
        - port: 8080
          protocol: TCP",
        "the only-gateway policy must select every mock-docs pod and admit only the gateway's pods, on 8080"
    );
    assert!(only_gateway[0].contains("namespace: mock-docs"));
}

#[test]
fn the_base_has_no_network_policy() {
    // demo.sh shows a direct call connecting before the policy; that means nothing if the base
    // already holds a policy.
    let kustomization = read("deploy/kind/base/kustomization.yaml");
    let resources: Vec<&str> = kustomization
        .lines()
        .skip_while(|line| *line != "resources:")
        .skip(1)
        .take_while(|line| line.starts_with("  - "))
        .collect();
    assert_eq!(
        resources,
        [
            "  - namespaces.yaml",
            "  - serviceaccounts.yaml",
            "  - postgres.yaml",
            "  - migrate-job.yaml",
            "  - mock-docs.yaml",
            "  - gateway.yaml",
            "  - workloads.yaml",
        ]
    );
    for file in resources {
        let path = format!("deploy/kind/base/{}", file.trim_start_matches("  - "));
        assert!(
            !read(&path).contains("kind: NetworkPolicy"),
            "{path} holds a NetworkPolicy"
        );
    }
}

#[test]
fn each_dummy_credentials_hash_matches_it() {
    for dir in [
        "deploy/compose/dummy-credentials",
        "deploy/kind/base/dummy-credentials",
    ] {
        let credential = read(&format!("{dir}/docs-credential"));
        assert!(
            credential.starts_with("dummy-"),
            "{dir}: the credential must be an obvious dummy"
        );
        assert_eq!(
            read(&format!("{dir}/docs-credential.sha256")).trim(),
            sha256_hex(credential.as_bytes()),
            "{dir}: mock-docs would refuse the gateway's credential"
        );
    }
}

#[test]
fn workload_tokens_are_for_the_gateways_audience_and_short_lived() {
    let workloads = read("deploy/kind/base/workloads.yaml");
    let cronjobs = documents_with(&workloads, "kind: CronJob");
    assert_eq!(cronjobs.len(), 3);
    for cronjob in cronjobs {
        assert!(
            cronjob.contains("  suspend: true\n"),
            "a workload CronJob would run on its schedule:\n{cronjob}"
        );
        assert!(
            cronjob.contains("      backoffLimit: 0\n"),
            "a failed workload would be retried:\n{cronjob}"
        );
        assert!(cronjob.contains("                      audience: switchboard\n                      expirationSeconds: 600\n"), "{cronjob}");
    }
    let gateway = read("deploy/kind/base/config/gateway.toml");
    assert!(gateway.contains("audiences = [\"switchboard\"]"));
    assert!(gateway.contains("max_lifetime_seconds = 3600"));
}

#[test]
fn the_kind_cluster_is_never_otto_dev() {
    let cluster = read("deploy/kind/cluster.yaml");
    assert!(cluster.contains("\nname: switchboard-demo\n"));
    assert!(!cluster.contains("otto-dev"));
}
