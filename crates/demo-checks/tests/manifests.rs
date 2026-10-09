//! The Compose file and the kind manifests hold to what the demo claims. Read as text, with no
//! YAML parser: each check names the exact lines it relies on, so a change to them has to
//! change the test too, on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::read;
use gateway::READINESS_REMOVAL;
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
fn each_teams_workload_names_its_own_project() {
    // Every Job demo.sh starts, the before-policy one included, keeps the template's
    // environment, and both modes read OWN_PROJECT through the gateway.
    let workloads = read("deploy/kind/base/workloads.yaml");
    for (team, own) in [("team-a", "atlas"), ("team-b", "borealis")] {
        let cronjob = documents_with(&workloads, &format!("  namespace: {team}\n"))
            .into_iter()
            .filter(|doc| doc.contains("  name: mock-workload\n"))
            .collect::<Vec<_>>();
        assert_eq!(cronjob.len(), 1, "{team}");
        assert!(
            cronjob[0].contains(&format!(
                "                - {{name: OWN_PROJECT, value: {own}}}\n"
            )),
            "{team}'s workload does not name {own}:\n{}",
            cronjob[0]
        );
    }
}

/// The number on the one line of `text` that starts with `prefix`, after it.
fn number_after(text: &str, prefix: &str, suffix: &str) -> u64 {
    let lines: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect();
    assert_eq!(lines.len(), 1, "want one line starting `{prefix}`:\n{text}");
    lines[0]
        .strip_suffix(suffix)
        .and_then(|number| number.parse().ok())
        .unwrap_or_else(|| panic!("`{prefix}{}` is not a number", lines[0]))
}

/// Decision 0009, Shutdown: how long a call that began just before the gateway was told to stop
/// may take, with its row: the begin budget, the call deadline and the finish deadline. The
/// demo's deployment files set none of them, so each is the code's default.
fn begin_call_and_finish() -> Duration {
    let budgets = audit_postgres::Budgets::default();
    budgets.begin + connector_proxy::DEFAULT_DEADLINE + budgets.finish_deadline
}

#[test]
fn the_gateway_is_given_time_to_complete_its_rows_when_it_stops() {
    let gateway = read("deploy/kind/base/gateway.yaml");
    let deployment = documents_with(&gateway, "kind: Deployment");
    assert_eq!(deployment.len(), 1, "{gateway}");
    let grace = number_after(deployment[0], "      terminationGracePeriodSeconds: ", "");
    let probe = deployment[0]
        .split_once("          readinessProbe:\n")
        .expect("the gateway has a readiness probe")
        .1;
    let probe: String = probe
        .lines()
        .take_while(|line| line.starts_with("            "))
        .collect::<Vec<_>>()
        .join("\n");
    // The probe asks the gateway's readiness check, which fails first when it stops.
    assert!(
        probe.starts_with(
            "            httpGet:\n              path: /readyz\n              port: http\n"
        ),
        "{probe}"
    );
    // The gateway goes on serving after its check fails for as long as the probe takes to
    // notice: its period times the failures it needs.
    let noticed = Duration::from_secs(
        number_after(&probe, "            periodSeconds: ", "")
            * number_after(&probe, "            failureThreshold: ", ""),
    );
    assert!(
        READINESS_REMOVAL >= noticed,
        "kind: the probe takes {noticed:?} to notice, longer than the gateway's \
         {READINESS_REMOVAL:?} readiness removal"
    );
    let needed = READINESS_REMOVAL + begin_call_and_finish();
    assert!(
        Duration::from_secs(grace) > needed,
        "kind: a grace period of {grace} s is not longer than {needed:?}"
    );

    // Compose has no readiness probe, but the gateway waits out its readiness removal all the
    // same.
    let compose = read("deploy/compose/compose.yaml");
    let service = compose_service(&compose, "gateway");
    let grace = number_after(&service, "    stop_grace_period: ", "s");
    assert!(
        Duration::from_secs(grace) > needed,
        "Compose: a grace period of {grace} s is not longer than {needed:?}"
    );
}

#[test]
fn the_kind_cluster_is_never_otto_dev() {
    let cluster = read("deploy/kind/cluster.yaml");
    assert!(cluster.contains("\nname: switchboard-demo\n"));
    assert!(!cluster.contains("otto-dev"));
}

/// The registry without its leading comment lines.
fn registry_body(path: &str) -> String {
    read(path)
        .lines()
        .skip_while(|line| line.starts_with('#') || line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_compose_and_kind_registries_differ_only_in_issuer_and_address() {
    let kind = registry_body("deploy/kind/base/config/registry/registry.toml");
    let compose = registry_body("deploy/compose/config/registry/registry.toml");
    let kind_issuer = "issuer = \"https://kubernetes.default.svc.cluster.local\"";
    let kind_address = "address = \"http://mock-docs.mock-docs.svc.cluster.local:8080/mcp\"";
    assert_eq!(kind.matches(kind_issuer).count(), 1);
    assert_eq!(kind.matches(kind_address).count(), 1);
    let as_compose = kind
        .replace(
            kind_issuer,
            "issuer = \"https://dev-issuer.switchboard.test\"",
        )
        .replace(kind_address, "address = \"http://mock-docs:8080/mcp\"");
    assert_eq!(as_compose, compose);
    // The kind registry is the registry crate's own demo file.
    assert_eq!(
        kind,
        registry_body("crates/gateway-registry/demo/registry.toml")
    );

    // The withdrawn copy is the Compose registry less the read tool, at a new revision.
    let withdrawn = registry_body("deploy/compose/config/registry-withdrawn.toml");
    assert!(withdrawn.contains("revision = \"demo-2\""));
    assert!(!withdrawn.contains("name = \"docs__read_document\""));
    assert!(withdrawn.contains("tools = [\"docs__list_documents\"]\n"));
    assert_eq!(
        compose.lines().count() - withdrawn.lines().count(),
        25,
        "the withdrawn copy differs by more than the read tool"
    );
}

#[test]
fn each_gateway_trusts_the_issuer_its_registry_selects_profiles_for() {
    for (dir, issuer) in [
        (
            "deploy/compose/config",
            "https://dev-issuer.switchboard.test",
        ),
        (
            "deploy/kind/base/config",
            "https://kubernetes.default.svc.cluster.local",
        ),
    ] {
        let line = format!("issuer = \"{issuer}\"");
        let gateway = read(&format!("{dir}/gateway.toml"));
        assert!(gateway.contains(&line), "{dir}");
        assert!(gateway.contains("subjects_file = \"teams.toml\""), "{dir}");
        assert!(
            gateway.contains("[audit]\nmode = \"postgres\"\n"),
            "{dir}: the demo must write audit rows to Postgres"
        );
        assert!(
            read(&format!("{dir}/registry/registry.toml")).contains(&line),
            "{dir}"
        );
    }
    // The deployment file reads teams.toml from its own directory, so each mounts it there.
    let compose = read("deploy/compose/compose.yaml");
    let gateway = compose_service(&compose, "gateway");
    assert!(gateway.contains("./config/gateway.toml:/etc/switchboard/gateway.toml:ro"));
    assert!(gateway.contains("./config/teams.toml:/etc/switchboard/teams.toml:ro"));
    assert!(gateway.contains("\"--config=/etc/switchboard/gateway.toml\""));
    let kustomization = read("deploy/kind/base/kustomization.yaml");
    assert!(kustomization.contains(
        "      - gateway.toml=config/gateway.toml\n      - teams.toml=config/teams.toml\n"
    ));
}

#[test]
fn the_dev_issuer_signs_for_every_subject_the_compose_demo_asks_for() {
    let compose = read("deploy/compose/compose.yaml");
    let issuer = compose_service(&compose, "dev-issuer");
    for team in ["team-a", "team-b"] {
        for account in ["mock-workload", "stranger"] {
            assert!(
                issuer.contains(&format!("      - --subject=workload:{team}:{account}\n")),
                "the dev issuer would refuse workload:{team}:{account}"
            );
        }
    }
    let driver = read("deploy/demo/demo.sh");
    assert!(driver.contains("subject=workload:$team:mock-workload"));
    assert!(driver.contains("subject=workload:$team:stranger"));
    // The strangers are signed for, and the team manifest leaves them out.
    let manifest = read("deploy/compose/config/teams.toml");
    assert!(
        !manifest
            .lines()
            .any(|line| line.starts_with("\"workload:") && line.contains("stranger"))
    );
}

/// The image is built with the repository root as its context and `COPY . .`, so the context
/// must leave out the worktrees under `.claude` (each with its own target directory, plus
/// session files), every target directory, and the demo transcripts.
#[test]
fn the_image_build_context_leaves_out_worktrees_targets_and_transcripts() {
    let dockerfile = read("deploy/Dockerfile");
    assert!(dockerfile.contains("\nCOPY . .\n"), "{dockerfile}");
    let ignored = read(".dockerignore");
    let lines: Vec<&str> = ignored.lines().map(str::trim).collect();
    for pattern in [
        ".git",
        ".demo",
        "target",
        "**/target",
        ".claude",
        "demo-runs",
    ] {
        assert!(
            lines.contains(&pattern),
            "{pattern} is not in .dockerignore"
        );
    }
}
