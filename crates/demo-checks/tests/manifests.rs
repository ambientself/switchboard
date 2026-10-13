//! The Compose file and the kind manifests hold to what the demo claims. Read as text, with no
//! YAML parser: each check names the exact lines it relies on, so a change to them has to
//! change the test too, on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::read;
use gateway::deployment::DeploymentFile;
use gateway::{READINESS_REMOVAL, SHUTDOWN_GRACE};
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
            "  - gateway-tokens.yaml",
            "  - postgres.yaml",
            "  - migrate-job.yaml",
            "  - mock-docs.yaml",
            "  - issuer-discovery.yaml",
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

/// The `listen` of a deployment file's `[metrics]`, and the MCP listener's, before any table.
fn listeners(config: &str) -> (&str, &str) {
    let (top, rest) = config.split_once("\n[http]\n").expect("an [http] table");
    let metrics = rest
        .split_once("\n[metrics]\n")
        .expect("a [metrics] table")
        .1
        .split_once("\n[")
        .expect("a table after [metrics]")
        .0;
    (
        value_after(top, "listen = "),
        value_after(metrics, "listen = "),
    )
}

/// In kind the metrics are on a containerPort of their own, which the teams cannot reach: the
/// gateway-from-teams policy admits them on the MCP port and no other, and the Service does not
/// expose the metrics port.
#[test]
fn the_teams_cannot_reach_the_kind_gateways_metrics_port() {
    let config = read("deploy/kind/base/config/gateway.toml");
    let (mcp, metrics) = listeners(&config);
    assert_eq!(mcp, "0.0.0.0:8080");
    assert_eq!(metrics, "0.0.0.0:9090");

    let manifest = read("deploy/kind/base/gateway.yaml");
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let ports = block_after(&gateway, "          ports:");
    let declared: Vec<&str> = ports
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        declared,
        [
            "            - containerPort: 8080",
            "              name: http",
            "            - containerPort: 9090",
            "              name: metrics",
        ]
    );
    let service = documents_with(&manifest, "kind: Service\n");
    assert_eq!(service.len(), 1, "{manifest}");
    assert!(
        !service[0].contains("9090") && !service[0].contains("metrics"),
        "the Service exposes the metrics port:\n{}",
        service[0]
    );

    let policies = read("deploy/kind/policy/networkpolicies.yaml");
    let from_teams = documents_with(&policies, "name: gateway-from-teams");
    assert_eq!(from_teams.len(), 1, "{policies}");
    assert!(from_teams[0].contains("namespace: switchboard"));
    let spec = from_teams[0].split_once("spec:\n").expect("a spec").1;
    let spec: String = spec
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    // One rule, with its ports: a rule without ports would admit every port.
    assert_eq!(
        spec.trim_end(),
        "  podSelector:
    matchLabels:
      app: gateway
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: team-a
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: team-b
      ports:
        - port: 8080
          protocol: TCP",
        "the gateway-from-teams policy must admit the teams on 8080 alone"
    );
}

/// In Compose the metrics listen on the container's loopback, and nothing publishes them.
#[test]
fn the_compose_gateways_metrics_are_on_its_loopback_and_unpublished() {
    let config = read("deploy/compose/config/gateway.toml");
    let (mcp, metrics) = listeners(&config);
    assert_eq!(mcp, "0.0.0.0:8080");
    assert_eq!(metrics, "127.0.0.1:9090");
    let compose = read("deploy/compose/compose.yaml");
    assert!(!compose.contains("9090"), "{compose}");
}

#[test]
fn each_dummy_credentials_hash_matches_it() {
    // Only Compose has dummy credentials, one for each entry of the mock server; in kind the
    // gateway presents each entry's ServiceAccount token.
    let dir = "deploy/compose/dummy-credentials";
    let callers = read(&format!("{dir}/mock-docs-callers"));
    let mut digests = Vec::new();
    for (entry, project) in [("docs-team-a", "atlas"), ("docs-team-b", "borealis")] {
        let credential = read(&format!("{dir}/{entry}-credential"));
        assert!(
            credential.starts_with("dummy-"),
            "{dir}/{entry}-credential must be an obvious dummy"
        );
        let digest = sha256_hex(credential.as_bytes());
        assert_eq!(
            read(&format!("{dir}/{entry}-credential.sha256")).trim(),
            digest,
            "{dir}: demo.sh would look for another digest in mock-docs' log"
        );
        // mock-docs accepts the credential for its team's project alone, which is the entry's
        // whole recorded reach.
        digests.push(format!("{digest} {project}"));
        let registry = read("deploy/compose/config/registry/registry.toml");
        assert_eq!(entry_reach(&registry, entry), [project]);
    }
    assert_eq!(
        callers.lines().collect::<Vec<_>>(),
        digests,
        "{dir}/mock-docs-callers: mock-docs would refuse an entry's credential, or let it name another team's project"
    );
    assert_ne!(
        read(&format!("{dir}/docs-team-a-credential")),
        read(&format!("{dir}/docs-team-b-credential"))
    );
}

#[test]
fn compose_gives_each_entry_its_own_credential_and_mock_docs_their_digests() {
    let compose = read("deploy/compose/compose.yaml");
    let gateway = compose_service(&compose, "gateway");
    assert!(
        gateway.contains(
            "    secrets:\n      - docs-team-a-credential\n      - docs-team-b-credential\n"
        ),
        "{gateway}"
    );
    let mock_docs = compose_service(&compose, "mock-docs");
    assert!(
        mock_docs.contains("      MOCK_DOCS_TOKEN_SHA256_FILE: /run/secrets/mock-docs-callers\n"),
        "{mock_docs}"
    );
    assert!(
        mock_docs.contains("    secrets:\n      - mock-docs-callers\n"),
        "{mock_docs}"
    );
    for (secret, file) in [
        ("docs-team-a-credential", "docs-team-a-credential"),
        ("docs-team-b-credential", "docs-team-b-credential"),
        ("mock-docs-callers", "mock-docs-callers"),
    ] {
        assert!(
            compose.contains(&format!(
                "  {secret}:\n    file: ./dummy-credentials/{file}\n"
            )),
            "{secret}"
        );
    }
    // The deployment file maps each entry's reference to its secret.
    let config = read("deploy/compose/config/gateway.toml");
    assert_eq!(
        credential_entries(&config),
        [
            "docs-team-a-credential = \"/run/secrets/docs-team-a-credential\"",
            "docs-team-b-credential = \"/run/secrets/docs-team-b-credential\"",
        ]
    );
}

/// Compose has no issuer for mock-docs, so the probe's third call presents a static dummy
/// (decision 0013, section 9): a secret of the gateway's, given to no other service, which
/// mock-docs does not accept and so must refuse as a stranger's.
#[test]
fn compose_gives_the_probe_a_dummy_mock_docs_does_not_accept() {
    let dir = "deploy/compose/dummy-credentials";
    let credential = read(&format!("{dir}/registry-probe-credential"));
    assert!(credential.starts_with("dummy-"), "{credential}");
    let digest = sha256_hex(credential.as_bytes());
    assert!(
        !read(&format!("{dir}/mock-docs-callers")).contains(&digest),
        "mock-docs would accept the probe's credential"
    );
    // demo.sh tells the probe's bearers, this one and the malformed one, from a workload's by
    // their digests.
    assert_eq!(
        read(&format!("{dir}/registry-probe-credential.sha256")).trim(),
        digest
    );
    assert_eq!(
        value_after(&read("deploy/demo/demo.sh"), "PROBE_MALFORMED_SHA="),
        sha256_hex(b"not-a-token")
    );
    for entry in ["docs-team-a", "docs-team-b"] {
        assert_ne!(read(&format!("{dir}/{entry}-credential")), credential);
    }
    let compose = read("deploy/compose/compose.yaml");
    assert!(compose.contains(
        "  registry-probe-credential:\n    file: ./dummy-credentials/registry-probe-credential\n"
    ));
    let gateway = compose_service(&compose, "gateway");
    assert!(
        gateway.contains("      - registry-probe-credential\n"),
        "{gateway}"
    );
    for service in ["mock-docs", "dev-issuer", "workload", "migrate"] {
        assert!(
            !compose_service(&compose, service).contains("registry-probe-credential"),
            "{service}"
        );
    }
    let config = read("deploy/compose/config/gateway.toml");
    assert_eq!(
        probe_credential_entries(&config),
        [
            "docs-team-a = \"/run/secrets/registry-probe-credential\"",
            "docs-team-b = \"/run/secrets/registry-probe-credential\"",
        ]
    );
}

/// The non-comment lines of a deployment file's `[credentials]` table.
fn credential_entries(config: &str) -> Vec<&str> {
    config
        .split_once("[credentials]\n")
        .expect("a [credentials] section")
        .1
        .lines()
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect()
}

/// The non-comment lines of a deployment file's `[drift.probe_credentials]` table.
fn probe_credential_entries(config: &str) -> Vec<&str> {
    config
        .split_once("[drift.probe_credentials]\n")
        .expect("a [drift.probe_credentials] section")
        .1
        .lines()
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect()
}

/// The one Deployment in a kind manifest.
fn only_deployment(path: &str) -> String {
    let text = read(path);
    let deployments = documents_with(&text, "kind: Deployment");
    assert_eq!(deployments.len(), 1, "{path}");
    deployments[0].to_owned()
}

/// The text after `prefix` on the one line of `text` that starts with it, without quotes.
fn value_after<'a>(text: &'a str, prefix: &str) -> &'a str {
    let lines: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect();
    assert_eq!(lines.len(), 1, "want one line starting `{prefix}`:\n{text}");
    lines[0].trim_matches('"')
}

/// The lines of the YAML block that follows the line `header` in `text`: those indented deeper
/// than it.
fn block_after(text: &str, header: &str) -> String {
    let indent = header.len() - header.trim_start().len();
    let after = text
        .split_once(&format!("{header}\n"))
        .unwrap_or_else(|| panic!("no line `{header}`:\n{text}"))
        .1;
    after
        .lines()
        .take_while(|line| line.len() - line.trim_start().len() > indent)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The items of the YAML list that follows the line `header` in `text`, each from its `- ` line
/// up to the next item. A comment between two items goes with the first.
fn items(text: &str, header: &str) -> Vec<String> {
    let block = block_after(text, header);
    let indent = block
        .lines()
        .find(|line| line.trim_start().starts_with("- "))
        .map(|line| line.len() - line.trim_start().len())
        .unwrap_or_else(|| panic!("no list after `{header}`"));
    let mut items: Vec<String> = Vec::new();
    for line in block.lines() {
        if line.len() - line.trim_start().len() == indent && line.trim_start().starts_with("- ") {
            items.push(String::new());
        }
        if let Some(item) = items.last_mut() {
            item.push_str(line);
            item.push('\n');
        }
    }
    items
}

/// The name of a list item that starts `- name: NAME`, or `- {name: NAME, ...}`.
fn item_name(item: &str) -> &str {
    let first = item.lines().next().unwrap().trim_start();
    let name = first
        .strip_prefix("- name: ")
        .or_else(|| first.strip_prefix("- {name: "))
        .unwrap_or_else(|| panic!("an item without a name first: {first}"));
    name.split([',', '}']).next().unwrap().trim()
}

/// The audience of each projected ServiceAccount token source in `volume`, None for a source
/// that names none and so gets the API server's. It reads a source block style
/// (`- serviceAccountToken:`, then its fields on the lines under it, past blank lines and
/// comments) or flow style (`- serviceAccountToken: {...}` or `- {serviceAccountToken: {...}}`,
/// its fields closed on that line). It panics on any other line that names
/// `serviceAccountToken`, on a flow mapping that does not close on its line, and on a field it
/// cannot read as `audience`, `expirationSeconds` or `path` with a value. It is not a YAML
/// parser: a quoted key, an alias, an anchor or tag on the audience, or an empty or null
/// audience can still be misread, and #182 replaces it with one.
fn token_audiences(volume: &str) -> Vec<Option<String>> {
    let lines: Vec<&str> = volume.lines().collect();
    let mut audiences = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let text = line.trim_start();
        if text.starts_with('#') || !text.contains("serviceAccountToken") {
            continue;
        }
        let fields: Vec<&str> = if text == "- serviceAccountToken:" {
            let indent = line.len() - text.len();
            lines[at + 1..]
                .iter()
                .filter(|next| !next.trim().is_empty() && !next.trim_start().starts_with('#'))
                .take_while(|next| next.len() - next.trim_start().len() > indent + 2)
                .map(|next| next.trim())
                .collect()
        } else {
            let rest = text
                .strip_prefix("- serviceAccountToken: {")
                .or_else(|| text.strip_prefix("- {serviceAccountToken: {"))
                .unwrap_or_else(|| panic!("a token source it cannot read: {text}"));
            let (fields, _) = rest.split_once('}').unwrap_or_else(|| {
                panic!("a token source that does not close on its line: {text}")
            });
            fields
                .split(',')
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .collect()
        };
        let mut audience = None;
        for field in fields {
            let (key, value) = field
                .split_once(": ")
                .unwrap_or_else(|| panic!("a token source field it cannot read: {field}"));
            let value = value.split(" #").next().unwrap().trim();
            match key {
                "audience" => audience = Some(value.trim_matches(['"', '\'']).to_owned()),
                "expirationSeconds" | "path" => {}
                _ => panic!("a token source field it cannot read: {field}"),
            }
        }
        audiences.push(audience);
    }
    audiences
}

/// The audiences the kind cluster's API server accepts: its issuer's, which a projected token
/// gets when it names none.
fn api_audience(audience: Option<&str>) -> bool {
    audience.is_none_or(|audience| audience == KIND_ISSUER)
}

const KIND_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

/// A pod template's containers of both kinds, by name, each with the names of the volumes it
/// mounts.
fn containers(pod: &str) -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    for header in ["      initContainers:", "      containers:"] {
        if !pod.contains(&format!("{header}\n")) {
            continue;
        }
        for container in items(pod, header) {
            let mounts = if container.contains("volumeMounts:\n") {
                let header = container
                    .lines()
                    .find(|line| line.trim_start() == "volumeMounts:")
                    .unwrap()
                    .to_owned();
                items(&container, &header)
                    .iter()
                    .map(|mount| item_name(mount).to_owned())
                    .collect()
            } else {
                Vec::new()
            };
            found.push((item_name(&container).to_owned(), mounts));
        }
    }
    found
}

/// The volumes of a pod template, by name, that hold a token the API server accepts.
fn api_token_volumes(pod: &str) -> Vec<String> {
    items(pod, "      volumes:")
        .iter()
        .filter(|volume| {
            token_audiences(volume)
                .iter()
                .any(|audience| api_audience(audience.as_deref()))
        })
        .map(|volume| item_name(volume).to_owned())
        .collect()
}

/// Decision 0013, section 10: in the gateway pod only the token writer mounts a token the API
/// server accepts, a projected one with no audience or the API server's, and the gateway
/// container mounts no ServiceAccount token at all. No container gets the default API token.
#[test]
fn only_the_token_writer_mounts_an_api_token_in_the_gateway_pod() {
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let api_volumes = api_token_volumes(&gateway);
    assert_eq!(api_volumes, ["api-token"], "{gateway}");
    let containers = containers(&gateway);
    let names: Vec<&str> = containers.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["wait-for-audit-schema", "token-writer", "gateway"]);
    let with_api_token: Vec<&str> = containers
        .iter()
        .filter(|(_, mounts)| mounts.iter().any(|mount| api_volumes.contains(mount)))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(with_api_token, ["token-writer"], "{gateway}");

    // The gateway container mounts no projected ServiceAccount token, of any audience.
    let token_volumes: Vec<String> = items(&gateway, "      volumes:")
        .iter()
        .filter(|volume| !token_audiences(volume).is_empty())
        .map(|volume| item_name(volume).to_owned())
        .collect();
    let (_, mounts) = containers
        .iter()
        .find(|(name, _)| name == "gateway")
        .unwrap();
    assert!(
        !mounts.iter().any(|mount| token_volumes.contains(mount)),
        "the gateway container mounts a ServiceAccount token: {mounts:?}"
    );

    // The token writer's API token is short-lived, and comes with the cluster's CA.
    let api_token = items(&gateway, "      volumes:")
        .into_iter()
        .find(|volume| item_name(volume) == "api-token")
        .unwrap();
    assert!(
        api_token.contains("                  expirationSeconds: 600\n"),
        "{api_token}"
    );
    assert!(
        api_token.contains("                  name: kube-root-ca.crt\n"),
        "{api_token}"
    );

    // No container is given the default API token.
    assert!(
        !gateway.contains("automountServiceAccountToken: true"),
        "{gateway}"
    );
    let accounts = read("deploy/kind/base/serviceaccounts.yaml");
    let account = documents_with(&accounts, "  name: gateway\n");
    assert_eq!(account.len(), 1);
    assert!(account[0].contains("\nautomountServiceAccountToken: false"));
}

/// Decision 0013, section 10: no workload mounts a token the API server accepts, neither the
/// default API token nor a projected one.
#[test]
fn no_workload_mounts_an_api_token() {
    let workloads = read("deploy/kind/base/workloads.yaml");
    let accounts = read("deploy/kind/base/serviceaccounts.yaml");
    let cronjobs = documents_with(&workloads, "kind: CronJob");
    assert_eq!(cronjobs.len(), 3);
    for cronjob in cronjobs {
        // The pod template, unindented to a Deployment's depth so the helpers read it.
        let pod: String = cronjob
            .lines()
            .map(|line| line.strip_prefix("    ").unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(api_token_volumes(&pod), Vec::<String>::new(), "{cronjob}");
        assert!(
            !cronjob.contains("automountServiceAccountToken: true"),
            "{cronjob}"
        );
        let namespace = value_after(cronjob, "  namespace: ");
        let account = value_after(cronjob, "          serviceAccountName: ");
        let account = documents_with(
            &accounts,
            &format!("  name: {account}\n  namespace: {namespace}\n"),
        );
        assert_eq!(account.len(), 1, "{namespace}");
        assert!(
            account[0].contains("\nautomountServiceAccountToken: false"),
            "{namespace}: {}",
            account[0]
        );
    }
}

/// What the token RBAC grants: ServiceAccount gateway may create tokens for the entries'
/// ServiceAccounts, the probe's, registry-probe, and the registry's own workload identity,
/// registry, named, and nothing else; and no other Role or binding is in the base.
#[test]
fn the_token_grant_names_exactly_the_entries_the_probes_and_the_registrys_service_accounts() {
    let grant = read("deploy/kind/base/gateway-tokens.yaml");
    let documents: Vec<String> = grant
        .split("\n---\n")
        .map(|doc| {
            doc.lines()
                .filter(|line| !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    assert_eq!(
        documents,
        [
            "apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: gateway-tokens
  namespace: switchboard
rules:
  - apiGroups: [\"\"]
    resources: [\"serviceaccounts/token\"]
    verbs: [\"create\"]
    resourceNames: [\"docs-team-a\", \"docs-team-b\", \"registry-probe\", \"registry\"]",
            "apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gateway-tokens
  namespace: switchboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: gateway-tokens
subjects:
  - kind: ServiceAccount
    name: gateway
    namespace: switchboard",
        ],
        "the token grant must be exactly this"
    );
    // The names are the token writer's accounts, each a ServiceAccount in the namespace. The
    // registry's token is for the gateway's own audience, switchboard; the rest are for
    // mock-docs'.
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    assert!(gateway.contains(
        "            - {name: TOKEN_SERVICE_ACCOUNTS, value: \"docs-team-a docs-team-b registry-probe registry:switchboard\"}\n"
    ));
    assert!(gateway.contains("            - {name: TOKEN_NAMESPACE, value: switchboard}\n"));
    let accounts = read("deploy/kind/base/serviceaccounts.yaml");
    for account in ["docs-team-a", "docs-team-b", "registry-probe", "registry"] {
        let found = documents_with(
            &accounts,
            &format!("  name: {account}\n  namespace: switchboard\n"),
        );
        assert_eq!(found.len(), 1, "{account}");
        assert!(found[0].contains("\nautomountServiceAccountToken: false"));
    }
    // No other file of the base grants a ServiceAccount anything or names ServiceAccounts in a
    // rule. A binding for other subjects, such as unauthenticated callers, is not checked here.
    let kustomization = read("deploy/kind/base/kustomization.yaml");
    for file in kustomization
        .lines()
        .filter_map(|line| line.strip_prefix("  - "))
        .filter(|file| file.ends_with(".yaml") && *file != "gateway-tokens.yaml")
    {
        let text = read(&format!("deploy/kind/base/{file}"));
        for document in text.split("\n---\n") {
            assert!(
                !document
                    .lines()
                    .any(|line| line.contains("resources:") && line.contains("serviceaccounts")),
                "{file} has a rule on ServiceAccounts: {document}"
            );
            let binding = document
                .lines()
                .any(|line| line == "kind: RoleBinding" || line == "kind: ClusterRoleBinding");
            if let (true, Some((_, subjects))) = (binding, document.split_once("\nsubjects:")) {
                assert!(
                    !subjects.contains("kind: ServiceAccount")
                        && !subjects.contains("system:serviceaccounts"),
                    "{file} binds a role to a ServiceAccount: {document}"
                );
            }
        }
    }
}

/// Decision 0013, section 10: in kind the gateway presents each entry's ServiceAccount token,
/// which the token writer writes, and holds no static credential.
#[test]
fn the_kind_gateway_presents_each_entrys_token_and_holds_no_secret() {
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let containers = items(&gateway, "      containers:");
    let container = containers
        .iter()
        .find(|container| item_name(container) == "gateway")
        .unwrap();
    // The gateway reads the tokens; only the token writer writes them.
    assert!(container.contains(
        "            - {name: entry-tokens, mountPath: /var/run/switchboard/tokens, readOnly: true}\n"
    ));
    let writer = items(&gateway, "      initContainers:")
        .into_iter()
        .find(|container| item_name(container) == "token-writer")
        .unwrap();
    assert!(
        writer.contains("          restartPolicy: Always\n"),
        "{writer}"
    );
    assert!(
        writer.contains(
            "            - {name: entry-tokens, mountPath: /var/run/switchboard/tokens}\n"
        )
    );
    assert!(
        writer.contains("            - {name: TOKEN_DIR, value: /var/run/switchboard/tokens}\n")
    );
    // The gateway starts only once the four tokens are written: it reads every credential,
    // the probe's included, at boot, and the reach check presents the registry's at once.
    assert!(writer.contains(
        "                - test -s /var/run/switchboard/tokens/docs-team-a && test -s /var/run/switchboard/tokens/docs-team-b && test -s /var/run/switchboard/tokens/registry-probe && test -s /var/run/switchboard/tokens/registry\n"
    ), "{writer}");
    assert!(gateway.contains(
        "        - name: entry-tokens\n          emptyDir: {medium: Memory, sizeLimit: 1Mi}"
    ));
    // No Secret volume, nor a Secret projected into one; the database URL comes from a Secret
    // by secretKeyRef, which is not a credential for mock-docs.
    for secret in ["secret:", "secretName"] {
        assert!(
            !gateway.contains(secret),
            "the gateway mounts a Secret:\n{gateway}"
        );
    }

    // The deployment file names each entry's token as its credential, under the registry's
    // references.
    let config = read("deploy/kind/base/config/gateway.toml");
    assert_eq!(
        credential_entries(&config),
        [
            "docs-team-a-credential = \"/var/run/switchboard/tokens/docs-team-a\"",
            "docs-team-b-credential = \"/var/run/switchboard/tokens/docs-team-b\"",
        ]
    );
    // The probe presents ServiceAccount registry-probe's token on its third call, for each
    // entry: the file the token writer writes for that account, which is a token for audience
    // mock-docs, the entries' own audience (decision 0013, section 9).
    assert_eq!(
        probe_credential_entries(&config),
        [
            "docs-team-a = \"/var/run/switchboard/tokens/registry-probe\"",
            "docs-team-b = \"/var/run/switchboard/tokens/registry-probe\"",
        ]
    );
    let writer_env = |name: &str| {
        value_after(&writer, &format!("            - {{name: {name}, value: "))
            .trim_end_matches('}')
            .trim_matches('"')
            .to_owned()
    };
    assert!(
        writer_env("TOKEN_SERVICE_ACCOUNTS")
            .split(' ')
            .any(|account| account == "registry-probe")
    );
    assert_eq!(writer_env("TOKEN_AUDIENCE"), "mock-docs");
    // The reach check presents ServiceAccount registry's token, for the gateway's own audience,
    // to the gateway's own listener: the file the token writer writes for that account.
    assert!(
        writer_env("TOKEN_SERVICE_ACCOUNTS")
            .split(' ')
            .any(|account| account == "registry:switchboard")
    );
    assert!(config.contains("\nreach_token_file = \"/var/run/switchboard/tokens/registry\"\n"));
    assert!(config.contains("\naudiences = [\"switchboard\"]\n"));
    assert_eq!(writer_env("TOKEN_DIR"), "/var/run/switchboard/tokens");

    // The dummy credentials and the Secrets made from them are not in kind.
    assert!(
        !common::repo()
            .join("deploy/kind/base/dummy-credentials")
            .exists()
    );
    let kustomization = read("deploy/kind/base/kustomization.yaml");
    assert!(
        !kustomization
            .lines()
            .any(|line| !line.starts_with('#') && line.contains("credential")),
        "{kustomization}"
    );
}

/// mock-docs in kind accepts only the entries' ServiceAccounts, signed by the cluster's issuer,
/// for its own audience, each for its team's project alone, and holds no static credential.
#[test]
fn the_kind_mock_docs_accepts_only_the_entries_identities() {
    use mock_docs_server::config;

    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let namespace = value_after(&gateway, "  namespace: ");
    let subjects: Vec<String> = ["docs-team-a", "docs-team-b"]
        .iter()
        .map(|account| format!("system:serviceaccount:{namespace}:{account}"))
        .collect();
    let audience = value_after(&gateway, "            - {name: TOKEN_AUDIENCE, value: ")
        .trim_end_matches('}')
        .to_owned();
    let issuer = value_after(&read("deploy/kind/base/config/gateway.toml"), "issuer = ").to_owned();
    assert_eq!(issuer, KIND_ISSUER);
    let driver = read("deploy/demo/demo.sh");
    assert_eq!(value_after(&driver, "KIND_ISSUER="), issuer);
    assert_eq!(
        value_after(&driver, "KIND_ENTRY_SUBJECTS="),
        subjects.join(" ")
    );

    let mock_docs = only_deployment("deploy/kind/base/mock-docs.yaml");
    let env: Vec<(String, String)> = block_after(&mock_docs, "          env:")
        .lines()
        .map(|line| {
            let pair = line
                .trim()
                .strip_prefix("- {name: ")
                .and_then(|rest| rest.strip_suffix('}'))
                .unwrap_or_else(|| panic!("an env line of another shape: {line}"));
            let (name, value) = pair.split_once(", value: ").expect("a name and a value");
            (name.to_owned(), value.trim_matches('"').to_owned())
        })
        .collect();
    let jwks = "/etc/mock-docs/issuer/jwks.json";
    // Each entry's ServiceAccount, for its team's project alone: the project the registry's
    // limit gives the team whose surface serves that entry's tools.
    let callers = format!("{}=atlas;{}=borealis", subjects[0], subjects[1]);
    let want: Vec<(String, String)> = [
        (config::LISTEN_VAR, "0.0.0.0:8080"),
        (config::ADMIN_LISTEN_VAR, "127.0.0.1:9091"),
        (config::JWT_ISSUER_VAR, issuer.as_str()),
        (config::JWT_AUDIENCE_VAR, audience.as_str()),
        (config::JWT_SUBJECTS_VAR, callers.as_str()),
        (config::JWKS_FILE_VAR, jwks),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect();
    assert_eq!(env, want);
    assert_eq!(audience, "mock-docs");
    let registry = read("deploy/kind/base/config/registry/registry.toml");
    for (entry, team, project) in [
        ("docs-team-a", "team-a", "atlas"),
        ("docs-team-b", "team-b", "borealis"),
    ] {
        assert!(registry.contains(&format!(
            "[[surfaces]]\nname = \"{entry}\"\ntools = [\"{entry}__list_documents\", \"{entry}__read_document\"]\nteams = [\"{team}\"]\n"
        )));
        assert!(registry.contains(&format!(
            "{team} = [{{ system = \"docs\", kind = \"project\", identifier = \"{project}\" }}]\n"
        )));
        assert!(registry.contains(&format!(
            "credential = {{ mode = \"team_service_identity\", reference = \"{entry}-credential\", principal = \"{entry}\" }}\n"
        )));
        // The entry's recorded reach is exactly what mock-docs lets its identity read.
        assert_eq!(entry_reach(&registry, entry), [project]);
    }
    // slow-doc keeps its default delay, past the call deadline, and the admin endpoint has no
    // credential of its own: on loopback it needs none (the next test).
    for name in config::STATIC_VARS.into_iter().chain([
        config::JWT_SUBJECT_VAR,
        config::ADMIN_TOKEN_SHA256_FILE_VAR,
        config::SLOW_MS_VAR,
    ]) {
        assert!(
            !mock_docs.contains(&format!("{name},")),
            "mock-docs sets {name}"
        );
    }
    for secret in ["secret:", "secretName", "secretKeyRef"] {
        assert!(
            !mock_docs.contains(secret),
            "mock-docs reads a Secret:\n{mock_docs}"
        );
    }

    // The keys are the cluster's, which demo.sh copies into mock-docs' namespace, and only
    // there: the gateway fetches its own (the next test).
    assert!(mock_docs.contains(
        "            - {name: issuer-keys, mountPath: /etc/mock-docs/issuer, readOnly: true}\n"
    ));
    assert!(
        mock_docs.contains(
            "        - name: issuer-keys\n          configMap: {name: cluster-issuer-keys}"
        )
    );
    let copies: Vec<&str> = driver
        .lines()
        .filter(|line| line.contains("create configmap cluster-issuer-keys"))
        .collect();
    assert_eq!(
        copies,
        [
            "  k -n mock-docs create configmap cluster-issuer-keys --from-file=jwks.json=\"$DEMO_DIR/cluster-jwks.json\" \\"
        ]
    );
    assert!(driver.contains(
        "\n  k -n switchboard delete configmap cluster-issuer-keys --ignore-not-found\n"
    ));
}

/// mock-docs' admin endpoint changes what it serves, and is for demo.sh's drift and reach
/// steps. In Compose and in kind it listens on its container's loopback, which the binary
/// allows with no admin credential only because no caller can reach it there, and demo.sh
/// reaches it from inside that container. No published port, containerPort, Service or network policy names its port,
/// so no workload, and not the gateway either, can reach it.
#[test]
fn mock_docs_admin_endpoint_is_reached_only_from_inside_its_container() {
    use mock_docs_server::config;

    let driver = read("deploy/demo/demo.sh");
    let address = value_after(&driver, "MOCK_ADMIN_URL=")
        .strip_prefix("http://")
        .expect("an http URL")
        .to_owned();
    let (host, port) = address.rsplit_once(':').expect("a host and a port");
    assert_eq!(host, "127.0.0.1", "the admin endpoint is on loopback");

    let compose = read("deploy/compose/compose.yaml");
    let mock_docs = compose_service(&compose, "mock-docs");
    assert!(
        mock_docs.contains(&format!("      {}: {address}\n", config::ADMIN_LISTEN_VAR)),
        "{mock_docs}"
    );
    for exposed in ["ports:", "expose:", config::ADMIN_TOKEN_SHA256_FILE_VAR] {
        assert!(!mock_docs.contains(exposed), "{exposed}:\n{mock_docs}");
    }
    assert_eq!(compose.matches(config::ADMIN_LISTEN_VAR).count(), 1);

    let kind = read("deploy/kind/base/mock-docs.yaml");
    assert!(kind.contains(&format!(
        "            - {{name: {}, value: \"{address}\"}}\n",
        config::ADMIN_LISTEN_VAR
    )));
    let mut manifests: Vec<String> = read("deploy/kind/base/kustomization.yaml")
        .lines()
        .filter_map(|line| line.strip_prefix("  - "))
        .filter(|file| file.ends_with(".yaml"))
        .map(|file| format!("deploy/kind/base/{file}"))
        .collect();
    manifests.push("deploy/kind/policy/networkpolicies.yaml".to_owned());
    manifests.push("deploy/kind/route-check/rbac.yaml".to_owned());
    for path in manifests {
        for line in read(&path).lines() {
            let line = line.trim_start().trim_start_matches("- ");
            for key in [
                "port:",
                "containerPort:",
                "targetPort:",
                "nodePort:",
                "hostPort:",
            ] {
                if let Some(value) = line.strip_prefix(key) {
                    assert_ne!(
                        value.trim(),
                        port,
                        "{path} names mock-docs' admin port: {line}"
                    );
                }
            }
        }
    }

    // demo.sh reaches it only by an exec into mock-docs' own container.
    assert_eq!(driver.matches("$MOCK_ADMIN_URL").count(), 1, "one request");
    for exec in [
        "    compose) dc exec -T mock-docs \"${request[@]}\" ;;\n",
        "    kind) k -n mock-docs exec deploy/mock-docs -c mock-docs -- \"${request[@]}\" ;;\n",
    ] {
        assert!(driver.contains(exec), "{exec}");
    }
}

/// The lines of the container `name` in a Deployment: from its `- name:` line to the next
/// container, or the end of the pod's containers. Blank lines and comments, at any indent, do
/// not end it.
fn container(deployment: &str, name: &str) -> String {
    let header = format!("        - name: {name}");
    let mut lines = deployment.lines().skip_while(|line| *line != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("no container `{name}`:\n{deployment}"));
    let rest = lines.take_while(|line| {
        line.starts_with("          ") || line.trim().is_empty() || line.trim().starts_with('#')
    });
    std::iter::once(first)
        .chain(rest)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The name of each volume the container mounts, from each item of its `volumeMounts:` list,
/// flow style (`- {name: ..., mountPath: ...}`) or block style (`- name: ...`, then the rest on
/// the lines under it). It reads every line up to the container's next key,
/// passing over blank lines and comments, takes each line at the items' indent that starts `-`,
/// a bare `-` among them, as an item, and panics on an item it cannot read the name of first or
/// a line that belongs to no item. It is not a YAML parser; #182 replaces it with one.
fn mounted(container: &str) -> Vec<String> {
    let header = "          volumeMounts:";
    let key_indent = header.len() - header.trim_start().len();
    let list = container
        .split_once(&format!("{header}\n"))
        .unwrap_or_else(|| panic!("no line `{header}`:\n{container}"))
        .1;
    let mut item_indent = None;
    let mut items: Vec<String> = Vec::new();
    for line in list.lines() {
        let text = line.trim_start();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let indent = line.len() - text.len();
        if indent <= key_indent && !text.starts_with('-') {
            // The container's next key.
            break;
        }
        let at = *item_indent.get_or_insert(indent);
        if indent == at && text.starts_with('-') {
            items.push(String::new());
        }
        assert!(indent >= at, "a volume mount line outside any item: {line}");
        let item = items
            .last_mut()
            .unwrap_or_else(|| panic!("a volume mount line outside any item: {line}"));
        item.push_str(line);
        item.push('\n');
    }
    items
        .iter()
        .map(|mount| item_name(mount).to_owned())
        .collect()
}

/// No volume the gateway's `container` mounts projects a token the API server accepts: each
/// projected token names an audience, and not the API server's, which in kind is the issuer.
fn no_api_token_mounted(gateway: &str, container: &str, issuer: &str) {
    for name in &mounted(container) {
        for audience in token_audiences(&volume(gateway, name)) {
            let audience = audience
                .unwrap_or_else(|| panic!("volume {name} projects a token for the API server"));
            assert!(
                audience != issuer && !audience.starts_with("https://kubernetes.default.svc"),
                "volume {name} projects a token for the API server's audience {audience}"
            );
        }
    }
}

/// #153: `mounted` reads a block-style mount as well as a flow-style one, past blank lines and
/// comments, and panics on an item whose name does not come first, a bare `-` among them,
/// rather than leave it out.
#[test]
fn every_volume_mount_of_the_gateway_container_is_read_however_it_is_written() {
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let gateway_container = container(&gateway, "gateway");
    assert_eq!(
        mounted(&gateway_container),
        ["config", "registry", "cluster-ca", "entry-tokens"]
    );

    // The token writer's API token, mounted into the gateway container block style.
    let first = "          volumeMounts:\n";
    let block = "            - name: api-token\n              mountPath: /var/run/secrets/switchboard/api\n              readOnly: true\n";
    let with_block = gateway_container.replacen(first, &format!("{first}{block}"), 1);
    assert_ne!(with_block, gateway_container);
    assert_eq!(
        mounted(&with_block),
        [
            "api-token",
            "config",
            "registry",
            "cluster-ca",
            "entry-tokens"
        ]
    );
    // The guard that the gateway container mounts no API token sees it: the volume names no
    // audience, so its token is the API server's.
    no_api_token_mounted(&gateway, &gateway_container, KIND_ISSUER);
    let guarded =
        std::panic::catch_unwind(|| no_api_token_mounted(&gateway, &with_block, KIND_ISSUER));
    let message = guarded.expect_err("a block-style API token mount passed the guard");
    assert_eq!(
        message.downcast_ref::<String>().map(String::as_str),
        Some("volume api-token projects a token for the API server")
    );

    // An item whose name is not on its first line is not passed over.
    let unnamed_first = "            - mountPath: /var/run/secrets/switchboard/api\n              name: api-token\n";
    let with_unnamed = gateway_container.replacen(first, &format!("{first}{unnamed_first}"), 1);
    let read = std::panic::catch_unwind(|| mounted(&with_unnamed));
    assert!(read.is_err(), "{:?}", read);

    // The same mount after a blank line, or after a comment at column 0, is still in the list,
    // and the guard sees it.
    let last = "            - {name: entry-tokens, mountPath: /var/run/switchboard/tokens, readOnly: true}\n";
    for (form, added) in [
        ("after a blank line", format!("\n{block}")),
        (
            "after a comment at column 0",
            format!("# The API token.\n{block}"),
        ),
    ] {
        let changed = gateway.replacen(last, &format!("{last}{added}"), 1);
        assert_ne!(changed, gateway, "{form}");
        let container = container(&changed, "gateway");
        assert_eq!(
            mounted(&container),
            [
                "config",
                "registry",
                "cluster-ca",
                "entry-tokens",
                "api-token"
            ],
            "{form}"
        );
        let guarded =
            std::panic::catch_unwind(|| no_api_token_mounted(&changed, &container, KIND_ISSUER));
        let message = guarded.expect_err(form);
        assert_eq!(
            message.downcast_ref::<String>().map(String::as_str),
            Some("volume api-token projects a token for the API server"),
            "{form}"
        );
    }

    // A bare `-` with the name on the next line, first in the list or last, is an item whose
    // name does not come first: it panics, rather than being dropped or read as part of the
    // item before it.
    let bare = "            -\n              name: api-token\n              mountPath: /var/run/secrets/switchboard/api\n";
    let config =
        "            - {name: config, mountPath: /etc/switchboard/config, readOnly: true}\n";
    for (form, changed) in [
        (
            "first",
            gateway.replacen(config, &format!("{bare}{config}"), 1),
        ),
        ("last", gateway.replacen(last, &format!("{last}{bare}"), 1)),
    ] {
        assert_ne!(changed, gateway, "{form}");
        let container = container(&changed, "gateway");
        let read = std::panic::catch_unwind(|| mounted(&container));
        let message = read.expect_err(form);
        assert_eq!(
            message.downcast_ref::<String>().map(String::as_str),
            Some("an item without a name first: -"),
            "{form}"
        );
    }
}

/// #153, decision 0013 section 10: `token_audiences` reads a projected token source flow style
/// as well as block style, so the guards see a token for the API server however its source is
/// written, and panics on a source it cannot read rather than leave it out.
#[test]
fn every_token_source_of_a_volume_is_read_however_it_is_written() {
    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    assert_eq!(token_audiences(&volume(&gateway, "api-token")), [None]);
    assert_eq!(api_token_volumes(&gateway), ["api-token"]);

    // The token writer's API token, mounted into the gateway container too.
    let cluster_ca = "            - {name: cluster-ca, mountPath: /etc/switchboard/cluster-ca, readOnly: true}\n";
    let api_mount = "            - {name: api-token, mountPath: /var/run/secrets/switchboard/api, readOnly: true}\n";
    let mounting = gateway.replacen(cluster_ca, &format!("{cluster_ca}{api_mount}"), 1);
    assert_ne!(mounting, gateway);
    let block = "              - serviceAccountToken:\n                  expirationSeconds: 600\n                  path: token\n";
    assert!(mounting.contains(block));

    // Each flow-style form of its source, with no audience or with the API server's: the
    // pod-wide guard and the gateway container's guard both see it.
    let unset = "volume api-token projects a token for the API server";
    let issuer = format!("{unset}'s audience {KIND_ISSUER}");
    for (source, audience, message) in [
        (
            "              - serviceAccountToken: {expirationSeconds: 600, path: token}\n"
                .to_owned(),
            None,
            unset.to_owned(),
        ),
        (
            "              - {serviceAccountToken: {expirationSeconds: 600, path: token}}\n"
                .to_owned(),
            None,
            unset.to_owned(),
        ),
        (
            "              - serviceAccountToken: {}\n".to_owned(),
            None,
            unset.to_owned(),
        ),
        (
            format!(
                "              - serviceAccountToken: {{path: token, audience: {KIND_ISSUER}}}\n"
            ),
            Some(KIND_ISSUER),
            issuer.clone(),
        ),
        (
            format!(
                "              - {{serviceAccountToken: {{path: token, audience: \"{KIND_ISSUER}\"}}}}\n"
            ),
            Some(KIND_ISSUER),
            issuer.clone(),
        ),
        (
            format!(
                "              - serviceAccountToken:\n                  # The API server's.\n                  audience: '{KIND_ISSUER}' # quoted\n                  path: token\n"
            ),
            Some(KIND_ISSUER),
            issuer.clone(),
        ),
    ] {
        let changed = mounting.replacen(block, &source, 1);
        assert_ne!(changed, mounting, "{source}");
        assert_eq!(
            token_audiences(&volume(&changed, "api-token")),
            [audience.map(str::to_owned)],
            "{source}"
        );
        assert_eq!(api_token_volumes(&changed), ["api-token"], "{source}");
        let container = container(&changed, "gateway");
        let guarded =
            std::panic::catch_unwind(|| no_api_token_mounted(&changed, &container, KIND_ISSUER));
        let panicked = guarded.expect_err(&source);
        assert_eq!(
            panicked.downcast_ref::<String>(),
            Some(&message),
            "{source}"
        );
    }

    // A blank line among a block-style source's fields does not end them.
    let spaced = volume(&gateway, "api-token").replacen(
        "- serviceAccountToken:\n",
        &format!("- serviceAccountToken:\n\n                  audience: {KIND_ISSUER}\n"),
        1,
    );
    assert_eq!(token_audiences(&spaced), [Some(KIND_ISSUER.to_owned())]);

    // A flow-style source for another audience is read as that audience, and passes.
    let other = "              - {serviceAccountToken: {audience: switchboard, path: token}}\n";
    let changed = mounting.replacen(block, other, 1);
    assert_eq!(
        token_audiences(&volume(&changed, "api-token")),
        [Some("switchboard".to_owned())]
    );
    assert_eq!(api_token_volumes(&changed), Vec::<String>::new());
    no_api_token_mounted(&changed, &container(&changed, "gateway"), KIND_ISSUER);

    // A source it cannot read panics, rather than being passed over.
    for source in [
        "              - serviceAccountToken: {path: token,\n                  audience: x}\n",
        "              -\n                serviceAccountToken: {path: token}\n",
        "              - \"serviceAccountToken\": {path: token}\n",
        "              - serviceAccountToken: # no audience\n                  path: token\n",
        "              - serviceAccountToken:\n                  {path: token}\n",
        "              - serviceAccountToken:\n                  audience:\n                    x\n",
    ] {
        let changed = mounting.replacen(block, source, 1);
        assert_ne!(changed, mounting, "{source}");
        let api_token = volume(&changed, "api-token");
        let read = std::panic::catch_unwind(|| token_audiences(&api_token));
        assert!(read.is_err(), "{source}: {read:?}");
    }
}

/// The pod's volume `name`: its `- name:` line and those under it.
fn volume(deployment: &str, name: &str) -> String {
    let volumes = block_after(deployment, "      volumes:");
    let header = format!("        - name: {name}");
    let mut lines = volumes.lines().skip_while(|line| *line != header);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("no volume `{name}`:\n{volumes}"));
    let rest = lines.take_while(|line| line.starts_with("          "));
    std::iter::once(first)
        .chain(rest)
        .collect::<Vec<_>>()
        .join("\n")
}

/// #88, decision 0013 section 10: in kind the gateway fetches the cluster issuer's keys from the
/// API server's own origin, over TLS with only the cluster CA trusted, and with no token. Its
/// container mounts kube-root-ca.crt and no token the API server accepts, and its deployment
/// file names no keys file and no token file.
#[test]
fn the_kind_gateway_fetches_the_clusters_keys_with_no_token() {
    let config = read("deploy/kind/base/config/gateway.toml");
    let issuer = value_after(&config, "issuer = ");
    assert_eq!(issuer, "https://kubernetes.default.svc.cluster.local");
    assert_eq!(
        value_after(&config, "keys_url = "),
        format!("{issuer}/openid/v1/jwks")
    );
    let ca_file = value_after(&config, "keys_ca_file = ");
    for field in ["keys_file", "keys_token_file"] {
        assert!(
            !config
                .lines()
                .any(|line| line.trim_start().starts_with(field)),
            "the kind gateway sets {field}:\n{config}"
        );
    }
    let refresh = number_after(&config, "keys_refresh_seconds = ", "");
    assert!((30..=300).contains(&refresh), "{refresh}");

    let gateway = only_deployment("deploy/kind/base/gateway.yaml");
    let container = container(&gateway, "gateway");
    let (ca_dir, ca_name) = ca_file.rsplit_once('/').unwrap();
    assert_eq!(ca_name, "ca.crt");
    assert!(
        container.contains(&format!(
            "            - {{name: cluster-ca, mountPath: {ca_dir}, readOnly: true}}\n"
        )),
        "{container}"
    );
    assert_eq!(
        volume(&gateway, "cluster-ca"),
        "        - name: cluster-ca\n          configMap: {name: kube-root-ca.crt}"
    );

    let mounts = mounted(&container);
    assert!(mounts.contains(&"cluster-ca".to_owned()), "{mounts:?}");
    no_api_token_mounted(&gateway, &container, issuer);
    assert!(
        !container.contains("/var/run/secrets/kubernetes.io/serviceaccount"),
        "{container}"
    );
    assert!(!gateway.contains("automountServiceAccountToken: true"));
    let accounts = read("deploy/kind/base/serviceaccounts.yaml");
    let account = documents_with(&accounts, "  name: gateway\n");
    assert_eq!(account.len(), 1);
    assert!(account[0].contains("\nautomountServiceAccountToken: false"));

    // The cluster-issuer-keys copy is mock-docs' alone.
    assert!(!gateway.contains("cluster-issuer-keys"), "{gateway}");
    assert!(!gateway.contains("/etc/switchboard/issuer"), "{gateway}");
}

/// Decision 0013 section 10: the only RBAC the kind base adds for the keys is one binding of the
/// existing ClusterRole system:service-account-issuer-discovery to system:unauthenticated, and
/// nothing else binds either.
#[test]
fn the_kind_issuer_discovery_binding_names_only_that_role_and_group() {
    let text = read("deploy/kind/base/issuer-discovery.yaml");
    let body: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
    assert_eq!(
        body,
        [
            "apiVersion: rbac.authorization.k8s.io/v1",
            "kind: ClusterRoleBinding",
            "metadata:",
            "  name: switchboard-issuer-discovery-unauthenticated",
            "roleRef:",
            "  apiGroup: rbac.authorization.k8s.io",
            "  kind: ClusterRole",
            "  name: system:service-account-issuer-discovery",
            "subjects:",
            "  - apiGroup: rbac.authorization.k8s.io",
            "    kind: Group",
            "    name: system:unauthenticated",
        ]
    );
    let kustomization = read("deploy/kind/base/kustomization.yaml");
    assert!(
        kustomization.contains("\n  - issuer-discovery.yaml\n"),
        "{kustomization}"
    );

    // No other manifest under deploy/kind binds that ClusterRole or that group, or defines a
    // role of that name.
    let mut others = Vec::new();
    let mut directories = vec![common::repo().join("deploy/kind")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|ext| ext == "yaml")
                && !path.ends_with("base/issuer-discovery.yaml")
            {
                let text = std::fs::read_to_string(&path).unwrap();
                let uncommented: String = text
                    .lines()
                    .filter(|line| !line.trim_start().starts_with('#'))
                    .collect();
                if uncommented.contains("system:service-account-issuer-discovery")
                    || uncommented.contains("system:unauthenticated")
                {
                    others.push(path);
                }
            }
        }
    }
    assert!(others.is_empty(), "{others:?}");
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

/// Each team's workload calls its own surface, which serves only its own entry's tools, in kind
/// and in Compose.
#[test]
fn each_teams_workload_calls_its_own_surface() {
    let workloads = read("deploy/kind/base/workloads.yaml");
    for (team, account) in [
        ("team-a", "mock-workload"),
        ("team-b", "mock-workload"),
        ("team-a", "stranger"),
    ] {
        let cronjob = documents_with(&workloads, &format!("  namespace: {team}\n"))
            .into_iter()
            .filter(|doc| doc.contains(&format!("          serviceAccountName: {account}\n")))
            .collect::<Vec<_>>();
        assert_eq!(cronjob.len(), 1, "{team} {account}");
        assert!(
            cronjob[0].contains(&format!(
                "                - {{name: GATEWAY_URL, value: \"http://gateway.switchboard.svc.cluster.local:8080/mcp/docs-{team}\"}}\n"
            )),
            "{team}'s {account} does not call its own surface:\n{}",
            cronjob[0]
        );
    }
    // In Compose, demo.sh names the surface on every run of the workload service.
    let driver = read("deploy/demo/demo.sh");
    assert!(
        driver.contains(
            "      -e \"GATEWAY_URL=http://gateway:8080/mcp/$(team_entry \"$team\")\" \\\n"
        )
    );
    let run = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!(
            ". '{}' && team_entry team-a && team_entry team-b",
            common::repo().join("deploy/demo/demo.sh").display()
        ))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "docs-team-a\ndocs-team-b\n"
    );
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
/// may take, with its row: the begin budget, the call deadline, and the finish deadline with one
/// answer budget more, for the last attempt to complete a failed begin's row. The call deadline
/// is the longest the deployment file at `path` sets for any server, or the default (decision
/// 0014, section 1); the budgets are not configurable, so each is the code's default.
fn begin_call_and_finish(path: &str) -> Duration {
    let file: DeploymentFile =
        toml::from_str(&read(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
    let budgets = audit_postgres::Budgets::default();
    budgets.begin + file.longest_deadline() + budgets.shutdown_wait()
}

#[test]
fn the_longest_deadline_is_the_longest_any_server_sets_or_the_default() {
    let longest = |text: &str| {
        toml::from_str::<DeploymentFile>(&format!(
            "{}{text}",
            read("deploy/kind/base/config/gateway.toml")
        ))
        .unwrap()
        .longest_deadline()
    };
    assert_eq!(longest(""), connector_proxy::DEFAULT_DEADLINE);
    assert_eq!(
        longest("\n[servers.a]\ndeadline_seconds = 2\n"),
        connector_proxy::DEFAULT_DEADLINE
    );
    assert_eq!(
        longest("\n[servers.a]\ndeadline_seconds = 2\n\n[servers.b]\ndeadline_seconds = 60\n"),
        Duration::from_secs(60)
    );
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
    // No call starts once the gateway stops taking connections, so the last starts within the
    // readiness removal. After the removal the gateway waits up to its shutdown grace for the
    // connections still open, and for the calls running however long they take: 8 + 2 + D +
    // 30 + 2 seconds, where D is the longest call deadline the deployment file sets.
    let needed = READINESS_REMOVAL
        + begin_call_and_finish("deploy/kind/base/config/gateway.toml").max(SHUTDOWN_GRACE);
    assert!(
        Duration::from_secs(grace) > needed,
        "kind: a grace period of {grace} s is not longer than {needed:?}"
    );

    // Compose has no readiness probe, but the gateway waits out its readiness removal all the
    // same.
    let compose = read("deploy/compose/compose.yaml");
    let service = compose_service(&compose, "gateway");
    let grace = number_after(&service, "    stop_grace_period: ", "s");
    let needed = READINESS_REMOVAL
        + begin_call_and_finish("deploy/compose/config/gateway.toml").max(SHUTDOWN_GRACE);
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

/// The identifiers in the reach of the server `entry` in `registry`, each a `docs` project.
/// The reach must be written on one `reach = [...]` line.
fn entry_reach(registry: &str, entry: &str) -> Vec<String> {
    let start = registry
        .find(&format!("[[servers]]\nname = \"{entry}\"\n"))
        .unwrap_or_else(|| panic!("no server `{entry}`"));
    let line = registry[start..]
        .lines()
        .find_map(|line| line.strip_prefix("reach = "))
        .expect("a reach line");
    let prefix = "{ system = \"docs\", kind = \"project\", identifier = \"";
    let identifiers: Vec<String> = line
        .split(prefix)
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        line.matches("identifier").count(),
        identifiers.len(),
        "{line}"
    );
    identifiers
}

/// The registry without its leading comment lines.
fn registry_body(path: &str) -> String {
    read(path)
        .lines()
        .skip_while(|line| line.starts_with('#') || line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each `binding_sha256` the tools in `registry` record, in the order of the tools: one for each
/// of its servers, the same on each of that server's tools.
fn bindings(registry: &str) -> Vec<String> {
    let mut bindings: Vec<String> = Vec::new();
    for binding in registry
        .lines()
        .filter_map(|line| line.strip_prefix("binding_sha256 = "))
    {
        if !bindings.iter().any(|seen| seen == binding) {
            bindings.push(binding.to_owned());
        }
    }
    assert_eq!(
        bindings.len(),
        registry.matches("\n[[servers]]\n").count(),
        "{bindings:?}"
    );
    bindings
}

#[test]
fn the_compose_and_kind_registries_differ_only_in_issuer_identity_address_and_binding() {
    let kind = registry_body("deploy/kind/base/config/registry/registry.toml");
    let compose = registry_body("deploy/compose/config/registry/registry.toml");
    let kind_issuer = "issuer = \"https://kubernetes.default.svc.cluster.local\"";
    let kind_identity = "identity = \"mock-docs.mock-docs.svc.cluster.local\"";
    let kind_address = "address = \"http://mock-docs.mock-docs.svc.cluster.local:8080/mcp\"";
    // The reach check's surface admits one principal, the registry's own workload identity,
    // which is the issuer's and its subject.
    let kind_reach = "principals = { only = [{ issuer = \"https://kubernetes.default.svc.cluster.local\", subject = \"system:serviceaccount:switchboard:registry\" }] }";
    let compose_reach = "principals = { only = [{ issuer = \"https://dev-issuer.switchboard.test\", subject = \"workload:registry:reach-check\" }] }";
    assert_eq!(kind.matches(kind_reach).count(), 1);
    assert_eq!(compose.matches(compose_reach).count(), 1);
    // The profile rule names the issuer once more.
    assert_eq!(kind.replace(kind_reach, "").matches(kind_issuer).count(), 1);
    // The mock server is registered once per team, both entries at the one address.
    for line in [kind_identity, kind_address] {
        assert_eq!(kind.matches(line).count(), 2, "{line}");
    }
    // Each binding differs because the identity and address do; the loader checks each file's.
    let mut as_compose = kind
        .replace(kind_reach, compose_reach)
        .replace(
            kind_issuer,
            "issuer = \"https://dev-issuer.switchboard.test\"",
        )
        .replace(kind_identity, "identity = \"mock-docs\"")
        .replace(kind_address, "address = \"http://mock-docs:8080/mcp\"");
    for (kind_binding, compose_binding) in bindings(&kind).iter().zip(bindings(&compose)) {
        as_compose = as_compose.replace(kind_binding, &compose_binding);
    }
    assert_eq!(as_compose, compose);
    // The kind registry is the registry crate's own demo file.
    assert_eq!(
        kind,
        registry_body("crates/gateway-registry/demo/registry.toml")
    );

    // The withdrawn copy is the Compose registry less each team's read tool, at a new
    // revision.
    let withdrawn = registry_body("deploy/compose/config/registry-withdrawn.toml");
    assert!(compose.contains("revision = \"demo-10\""));
    assert!(withdrawn.contains("revision = \"demo-11\""));
    for entry in ["docs-team-a", "docs-team-b"] {
        assert!(!withdrawn.contains(&format!("name = \"{entry}__read_document\"")));
        assert!(withdrawn.contains(&format!("tools = [\"{entry}__list_documents\"]\n")));
    }
    assert_eq!(
        compose.lines().count() - withdrawn.lines().count(),
        2 * 23,
        "the withdrawn copy differs by more than the read tools"
    );
    // demo.sh names the same revisions.
    let driver = read("deploy/demo/demo.sh");
    assert!(driver.contains("\nREVISION=demo-10\nWITHDRAWN_REVISION=demo-11\n"));
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

/// Decision 0011, section 4: the reach check is a gateway call by the registry's own workload
/// identity, admitted only to a surface restricted to that one subject. In each registry the
/// registry-reach surface serves each entry's reach check's tool, and nothing else, to team
/// registry and, of it, that one principal; no other surface admits team registry; the team
/// manifest maps that subject, and no other, to team registry; and the deployment file's reach
/// check calls the gateway's own listener on that surface, with a Host it serves.
#[test]
fn the_registry_reach_surface_admits_only_the_registrys_own_principal() {
    use std::collections::BTreeSet;

    for (dir, issuer, subject) in [
        (
            "deploy/compose/config",
            "https://dev-issuer.switchboard.test",
            "workload:registry:reach-check",
        ),
        (
            "deploy/kind/base/config",
            KIND_ISSUER,
            "system:serviceaccount:switchboard:registry",
        ),
    ] {
        let registry = gateway_registry::Registry::from_toml_str(&read(&format!(
            "{dir}/registry/registry.toml"
        )))
        .unwrap();
        let snapshot = registry.snapshot();
        let reach = snapshot.surface(&"registry-reach".into()).unwrap();
        assert_eq!(
            serde_json::to_value(&reach.principals).unwrap(),
            serde_json::json!({"only": [{"issuer": issuer, "subject": subject}]}),
            "{dir}"
        );
        assert_eq!(
            reach.teams,
            ["registry".into()].into_iter().collect(),
            "{dir}"
        );
        assert!(reach.groups.is_empty(), "{dir}");
        let checked: BTreeSet<_> = registry
            .servers()
            .values()
            .map(|server| server.reach_check.clone().unwrap().tool)
            .collect();
        assert_eq!(reach.tools, checked, "{dir}");
        for surface in snapshot.surfaces() {
            if surface.name != reach.name {
                assert!(
                    !surface.teams.contains(&"registry".into()),
                    "{dir}: {}",
                    surface.name
                );
            }
        }

        let manifest: toml::Table = toml::from_str(&read(&format!("{dir}/teams.toml"))).unwrap();
        let in_registry: Vec<&String> = manifest["subjects"]
            .as_table()
            .unwrap()
            .iter()
            .filter(|(_, team)| team.as_str() == Some("registry"))
            .map(|(subject, _)| subject)
            .collect();
        assert_eq!(in_registry, [subject], "{dir}");

        let file: DeploymentFile = toml::from_str(&read(&format!("{dir}/gateway.toml"))).unwrap();
        let drift = file.drift.unwrap();
        assert_eq!(
            drift.reach_url,
            Some(format!(
                "http://127.0.0.1:{}/mcp/registry-reach",
                file.listen.port()
            )),
            "{dir}"
        );
        assert!(
            file.http
                .allowed_hosts
                .contains(drift.reach_host.as_deref().unwrap()),
            "{dir}"
        );
    }
}

/// In Compose the registry's workload token comes from the dev issuer, which signs for its
/// subject, into a volume only the reach-token service writes and the gateway reads, read-only.
/// It is not in the image or a secret, and no other service mounts it.
#[test]
fn compose_writes_the_registrys_token_where_only_the_gateway_reads_it() {
    let compose = read("deploy/compose/compose.yaml");
    assert!(
        compose_service(&compose, "dev-issuer")
            .contains("      - --subject=workload:registry:reach-check\n")
    );
    let writer = compose_service(&compose, "reach-token");
    assert!(writer.contains(
        "'http://dev-issuer:8090/token?subject=workload:registry:reach-check&audience=switchboard'"
    ));
    assert!(
        writer.contains("      - reach-token:/shared/reach\n"),
        "{writer}"
    );
    let gateway = compose_service(&compose, "gateway");
    assert!(
        gateway.contains("      - reach-token:/shared/reach:ro\n"),
        "{gateway}"
    );
    assert!(gateway.contains("      reach-token:\n        condition: service_healthy\n"));
    for service in ["postgres", "migrate", "dev-issuer", "mock-docs", "workload"] {
        assert!(
            !compose_service(&compose, service).contains("reach-token"),
            "{service}"
        );
    }
    let config = read("deploy/compose/config/gateway.toml");
    assert!(config.contains("\nreach_token_file = \"/shared/reach/registry\"\n"));
}
