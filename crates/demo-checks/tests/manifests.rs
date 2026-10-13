//! The Compose file and the kind manifests hold to what the demo claims. Most checks read them
//! as text and name the exact lines they rely on, so a change to them has to change the test
//! too, on purpose. The token guards read the kind manifests with a YAML parser instead, as the
//! API server does, since no list of lines can name every way to write a token into a pod.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::read;
use gateway::deployment::DeploymentFile;
use gateway::{READINESS_REMOVAL, SHUTDOWN_GRACE};
use sha2::{Digest, Sha256};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};
use yaml_rust2::{Yaml, YamlLoader, yaml::Hash};

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

// The token guards' reader (#182). The guards that keep a token the API server accepts out of
// the gateway container and the teams' workloads (decision 0013, section 10) read the manifests
// with a YAML parser and walk the parsed pods, so aliases, anchors, tags, quoting, escapes,
// blank lines and comments are the parser's to read. Where a field has a shape they do not
// expect, they panic rather than read it as absent, and so they do on a tag or a merge key the
// parser would read otherwise than the API server does ([`ReadAsTheApiServer`]).

/// The documents of a manifest, parsed, with each merge key (`<<`) applied as the API server's
/// YAML reader applies it. The parser resolves aliases but leaves merge keys to this. It panics
/// on a manifest [`ReadAsTheApiServer`] refuses.
fn manifest(text: &str) -> Vec<Yaml> {
    Parser::new_from_str(text)
        .load(&mut ReadAsTheApiServer, true)
        .unwrap_or_else(|error| panic!("a manifest the parser cannot read: {error}"));
    YamlLoader::load_from_str(text)
        .unwrap_or_else(|error| panic!("a manifest the parser cannot read: {error}"))
        .into_iter()
        .map(merged)
        .collect()
}

/// `node` with each merge key applied: a mapping gets each key of the mappings it merges that it
/// does not set itself, from the first of them that sets it.
fn merged(node: Yaml) -> Yaml {
    match node {
        Yaml::Array(items) => Yaml::Array(items.into_iter().map(merged).collect()),
        Yaml::Hash(entries) => {
            let mut own = Hash::new();
            let mut merges = Vec::new();
            for (key, value) in entries {
                if key.as_str() == Some("<<") {
                    match merged(value) {
                        Yaml::Array(mappings) => merges.extend(mappings),
                        mapping => merges.push(mapping),
                    }
                } else {
                    own.insert(merged(key), merged(value));
                }
            }
            for mapping in merges {
                let Yaml::Hash(mapping) = mapping else {
                    panic!("a merge key whose value is not a mapping: {mapping:?}");
                };
                for (key, value) in mapping {
                    if !own.contains_key(&key) {
                        own.insert(key, value);
                    }
                }
            }
            Yaml::Hash(own)
        }
        scalar => scalar,
    }
}

/// Refuses, from the parser's events, the YAML its loader keeps less of than the API server's
/// reader reads, so that [`manifest`] fails rather than read a field otherwise:
///
/// - A tag other than the core schema's `str`, `map`, `seq`, `bool`, `int`, `float` and `null`,
///   however it is spelled. The loader keeps a `!!binary` scalar's base64 text, where the API
///   server decodes it, so a `!!binary` key could hide a `serviceAccountToken` source and a
///   `!!binary` audience the API server's own; and it reads a scalar with a local or verbatim
///   tag as a string.
/// - A `<<` that is quoted or tagged, other than `!!merge <<`. The loader keeps no scalar's style,
///   so it reads `'<<'`, `"<<"` and `!!str <<` as the plain merge key, where the API server reads
///   an ordinary key (and kustomize drops it).
struct ReadAsTheApiServer;

/// The core schema's tags, which the loader reads as the API server does.
const CORE_TAGS: [&str; 7] = ["str", "map", "seq", "bool", "int", "float", "null"];

/// The name of a tag in the YAML tag namespace (`!!name`), or None for any other tag.
fn yaml_tag(tag: &Tag) -> Option<&str> {
    (tag.handle == "tag:yaml.org,2002:").then_some(tag.suffix.as_str())
}

impl MarkedEventReceiver for ReadAsTheApiServer {
    fn on_event(&mut self, event: Event, mark: Marker) {
        let at = format!("line {}, column {}", mark.line(), mark.col());
        let tag = match &event {
            Event::Scalar(value, style, _, tag) if value == "<<" => {
                assert!(
                    *style == TScalarStyle::Plain
                        && tag
                            .as_ref()
                            .is_none_or(|tag| yaml_tag(tag) == Some("merge")),
                    "a `<<` that is quoted or tagged, at {at}: the API server reads it as an \
                     ordinary key, not a merge key"
                );
                return;
            }
            Event::Scalar(_, _, _, tag)
            | Event::SequenceStart(_, tag)
            | Event::MappingStart(_, tag) => tag,
            _ => return,
        };
        if let Some(tag) = tag {
            assert!(
                yaml_tag(tag).is_some_and(|name| CORE_TAGS.contains(&name)),
                "a tag the parser does not read as the API server does, at {at}: {}{}",
                tag.handle,
                tag.suffix
            );
        }
    }
}

/// The one YAML value in `text`, to compare a part of a manifest with what it must be.
fn yaml(text: &str) -> Yaml {
    let mut documents = manifest(text);
    assert_eq!(documents.len(), 1, "{text}");
    documents.remove(0)
}

/// `node` as a mapping, or None if it is absent or null. It panics on anything else.
fn mapping<'a>(node: &'a Yaml, what: &str) -> Option<&'a Hash> {
    match node {
        Yaml::Hash(entries) => Some(entries),
        Yaml::BadValue | Yaml::Null => None,
        other => panic!("{what} that is not a mapping: {other:?}"),
    }
}

/// The items of the list `node`, none if it is absent or null. It panics on anything else.
fn list<'a>(node: &'a Yaml, what: &str) -> &'a [Yaml] {
    match node {
        Yaml::Array(items) => items,
        Yaml::BadValue | Yaml::Null => &[],
        other => panic!("{what} that is not a list: {other:?}"),
    }
}

/// The string `node`, which must be one.
fn string<'a>(node: &'a Yaml, what: &str) -> &'a str {
    node.as_str()
        .unwrap_or_else(|| panic!("{what} that is not a string: {node:?}"))
}

/// The kind, namespace and name of a manifest's document.
fn label(document: &Yaml) -> String {
    let metadata = &document["metadata"];
    format!(
        "{} {}/{}",
        document["kind"].as_str().unwrap_or("?"),
        metadata["namespace"].as_str().unwrap_or(""),
        metadata["name"].as_str().unwrap_or("?")
    )
}

/// Every pod spec in a manifest's documents, each with its document: each mapping, at any depth,
/// that has `containers` or `initContainers`. So a Pod's spec, the template of a Deployment, a
/// Job or any other controller, and a CronJob's job template are all read, and so is the pod of
/// a kind these tests do not name.
fn pod_specs(documents: &[Yaml]) -> Vec<(&Yaml, &Yaml)> {
    fn find<'a>(node: &'a Yaml, found: &mut Vec<&'a Yaml>) {
        match node {
            Yaml::Hash(entries) => {
                if ["containers", "initContainers"]
                    .iter()
                    .any(|key| !node[*key].is_badvalue())
                {
                    found.push(node);
                } else {
                    entries.values().for_each(|value| find(value, found));
                }
            }
            Yaml::Array(items) => items.iter().for_each(|item| find(item, found)),
            _ => {}
        }
    }
    let mut pods = Vec::new();
    for document in documents {
        let mut found = Vec::new();
        find(document, &mut found);
        pods.extend(found.into_iter().map(|pod| (document, pod)));
    }
    pods
}

/// The one pod spec in the manifest `text`.
fn only_pod(text: &str) -> Yaml {
    let documents = manifest(text);
    let pods = pod_specs(&documents);
    let labels: Vec<String> = pods.iter().map(|(document, _)| label(document)).collect();
    assert_eq!(pods.len(), 1, "want one pod: {labels:?}");
    pods[0].1.clone()
}

/// The lists of a pod spec's containers, init containers first.
const CONTAINER_LISTS: [&str; 3] = ["initContainers", "containers", "ephemeralContainers"];

/// A pod spec's containers of every kind, in the order of [`CONTAINER_LISTS`].
fn pod_containers(pod: &Yaml) -> Vec<&Yaml> {
    CONTAINER_LISTS
        .iter()
        .flat_map(|key| list(&pod[*key], key))
        .collect()
}

/// A pod spec's containers, each by name with the name of each volume it mounts.
fn containers(pod: &Yaml) -> Vec<(String, Vec<String>)> {
    pod_containers(pod)
        .into_iter()
        .map(|container| {
            let mounts = list(&container["volumeMounts"], "volumeMounts")
                .iter()
                .map(|mount| string(&mount["name"], "a volume mount's name").to_owned())
                .collect();
            let name = string(&container["name"], "a container's name");
            (name.to_owned(), mounts)
        })
        .collect()
}

/// The container `name` of a pod spec.
fn container<'a>(pod: &'a Yaml, name: &str) -> &'a Yaml {
    let found: Vec<&Yaml> = pod_containers(pod)
        .into_iter()
        .filter(|container| container["name"].as_str() == Some(name))
        .collect();
    assert_eq!(found.len(), 1, "want one container `{name}`");
    found[0]
}

/// The volume mounts of `container` that mount the volume `name`.
fn mounts_of<'a>(container: &'a Yaml, name: &str) -> Vec<&'a Yaml> {
    list(&container["volumeMounts"], "volumeMounts")
        .iter()
        .filter(|mount| mount["name"].as_str() == Some(name))
        .collect()
}

/// The volume `name` of a pod spec.
fn volume<'a>(pod: &'a Yaml, name: &str) -> &'a Yaml {
    let found: Vec<&Yaml> = list(&pod["volumes"], "volumes")
        .iter()
        .filter(|volume| volume["name"].as_str() == Some(name))
        .collect();
    assert_eq!(found.len(), 1, "want one volume `{name}`");
    found[0]
}

/// A pod spec's volumes, each by name with the audience of each ServiceAccount token it projects.
fn volumes(pod: &Yaml) -> Vec<(String, Vec<Option<String>>)> {
    list(&pod["volumes"], "volumes")
        .iter()
        .map(|volume| {
            let name = string(&volume["name"], "a volume's name");
            (name.to_owned(), token_audiences(volume))
        })
        .collect()
}

/// The audience of each ServiceAccount token source of `volume`, None for one that names none,
/// or an empty or null one: the API server gives such a token its own audience. A source whose
/// `serviceAccountToken` is null counts as one with no audience.
fn token_audiences(volume: &Yaml) -> Vec<Option<String>> {
    mapping(&volume["projected"], "a projected volume");
    list(&volume["projected"]["sources"], "a projection's sources")
        .iter()
        .filter_map(|source| {
            let source = mapping(source, "a projected source")?;
            let token = source.get(&Yaml::String("serviceAccountToken".to_owned()))?;
            Some(audience(token))
        })
        .collect()
}

/// The audience a projected token source names, None if it names none, or an empty or null one.
/// The parser reads only `~`, `null` and an empty value as null, where the API server's reader
/// reads `Null` and `NULL` as null too, so those are taken for null whether quoted or not.
fn audience(token: &Yaml) -> Option<String> {
    mapping(token, "a serviceAccountToken");
    match &token["audience"] {
        Yaml::BadValue | Yaml::Null => None,
        Yaml::String(audience) if ["", "Null", "NULL"].contains(&audience.as_str()) => None,
        Yaml::String(audience) => Some(audience.clone()),
        other => panic!("an audience that is not a string: {other:?}"),
    }
}

/// The audiences the kind cluster's API server accepts: its issuer's, which a projected token
/// gets when it names none.
fn api_audience(audience: Option<&str>) -> bool {
    audience.is_none_or(|audience| audience == KIND_ISSUER)
}

const KIND_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

/// The volumes of a pod spec, by name, that hold a token the API server accepts.
fn api_token_volumes(pod: &Yaml) -> Vec<String> {
    volumes(pod)
        .into_iter()
        .filter(|(_, audiences)| {
            audiences
                .iter()
                .any(|audience| api_audience(audience.as_deref()))
        })
        .map(|(name, _)| name)
        .collect()
}

/// Whether a pod spec turns on the default API token for its containers: it sets
/// `automountServiceAccountToken`, and not to null or false. A YAML 1.1 `yes` or `on`, which the
/// API server reads as true, turns it on too, and so does a value the parser cannot read, which it
/// gives as no value: `!!bool yes` or `!!bool on`, which the API server reads as true, and also
/// `!!bool no`, which fails this guard though the API server reads it as false.
fn turns_on_the_default_token(pod: &Yaml) -> bool {
    let set = mapping(pod, "a pod spec")
        .and_then(|pod| pod.get(&Yaml::String("automountServiceAccountToken".to_owned())));
    !matches!(set, None | Some(Yaml::Null | Yaml::Boolean(false)))
}

/// The ServiceAccount `name` in `namespace` turns off the default API token.
fn account_turns_off_the_default_token(namespace: &str, name: &str) {
    let accounts = manifest(&read("deploy/kind/base/serviceaccounts.yaml"));
    let account: Vec<&Yaml> = accounts
        .iter()
        .filter(|document| label(document) == format!("ServiceAccount {namespace}/{name}"))
        .collect();
    assert_eq!(account.len(), 1, "ServiceAccount {namespace}/{name}");
    assert_eq!(
        account[0]["automountServiceAccountToken"],
        Yaml::Boolean(false),
        "ServiceAccount {namespace}/{name} mounts the default API token"
    );
}

/// Decision 0013, section 10, in the gateway's pod: only the token writer mounts a token the API
/// server accepts, a projected one with no audience or the API server's, and the gateway
/// container mounts no ServiceAccount token at all. No container gets the default API token.
fn only_the_token_writer_holds_an_api_token(pod: &Yaml) {
    let api_volumes = api_token_volumes(pod);
    assert_eq!(
        api_volumes,
        ["api-token"],
        "the volumes that hold a token the API server accepts"
    );
    let containers = containers(pod);
    let with_api_token: Vec<&str> = containers
        .iter()
        .filter(|(_, mounts)| mounts.iter().any(|mount| api_volumes.contains(mount)))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        with_api_token,
        ["token-writer"],
        "the containers that mount a token the API server accepts"
    );

    // The gateway container mounts no projected ServiceAccount token, of any audience.
    let token_volumes: Vec<String> = volumes(pod)
        .into_iter()
        .filter(|(_, audiences)| !audiences.is_empty())
        .map(|(name, _)| name)
        .collect();
    let mounts: Vec<&String> = containers
        .iter()
        .filter(|(name, _)| name == "gateway")
        .flat_map(|(_, mounts)| mounts)
        .collect();
    assert!(!mounts.is_empty(), "the gateway container mounts nothing");
    assert!(
        !mounts.iter().any(|mount| token_volumes.contains(mount)),
        "the gateway container mounts a ServiceAccount token: {mounts:?}"
    );

    assert!(
        !turns_on_the_default_token(pod),
        "the gateway's pod turns on the default API token"
    );
}

/// No volume the container `name` of the gateway's pod mounts projects a token the API server
/// accepts: each projected token names an audience, and not the API server's, which in kind is
/// the issuer.
fn no_api_token_mounted(pod: &Yaml, name: &str, issuer: &str) {
    let (_, mounts) = containers(pod)
        .into_iter()
        .find(|(container, _)| container == name)
        .unwrap_or_else(|| panic!("no container `{name}`"));
    let volumes = volumes(pod);
    for mounted in &mounts {
        for (volume, audiences) in volumes.iter().filter(|(volume, _)| volume == mounted) {
            for audience in audiences {
                let audience = audience.as_deref().unwrap_or_else(|| {
                    panic!("volume {volume} projects a token for the API server")
                });
                assert!(
                    audience != issuer && !audience.starts_with("https://kubernetes.default.svc"),
                    "volume {volume} projects a token for the API server's audience {audience}"
                );
            }
        }
    }
}

/// Decision 0013, section 10, for a team's workload: no volume of its pod holds a token the API
/// server accepts, and the pod does not turn the default API token on.
fn no_api_token_in_workload(document: &Yaml, pod: &Yaml) {
    let label = label(document);
    assert_eq!(
        api_token_volumes(pod),
        Vec::<String>::new(),
        "{label}: the volumes that hold a token the API server accepts"
    );
    assert!(
        !turns_on_the_default_token(pod),
        "{label} turns on the default API token"
    );
}

/// Decision 0013, section 10: in the gateway pod only the token writer mounts a token the API
/// server accepts, and the gateway container mounts no ServiceAccount token at all. No container
/// gets the default API token.
#[test]
fn only_the_token_writer_mounts_an_api_token_in_the_gateway_pod() {
    let pod = only_pod(&read("deploy/kind/base/gateway.yaml"));
    let names: Vec<String> = containers(&pod).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["wait-for-audit-schema", "token-writer", "gateway"]);
    only_the_token_writer_holds_an_api_token(&pod);
    no_api_token_mounted(&pod, "gateway", KIND_ISSUER);

    // The token writer's API token is short-lived, and comes with the cluster's CA.
    assert_eq!(
        *volume(&pod, "api-token"),
        yaml(
            "name: api-token
projected:
  sources:
    - serviceAccountToken: {expirationSeconds: 600, path: token}
    - configMap: {name: kube-root-ca.crt, items: [{key: ca.crt, path: ca.crt}]}"
        )
    );
    account_turns_off_the_default_token("switchboard", "gateway");
}

/// Decision 0013, section 10: no workload mounts a token the API server accepts, neither the
/// default API token nor a projected one.
#[test]
fn no_workload_mounts_an_api_token() {
    let documents = manifest(&read("deploy/kind/base/workloads.yaml"));
    let pods = pod_specs(&documents);
    let labels: Vec<String> = pods.iter().map(|(document, _)| label(document)).collect();
    assert_eq!(
        labels,
        [
            "CronJob team-a/mock-workload",
            "CronJob team-b/mock-workload",
            "CronJob team-a/stranger-workload",
        ]
    );
    for (document, pod) in pods {
        no_api_token_in_workload(document, pod);
        let namespace = string(&document["metadata"]["namespace"], "a namespace");
        let account = string(&pod["serviceAccountName"], "a serviceAccountName");
        account_turns_off_the_default_token(namespace, account);
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
    for account in ["docs-team-a", "docs-team-b", "registry-probe", "registry"] {
        account_turns_off_the_default_token("switchboard", account);
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
    let pod = only_pod(&gateway);
    // The gateway reads the tokens; only the token writer writes them.
    assert_eq!(
        mounts_of(container(&pod, "gateway"), "entry-tokens"),
        [&yaml(
            "{name: entry-tokens, mountPath: /var/run/switchboard/tokens, readOnly: true}"
        )]
    );
    let writer = container(&pod, "token-writer");
    assert_eq!(writer["restartPolicy"].as_str(), Some("Always"));
    assert_eq!(
        mounts_of(writer, "entry-tokens"),
        [&yaml(
            "{name: entry-tokens, mountPath: /var/run/switchboard/tokens}"
        )]
    );
    // The gateway starts only once the four tokens are written: it reads every credential,
    // the probe's included, at boot, and the reach check presents the registry's at once.
    assert_eq!(
        writer["startupProbe"]["exec"]["command"],
        yaml(
            "[sh, -c, test -s /var/run/switchboard/tokens/docs-team-a && test -s /var/run/switchboard/tokens/docs-team-b && test -s /var/run/switchboard/tokens/registry-probe && test -s /var/run/switchboard/tokens/registry]"
        )
    );
    assert_eq!(
        *volume(&pod, "entry-tokens"),
        yaml("{name: entry-tokens, emptyDir: {medium: Memory, sizeLimit: 1Mi}}")
    );
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
        let values: Vec<&str> = list(&writer["env"], "env")
            .iter()
            .filter(|variable| variable["name"].as_str() == Some(name))
            .map(|variable| string(&variable["value"], name))
            .collect();
        assert_eq!(values.len(), 1, "want one {name}");
        values[0].to_owned()
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

/// The message of the panic `run` ends in. It must panic: `form` passed a guard it must fail.
fn panic_message(form: &str, run: impl FnOnce()) -> String {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
        .err()
        .unwrap_or_else(|| panic!("{form}: passed the guard"));
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_default()
}

/// #153 and #182: the gateway's guards see the token writer's API token mounted into the gateway
/// container however the mount is written.
#[test]
fn the_gateway_guards_see_an_api_token_mount_however_it_is_written() {
    let gateway = read("deploy/kind/base/gateway.yaml");
    let config =
        "            - {name: config, mountPath: /etc/switchboard/config, readOnly: true}\n";
    let last = "            - {name: entry-tokens, mountPath: /var/run/switchboard/tokens, readOnly: true}\n";
    let writers = "            - {name: api-token, mountPath: /var/run/secrets/switchboard/api, readOnly: true}\n";
    let anchored = "            - &api-mount {name: api-token, mountPath: /var/run/secrets/switchboard/api, readOnly: true}\n";
    let block = "            - name: api-token\n              mountPath: /var/run/secrets/switchboard/api\n              readOnly: true\n";
    let bare = "            -\n              name: api-token\n              mountPath: /var/run/secrets/switchboard/api\n";
    let first = |mount: &str| gateway.replacen(config, &format!("{mount}{config}"), 1);
    let after_last = |mount: &str| gateway.replacen(last, &format!("{last}{mount}"), 1);
    // The token writer's own mount, anchored, and the gateway container's by an alias of it.
    let aliased = |mount: &str| {
        gateway
            .replacen(writers, anchored, 1)
            .replacen(config, &format!("{mount}{config}"), 1)
    };
    for (form, changed) in [
        ("flow style", first(writers)),
        ("block style", first(block)),
        ("after a blank line", after_last(&format!("\n{block}"))),
        (
            "after a comment at column 0",
            after_last(&format!("# The API token.\n{block}")),
        ),
        ("a bare dash, first", first(bare)),
        ("a bare dash, last", after_last(bare)),
        (
            "its name not first",
            first(
                "            - mountPath: /var/run/secrets/switchboard/api\n              name: api-token\n",
            ),
        ),
        (
            "a quoted key",
            first(
                "            - {\"name\": api-token, mountPath: /var/run/secrets/switchboard/api}\n",
            ),
        ),
        (
            "an escaped name",
            first(
                "            - {name: \"api\\x2dtoken\", mountPath: /var/run/secrets/switchboard/api}\n",
            ),
        ),
        (
            "a tagged name",
            first(
                "            - {name: !!str api-token, mountPath: /var/run/secrets/switchboard/api}\n",
            ),
        ),
        ("an alias", aliased("            - *api-mount\n")),
        (
            "a merge key",
            aliased("            - {<<: *api-mount, readOnly: true}\n"),
        ),
    ] {
        assert_ne!(changed, gateway, "{form}");
        let pod = only_pod(&changed);
        let (_, mounts) = containers(&pod)
            .into_iter()
            .find(|(name, _)| name == "gateway")
            .unwrap();
        assert!(
            mounts.contains(&"api-token".to_owned()),
            "{form}: {mounts:?}"
        );
        let message = panic_message(form, || only_the_token_writer_holds_an_api_token(&pod));
        assert!(
            message.contains("the containers that mount a token the API server accepts"),
            "{form}: {message}"
        );
        assert_eq!(
            panic_message(form, || no_api_token_mounted(&pod, "gateway", KIND_ISSUER)),
            "volume api-token projects a token for the API server",
            "{form}"
        );
    }
}

/// Projected token sources however they are written, for #153's and #182's guards: each the
/// text of a source item, its lines indented by `$I`, and whether it reads as the issuer's
/// audience, `$ISSUER`, rather than none. A token with no audience, or an empty or null one, is
/// the API server's.
const TOKEN_SOURCE_FORMS: &[(&str, &str, bool)] = &[
    // Past blank lines and comments, in any style.
    (
        "after a blank line",
        "\n$I- serviceAccountToken: {expirationSeconds: 600, path: token}\n",
        false,
    ),
    (
        "after a comment at column 0",
        "# Another source.\n$I- serviceAccountToken: {expirationSeconds: 600, path: token}\n",
        false,
    ),
    (
        "block style",
        "$I- serviceAccountToken:\n$I    expirationSeconds: 600\n$I    path: token\n",
        false,
    ),
    (
        "block style, past a blank line and a comment at column 0",
        "$I- serviceAccountToken:\n\n# The API server's.\n$I    path: token\n$I    audience: $ISSUER\n",
        true,
    ),
    (
        "in a flow mapping",
        "$I- {serviceAccountToken: {expirationSeconds: 600, path: token}}\n",
        false,
    ),
    (
        "a flow mapping over two lines",
        "$I- serviceAccountToken: {path: token,\n$I    expirationSeconds: 600}\n",
        false,
    ),
    (
        "a flow mapping on the next line",
        "$I- serviceAccountToken:\n$I    {path: token}\n",
        false,
    ),
    (
        "a comment after its key",
        "$I- serviceAccountToken: # no audience\n$I    path: token\n",
        false,
    ),
    (
        "a bare dash",
        "$I-\n$I  serviceAccountToken: {path: token}\n",
        false,
    ),
    ("empty", "$I- serviceAccountToken: {}\n", false),
    ("null", "$I- serviceAccountToken:\n", false),
    // Its key however it is written.
    (
        "a double-quoted key",
        "$I- \"serviceAccountToken\": {path: token}\n",
        false,
    ),
    (
        "a single-quoted key",
        "$I- 'serviceAccountToken': {path: token}\n",
        false,
    ),
    (
        "an escaped key",
        "$I- \"service\\x41ccountToken\": {path: token}\n",
        false,
    ),
    (
        "an explicit key",
        "$I- ? serviceAccountToken\n$I  : {path: token}\n",
        false,
    ),
    (
        "a merge key",
        "$I- <<: {serviceAccountToken: {path: token}}\n",
        false,
    ),
    (
        "a tagged source",
        "$I- !!map {serviceAccountToken: {path: token}}\n",
        false,
    ),
    // The API server's audience however it is written.
    (
        "the issuer",
        "$I- serviceAccountToken: {path: token, audience: $ISSUER}\n",
        true,
    ),
    (
        "the issuer, double-quoted",
        "$I- {serviceAccountToken: {path: token, audience: \"$ISSUER\"}}\n",
        true,
    ),
    (
        "the issuer, single-quoted, past a comment",
        "$I- serviceAccountToken:\n$I    # The API server's.\n$I    audience: '$ISSUER' # quoted\n$I    path: token\n",
        true,
    ),
    (
        "the issuer, anchored",
        "$I- serviceAccountToken: {path: token, audience: &audience $ISSUER}\n",
        true,
    ),
    (
        "the issuer, tagged",
        "$I- serviceAccountToken: {path: token, audience: !!str $ISSUER}\n",
        true,
    ),
    (
        "the issuer, with escaped slashes",
        "$I- serviceAccountToken: {path: token, audience: \"https:\\/\\/kubernetes.default.svc.cluster.local\"}\n",
        true,
    ),
    (
        "the issuer, with hex escapes",
        "$I- serviceAccountToken: {path: token, audience: \"\\x68ttps://kubernetes\\x2edefault.svc.cluster.local\"}\n",
        true,
    ),
    (
        "the issuer, with a unicode escape",
        "$I- serviceAccountToken: {path: token, audience: \"\\u0068ttps://kubernetes.default.svc.cluster.local\"}\n",
        true,
    ),
    (
        "the issuer, folded",
        "$I- serviceAccountToken:\n$I    path: token\n$I    audience: >-\n$I      $ISSUER\n",
        true,
    ),
    (
        "the issuer, on the next line",
        "$I- serviceAccountToken:\n$I    audience:\n$I      $ISSUER\n$I    path: token\n",
        true,
    ),
    // An empty or null audience, which the API server fills in with its own.
    (
        "an empty audience, double-quoted",
        "$I- serviceAccountToken: {path: token, audience: \"\"}\n",
        false,
    ),
    (
        "an empty audience, single-quoted",
        "$I- serviceAccountToken: {path: token, audience: ''}\n",
        false,
    ),
    (
        "a null audience",
        "$I- serviceAccountToken: {path: token, audience: null}\n",
        false,
    ),
    (
        "a Null audience",
        "$I- serviceAccountToken: {path: token, audience: Null}\n",
        false,
    ),
    (
        "a NULL audience",
        "$I- serviceAccountToken: {path: token, audience: NULL}\n",
        false,
    ),
    (
        "a ~ audience",
        "$I- serviceAccountToken: {path: token, audience: ~}\n",
        false,
    ),
    (
        "an audience with no value",
        "$I- serviceAccountToken:\n$I    audience:\n$I    path: token\n",
        false,
    ),
    (
        "an audience tagged null",
        "$I- serviceAccountToken: {path: token, audience: !!null }\n",
        false,
    ),
    (
        "an empty audience tagged null",
        "$I- serviceAccountToken: {path: token, audience: !!null ''}\n",
        false,
    ),
];

/// A token source form of [`TOKEN_SOURCE_FORMS`], its items indented by `indent` spaces.
fn token_source(form: &str, indent: usize) -> String {
    form.replace("$ISSUER", KIND_ISSUER)
        .replace("$I", &" ".repeat(indent))
}

/// What the gateway container's guard says of a token for the API server in `volume`.
fn api_token_message(volume: &str, issuer: bool) -> String {
    let unset = format!("volume {volume} projects a token for the API server");
    if issuer {
        format!("{unset}'s audience {KIND_ISSUER}")
    } else {
        unset
    }
}

/// Both of the gateway pod's guards fail on `changed`, a gateway.yaml in which the gateway
/// container mounts `volume`, which projects a token for the API server.
fn gateway_guards_fail(changed: &str, form: &str, volume: &str, issuer: bool) {
    let pod = only_pod(changed);
    let message = panic_message(form, || only_the_token_writer_holds_an_api_token(&pod));
    assert!(
        message.contains("the volumes that hold a token the API server accepts"),
        "{form}: {message}"
    );
    assert_eq!(
        panic_message(form, || no_api_token_mounted(&pod, "gateway", KIND_ISSUER)),
        api_token_message(volume, issuer),
        "{form}"
    );
}

/// #153 and #182: the gateway's guards see a token for the API server in a volume the gateway
/// container mounts, however its source is written.
#[test]
fn the_gateway_guards_see_an_api_token_source_however_it_is_written() {
    let gateway = read("deploy/kind/base/gateway.yaml");
    // The config volume, which the gateway container mounts, projecting its ConfigMap and a
    // token: where it is, first of the volumes, or moved last.
    let config = "        - name: config\n          configMap: {name: gateway-config}\n";
    let projected = "        - name: config\n          projected:\n            sources:\n              - configMap: {name: gateway-config}\n";
    let last = "          emptyDir: {medium: Memory, sizeLimit: 1Mi}\n";
    for (form, source, issuer) in TOKEN_SOURCE_FORMS {
        let with_source = format!("{projected}{}", token_source(source, 14));
        for (place, changed) in [
            ("first", gateway.replacen(config, &with_source, 1)),
            (
                "last",
                gateway
                    .replacen(config, "", 1)
                    .replacen(last, &format!("{last}{with_source}"), 1),
            ),
        ] {
            let form = format!("{form}, {place}");
            assert_ne!(changed, gateway, "{form}");
            let pod = only_pod(&changed);
            let want = issuer.then(|| KIND_ISSUER.to_owned());
            assert_eq!(token_audiences(volume(&pod, "config")), [want], "{form}");
            gateway_guards_fail(&changed, &form, "config", *issuer);
        }
    }

    // The entry-tokens volume, which the gateway container mounts, given the token writer's API
    // token by an alias.
    let entry_tokens = "          emptyDir: {medium: Memory, sizeLimit: 1Mi}\n";
    let as_entry_tokens = |text: &str, projected: &str| {
        text.replacen(
            entry_tokens,
            &format!("          projected: {projected}\n"),
            1,
        )
    };
    let source = "              - serviceAccountToken:\n                  expirationSeconds: 600\n                  path: token\n";
    let anchored_source = gateway.replacen(
        source,
        "              - &api-source\n                serviceAccountToken:\n                  expirationSeconds: 600\n                  path: token\n",
        1,
    );
    let anchored_token = gateway.replacen(
        "              - serviceAccountToken:\n",
        "              - serviceAccountToken: &writer-token\n",
        1,
    );
    // The issuer, anchored in an environment variable of the gateway container.
    let rust_log = "            - name: RUST_LOG\n              value: info\n";
    let anchored_issuer = gateway.replacen(
        rust_log,
        &format!("{rust_log}            - {{name: KIND_ISSUER, value: &issuer {KIND_ISSUER}}}\n"),
        1,
    );
    for (form, changed, issuer) in [
        (
            "its sources by an alias",
            as_entry_tokens(
                &gateway.replacen(
                    "            sources:\n",
                    "            sources: &api-sources\n",
                    1,
                ),
                "{sources: *api-sources}",
            ),
            false,
        ),
        (
            "a source by an alias",
            as_entry_tokens(&anchored_source, "{sources: [*api-source]}"),
            false,
        ),
        (
            "a source merged from an alias",
            as_entry_tokens(&anchored_source, "{sources: [{<<: *api-source}]}"),
            false,
        ),
        (
            "its token by an alias",
            as_entry_tokens(
                &anchored_token,
                "{sources: [{serviceAccountToken: *writer-token}]}",
            ),
            false,
        ),
        (
            "its audience by an alias",
            as_entry_tokens(
                &anchored_issuer,
                "{sources: [{serviceAccountToken: {path: token, audience: *issuer}}]}",
            ),
            true,
        ),
    ] {
        assert_ne!(changed, gateway, "{form}");
        let pod = only_pod(&changed);
        let want = issuer.then(|| KIND_ISSUER.to_owned());
        assert_eq!(
            token_audiences(volume(&pod, "entry-tokens")),
            [want],
            "{form}"
        );
        gateway_guards_fail(&changed, form, "entry-tokens", issuer);
    }

    // A token for another audience is not the API server's, but the gateway container mounts no
    // token of any audience.
    let other = format!(
        "{projected}              - {{serviceAccountToken: {{audience: switchboard, path: token}}}}\n"
    );
    let changed = gateway.replacen(config, &other, 1);
    let pod = only_pod(&changed);
    assert_eq!(
        token_audiences(volume(&pod, "config")),
        [Some("switchboard".to_owned())]
    );
    assert_eq!(api_token_volumes(&pod), ["api-token"]);
    no_api_token_mounted(&pod, "gateway", KIND_ISSUER);
    let message = panic_message("another audience", || {
        only_the_token_writer_holds_an_api_token(&pod)
    });
    assert!(
        message.starts_with("the gateway container mounts a ServiceAccount token: "),
        "{message}"
    );
}

/// #153 and #182: the workloads' guard sees a token for the API server in a workload's volume,
/// however its source is written.
#[test]
fn the_workload_guard_sees_an_api_token_source_however_it_is_written() {
    let workloads = read("deploy/kind/base/workloads.yaml");
    // team-a's wrong-audience token, and a source after it.
    let wrong = "                      audience: not-switchboard\n                      expirationSeconds: 600\n                      path: token\n";
    let with = |text: &str, source: &str| text.replacen(wrong, &format!("{wrong}{source}"), 1);
    let mut forms: Vec<(String, String, bool)> = TOKEN_SOURCE_FORMS
        .iter()
        .map(|(form, source, issuer)| {
            (
                (*form).to_owned(),
                with(&workloads, &token_source(source, 18)),
                *issuer,
            )
        })
        .collect();
    // The issuer, anchored in an environment variable of team-a's workload.
    let own = "                - {name: OWN_PROJECT, value: atlas}\n";
    let anchored_issuer = workloads.replacen(
        own,
        &format!("{own}                - {{name: KIND_ISSUER, value: &issuer {KIND_ISSUER}}}\n"),
        1,
    );
    forms.push((
        "its audience by an alias".to_owned(),
        with(
            &anchored_issuer,
            "                  - serviceAccountToken: {path: token, audience: *issuer}\n",
        ),
        true,
    ));
    // team-a's own token for the gateway, anchored, and merged into a source that empties its
    // audience.
    let anchored_token = workloads.replacen(
        "                  - serviceAccountToken:\n                      audience: switchboard\n",
        "                  - serviceAccountToken: &workload-token\n                      audience: switchboard\n",
        1,
    );
    forms.push((
        "its audience emptied over a merge key".to_owned(),
        with(
            &anchored_token,
            "                  - serviceAccountToken: {<<: *workload-token, audience: ''}\n",
        ),
        false,
    ));

    for (form, changed, issuer) in forms {
        assert_ne!(changed, workloads, "{form}");
        let documents = manifest(&changed);
        let (document, pod) = pod_specs(&documents)[0];
        assert_eq!(label(document), "CronJob team-a/mock-workload", "{form}");
        let want = issuer.then(|| KIND_ISSUER.to_owned());
        assert_eq!(
            token_audiences(volume(pod, "wrong-audience-token")),
            [Some("not-switchboard".to_owned()), want],
            "{form}"
        );
        let message = panic_message(&form, || no_api_token_in_workload(document, pod));
        assert!(
            message.contains(
                "CronJob team-a/mock-workload: the volumes that hold a token the API server accepts"
            ),
            "{form}: {message}"
        );
    }
}

/// #182: the guards see the default API token turned on in the gateway's pod or a workload's,
/// however it is written: `true`, or a YAML 1.1 `yes` or `on`, tagged `!!bool` or not, which the
/// API server reads as true.
#[test]
fn the_guards_see_the_default_api_token_turned_on() {
    let gateway = read("deploy/kind/base/gateway.yaml");
    let workloads = read("deploy/kind/base/workloads.yaml");
    let gateway_account = "      serviceAccountName: gateway\n";
    let workload_account = "          serviceAccountName: mock-workload\n";
    let turned = |value: &str| {
        (
            gateway.replacen(
                gateway_account,
                &format!("{gateway_account}      automountServiceAccountToken: {value}\n"),
                1,
            ),
            workloads.replacen(
                workload_account,
                &format!("{workload_account}          automountServiceAccountToken: {value}\n"),
                1,
            ),
        )
    };
    for value in [
        "true",
        "True",
        "!!bool true",
        "yes",
        "on",
        "!!bool yes",
        "!!bool on",
        "!!bool y",
    ] {
        let (gateway_changed, workloads_changed) = turned(value);
        assert_ne!(gateway_changed, gateway, "{value}");
        let pod = only_pod(&gateway_changed);
        assert_eq!(
            panic_message(value, || only_the_token_writer_holds_an_api_token(&pod)),
            "the gateway's pod turns on the default API token",
            "{value}"
        );
        assert_ne!(workloads_changed, workloads, "{value}");
        let documents = manifest(&workloads_changed);
        let (document, pod) = pod_specs(&documents)[0];
        assert_eq!(
            panic_message(value, || no_api_token_in_workload(document, pod)),
            "CronJob team-a/mock-workload turns on the default API token",
            "{value}"
        );
    }
    // Turned off, or left to the ServiceAccount, it passes.
    for value in ["false", "False", "~"] {
        let (gateway_changed, workloads_changed) = turned(value);
        only_the_token_writer_holds_an_api_token(&only_pod(&gateway_changed));
        let documents = manifest(&workloads_changed);
        let (document, pod) = pod_specs(&documents)[0];
        no_api_token_in_workload(document, pod);
    }
}

/// #182: the reader refuses what its parser would read otherwise than the API server, in the
/// gateway's pod and in a workload: a `!!binary` key that the API server decodes to
/// `serviceAccountToken`, or a `!!binary` audience it decodes to the issuer, however the tag is
/// spelled; and a `<<` that is quoted or tagged, which the API server reads as an ordinary key
/// where the parser would merge it. `!!merge <<` and `? <<` still merge.
#[test]
fn the_guards_refuse_a_tag_or_merge_key_the_parser_reads_otherwise() {
    let gateway = read("deploy/kind/base/gateway.yaml");
    let workloads = read("deploy/kind/base/workloads.yaml");
    // The gateway's config volume, which the gateway container mounts, projecting its ConfigMap
    // and a source; and a source after team-a's wrong-audience token.
    let config = "        - name: config\n          configMap: {name: gateway-config}\n";
    let projected = "        - name: config\n          projected:\n            sources:\n              - configMap: {name: gateway-config}\n";
    let wrong = "                      audience: not-switchboard\n                      expirationSeconds: 600\n                      path: token\n";
    let with_source = |source: &str| {
        vec![
            gateway.replacen(
                config,
                &format!("{projected}{}", token_source(source, 14)),
                1,
            ),
            workloads.replacen(wrong, &format!("{wrong}{}", token_source(source, 18)), 1),
        ]
    };
    // Directives go before the first document, which is the gateway's Deployment and team-a's
    // workload.
    let tag_directive = "%TAG !y! tag:yaml.org,2002:\n---\n";
    let with_directive = |changed: Vec<String>| {
        changed
            .into_iter()
            .map(|text| format!("{tag_directive}{text}"))
            .collect::<Vec<_>>()
    };
    let issuer_in_base64 = "aHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWw=";
    let binary = "a tag the parser does not read as the API server does";
    let merge = "a `<<` that is quoted or tagged";
    let mut forms = Vec::new();
    for (form, source) in [
        (
            "a !!binary key",
            "$I- !!binary c2VydmljZUFjY291bnRUb2tlbg==: {path: token}\n",
        ),
        (
            "a verbatim binary key",
            "$I- !<tag:yaml.org,2002:binary> c2VydmljZUFjY291bnRUb2tlbg==: {path: token}\n",
        ),
        (
            "a !!binary audience",
            "$I- serviceAccountToken: {path: token, audience: !!binary $BINARY}\n",
        ),
        (
            "a local tag",
            "$I- serviceAccountToken: {path: token, audience: !issuer $ISSUER}\n",
        ),
    ] {
        forms.push((
            form,
            with_source(&source.replace("$BINARY", issuer_in_base64)),
            binary,
        ));
    }
    forms.push((
        "a binary key under a %TAG directive",
        with_directive(with_source(
            "$I- !y!binary c2VydmljZUFjY291bnRUb2tlbg==: {path: token}\n",
        )),
        binary,
    ));
    // team-a's own wrong audience, given as the issuer's in base64.
    forms.push((
        "team-a's audience in !!binary",
        vec![workloads.replacen(
            "audience: not-switchboard\n",
            &format!("audience: !!binary {issuer_in_base64}\n"),
            1,
        )],
        binary,
    ));
    for (form, source) in [
        (
            "a single-quoted <<",
            "$I- serviceAccountToken: {path: api-token, '<<': {audience: switchboard}}\n",
        ),
        (
            "a double-quoted <<",
            "$I- serviceAccountToken: {path: api-token, \"<<\": {audience: switchboard}}\n",
        ),
        (
            "a !!str <<",
            "$I- serviceAccountToken: {path: api-token, !!str <<: {audience: switchboard}}\n",
        ),
        (
            "a single-quoted <<, block style",
            "$I- serviceAccountToken:\n$I    path: api-token\n$I    '<<': {audience: switchboard}\n",
        ),
    ] {
        forms.push((form, with_source(source), merge));
    }
    for (form, changed, refusal) in forms {
        for changed in changed {
            assert!(changed != gateway && changed != workloads, "{form}");
            let message = panic_message(form, || {
                manifest(&changed);
            });
            assert!(message.starts_with(refusal), "{form}: {message}");
        }
    }

    // A plain `<<`, tagged `!!merge` or as an explicit key, is a merge key to the API server
    // too: the source's audience is the gateway's, and the workload passes.
    for (form, source) in [
        (
            "a !!merge <<",
            "$I- serviceAccountToken: {path: api-token, !!merge <<: {audience: switchboard}}\n",
        ),
        (
            "an explicit <<",
            "$I- serviceAccountToken:\n$I    path: api-token\n$I    ? <<\n$I    : {audience: switchboard}\n",
        ),
    ] {
        let changed = with_source(source).remove(1);
        let documents = manifest(&changed);
        let (document, pod) = pod_specs(&documents)[0];
        assert_eq!(
            token_audiences(volume(pod, "wrong-audience-token")),
            [
                Some("not-switchboard".to_owned()),
                Some("switchboard".to_owned())
            ],
            "{form}"
        );
        no_api_token_in_workload(document, pod);
    }
}

/// `kustomize build` of the kustomization `directory`, as demo.sh applies it, or None if neither
/// kustomize nor kubectl is installed.
fn kustomize_build(directory: &str) -> Option<String> {
    for command in [&["kustomize", "build"][..], &["kubectl", "kustomize"]] {
        let output = match std::process::Command::new(command[0])
            .args(&command[1..])
            .arg(directory)
            .current_dir(common::repo())
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{command:?} {directory}: {error}"),
        };
        assert!(
            output.status.success(),
            "{command:?} {directory}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Some(String::from_utf8(output.stdout).unwrap());
    }
    None
}

/// Decision 0013, section 10, on what demo.sh applies, `kustomize build deploy/kind/base`, as well
/// as on the files it is built from: in the gateway's pod only the token writer mounts a token
/// the API server accepts, and the gateway container none; no other pod in the build holds one;
/// and no pod gets the default API token, which each pod turns off itself or leaves to a
/// ServiceAccount in the build that does. With neither kustomize nor kubectl installed it says it
/// was skipped and passes; CI, whose runner has both, fails on that line.
#[test]
fn the_token_guards_hold_on_the_built_kind_base() {
    let Some(built) = kustomize_build("deploy/kind/base") else {
        eprintln!("skipped: neither kustomize nor kubectl is installed");
        return;
    };
    let documents = manifest(&built);
    let pods = pod_specs(&documents);
    let labels: Vec<String> = pods.iter().map(|(document, _)| label(document)).collect();
    assert_eq!(
        labels,
        [
            "Deployment mock-docs/mock-docs",
            "Deployment switchboard/gateway",
            "Deployment switchboard/postgres",
            "CronJob team-a/mock-workload",
            "CronJob team-a/stranger-workload",
            "CronJob team-b/mock-workload",
            "Job switchboard/migrate",
        ]
    );
    for (document, pod) in pods {
        let name = label(document);
        if name == "Deployment switchboard/gateway" {
            only_the_token_writer_holds_an_api_token(pod);
            no_api_token_mounted(pod, "gateway", KIND_ISSUER);
        } else {
            no_api_token_in_workload(document, pod);
        }
        if pod["automountServiceAccountToken"] != Yaml::Boolean(false) {
            let namespace = string(&document["metadata"]["namespace"], "a namespace");
            let account = pod["serviceAccountName"].as_str().unwrap_or("default");
            let accounts: Vec<&Yaml> = documents
                .iter()
                .filter(|document| {
                    label(document) == format!("ServiceAccount {namespace}/{account}")
                })
                .collect();
            assert_eq!(accounts.len(), 1, "{name}: ServiceAccount {account}");
            assert_eq!(
                accounts[0]["automountServiceAccountToken"],
                Yaml::Boolean(false),
                "{name}: ServiceAccount {namespace}/{account} mounts the default API token"
            );
        }
    }
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
    let pod = only_pod(&gateway);
    let container = container(&pod, "gateway");
    let (ca_dir, ca_name) = ca_file.rsplit_once('/').unwrap();
    assert_eq!(ca_name, "ca.crt");
    assert_eq!(
        mounts_of(container, "cluster-ca"),
        [&yaml(&format!(
            "{{name: cluster-ca, mountPath: {ca_dir}, readOnly: true}}"
        ))]
    );
    assert_eq!(
        *volume(&pod, "cluster-ca"),
        yaml("{name: cluster-ca, configMap: {name: kube-root-ca.crt}}")
    );

    no_api_token_mounted(&pod, "gateway", issuer);
    for mount in list(&container["volumeMounts"], "volumeMounts") {
        let path = string(&mount["mountPath"], "a mountPath");
        assert!(
            !path.starts_with("/var/run/secrets/kubernetes.io/serviceaccount"),
            "the gateway container mounts {path}"
        );
    }
    assert!(!turns_on_the_default_token(&pod));
    account_turns_off_the_default_token("switchboard", "gateway");

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
