//! A deployment written to files, as the `switchboard` binary reads it: the deployment file, the
//! kind demo's registry (with the mock server's two entries moved to an address on loopback, and
//! their tools' approvals bound to it again), the issuer's keys, the team manifest, the
//! gateway's credential for each entry and the probe's credential.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use gateway::{Deployment, path::RequestPath};
use gateway_identity::SigningAlgorithm;
use gateway_testkit::LocalIssuer;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use mock_docs_server::AcceptedCredential;
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// The kind demo's registry, as deployed.
pub const KIND_REGISTRY: &str =
    include_str!("../../../../deploy/kind/base/config/registry/registry.toml");
/// The mock server's address in the kind registry, where both of its entries name it.
pub const KIND_ADDRESS: &str = "http://mock-docs.mock-docs.svc.cluster.local:8080/mcp";
/// The cluster's ServiceAccount issuer, which the kind registry's rule names.
pub const CLUSTER_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";
/// The audience the demo's workloads project their tokens for.
pub const AUDIENCE: &str = "switchboard";
/// Team A's workload, as Kubernetes names its ServiceAccount.
pub const TEAM_A_SA: &str = "system:serviceaccount:team-a:mock-workload";
/// Team B's workload.
pub const TEAM_B_SA: &str = "system:serviceaccount:team-b:mock-workload";
/// A ServiceAccount the team manifest does not list.
pub const STRANGER_SA: &str = "system:serviceaccount:team-a:stranger";
/// The gateway's credential for team A's entry of the mock server, docs-team-a. A dummy.
pub const CREDENTIAL: &str = "dummy-gateway-credential-for-the-wiring-tests";
/// The gateway's credential for team B's entry, docs-team-b. A dummy.
pub const TEAM_B_CREDENTIAL: &str = "dummy-team-b-credential-for-the-wiring-tests";
/// The probe's credential for both entries: a stranger's, which the mock server refuses. A
/// dummy.
pub const PROBE_CREDENTIAL: &str = "dummy-probe-credential-for-the-wiring-tests";
/// Team A's entry's read tool, which names a project.
pub const READ_TOOL: &str = "docs-team-a__read_document";
/// Team A's entry's list tool.
pub const LIST_TOOL: &str = "docs-team-a__list_documents";
/// Team A's surface.
pub const SURFACE: &str = "docs-team-a";
/// Team B's entry's read tool.
pub const TEAM_B_READ_TOOL: &str = "docs-team-b__read_document";
/// Team B's entry's list tool.
pub const TEAM_B_LIST_TOOL: &str = "docs-team-b__list_documents";
/// Team B's surface.
pub const TEAM_B_SURFACE: &str = "docs-team-b";

/// What a mock server accepts to answer both entries: each entry's credential, for every
/// project.
pub fn mock_credentials() -> Vec<AcceptedCredential> {
    vec![
        AcceptedCredential::token(CREDENTIAL),
        AcceptedCredential::token(TEAM_B_CREDENTIAL),
    ]
}

/// An RS256 issuer named like the cluster's, with a fresh key.
pub fn cluster_issuer() -> LocalIssuer {
    LocalIssuer::new(CLUSTER_ISSUER, SigningAlgorithm::Rs256).unwrap()
}

/// A token shaped like a projected ServiceAccount token: `aud` an array, a `jti`, `nbf`, and
/// the nested `kubernetes.io` claim naming the namespace, ServiceAccount and pod.
pub fn kubernetes_token(issuer: &LocalIssuer, subject: &str, audiences: &[&str]) -> String {
    let mut parts = subject.split(':').skip(2);
    let namespace = parts.next().unwrap_or("default");
    let account = parts.next().unwrap_or("default");
    issuer
        .workload_token(subject, AUDIENCE, SystemTime::now())
        .audiences(audiences)
        .claim("jti", json!("8f5c1e3a-0d2b-4c6e-9a7f-1b2c3d4e5f60"))
        .claim(
            "kubernetes.io",
            json!({
                "namespace": namespace,
                "serviceaccount": {"name": account, "uid": "0a1b2c3d-dummy-uid"},
                "pod": {"name": format!("{account}-pod"), "uid": "4e5f6a7b-dummy-uid"},
                "node": {"name": "switchboard-demo-control-plane", "uid": "8c9d0e1f-dummy-uid"},
            }),
        )
        .build()
}

/// A directory of deployment files.
pub struct Files {
    pub dir: PathBuf,
}

impl Files {
    /// Writes a deployment trusting `keys` (a JWK set document) for the cluster issuer, with
    /// the kind registry pointed at `mock_url` and audit disabled.
    pub fn new(name: &str, keys: &str, mock_url: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("gateway-files-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("registry")).unwrap();
        let files = Self { dir };
        files.write("registry/registry.toml", &registry(mock_url));
        files.write("jwks.json", keys);
        files.write(
            "teams.toml",
            &format!("[subjects]\n\"{TEAM_A_SA}\" = \"team-a\"\n\"{TEAM_B_SA}\" = \"team-b\"\n"),
        );
        files.write("docs-team-a-credential", &format!("{CREDENTIAL}\n"));
        files.write("docs-team-b-credential", &format!("{TEAM_B_CREDENTIAL}\n"));
        files.write(
            "registry-probe-credential",
            &format!("{PROBE_CREDENTIAL}\n"),
        );
        files.write(
            "gateway.toml",
            &deployment_file("[audit]\nmode = \"disabled\"\n"),
        );
        files
    }

    /// Writes `contents` to `relative` in the directory.
    pub fn write(&self, relative: &str, contents: &str) {
        std::fs::write(self.dir.join(relative), contents).unwrap();
    }

    /// The path of `relative` in the directory.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.dir.join(relative)
    }

    /// Loads the deployment file, with no environment variables set but `env`.
    pub fn load_with(&self, env: &[(&str, &str)]) -> Result<Deployment, gateway::DeploymentError> {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        Deployment::load(&self.path("gateway.toml"), move |name| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        })
    }

    /// Loads the deployment file, which must load.
    pub fn load(&self) -> Deployment {
        self.load_with(&[]).unwrap()
    }
}

/// The kind registry with the mock server's entries at `mock_url`.
pub fn registry(mock_url: &str) -> String {
    assert_eq!(KIND_REGISTRY.matches(KIND_ADDRESS).count(), 2);
    rebind(KIND_REGISTRY, mock_url)
}

/// `text`, a registry whose servers are all entries of the mock server, at one address, with
/// every entry moved to `address`, as its owner would register it and a person would approve it
/// again: the address, the identity (the address's host) and each tool's `binding_sha256`,
/// through [`gateway_registry::binding_sha256`]. Each binding is recomputed from the entry as
/// loaded, so it covers every field the binding does, the connector entry's included; the
/// result must load.
pub fn rebind(text: &str, address: &str) -> String {
    let loaded = gateway_registry::Registry::from_toml_str(text).unwrap();
    let servers: Vec<_> = loaded.servers().values().collect();
    let first = servers.first().expect("the registry has a server");
    assert!(
        servers
            .iter()
            .all(|server| server.address == first.address && server.identity == first.identity),
        "the registry's servers are at more than one address"
    );
    let identity = gateway_registry::address_host(address).unwrap().to_owned();
    let replace = |text: &str, from: String, to: String, count: usize| {
        assert_eq!(text.matches(&from).count(), count, "{from}");
        text.replace(&from, &to)
    };
    let mut text = replace(
        text,
        format!("address = \"{}\"\n", first.address),
        format!("address = \"{address}\"\n"),
        servers.len(),
    );
    text = replace(
        &text,
        format!("identity = \"{}\"\n", first.identity),
        format!("identity = \"{identity}\"\n"),
        servers.len(),
    );
    for before in servers {
        let mut after = before.clone();
        after.address = address.to_owned();
        after.identity.clone_from(&identity);
        let tools = loaded
            .routes()
            .values()
            .filter(|route| route.server == before.name)
            .count();
        text = replace(
            &text,
            format!(
                "binding_sha256 = \"{}\"\n",
                gateway_registry::binding_sha256(before)
            ),
            format!(
                "binding_sha256 = \"{}\"\n",
                gateway_registry::binding_sha256(&after)
            ),
            tools,
        );
    }
    let moved = gateway_registry::Registry::from_toml_str(&text)
        .unwrap_or_else(|error| panic!("the moved registry does not load: {error}"));
    for (tool, approval) in moved.approvals() {
        let server = &moved.servers()[&moved.routes()[tool].server];
        assert_eq!(server.address, address);
        assert_eq!(
            approval.binding_sha256,
            gateway_registry::binding_sha256(server)
        );
    }
    text
}

/// The revision the kind registry is at.
pub const KIND_REVISION: &str = "demo-7";

/// The kind registry with the mock server at `mock_url`, under `revision` instead of
/// [`KIND_REVISION`].
pub fn registry_at_revision(mock_url: &str, revision: &str) -> String {
    let line = format!("revision = \"{KIND_REVISION}\"\n");
    let text = registry(mock_url);
    assert_eq!(text.matches(&line).count(), 1);
    text.replace(&line, &format!("revision = \"{revision}\"\n"))
}

/// The path [`KeysServer`] serves its keys at.
pub const KEYS_PATH: &str = "/keys";

/// An issuer's origin on loopback, serving a JWK set at [`KEYS_PATH`], or a failing status, as
/// the test sets. Any other path is `404`. It runs on the test's Tokio runtime.
pub struct KeysServer {
    /// The origin, `http://127.0.0.1:PORT`: the issuer's name too.
    pub url: String,
    answer: Arc<Mutex<(StatusCode, String)>>,
}

impl KeysServer {
    /// Starts a server answering `404` until told otherwise.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let answer = Arc::new(Mutex::new((StatusCode::NOT_FOUND, String::new())));
        let state = Arc::clone(&answer);
        let router = Router::new()
            .route(
                KEYS_PATH,
                get(
                    |State(answer): State<Arc<Mutex<(StatusCode, String)>>>| async move {
                        answer.lock().unwrap().clone()
                    },
                ),
            )
            .with_state(state);
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, answer }
    }

    /// Answers `200` with `document`.
    pub fn serve(&self, document: impl Into<String>) {
        *self.answer.lock().unwrap() = (StatusCode::OK, document.into());
    }

    /// Answers with `status` and no body.
    pub fn fail(&self, status: StatusCode) {
        *self.answer.lock().unwrap() = (status, String::new());
    }

    /// The URL the keys are served at.
    pub fn keys_url(&self) -> String {
        format!("{}{KEYS_PATH}", self.url)
    }
}

/// The `[[identity.issuers]]` entry for an ES256 user issuer named `issuer`, whose keys are
/// fetched from `keys_url` every five minutes, the default.
pub fn keys_url_issuer(issuer: &str, keys_url: &str) -> String {
    format!(
        "[[identity.issuers]]\nissuer = \"{issuer}\"\nkind = \"user\"\n\
         audiences = [\"{AUDIENCE}\"]\nalgorithm = \"ES256\"\nkeys_url = \"{keys_url}\"\n\
         max_lifetime_seconds = 3600\nleeway_seconds = 30\n"
    )
}

/// A deployment file, relative paths and all, with `audit` as its audit table.
pub fn deployment_file(audit: &str) -> String {
    deployment_file_probing(audit, &["docs-team-a", "docs-team-b"])
}

/// [`deployment_file`], giving each of `servers` the probe's credential.
pub fn deployment_file_probing(audit: &str, servers: &[&str]) -> String {
    let probes: String = servers
        .iter()
        .map(|server| format!("{server} = \"registry-probe-credential\"\n"))
        .collect();
    format!(
        r#"deployment = "files-test"
listen = "127.0.0.1:0"

[http]
allowed_hosts = ["127.0.0.1"]
allowed_origins = []

[registry]
file = "registry/registry.toml"
poll_seconds = 1

[identity]
mode = "enforce"

[[identity.issuers]]
issuer = "{CLUSTER_ISSUER}"
kind = "workload"
audiences = ["{AUDIENCE}"]
algorithm = "RS256"
keys_file = "jwks.json"
subjects_file = "teams.toml"
max_lifetime_seconds = 3600
leeway_seconds = 30

{audit}
[credentials]
docs-team-a-credential = "docs-team-a-credential"
docs-team-b-credential = "docs-team-b-credential"

[drift.probe_credentials]
{probes}"#
    )
}

/// A JWK set document holding every key of `issuers`.
pub fn key_set(issuers: &[&LocalIssuer]) -> String {
    let keys: Vec<Value> = issuers
        .iter()
        .flat_map(|issuer| {
            serde_json::to_value(issuer.jwk_set()).unwrap()["keys"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect();
    json!({ "keys": keys }).to_string()
}

/// What the request path answered: the HTTP status and the JSON body.
pub struct Answered {
    pub status: u16,
    pub body: Value,
}

/// Sends one JSON-RPC request on team A's surface, in the 2025-06-18 era, with `token` as the
/// bearer if there is one.
pub async fn rpc(path: &RequestPath, token: Option<&str>, method: &str, params: Value) -> Answered {
    rpc_on(path, SURFACE, token, method, params).await
}

/// Sends one JSON-RPC request on `surface`, as [`rpc`] does.
pub async fn rpc_on(
    path: &RequestPath,
    surface: &str,
    token: Option<&str>,
    method: &str,
    params: Value,
) -> Answered {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2025-06-18"),
    );
    if let Some(token) = token {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let response = path
        .handle(
            &Method::POST,
            &headers,
            surface,
            body.to_string().as_bytes(),
        )
        .await;
    Answered {
        status: response.status.as_u16(),
        body: serde_json::from_slice(&response.body).unwrap_or(Value::Null),
    }
}

/// Calls `tool` with `arguments` on team A's surface.
pub async fn call(path: &RequestPath, token: &str, tool: &str, arguments: Value) -> Answered {
    call_on(path, SURFACE, token, tool, arguments).await
}

/// Calls `tool` with `arguments` on `surface`.
pub async fn call_on(
    path: &RequestPath,
    surface: &str,
    token: &str,
    tool: &str,
    arguments: Value,
) -> Answered {
    rpc_on(
        path,
        surface,
        Some(token),
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await
}

/// The names `tools/list` answers with on team A's surface, sorted.
pub async fn listed(path: &RequestPath, token: &str) -> Vec<String> {
    listed_on(path, SURFACE, token).await
}

/// The names `tools/list` answers with on `surface`, sorted.
pub async fn listed_on(path: &RequestPath, surface: &str, token: &str) -> Vec<String> {
    let answered = rpc_on(path, surface, Some(token), "tools/list", json!({})).await;
    let mut names: Vec<String> = answered.body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{}", answered.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}
