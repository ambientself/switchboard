//! A deployment written to files, as the `switchboard` binary reads it: the deployment file, the
//! kind demo's registry (with the mock server's address swapped for one on loopback), the
//! issuer's keys, the team manifest and the gateway's credential for the mock server.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use gateway::{Deployment, path::RequestPath};
use gateway_identity::SigningAlgorithm;
use gateway_testkit::LocalIssuer;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};

/// The kind demo's registry, as deployed.
pub const KIND_REGISTRY: &str =
    include_str!("../../../../deploy/kind/base/config/registry/registry.toml");
/// The mock server's address in the kind registry.
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
/// The gateway's credential for the mock server. A dummy.
pub const CREDENTIAL: &str = "dummy-gateway-credential-for-the-wiring-tests";
/// The read tool, which names a project.
pub const READ_TOOL: &str = "docs__read_document";
/// The list tool.
pub const LIST_TOOL: &str = "docs__list_documents";
/// The surface.
pub const SURFACE: &str = "docs";

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
        files.write("docs-credential", &format!("{CREDENTIAL}\n"));
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

/// The kind registry with the mock server at `mock_url`.
pub fn registry(mock_url: &str) -> String {
    assert_eq!(KIND_REGISTRY.matches(KIND_ADDRESS).count(), 1);
    KIND_REGISTRY.replace(KIND_ADDRESS, mock_url)
}

/// A deployment file, relative paths and all, with `audit` as its audit table.
pub fn deployment_file(audit: &str) -> String {
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
docs-credential = "docs-credential"
"#
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

/// Sends one JSON-RPC request, in the 2025-06-18 era, with `token` as the bearer if there is
/// one.
pub async fn rpc(path: &RequestPath, token: Option<&str>, method: &str, params: Value) -> Answered {
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
            SURFACE,
            body.to_string().as_bytes(),
        )
        .await;
    Answered {
        status: response.status.as_u16(),
        body: serde_json::from_slice(&response.body).unwrap_or(Value::Null),
    }
}

/// Calls `tool` with `arguments`.
pub async fn call(path: &RequestPath, token: &str, tool: &str, arguments: Value) -> Answered {
    rpc(
        path,
        Some(token),
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await
}

/// The names `tools/list` answers with, sorted.
pub async fn listed(path: &RequestPath, token: &str) -> Vec<String> {
    let answered = rpc(path, Some(token), "tools/list", json!({})).await;
    let mut names: Vec<String> = answered.body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{}", answered.body))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}
