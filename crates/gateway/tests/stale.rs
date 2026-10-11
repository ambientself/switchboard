//! The maximum age of the policy (decision 0013, section 8), over loopback: the kind registry
//! from files, read again every second by the reloader, with a maximum age of two seconds and
//! an in-memory audit store.
//!
//! A registry file that cannot be read for longer than the maximum age makes the policy stale:
//! `/readyz` answers 503, and `tools/call` and `tools/list` are refused with the stale-policy
//! sentence and no row. A read that succeeds again ends it. Every read counts, so an unchanged
//! file keeps the policy fresh, and so does a file that reads but does not load. The age counts
//! from boot's own read of the file, so a boot slower than the maximum age, started through
//! `start::prepare` with an issuer whose keys are slow to fetch, starts stale. The reloader
//! reads the file as soon as it starts, so a file that reads ends that at once.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::routing::get;

use connector_proxy::{FileCredentials, ProxyConnector, Upstream};
use files::{AUDIENCE, Files, LIST_TOOL, READ_TOOL, SURFACE, TEAM_A_SA, cluster_issuer};
use gateway::boot::{self, Settings, Wiring};
use gateway::{
    AuditSection, Freshness, Metrics, POLICY_STALE, TELEMETRY_QUEUE, Telemetry, Timeouts,
    serve_with_telemetry,
};
use gateway_core::InstanceName;
use gateway_identity::{SigningAlgorithm, SystemClock};
use gateway_mcp::DENIAL_CODE;
use gateway_registry::Registry;
use gateway_testkit::{InMemoryAuditStore, LocalIssuer};
use mock_docs_server::{AcceptedCredential, Config};
use serde_json::{Value, json};
use support::{Answer, Http, PATIENCE, exchange, legacy};
use tokio::net::TcpListener;

/// How often the reloader reads the registry file.
const POLL: Duration = Duration::from_secs(1);

/// The maximum age: twice the poll, the least the deployment file allows.
const MAX_AGE: Duration = Duration::from_secs(2);

/// Longer than the maximum age.
const PAST_MAX_AGE: Duration = Duration::from_secs(3);

/// The gateway, served on loopback, and what the test reads back.
struct Stale {
    address: SocketAddr,
    token: String,
    store: Arc<InMemoryAuditStore>,
    mock: mock_docs_server::Running,
    telemetry: Telemetry,
    freshness: Freshness,
    registry_file: std::path::PathBuf,
    _files: Files,
}

impl Stale {
    async fn start(name: &str) -> Self {
        let mock =
            mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
                .await
                .unwrap();
        let issuer = cluster_issuer();
        let files = Files::new(name, &issuer.jwks_document(), &mock.url());
        let deployment = files.load();
        let registry_file = deployment.registry_file;
        let loaded = std::fs::read(&registry_file).unwrap();
        let settings = Settings {
            deployment: deployment.deployment,
            identity: deployment.identity,
            audit: AuditSection { disabled: false },
            http: deployment.http,
            max_age: Some(MAX_AGE),
            read_at: Instant::now(),
        };
        let registry = Registry::from_toml_str(std::str::from_utf8(&loaded).unwrap()).unwrap();
        let credentials =
            FileCredentials::load([("mock-docs".into(), files.path("docs-credential"))]).unwrap();
        let upstream = Upstream::new("mock-docs", mock.url())
            .tool(READ_TOOL.parse().unwrap(), "read_document")
            .tool(LIST_TOOL.parse().unwrap(), "list_documents");
        let connector = Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap());
        let store = Arc::new(InMemoryAuditStore::new());
        let wiring = Wiring::new(Arc::new(SystemClock))
            .audit_store(store.clone())
            .proxied("mock-docs", connector);
        let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
        let freshness = gates.freshness().clone();
        tokio::spawn(reloader.watch(registry_file.clone(), POLL, loaded));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        tokio::spawn(serve_with_telemetry(
            listener,
            gates,
            telemetry.clone(),
            drain,
            std::future::pending(),
            Timeouts::default(),
            gateway::DEFAULT_MAX_IN_FLIGHT,
        ));
        Self {
            address,
            token: files::kubernetes_token(&issuer, TEAM_A_SA, &[AUDIENCE]),
            store,
            mock,
            telemetry,
            freshness,
            registry_file,
            _files: files,
        }
    }

    async fn ready(&self) -> u16 {
        ready(self.address).await
    }

    async fn list(&self) -> Value {
        list(self.address, &self.token).await
    }

    async fn read(&self) -> Value {
        read(self.address, &self.token).await
    }

    /// Every row written: call rows and list rows.
    fn rows(&self) -> usize {
        self.store.rows().len() + self.store.list_rows().len()
    }

    /// How many `tools/call` requests reached the mock server.
    fn upstream_calls(&self) -> usize {
        self.mock
            .log_lines()
            .iter()
            .filter(|line| line["rpc_method"] == json!("tools/call"))
            .count()
    }

    /// Waits until `/readyz` answers `status`, or fails the test.
    async fn until_ready_is(&self, status: u16) {
        until_ready_is(self.address, status).await;
    }

    /// The policy-age gauge as `GET /metrics` would export it.
    fn exported_age(&self) -> f64 {
        let text = Metrics::new(self.telemetry.clone(), None)
            .with_policy(self.freshness.clone())
            .render();
        assert!(
            text.contains("# TYPE switchboard_policy_age_seconds gauge\n"),
            "{text}"
        );
        assert!(
            text.contains("\nswitchboard_policy_max_age_seconds 2\n"),
            "{text}"
        );
        text.lines()
            .find_map(|line| line.strip_prefix("switchboard_policy_age_seconds "))
            .unwrap_or_else(|| panic!("{text}"))
            .parse()
            .unwrap()
    }
}

async fn send(address: SocketAddr, request: Http) -> Answer {
    let length = request.body.len().to_string();
    let request = request
        .header("host", &format!("127.0.0.1:{}", address.port()))
        .header("content-length", &length);
    let mut bytes = request.head();
    bytes.extend_from_slice(&request.body);
    exchange(address, &bytes).await
}

async fn ready(address: SocketAddr) -> u16 {
    send(address, Http::new("GET", "/readyz")).await.status
}

/// Waits until `/readyz` at `address` answers `status`, or fails the test.
async fn until_ready_is(address: SocketAddr, status: u16) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while ready(address).await != status {
        assert!(
            tokio::time::Instant::now() < deadline,
            "/readyz did not answer {status} within {PATIENCE:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn rpc(address: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    let request = Http::new("POST", &format!("/mcp/{SURFACE}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .bearer(token)
        .body(legacy(method, params).to_string().into_bytes());
    let answer = send(address, request).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    answer.json()
}

async fn list(address: SocketAddr, token: &str) -> Value {
    rpc(address, token, "tools/list", json!({})).await
}

async fn read(address: SocketAddr, token: &str) -> Value {
    rpc(
        address,
        token,
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {"project": "atlas", "document": "plan"}}),
    )
    .await
}

/// A served tool list: a result naming both tools.
fn assert_listed(answer: &Value) {
    let names: Vec<&str> = answer["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&READ_TOOL) && names.contains(&LIST_TOOL),
        "{answer}"
    );
}

/// An allowed read that ran.
fn assert_ran(answer: &Value) {
    assert_eq!(answer["result"]["isError"], json!(false), "{answer}");
}

/// The stale-policy refusal, naming no row.
fn assert_stale(answer: &Value) {
    assert_eq!(
        answer["error"],
        json!({"code": DENIAL_CODE, "message": POLICY_STALE}),
        "{answer}"
    );
}

#[tokio::test]
async fn a_registry_file_not_read_within_the_maximum_age_makes_the_policy_stale() {
    let gateway = Stale::start("stale").await;

    // Fresh: ready, and serving.
    assert_eq!(gateway.ready().await, 200);
    assert_listed(&gateway.list().await);
    assert_ran(&gateway.read().await);
    assert_eq!(gateway.rows(), 2, "a list row and a call row");

    // Every read counts, changed or not: an unchanged file keeps the policy fresh.
    tokio::time::sleep(PAST_MAX_AGE).await;
    assert_eq!(gateway.ready().await, 200);
    assert_listed(&gateway.list().await);
    assert!(gateway.exported_age() < MAX_AGE.as_secs_f64());

    // The file cannot be read. Once the maximum age has passed, the policy is stale.
    let away = gateway.registry_file.with_extension("away");
    std::fs::rename(&gateway.registry_file, &away).unwrap();
    gateway.until_ready_is(503).await;
    let rows = gateway.rows();
    let upstream = gateway.upstream_calls();
    assert_stale(&gateway.list().await);
    assert_stale(&gateway.read().await);
    assert_eq!(gateway.rows(), rows, "a stale refusal wrote a row");
    assert_eq!(gateway.upstream_calls(), upstream, "a stale call was sent");
    assert_eq!(gateway.store.begin_attempts(), 1, "a stale call was begun");
    assert_eq!(gateway.telemetry.counts().policy_stale, 2);
    assert!(gateway.exported_age() > MAX_AGE.as_secs_f64());

    // Read again: the gateway serves again.
    std::fs::rename(&away, &gateway.registry_file).unwrap();
    gateway.until_ready_is(200).await;
    assert_ran(&gateway.read().await);
    assert_listed(&gateway.list().await);
    assert_eq!(gateway.telemetry.counts().policy_stale, 2);
}

/// A file that reads but does not load keeps the last good policy, and is not stale (decision
/// 0013, section 8).
#[tokio::test]
async fn a_registry_file_that_reads_but_does_not_load_is_not_stale() {
    let gateway = Stale::start("not-loading").await;
    std::fs::write(&gateway.registry_file, "this is not a registry [").unwrap();
    tokio::time::sleep(PAST_MAX_AGE).await;
    assert_eq!(gateway.ready().await, 200);
    assert_listed(&gateway.list().await);
    assert_ran(&gateway.read().await);
    assert_eq!(gateway.telemetry.counts().policy_stale, 0);
}

/// What a slow issuer does to the registry file when its keys are fetched.
#[derive(Clone, Copy, PartialEq)]
enum DuringFetch {
    /// Moves it aside, so boot's read is the last one that succeeds.
    MoveAside,
    /// Leaves it where it is, readable.
    LeaveIt,
}

/// An issuer's origin on loopback whose keys take [`PAST_MAX_AGE`] to fetch. When the fetch
/// begins it does `during` to `registry_file`. Returns the origin, which is also the issuer's
/// name.
async fn slow_issuer(registry_file: PathBuf, during: DuringFetch) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let document = LocalIssuer::new(&url, SigningAlgorithm::Es256)
        .unwrap()
        .jwks_document();
    let router = Router::new().route(
        files::KEYS_PATH,
        get(move || {
            let registry_file = registry_file.clone();
            let document = document.clone();
            async move {
                if during == DuringFetch::MoveAside {
                    std::fs::rename(&registry_file, registry_file.with_extension("away")).unwrap();
                }
                tokio::time::sleep(PAST_MAX_AGE).await;
                document
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
}

/// A gateway started through `start::prepare` with an issuer whose keys take longer than the
/// maximum age to fetch, served on loopback. Its reloader is not started.
struct SlowBoot {
    address: SocketAddr,
    token: String,
    telemetry: Telemetry,
    registry_file: PathBuf,
    watch: gateway::start::Watch,
    _mock: mock_docs_server::Running,
    _files: Files,
}

impl SlowBoot {
    /// Boots as `name`, the slow issuer doing `during` to the registry file, with the
    /// reloader to read it every `poll`.
    async fn start(name: &str, during: DuringFetch, poll: Duration) -> Self {
        let mock =
            mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
                .await
                .unwrap();
        let cluster = cluster_issuer();
        let files = Files::new(name, &cluster.jwks_document(), &mock.url());
        let registry_file = files.path("registry/registry.toml");
        let url = slow_issuer(registry_file.clone(), during).await;
        files.write(
            "gateway.toml",
            &files::deployment_file(&format!(
                "{}\n[audit]\nmode = \"disabled\"\n",
                files::keys_url_issuer(&url, &format!("{url}{}", files::KEYS_PATH)),
            )),
        );
        let mut deployment = files.load();
        deployment.poll = poll;
        deployment.max_age = MAX_AGE;
        let prepared =
            gateway::start::prepare(deployment, InstanceName::new(name), Arc::new(SystemClock))
                .await
                .unwrap();
        assert_eq!(
            registry_file.exists(),
            during == DuringFetch::LeaveIt,
            "the keys were not fetched as the test means"
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        tokio::spawn(serve_with_telemetry(
            listener,
            prepared.gates,
            telemetry.clone(),
            drain,
            std::future::pending(),
            Timeouts::default(),
            gateway::DEFAULT_MAX_IN_FLIGHT,
        ));
        Self {
            address,
            token: files::kubernetes_token(&cluster, TEAM_A_SA, &[AUDIENCE]),
            telemetry,
            registry_file,
            watch: prepared.watch,
            _mock: mock,
            _files: files,
        }
    }
}

/// The policy's age counts from boot's read of the registry file, not from when the gates pass
/// (decision 0013, section 8). A boot that takes longer than the maximum age, here fetching an
/// issuer's keys, with the file unreadable from just after that read, starts stale: `/readyz`
/// answers 503 from the first request, and calls and lists are refused. Once the file reads
/// again, the gateway serves.
#[tokio::test]
async fn a_boot_slower_than_the_maximum_age_starts_stale() {
    let gateway = SlowBoot::start("slow-boot", DuringFetch::MoveAside, POLL).await;
    let (address, token) = (gateway.address, &gateway.token);
    tokio::spawn(gateway.watch.run());

    assert_eq!(ready(address).await, 503);
    assert_stale(&list(address, token).await);
    assert_stale(&read(address, token).await);
    assert_eq!(gateway.telemetry.counts().policy_stale, 2);

    let registry_file = &gateway.registry_file;
    std::fs::rename(registry_file.with_extension("away"), registry_file).unwrap();
    until_ready_is(address, 200).await;
    assert_listed(&list(address, token).await);
    assert_ran(&read(address, token).await);
}

/// The reloader reads the registry file as soon as it starts, not a poll later. A boot slower
/// than the maximum age with the file readable throughout is stale until then; once the
/// reloader starts, the gateway serves at once, though the next poll is a minute away.
#[tokio::test]
async fn a_slow_boot_with_the_file_readable_serves_as_soon_as_the_reloader_starts() {
    /// Far longer than the test waits for `/readyz`.
    const LONG_POLL: Duration = Duration::from_secs(60);
    const _: () = assert!(PATIENCE.as_secs() < LONG_POLL.as_secs());

    let gateway = SlowBoot::start("slow-boot-readable", DuringFetch::LeaveIt, LONG_POLL).await;
    let (address, token) = (gateway.address, &gateway.token);
    assert_eq!(ready(address).await, 503);
    assert_stale(&list(address, token).await);

    tokio::spawn(gateway.watch.run());
    until_ready_is(address, 200).await;
    assert_listed(&list(address, token).await);
    assert_ran(&read(address, token).await);
    assert_eq!(gateway.telemetry.counts().policy_stale, 1);
}
