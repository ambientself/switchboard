//! The reach check (decision 0011, section 4; decision 0013, section 5, step 3), against the
//! mock server on loopback, whose callers are each limited to their team's project as in the
//! demos: docs-team-a's credential to atlas and docs-team-b's to borealis.
//!
//! Each replica is the kind registry's two entries of one mock server, with its registry-reach
//! surface, served on a loopback listener with an in-memory audit store. Its reach check calls
//! that listener, as the registry's own workload, exactly as the binary's does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use connector_proxy::{Destination, FileCredentials, ProxyConnector, Upstream};
use files::{
    AUDIENCE, CREDENTIAL, Files, KIND_REVISION, LIST_TOOL, READ_TOOL, SURFACE, TEAM_A_SA,
    TEAM_B_CREDENTIAL, TEAM_B_LIST_TOOL, TEAM_B_SA, TEAM_B_SURFACE, cluster_issuer,
    kubernetes_token,
};
use gateway::boot::{self, Settings, Wiring};
use gateway::reload::Reloader;
use gateway::{
    AuditSection, DriftPass, Metrics, ReachCaller, ReachSettings, TELEMETRY_QUEUE, Telemetry,
    Timeouts, probe_credentials, serve_with_telemetry, start,
};
use gateway_core::audit::{DecisionKind, Outcome, RecordedResources};
use gateway_core::{ConnectorName, InstanceName};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::{InMemoryAuditStore, LocalIssuer};
use mock_docs_server::{AcceptedCredential, Config, Projects};
use serde_json::{Value, json};
use support::{Http, PATIENCE, eventually, exchange};
use tokio::net::TcpListener;

/// The registry's own workload identity, as the kind registry's registry-reach surface names
/// it, and the team manifest maps it to team registry.
const REGISTRY_SA: &str = "system:serviceaccount:switchboard:registry";

/// Another subject the tests map to team registry: the surface admits only `REGISTRY_SA`.
const IMPOSTOR_SA: &str = "system:serviceaccount:switchboard:impostor";

/// The reach check's surface.
const REACH_SURFACE: &str = "registry-reach";

/// The drift interval the running tests use.
const INTERVAL: Duration = Duration::from_secs(1);

/// docs-team-a's two tools, withdrawn together on a mismatch: the derived revision's names.
const TEAM_A_TOOLS: &str = "docs-team-a__list_documents,docs-team-a__read_document";

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

fn token(subject: &str) -> String {
    kubernetes_token(issuer(), subject, &[AUDIENCE])
}

/// The mock server, each entry's credential limited to its team's project.
async fn mock() -> mock_docs_server::Running {
    mock_docs_server::start(Config::new(vec![
        AcceptedCredential::token(CREDENTIAL).limited_to(Projects::only(["atlas"])),
        AcceptedCredential::token(TEAM_B_CREDENTIAL).limited_to(Projects::only(["borealis"])),
    ]))
    .await
    .unwrap()
}

/// How the mock server names docs-team-a's credential, for widening it.
fn team_a_caller() -> String {
    AcceptedCredential::token(CREDENTIAL).logged_prefix()
}

/// The mock server's `tools/call` requests so far, each as `project refused-or-answered`.
fn canary_calls(mock: &mock_docs_server::Running) -> Vec<String> {
    mock.log_lines()
        .into_iter()
        .filter(|line| line["rpc_method"] == json!("tools/call"))
        .map(|line| {
            format!(
                "{} {}",
                line["project"].as_str().unwrap_or("none"),
                if line.get("refused").is_some() {
                    "refused"
                } else {
                    "answered"
                }
            )
        })
        .collect()
}

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Logs on this thread into a new capture until the guard is dropped.
    fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let captured = Self::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        (captured, tracing::subscriber::set_default(subscriber))
    }

    /// Each line whose `event` is `event`, as its level and fields.
    fn events(&self, event: &str) -> Vec<(String, Value)> {
        let logged = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        logged
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|line| line["fields"]["event"] == event)
            .map(|line| {
                (
                    line["level"].as_str().unwrap().to_owned(),
                    line["fields"].clone(),
                )
            })
            .collect()
    }

    /// Everything logged, as text.
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// The connector for `entry`, one of the mock server's entries, as the binary builds it.
fn proxy(entry: &str, url: &str, files: &Files) -> Arc<ProxyConnector> {
    let credential = files.path(&format!("{entry}-credential"));
    let credentials = FileCredentials::load([(entry.into(), credential)]).unwrap();
    // The entry is in_cluster.
    let upstream = Upstream {
        destination: Destination::InCluster,
        ..Upstream::new(entry, url)
    }
    .tool(
        format!("{entry}__read_document").parse().unwrap(),
        "read_document",
    )
    .tool(
        format!("{entry}__list_documents").parse().unwrap(),
        "list_documents",
    );
    Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap())
}

/// One gateway replica over the mock server at `url`, served on a loopback listener, with a
/// drift pass that checks each entry's reach through that listener. The pass is driven by the
/// test.
struct Replica {
    address: SocketAddr,
    reloader: Reloader,
    drift: DriftPass,
    store: Arc<InMemoryAuditStore>,
    files: Files,
}

impl Replica {
    /// A replica of the kind registry, its servers at `url`, whose team manifest maps the
    /// registry's ServiceAccount and `IMPOSTOR_SA` to team registry, and whose reach check
    /// presents the registry's token unless `with_token` is false.
    async fn new(name: &str, url: &str, with_token: bool) -> Self {
        Self::reaching(name, url, with_token, None).await
    }

    /// As [`Replica::new`], with the reach check sent to `reach` in place of the replica's own
    /// listener when it is given.
    async fn reaching(name: &str, url: &str, with_token: bool, reach: Option<SocketAddr>) -> Self {
        let files = Files::new(name, &issuer().jwks_document(), url);
        files.write(
            "teams.toml",
            &format!(
                "[subjects]\n\"{TEAM_A_SA}\" = \"team-a\"\n\"{TEAM_B_SA}\" = \"team-b\"\n\
                 \"{REGISTRY_SA}\" = \"registry\"\n\"{IMPOSTOR_SA}\" = \"registry\"\n"
            ),
        );
        if with_token {
            files.write("registry-token", &format!("{}\n", token(REGISTRY_SA)));
        }
        let deployment = files.load();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reach = ReachSettings::from_fields(
            Some(Path::new("registry-token")),
            Some(&format!(
                "http://{}/mcp/{REACH_SURFACE}",
                reach.unwrap_or(address)
            )),
            Some("127.0.0.1"),
            &deployment.http.allowed_hosts,
            &files.dir,
        )
        .unwrap()
        .unwrap();
        let settings = Settings {
            deployment: deployment.deployment,
            identity: deployment.identity,
            audit: AuditSection { disabled: false },
            http: deployment.http,
            max_age: None,
            read_at: Instant::now(),
        };
        let registry = Registry::load(&deployment.registry_file).unwrap();
        let probes = probe_credentials(&registry, &deployment.probe_credentials).unwrap();
        let store = Arc::new(InMemoryAuditStore::new());
        let mut wiring = Wiring::new(Arc::new(SystemClock)).audit_store(store.clone());
        let mut connectors = BTreeMap::new();
        for entry in ["docs-team-a", "docs-team-b"] {
            let connector = proxy(entry, url, &files);
            connectors.insert(ConnectorName::new(entry), connector.clone());
            wiring = wiring.proxied(entry, connector);
        }
        let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
        let drift = DriftPass::new(reloader.withdrawals(), connectors, probes, INTERVAL)
            .with_reach(ReachCaller::new(reach), &BTreeMap::new());
        let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        tokio::spawn(serve_with_telemetry(
            listener,
            gates,
            telemetry,
            drain,
            std::future::pending(),
            Timeouts::default(),
            gateway::DEFAULT_MAX_IN_FLIGHT,
        ));
        Self {
            address,
            reloader,
            drift,
            store,
            files,
        }
    }

    fn withdrawn(&self) -> BTreeSet<String> {
        self.drift
            .withdrawals()
            .standing()
            .iter()
            .map(|tool| tool.as_str().to_owned())
            .collect()
    }

    /// One JSON-RPC request on `surface` over the listener, as `subject`.
    async fn rpc(&self, surface: &str, subject: &str, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            .to_string()
            .into_bytes();
        let request = Http::new("POST", &format!("/mcp/{surface}"))
            .header("host", &format!("127.0.0.1:{}", self.address.port()))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18")
            .header("content-length", &body.len().to_string())
            .bearer(&token(subject))
            .body(body);
        let mut bytes = request.head();
        bytes.extend_from_slice(&request.body);
        let answer = tokio::time::timeout(PATIENCE, exchange(self.address, &bytes))
            .await
            .unwrap();
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }

    /// The names `tools/list` answers with on `surface`, as `subject`, sorted.
    async fn listed(&self, surface: &str, subject: &str) -> Vec<String> {
        let answer = self.rpc(surface, subject, "tools/list", json!({})).await;
        let mut names: Vec<String> = answer["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("{answer}"))
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    /// Each call row so far, as [`call_rows`] gives them.
    fn rows(&self) -> Vec<String> {
        call_rows(&self.store)
    }

    fn metrics(&self) -> String {
        let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        Metrics::new(telemetry, None)
            .with_drift(self.drift.signals())
            .render()
    }

    /// Applies the registry `text`, as the reloader does when the file changes.
    fn reload(&self, text: &str) -> String {
        self.reloader
            .apply(&Registry::from_toml_str(text).unwrap())
            .unwrap()
            .as_str()
            .to_owned()
    }
}

/// Each call row in `store` so far, as `subject team surface tool project decision outcome`.
fn call_rows(store: &InMemoryAuditStore) -> Vec<String> {
    store
        .rows()
        .iter()
        .map(|row| {
            let principal = row.proved_principal.get();
            let outcome = match row.completion.as_ref().map(|done| &done.outcome) {
                None => "none".to_owned(),
                Some(Outcome::Ok) => "ok".to_owned(),
                Some(Outcome::Error { error_kind }) => format!("error:{error_kind:?}"),
                Some(Outcome::Refused { .. }) => "refused".to_owned(),
            };
            let project = match &row.resources {
                RecordedResources::Named(named) => named
                    .iter()
                    .map(|resource| resource.identifier.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                RecordedResources::Reach(entry) => format!("reach:{}", entry.as_str()),
                RecordedResources::Unknown => "unknown".to_owned(),
            };
            format!(
                "{} {} {} {} {} {} {}",
                principal.id.subject.as_str(),
                principal.team().map_or("none", |team| team.as_str()),
                row.surface.as_str(),
                row.tool,
                project,
                if row.decision == DecisionKind::Allow {
                    "allow"
                } else {
                    "deny"
                },
                outcome
            )
        })
        .collect()
}

/// The value of the sample `series` in `text`.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{series} ")))
        .map(|value| value.parse().unwrap())
}

/// `series` of `switchboard_reach_checks_total` for `server` and `result`.
fn reach_checks(text: &str, server: &str, result: &str) -> Option<f64> {
    sample(
        text,
        &format!("switchboard_reach_checks_total{{server=\"{server}\",result=\"{result}\"}}"),
    )
}

/// A registry `text` in which docs-team-a's tools are approved again, unchanged, at a new time
/// and under `revision`: a new approval, which clears a standing withdrawal.
fn reapproved(text: &str, revision: &str) -> String {
    let mut text = text.to_owned();
    for tool in [LIST_TOOL, READ_TOOL] {
        let start = text.find(&format!("[[tools]]\nname = \"{tool}\"")).unwrap();
        let at = start
            + text[start..]
                .find("approved_at = 2026-10-11T00:00:00Z")
                .unwrap();
        text.replace_range(
            at..at + "approved_at = 2026-10-11T00:00:00Z".len(),
            "approved_at = 2026-10-12T09:30:00Z",
        );
    }
    let line = format!("revision = \"{KIND_REVISION}\"\n");
    assert_eq!(text.matches(&line).count(), 1);
    text.replace(&line, &format!("revision = \"{revision}\"\n"))
}

/// A refused canary holds: each entry's reach check is a call by the registry's principal on its
/// own surface, decided, audited and sent with the entry's own credential, which the server
/// refuses. Nothing is withdrawn. The boot pass makes no reach check; the running pass makes
/// each entry's first at once.
#[tokio::test]
async fn a_refused_canary_is_held_with_a_row_by_the_registry_principal() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let replica = Replica::new("reach-held", &mock.url(), true).await;

    // The boot pass reads the tool lists and probes, and makes no reach check.
    replica.drift.pass().await;
    assert!(replica.store.rows().is_empty(), "{:?}", replica.rows());
    assert!(canary_calls(&mock).is_empty());

    let signals = replica.drift.signals();
    let withdrawals = replica.drift.withdrawals().clone();
    let started = Instant::now();
    let running = tokio::spawn(replica.drift.run());
    eventually("both entries' reach checks", || {
        signals
            .counts()
            .iter()
            .all(|(_, counts)| counts.reach_held >= 1)
    })
    .await;
    running.abort();
    // The first check comes at once, not an interval later.
    assert!(started.elapsed() < INTERVAL, "{:?}", started.elapsed());
    assert!(withdrawals.standing().is_empty());

    // Each check's row: the registry's principal, on its own surface, the entry's canary tool
    // naming the other team's project, allowed, and completed as the server's refusal.
    let rows = call_rows(&replica.store);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        rows.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            format!(
                "{REGISTRY_SA} registry {REACH_SURFACE} {LIST_TOOL} borealis allow error:VendorRefusal"
            ),
            format!(
                "{REGISTRY_SA} registry {REACH_SURFACE} {TEAM_B_LIST_TOOL} atlas allow error:VendorRefusal"
            ),
        ])
    );
    // The server refused both, each for the project outside its entry's credential.
    let mut calls = canary_calls(&mock);
    calls.sort();
    assert_eq!(calls, ["atlas refused", "borealis refused"]);

    let held = captured.events("reach_held");
    assert_eq!(held.len(), 2, "{held:?}");
    for (level, fields) in &held {
        assert_eq!(level, "INFO");
        assert_ne!(fields["row"], "none", "{fields}");
    }
    assert!(captured.events("reach_mismatch").is_empty());
    assert!(captured.events("reach_check_failed").is_empty());
    assert!(captured.events("tool_withdrawn").is_empty());
    let text = Metrics::new(Telemetry::bounded(TELEMETRY_QUEUE).0, None)
        .with_drift(signals)
        .render();
    for server in ["docs-team-a", "docs-team-b"] {
        assert_eq!(reach_checks(&text, server, "held"), Some(1.0), "{text}");
        assert_eq!(reach_checks(&text, server, "mismatch"), Some(0.0), "{text}");
        assert_eq!(reach_checks(&text, server, "failed"), Some(0.0), "{text}");
    }
    // The registry's token is never logged.
    let presented = std::fs::read_to_string(replica.files.path("registry-token")).unwrap();
    assert!(!captured.text().contains(presented.trim()));
}

/// A first reach check that hangs does not hold back the first poll: each entry's schedule
/// begins before its first check, so the first poll comes an interval after the pass starts
/// while that check still waits for an answer (the call deadline plus the allowance).
#[tokio::test]
async fn a_hanging_first_check_does_not_delay_the_first_poll() {
    let mock = mock().await;
    // A listener that takes each connection and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_address = silent.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            open.push(stream);
        }
    });
    let replica = Replica::reaching("reach-hang", &mock.url(), true, Some(silent_address)).await;

    let signals = replica.drift.signals();
    let started = Instant::now();
    let running = tokio::spawn(replica.drift.run());
    eventually("both entries' first polls", || {
        signals
            .counts()
            .iter()
            .all(|(_, counts)| counts.polls_ok >= 1)
    })
    .await;
    let elapsed = started.elapsed();
    let counts = signals.counts();
    running.abort();
    held.abort();
    // About one interval, and far short of the hanging check's deadline and allowance.
    assert!(elapsed < 3 * INTERVAL, "{elapsed:?}");
    // The first checks were still waiting when the polls came.
    for (server, counts) in &counts {
        assert_eq!(
            (
                counts.reach_held,
                counts.reach_mismatch,
                counts.reach_failed
            ),
            (0, 0, 0),
            "{server}: {counts:?}"
        );
    }
}

/// A widened caller is withdrawn: once the server answers docs-team-a's canary, every tool of
/// that entry is withdrawn from every surface, logged and counted, and docs-team-b's are not. A
/// new approval brings them back, and the next check holds again.
#[tokio::test]
async fn a_widened_caller_is_withdrawn() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let replica = Replica::new("reach-widened", &mock.url(), true).await;
    replica.drift.reach_pass().await;
    assert!(replica.withdrawn().is_empty());

    assert!(
        mock.server()
            .set_projects(&team_a_caller(), Projects::only(["atlas", "borealis"]))
    );
    replica.drift.reach_pass().await;

    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([LIST_TOOL.to_owned(), READ_TOOL.to_owned()])
    );
    let derived = format!("{KIND_REVISION}+withdrawn:{TEAM_A_TOOLS}");
    assert!(replica.listed(SURFACE, TEAM_A_SA).await.is_empty());
    assert_eq!(
        replica.listed(TEAM_B_SURFACE, TEAM_B_SA).await,
        [TEAM_B_LIST_TOOL, files::TEAM_B_READ_TOOL]
    );
    assert_eq!(
        replica.listed(REACH_SURFACE, REGISTRY_SA).await,
        [TEAM_B_LIST_TOOL]
    );
    let answer = replica
        .rpc(
            SURFACE,
            TEAM_A_SA,
            "tools/call",
            json!({"name": READ_TOOL, "arguments": {"project": "atlas", "document": "plan"}}),
        )
        .await;
    assert!(answer.get("error").is_some(), "{answer}");
    assert_eq!(
        replica
            .store
            .rows()
            .last()
            .unwrap()
            .policy_revision
            .as_str(),
        derived
    );
    // The mismatch's own row: the canary allowed and answered ok.
    assert!(
        replica.rows().contains(&format!(
            "{REGISTRY_SA} registry {REACH_SURFACE} {LIST_TOOL} borealis allow ok"
        )),
        "{:?}",
        replica.rows()
    );

    let mismatch = captured.events("reach_mismatch");
    assert_eq!(mismatch.len(), 1, "{mismatch:?}");
    assert_eq!(mismatch[0].0, "ERROR");
    assert_eq!(mismatch[0].1["server"], "docs-team-a");
    assert_eq!(mismatch[0].1["withdrawn"], 2);
    let withdrawn = captured.events("tool_withdrawn");
    assert_eq!(withdrawn.len(), 2, "{withdrawn:?}");
    for (level, fields) in &withdrawn {
        assert_eq!(level, "ERROR");
        assert_eq!(fields["cause"], "reach mismatch");
        assert_eq!(fields["server"], "docs-team-a");
        assert_eq!(fields["base"], KIND_REVISION);
    }
    assert_eq!(withdrawn[1].1["revision"], derived);
    let text = replica.metrics();
    assert_eq!(
        reach_checks(&text, "docs-team-a", "mismatch"),
        Some(1.0),
        "{text}"
    );
    assert_eq!(
        reach_checks(&text, "docs-team-b", "held"),
        Some(2.0),
        "{text}"
    );
    assert_eq!(
        sample(
            &text,
            "switchboard_drift_withdrawals_total{server=\"docs-team-a\"}"
        ),
        Some(2.0),
        "{text}"
    );
    assert_eq!(sample(&text, "switchboard_tools_withdrawn"), Some(2.0));

    // While the canary tool is withdrawn, the entry's check fails without a call.
    let before = canary_calls(&mock).len();
    replica.drift.reach_pass().await;
    assert_eq!(
        canary_calls(&mock).len(),
        before + 1,
        "docs-team-b's check only"
    );
    let failed = captured.events("reach_check_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0].0, "WARN");
    assert_eq!(failed[0].1["server"], "docs-team-a");
    assert_eq!(captured.events("tool_withdrawn").len(), 2);

    // The caller narrowed again and the tools approved again: served, and the check holds.
    assert!(
        mock.server()
            .set_projects(&team_a_caller(), Projects::only(["atlas"]))
    );
    let again = reapproved(&files::registry(&mock.url()), "demo-12");
    assert_eq!(replica.reload(&again), "demo-12");
    assert!(replica.withdrawn().is_empty());
    assert_eq!(
        replica.listed(SURFACE, TEAM_A_SA).await,
        [LIST_TOOL, READ_TOOL]
    );
    replica.drift.reach_pass().await;
    assert!(replica.withdrawn().is_empty());
    let text = replica.metrics();
    assert_eq!(
        reach_checks(&text, "docs-team-a", "held"),
        Some(2.0),
        "{text}"
    );
    assert_eq!(captured.events("reach_mismatch").len(), 1);
}

/// A relay between the reach check and the replica's listener that sends each request on at
/// once and holds every answer until it is released.
struct Relay {
    listener: TcpListener,
}

impl Relay {
    async fn bind() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Relays each connection to `target` until the test ends, holding the answers until `true`
    /// is sent on the sender it returns.
    fn start(self, target: SocketAddr) -> tokio::sync::watch::Sender<bool> {
        let (released, _) = tokio::sync::watch::channel(false);
        let watched = released.clone();
        let listener = self.listener;
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let mut release = watched.subscribe();
                tokio::spawn(async move {
                    let server = tokio::net::TcpStream::connect(target).await.unwrap();
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
                    });
                    if release.wait_for(|released| *released).await.is_ok() {
                        let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
                    }
                });
            }
        });
        released
    }
}

/// A reach check is judged against the approvals it began under, as a poll is. docs-team-a's
/// tools are approved again while a check is out, and the widened server's answer to it comes
/// after: the mismatch is logged, but it withdraws nothing, since it never checked the new
/// approval. A check started after the approval withdraws both tools.
#[tokio::test]
async fn a_check_outstanding_across_a_new_approval_does_not_withdraw_it() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let relay = Relay::bind().await;
    let replica = Replica::reaching("reach-stale", &mock.url(), true, Some(relay.address())).await;
    let release = relay.start(replica.address);
    assert!(
        mock.server()
            .set_projects(&team_a_caller(), Projects::only(["atlas", "borealis"]))
    );
    let again = reapproved(&files::registry(&mock.url()), "demo-12");

    let approving = async {
        // Both checks' calls are decided, sent and answered, and the answers held.
        eventually("both checks' rows", || {
            let rows = replica.rows();
            rows.len() == 2 && rows.iter().all(|row| !row.ends_with(" none"))
        })
        .await;
        assert!(replica.rows().contains(&format!(
            "{REGISTRY_SA} registry {REACH_SURFACE} {LIST_TOOL} borealis allow ok"
        )));
        assert_eq!(replica.reload(&again), "demo-12");
        release.send_replace(true);
    };
    tokio::join!(replica.drift.reach_pass(), approving);

    let mismatch = captured.events("reach_mismatch");
    assert_eq!(mismatch.len(), 1, "{mismatch:?}");
    assert_eq!(mismatch[0].1["server"], "docs-team-a");
    assert_eq!(mismatch[0].1["withdrawn"], 0);
    assert!(replica.withdrawn().is_empty(), "{:?}", replica.withdrawn());
    assert!(captured.events("tool_withdrawn").is_empty());
    assert_eq!(
        replica.listed(SURFACE, TEAM_A_SA).await,
        [LIST_TOOL, READ_TOOL]
    );

    // The next check began under the new approval, and withdraws both tools.
    replica.drift.reach_pass().await;
    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([LIST_TOOL.to_owned(), READ_TOOL.to_owned()])
    );
    assert_eq!(captured.events("reach_mismatch").len(), 2);
    assert_eq!(captured.events("tool_withdrawn").len(), 2);
}

/// A missing token is a failed check: logged at WARN and counted, nothing sent to the server
/// and nothing withdrawn, even with a caller widened so a check would find a mismatch.
#[tokio::test]
async fn a_missing_token_is_a_failed_check_and_nothing_is_withdrawn() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let replica = Replica::new("reach-no-token", &mock.url(), false).await;
    assert!(
        mock.server()
            .set_projects(&team_a_caller(), Projects::only(["atlas", "borealis"]))
    );

    replica.drift.reach_pass().await;

    assert!(replica.withdrawn().is_empty());
    assert!(canary_calls(&mock).is_empty());
    assert!(replica.store.rows().is_empty());
    let failed = captured.events("reach_check_failed");
    assert_eq!(failed.len(), 2, "{failed:?}");
    for (level, fields) in &failed {
        assert_eq!(level, "WARN");
        assert!(
            fields["reason"]
                .as_str()
                .unwrap()
                .starts_with("could not read the registry's token file"),
            "{fields}"
        );
    }
    let text = replica.metrics();
    for server in ["docs-team-a", "docs-team-b"] {
        assert_eq!(reach_checks(&text, server, "failed"), Some(1.0), "{text}");
        assert_eq!(reach_checks(&text, server, "held"), Some(0.0), "{text}");
    }

    // A token the gateway refuses fails the check too, and withdraws nothing.
    replica.files.write("registry-token", "not-a-token\n");
    replica.drift.reach_pass().await;
    assert!(replica.withdrawn().is_empty());
    assert!(canary_calls(&mock).is_empty());
    assert_eq!(captured.events("reach_check_failed").len(), 4);
    assert!(captured.events("tool_withdrawn").is_empty());
}

/// Another workload is denied the registry-reach surface: a team's workload, which its team
/// does not admit, and another principal in team registry, which its restriction to the
/// registry's own subject does not. Each is a deny row, and nothing reaches the server.
#[tokio::test]
async fn another_workload_is_denied_the_registry_reach_surface() {
    let mock = mock().await;
    let replica = Replica::new("reach-denied", &mock.url(), true).await;
    for subject in [TEAM_A_SA, IMPOSTOR_SA] {
        let answer = replica
            .rpc(
                REACH_SURFACE,
                subject,
                "tools/call",
                json!({"name": LIST_TOOL, "arguments": {"project": "borealis"}}),
            )
            .await;
        assert_eq!(
            answer["error"]["code"],
            json!(gateway_mcp::DENIAL_CODE),
            "{subject}: {answer}"
        );
        assert!(replica.listed(REACH_SURFACE, subject).await.is_empty());
    }
    let rows = call_rows(&replica.store);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().all(|row| row.ends_with(" deny none")),
        "{rows:?}"
    );
    assert!(canary_calls(&mock).is_empty());
    // The registry's own principal is admitted, to the canary tools alone.
    assert_eq!(
        replica.listed(REACH_SURFACE, REGISTRY_SA).await,
        [LIST_TOOL, TEAM_B_LIST_TOOL]
    );
}

/// The binary's start: with `[drift] reach_*` set, boot says each entry's reach is checked, and
/// the boot pass, before the listener is bound, makes no reach check, so none fails there.
#[tokio::test]
async fn boot_makes_no_reach_check() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let files = Files::new("reach-boot", &issuer().jwks_document(), &mock.url());
    files.write("registry-token", &format!("{}\n", token(REGISTRY_SA)));
    let deployment = files::deployment_file("[audit]\nmode = \"disabled\"\n").replace(
        "[drift.probe_credentials]\n",
        "[drift]\nreach_token_file = \"registry-token\"\n\
         reach_url = \"http://127.0.0.1:9/mcp/registry-reach\"\nreach_host = \"127.0.0.1\"\n\n\
         [drift.probe_credentials]\n",
    );
    files.write("gateway.toml", &deployment);
    let prepared = start::prepare(
        files.load(),
        InstanceName::new("reach-test"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap();
    assert!(prepared.drift.checks_reach());
    let boot: Vec<Value> = captured
        .events("boot")
        .into_iter()
        .map(|(_, fields)| fields)
        .filter(|fields| fields.get("reach_url").is_some())
        .collect();
    assert_eq!(boot.len(), 1, "{boot:?}");
    assert_eq!(
        boot[0]["reach_url"],
        "http://127.0.0.1:9/mcp/registry-reach"
    );
    for event in ["reach_held", "reach_mismatch", "reach_check_failed"] {
        assert!(captured.events(event).is_empty(), "{event}");
    }
    assert!(canary_calls(&mock).is_empty());
}
