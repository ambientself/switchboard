//! The drift pass and its withdrawals (decision 0013, sections 5 to 7 and 11), against the mock
//! server on loopback, whose admin definition override plays a server whose definition drifts.
//!
//! Each replica here is the kind registry's two entries of one mock server, built as the boot
//! gates build them, with its drift pass driven by the test, an in-memory audit store and the
//! request path. The boot tests start the gateway with `start::prepare`, as the binary does,
//! and serve it on a listener bound only after.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::routing::post;
use connector_proxy::{Destination, FileCredentials, ProxyConnector, Upstream};
use files::{
    AUDIENCE, Files, KIND_REVISION, LIST_TOOL, READ_TOOL, SURFACE, TEAM_A_SA, TEAM_B_LIST_TOOL,
    TEAM_B_READ_TOOL, TEAM_B_SA, TEAM_B_SURFACE, call, cluster_issuer, kubernetes_token, listed,
    listed_on,
};
use gateway::boot::{self, Settings, Wiring};
use gateway::path::RequestPath;
use gateway::reload::{ReloadError, Reloader};
use gateway::{
    AuditSection, DriftPass, Metrics, ProbeCredentials, TELEMETRY_QUEUE, Telemetry, Timeouts,
    probe_credentials, serve_with_telemetry, start,
};
use gateway_core::{ConnectorName, InstanceName, ToolName};
use gateway_identity::SystemClock;
use gateway_mcp::DENIAL_CODE;
use gateway_registry::Registry;
use gateway_testkit::{InMemoryAuditStore, LocalIssuer};
use mock_docs_server::Config;
use serde_json::{Value, json};
use support::{Http, PATIENCE, eventually, exchange, legacy};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// The drift interval the running tests use.
const INTERVAL: Duration = Duration::from_secs(1);

/// The description the mock server serves for `read_document` once it drifts.
const CHANGED: &str = "Read one document of one project, and send it to the vendor's archive.";

/// Both entries' read tools, withdrawn together when the shared server's `read_document`
/// changes: the derived revision's names, sorted by byte.
const BOTH_READS: &str = "docs-team-a__read_document,docs-team-b__read_document";

/// The description the mock server serves for `list_documents`, each entry's reach check tool,
/// once it drifts.
const CHANGED_LIST: &str = "List the documents of one project, and whatever else it holds.";

/// docs-team-a's two tools, withdrawn together when its reach check tool is: the derived
/// revision's names.
const TEAM_A_TOOLS: &str = "docs-team-a__list_documents,docs-team-a__read_document";

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

fn token() -> String {
    kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE])
}

/// One gateway replica over the mock server at `url`, from the files in `files`.
struct Replica {
    path: RequestPath,
    reloader: Reloader,
    drift: DriftPass,
    probes: ProbeCredentials,
    store: Arc<InMemoryAuditStore>,
}

/// The connector for `entry`, one of the mock server's entries, as the binary builds it.
fn proxy(entry: &str, url: &str, files: &Files) -> Arc<ProxyConnector> {
    proxy_within(entry, url, files, connector_proxy::DEFAULT_DEADLINE)
}

/// [`proxy`], with `deadline` for its calls and its tool list.
fn proxy_within(entry: &str, url: &str, files: &Files, deadline: Duration) -> Arc<ProxyConnector> {
    let credential = files.path(&format!("{entry}-credential"));
    let credentials = FileCredentials::load([(entry.into(), credential)]).unwrap();
    // The entry is in_cluster.
    let mut upstream = Upstream {
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
    upstream.deadline = deadline;
    Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap())
}

impl Replica {
    /// A replica of the registry in `files`, its servers at `url`. The drift pass has not run.
    fn new(files: &Files, url: &str) -> Self {
        Self::split(files, url, url)
    }

    /// As [`Replica::new`], with docs-team-a's server at `team_a` and docs-team-b's at
    /// `team_b`, so a definition can drift on one entry alone.
    fn split(files: &Files, team_a: &str, team_b: &str) -> Self {
        let deployment = files.load();
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
        for (entry, url) in [("docs-team-a", team_a), ("docs-team-b", team_b)] {
            let connector = proxy(entry, url, files);
            connectors.insert(ConnectorName::new(entry), connector.clone());
            wiring = wiring.proxied(entry, connector);
        }
        let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
        let drift = DriftPass::new(reloader.withdrawals(), connectors, probes.clone(), INTERVAL);
        Self {
            path: RequestPath::new(gates),
            reloader,
            drift,
            probes,
            store,
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

    fn revision(&self) -> String {
        self.path.gates().policy().revision().as_str().to_owned()
    }

    /// The names team A's surface lists.
    async fn listed(&self) -> Vec<String> {
        listed(&self.path, &token()).await
    }

    /// The names team B's surface lists.
    async fn listed_by_team_b(&self) -> Vec<String> {
        let token = kubernetes_token(issuer(), TEAM_B_SA, &[AUDIENCE]);
        listed_on(&self.path, TEAM_B_SURFACE, &token).await
    }

    /// Calls team A's read tool, and returns the answer and the revision its row recorded.
    async fn read(&self) -> (Value, String) {
        let answered = call(
            &self.path,
            &token(),
            READ_TOOL,
            json!({"project": "atlas", "document": "plan"}),
        )
        .await;
        let row = self.store.rows().pop().expect("the call has a row");
        (answered.body, row.policy_revision.as_str().to_owned())
    }

    /// Applies the registry `text`, as the reloader does when the file changes.
    fn reload(&self, text: &str) -> String {
        self.reloader
            .apply(&Registry::from_toml_str(text).unwrap())
            .unwrap()
            .as_str()
            .to_owned()
    }

    fn metrics(&self) -> String {
        let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        Metrics::new(telemetry, None)
            .with_drift(self.drift.signals())
            .render()
    }
}

/// The mock server, serving each entry's credential.
async fn mock() -> mock_docs_server::Running {
    mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap()
}

/// Serves `CHANGED` as `read_document`'s description, through the admin endpoint.
async fn drift_through_admin(mock: &mock_docs_server::Running) {
    let body = json!({"description": CHANGED}).to_string();
    let request = Http::new("PUT", "/admin/definitions/read_document")
        .header("host", &mock.admin_address().to_string())
        .header("content-type", "application/json")
        .bearer(files::CREDENTIAL)
        .header("content-length", &body.len().to_string())
        .body(body.into_bytes());
    let mut bytes = request.head();
    bytes.extend_from_slice(&request.body);
    let answer = exchange(mock.admin_address(), &bytes).await;
    assert!(answer.status < 300, "{answer:?}");
    assert_eq!(
        mock.server()
            .definition(mock_docs_server::ToolName::ReadDocument)["description"],
        json!(CHANGED)
    );
}

fn drift(mock: &mock_docs_server::Running, description: Option<&str>) {
    mock.server().set_description(
        mock_docs_server::ToolName::ReadDocument,
        description.map(str::to_owned),
    );
}

/// `revision` with both read tools withdrawn.
fn without_reads(revision: &str) -> String {
    format!("{revision}+withdrawn:{BOTH_READS}")
}

/// The value of the sample `series` in `text`.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{series} ")))
        .map(|value| value.parse().unwrap())
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
}

/// A registry `text` in which `tool` is approved again with `description`, as a person would
/// approve what the server serves now: its description, its definition's hash and the time
/// of the approval change, under `revision`.
fn reapproved(text: &str, tool: &str, description: &str, revision: &str) -> String {
    let registry = Registry::from_toml_str(text).unwrap();
    let name: ToolName = tool.parse().unwrap();
    let definition = &registry.definitions()[&name];
    let before = &registry.approvals()[&name];
    let upstream = &registry.routes()[&name].upstream_name;
    let after = gateway_registry::definition_sha256(
        upstream,
        definition.title.as_deref(),
        description,
        &definition.input_schema,
    );
    let start = text.find(&format!("[[tools]]\nname = \"{tool}\"")).unwrap();
    let end = start
        + 1
        + text[start + 1..]
            .find("[[tools]]")
            .unwrap_or(text.len() - start - 1);
    let block = text[start..end]
        .replace(
            &format!("description = \"{}\"", definition.description),
            &format!("description = \"{description}\""),
        )
        .replace(
            &format!("definition_sha256 = \"{}\"", before.definition_sha256),
            &format!("definition_sha256 = \"{after}\""),
        )
        .replace(
            "approved_at = 2026-10-11T00:00:00Z",
            "approved_at = 2026-10-12T09:30:00Z",
        );
    let text = format!("{}{block}{}", &text[..start], &text[end..]);
    at_revision(&text, revision)
}

/// A registry `text` in which `tool` is approved at `approved_at` with `description`, the
/// definition's hash changed to match: an approval of what the server serves, whatever the tool
/// was approved as before.
fn approval(text: &str, tool: &str, description: &str, approved_at: &str) -> String {
    let registry = Registry::from_toml_str(text).unwrap();
    let name: ToolName = tool.parse().unwrap();
    let definition = &registry.definitions()[&name];
    let before = &registry.approvals()[&name];
    let upstream = &registry.routes()[&name].upstream_name;
    let after = gateway_registry::definition_sha256(
        upstream,
        definition.title.as_deref(),
        description,
        &definition.input_schema,
    );
    let start = text.find(&format!("[[tools]]\nname = \"{tool}\"")).unwrap();
    let end = start
        + 1
        + text[start + 1..]
            .find("[[tools]]")
            .unwrap_or(text.len() - start - 1);
    let mut block = text[start..end]
        .replace(
            &format!("description = \"{}\"", definition.description),
            &format!("description = \"{description}\""),
        )
        .replace(
            &format!("definition_sha256 = \"{}\"", before.definition_sha256),
            &format!("definition_sha256 = \"{after}\""),
        );
    let at = block.find("approved_at = ").unwrap();
    let line_end = at + block[at..].find('\n').unwrap();
    block.replace_range(at..line_end, &format!("approved_at = {approved_at}"));
    format!("{}{block}{}", &text[..start], &text[end..])
}

/// `text` under `revision`.
fn at_revision(text: &str, revision: &str) -> String {
    let line = |revision: &str| format!("revision = \"{revision}\"\n");
    let current = Registry::from_toml_str(text).unwrap();
    let current = current.snapshot().revision().as_str().to_owned();
    assert_eq!(text.matches(&line(&current)).count(), 1);
    text.replace(&line(&current), &line(revision))
}

#[tokio::test]
async fn a_served_definition_equal_to_the_approved_one_withdraws_nothing() {
    let mock = mock().await;
    let files = Files::new("drift-equal", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());

    replica.drift.pass().await;

    assert!(replica.withdrawn().is_empty());
    assert_eq!(replica.revision(), KIND_REVISION);
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    let text = replica.metrics();
    for server in ["docs-team-a", "docs-team-b"] {
        let polls = format!("switchboard_drift_polls_total{{server=\"{server}\",result=\"ok\"}}");
        assert_eq!(sample(&text, &polls), Some(1.0), "{text}");
        let withdrawals = format!("switchboard_drift_withdrawals_total{{server=\"{server}\"}}");
        assert_eq!(sample(&text, &withdrawals), Some(0.0), "{text}");
    }
    assert_eq!(
        sample(&text, "switchboard_tools_withdrawn"),
        Some(0.0),
        "{text}"
    );
    // Each entry's list went to the server with that entry's own credential.
    let lists: Vec<Value> = mock
        .log_lines()
        .into_iter()
        .filter(|line| line["rpc_method"] == json!("tools/list"))
        .collect();
    assert_eq!(lists.len(), 2, "{lists:?}");
    assert!(
        lists.iter().all(|line| line["accepted"] == json!(true)),
        "{lists:?}"
    );
}

/// A changed description is withdrawn within one interval, from every surface, and a call to
/// it is refused under the derived revision, which its row records. The withdrawal is logged at
/// ERROR and counted.
#[tokio::test]
async fn a_changed_description_is_withdrawn_within_one_interval() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let files = Files::new("drift-changed", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());
    let withdrawals = replica.drift.withdrawals().clone();
    let signals = replica.drift.signals();
    let drift_pass = DriftPass::new(
        withdrawals.clone(),
        BTreeMap::from([
            (
                ConnectorName::new("docs-team-a"),
                proxy("docs-team-a", &mock.url(), &files),
            ),
            (
                ConnectorName::new("docs-team-b"),
                proxy("docs-team-b", &mock.url(), &files),
            ),
        ]),
        replica.probes.clone(),
        INTERVAL,
    );
    let running = tokio::spawn(drift_pass.run());

    drift(&mock, Some(CHANGED));
    let changed = Instant::now();
    eventually("the withdrawal", || withdrawals.standing().len() == 2).await;
    running.abort();

    // One interval, and the time a poll takes.
    assert!(changed.elapsed() < INTERVAL * 2, "{:?}", changed.elapsed());
    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([READ_TOOL.to_owned(), TEAM_B_READ_TOOL.to_owned()])
    );
    assert_eq!(replica.revision(), without_reads(KIND_REVISION));
    assert_eq!(replica.listed().await, [LIST_TOOL]);
    let (answer, revision) = replica.read().await;
    assert_eq!(answer["error"]["code"], json!(DENIAL_CODE), "{answer}");
    assert_eq!(revision, without_reads(KIND_REVISION));
    let calls = mock
        .log_lines()
        .iter()
        .filter(|line| line["rpc_method"] == json!("tools/call"))
        .count();
    assert_eq!(calls, 0, "the withdrawn tool's call was sent");

    let withdrawn = captured.events("tool_withdrawn");
    assert_eq!(withdrawn.len(), 2, "{withdrawn:?}");
    // Each server's poll is judged as it answers, so the first withdrawal's revision names its
    // own tool, and the second's both.
    for (level, fields) in &withdrawn {
        assert_eq!(level, "ERROR");
        assert_eq!(fields["cause"], "definition changed");
        assert_eq!(fields["base"], KIND_REVISION);
    }
    assert_eq!(
        withdrawn[0].1["revision"],
        format!(
            "{KIND_REVISION}+withdrawn:{}",
            withdrawn[0].1["tool"].as_str().unwrap()
        )
    );
    assert_eq!(withdrawn[1].1["revision"], without_reads(KIND_REVISION));
    let named: BTreeSet<(String, String)> = withdrawn
        .iter()
        .map(|(_, fields)| {
            (
                fields["tool"].as_str().unwrap().to_owned(),
                fields["server"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        named,
        BTreeSet::from([
            (READ_TOOL.to_owned(), "docs-team-a".to_owned()),
            (TEAM_B_READ_TOOL.to_owned(), "docs-team-b".to_owned()),
        ])
    );
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let text = Metrics::new(telemetry, None).with_drift(signals).render();
    for server in ["docs-team-a", "docs-team-b"] {
        let withdrawals = format!("switchboard_drift_withdrawals_total{{server=\"{server}\"}}");
        assert_eq!(sample(&text, &withdrawals), Some(1.0), "{text}");
    }
    assert_eq!(
        sample(&text, "switchboard_tools_withdrawn"),
        Some(2.0),
        "{text}"
    );

    // A withdrawn tool stays withdrawn: the next pass logs and counts nothing more.
    replica.drift.pass().await;
    assert_eq!(captured.events("tool_withdrawn").len(), 2);
}

/// Decision 0013, section 11: two gateways, each with its own drift pass over one server, each
/// withdraw the changed definition, and their rows record the derived revision.
#[tokio::test]
async fn two_replicas_over_one_server_each_withdraw() {
    let mock = mock().await;
    let files = Files::new("drift-two", &issuer().jwks_document(), &mock.url());
    let replicas = [
        Replica::new(&files, &mock.url()),
        Replica::new(&files, &mock.url()),
    ];
    for replica in &replicas {
        replica.drift.pass().await;
        assert!(replica.withdrawn().is_empty());
    }

    drift_through_admin(&mock).await;
    for replica in &replicas {
        replica.drift.pass().await;
    }

    for replica in &replicas {
        assert_eq!(replica.revision(), without_reads(KIND_REVISION));
        assert_eq!(replica.listed().await, [LIST_TOOL]);
        let (_, revision) = replica.read().await;
        assert_eq!(revision, without_reads(KIND_REVISION));
        let list_row = replica.store.list_rows().pop().unwrap().1;
        assert_eq!(
            list_row.policy_revision.as_str(),
            without_reads(KIND_REVISION)
        );
    }
}

/// A server that no longer lists a tool has it withdrawn, as no longer listed. A tool it lists
/// that nobody approved is ignored.
#[tokio::test]
async fn a_tool_the_server_no_longer_lists_is_withdrawn_and_an_unapproved_one_is_ignored() {
    use mock_docs_server::ToolName as Mock;
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let files = Files::new("drift-unlisted", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());

    mock.server().set_tools(vec![
        Mock::ListDocuments,
        Mock::ReadDocument,
        Mock::SearchDocuments,
    ]);
    replica.drift.pass().await;
    assert!(replica.withdrawn().is_empty());
    assert_eq!(replica.revision(), KIND_REVISION);

    mock.server().set_tools(vec![Mock::ListDocuments]);
    replica.drift.pass().await;
    assert_eq!(replica.revision(), without_reads(KIND_REVISION));
    assert_eq!(replica.listed().await, [LIST_TOOL]);
    let withdrawn = captured.events("tool_withdrawn");
    assert_eq!(withdrawn.len(), 2, "{withdrawn:?}");
    assert!(
        withdrawn
            .iter()
            .all(|(_, fields)| fields["cause"] == "no longer listed"),
        "{withdrawn:?}"
    );
}

/// A reload that keeps the tool's approval keeps its withdrawal, under a revision naming the new
/// base. Approving the definition the server serves now clears it: the tool is served again,
/// and the next pass leaves it served.
#[tokio::test]
async fn a_reload_keeps_a_withdrawal_and_a_new_approval_clears_it() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let files = Files::new("drift-reload", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());
    drift(&mock, Some(CHANGED));
    replica.drift.pass().await;
    assert_eq!(replica.revision(), without_reads(KIND_REVISION));

    let original = files::registry(&mock.url());
    let same = at_revision(&original, "demo-12");
    assert_eq!(replica.reload(&same), without_reads("demo-12"));
    assert_eq!(replica.revision(), without_reads("demo-12"));
    assert_eq!(replica.listed().await, [LIST_TOOL]);
    let (_, revision) = replica.read().await;
    assert_eq!(revision, without_reads("demo-12"));
    assert!(captured.events("policy_withdrawal_cleared").is_empty());

    // Team A's read tool approved again as served now; team B's is not.
    let again = reapproved(&same, READ_TOOL, CHANGED, "demo-13");
    assert_eq!(
        replica.reload(&again),
        format!("demo-13+withdrawn:{TEAM_B_READ_TOOL}")
    );
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    let (answer, revision) = replica.read().await;
    assert_eq!(answer["result"]["isError"], json!(false), "{answer}");
    assert_eq!(revision, format!("demo-13+withdrawn:{TEAM_B_READ_TOOL}"));
    let cleared = captured.events("policy_withdrawal_cleared");
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    assert_eq!(cleared[0].0, "INFO");
    assert_eq!(cleared[0].1["tool"], READ_TOOL);

    replica.drift.pass().await;
    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([TEAM_B_READ_TOOL.to_owned()])
    );
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);

    // A version that removes team B's read tool drops its withdrawal.
    let start = again
        .find(&format!("[[tools]]\nname = \"{TEAM_B_READ_TOOL}\""))
        .unwrap();
    let end = start + again[start..].find("\n[[surfaces]]").unwrap();
    let removed = at_revision(
        &format!("{}{}", &again[..start], &again[end..]).replace(
            &format!(
                "tools = [\"{}\", \"{TEAM_B_READ_TOOL}\"]",
                files::TEAM_B_LIST_TOOL
            ),
            &format!("tools = [\"{}\"]", files::TEAM_B_LIST_TOOL),
        ),
        "demo-12",
    );
    assert_eq!(replica.reload(&removed), "demo-12");
    assert!(replica.withdrawn().is_empty());
    assert_eq!(captured.events("policy_withdrawal_cleared").len(), 2);
}

/// While a withdrawal stands, a file that changes the policy but keeps the loaded revision is
/// refused. It is compared with the loaded base, not the derived policy served, whose revision
/// no registry can have: accepted, it would put a different policy under the same base in the
/// rows.
#[tokio::test]
async fn a_changed_policy_under_the_base_revision_is_refused_while_a_withdrawal_stands() {
    let mock = mock().await;
    let files = Files::new("drift-same", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());
    drift(&mock, Some(CHANGED));
    replica.drift.pass().await;
    assert_eq!(replica.revision(), without_reads(KIND_REVISION));

    let original = files::registry(&mock.url());
    let changed = reapproved(&original, READ_TOOL, CHANGED, KIND_REVISION);
    let refused = replica
        .reloader
        .apply(&Registry::from_toml_str(&changed).unwrap())
        .unwrap_err();

    assert!(
        matches!(&refused, ReloadError::RevisionUnchanged(revision) if revision.as_str() == KIND_REVISION),
        "{refused}"
    );
    assert_eq!(replica.revision(), without_reads(KIND_REVISION));
    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([READ_TOOL.to_owned(), TEAM_B_READ_TOOL.to_owned()])
    );
}

/// A server that cannot be reached, or that answers with a list that goes on in another page,
/// keeps its tools served. Each failed poll is logged and counted.
#[tokio::test]
async fn a_poll_that_fails_withdraws_nothing_and_is_counted() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let url = mock.url();
    let files = Files::new("drift-down", &issuer().jwks_document(), &url);
    let replica = Replica::new(&files, &url);
    drop(mock);

    replica.drift.pass().await;

    assert!(replica.withdrawn().is_empty());
    assert_eq!(replica.revision(), KIND_REVISION);
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    let text = replica.metrics();
    for server in ["docs-team-a", "docs-team-b"] {
        let failed =
            format!("switchboard_drift_polls_total{{server=\"{server}\",result=\"failed\"}}");
        assert_eq!(sample(&text, &failed), Some(1.0), "{text}");
    }
    let failed = captured.events("drift_poll_failed");
    assert_eq!(failed.len(), 2, "{failed:?}");
    assert!(
        failed.iter().all(|(level, _)| level == "WARN"),
        "{failed:?}"
    );

    // A server whose list names a next page, here with no tools on the first: read as a list,
    // every tool would look removed.
    let paged = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let paged_url = format!("http://{}/mcp", paged.local_addr().unwrap());
    let router = Router::new().route(
        "/mcp",
        post(|body: String| async move {
            let request: Value = serde_json::from_str(&body).unwrap();
            (
                [("content-type", "application/json")],
                json!({"jsonrpc": "2.0", "id": request["id"],
                       "result": {"tools": [], "nextCursor": "page-2"}})
                .to_string(),
            )
        }),
    );
    tokio::spawn(async move { axum::serve(paged, router).await });
    let paged_files = Files::new("drift-paged", &issuer().jwks_document(), &paged_url);
    let replica = Replica::new(&paged_files, &paged_url);
    replica.drift.pass().await;
    assert!(replica.withdrawn().is_empty());
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    let reasons: Vec<Value> = captured
        .events("drift_poll_failed")
        .into_iter()
        .skip(2)
        .map(|(_, fields)| fields["reason"].clone())
        .collect();
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(
        reasons
            .iter()
            .all(|reason| reason.as_str().unwrap().contains("another page")),
        "{reasons:?}"
    );
}

/// A server that accepts connections and never answers on them.
async fn silent_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    url
}

/// Decision 0013, section 5: each server is polled on a schedule of its own, so a changed
/// definition on a server whose call deadline is at most the interval is withdrawn within one
/// interval plus that deadline, however long another server's polls take. Team B's entry here
/// is a server that never answers, under a 60 s deadline; team A's is the mock server, under a
/// 1 s deadline, equal to the interval.
#[tokio::test]
async fn a_server_that_never_answers_does_not_hold_back_another_servers_withdrawal() {
    let mock = mock().await;
    let files = Files::new("drift-silent", &issuer().jwks_document(), &mock.url());
    let replica = Replica::new(&files, &mock.url());
    let silent = silent_server().await;
    let own_deadline = Duration::from_secs(1);
    let withdrawals = replica.drift.withdrawals().clone();
    let signals = replica.drift.signals();
    let drift_pass = DriftPass::new(
        withdrawals.clone(),
        BTreeMap::from([
            (
                ConnectorName::new("docs-team-a"),
                proxy_within("docs-team-a", &mock.url(), &files, own_deadline),
            ),
            (
                ConnectorName::new("docs-team-b"),
                proxy_within("docs-team-b", &silent, &files, Duration::from_secs(60)),
            ),
        ]),
        replica.probes.clone(),
        INTERVAL,
    );
    let running = tokio::spawn(drift_pass.run());
    let polled = |server: &str| {
        signals
            .counts()
            .into_iter()
            .find(|(name, _)| name.as_str() == server)
            .map(|(_, counts)| counts)
            .unwrap()
    };

    // Team A's first poll has answered, unchanged; team B's is outstanding for a minute.
    eventually("team A's first poll", || {
        polled("docs-team-a").polls_ok >= 1
    })
    .await;
    drift(&mock, Some(CHANGED));
    let changed = Instant::now();
    eventually("the withdrawal of team A's read tool", || {
        !withdrawals.standing().is_empty()
    })
    .await;
    running.abort();

    // One interval and team A's own deadline, with room to spare, and far short of team B's.
    assert!(
        changed.elapsed() < INTERVAL + own_deadline + Duration::from_secs(5),
        "{:?}",
        changed.elapsed()
    );
    assert_eq!(replica.withdrawn(), BTreeSet::from([READ_TOOL.to_owned()]));
    assert_eq!(
        replica.revision(),
        format!("{KIND_REVISION}+withdrawn:{READ_TOOL}")
    );
    let team_b = polled("docs-team-b");
    assert_eq!((team_b.polls_ok, team_b.withdrawals), (0, 0), "{team_b:?}");
}

/// A server whose `tools/list` answers only once released, with the mock server's own
/// definitions: the ones the kind registry approves.
struct Held {
    url: String,
    arrived: Arc<AtomicUsize>,
    release: Arc<Semaphore>,
}

impl Held {
    async fn start() -> Self {
        use mock_docs_server::ToolName as Mock;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let arrived = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (counted, gate) = (arrived.clone(), release.clone());
        let router = Router::new().route(
            "/mcp",
            post(move |body: String| async move {
                let request: Value = serde_json::from_str(&body).unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                gate.acquire().await.unwrap().forget();
                let tools = [
                    Mock::ListDocuments.definition(),
                    Mock::ReadDocument.definition(),
                ];
                (
                    [("content-type", "application/json")],
                    json!({"jsonrpc": "2.0", "id": request["id"], "result": {"tools": tools}})
                        .to_string(),
                )
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self {
            url,
            arrived,
            release,
        }
    }
}

/// A poll is judged against the approvals it began under. Team A's read tool is approved again,
/// for a new definition, while a poll that read the old one is outstanding: when the poll
/// answers, it does not withdraw the new approval, which it never compared. The polls' deadline
/// is far past the test's patience, so each answers and is judged rather than timing out.
#[tokio::test]
async fn a_poll_outstanding_across_a_new_approval_does_not_withdraw_it() {
    let (captured, _logging) = Captured::start();
    let held = Held::start().await;
    let files = Files::new("drift-stale", &issuer().jwks_document(), &held.url);
    let replica = Replica::new(&files, &held.url);
    let again = reapproved(&files::registry(&held.url), READ_TOOL, CHANGED, "demo-13");
    let long = Duration::from_secs(600);
    let drift_pass = DriftPass::new(
        replica.drift.withdrawals().clone(),
        ["docs-team-a", "docs-team-b"]
            .into_iter()
            .map(|entry| {
                let connector = proxy_within(entry, &held.url, &files, long);
                (ConnectorName::new(entry), connector)
            })
            .collect(),
        // No probe: the held server would hold its calls too. Each poll's list alone is judged.
        ProbeCredentials::new(),
        INTERVAL,
    );

    let approving = async {
        eventually("both entries' polls", || {
            held.arrived.load(Ordering::SeqCst) == 2
        })
        .await;
        assert_eq!(replica.reload(&again), "demo-13");
        held.release.add_permits(2);
    };
    tokio::join!(drift_pass.pass(), approving);

    // Each entry's one poll answered and was judged: none failed before the reload.
    let polled: BTreeMap<String, (u64, u64)> = replica
        .drift
        .signals()
        .counts()
        .into_iter()
        .map(|(server, counts)| {
            let polled = (counts.polls_ok, counts.polls_failed);
            (server.as_str().to_owned(), polled)
        })
        .collect();
    assert_eq!(
        polled,
        BTreeMap::from([
            ("docs-team-a".to_owned(), (1, 0)),
            ("docs-team-b".to_owned(), (1, 0)),
        ])
    );
    assert!(replica.withdrawn().is_empty(), "{:?}", replica.withdrawn());
    assert!(captured.events("tool_withdrawn").is_empty());
    assert_eq!(replica.revision(), "demo-13");
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
}

/// A gateway started as the binary starts it, and served on a listener bound after.
struct Booted {
    address: SocketAddr,
    withdrawn: usize,
}

async fn boot(files: &Files) -> Booted {
    let prepared = start::prepare(
        files.load(),
        InstanceName::new("drift-test"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap();
    let withdrawn = prepared.drift.withdrawals().standing().len();
    // The drift pass's timer is not run: whatever is withdrawn was withdrawn during boot.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    tokio::spawn(serve_with_telemetry(
        listener,
        prepared.gates,
        telemetry,
        drain,
        std::future::pending(),
        Timeouts::default(),
        gateway::DEFAULT_MAX_IN_FLIGHT,
    ));
    Booted { address, withdrawn }
}

/// The names the first `tools/list` on team A's surface answers with, over the listener.
async fn first_list(address: SocketAddr) -> Vec<String> {
    let body = legacy("tools/list", json!({})).to_string().into_bytes();
    let request = Http::new("POST", &format!("/mcp/{SURFACE}"))
        .header("host", &format!("127.0.0.1:{}", address.port()))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("content-length", &body.len().to_string())
        .bearer(&token())
        .body(body);
    let mut bytes = request.head();
    bytes.extend_from_slice(&request.body);
    let answer = tokio::time::timeout(PATIENCE, exchange(address, &bytes))
        .await
        .unwrap();
    assert_eq!(answer.status, 200, "{answer:?}");
    let mut names: Vec<String> = answer.json()["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer:?}"))
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

/// Decision 0013, sections 5 and 11: a tool whose served definition differs at boot is never
/// served. The first pass runs before the listener is bound, so the first `tools/list` it
/// answers already lacks it. A restart against a server still changed withdraws it again; a
/// restart against a server restored to its approved definition serves it again, which is
/// section 7's stated residual.
#[tokio::test]
async fn a_definition_changed_at_boot_is_never_served_and_a_restart_detects_it_again() {
    let (captured, _logging) = Captured::start();
    let mock = mock().await;
    let files = Files::new("drift-boot", &issuer().jwks_document(), &mock.url());
    drift(&mock, Some(CHANGED));

    let first = boot(&files).await;
    assert_eq!(first.withdrawn, 2);
    assert_eq!(first_list(first.address).await, [LIST_TOOL]);
    // The boot line says what is served: the derived revision, and the two tools left.
    let serving: Vec<Value> = captured
        .events("boot")
        .into_iter()
        .map(|(_, fields)| fields)
        .filter(|fields| fields.get("registry_revision").is_some())
        .collect();
    assert_eq!(serving.len(), 1, "{serving:?}");
    assert_eq!(serving[0]["registry_revision"], KIND_REVISION);
    assert_eq!(serving[0]["revision"], without_reads(KIND_REVISION));
    assert_eq!(serving[0]["tools"], 2);
    assert_eq!(serving[0]["withdrawn"], 2);

    // A restart with the server still changed: withdrawn again, before serving.
    let restarted = boot(&files).await;
    assert_eq!(restarted.withdrawn, 2);
    assert_eq!(first_list(restarted.address).await, [LIST_TOOL]);

    // The server restored, and the replica restarted: the tool is served again, with no new
    // approval.
    drift(&mock, None);
    let restored = boot(&files).await;
    assert_eq!(restored.withdrawn, 0);
    assert_eq!(first_list(restored.address).await, [LIST_TOOL, READ_TOOL]);
    // The replicas that saw the change keep it withdrawn.
    assert_eq!(first_list(first.address).await, [LIST_TOOL]);
}

/// A failed first poll does not stop boot: the gateway starts and serves the server's tools.
#[tokio::test]
async fn a_server_down_at_boot_does_not_stop_it() {
    let files = Files::new(
        "drift-boot-down",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let booted = boot(&files).await;
    assert_eq!(booted.withdrawn, 0);
    assert_eq!(first_list(booted.address).await, [LIST_TOOL, READ_TOOL]);
}

/// Decision 0013, section 5, as noted on 2026-10-12: the gateway refuses to start with a drift
/// interval shorter than a proxied server's call deadline, naming the server, its deadline and
/// the interval, before it connects to anything. An interval equal to the deadline starts.
#[tokio::test]
async fn start_refuses_a_drift_interval_shorter_than_a_call_deadline() {
    let mock = mock().await;
    let files = Files::new("drift-interval", &issuer().jwks_document(), &mock.url());
    let deployment = |deadline: u64| {
        let text = files::deployment_file("[audit]\nmode = \"disabled\"\n");
        assert_eq!(text.matches("[drift]\n").count(), 1, "{text}");
        text.replace(
            "[drift]\n",
            &format!(
                "[servers.docs-team-a]\ndeadline_seconds = {deadline}\n\n\
                 [drift]\ninterval_seconds = 10\n"
            ),
        )
    };

    files.write("gateway.toml", &deployment(11));
    let refused = start::prepare(
        files.load(),
        InstanceName::new("drift-test"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            &refused,
            start::StartError::IntervalBelowDeadline { server, deadline, interval }
                if server.as_str() == "docs-team-a"
                    && *deadline == Duration::from_secs(11)
                    && *interval == Duration::from_secs(10)
        ),
        "{refused:?}"
    );
    let said = refused.to_string();
    assert!(
        said.contains("is 10 s, shorter than server `docs-team-a`'s call deadline of 11 s"),
        "{said}"
    );
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());

    files.write("gateway.toml", &deployment(10));
    let booted = boot(&files).await;
    assert_eq!(booted.withdrawn, 0);
    assert_eq!(first_list(booted.address).await, [LIST_TOOL, READ_TOOL]);
}

/// Decision 0011, section 4, as noted on 2026-10-12: a withdrawal of an entry's reach check
/// tool withdraws the entry's other tools with it, since the entry's reach can no longer be
/// checked. docs-team-a's server changes `list_documents`, its reach check tool: both of its
/// tools are withdrawn in one policy, the read tool with the cause naming the reach check tool,
/// and its rows record the derived revision naming both. docs-team-b's server, another, is
/// unchanged, and its tools stay served.
#[tokio::test]
async fn a_withdrawn_reach_check_tool_withdraws_its_entrys_other_tools() {
    let (captured, _logging) = Captured::start();
    let team_a = mock().await;
    let team_b = mock().await;
    let files = Files::new("drift-canary", &issuer().jwks_document(), &team_a.url());
    let replica = Replica::split(&files, &team_a.url(), &team_b.url());

    team_a.server().set_description(
        mock_docs_server::ToolName::ListDocuments,
        Some(CHANGED_LIST.to_owned()),
    );
    replica.drift.pass().await;

    let derived = format!("{KIND_REVISION}+withdrawn:{TEAM_A_TOOLS}");
    assert_eq!(
        replica.withdrawn(),
        BTreeSet::from([LIST_TOOL.to_owned(), READ_TOOL.to_owned()])
    );
    assert_eq!(replica.revision(), derived);
    assert!(replica.listed().await.is_empty());
    let list_row = replica.store.list_rows().pop().unwrap().1;
    assert_eq!(list_row.policy_revision.as_str(), derived);
    let (answer, revision) = replica.read().await;
    assert_eq!(answer["error"]["code"], json!(DENIAL_CODE), "{answer}");
    assert_eq!(revision, derived);
    assert_eq!(
        replica.listed_by_team_b().await,
        [TEAM_B_LIST_TOOL, TEAM_B_READ_TOOL]
    );

    let withdrawn = captured.events("tool_withdrawn");
    assert_eq!(withdrawn.len(), 2, "{withdrawn:?}");
    let mut causes = BTreeMap::new();
    for (level, fields) in &withdrawn {
        assert_eq!(level, "ERROR");
        assert_eq!(fields["server"], "docs-team-a");
        assert_eq!(fields["base"], KIND_REVISION);
        assert_eq!(fields["revision"], derived.as_str());
        causes.insert(
            fields["tool"].as_str().unwrap().to_owned(),
            (fields["cause"].clone(), fields["reach_check_tool"].clone()),
        );
    }
    assert_eq!(
        causes,
        BTreeMap::from([
            (
                LIST_TOOL.to_owned(),
                (json!("definition changed"), Value::Null)
            ),
            (
                READ_TOOL.to_owned(),
                (json!("reach check tool withdrawn"), json!(LIST_TOOL))
            ),
        ])
    );
    let text = replica.metrics();
    for (server, count) in [("docs-team-a", 2.0), ("docs-team-b", 0.0)] {
        let withdrawals = format!("switchboard_drift_withdrawals_total{{server=\"{server}\"}}");
        assert_eq!(sample(&text, &withdrawals), Some(count), "{text}");
    }
    assert_eq!(
        sample(&text, "switchboard_tools_withdrawn"),
        Some(2.0),
        "{text}"
    );

    // Both stay withdrawn, and the next pass logs nothing more.
    replica.drift.pass().await;
    assert_eq!(captured.events("tool_withdrawn").len(), 2);
    assert!(replica.listed().await.is_empty());
}

/// A tool withdrawn with its entry's reach check tool stands while that tool's withdrawal does,
/// whatever its own approval: approving it again alone keeps it withdrawn, a new approval of the
/// reach check tool clears both, and so does one of the whole entry. A tool withdrawn for a
/// cause of its own keeps its own key: the reach check tool's new approval leaves it withdrawn.
/// Approved again alone while the reach check tool is withdrawn, it is withdrawn at once with
/// that tool, and logged. The other entry is never touched.
#[tokio::test]
async fn a_withdrawal_with_the_reach_check_tool_clears_with_it() {
    use mock_docs_server::ToolName as Mock;
    let (captured, _logging) = Captured::start();
    let team_a = mock().await;
    let team_b = mock().await;
    let files = Files::new(
        "drift-canary-cleared",
        &issuer().jwks_document(),
        &team_a.url(),
    );
    let replica = Replica::split(&files, &team_a.url(), &team_b.url());
    let described = |tool: Mock| {
        tool.definition()["description"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (list, read) = (
        described(Mock::ListDocuments),
        described(Mock::ReadDocument),
    );
    let both = BTreeSet::from([LIST_TOOL.to_owned(), READ_TOOL.to_owned()]);
    let lines = |event: &str, field: &str| -> Vec<String> {
        captured
            .events(event)
            .into_iter()
            .map(|(_, fields)| {
                format!(
                    "{}: {}",
                    fields["tool"].as_str().unwrap(),
                    fields[field].as_str().unwrap()
                )
            })
            .collect()
    };
    let cleared = || lines("policy_withdrawal_cleared", "reason");
    let withdrawn = || lines("tool_withdrawn", "cause");
    let with_canary = format!("{READ_TOOL}: its entry's reach check tool is no longer withdrawn");

    // The reach check tool changes: both of docs-team-a's tools are withdrawn.
    team_a
        .server()
        .set_description(Mock::ListDocuments, Some(CHANGED_LIST.to_owned()));
    replica.drift.pass().await;
    assert_eq!(replica.withdrawn(), both);

    // The read tool approved again alone: the entry still cannot be checked.
    let text = approval(
        &files::registry(&team_a.url()),
        READ_TOOL,
        &read,
        "2026-10-12T09:00:00Z",
    );
    assert_eq!(
        replica.reload(&at_revision(&text, "demo-12")),
        format!("demo-12+withdrawn:{TEAM_A_TOOLS}")
    );
    assert_eq!(replica.withdrawn(), both);
    assert!(cleared().is_empty(), "{:?}", cleared());
    assert_eq!(withdrawn().len(), 2);

    // The reach check tool approved again as served now: both are served again, and stay so.
    let text = approval(&text, LIST_TOOL, CHANGED_LIST, "2026-10-12T09:10:00Z");
    assert_eq!(replica.reload(&at_revision(&text, "demo-13")), "demo-13");
    assert_eq!(
        cleared(),
        [format!("{LIST_TOOL}: approved again"), with_canary.clone()]
    );
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    replica.drift.pass().await;
    assert!(replica.withdrawn().is_empty());

    // It changes back, and both are withdrawn again. A new approval of the whole entry clears
    // both.
    team_a.server().set_description(Mock::ListDocuments, None);
    replica.drift.pass().await;
    assert_eq!(replica.withdrawn(), both);
    let text = approval(&text, LIST_TOOL, &list, "2026-10-12T09:20:00Z");
    let text = approval(&text, READ_TOOL, &read, "2026-10-12T09:20:00Z");
    assert_eq!(replica.reload(&at_revision(&text, "demo-14")), "demo-14");
    assert!(replica.withdrawn().is_empty());
    assert_eq!(
        cleared()[2..],
        [format!("{LIST_TOOL}: approved again"), with_canary.clone()]
    );

    // Both definitions change: each is withdrawn for a cause of its own.
    team_a
        .server()
        .set_description(Mock::ListDocuments, Some(CHANGED_LIST.to_owned()));
    team_a
        .server()
        .set_description(Mock::ReadDocument, Some(CHANGED.to_owned()));
    replica.drift.pass().await;
    assert_eq!(replica.withdrawn(), both);
    assert_eq!(
        withdrawn()[4..],
        [
            format!("{LIST_TOOL}: definition changed"),
            format!("{READ_TOOL}: definition changed")
        ]
    );

    // The reach check tool approved again alone: the read tool's own withdrawal stands.
    let text = approval(&text, LIST_TOOL, CHANGED_LIST, "2026-10-12T09:30:00Z");
    assert_eq!(
        replica.reload(&at_revision(&text, "demo-15")),
        format!("demo-15+withdrawn:{READ_TOOL}")
    );
    assert_eq!(cleared()[4..], [format!("{LIST_TOOL}: approved again")]);

    // The reach check tool changes back, and is withdrawn again, alone: the read tool already
    // is.
    team_a.server().set_description(Mock::ListDocuments, None);
    replica.drift.pass().await;
    assert_eq!(replica.withdrawn(), both);
    assert_eq!(
        withdrawn()[6..],
        [format!("{LIST_TOOL}: definition changed")]
    );

    // The read tool approved again alone, as served now: its own withdrawal is dropped, and it
    // is withdrawn at once with the reach check tool, which still is.
    let text = approval(&text, READ_TOOL, CHANGED, "2026-10-12T09:40:00Z");
    let derived = format!("demo-16+withdrawn:{TEAM_A_TOOLS}");
    assert_eq!(replica.reload(&at_revision(&text, "demo-16")), derived);
    assert_eq!(cleared()[5..], [format!("{READ_TOOL}: approved again")]);
    let again = captured.events("tool_withdrawn");
    assert_eq!(again.len(), 8, "{again:?}");
    let (level, fields) = &again[7];
    assert_eq!(level, "ERROR");
    assert_eq!(fields["tool"], READ_TOOL);
    assert_eq!(fields["cause"], "reach check tool withdrawn");
    assert_eq!(fields["reach_check_tool"], LIST_TOOL);
    assert_eq!(fields["base"], "demo-16");
    assert_eq!(fields["revision"], derived.as_str());

    // The reach check tool approved again: both are served, and stay so.
    let text = approval(&text, LIST_TOOL, &list, "2026-10-12T09:50:00Z");
    assert_eq!(replica.reload(&at_revision(&text, "demo-17")), "demo-17");
    assert_eq!(
        cleared()[6..],
        [format!("{LIST_TOOL}: approved again"), with_canary]
    );
    replica.drift.pass().await;
    assert!(replica.withdrawn().is_empty());
    assert_eq!(replica.listed().await, [LIST_TOOL, READ_TOOL]);
    assert!(
        captured
            .events("tool_withdrawn")
            .iter()
            .all(|(_, fields)| fields["server"] == "docs-team-a")
    );
    assert_eq!(
        replica.listed_by_team_b().await,
        [TEAM_B_LIST_TOOL, TEAM_B_READ_TOOL]
    );
}
