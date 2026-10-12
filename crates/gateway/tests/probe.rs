//! The probe of each proxied server (decision 0010, "Self-built servers at registration";
//! decision 0013, section 9): the drift pass's, which reports an open server and leaves its
//! tools listed, `switchboard probe`, which makes an entry's record, and the loader's rule that
//! every entry has a refused one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use files::{
    AUDIENCE, CREDENTIAL, Files, KIND_REVISION, LIST_TOOL, READ_TOOL, TEAM_A_SA, TEAM_B_CREDENTIAL,
    cluster_issuer, kubernetes_token, listed,
};
use gateway::path::RequestPath;
use gateway::start::{StartError, prepare};
use gateway::{Metrics, ProbeCredentialError, TELEMETRY_QUEUE, Telemetry};
use gateway_core::InstanceName;
use gateway_identity::SystemClock;
use gateway_registry::RegistryError;
use gateway_testkit::LocalIssuer;
use http::HeaderMap;
use mock_docs_server::Config;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const BINARY: &str = env!("CARGO_BIN_EXE_switchboard");

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

/// A server that serves the mock server's tool list to the gateway, with either entry's
/// credential, and dispatches every other request, whatever it carries: it answers each with a
/// JSON-RPC error for an unknown tool. It does not check its caller, so it is open.
async fn open_server() -> String {
    use mock_docs_server::ToolName as Mock;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let router = Router::new().route(
        "/mcp",
        post(|headers: HeaderMap, body: String| async move {
            let request: Value = serde_json::from_str(&body).unwrap();
            let bearer = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            let gateway = [CREDENTIAL, TEAM_B_CREDENTIAL].contains(&bearer.unwrap_or_default());
            let answer = if request["method"] == "tools/list" && gateway {
                let tools = [
                    Mock::ListDocuments.definition(),
                    Mock::ReadDocument.definition(),
                ];
                json!({"jsonrpc": "2.0", "id": request["id"], "result": {"tools": tools}})
            } else {
                json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32602, "message": "Unknown tool"},
                })
            };
            ([("content-type", "application/json")], answer.to_string())
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
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

/// The value of the sample `series` in `text`.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{series} ")))
        .map(|value| value.parse().unwrap())
}

fn probe_results(metrics: &str, server: &str, result: &str) -> Option<f64> {
    sample(
        metrics,
        &format!("switchboard_probe_results_total{{server=\"{server}\",result=\"{result}\"}}"),
    )
}

async fn prepared(files: &Files) -> Result<gateway::start::Prepared, StartError> {
    prepare(
        files.load(),
        InstanceName::new("probe-test"),
        Arc::new(SystemClock),
    )
    .await
}

/// A server that dispatches the probe's calls is reported open by the first drift pass, at
/// ERROR and in the metrics, naming the calls it dispatched. Boot goes on, and its tools stay
/// listed and callable under the registry's own revision: nothing is withdrawn (decision 0010).
#[tokio::test]
async fn an_open_server_is_reported_and_its_tools_stay_listed() {
    let (captured, _logging) = Captured::start();
    let url = open_server().await;
    let files = Files::new("probe-open", &issuer().jwks_document(), &url);

    let prepared = prepared(&files).await.unwrap();

    let open = captured.events(gateway::SERVER_OPEN_EVENT);
    let mut servers: Vec<&str> = open
        .iter()
        .map(|(_, fields)| fields["server"].as_str().unwrap())
        .collect();
    servers.sort_unstable();
    assert_eq!(servers, ["docs-team-a", "docs-team-b"], "{open:?}");
    for (level, fields) in &open {
        assert_eq!(level, "ERROR");
        assert_eq!(
            fields["dispatched"],
            json!("no_credential,malformed_credential,foreign_token"),
            "{fields}"
        );
    }
    assert!(captured.events("tool_withdrawn").is_empty());
    assert!(prepared.drift.withdrawals().standing().is_empty());
    assert_eq!(
        prepared.gates.policy().revision().as_str(),
        KIND_REVISION,
        "the policy served is the registry's"
    );

    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let metrics = Metrics::new(telemetry, None)
        .with_drift(prepared.drift.signals())
        .render();
    for server in ["docs-team-a", "docs-team-b"] {
        assert_eq!(
            probe_results(&metrics, server, "open"),
            Some(1.0),
            "{metrics}"
        );
        assert_eq!(probe_results(&metrics, server, "refused"), Some(0.0));
        assert_eq!(probe_results(&metrics, server, "not_shown"), Some(0.0));
    }
    assert_eq!(sample(&metrics, "switchboard_tools_withdrawn"), Some(0.0));

    let path = RequestPath::new(prepared.gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);
    assert_eq!(listed(&path, &token).await, [LIST_TOOL, READ_TOOL]);

    // The next pass probes again and reports the server again.
    prepared.drift.pass().await;
    assert_eq!(captured.events(gateway::SERVER_OPEN_EVENT).len(), 4);
    assert!(prepared.drift.withdrawals().standing().is_empty());
    assert_eq!(listed(&path, &token).await, [LIST_TOOL, READ_TOOL]);
}

/// The mock server checks its caller: every pass finds it refused, and logs nothing.
#[tokio::test]
async fn a_server_that_refuses_the_probe_is_counted_refused_and_not_logged() {
    let (captured, _logging) = Captured::start();
    let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap();
    let files = Files::new("probe-refused", &issuer().jwks_document(), &mock.url());

    let prepared = prepared(&files).await.unwrap();
    prepared.drift.pass().await;

    assert!(captured.events(gateway::SERVER_OPEN_EVENT).is_empty());
    assert!(captured.events(gateway::PROBE_NOT_SHOWN_EVENT).is_empty());
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let metrics = Metrics::new(telemetry, None)
        .with_drift(prepared.drift.signals())
        .render();
    for server in ["docs-team-a", "docs-team-b"] {
        assert_eq!(
            probe_results(&metrics, server, "refused"),
            Some(2.0),
            "{metrics}"
        );
        assert_eq!(probe_results(&metrics, server, "open"), Some(0.0));
    }
}

/// A server that cannot be reached is not shown to refuse anything: the probe says so at WARN,
/// counts it as not shown, and boot goes on.
#[tokio::test]
async fn an_unreachable_server_is_not_shown_never_refused() {
    let (captured, _logging) = Captured::start();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    drop(listener);
    let files = Files::new("probe-unreachable", &issuer().jwks_document(), &url);

    let prepared = prepared(&files).await.unwrap();

    let warned = captured.events(gateway::PROBE_NOT_SHOWN_EVENT);
    assert_eq!(warned.len(), 2, "{warned:?}");
    assert!(warned.iter().all(|(level, _)| level == "WARN"));
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let metrics = Metrics::new(telemetry, None)
        .with_drift(prepared.drift.signals())
        .render();
    for server in ["docs-team-a", "docs-team-b"] {
        assert_eq!(probe_results(&metrics, server, "not_shown"), Some(1.0));
        assert_eq!(probe_results(&metrics, server, "refused"), Some(0.0));
    }
}

/// The deployment file gives every server in the registry a probe credential, and none for a
/// server the registry does not name; the gateway does not start otherwise.
#[tokio::test]
async fn every_server_needs_a_probe_credential_to_start() {
    let files = Files::new(
        "probe-credentials",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let text = std::fs::read_to_string(files.path("gateway.toml")).unwrap();

    files.write(
        "gateway.toml",
        &text.replace("docs-team-b = \"registry-probe-credential\"\n", ""),
    );
    let refused = prepared(&files).await.unwrap_err();
    assert!(
        matches!(&refused, StartError::ProbeCredentials(ProbeCredentialError::Missing(server)) if server.as_str() == "docs-team-b"),
        "{refused}"
    );

    files.write(
        "gateway.toml",
        &format!("{text}docs-team-c = \"registry-probe-credential\"\n"),
    );
    let refused = prepared(&files).await.unwrap_err();
    assert!(
        matches!(&refused, StartError::ProbeCredentials(ProbeCredentialError::UnknownServer(server)) if server.as_str() == "docs-team-c"),
        "{refused}"
    );

    files.write("gateway.toml", &text);
    files.write("registry-probe-credential", "");
    let refused = prepared(&files).await.unwrap_err();
    assert!(
        matches!(
            &refused,
            StartError::ProbeCredentials(ProbeCredentialError::File(_))
        ),
        "{refused}"
    );
}

/// The registry `files` holds, with each entry's probe record replaced by `record`, or removed.
fn with_records(files: &Files, record: Option<&str>) {
    let path = files.path("registry/registry.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let line = "probe = { result = \"refused\", date = 2026-10-12 }\n";
    assert_eq!(text.matches(line).count(), 2, "{text}");
    let replaced = text.replace(
        line,
        &record
            .map(|record| format!("{record}\n"))
            .unwrap_or_default(),
    );
    std::fs::write(&path, replaced).unwrap();
}

/// The loader refuses an entry with no probe record, or one whose result is not `refused`, so
/// the gateway does not start.
#[tokio::test]
async fn an_entry_without_a_refused_probe_record_does_not_start() {
    let files = Files::new(
        "probe-record",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    with_records(&files, None);
    let refused = prepared(&files).await.unwrap_err();
    assert!(
        matches!(&refused, StartError::Registry(RegistryError::ProbeMissing(server)) if server.as_str() == "docs-team-a"),
        "{refused}"
    );

    for result in ["open", "not_shown"] {
        let files = Files::new(
            &format!("probe-record-{result}"),
            &issuer().jwks_document(),
            "http://127.0.0.1:9/mcp",
        );
        with_records(
            &files,
            Some(&format!(
                "probe = {{ result = \"{result}\", date = 2026-10-12 }}"
            )),
        );
        let refused = prepared(&files).await.unwrap_err();
        assert!(
            matches!(&refused, StartError::Registry(RegistryError::ProbeNotRefused { server, result: found }) if server.as_str() == "docs-team-a" && *found == result),
            "{refused}"
        );
    }
}

/// Runs `switchboard probe` for `server` with the deployment in `files`.
fn run_probe(files: &Files, server: &str) -> Output {
    Command::new(BINARY)
        .arg("probe")
        .arg(format!(
            "--config={}",
            files.path("gateway.toml").to_str().unwrap()
        ))
        .arg(format!("--server={server}"))
        .env_remove("SWITCHBOARD_DATABASE_URL")
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The record line, and the date it names, which must be a plain date.
fn record_date(line: &str, result: &str) -> String {
    let date = line
        .strip_prefix(&format!("probe = {{ result = \"{result}\", date = "))
        .and_then(|rest| rest.strip_suffix(" }"))
        .unwrap_or_else(|| panic!("not a record line: {line}"));
    assert!(
        date.len() == 10
            && date.chars().enumerate().all(|(i, c)| if i == 4 || i == 7 {
                c == '-'
            } else {
                c.is_ascii_digit()
            }),
        "{date}"
    );
    date.to_owned()
}

/// `switchboard probe` probes an entry that has no record yet, reading only the deployment file
/// and that entry, and prints each call, the result and the record line. It exits 0 because
/// the server refused all three calls.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_prints_a_refused_record_for_an_entry_without_one() {
    let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap();
    let files = Files::new("probe-command", &issuer().jwks_document(), &mock.url());
    with_records(&files, None);
    // Nothing but the deployment file and the entry is read: not the keys, nor the team
    // manifest, nor the gateway's credentials.
    for unread in ["jwks.json", "teams.toml", "docs-team-a-credential"] {
        std::fs::remove_file(files.path(unread)).unwrap();
    }

    let output = tokio::task::block_in_place(|| run_probe(&files, "docs-team-a"));

    let lines = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{lines:?} {output:?}");
    assert_eq!(lines[0], format!("server docs-team-a at {}", mock.url()));
    assert_eq!(
        lines[1..5],
        [
            "no_credential: refused",
            "malformed_credential: refused",
            "foreign_token: refused",
            "result: refused",
        ]
    );
    record_date(&lines[5], "refused");
    assert_eq!(lines.len(), 6, "{lines:?}");
    // The mock server saw three calls, each refused, and none carried the gateway's credential.
    let requests: Vec<Value> = mock
        .log_lines()
        .into_iter()
        .filter(|line| line["event"] == "request")
        .collect();
    assert_eq!(requests.len(), 3, "{requests:?}");
    assert!(requests.iter().all(|line| line["accepted"] == json!(false)));
}

/// `switchboard probe` exits 1 for a server it finds open, and for one it cannot reach, and
/// records each as what it found, never as refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_exits_1_and_records_what_it_found_unless_refused() {
    let open = open_server().await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = format!("http://{}/mcp", listener.local_addr().unwrap());
    drop(listener);
    for (url, result, verdict) in [
        (open.as_str(), "open", "open: the call was dispatched"),
        (
            closed.as_str(),
            "not_shown",
            "not shown: the server could not be reached",
        ),
    ] {
        let files = Files::new(&format!("probe-{result}"), &issuer().jwks_document(), url);
        let output = tokio::task::block_in_place(|| run_probe(&files, "docs-team-b"));
        let lines = stdout(&output);
        assert_eq!(output.status.code(), Some(1), "{result}: {lines:?}");
        assert_eq!(
            lines[1..5],
            [
                format!("no_credential: {verdict}"),
                format!("malformed_credential: {verdict}"),
                format!("foreign_token: {verdict}"),
                format!("result: {result}"),
            ]
        );
        record_date(&lines[5], result);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("only a refused probe"), "{stderr}");
    }
}

/// A probe that cannot be made exits 1 and says why; a malformed command line exits 2.
#[test]
fn the_command_refuses_what_it_cannot_probe() {
    let files = Files::new(
        "probe-refusals",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let output = run_probe(&files, "docs-team-c");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("the registry has no server `docs-team-c`"),
        "{stderr}"
    );

    let text = std::fs::read_to_string(files.path("gateway.toml")).unwrap();
    files.write(
        "gateway.toml",
        &text.replace("docs-team-a = \"registry-probe-credential\"\n", ""),
    );
    let output = run_probe(&files, "docs-team-a");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("no probe credential for server `docs-team-a`"),
        "{stderr}"
    );

    for arguments in [
        vec!["probe", "--server=docs-team-a"],
        vec!["probe", "--config=gateway.toml"],
        vec!["--config=gateway.toml", "--server=docs-team-a"],
        vec!["migrate", "--server=docs-team-a"],
    ] {
        let output = Command::new(BINARY).args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
    }
    let output = Command::new(BINARY).arg("--help").output().unwrap();
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("switchboard probe --config=FILE --server=NAME")
    );
}

/// The probe is bounded as a call to the server is: a server that never answers is not shown
/// within the deadline `[servers.<name>]` sets.
#[tokio::test(flavor = "multi_thread")]
async fn the_command_holds_each_call_to_the_servers_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let router = Router::new().route("/mcp", post(std::future::pending::<String>));
    tokio::spawn(async move { axum::serve(listener, router).await });
    let files = Files::new("probe-deadline", &issuer().jwks_document(), &url);
    let text = std::fs::read_to_string(files.path("gateway.toml")).unwrap();
    files.write(
        "gateway.toml",
        &format!("{text}\n[servers.docs-team-a]\ndeadline_seconds = 1\n"),
    );

    let started = std::time::Instant::now();
    let output = tokio::task::block_in_place(|| run_probe(&files, "docs-team-a"));

    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains(&"result: not_shown".to_owned()),
        "{output:?}"
    );
}
