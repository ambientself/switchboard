//! The metrics listener (design section 11's signals, decision 0009): `GET /metrics` on its own
//! listener, in Prometheus text, with every signal named; a begin that fails counted as a begin
//! failure and as an audit-failure answer; the open-row poll, which starts at once and counts a
//! failed poll; the open rows of a real database (with `SWITCHBOARD_TEST_DATABASE_URL`); and a
//! `[metrics]` that would take the MCP listener's port refused.
//!
//! The audit store in most tests is a Postgres store pointed at a port nothing listens on: it
//! counts as the real store does, and every begin and poll fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use audit_postgres::{Budgets, GATEWAY_ROLE, OWNER_ROLE, PgAuditStore, PoolSizes, ROLES, migrate};
use gateway::{
    DeploymentError, METRICS_CONTENT_TYPE, Metrics, TELEMETRY_QUEUE, Telemetry, Wiring, boot,
    path::RequestPath, serve_metrics,
};
use gateway_core::audit::{self, Begun, RowStart};
use gateway_core::{CallContext, RequestedTool, decide};
use gateway_testkit::{
    CONNECTOR, Caller, FakeCredentialSource, Fixture, FixtureConnector, READ_TOOL, SURFACE_ALL,
    SURFACE_READ, TEAM_A_DOCUMENT, row_start,
};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use support::{FixtureResources, PATIENCE};

/// The sentence a call or list is refused with when its row cannot be written.
const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// Every family the endpoint writes with audit in Postgres.
const AUDIT_FAMILIES: [(&str, &str); 16] = [
    ("switchboard_audit_begin_failures_total", "counter"),
    ("switchboard_audit_failure_answers_total", "counter"),
    (
        "switchboard_audit_answers_released_before_finish_total",
        "counter",
    ),
    ("switchboard_audit_finishes_given_up_total", "counter"),
    ("switchboard_audit_begins_never_committed_total", "counter"),
    ("switchboard_audit_finishes_in_flight", "gauge"),
    ("switchboard_audit_open_rows", "gauge"),
    (
        "switchboard_audit_oldest_open_row_deadline_seconds",
        "gauge",
    ),
    ("switchboard_audit_open_rows_poll_failures_total", "counter"),
    ("switchboard_audit_begin_latency_seconds", "histogram"),
    ("switchboard_audit_finish_latency_seconds", "histogram"),
    ("switchboard_audit_pool_connections_in_use", "gauge"),
    ("switchboard_audit_pool_connections_open", "gauge"),
    ("switchboard_audit_pool_connections_max", "gauge"),
    ("switchboard_telemetry_events_total", "counter"),
    ("switchboard_telemetry_dropped_total", "counter"),
];

/// The families written whatever the audit store.
const TELEMETRY_FAMILIES: [&str; 2] = [
    "switchboard_telemetry_events_total",
    "switchboard_telemetry_dropped_total",
];

/// A Postgres store on a port nothing listens on, with a begin budget of half a second.
fn unreachable_store() -> Arc<PgAuditStore> {
    let config: tokio_postgres::Config =
        "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard?connect_timeout=1"
            .parse()
            .unwrap();
    let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())
        .unwrap()
        .with_budgets(Budgets {
            begin: Duration::from_millis(500),
            answer: Duration::from_millis(500),
            finish_deadline: Duration::from_secs(1),
        });
    Arc::new(store)
}

/// `metrics` served on `127.0.0.1:0`, until the sender is dropped or sent on.
async fn serve(metrics: Metrics) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(serve_metrics(listener, metrics, async {
        let _ = stopped.await;
    }));
    (address, stop)
}

/// The status, the headers (lower-cased names) and the body of `method target`.
async fn get(address: SocketAddr, method: &str, target: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request =
        format!("{method} {target} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    let received = String::from_utf8(received).unwrap();
    let (head, body) = received.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// The value of the one sample written exactly as `series`, name and labels.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            (name == series).then(|| value.parse().unwrap())
        })
}

/// The sum of every sample of the family `name`, whatever its labels.
fn total(text: &str, name: &str) -> f64 {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.rsplit_once(' '))
        .filter(|(series, _)| *series == name || series.starts_with(&format!("{name}{{")))
        .map(|(_, value)| value.parse::<f64>().unwrap())
        .sum()
}

/// Waits until `done` holds for the text the endpoint answers with.
async fn until_scraped(address: SocketAddr, what: &str, done: impl Fn(&str) -> bool) -> String {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let (_, _, text) = get(address, "GET", "/metrics").await;
        if done(&text) {
            return text;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_endpoint_answers_with_every_signal_and_nothing_else() {
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let (address, _stop) = serve(Metrics::new(telemetry, Some(unreachable_store()))).await;

    let (status, head, text) = get(address, "GET", "/metrics").await;
    assert_eq!(status, 200, "{head}");
    assert!(
        head.contains(&format!("content-type: {METRICS_CONTENT_TYPE}")),
        "{head}"
    );
    for (name, kind) in AUDIT_FAMILIES {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "{name} {kind}\n{text}"
        );
        assert!(text.contains(&format!("# HELP {name} ")), "{name}");
    }
    for histogram in [
        "switchboard_audit_begin_latency_seconds",
        "switchboard_audit_finish_latency_seconds",
    ] {
        for series in [
            format!("{histogram}_bucket{{le=\"0.005\"}}"),
            format!("{histogram}_bucket{{le=\"30\"}}"),
            format!("{histogram}_bucket{{le=\"+Inf\"}}"),
            format!("{histogram}_sum"),
            format!("{histogram}_count"),
        ] {
            assert!(sample(&text, &series).is_some(), "{series}\n{text}");
        }
    }
    for pool in ["begin", "finish"] {
        let series = format!("switchboard_audit_pool_connections_max{{pool=\"{pool}\"}}");
        assert!(sample(&text, &series).unwrap() >= 1.0, "{series}\n{text}");
    }
    assert!(
        text.contains("no connection obtained within the begin budget (waiting for the pool or opening a connection)"),
        "{text}"
    );
    assert!(!text.contains("receipt"), "{text}");

    // Nothing else is on the port.
    for target in ["/", "/readyz", "/mcp/read", "/metrics/x"] {
        let (status, _, _) = get(address, "GET", target).await;
        assert_eq!(status, 404, "{target}");
    }
    let (status, head, _) = get(address, "POST", "/metrics").await;
    assert_eq!(status, 405, "{head}");
}

#[tokio::test]
async fn with_audit_disabled_only_the_telemetry_counters_are_exported() {
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let (address, _stop) = serve(Metrics::new(telemetry, None)).await;
    let (status, _, text) = get(address, "GET", "/metrics").await;
    assert_eq!(status, 200);
    for name in TELEMETRY_FAMILIES {
        assert!(text.contains(&format!("# TYPE {name} counter\n")), "{text}");
    }
    assert!(!text.contains("switchboard_audit_"), "{text}");
    assert_eq!(
        sample(&text, "switchboard_telemetry_events_total{event=\"ping\"}"),
        Some(0.0)
    );
}

/// The poller starts with the listener, and its first poll runs at once. Against a database
/// that is not there, each poll fails and is counted, and no open-row count is made up.
#[tokio::test]
async fn the_open_row_poll_runs_at_once_and_a_failed_poll_is_counted() {
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let (address, _stop) = serve(Metrics::new(telemetry, Some(unreachable_store()))).await;
    let text = until_scraped(address, "a failed poll counted", |text| {
        sample(text, "switchboard_audit_open_rows_poll_failures_total") == Some(1.0)
    })
    .await;
    assert_eq!(sample(&text, "switchboard_audit_open_rows"), None, "{text}");
    assert_eq!(
        sample(&text, "switchboard_audit_oldest_open_row_deadline_seconds"),
        None,
        "{text}"
    );
}

/// The headers a well-behaved client sends, with `token`.
fn headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "accept",
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// The error message `method` is answered with on the read surface.
async fn refusal(path: &RequestPath, token: &str, method: &str, params: Value) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let answered = path
        .handle(
            &Method::POST,
            &headers(token),
            SURFACE_READ,
            body.to_string().as_bytes(),
        )
        .await;
    let body: Value = serde_json::from_slice(&answered.body).unwrap();
    body["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned()
}

#[tokio::test]
async fn a_failed_begin_counts_one_begin_failure_and_one_audit_failure_answer() {
    let fixture = Fixture::new().unwrap();
    let store = unreachable_store();
    let connector = Arc::new(FixtureConnector::new(Arc::new(FakeCredentialSource::new())));
    let config: gateway::Config = serde_json::from_value(support::config(&fixture)).unwrap();
    let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
        .audit_store(store.clone())
        .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources));
    let gates = boot::check(config, wiring).unwrap();
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let path = RequestPath::with_telemetry(gates, telemetry.clone());
    let metrics = Metrics::new(telemetry, Some(store));
    let token = fixture.token(Caller::TeamA);

    let called = refusal(
        &path,
        &token,
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {"document": TEAM_A_DOCUMENT}}),
    )
    .await;
    assert_eq!(called, AUDIT_FAILURE);
    assert!(connector.received().is_empty(), "the tool ran");
    let text = metrics.render();
    assert_eq!(
        total(&text, "switchboard_audit_begin_failures_total"),
        1.0,
        "{text}"
    );
    assert_eq!(
        sample(&text, "switchboard_audit_failure_answers_total"),
        Some(1.0),
        "{text}"
    );
    assert_eq!(
        sample(&text, "switchboard_audit_begin_latency_seconds_count"),
        Some(1.0),
        "{text}"
    );

    // A list whose row cannot be written is answered with the sentence too. A list row is not
    // a begin.
    let listed = refusal(&path, &token, "tools/list", json!({})).await;
    assert_eq!(listed, AUDIT_FAILURE);
    let text = metrics.render();
    assert_eq!(
        sample(&text, "switchboard_audit_failure_answers_total"),
        Some(2.0),
        "{text}"
    );
    assert_eq!(
        total(&text, "switchboard_audit_begin_failures_total"),
        1.0,
        "{text}"
    );
}

#[test]
fn a_metrics_listener_on_the_mcp_port_refuses_to_start() {
    let files = files::Files::new(
        "metrics-collision",
        &files::cluster_issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let listen_line = "listen = \"127.0.0.1:0\"\n";
    let deployment = |listen: &str, metrics: &str| {
        let text = files::deployment_file(
            "[audit]\nmode = \"disabled\"\n\n[metrics]\nlisten = \"METRICS\"\n",
        );
        assert_eq!(text.matches(listen_line).count(), 1);
        text.replace(listen_line, &format!("listen = \"{listen}\"\n"))
            .replace("METRICS", metrics)
    };
    for (listen, metrics) in [
        ("0.0.0.0:8080", "0.0.0.0:8080"),
        ("127.0.0.1:8080", "127.0.0.1:8080"),
        ("0.0.0.0:8080", "127.0.0.1:8080"),
        ("127.0.0.1:8080", "0.0.0.0:8080"),
    ] {
        files.write("gateway.toml", &deployment(listen, metrics));
        let refused = gateway::Deployment::load(&files.path("gateway.toml"), |_| None);
        assert!(
            matches!(refused, Err(DeploymentError::MetricsOnMcpListener { .. })),
            "{listen} {metrics}: {refused:?}"
        );
    }
    let said = DeploymentError::MetricsOnMcpListener {
        metrics: "0.0.0.0:8080".parse().unwrap(),
        listen: "0.0.0.0:8080".parse().unwrap(),
    }
    .to_string();
    assert!(said.contains("metrics.listen"), "{said}");

    // A port of its own, or another address's, is served; no `[metrics]` serves nothing.
    for (listen, metrics) in [
        ("0.0.0.0:8080", "0.0.0.0:9090"),
        ("127.0.0.1:8080", "10.0.0.1:8080"),
        ("127.0.0.1:0", "127.0.0.1:0"),
    ] {
        files.write("gateway.toml", &deployment(listen, metrics));
        let loaded = gateway::Deployment::load(&files.path("gateway.toml"), |_| None).unwrap();
        assert_eq!(loaded.metrics, Some(metrics.parse().unwrap()));
    }
    files.write(
        "gateway.toml",
        &files::deployment_file("[audit]\nmode = \"disabled\"\n"),
    );
    let loaded = gateway::Deployment::load(&files.path("gateway.toml"), |_| None).unwrap();
    assert_eq!(loaded.metrics, None);

    // Unknown keys are refused, as in every table.
    files.write(
        "gateway.toml",
        &files::deployment_file(
            "[audit]\nmode = \"disabled\"\n\n[metrics]\nlisten = \"127.0.0.1:0\"\npath = \"/m\"\n",
        ),
    );
    let refused = gateway::Deployment::load(&files.path("gateway.toml"), |_| None).unwrap_err();
    assert!(
        refused.to_string().contains("unknown field `path`"),
        "{refused}"
    );
}

// --- Against a database ---------------------------------------------------------------------

const URL_VARIABLE: &str = "SWITCHBOARD_TEST_DATABASE_URL";

/// Given to both audit roles on the throwaway test server. A dummy value for tests only.
const DUMMY_PASSWORD: &str = "dummy-password-for-tests-only";

async fn connect(config: &tokio_postgres::Config) -> tokio_postgres::Client {
    let (client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

#[tokio::test(flavor = "multi_thread")]
async fn the_open_rows_count_a_row_past_its_deadline() {
    let Ok(server_url) = std::env::var(URL_VARIABLE) else {
        eprintln!("skipped: {URL_VARIABLE} is not set");
        return;
    };
    let server: tokio_postgres::Config = server_url.parse().unwrap();
    let database = format!("switchboard_metrics_test_{}", std::process::id());
    let admin = connect(&server).await;
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut in_database = server.clone();
    in_database.dbname(&database);
    let setup = connect(&in_database).await;
    setup.batch_execute(ROLES).await.unwrap();
    for role in [OWNER_ROLE, GATEWAY_ROLE] {
        setup
            .batch_execute(&format!("ALTER ROLE {role} PASSWORD '{DUMMY_PASSWORD}'"))
            .await
            .unwrap();
    }
    let mut owner = in_database.clone();
    owner.user(OWNER_ROLE).password(DUMMY_PASSWORD);
    migrate(&mut connect(&owner).await).await.unwrap();

    let outcome = tokio::spawn(open_row(in_database.clone(), setup)).await;
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
        .unwrap();
    outcome.unwrap();
}

/// Begins an allowed call and leaves it unfinished, waits for its deadline to pass, then reads
/// the open rows from the endpoint.
async fn open_row(in_database: tokio_postgres::Config, setup: tokio_postgres::Client) {
    let mut as_gateway = in_database;
    as_gateway.user(GATEWAY_ROLE).password(DUMMY_PASSWORD);
    // A row begun with no call deadline is open 2 s after it begins.
    let store = Arc::new(
        PgAuditStore::connect(as_gateway, tokio_postgres::NoTls, PoolSizes::default())
            .unwrap()
            .with_budgets(Budgets {
                begin: Duration::from_secs(1),
                answer: Duration::from_secs(1),
                finish_deadline: Duration::from_secs(1),
            }),
    );
    let fixture = Fixture::new().unwrap();
    let arguments = json!({"document": TEAM_A_DOCUMENT});
    let context = CallContext {
        resources: FixtureConnector::resources_of(READ_TOOL, &arguments),
        caller: fixture.caller_context(Caller::TeamA, SURFACE_ALL).unwrap(),
        tool: RequestedTool::new(READ_TOOL),
    };
    let start = RowStart {
        call_deadline_ms: 0,
        ..row_start()
    };
    let decision = decide(&fixture.policy, &context);
    let begun = audit::begin(
        store.as_ref(),
        start,
        decision,
        arguments,
        Default::default(),
    )
    .await
    .unwrap();
    let Begun::Allowed(guard) = begun else {
        panic!("the read was denied");
    };
    let row = guard.row().clone();
    // Dropped unfinished: the row keeps an empty outcome.
    drop(guard);
    let deadline_passed = || async {
        setup
            .query_one(
                "SELECT deadline < clock_timestamp() FROM switchboard_audit.call_rows
                 WHERE id = ($1::text)::uuid",
                &[&row.as_str()],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    };
    for _ in 0..200 {
        if deadline_passed().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(deadline_passed().await, "the row's deadline did not pass");
    let deadline: std::time::SystemTime = setup
        .query_one(
            "SELECT deadline FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap()
        .get(0);

    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let (address, _stop) = serve(Metrics::new(telemetry, Some(store))).await;
    let text = until_scraped(address, "the open row counted", |text| {
        sample(text, "switchboard_audit_open_rows") == Some(1.0)
    })
    .await;
    let oldest = sample(&text, "switchboard_audit_oldest_open_row_deadline_seconds").unwrap();
    let expected = deadline
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!((oldest - expected).abs() < 1e-3, "{oldest} {expected}");
    assert_eq!(
        sample(&text, "switchboard_audit_open_rows_poll_failures_total"),
        Some(0.0),
        "{text}"
    );
}
