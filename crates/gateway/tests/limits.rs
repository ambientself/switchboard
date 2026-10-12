//! Decision 0014's limits, against scripted servers that hang or answer: the instance's cap on
//! requests in flight, each server's and each team's cap on calls in flight, the team's slot
//! given back when the server's cap refuses, a hanging server isolated by them, the slots freed
//! at the deadline, the argument check before any slot is taken, the caps and each server's
//! bounds from the deployment file, their ceilings, and the signals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use connector_proxy::{FileCredentials, ProxyConnector, Upstream, outcome};
use files::{AUDIENCE, Answered, Files, TEAM_A_SA, TEAM_B_SA, cluster_issuer, deployment_file};
use gateway::Gates;
use gateway::boot::{self, Settings, Wiring};
use gateway::path::RequestPath;
use gateway::start::{StartError, prepare};
use gateway::{
    AT_CAPACITY, AuditSection, Bulkhead, DeploymentError, Metrics, ProxiedSignals, TELEMETRY_QUEUE,
    Telemetry, Timeouts, invalid_argument, serve_with_telemetry, server_at_capacity,
    team_at_capacity,
};
use gateway_core::audit::{Completion, Outcome};
use gateway_core::{ConnectorName, ErrorKind, InstanceName};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::{InMemoryAuditStore, LocalIssuer};
use serde_json::{Value, json};
use support::{Http, eventually, exchange, legacy};
use tokio::net::TcpListener;

/// The server that hangs, and its tool.
const SLOW: &str = "slow";
const SLOW_TOOL: &str = "slow__read";
/// The server that answers, and its tool.
const OTHER: &str = "other";
const OTHER_TOOL: &str = "other__read";

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

fn token(subject: &str) -> String {
    files::kubernetes_token(issuer(), subject, &[AUDIENCE])
}

/// Calls `tool` on this file's surface, `docs`.
async fn call(path: &RequestPath, token: &str, tool: &str, arguments: Value) -> Answered {
    files::call_on(path, "docs", token, tool, arguments).await
}

/// The credential reference of `server`: the deployment file names one file for each, as it
/// does for the demo's two entries.
fn reference(server: &str) -> &'static str {
    if server == SLOW {
        "docs-team-a-credential"
    } else {
        "docs-team-b-credential"
    }
}

/// A proxied server on loopback that counts each `tools/call` it receives, and then either
/// never answers or answers with a text of `answer_bytes` bytes. Anything else, such as the
/// drift pass's `tools/list`, it answers at once with 404, which the pass takes as a failed
/// poll that withdraws nothing.
struct Scripted {
    url: String,
    received: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct Script {
    received: Arc<AtomicUsize>,
    answer_bytes: Option<usize>,
}

async fn answer(State(script): State<Script>, body: Bytes) -> Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    if request["method"] != json!("tools/call") {
        return http::StatusCode::NOT_FOUND.into_response();
    }
    script.received.fetch_add(1, Ordering::SeqCst);
    let Some(size) = script.answer_bytes else {
        return std::future::pending().await;
    };
    let answer = json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {"content": [{"type": "text", "text": "x".repeat(size)}], "isError": false},
    });
    (
        [(http::header::CONTENT_TYPE, "application/json")],
        answer.to_string(),
    )
        .into_response()
}

impl Scripted {
    async fn start(answer_bytes: Option<usize>) -> Self {
        let received = Arc::new(AtomicUsize::new(0));
        let script = Script {
            received: received.clone(),
            answer_bytes,
        };
        let router = Router::new().route("/mcp", post(answer)).with_state(script);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { url, received }
    }

    /// One that never answers.
    async fn hanging() -> Self {
        Self::start(None).await
    }

    /// One that answers at once.
    async fn answering() -> Self {
        Self::start(Some(16)).await
    }

    fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

/// A registry of the two servers, each with one read tool that takes one string argument and
/// names no resources, served on the surface `docs` to team-a and team-b. Each server's
/// identity is its address's host, its credential is one of the two the deployment file names,
/// and its tool's approval binds that entry.
fn registry_text(slow_url: &str, other_url: &str) -> String {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"n": {"type": "string"}},
    });
    let sha = gateway_registry::definition_sha256("read", None, "Reads.", &schema);
    let entry = |name: &str, url: &str| gateway_registry::Server {
        name: name.into(),
        system: name.into(),
        owner: "platform".into(),
        identity: gateway_registry::address_host(url).unwrap().to_owned(),
        address: url.to_owned(),
        credential: gateway_registry::Credential {
            mode: gateway_core::CredentialMode::GatewayToken,
            reference: reference(name).into(),
            principal: name.into(),
        },
        narrowing: gateway_core::Narrowing::None,
        permits: gateway_core::Classification::Read,
        reach: Default::default(),
        reach_test: None,
        destination: gateway_registry::Destination::InCluster,
        probe: None,
        reach_check: None,
    };
    let server = |name: &str, url: &str| {
        let identity = entry(name, url).identity;
        let reference = reference(name);
        format!(
            "[[servers]]\nname = \"{name}\"\nsystem = \"{name}\"\nowner = \"platform\"\n\
             identity = \"{identity}\"\naddress = \"{url}\"\n\
             credential = {{ mode = \"gateway_token\", reference = \"{reference}\", principal = \"{name}\" }}\n\
             narrowing = \"none\"\npermits = \"read\"\nreach = []\ndestination = \"in_cluster\"\n\n"
        )
    };
    let tool = |name: &str, url: &str| {
        let binding = gateway_registry::binding_sha256(&entry(name, url));
        format!(
            "[[tools]]\nname = \"{name}__read\"\nserver = \"{name}\"\nupstream_name = \"read\"\n\
             classification = \"read\"\ndescription = \"Reads.\"\n\
             approved_by = \"approver@example.test\"\napproved_at = 2026-10-06T00:00:00Z\n\
             definition_sha256 = \"{sha}\"\nbinding_sha256 = \"{binding}\"\n\
             resources = \"no_resources\"\n\n\
             [tools.input_schema]\ntype = \"object\"\nadditionalProperties = false\n\n\
             [tools.input_schema.properties.n]\ntype = \"string\"\n\n"
        )
    };
    format!(
        "revision = \"limits-1\"\n\n{}{}{}{}\
         [[surfaces]]\nname = \"docs\"\ntools = [\"{SLOW_TOOL}\", \"{OTHER_TOOL}\"]\n\
         teams = [\"team-a\", \"team-b\"]\nprincipals = \"any_in_teams_and_groups\"\n\n\
         [[profiles]]\nname = \"workload-read\"\nclassifications = [\"read\"]\n\
         requires_delegation = false\n\n\
         [[profile_rules]]\nissuer = \"{}\"\nprincipal = \"workload\"\nprofile = \"workload-read\"\n\n\
         [limits]\n",
        server(SLOW, slow_url),
        server(OTHER, other_url),
        tool(SLOW, slow_url),
        tool(OTHER, other_url),
        files::CLUSTER_ISSUER,
    )
}

/// What a test reads back: the audit store, the two servers and the bulkheads' signals.
struct Upstreams {
    store: Arc<InMemoryAuditStore>,
    slow: Scripted,
    other: Scripted,
    signals: ProxiedSignals,
    _files: Files,
}

/// The two servers, the slow one hanging, behind bulkheads with `per_server` and `per_team`
/// caps and calls bounded at `deadline`, wired as `start` wires them, over an in-memory audit
/// store so the rows can be read.
async fn wired(
    name: &str,
    per_server: usize,
    per_team: usize,
    deadline: Duration,
) -> (Gates, Upstreams) {
    let slow = Scripted::hanging().await;
    let other = Scripted::answering().await;
    let files = Files::new(name, &issuer().jwks_document(), &slow.url);
    let deployment = files.load();
    let settings = Settings {
        deployment: deployment.deployment,
        identity: deployment.identity,
        audit: AuditSection { disabled: false },
        http: deployment.http,
        max_age: None,
        read_at: Instant::now(),
    };
    let registry = Registry::from_toml_str(&registry_text(&slow.url, &other.url)).unwrap();
    let credentials = Arc::new(
        FileCredentials::load([
            (SLOW.into(), files.path(reference(SLOW))),
            (OTHER.into(), files.path(reference(OTHER))),
        ])
        .unwrap(),
    );
    let store = Arc::new(InMemoryAuditStore::new());
    let mut wiring = Wiring::new(Arc::new(SystemClock)).audit_store(store.clone());
    let mut signals = BTreeMap::new();
    for (server, url, tool) in [
        (SLOW, &slow.url, SLOW_TOOL),
        (OTHER, &other.url, OTHER_TOOL),
    ] {
        let mut upstream = Upstream::new(server, url.clone()).tool(tool.parse().unwrap(), "read");
        upstream.deadline = deadline;
        let connector = ProxyConnector::new(upstream, credentials.clone()).unwrap();
        let bulkhead = Bulkhead::new(server.into(), Arc::new(connector), per_server, per_team);
        signals.insert(ConnectorName::new(server), bulkhead.signals());
        wiring = wiring
            .proxied(server, Arc::new(bulkhead))
            .call_deadline(server, deadline);
    }
    let (gates, _reloader) = boot::check_registry(settings, registry, wiring).unwrap();
    let upstreams = Upstreams {
        store,
        slow,
        other,
        signals: ProxiedSignals::new(signals),
        _files: files,
    };
    (gates, upstreams)
}

/// [`wired`], called through the request path.
struct World {
    path: RequestPath,
    up: Upstreams,
}

impl World {
    async fn new(name: &str, per_server: usize, per_team: usize, deadline: Duration) -> Self {
        let (gates, up) = wired(name, per_server, per_team, deadline).await;
        Self {
            path: RequestPath::new(gates),
            up,
        }
    }

    /// Calls `tool` as `subject`'s team on a task of its own.
    fn spawn_call(
        &self,
        subject: &'static str,
        tool: &'static str,
    ) -> tokio::task::JoinHandle<Answered> {
        let path = self.path.clone();
        tokio::spawn(async move { call(&path, &token(subject), tool, json!({"n": "1"})).await })
    }

    async fn call(&self, subject: &str, tool: &str) -> Answered {
        call(&self.path, &token(subject), tool, json!({"n": "1"})).await
    }

    /// The completion of every row whose tool is `tool`, in the order they were begun.
    fn completions(&self, tool: &str) -> Vec<Option<Completion>> {
        self.up
            .store
            .rows()
            .into_iter()
            .filter(|row| row.tool == tool)
            .map(|row| row.completion)
            .collect()
    }
}

/// The capacity sentence, or any other refusal, the caller read.
fn refusal(answered: &Answered) -> String {
    assert_eq!(answered.status, 200, "{}", answered.body);
    answered.body["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("not a refusal: {}", answered.body))
        .to_owned()
}

/// The text of a tool result that is an error.
fn tool_error(answered: &Answered) -> String {
    assert_eq!(
        answered.body["result"]["isError"],
        json!(true),
        "{}",
        answered.body
    );
    answered.body["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn is_ok(answered: &Answered) -> bool {
    answered.body["result"]["isError"] == json!(false)
}

fn refused_with(sentence: String) -> Outcome {
    Outcome::Refused { sentence }
}

fn outcome_of(completion: &Option<Completion>) -> Option<&Outcome> {
    completion.as_ref().map(|completion| &completion.outcome)
}

/// `gates` served over HTTP on loopback with at most `max_in_flight` requests in flight: its
/// address, and the telemetry it counts in.
async fn serve(gates: Gates, max_in_flight: usize) -> (SocketAddr, Telemetry) {
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
        max_in_flight,
    ));
    (address, telemetry)
}

/// The bytes of an HTTP request that calls `tool` on the surface `docs` as `subject`.
fn http_call(subject: &str, tool: &str) -> Vec<u8> {
    let body = legacy("tools/call", json!({"name": tool, "arguments": {"n": "1"}}))
        .to_string()
        .into_bytes();
    let http = Http::new("POST", "/mcp/docs")
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .bearer(&token(subject))
        .header("content-length", &body.len().to_string())
        .body(body);
    let mut bytes = http.head();
    bytes.extend_from_slice(&http.body);
    bytes
}

/// Decision 0014, section 2: a request over the instance's cap is answered 503 before its body
/// is read, with `Retry-After`, a `call_shed` event and no row. The slots are the answer tasks'
/// until they end, so the calls holding them complete and the next request is served.
#[tokio::test]
async fn the_instance_cap_sheds_with_503_and_no_row() {
    let (gates, world) = wired("instance", 32, 8, Duration::from_secs(3)).await;
    let (address, telemetry) = serve(gates, 2).await;
    let hanging: Vec<_> = (0..2)
        .map(|_| {
            let bytes = http_call(TEAM_A_SA, SLOW_TOOL);
            tokio::spawn(async move { exchange(address, &bytes).await })
        })
        .collect();
    eventually("both calls reach the hanging server", || {
        world.slow.received() == 2
    })
    .await;
    let rows = world.store.rows().len();

    let shed = exchange(address, &http_call(TEAM_B_SA, OTHER_TOOL)).await;
    assert_eq!(shed.status, 503, "{shed:?}");
    assert_eq!(shed.header("retry-after"), Some("1"));
    assert_eq!(shed.error_message(), AT_CAPACITY);
    assert_eq!(world.store.rows().len(), rows, "the shed request has a row");
    assert_eq!(world.other.received(), 0, "the shed request was sent");
    assert_eq!(telemetry.counts().calls_shed, 1);
    let rendered = Metrics::new(telemetry.clone(), None).render();
    assert!(
        rendered.contains("switchboard_calls_shed_total{scope=\"instance\"} 1\n"),
        "{rendered}"
    );

    // The two calls end at their deadline, and their slots with them.
    for answer in hanging {
        let answer = answer.await.unwrap();
        assert_eq!(answer.status, 200, "{answer:?}");
    }
    let served = exchange(address, &http_call(TEAM_B_SA, OTHER_TOOL)).await;
    assert_eq!(served.status, 200, "{served:?}");
    assert_eq!(
        served.json()["result"]["isError"],
        json!(false),
        "{served:?}"
    );
    assert_eq!(telemetry.counts().calls_shed, 1);
}

/// One call past the server's cap is refused with the capacity sentence and nothing sent, and
/// its row records the refusal and the sentence. The slot is held until the call holding it
/// ends at its deadline, and the next call is sent.
#[tokio::test]
async fn a_call_past_the_servers_cap_is_refused_with_a_row_until_the_deadline_frees_its_slot() {
    let world = World::new("server-cap", 1, 8, Duration::from_secs(1)).await;
    let holding = world.spawn_call(TEAM_A_SA, SLOW_TOOL);
    eventually("the first call reaches the hanging server", || {
        world.up.slow.received() == 1
    })
    .await;

    let refused = world.call(TEAM_B_SA, SLOW_TOOL).await;
    assert_eq!(refusal(&refused), server_at_capacity(SLOW, SLOW_TOOL));
    assert_eq!(world.up.slow.received(), 1, "the refused call was sent");

    let late = holding.await.unwrap();
    assert_eq!(tool_error(&late), outcome::TIMED_OUT);
    let after = world.call(TEAM_B_SA, SLOW_TOOL).await;
    assert_eq!(tool_error(&after), outcome::TIMED_OUT);
    assert_eq!(
        world.up.slow.received(),
        2,
        "the call after the deadline was not sent"
    );

    let completions = world.completions(SLOW_TOOL);
    assert_eq!(completions.len(), 3);
    let late_read = Outcome::Error {
        error_kind: ErrorKind::OversizedOrLateRead,
    };
    assert_eq!(outcome_of(&completions[0]), Some(&late_read));
    assert_eq!(
        outcome_of(&completions[1]),
        Some(&refused_with(server_at_capacity(SLOW, SLOW_TOOL)))
    );
    assert_eq!(outcome_of(&completions[2]), Some(&late_read));
    let counts = world.up.signals.counts();
    assert_eq!(counts[1].0.as_str(), SLOW);
    assert_eq!((counts[1].1.shed_server, counts[1].1.shed_team), (1, 0));
}

/// A call the server's cap refuses gives back the team slot it took first. Team-b fills the
/// server's cap of 2, and team-a's call is refused at it. Once team-b's calls end at their
/// deadline, team-a still has its whole cap of 2: both of its calls are sent at once.
#[tokio::test]
async fn a_call_refused_at_the_servers_cap_gives_back_its_teams_slot() {
    let world = World::new("team-slot", 2, 2, Duration::from_secs(1)).await;
    let team_b: Vec<_> = (0..2)
        .map(|_| world.spawn_call(TEAM_B_SA, SLOW_TOOL))
        .collect();
    eventually("team-b's two calls reach the hanging server", || {
        world.up.slow.received() == 2
    })
    .await;

    let refused = world.call(TEAM_A_SA, SLOW_TOOL).await;
    assert_eq!(refusal(&refused), server_at_capacity(SLOW, SLOW_TOOL));
    assert_eq!(world.up.slow.received(), 2, "the refused call was sent");
    for call in team_b {
        assert_eq!(tool_error(&call.await.unwrap()), outcome::TIMED_OUT);
    }

    let first = world.spawn_call(TEAM_A_SA, SLOW_TOOL);
    eventually("team-a's first call reaches the hanging server", || {
        world.up.slow.received() == 3
    })
    .await;
    let second = world.call(TEAM_A_SA, SLOW_TOOL).await;
    assert_eq!(tool_error(&second), outcome::TIMED_OUT);
    assert_eq!(tool_error(&first.await.unwrap()), outcome::TIMED_OUT);
    assert_eq!(
        world.up.slow.received(),
        4,
        "team-a's second call was not sent"
    );
    let counts = world.up.signals.counts();
    assert_eq!((counts[1].1.shed_server, counts[1].1.shed_team), (1, 0));
}

/// Isolation: a hanging server holds team-a to its cap of 8 calls to it, and refuses team-a's
/// ninth with the team's capacity sentence. Team-b's call to the same server is still sent, and
/// team-a's call to another server is answered.
#[tokio::test]
async fn a_hanging_server_holds_one_team_to_its_cap_and_holds_up_no_one_else() {
    let world = World::new(
        "isolation",
        gateway::DEFAULT_PER_SERVER_IN_FLIGHT,
        gateway::DEFAULT_PER_TEAM_PER_SERVER_IN_FLIGHT,
        Duration::from_secs(5),
    )
    .await;
    let hanging: Vec<_> = (0..8)
        .map(|_| world.spawn_call(TEAM_A_SA, SLOW_TOOL))
        .collect();
    eventually("team-a's eight calls reach the hanging server", || {
        world.up.slow.received() == 8
    })
    .await;

    let ninth = world.call(TEAM_A_SA, SLOW_TOOL).await;
    assert_eq!(refusal(&ninth), team_at_capacity(SLOW, SLOW_TOOL));
    assert_eq!(world.up.slow.received(), 8, "team-a's ninth call was sent");

    let team_b = world.spawn_call(TEAM_B_SA, SLOW_TOOL);
    eventually("team-b's call reaches the hanging server", || {
        world.up.slow.received() == 9
    })
    .await;
    let elsewhere = world.call(TEAM_A_SA, OTHER_TOOL).await;
    assert!(is_ok(&elsewhere), "{}", elsewhere.body);
    assert_eq!(world.up.other.received(), 1);

    for call in hanging {
        assert_eq!(tool_error(&call.await.unwrap()), outcome::TIMED_OUT);
    }
    assert_eq!(tool_error(&team_b.await.unwrap()), outcome::TIMED_OUT);
    let refused: Vec<Outcome> = world
        .completions(SLOW_TOOL)
        .into_iter()
        .filter_map(|completion| completion.map(|completion| completion.outcome))
        .filter(|outcome| matches!(outcome, Outcome::Refused { .. }))
        .collect();
    assert_eq!(
        refused,
        [refused_with(team_at_capacity(SLOW, SLOW_TOOL))],
        "one refusal, with the team's sentence, on its row"
    );

    // The signals, labelled by server only.
    let rendered = Metrics::new(Telemetry::detached(), None)
        .with_proxied(world.up.signals.clone())
        .render();
    for line in [
        "switchboard_calls_shed_total{scope=\"instance\"} 0",
        "switchboard_calls_shed_total{scope=\"server\"} 0",
        "switchboard_calls_shed_total{scope=\"team\"} 1",
        "switchboard_proxied_calls_total{server=\"other\",outcome=\"ok\"} 1",
        "switchboard_proxied_calls_total{server=\"slow\",outcome=\"ok\"} 0",
        "switchboard_proxied_calls_total{server=\"slow\",outcome=\"error\"} 9",
        "switchboard_proxied_calls_total{server=\"slow\",outcome=\"refused\"} 0",
        "switchboard_proxied_late_or_oversized_total{server=\"slow\"} 9",
        "switchboard_proxied_late_or_oversized_total{server=\"other\"} 0",
        "switchboard_proxied_call_seconds_bucket{server=\"slow\",le=\"2\"} 0",
        "switchboard_proxied_call_seconds_bucket{server=\"slow\",le=\"30\"} 9",
        "switchboard_proxied_call_seconds_bucket{server=\"slow\",le=\"+Inf\"} 9",
        "switchboard_proxied_call_seconds_count{server=\"slow\"} 9",
        "switchboard_proxied_call_seconds_count{server=\"other\"} 1",
    ] {
        assert!(
            rendered.lines().any(|sample| sample == line),
            "{line}\n{rendered}"
        );
    }
    for family in [
        "# TYPE switchboard_calls_shed_total counter",
        "# TYPE switchboard_proxied_calls_total counter",
        "# TYPE switchboard_proxied_call_seconds histogram",
        "# TYPE switchboard_proxied_late_or_oversized_total counter",
    ] {
        assert!(
            rendered.lines().any(|line| line == family),
            "{family}\n{rendered}"
        );
    }
    assert!(
        !rendered.contains("team-a"),
        "a team names a series:\n{rendered}"
    );
}

/// A call whose arguments fail the approved schema is an error with nothing sent, even with
/// its team's slots all taken: the check runs before any slot is taken, so it is never
/// refused for capacity, nor counted as shed.
#[tokio::test]
async fn a_call_that_fails_the_argument_check_takes_no_slot() {
    let world = World::new("arguments", 32, 1, Duration::from_secs(2)).await;
    let holding = world.spawn_call(TEAM_A_SA, SLOW_TOOL);
    eventually("the first call reaches the hanging server", || {
        world.up.slow.received() == 1
    })
    .await;

    let invalid = call(&world.path, &token(TEAM_A_SA), SLOW_TOOL, json!({"n": 1})).await;
    assert_eq!(tool_error(&invalid), invalid_argument(SLOW_TOOL));
    assert_eq!(world.up.slow.received(), 1, "the invalid call was sent");
    let completions = world.completions(SLOW_TOOL);
    assert_eq!(
        outcome_of(&completions[1]),
        Some(&Outcome::Error {
            error_kind: ErrorKind::InvalidArguments
        })
    );
    let counts = world.up.signals.counts();
    assert_eq!(
        (counts[1].1.shed_server, counts[1].1.shed_team),
        (0, 0),
        "a call that failed the check took a slot or was shed"
    );
    let _ = holding.await;
}

/// `start::prepare` builds each server's connector with the bounds the deployment file sets
/// for it, and in a bulkhead with the caps `[limits]` sets: a deadline of 1 s ends a hanging
/// call long before the default 5 s, an answer cap of 100 bytes refuses a longer answer, and
/// a team cap of 1 refuses a second call while the first runs.
#[tokio::test]
async fn the_deployment_files_bounds_and_caps_reach_the_gateway() {
    let slow = Scripted::hanging().await;
    let other = Scripted::start(Some(1000)).await;
    let files = Files::new("bounds", &issuer().jwks_document(), &slow.url);
    files.write(
        "registry/registry.toml",
        &registry_text(&slow.url, &other.url),
    );
    files.write(
        "gateway.toml",
        &deployment_file(
            "[audit]\nmode = \"disabled\"\n\n[limits]\nper_team_per_server_in_flight = 1\n\n\
             [servers.slow]\ndeadline_seconds = 1\n\n[servers.other]\nmax_result_bytes = 100\n",
        ),
    );
    let prepared = prepare(
        files.load(),
        InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap();
    let path = RequestPath::new(prepared.gates);

    let started = Instant::now();
    let holding = {
        let path = path.clone();
        tokio::spawn(
            async move { call(&path, &token(TEAM_A_SA), SLOW_TOOL, json!({"n": "1"})).await },
        )
    };
    eventually("the first call reaches the hanging server", || {
        slow.received() == 1
    })
    .await;
    let second = call(&path, &token(TEAM_A_SA), SLOW_TOOL, json!({"n": "2"})).await;
    assert_eq!(refusal(&second), team_at_capacity(SLOW, SLOW_TOOL));
    assert_eq!(tool_error(&holding.await.unwrap()), outcome::TIMED_OUT);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the hanging call took {:?}",
        started.elapsed()
    );

    let large = call(&path, &token(TEAM_A_SA), OTHER_TOOL, json!({"n": "1"})).await;
    assert_eq!(tool_error(&large), outcome::TOO_LARGE);
    assert_eq!(other.received(), 1);
    let counts = prepared.proxied.counts();
    assert_eq!(counts[1].1.shed_team, 1);
    assert_eq!(counts[0].1.late_or_oversized, 1);
    assert_eq!(prepared.max_in_flight, gateway::DEFAULT_MAX_IN_FLIGHT);
}

/// `start::prepare` holds the instance and each server to the caps `[limits]` sets, served as
/// the binary serves it, with both servers hanging. With `per_server_in_flight = 1`, team-b's
/// call to the server team-a's call holds is refused with the server's sentence. With
/// `max_in_flight = 2`, a third request while two hang is answered 503 before it is read.
#[tokio::test]
async fn the_deployment_files_caps_on_calls_in_flight_reach_the_server_and_each_bulkhead() {
    let slow = Scripted::hanging().await;
    let other = Scripted::hanging().await;
    let files = Files::new("caps", &issuer().jwks_document(), &slow.url);
    files.write(
        "registry/registry.toml",
        &registry_text(&slow.url, &other.url),
    );
    files.write(
        "gateway.toml",
        &deployment_file(
            "[audit]\nmode = \"disabled\"\n\n[limits]\nmax_in_flight = 2\nper_server_in_flight = 1\n\n\
             [servers.slow]\ndeadline_seconds = 3\n\n[servers.other]\ndeadline_seconds = 3\n",
        ),
    );
    let prepared = prepare(
        files.load(),
        InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap();
    let (address, telemetry) = serve(prepared.gates, prepared.max_in_flight).await;
    let spawn_call = |subject: &str, tool: &str| {
        let bytes = http_call(subject, tool);
        tokio::spawn(async move { exchange(address, &bytes).await })
    };

    let holding_slow = spawn_call(TEAM_A_SA, SLOW_TOOL);
    eventually("team-a's call reaches the hanging server", || {
        slow.received() == 1
    })
    .await;
    let refused = exchange(address, &http_call(TEAM_B_SA, SLOW_TOOL)).await;
    assert_eq!(refused.status, 200, "{refused:?}");
    assert_eq!(
        refused.json()["error"]["message"],
        json!(server_at_capacity(SLOW, SLOW_TOOL)),
        "{refused:?}"
    );
    assert_eq!(
        slow.received(),
        1,
        "the call over the server's cap was sent"
    );

    let holding_other = spawn_call(TEAM_B_SA, OTHER_TOOL);
    eventually("team-b's call reaches the other hanging server", || {
        other.received() == 1
    })
    .await;
    let shed = exchange(address, &http_call(TEAM_A_SA, OTHER_TOOL)).await;
    assert_eq!(shed.status, 503, "{shed:?}");
    assert_eq!(shed.error_message(), AT_CAPACITY);
    assert_eq!(
        other.received(),
        1,
        "the request over the instance's cap was sent"
    );
    assert_eq!(telemetry.counts().calls_shed, 1);

    for holding in [holding_slow, holding_other] {
        let late = holding.await.unwrap();
        assert_eq!(late.status, 200, "{late:?}");
        assert_eq!(
            late.json()["result"]["content"][0]["text"],
            json!(outcome::TIMED_OUT),
            "{late:?}"
        );
    }
    let counts = prepared.proxied.counts();
    assert_eq!((counts[1].1.shed_server, counts[1].1.shed_team), (1, 0));
    assert_eq!((counts[0].1.shed_server, counts[0].1.shed_team), (0, 0));
}

/// `[servers.<name>]` for a server the registry does not name refuses the start.
#[tokio::test]
async fn bounds_for_a_server_the_registry_lacks_refuse_the_start() {
    let files = Files::new(
        "unknown-server",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    files.write(
        "gateway.toml",
        &deployment_file(
            "[audit]\nmode = \"disabled\"\n\n[servers.mock-dcos]\ndeadline_seconds = 9\n",
        ),
    );
    let refused = prepare(
        files.load(),
        InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&refused, StartError::UnknownServerLimits(name) if name.as_str() == "mock-dcos"),
        "{refused}"
    );
}

/// The deployment file with `extra` beside its audit table, loaded.
fn load_with(name: &str, extra: &str) -> Result<gateway::Deployment, DeploymentError> {
    let files = Files::new(name, &issuer().jwks_document(), "http://127.0.0.1:9/mcp");
    files.write(
        "gateway.toml",
        &deployment_file(&format!("[audit]\nmode = \"disabled\"\n\n{extra}")),
    );
    files.load_with(&[])
}

#[test]
fn the_caps_and_each_servers_bounds_have_decision_0014s_defaults() {
    let loaded = load_with("defaults", "").unwrap();
    assert_eq!(
        loaded.limits,
        gateway::Limits {
            max_in_flight: 256,
            per_server_in_flight: 32,
            per_team_per_server_in_flight: 8,
        }
    );
    assert!(loaded.servers.is_empty());
    assert_eq!(
        gateway::ServerLimits::default(),
        gateway::ServerLimits {
            deadline: Duration::from_secs(5),
            max_result_bytes: 64 * 1024,
        }
    );
}

#[test]
fn the_caps_and_each_servers_bounds_can_be_set_up_to_their_ceilings() {
    let loaded = load_with(
        "set",
        "[limits]\nmax_in_flight = 1\nper_server_in_flight = 2\nper_team_per_server_in_flight = 3\n\n\
         [servers.mock-docs]\ndeadline_seconds = 60\nmax_result_bytes = 1048576\n\n\
         [servers.other]\ndeadline_seconds = 1\n",
    )
    .unwrap();
    assert_eq!(
        loaded.limits,
        gateway::Limits {
            max_in_flight: 1,
            per_server_in_flight: 2,
            per_team_per_server_in_flight: 3,
        }
    );
    assert_eq!(
        loaded.servers,
        BTreeMap::from([
            (
                ConnectorName::new("mock-docs"),
                gateway::ServerLimits {
                    deadline: gateway::MAX_SERVER_DEADLINE,
                    max_result_bytes: gateway::MAX_SERVER_RESULT_BYTES,
                }
            ),
            (
                ConnectorName::new("other"),
                gateway::ServerLimits {
                    deadline: Duration::from_secs(1),
                    max_result_bytes: 64 * 1024,
                }
            ),
        ])
    );
}

#[test]
fn values_past_the_ceilings_or_zero_are_refused() {
    for (extra, expected) in [
        (
            "[servers.mock-docs]\ndeadline_seconds = 61\n",
            "`servers.mock-docs.deadline_seconds` is 61; it must be from 1 to 60",
        ),
        (
            "[servers.mock-docs]\ndeadline_seconds = 0\n",
            "`servers.mock-docs.deadline_seconds` is 0; it must be from 1 to 60",
        ),
        (
            "[servers.mock-docs]\nmax_result_bytes = 1048577\n",
            "`servers.mock-docs.max_result_bytes` is 1048577; it must be from 1 to 1048576",
        ),
        (
            "[servers.mock-docs]\nmax_result_bytes = 0\n",
            "`servers.mock-docs.max_result_bytes` is 0; it must be from 1 to 1048576",
        ),
        (
            "[limits]\nmax_in_flight = 0\n",
            "`limits.max_in_flight` must be at least 1",
        ),
        (
            "[limits]\nper_server_in_flight = 0\n",
            "`limits.per_server_in_flight` must be at least 1",
        ),
        (
            "[limits]\nper_team_per_server_in_flight = 0\n",
            "`limits.per_team_per_server_in_flight` must be at least 1",
        ),
    ] {
        let refused = load_with("ceilings", extra).unwrap_err();
        assert_eq!(refused.to_string(), expected, "{extra}");
    }
    for extra in [
        "[limits]\nmax_in_flight = 1\nqueue = 4\n",
        "[servers.mock-docs]\ndeadline_seconds = 5\nretries = 2\n",
    ] {
        let refused = load_with("unknown-field", extra).unwrap_err();
        assert!(
            refused.to_string().contains("unknown field"),
            "{extra}: {refused}"
        );
    }
}
