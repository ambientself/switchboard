//! The gateway-level bound around a connector in the gateway's own process, and the rate
//! quotas it shares with proxied servers (decision 0014, sections 1 and 2; #12): a scripted
//! in-process connector told to answer late or too large, behind the boot gates and the request
//! path, with the testkit's policy, issuers and audit store.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway::path::RequestPath;
use gateway::{
    BootError, Config, InProcessLimits, InProcessSignals, Metrics, Rate, RateQuotas,
    TELEMETRY_QUEUE, Telemetry, Wiring, boot, server_over_quota, team_over_quota,
};
use gateway_core::audit::Outcome;
use gateway_core::{
    BoxFuture, Classification, Connector, ErrorKind, ReceiptState, ToolCall, ToolOutcome,
    VendorReference,
};
use gateway_mcp::{DENIAL_CODE, TOOL_USE_ID_META};
use gateway_testkit::{
    CONNECTOR, Caller, DRAFT_TOOL, Fixture, GROUP_G_DOCUMENT, InMemoryAuditStore, READ_TOOL,
    SURFACE_ALL, SURFACE_READ, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT, fresh_key,
};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};
use support::{FixtureResources, eventually};

/// The deadline the tests that wait for one give the connector.
const DEADLINE: Duration = Duration::from_millis(200);

/// What the scripted connector does with its next calls.
#[derive(Clone, Copy, Debug)]
enum Script {
    /// Answers at once with a short text.
    Answer,
    /// Answers after the given time.
    Late(Duration),
    /// Answers at once with a text of the given length.
    Long(usize),
}

/// An in-process connector that does what its script says. A read answers `ok` with a text;
/// any other tool, a side effect, answers as the vendor confirmed it, with a reference.
struct Scripted {
    script: Mutex<Script>,
    started: AtomicUsize,
    finished: AtomicUsize,
}

impl Scripted {
    fn new() -> Self {
        Self {
            script: Mutex::new(Script::Answer),
            started: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
        }
    }

    fn script(&self, script: Script) {
        *self.script.lock().unwrap() = script;
    }

    fn started(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    fn finished(&self) -> usize {
        self.finished.load(Ordering::SeqCst)
    }
}

impl Connector for Scripted {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let script = *self.script.lock().unwrap();
        let read = call.tool().classification == Classification::Read;
        self.started.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let text = match script {
                Script::Answer => "answered".to_owned(),
                Script::Late(after) => {
                    tokio::time::sleep(after).await;
                    "answered late".to_owned()
                }
                Script::Long(length) => "x".repeat(length),
            };
            self.finished.fetch_add(1, Ordering::SeqCst);
            let result = json!({"text": text});
            if read {
                ToolOutcome::Ok(result)
            } else {
                ToolOutcome::Completed(result, VendorReference::new("draft-7"))
            }
        })
    }
}

/// The testkit's world behind the request path, with the scripted connector in the fixture
/// connector's place.
struct World {
    fixture: Fixture,
    store: Arc<InMemoryAuditStore>,
    connector: Arc<Scripted>,
    signals: Arc<InProcessSignals>,
    path: RequestPath,
}

impl World {
    fn new(wire: impl FnOnce(Wiring) -> Wiring) -> Self {
        Self::booted(wire).unwrap()
    }

    fn booted(wire: impl FnOnce(Wiring) -> Wiring) -> Result<Self, BootError> {
        let fixture = Fixture::new().unwrap();
        let store = Arc::new(InMemoryAuditStore::new());
        let connector = Arc::new(Scripted::new());
        let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
            .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources))
            .audit_store(store.clone());
        let config: Config = serde_json::from_value(support::config(&fixture)).unwrap();
        let gates = boot::check(config, wire(wiring))?;
        Ok(Self {
            fixture,
            store,
            connector,
            signals: gates.in_process_signals(),
            path: RequestPath::new(gates),
        })
    }

    /// A `tools/call` of `tool` from `caller` on `surface`, naming `document`, with a fresh
    /// tool-use identifier, which is the key a call of a tool not classified `read` needs.
    async fn call(&self, caller: Caller, surface: &str, tool: &str, document: &str) -> Value {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let bearer = format!("Bearer {}", self.fixture.token(caller));
        headers.insert("authorization", HeaderValue::from_str(&bearer).unwrap());
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": Fixture::arguments_naming(document),
                "_meta": {TOOL_USE_ID_META: fresh_key().as_str()},
            },
        });
        let response = self
            .path
            .handle(
                &Method::POST,
                &headers,
                surface,
                body.to_string().as_bytes(),
            )
            .await;
        assert_eq!(response.status, 200, "{response:?}");
        serde_json::from_slice(&response.body).unwrap()
    }

    /// The outcome the row at `position` was completed with.
    fn outcome(&self, position: usize) -> Option<Outcome> {
        self.store
            .row(position)
            .expect("the row exists")
            .completion
            .map(|completion| completion.outcome)
    }

    /// The state of the `nth` receipt reserved, as the store holds it, not as a reader would
    /// see a `pending` one past its deadline. Only a call of a tool not classified `read`
    /// reserves one.
    fn held_receipt(&self, nth: usize) -> ReceiptState {
        self.store
            .held_receipts()
            .get(nth)
            .expect("the receipt was reserved")
            .state
    }
}

/// The text of a result marked as an error.
fn tool_error(body: &Value) -> String {
    assert_eq!(body["result"]["isError"], json!(true), "{body}");
    body["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The sentence of a refusal.
fn refusal(body: &Value) -> String {
    assert_eq!(body["error"]["code"], json!(DENIAL_CODE), "{body}");
    body["error"]["message"].as_str().unwrap().to_owned()
}

fn bounded(deadline: Duration, max_result_bytes: usize) -> impl FnOnce(Wiring) -> Wiring {
    move |wiring| {
        wiring.in_process_limits(
            CONNECTOR,
            InProcessLimits {
                deadline,
                max_result_bytes,
            },
        )
    }
}

fn quotas(server: (u32, u32), team: (u32, u32)) -> impl FnOnce(Wiring) -> Wiring {
    move |wiring| {
        wiring.quotas(RateQuotas {
            per_server: Rate {
                per_minute: server.0,
                burst: server.1,
            },
            per_team_per_server: Rate {
                per_minute: team.0,
                burst: team.1,
            },
        })
    }
}

// --- The deadline ---------------------------------------------------------------------------

/// A read that has not finished by its deadline is cancelled, and is an error of the kind
/// `oversized_or_late_read`, never cut short silently.
#[tokio::test]
async fn a_late_read_is_an_oversized_or_late_read_error_and_is_cancelled() {
    let world = World::new(bounded(DEADLINE, 1024 * 1024));
    world.connector.script(Script::Late(Duration::from_secs(2)));
    let started = std::time::Instant::now();
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    let took = started.elapsed();
    assert_eq!(tool_error(&body), gateway::bound::LATE);
    assert!(took >= DEADLINE, "answered in {took:?}");
    assert!(took < Duration::from_secs(2), "answered in {took:?}");
    assert_eq!(
        world.outcome(0),
        Some(Outcome::Error {
            error_kind: ErrorKind::OversizedOrLateRead
        })
    );
    // The read was dropped at the deadline: it never finishes.
    tokio::time::sleep(Duration::from_millis(2200).saturating_sub(took)).await;
    assert_eq!(world.connector.started(), 1);
    assert_eq!(world.connector.finished(), 0);
    let counts = world.signals.counts();
    assert_eq!((counts.late, counts.oversized), (1, 0));
}

/// A side effect that has not finished by its deadline is answered `unknown`, its row recorded
/// as `unknown` and its receipt left `unknown`. It is not cancelled: it runs to its end on a
/// task of its own (decision 0009, "Where a call runs").
#[tokio::test]
async fn a_late_side_effect_is_unknown_with_its_receipt_unknown_and_runs_to_its_end() {
    let world = World::new(bounded(DEADLINE, 1024 * 1024));
    world.connector.script(Script::Late(DEADLINE * 3));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, TEAM_A_DOCUMENT)
        .await;
    let sentence = tool_error(&body);
    assert!(sentence.contains("may have taken effect"), "{sentence}");
    assert_eq!(world.outcome(0), Some(Outcome::Unknown));
    assert_eq!(world.held_receipt(0), ReceiptState::Unknown);
    assert_eq!(world.connector.finished(), 0, "answered before it finished");
    eventually("the late side effect ran to its end", || {
        world.connector.finished() == 1
    })
    .await;
    // Its end changes nothing recorded: the receipt waits for reconciliation.
    assert_eq!(world.outcome(0), Some(Outcome::Unknown));
    assert_eq!(world.held_receipt(0), ReceiptState::Unknown);
    let counts = world.signals.counts();
    assert_eq!((counts.late, counts.oversized), (1, 0));
}

/// A call that finishes within its deadline is answered as the connector answered it, and a
/// row's deadline includes the bound's.
#[tokio::test]
async fn a_call_within_its_bound_is_answered_as_the_connector_answered() {
    let world = World::new(bounded(Duration::from_secs(7), 1024 * 1024));
    world
        .connector
        .script(Script::Late(Duration::from_millis(50)));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(world.outcome(0), Some(Outcome::Ok));
    assert_eq!(world.store.row(0).unwrap().call_deadline_ms, 7_000);
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(world.held_receipt(0), ReceiptState::Completed);
    assert_eq!(world.signals.counts(), Default::default());
}

// --- The size bound -------------------------------------------------------------------------

/// A result over the size bound, counted as its JSON text, is discarded: from a read an error
/// of the kind `oversized_or_late_read`, from a side effect `unknown` with its receipt
/// `unknown`, though the vendor confirmed it. A result at the bound passes.
#[tokio::test]
async fn an_oversized_result_is_an_error_from_a_read_and_unknown_from_a_side_effect() {
    // `{"text":"xxxx"}` is 11 bytes and four more.
    let world = World::new(bounded(Duration::from_secs(5), 15));
    world.connector.script(Script::Long(4));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(world.outcome(0), Some(Outcome::Ok));

    world.connector.script(Script::Long(5));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(tool_error(&body), gateway::bound::TOO_LARGE);
    assert_eq!(
        world.outcome(1),
        Some(Outcome::Error {
            error_kind: ErrorKind::OversizedOrLateRead
        })
    );

    let body = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, TEAM_A_DOCUMENT)
        .await;
    let sentence = tool_error(&body);
    assert!(sentence.contains("may have taken effect"), "{sentence}");
    assert_eq!(world.outcome(2), Some(Outcome::Unknown));
    assert_eq!(world.held_receipt(0), ReceiptState::Unknown);
    let counts = world.signals.counts();
    assert_eq!((counts.late, counts.oversized), (0, 2));
}

/// With no limits wired, a connector in the gateway's own process has the defaults: 5 s, and
/// a result of 1 MiB.
#[tokio::test]
async fn the_default_bound_is_five_seconds_and_one_mebibyte() {
    let world = World::new(|wiring| wiring);
    // `{"text":"…"}` with 1 MiB of text is over 1 MiB.
    world.connector.script(Script::Long(1024 * 1024));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(tool_error(&body), gateway::bound::TOO_LARGE);
    world.connector.script(Script::Long(1024 * 1024 - 11));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    assert_eq!(world.store.row(1).unwrap().call_deadline_ms, 5_000);
}

/// The boot gates refuse a bound of zero, or past decision 0014's ceilings of 60 s and 1 MiB.
#[test]
fn a_bound_past_its_ceilings_or_zero_refuses_to_boot() {
    for (deadline, bytes) in [
        (Duration::from_secs(61), 1),
        (Duration::ZERO, 1),
        (Duration::from_secs(1), 1024 * 1024 + 1),
        (Duration::from_secs(1), 0),
    ] {
        let refused = World::booted(bounded(deadline, bytes)).err().unwrap();
        assert!(
            matches!(refused, BootError::InProcessLimitsOutOfRange { .. }),
            "{refused}"
        );
    }
    let refused = World::booted(|wiring| wiring.call_deadline(CONNECTOR, Duration::from_secs(61)))
        .err()
        .unwrap();
    assert!(
        matches!(refused, BootError::InProcessLimitsOutOfRange { .. }),
        "{refused}"
    );
    assert!(World::booted(bounded(Duration::from_secs(60), 1024 * 1024)).is_ok());
}

// --- The rate quotas ------------------------------------------------------------------------

/// A call over its server's quota is refused with the server's sentence, recorded on its row,
/// and the connector is not called.
#[tokio::test]
async fn a_call_over_the_servers_quota_is_refused_and_not_sent() {
    let world = World::new(quotas((1, 2), (60, 60)));
    for _ in 0..2 {
        let body = world
            .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
            .await;
        assert!(body.get("error").is_none(), "{body}");
    }
    let body = world
        .call(Caller::TeamB, SURFACE_ALL, READ_TOOL, TEAM_B_DOCUMENT)
        .await;
    let sentence = server_over_quota(CONNECTOR, READ_TOOL);
    assert_eq!(refusal(&body), sentence);
    assert_eq!(world.outcome(2), Some(Outcome::Refused { sentence }));
    assert_eq!(world.connector.started(), 2);
    let counts = world.signals.counts();
    assert_eq!((counts.over_quota_server, counts.over_quota_team), (1, 0));
}

/// A team over its quota on a server is refused with the team's sentence, and another team is
/// still served.
#[tokio::test]
async fn a_team_over_its_quota_is_refused_and_other_teams_are_served() {
    let world = World::new(quotas((60, 60), (1, 1)));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert!(body.get("error").is_none(), "{body}");
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    let sentence = team_over_quota(CONNECTOR, READ_TOOL);
    assert_eq!(refusal(&body), sentence);
    assert_eq!(world.outcome(1), Some(Outcome::Refused { sentence }));
    let body = world
        .call(Caller::TeamB, SURFACE_ALL, READ_TOOL, TEAM_B_DOCUMENT)
        .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(world.connector.started(), 2);
    let counts = world.signals.counts();
    assert_eq!((counts.over_quota_server, counts.over_quota_team), (0, 1));
}

/// A caller with no team, a user, is held by the server's quota alone.
#[tokio::test]
async fn a_caller_with_no_team_meets_only_the_servers_quota() {
    let world = World::new(quotas((1, 3), (1, 1)));
    for _ in 0..3 {
        let body = world
            .call(
                Caller::UserInGroupG,
                SURFACE_READ,
                READ_TOOL,
                GROUP_G_DOCUMENT,
            )
            .await;
        assert!(body.get("error").is_none(), "{body}");
    }
    let body = world
        .call(
            Caller::UserInGroupG,
            SURFACE_READ,
            READ_TOOL,
            GROUP_G_DOCUMENT,
        )
        .await;
    assert_eq!(refusal(&body), server_over_quota(CONNECTOR, READ_TOOL));
    assert_eq!(world.connector.started(), 3);
}

/// A side effect over a quota was not sent, so its receipt is settled `not_performed`.
#[tokio::test]
async fn a_side_effect_over_a_quota_settles_its_receipt_not_performed() {
    let world = World::new(quotas((60, 60), (1, 1)));
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, TEAM_A_DOCUMENT)
        .await;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(world.held_receipt(0), ReceiptState::Completed);
    let body = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, TEAM_A_DOCUMENT)
        .await;
    let sentence = team_over_quota(CONNECTOR, DRAFT_TOOL);
    assert_eq!(refusal(&body), sentence);
    assert_eq!(world.outcome(1), Some(Outcome::Refused { sentence }));
    assert_eq!(world.held_receipt(1), ReceiptState::NotPerformed);
    assert_eq!(world.connector.started(), 1);
}

/// A quota refills at its rate: a call refused for now is served once a token has come back.
#[tokio::test]
async fn a_quota_refills_at_its_rate() {
    // 600 a minute: a token every 100 ms.
    let world = World::new(quotas((600, 1), (600, 600)));
    let read = || world.call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT);
    assert!(read().await.get("error").is_none());
    assert_eq!(
        refusal(&read().await),
        server_over_quota(CONNECTOR, READ_TOOL)
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(read().await.get("error").is_none());
    assert_eq!(world.connector.started(), 2);
}

// --- The metrics ----------------------------------------------------------------------------

/// The metrics listener counts quota refusals by scope, and bound breaches by kind, each from
/// zero.
#[tokio::test]
async fn the_metrics_count_quota_refusals_by_scope_and_breaches_by_kind() {
    let (telemetry, _drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let world = World::new(|wiring| quotas((60, 60), (1, 1))(bounded(DEADLINE, 15)(wiring)));
    let rendered = Metrics::new(telemetry.clone(), None)
        .with_in_process(world.signals.clone())
        .render();
    for line in [
        "switchboard_calls_over_quota_total{scope=\"server\"} 0",
        "switchboard_calls_over_quota_total{scope=\"team\"} 0",
        "switchboard_in_process_bound_breaches_total{kind=\"late\"} 0",
        "switchboard_in_process_bound_breaches_total{kind=\"oversized\"} 0",
    ] {
        assert!(
            rendered.lines().any(|got| got == line),
            "{line}\n{rendered}"
        );
    }

    world.connector.script(Script::Long(100));
    world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
        .await;
    world.connector.script(Script::Late(Duration::from_secs(1)));
    world
        .call(Caller::TeamB, SURFACE_ALL, READ_TOOL, TEAM_B_DOCUMENT)
        .await;
    let rendered = Metrics::new(telemetry, None)
        .with_in_process(world.signals.clone())
        .render();
    for line in [
        "switchboard_calls_over_quota_total{scope=\"server\"} 0",
        "switchboard_calls_over_quota_total{scope=\"team\"} 1",
        "switchboard_in_process_bound_breaches_total{kind=\"late\"} 1",
        "switchboard_in_process_bound_breaches_total{kind=\"oversized\"} 1",
    ] {
        assert!(
            rendered.lines().any(|got| got == line),
            "{line}\n{rendered}"
        );
    }
}
