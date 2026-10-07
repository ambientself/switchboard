//! The request path, design section 6, driven with raw MCP requests over the testkit's world
//! and no HTTP server: a method, headers and a body go in, an HTTP response comes out. The
//! futures are driven with the testkit's `block_on` and `poll_once`, so nothing here needs an
//! async runtime.
//!
//! The cases mirror the testkit's `end_to_end.rs`, which strings the core's steps together by
//! hand. Here the gateway's own path does that, from a token and a JSON-RPC body.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use gateway::{
    AUDIT_DISABLED_NOTE, Config, IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE, MAX_TOOL_USE_ID,
    RequestPath, ResourceAdapter, Wiring, boot,
};
use gateway_core::audit::{Completion, DecisionKind, Outcome};
use gateway_core::{
    ApprovedTool, AuditRecord, Classification, IDENTITY_FAILURE, ReasonKind, Resources,
};
use gateway_mcp::{
    CHALLENGE, CLIENT_CAPABILITIES_META, DENIAL_CODE, MODERN, PROTOCOL_VERSION_META,
    TOOL_USE_ID_META,
};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, DRAFT_REFUSAL, DRAFT_TOOL, FOREIGN_DRAFT, FakeCredentialSource,
    Fixture, FixtureConnector, GROUP_G, GROUP_REVIEW, InMemoryAuditStore, PROFILE_REVIEWER,
    PROFILE_TEAM_A, PROFILE_TEAM_B, PROFILE_USER, READ_TOOL, SCOPE_REFUSAL, SCOPED_READ_TOOL,
    SURFACE_ALL, SURFACE_READ, TEAM_A, TEAM_A_DOCUMENT, TEAM_A_SUBJECT, TEAM_B, TEAM_B_DOCUMENT,
    TEAM_B_SUBJECT, USER_ISSUER, USER_SUBJECT, WORKLOAD_ISSUER, WRITE_TOOL, block_on, document,
    poll_once,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde_json::{Value, json};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// The fixture connector's adapter, recording the tools it is asked about.
#[derive(Default)]
struct FixtureResources {
    asked: Mutex<Vec<String>>,
}

impl FixtureResources {
    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl ResourceAdapter for FixtureResources {
    fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
        self.asked.lock().unwrap().push(tool.name.to_string());
        FixtureConnector::resources_of(tool.name.as_str(), arguments)
    }
}

/// An adapter that always names team B's document.
struct TeamBDocument;

impl ResourceAdapter for TeamBDocument {
    fn resources(&self, _tool: &ApprovedTool, _arguments: &Value) -> Resources {
        Resources::Named(vec![document(TEAM_B_DOCUMENT)])
    }
}

/// The testkit's world behind the gateway's request path.
struct World {
    fixture: Fixture,
    store: Arc<InMemoryAuditStore>,
    credentials: Arc<FakeCredentialSource>,
    connector: Arc<FixtureConnector>,
    resources: Arc<FixtureResources>,
    path: RequestPath,
}

impl World {
    fn new() -> Self {
        Self::with(|_| {}, |wiring| wiring)
    }

    /// A world whose configuration `configure` changes and whose wiring `wire` adds to. The
    /// audit store is wired in unless the configuration disables audit.
    fn with(configure: impl FnOnce(&mut Value), wire: impl FnOnce(Wiring) -> Wiring) -> Self {
        let fixture = Fixture::new().unwrap();
        let credentials = Arc::new(FakeCredentialSource::new());
        let connector = Arc::new(FixtureConnector::new(credentials.clone()));
        let store = Arc::new(InMemoryAuditStore::new());
        let resources = Arc::new(FixtureResources::default());

        let mut config = Self::config(&fixture);
        configure(&mut config);
        let mut wiring = Wiring::new(Arc::new(fixture.clock.clone())).connector(
            CONNECTOR,
            connector.clone(),
            resources.clone(),
        );
        if config["audit"]["disabled"] != json!(true) {
            wiring = wiring.audit_store(store.clone());
        }
        let config: Config = serde_json::from_value(config).unwrap();
        let gates = boot::check(config, wire(wiring)).unwrap();
        Self {
            fixture,
            store,
            credentials,
            connector,
            resources,
            path: RequestPath::new(gates),
        }
    }

    fn config(fixture: &Fixture) -> Value {
        let issuer = |issuer: &gateway_testkit::LocalIssuer, kind: Value| {
            json!({
                "issuer": issuer.issuer(),
                "audiences": [AUDIENCE],
                "kind": kind,
                "algorithm": "ES256",
                "keys": serde_json::to_value(issuer.jwk_set()).unwrap(),
                "max_lifetime_secs": gateway_testkit::DEFAULT_MAX_LIFETIME,
                "leeway_secs": gateway_testkit::DEFAULT_LEEWAY,
            })
        };
        let definition = |name: &str| {
            json!({
                "name": name,
                "description": format!("The fixture's {name}."),
                "input_schema": {"type": "object", "properties": {"document": {"type": "string"}}},
            })
        };
        let mut read = definition(READ_TOOL);
        read["title"] = json!("Read a document");
        json!({
            "deployment": "path-test",
            "identity": {"enforce": [
                issuer(&fixture.workload_issuer, json!({"workload": {"subjects": {
                    TEAM_A_SUBJECT: TEAM_A,
                    TEAM_B_SUBJECT: TEAM_B,
                }}})),
                issuer(&fixture.user_issuer, json!({"user": {}})),
            ]},
            "audit": {},
            "http": {"allowed_hosts": ["localhost"]},
            "policy": gateway_testkit::policy_data(),
            "catalog": [
                read,
                definition(DRAFT_TOOL),
                definition(WRITE_TOOL),
                definition(SCOPED_READ_TOOL),
            ],
            "profiles": {
                "workloads": [
                    {"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": PROFILE_TEAM_A},
                    {"issuer": WORKLOAD_ISSUER, "team": TEAM_B, "profile": PROFILE_TEAM_B},
                ],
                "users": [
                    {"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_USER},
                    {"issuer": USER_ISSUER, "group": GROUP_REVIEW, "profile": PROFILE_REVIEWER},
                ],
            },
        })
    }

    fn token(&self, caller: Caller) -> String {
        self.fixture.token(caller)
    }

    /// Sends `request` with `token` as its bearer token, through the whole path.
    fn send(&self, token: Option<&str>, surface: &str, request: Raw) -> Got {
        let request = match token {
            Some(token) => request.header("authorization", &format!("Bearer {token}")),
            None => request,
        };
        Got::from(block_on(self.path.handle(
            &request.method,
            &request.headers,
            surface,
            &request.body,
        )))
    }

    /// A 2026-07-28 `tools/call` from `caller`.
    fn call(&self, caller: Caller, surface: &str, tool: &str, arguments: Value) -> Got {
        self.send(
            Some(&self.token(caller)),
            surface,
            tools_call(tool, arguments),
        )
    }

    /// Nothing reached the connector or the credential source.
    fn assert_nothing_ran(&self) {
        assert!(
            self.connector.received().is_empty(),
            "the connector received a call"
        );
        assert!(self.connector.writes().is_empty(), "a write happened");
        assert!(
            self.credentials.requests().is_empty(),
            "a credential was requested"
        );
    }

    fn row(&self, position: usize) -> AuditRecord {
        self.store.row(position).expect("the row exists")
    }
}

/// A raw request: what the HTTP layer hands the path.
#[derive(Clone, Debug)]
struct Raw {
    method: Method,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Raw {
    fn post(body: impl Into<Vec<u8>>) -> Self {
        Raw {
            method: Method::POST,
            headers: HeaderMap::new(),
            body: body.into(),
        }
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
    }

    /// A 2026-07-28 request with its `_meta` and mirrored headers, as a conforming client
    /// sends it.
    fn modern(method: &str, mut params: Value) -> Self {
        let meta = params
            .as_object_mut()
            .unwrap()
            .entry("_meta")
            .or_insert_with(|| json!({}));
        meta[PROTOCOL_VERSION_META] = json!(MODERN);
        meta[CLIENT_CAPABILITIES_META] = json!({});
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        let mut raw = Raw::post(body.to_string())
            .header("mcp-protocol-version", MODERN)
            .header("mcp-method", method);
        if let Some(name) = name {
            raw = raw.header("mcp-name", &name);
        }
        raw
    }

    /// A 2025-06-18 request as Otto's callers send it: no protocol header and no version in
    /// `_meta`.
    fn legacy(method: &str, params: Value) -> Self {
        let body = json!({"jsonrpc": "2.0", "id": "legacy-1", "method": method, "params": params});
        Raw::post(body.to_string())
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        self
    }

    fn append(mut self, name: &str, value: &str) -> Self {
        self.headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        self
    }
}

fn tools_call(tool: &str, arguments: Value) -> Raw {
    Raw::modern("tools/call", json!({"name": tool, "arguments": arguments}))
}

fn tools_call_with_id(tool: &str, arguments: Value, tool_use_id: &str) -> Raw {
    Raw::modern(
        "tools/call",
        json!({"name": tool, "arguments": arguments, "_meta": {TOOL_USE_ID_META: tool_use_id}}),
    )
}

fn tools_list() -> Raw {
    Raw::modern("tools/list", json!({}))
}

/// What came back.
#[derive(Debug)]
struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl From<gateway_mcp::HttpResponse> for Got {
    fn from(response: gateway_mcp::HttpResponse) -> Self {
        assert!(
            !response.headers.contains_key("mcp-session-id"),
            "no response carries a session"
        );
        Got {
            status: response.status,
            headers: response.headers,
            body: response.body,
        }
    }
}

impl Got {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// The result of a 200 answer.
    fn result(&self) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{self:?}");
        let body = self.json();
        assert!(body.get("error").is_none(), "{body}");
        body["result"].clone()
    }

    /// The sentence of a refusal: a 200 with the denial code.
    fn denial(&self) -> String {
        assert_eq!(self.status, StatusCode::OK, "{self:?}");
        let body = self.json();
        assert_eq!(body["error"]["code"], json!(DENIAL_CODE), "{body}");
        body["error"]["message"].as_str().unwrap().to_owned()
    }

    fn tool_names(&self) -> Vec<String> {
        self.result()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn own(caller: Caller) -> Value {
    json!({"document": caller.own_document()})
}

// --- Allowed calls --------------------------------------------------------------------------

#[test]
fn an_allowed_read_returns_the_echo_and_completes_its_row() {
    let world = World::new();
    world
        .connector
        .take_time(world.fixture.clock.clone(), Duration::from_millis(25));
    let arguments = json!({"document": TEAM_A_DOCUMENT, "page": 2});
    let got = world.send(
        Some(&world.token(Caller::TeamA)),
        SURFACE_ALL,
        tools_call_with_id(READ_TOOL, arguments.clone(), "toolu_01ABC"),
    );

    let result = got.result();
    let echo = json!({
        "tool": READ_TOOL,
        "echo": arguments,
        "credential": "fake-credential-for-fixture-team-a-1",
    });
    assert_eq!(result["isError"], json!(false));
    assert_eq!(result["structuredContent"], echo);
    assert_eq!(result["content"][0]["text"], json!(echo.to_string()));
    assert_eq!(result["resultType"], json!("complete"));

    let rows = world.store.rows();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(row.tool, READ_TOOL);
    assert_eq!(row.classification, Some(Classification::Read));
    assert_eq!(row.surface.as_str(), SURFACE_ALL);
    assert_eq!(row.deployment.as_str(), "path-test");
    assert_eq!(row.profile.as_str(), PROFILE_TEAM_A);
    assert_eq!(
        row.tool_use_id.as_ref().map(|id| id.as_str()),
        Some("toolu_01ABC")
    );
    assert_eq!(
        row.proved_principal.get(),
        world.fixture.principal(Caller::TeamA).unwrap().get()
    );
    assert_eq!(row.claimed_team, None);
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 25
        })
    );
    assert_eq!(world.connector.received().len(), 1);
    assert_eq!(world.credentials.requests().len(), 1);
}

#[test]
fn a_legacy_call_with_no_protocol_header_is_served_the_same_way() {
    let world = World::new();
    let token = world.token(Caller::TeamB);
    let got = world.send(
        Some(&token),
        SURFACE_READ,
        Raw::legacy(
            "tools/call",
            json!({"name": READ_TOOL, "arguments": own(Caller::TeamB),
                   "_meta": {TOOL_USE_ID_META: "toolu_legacy"}}),
        ),
    );
    let body = got.json();
    assert_eq!(body["id"], json!("legacy-1"));
    let result = got.result();
    assert_eq!(result["isError"], json!(false));
    assert_eq!(result["structuredContent"]["tool"], json!(READ_TOOL));
    assert!(result.get("resultType").is_none(), "{result}");
    let row = world.row(0);
    assert_eq!(row.profile.as_str(), PROFILE_TEAM_B);
    assert_eq!(
        row.tool_use_id.as_ref().map(|id| id.as_str()),
        Some("toolu_legacy")
    );
    assert_eq!(row.completion.map(|c| c.outcome), Some(Outcome::Ok));
}

#[test]
fn each_caller_runs_under_its_own_credential() {
    let world = World::new();
    for (caller, surface) in [
        (Caller::TeamA, SURFACE_ALL),
        (Caller::TeamB, SURFACE_ALL),
        (Caller::UserInGroupG, SURFACE_READ),
    ] {
        let result = world.call(caller, surface, READ_TOOL, own(caller)).result();
        assert_eq!(result["isError"], json!(false), "{caller:?}");
    }
    let labels: Vec<_> = world
        .credentials
        .requests()
        .into_iter()
        .map(|request| request.issued.unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            "fake-credential-for-fixture-team-a-1",
            "fake-credential-for-fixture-team-b-2",
            "fake-credential-for-fixture-user-user-1@fixture.test-3",
        ]
    );
    let profiles: Vec<String> = world
        .store
        .rows()
        .iter()
        .map(|row| row.profile.to_string())
        .collect();
    assert_eq!(profiles, [PROFILE_TEAM_A, PROFILE_TEAM_B, PROFILE_USER]);
}

#[test]
fn the_two_teams_documents_are_separate() {
    let world = World::new();
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(
        result["structuredContent"]["echo"]["document"],
        json!(TEAM_A_DOCUMENT)
    );

    let sentence = world
        .call(
            Caller::TeamA,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_B_DOCUMENT}),
        )
        .denial();
    assert!(sentence.contains(TEAM_B_DOCUMENT), "{sentence}");
    assert_eq!(world.row(1).reason, Some(ReasonKind::ResourceOutsideLimit));
    assert_eq!(
        world.connector.received().len(),
        1,
        "only the allowed read ran"
    );
}

#[test]
fn an_allowed_proposal_runs_under_the_callers_credential_and_completes_its_row() {
    let world = World::new();
    let arguments = json!({"document": TEAM_A_DOCUMENT, "text": "A proposed change."});
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, DRAFT_TOOL, arguments.clone())
        .result();
    assert_eq!(result["isError"], json!(false));
    assert_eq!(result["structuredContent"]["draft"], json!("draft-1"));
    let row = world.row(0);
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(row.classification, Some(Classification::Propose));
    assert_eq!(row.completion.map(|c| c.outcome), Some(Outcome::Ok));
    let writes = world.connector.writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].tool, DRAFT_TOOL);
    assert_eq!(writes[0].arguments, arguments);
    assert_eq!(writes[0].credential, "fake-credential-for-fixture-team-a-1");

    // A draft the gateway did not open is refused by the connector when it runs, and the row
    // records the refusal.
    let sentence = world
        .call(
            Caller::TeamA,
            SURFACE_ALL,
            DRAFT_TOOL,
            json!({"document": TEAM_A_DOCUMENT, "draft": FOREIGN_DRAFT}),
        )
        .denial();
    assert_eq!(sentence, DRAFT_REFUSAL);
    let row = world.row(1);
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion.map(|c| c.outcome),
        Some(Outcome::Refused {
            sentence: DRAFT_REFUSAL.to_owned()
        })
    );
    assert_eq!(
        world.connector.writes().len(),
        1,
        "the refused revision wrote nothing"
    );
}

// --- Denials --------------------------------------------------------------------------------

#[test]
fn a_denied_call_never_reaches_the_connector_and_its_row_is_the_denial() {
    use ReasonKind::*;
    let world = World::new();
    let now = gateway_identity::Clock::now(&world.fixture.clock);
    // A user whose two groups select two different profiles gets none.
    let ambiguous_user = world
        .fixture
        .user_issuer
        .user_token(USER_SUBJECT, AUDIENCE, &[GROUP_G, GROUP_REVIEW], now)
        .build();
    let team_a = world.token(Caller::TeamA);
    let team_b = world.token(Caller::TeamB);
    let user = world.token(Caller::UserInGroupG);
    let table: [(&str, &str, &str, Value, ReasonKind); 11] = [
        (
            &ambiguous_user,
            SURFACE_READ,
            READ_TOOL,
            json!({"document": "group-g-notes"}),
            ProfileUnknown,
        ),
        (
            &team_a,
            SURFACE_ALL,
            "fixture__no_such_tool",
            own(Caller::TeamA),
            UnknownTool,
        ),
        (
            &team_a,
            SURFACE_ALL,
            "not a tool name!",
            own(Caller::TeamA),
            UnknownTool,
        ),
        (
            &team_a,
            SURFACE_READ,
            WRITE_TOOL,
            own(Caller::TeamA),
            ToolNotOnSurface,
        ),
        (
            &user,
            SURFACE_ALL,
            READ_TOOL,
            own(Caller::UserInGroupG),
            SurfaceNotPermitted,
        ),
        (
            &team_a,
            "no-such-surface",
            READ_TOOL,
            own(Caller::TeamA),
            SurfaceNotPermitted,
        ),
        (
            &team_b,
            SURFACE_ALL,
            WRITE_TOOL,
            own(Caller::TeamB),
            ClassificationNotPermitted,
        ),
        // A direct write is denied in every profile, even to team A, whose profile may propose.
        (
            &team_a,
            SURFACE_ALL,
            WRITE_TOOL,
            own(Caller::TeamA),
            ClassificationNotPermitted,
        ),
        (
            &team_b,
            SURFACE_ALL,
            DRAFT_TOOL,
            own(Caller::TeamB),
            ClassificationNotPermitted,
        ),
        (
            &team_b,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_A_DOCUMENT}),
            ResourceOutsideLimit,
        ),
        (
            &team_b,
            SURFACE_ALL,
            READ_TOOL,
            json!({}),
            ResourceOutsideLimit,
        ),
    ];
    for (position, (token, surface, tool, arguments, expected)) in table.into_iter().enumerate() {
        let sentence = world
            .send(Some(token), surface, tools_call(tool, arguments))
            .denial();
        let row = world.row(position);
        assert_eq!(row.reason, Some(expected), "{surface} {tool}");
        assert_eq!(row.decision, DecisionKind::Deny);
        assert_eq!(
            row.sentence.as_deref(),
            Some(sentence.as_str()),
            "the row and the answer say the same"
        );
        assert_eq!(row.completion, None, "a denial's row is complete as begun");
        world.assert_nothing_ran();
    }
    assert_eq!(world.row(0).profile.as_str(), gateway::NO_PROFILE);
    assert_eq!(world.store.rows().len(), 11, "one row per denied call");
    assert_eq!(world.store.finish_attempts(), 0);
}

#[test]
fn a_legacy_denial_is_the_same_sentence_and_the_same_code() {
    let world = World::new();
    let got = world.send(
        Some(&world.token(Caller::TeamB)),
        SURFACE_ALL,
        Raw::legacy(
            "tools/call",
            json!({"name": WRITE_TOOL, "arguments": own(Caller::TeamB)}),
        ),
    );
    let sentence = got.denial();
    assert_eq!(got.json()["id"], json!("legacy-1"));
    assert_eq!(world.row(0).sentence.as_deref(), Some(sentence.as_str()));
    world.assert_nothing_ran();
}

// --- Audit ----------------------------------------------------------------------------------

#[test]
fn when_the_audit_row_cannot_be_begun_the_call_is_refused_and_nothing_runs() {
    let world = World::new();
    world.store.fail_next_begin();
    let sentence = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .denial();
    assert_eq!(sentence, AUDIT_FAILURE);
    assert!(world.store.rows().is_empty());
    world.assert_nothing_ran();

    // A call that would have been denied is refused the same way.
    world.store.fail_next_begin();
    let sentence = world
        .call(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamB))
        .denial();
    assert_eq!(sentence, AUDIT_FAILURE);
    assert!(world.store.rows().is_empty());

    // A store that is down refuses every call while it is down.
    world.store.fail_all_begins();
    for _ in 0..3 {
        let sentence = world
            .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
            .denial();
        assert_eq!(sentence, AUDIT_FAILURE);
    }
    world.assert_nothing_ran();

    // And when it is back, the same call goes through.
    world.store.stop_failing();
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(result["isError"], json!(false));
}

#[test]
fn a_failure_to_finish_the_row_does_not_undo_a_success() {
    let world = World::new();
    world.store.fail_next_finish();
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(
        result["isError"],
        json!(false),
        "the result of a call that ran is still returned"
    );
    assert_eq!(result["structuredContent"]["tool"], json!(READ_TOOL));
    assert_eq!(world.connector.received().len(), 1, "it ran once");
    let row = world.row(0);
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion, None,
        "the empty outcome is the evidence that the gateway never learned what happened"
    );
}

#[test]
fn a_scope_refusal_is_a_denial_with_the_connectors_sentence_and_the_outcome_refused() {
    let world = World::new();
    let sentence = world
        .call(
            Caller::TeamA,
            SURFACE_ALL,
            SCOPED_READ_TOOL,
            json!({"document": gateway_testkit::FORBIDDEN_DOCUMENT}),
        )
        .denial();
    assert_eq!(sentence, SCOPE_REFUSAL);
    let row = world.row(0);
    assert_eq!(row.decision, DecisionKind::Allow, "the decision allowed it");
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Refused {
                sentence: SCOPE_REFUSAL.to_owned()
            },
            latency_ms: 0
        })
    );
    assert_eq!(world.connector.received().len(), 1, "it ran, and refused");
}

#[test]
fn a_scope_refusal_that_cannot_be_recorded_is_answered_with_the_audit_sentence() {
    let world = World::new();
    world.store.fail_next_finish();
    let sentence = world
        .call(
            Caller::TeamA,
            SURFACE_ALL,
            SCOPED_READ_TOOL,
            json!({"document": gateway_testkit::FORBIDDEN_DOCUMENT}),
        )
        .denial();
    assert_eq!(sentence, AUDIT_FAILURE);
    assert_eq!(world.row(0).completion, None);
}

#[test]
fn a_tool_error_is_a_result_marked_as_an_error_and_recorded_as_one() {
    let world = World::new();
    world.connector.fail_next();
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(result["isError"], json!(true));
    assert_eq!(
        result["content"][0]["text"],
        json!("the fixture connector was told to fail")
    );
    assert_eq!(
        world.row(0).completion.map(|c| c.outcome),
        Some(Outcome::Error)
    );

    world.credentials.refuse_next();
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(result["isError"], json!(true));
    assert_eq!(
        world.row(1).completion.map(|c| c.outcome),
        Some(Outcome::Error)
    );
}

#[test]
fn the_row_is_written_before_the_tool_runs_and_finished_before_the_answer() {
    let world = World::new();
    let token = world.token(Caller::TeamA);
    let send = |world: &World| {
        let request = tools_call(READ_TOOL, own(Caller::TeamA))
            .header("authorization", &format!("Bearer {token}"));
        let admitted = world.path.admit(&request.method, &request.headers).unwrap();
        world
            .path
            .respond(admitted, SURFACE_ALL, &request.headers, &request.body)
    };

    // A connector that hangs: the row already exists, with an empty outcome.
    let gate = world.connector.hang_next();
    let mut call = pin!(send(&world));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(world.connector.received().len(), 1);
    let row = world.row(0);
    assert_eq!((row.decision, row.completion), (DecisionKind::Allow, None));
    gate.open();
    let Poll::Ready(response) = poll_once(call.as_mut()) else {
        panic!("not answered once the connector returned")
    };
    assert_eq!(Got::from(response).result()["isError"], json!(false));

    // A store that is slow to finish: the tool has run, and the answer waits for the row.
    let gate = world.store.hold_finishes();
    let mut call = pin!(send(&world));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(world.connector.received().len(), 2, "the tool has run");
    assert_eq!(world.row(1).completion, None);
    gate.open();
    assert!(poll_once(call.as_mut()).is_ready());
    assert!(world.row(1).completion.is_some());

    // A store that is slow to begin: nothing runs, and nothing is answered, until the row is
    // written.
    let gate = world.store.hold_begins();
    let mut call = pin!(send(&world));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(world.store.rows().len(), 2);
    assert_eq!(
        world.connector.received().len(),
        2,
        "no third call has arrived"
    );
    gate.open();
    assert!(poll_once(call.as_mut()).is_ready());
    assert_eq!(world.store.rows().len(), 3);
    assert_eq!(world.connector.received().len(), 3);
}

/// The HTTP layer spawns the future `respond` returns, so it must own what it uses.
#[test]
fn the_answering_future_can_be_spawned() {
    fn spawnable<F: Future + Send + 'static>(future: F) -> F {
        future
    }
    let world = World::new();
    let request = tools_call(READ_TOOL, own(Caller::TeamA)).header(
        "authorization",
        &format!("Bearer {}", world.token(Caller::TeamA)),
    );
    let admitted = world.path.admit(&request.method, &request.headers).unwrap();
    let future = spawnable(world.path.respond(
        admitted,
        SURFACE_ALL,
        &request.headers,
        &request.body,
    ));
    // The request it was made from is gone; the future still answers.
    drop(request);
    let result = Got::from(block_on(future)).result();
    assert_eq!(result["isError"], json!(false));
}

// --- The tool-use identifier (G5) -----------------------------------------------------------

#[test]
fn a_tool_use_identifier_outside_its_bound_is_dropped_before_the_row() {
    let world = World::new();
    let token = world.token(Caller::TeamA);
    let longest = "t".repeat(MAX_TOOL_USE_ID);
    let cases: [(&str, Option<&str>); 5] = [
        (&longest, Some(&longest)),
        (&"t".repeat(MAX_TOOL_USE_ID + 1), None),
        ("toolu_01\nforged log line", None),
        ("toolu_\u{1b}[2J", None),
        ("toolu_ünicode", None),
    ];
    for (position, (sent, kept)) in cases.into_iter().enumerate() {
        let result = world
            .send(
                Some(&token),
                SURFACE_ALL,
                tools_call_with_id(READ_TOOL, own(Caller::TeamA), sent),
            )
            .result();
        assert_eq!(
            result["isError"],
            json!(false),
            "the call itself goes ahead"
        );
        assert_eq!(
            world
                .row(position)
                .tool_use_id
                .as_ref()
                .map(|id| id.as_str()),
            kept,
            "{sent:?}"
        );
    }
}

// --- Identity -------------------------------------------------------------------------------

#[test]
fn every_identity_failure_is_the_same_401_and_nothing_runs() {
    let world = World::new();
    let now = gateway_identity::Clock::now(&world.fixture.clock);
    let issuer = &world.fixture.workload_issuer;
    let wrong_audience = issuer
        .workload_token(TEAM_A_SUBJECT, "another-gateway", now)
        .build();
    let unknown_subject = issuer
        .workload_token("system:serviceaccount:team-c:sandbox", AUDIENCE, now)
        .build();
    let bad_signature = issuer
        .workload_token(TEAM_A_SUBJECT, AUDIENCE, now)
        .corrupt_signature()
        .build();
    let oversized = "a".repeat(gateway_identity::MAX_TOKEN_BYTES + 1);
    let good = world.token(Caller::TeamA);
    let call = || tools_call(READ_TOOL, own(Caller::TeamA));

    let attempts: Vec<(&str, Raw)> = vec![
        ("no header", call()),
        (
            "garbage",
            call().header("authorization", "Bearer not-a-token"),
        ),
        ("empty token", call().header("authorization", "Bearer ")),
        (
            "another scheme",
            call().header("authorization", &format!("Basic {good}")),
        ),
        ("no scheme", call().header("authorization", &good)),
        (
            "two headers",
            call()
                .append("authorization", &format!("Bearer {good}"))
                .append("authorization", &format!("Bearer {good}")),
        ),
        (
            "wrong audience",
            call().header("authorization", &format!("Bearer {wrong_audience}")),
        ),
        (
            "unknown subject",
            call().header("authorization", &format!("Bearer {unknown_subject}")),
        ),
        (
            "bad signature",
            call().header("authorization", &format!("Bearer {bad_signature}")),
        ),
        (
            "oversized",
            call().header("authorization", &format!("Bearer {oversized}")),
        ),
        // Identity runs before the body is read: a caller who is not verified never learns
        // that the body was bad.
        (
            "invalid JSON",
            Raw::post("{not json").header("authorization", "Bearer not-a-token"),
        ),
        ("a batch with no token", Raw::post("[]")),
        (
            "initialize with no token",
            Raw::legacy("initialize", json!({})),
        ),
        (
            "discover with no token",
            Raw::modern("server/discover", json!({})),
        ),
        ("tools/list with no token", tools_list()),
    ];

    let mut first: Option<Vec<u8>> = None;
    let mut check = |case: &str, request: Raw| {
        let got = Got::from(block_on(world.path.handle(
            &request.method,
            &request.headers,
            SURFACE_ALL,
            &request.body,
        )));
        assert_eq!(got.status, StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            got.headers
                .get("www-authenticate")
                .map(|v| v.to_str().unwrap()),
            Some(CHALLENGE),
            "{case}"
        );
        let body = got.json();
        assert_eq!(body["id"], Value::Null, "{case}");
        assert_eq!(body["error"]["code"], json!(DENIAL_CODE), "{case}");
        assert_eq!(body["error"]["message"], json!(IDENTITY_FAILURE), "{case}");
        match &first {
            None => first = Some(got.body),
            Some(first) => assert_eq!(&got.body, first, "{case}: the bytes differ"),
        }
    };
    for (case, request) in attempts {
        check(case, request);
    }
    // The good token was good until now: the cases above that carried it failed for the way
    // they carried it.
    world.fixture.clock.advance(Duration::from_secs(7200));
    check(
        "expired",
        call().header("authorization", &format!("Bearer {good}")),
    );

    world.assert_nothing_ran();
    assert!(
        world.store.rows().is_empty(),
        "identity failures are telemetry, not audit rows"
    );
    assert_eq!(world.store.begin_attempts(), 0);
}

#[test]
fn during_an_audit_outage_an_identity_failure_is_still_the_same_401() {
    // Decision 0009: an identity failure writes no row, so an audit outage does not change its
    // answer, and a caller who is not verified cannot tell that the store is down.
    let world = World::new();
    world.store.fail_all_begins();
    let got = world.send(None, SURFACE_ALL, tools_call(READ_TOOL, own(Caller::TeamA)));
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    assert_eq!(got.json()["error"]["message"], json!(IDENTITY_FAILURE));
    assert_eq!(world.store.begin_attempts(), 0);

    // A verified caller in the same outage is refused with the audit sentence.
    let sentence = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .denial();
    assert_eq!(sentence, AUDIT_FAILURE);
    world.assert_nothing_ran();
}

#[test]
fn the_bearer_scheme_is_matched_without_regard_to_case() {
    let world = World::new();
    let token = world.token(Caller::TeamA);
    for scheme in ["bearer", "BEARER", "Bearer"] {
        let got = world.send(
            None,
            SURFACE_ALL,
            tools_call(READ_TOOL, own(Caller::TeamA))
                .header("authorization", &format!("{scheme} {token}")),
        );
        assert_eq!(got.result()["isError"], json!(false), "{scheme}");
    }
}

#[test]
fn what_is_not_a_json_post_is_refused_before_identity() {
    let world = World::new();
    let get = Raw {
        method: Method::GET,
        ..tools_list()
    };
    let got = world.send(None, SURFACE_ALL, get);
    assert_eq!(got.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(got.headers.get("allow").unwrap(), "POST");

    let got = world.send(
        None,
        SURFACE_ALL,
        tools_list().header("content-type", "text/plain"),
    );
    assert_eq!(got.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let got = world.send(
        None,
        SURFACE_ALL,
        tools_list().header("accept", "text/html"),
    );
    assert_eq!(got.status, StatusCode::NOT_ACCEPTABLE);
    assert!(world.store.rows().is_empty());
}

// --- Identity disabled (owner answer Q4) and audit disabled ----------------------------------

#[test]
fn with_identity_disabled_nothing_is_listed_every_call_is_refused_and_it_says_so() {
    let world = World::with(
        |config| config["identity"] = json!({"disabled": true}),
        |wiring| wiring,
    );
    // No token is needed, and one is not looked at.
    for token in [None, Some("not-a-token")] {
        let sentence = world
            .send(
                token,
                SURFACE_ALL,
                tools_call(READ_TOOL, own(Caller::TeamA)),
            )
            .denial();
        assert_eq!(sentence, IDENTITY_DISABLED);
        let tools = world.send(token, SURFACE_ALL, tools_list()).tool_names();
        assert!(tools.is_empty(), "{tools:?}");
    }
    world.assert_nothing_ran();
    assert!(world.store.rows().is_empty());
    assert_eq!(world.store.begin_attempts(), 0);
    assert!(world.resources.asked().is_empty());

    let initialized = world
        .send(None, SURFACE_ALL, Raw::legacy("initialize", json!({})))
        .result();
    assert_eq!(initialized["instructions"], json!(IDENTITY_DISABLED_NOTE));
    let discovered = world
        .send(None, SURFACE_ALL, Raw::modern("server/discover", json!({})))
        .result();
    assert_eq!(discovered["instructions"], json!(IDENTITY_DISABLED_NOTE));
}

#[test]
fn with_audit_disabled_calls_run_and_it_says_so() {
    let world = World::with(
        |config| config["audit"] = json!({"disabled": true}),
        |wiring| wiring,
    );
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(result["isError"], json!(false));
    assert_eq!(world.connector.received().len(), 1);
    assert!(
        world.store.rows().is_empty(),
        "the store was never wired in"
    );

    let token = world.token(Caller::TeamA);
    let initialized = world
        .send(
            Some(&token),
            SURFACE_ALL,
            Raw::legacy("initialize", json!({})),
        )
        .result();
    assert_eq!(initialized["instructions"], json!(AUDIT_DISABLED_NOTE));
}

#[test]
fn with_every_gate_on_the_server_gives_no_instructions() {
    let world = World::new();
    let token = world.token(Caller::TeamA);
    let initialized = world
        .send(
            Some(&token),
            SURFACE_ALL,
            Raw::legacy("initialize", json!({})),
        )
        .result();
    assert_eq!(initialized["protocolVersion"], json!("2025-06-18"));
    assert_eq!(
        initialized["serverInfo"]["name"],
        json!(gateway::SERVER_NAME)
    );
    assert!(initialized.get("instructions").is_none(), "{initialized}");
}

// --- tools/list -----------------------------------------------------------------------------

#[test]
fn tools_list_returns_only_what_the_caller_may_call() {
    let world = World::new();
    let list = |caller: Caller, surface: &str| {
        world
            .send(Some(&world.token(caller)), surface, tools_list())
            .tool_names()
    };
    assert_eq!(
        list(Caller::TeamB, SURFACE_ALL),
        [READ_TOOL, SCOPED_READ_TOOL],
        "team B may not propose, and nobody may write"
    );
    assert_eq!(
        list(Caller::TeamA, SURFACE_ALL),
        [DRAFT_TOOL, READ_TOOL, SCOPED_READ_TOOL],
        "team A may propose, and nobody may write"
    );
    assert_eq!(
        list(Caller::UserInGroupG, SURFACE_READ),
        [READ_TOOL, SCOPED_READ_TOOL]
    );
    assert!(list(Caller::UserInGroupG, SURFACE_ALL).is_empty());
    assert!(list(Caller::TeamA, "no-such-surface").is_empty());

    // Every tool team A is listed on the surface, it is allowed to call; the core decides both.
    let team_a: BTreeSet<String> = list(Caller::TeamA, SURFACE_ALL).into_iter().collect();
    assert!(team_a.contains(READ_TOOL));

    assert!(world.store.rows().is_empty(), "a list writes no row");
    world.assert_nothing_ran();
}

#[test]
fn a_listed_tool_carries_its_catalog_definition() {
    let world = World::new();
    let result = world
        .send(Some(&world.token(Caller::TeamB)), SURFACE_ALL, tools_list())
        .result();
    assert_eq!(result["cacheScope"], json!("private"));
    assert_eq!(result["ttlMs"], json!(0));
    let read = &result["tools"][0];
    assert_eq!(
        read,
        &json!({
            "name": READ_TOOL,
            "title": "Read a document",
            "description": format!("The fixture's {READ_TOOL}."),
            "inputSchema": {"type": "object", "properties": {"document": {"type": "string"}}},
            "annotations": {"readOnlyHint": true},
        })
    );
}

#[test]
fn the_list_is_the_same_in_both_eras() {
    let world = World::new();
    let token = world.token(Caller::TeamB);
    let modern = world.send(Some(&token), SURFACE_ALL, tools_list()).result();
    let legacy = world
        .send(
            Some(&token),
            SURFACE_ALL,
            Raw::legacy("tools/list", json!({})),
        )
        .result();
    assert_eq!(modern["tools"], legacy["tools"]);
    assert!(legacy.get("cacheScope").is_none());
}

// --- Resources ------------------------------------------------------------------------------

#[test]
fn the_resources_come_from_the_adapter_of_the_approved_tools_connector() {
    // A second adapter is registered under a connector named after the tool. It is never the
    // read tool's adapter: that is chosen by the approved tool's connector.
    let world = World::with(
        |_| {},
        |wiring| {
            wiring.connector(
                READ_TOOL,
                Arc::new(FixtureConnector::new(Arc::new(FakeCredentialSource::new()))),
                Arc::new(TeamBDocument),
            )
        },
    );
    let result = world
        .call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA))
        .result();
    assert_eq!(result["isError"], json!(false));
    assert_eq!(world.resources.asked(), [READ_TOOL]);
}

#[test]
fn a_name_that_is_not_an_approved_tool_reaches_no_adapter() {
    let world = World::new();
    for name in ["fixture__no_such_tool", "not a tool name!"] {
        world
            .call(Caller::TeamA, SURFACE_ALL, name, own(Caller::TeamA))
            .denial();
    }
    assert!(world.resources.asked().is_empty());
}

// --- What writes no row ---------------------------------------------------------------------

#[test]
fn discovery_notifications_and_protocol_refusals_write_no_row_and_run_nothing() {
    let world = World::new();
    let token = world.token(Caller::TeamA);
    let send = |request: Raw| world.send(Some(&token), SURFACE_ALL, request);

    assert!(
        send(Raw::legacy("initialize", json!({})))
            .result()
            .is_object()
    );
    assert_eq!(send(Raw::legacy("ping", json!({}))).result(), json!({}));
    let discovered = send(Raw::modern("server/discover", json!({}))).result();
    assert_eq!(discovered["supportedVersions"], json!([MODERN]));

    let accepted = send(Raw::post(
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
    ));
    assert_eq!(accepted.status, StatusCode::ACCEPTED);
    assert!(accepted.body.is_empty());

    let mismatched = send(tools_call(READ_TOOL, own(Caller::TeamA)).header("mcp-name", WRITE_TOOL));
    assert_eq!(mismatched.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        mismatched.json()["error"]["code"],
        json!(gateway_mcp::HEADER_MISMATCH)
    );

    let invalid = send(Raw::post("{not json"));
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.json()["error"]["code"],
        json!(gateway_mcp::PARSE_ERROR)
    );

    let modern_ping = send(Raw::modern("ping", json!({})));
    assert_eq!(modern_ping.status, StatusCode::NOT_FOUND);

    assert!(world.store.rows().is_empty());
    assert_eq!(world.store.begin_attempts(), 0);
    world.assert_nothing_ran();
}
