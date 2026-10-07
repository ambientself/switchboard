//! The MCP SDK as a client of the fixture gateway (plan #26 section 6, test 6).
//!
//! `rmcp` 3.5.1 connects in each of its three lifecycle modes:
//!
//! - `Initialize`: the 2025-06-18 handshake, `initialize` then `notifications/initialized`;
//! - `Discover`: `server/discover`, after which every request carries its version in `_meta`
//!   and the 2026-07-28 headers;
//! - `Auto`: tries `server/discover` and falls back to `initialize` only when the server is
//!   legacy. The gateway is not, so the client must stay modern.
//!
//! In each mode every fixture caller lists its tools, reads its own document and is denied
//! another team's. The SDK's HTTP client is wrapped so the test sees every POST the SDK sent,
//! with its headers, and any session the gateway tried to start, which must be none.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway_core::audit::{DecisionKind, Outcome};
use gateway_dev::client::other_document;
use gateway_dev::{FixtureGateway, catalog_data, start_fixture_gateway};
use gateway_mcp::{CHALLENGE, DENIAL_CODE, LEGACY, MODERN, TOOL_USE_ID_META};
use gateway_testkit::{Caller, DOCUMENT_ARGUMENT, READ_TOOL, SURFACE_ALL, SURFACE_READ};
use rmcp::model::{
    CallToolRequestParams, ClientJsonRpcMessage, ErrorCode, ProtocolVersion, RequestMetaObject,
};
use rmcp::service::{ClientInitializeError, RoleClient, RunningService, ServiceError};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::common::client_side_sse::BoxedSseResponse;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClient, StreamableHttpClientTransportConfig, StreamableHttpError,
    StreamableHttpPostResponse,
};
use rmcp::{ClientLifecycleMode, ClientServiceExt};
use rmcp_reqwest::header::{HeaderName, HeaderValue};
use serde_json::{Value, json};

const CALLERS: [Caller; 3] = [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG];

/// One POST the SDK sent.
#[derive(Clone, Debug)]
struct Sent {
    /// The JSON-RPC method, or `"response"` for a message that has none.
    method: String,
    /// The headers the SDK's transport added, by lower-case name. The token is not among them.
    headers: HashMap<String, String>,
    /// The `Mcp-Session-Id` the gateway answered with, if any.
    session: Option<String>,
    /// The `WWW-Authenticate` challenge, when the gateway answered 401 with one.
    challenge: Option<String>,
}

/// The SDK's HTTP client, with no proxy, recording each POST.
#[derive(Clone)]
struct Recording {
    http: rmcp_reqwest::Client,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl Recording {
    fn new() -> Self {
        Self {
            http: rmcp_reqwest::Client::builder().no_proxy().build().unwrap(),
            sent: Arc::default(),
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    fn methods(&self) -> Vec<String> {
        self.sent().into_iter().map(|sent| sent.method).collect()
    }
}

fn method_of(message: &ClientJsonRpcMessage) -> String {
    serde_json::to_value(message)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "response".to_owned())
}

impl StreamableHttpClient for Recording {
    type Error = rmcp_reqwest::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let method = method_of(&message);
        let headers = custom_headers
            .iter()
            .map(|(name, value)| {
                let value = value.to_str().unwrap_or_default().to_owned();
                (name.as_str().to_owned(), value)
            })
            .collect();
        let answer = self
            .http
            .post_message(uri, message, session_id, auth_header, custom_headers)
            .await;
        let session = match &answer {
            Ok(
                StreamableHttpPostResponse::Json(_, session)
                | StreamableHttpPostResponse::Sse(_, session),
            ) => session.clone(),
            _ => None,
        };
        let challenge = match &answer {
            Err(StreamableHttpError::AuthRequired(required)) => {
                Some(required.www_authenticate_header.clone())
            }
            _ => None,
        };
        self.sent.lock().unwrap().push(Sent {
            method,
            headers,
            session,
            challenge,
        });
        answer
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.http
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxedSseResponse, StreamableHttpError<Self::Error>> {
        self.http
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await
    }
}

type Connected = RunningService<RoleClient, ()>;

/// The SDK's transport to `surface`, presenting `token` if there is one.
fn transport(
    gateway: &FixtureGateway,
    surface: &str,
    token: Option<String>,
    recording: &Recording,
) -> StreamableHttpClientTransport<Recording> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(gateway.url(surface));
    if let Some(token) = token {
        config = config.auth_header(token);
    }
    StreamableHttpClientTransport::with_client(recording.clone(), config)
}

/// Connects to `surface` as `caller` in `mode`.
async fn connect(
    gateway: &FixtureGateway,
    surface: &str,
    caller: Caller,
    mode: Mode,
) -> (Connected, Recording) {
    let recording = Recording::new();
    let transport = transport(gateway, surface, Some(gateway.token(caller)), &recording);
    let client = ()
        .serve_with_lifecycle(transport, mode.lifecycle())
        .await
        .unwrap_or_else(|error| panic!("{mode:?}, {caller:?} did not connect: {error}"));
    (client, recording)
}

/// The SDK's three lifecycle modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Initialize,
    Discover,
    Auto,
}

const MODES: [Mode; 3] = [Mode::Initialize, Mode::Discover, Mode::Auto];

impl Mode {
    fn lifecycle(self) -> ClientLifecycleMode {
        let modern = vec![ProtocolVersion::V_2026_07_28];
        match self {
            Mode::Initialize => ClientLifecycleMode::Initialize,
            Mode::Discover => ClientLifecycleMode::Discover {
                preferred_versions: modern,
            },
            Mode::Auto => ClientLifecycleMode::Auto {
                preferred_versions: modern,
                legacy_version: Some(ProtocolVersion::V_2025_06_18),
            },
        }
    }

    /// Whether the client should end up in the 2026-07-28 era.
    fn modern(self) -> bool {
        self != Mode::Initialize
    }

    /// The requests the client opens with.
    fn opening(self) -> &'static [&'static str] {
        if self.modern() {
            &["server/discover"]
        } else {
            &["initialize", "notifications/initialized"]
        }
    }
}

/// A read of `document`, with a tool-use identifier in `_meta`.
fn read(document: &str, tool_use_id: &str) -> CallToolRequestParams {
    let mut params = CallToolRequestParams::new(READ_TOOL).with_arguments(
        json!({DOCUMENT_ARGUMENT: document})
            .as_object()
            .unwrap()
            .clone(),
    );
    let mut meta = RequestMetaObject::new();
    meta.0
        .insert(TOOL_USE_ID_META.to_owned(), json!(tool_use_id));
    params.meta = Some(meta);
    params
}

/// The tool names `tools/list` gives `caller` on `surface`, asked by hand in the legacy era.
async fn listed_by_hand(
    gateway: &FixtureGateway,
    surface: &str,
    caller: Caller,
) -> BTreeSet<String> {
    let (status, body) = support::post(
        &gateway.url(surface),
        Some(&gateway.token(caller)),
        &support::legacy("tools/list", json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_sdk_lists_reads_and_is_denied_in_each_lifecycle_mode() {
    let gateway = start_fixture_gateway().await.unwrap();
    let mut calls = 0;
    for mode in MODES {
        for caller in CALLERS {
            let context = format!("{mode:?}, {caller:?}");
            let (client, recording) = connect(&gateway, SURFACE_READ, caller, mode).await;

            // The era the client settled in. In Auto it found the gateway modern and stayed.
            let peer = client.peer_info().unwrap();
            let expected = if mode.modern() { MODERN } else { LEGACY };
            assert_eq!(peer.protocol_version.as_str(), expected, "{context}");

            // The tools a hand-written request gets, which include the read tool.
            let listed: BTreeSet<String> = client
                .list_all_tools()
                .await
                .unwrap_or_else(|error| panic!("{context}: tools/list failed: {error}"))
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect();
            assert_eq!(
                listed,
                listed_by_hand(&gateway, SURFACE_READ, caller).await,
                "{context}"
            );
            assert!(listed.contains(READ_TOOL), "{context}: {listed:?}");

            // The caller's own document: a result, and an allow row with the tool-use id.
            let own = caller.own_document();
            let tool_use_id = format!("toolu_rmcp_{calls}");
            let result = client
                .call_tool(read(own, &tool_use_id))
                .await
                .unwrap_or_else(|error| panic!("{context}: reading {own} failed: {error}"));
            calls += 1;
            assert_eq!(result.is_error, Some(false), "{context}: {result:?}");
            assert!(result.structured_content.is_some(), "{context}: {result:?}");
            let row = gateway.store().rows().last().cloned().unwrap();
            assert_eq!(row.decision, DecisionKind::Allow, "{context}");
            assert_eq!(
                row.tool_use_id.as_ref().map(|id| id.as_str()),
                Some(tool_use_id.as_str()),
                "{context}"
            );

            // Another team's document: the denial code, and the sentence on the deny row.
            let other = other_document(caller);
            let denied = client
                .call_tool(read(other, &format!("toolu_rmcp_{calls}")))
                .await;
            calls += 1;
            let Err(ServiceError::McpError(error)) = denied else {
                panic!("{context}: reading {other} was not denied: {denied:?}");
            };
            assert_eq!(i64::from(error.code.0), DENIAL_CODE, "{context}");
            assert!(
                error.message.contains(other),
                "{context}: {}",
                error.message
            );
            let row = gateway.store().rows().last().cloned().unwrap();
            assert_eq!(row.decision, DecisionKind::Deny, "{context}");
            assert_eq!(row.sentence.as_deref(), Some(&*error.message), "{context}");

            client.cancel().await.unwrap();

            // What went over the wire: the era's opening and nothing else; in Auto, no
            // initialize at all.
            let mut expected: Vec<&str> = mode.opening().to_vec();
            expected.extend(["tools/list", "tools/call", "tools/call"]);
            assert_eq!(recording.methods(), expected, "{context}");
            for sent in recording.sent() {
                assert_eq!(sent.session, None, "{context}: a session was started");
                let header = |name: &str| sent.headers.get(name).map(String::as_str);
                if mode.modern() {
                    assert_eq!(header("mcp-protocol-version"), Some(MODERN), "{context}");
                    assert_eq!(header("mcp-method"), Some(&*sent.method), "{context}");
                    if sent.method == "tools/call" {
                        assert_eq!(header("mcp-name"), Some(READ_TOOL), "{context}");
                    }
                } else {
                    assert_eq!(header("mcp-method"), None, "{context}: {sent:?}");
                    if sent.method != "initialize" {
                        assert_eq!(header("mcp-protocol-version"), Some(LEGACY), "{context}");
                    }
                }
            }
        }
    }
    // One row per call, and only the allowed half reached the tool.
    assert_eq!(gateway.store().rows().len(), calls);
    assert_eq!(gateway.connector().received().len(), calls / 2);
}

#[tokio::test]
async fn the_sdk_reads_the_tool_definitions_as_the_catalog_states_them() {
    let gateway = start_fixture_gateway().await.unwrap();
    let catalog = catalog_data();
    let definition = catalog
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == json!(READ_TOOL))
        .unwrap();
    for mode in MODES {
        for surface in [SURFACE_READ, SURFACE_ALL] {
            for caller in CALLERS {
                let context = format!("{mode:?}, {caller:?}, {surface}");
                let (client, _) = connect(&gateway, surface, caller, mode).await;
                let tools = client.list_all_tools().await.unwrap();
                let listed: BTreeSet<String> =
                    tools.iter().map(|tool| tool.name.to_string()).collect();
                assert_eq!(
                    listed,
                    listed_by_hand(&gateway, surface, caller).await,
                    "{context}"
                );
                if let Some(tool) = tools.iter().find(|tool| tool.name == READ_TOOL) {
                    assert_eq!(tool.title.as_deref(), definition["title"].as_str());
                    assert_eq!(
                        tool.description.as_deref(),
                        definition["description"].as_str()
                    );
                    assert_eq!(
                        Value::Object((*tool.input_schema).clone()),
                        definition["input_schema"],
                        "{context}"
                    );
                    let annotations = tool.annotations.as_ref().unwrap();
                    assert_eq!(annotations.read_only_hint, Some(true), "{context}");
                }
                client.cancel().await.unwrap();
            }
        }
    }
    assert!(gateway.store().rows().is_empty());
}

#[tokio::test]
async fn a_failing_tool_reaches_the_sdk_as_an_error_result() {
    let gateway = start_fixture_gateway().await.unwrap();
    let caller = Caller::TeamA;
    for mode in MODES {
        let (client, _) = connect(&gateway, SURFACE_READ, caller, mode).await;
        gateway.connector().fail_next();
        let result = client
            .call_tool(read(caller.own_document(), "toolu_rmcp_failing"))
            .await
            .unwrap_or_else(|error| panic!("{mode:?}: not a result: {error}"));
        assert_eq!(result.is_error, Some(true), "{mode:?}: {result:?}");
        client.cancel().await.unwrap();
    }
    assert_eq!(gateway.connector().received().len(), MODES.len());
}

#[tokio::test]
async fn the_sdk_with_no_token_or_a_bad_one_is_refused_before_it_starts() {
    let gateway = start_fixture_gateway().await.unwrap();
    let forged = gateway
        .token_builder(Caller::TeamA)
        .audience("someone-else")
        .build();
    for mode in MODES {
        for token in [None, Some(forged.clone())] {
            let context = format!("{mode:?}, token: {}", token.is_some());
            let recording = Recording::new();
            let transport = transport(&gateway, SURFACE_READ, token, &recording);
            let refused = ().serve_with_lifecycle(transport, mode.lifecycle()).await;
            let Err(error) = refused else {
                panic!("{context}: the client connected");
            };
            // The SDK sees the challenge, which is what sends a client to authenticate. Auto
            // does not mistake a refusal for a legacy server and fall back to initialize.
            assert!(
                matches!(error, ClientInitializeError::TransportError { .. }),
                "{context}: {error:?}"
            );
            let sent = recording.sent();
            assert_eq!(sent.len(), 1, "{context}: {sent:?}");
            assert_eq!(sent[0].method, mode.opening()[0], "{context}");
            assert_eq!(sent[0].challenge.as_deref(), Some(CHALLENGE), "{context}");
        }
    }
    assert!(gateway.store().rows().is_empty());
    assert!(gateway.connector().received().is_empty());
}

#[tokio::test]
async fn a_method_the_gateway_does_not_serve_is_an_error_and_the_client_carries_on() {
    let gateway = start_fixture_gateway().await.unwrap();
    for mode in MODES {
        let (client, _) = connect(&gateway, SURFACE_READ, Caller::TeamA, mode).await;
        let missing = client.list_resources(None).await;
        let Err(ServiceError::McpError(error)) = missing else {
            panic!("{mode:?}: resources/list was served: {missing:?}");
        };
        assert_eq!(error.code, ErrorCode::METHOD_NOT_FOUND, "{mode:?}");
        let tools = client.list_all_tools().await.unwrap();
        assert!(!tools.is_empty(), "{mode:?}");
        client.cancel().await.unwrap();
    }
}

/// Waits up to five seconds for `condition`.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what} did not happen within five seconds");
}

#[tokio::test]
async fn a_call_the_sdk_abandons_still_runs_to_the_end_of_its_row() {
    let gateway = start_fixture_gateway().await.unwrap();
    let caller = Caller::TeamA;
    for (index, mode) in MODES.into_iter().enumerate() {
        let (client, _) = connect(&gateway, SURFACE_READ, caller, mode).await;
        let gate = gateway.connector().hang_next();
        let peer = client.peer().clone();
        let params = read(
            caller.own_document(),
            &format!("toolu_rmcp_abandoned_{index}"),
        );
        let call = tokio::spawn(async move { peer.call_tool(params).await });
        eventually("the call reaching the tool", || gate.waiting() == 1).await;

        // The client goes away with the call in flight, which closes its connection.
        call.abort();
        client.cancel().await.unwrap();
        let row = gateway.store().rows().last().cloned().unwrap();
        assert_eq!(row.decision, DecisionKind::Allow, "{mode:?}");
        assert_eq!(
            row.completion, None,
            "{mode:?}: finished before the tool did"
        );

        gate.open();
        eventually("the row being finished", || {
            gateway.store().rows()[index].completion.is_some()
        })
        .await;
        let completion = gateway.store().rows()[index].completion.clone().unwrap();
        assert_eq!(completion.outcome, Outcome::Ok, "{mode:?}");
    }
}

#[tokio::test]
async fn concurrent_calls_on_one_client_are_each_answered_and_recorded() {
    const CALLS: usize = 8;
    let gateway = start_fixture_gateway().await.unwrap();
    let caller = Caller::TeamA;
    for mode in MODES {
        let (client, _) = connect(&gateway, SURFACE_READ, caller, mode).await;
        let mut calls = tokio::task::JoinSet::new();
        for index in 0..CALLS {
            let peer = client.peer().clone();
            let document = if index % 2 == 0 {
                caller.own_document()
            } else {
                other_document(caller)
            };
            let params = read(document, &format!("toolu_rmcp_{mode:?}_{index}"));
            calls.spawn(async move { (index, peer.call_tool(params).await) });
        }
        while let Some(joined) = calls.join_next().await {
            let (index, answer) = joined.unwrap();
            match answer {
                Ok(result) if index % 2 == 0 => assert_eq!(result.is_error, Some(false)),
                Err(ServiceError::McpError(error)) if index % 2 == 1 => {
                    assert_eq!(i64::from(error.code.0), DENIAL_CODE);
                }
                other => panic!("{mode:?}, call {index}: {other:?}"),
            }
        }
        client.cancel().await.unwrap();
    }
    let rows = gateway.store().rows();
    assert_eq!(rows.len(), CALLS * MODES.len());
    let ids: BTreeSet<String> = rows
        .iter()
        .map(|row| row.tool_use_id.as_ref().unwrap().as_str().to_owned())
        .collect();
    assert_eq!(ids.len(), rows.len(), "each call has its own row");
    assert_eq!(
        gateway.connector().received().len(),
        CALLS / 2 * MODES.len()
    );
}
