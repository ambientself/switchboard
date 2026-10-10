//! The request path, design section 6: from a request that reached the endpoint to its answer.
//!
//! [`RequestPath`] holds the [`Gates`] and runs every step after the HTTP layer's own checks
//! (host, origin and body size). It is split where the body is read, so the HTTP layer can run
//! identity before it reads a byte of the body:
//!
//! 1. [`RequestPath::admit`] takes the method and headers only. It refuses what is not a JSON
//!    POST (405, 415, 406), then checks the caller's bearer token. A caller who cannot be
//!    verified gets one 401 whatever the cause; the cause goes to the log and nowhere else.
//! 2. [`RequestPath::respond`] takes what `admit` let through, the surface from the URL, and
//!    the headers and body. It parses the request with [`gateway_mcp::parse`] and answers it.
//!
//! [`RequestPath::handle`] runs both, in that order.
//!
//! The path emits decision 0009's telemetry events to its [`Telemetry`], each naming the
//! deployment and the request's [`Source`]: `identity_failed` for each caller `admit` refuses,
//! with the cause and the issuer and subject the token claimed; `unparsable_body` for each
//! protocol refusal, with its kind; and `initialize`, `ping` and `discover` for each one
//! answered. Emitting never waits: a full queue drops the event and counts the drop.
//!
//! What `respond` does with each request:
//!
//! - A protocol refusal is answered as [`gateway_mcp`] renders it, and a notification gets 202
//!   with no body. Neither writes a row.
//! - `initialize`, `ping` and `server/discover` are answered with no decision and no audit row:
//!   decision 0009 makes them telemetry. They still need a verified caller, because `admit` ran
//!   first.
//! - `tools/list` selects the caller's profile and finds the tools on the surface that pass
//!   the core's checks. It writes a row of kind `list` naming them ([`audit::listed`]), and
//!   only then answers, with the tools the core hands back and their catalog definitions
//!   (decision 0009). If the row cannot be written, the list is refused with the audit
//!   sentence and lists nothing. The answer names the row in its `_meta`, unless audit is
//!   disabled.
//! - `tools/call` reads the call's resources through the adapter registered for the approved
//!   tool's connector, decides, writes the row, runs the tool if allowed, completes the row and
//!   answers. A denial is answered with the sentence the row holds. The answer names the row
//!   it wrote, in the result's `_meta` or in `error.data` (decision 0009), so a person can
//!   quote it; see [`gateway_mcp::render_with_row`]. It names none when begin failed or audit
//!   is disabled, because then no row was written under that identifier.
//! - An allowed call whose connector is not registered is given up: its row is completed as
//!   `error` and it is answered 500. The boot gates and every reload refuse such a policy, so
//!   this is a fault in the gateway.
//!
//! A client that disconnects is told apart by the [`Disconnect`] `respond` is given (decision
//! 0009, "Where a call runs"). If it has fired once the row is begun, the connector is not
//! called and the row is completed as `error`. If it fires while a read runs, the read is
//! cancelled and recorded as `error`. A side effect runs to completion whatever it does. Either
//! way the answer is still made; nobody is left to read it.
//!
//! Each request takes the policy served at that moment once ([`Gates::policy`]) and decides
//! everything from it, so a registry reload never splits one request across two versions.
//!
//! What the path does not do yet, and why:
//!
//! - **Identity failures are telemetry, not audited**, as decision 0009 records: an audit row
//!   needs a proved principal, which a failed caller does not have. With identity disabled
//!   there is no principal either, so `tools/list` lists nothing and every `tools/call` is
//!   refused with [`IDENTITY_DISABLED`], with no row.
//! - **There is no answer budget.** The core gives out the answer only once the store's
//!   `finish` returns, so the path waits for it, however long that takes. The budget belongs
//!   inside the store (#10).
//! - **The tool-use identifier is bounded here.** It comes from the caller's `_meta` and the
//!   core writes it to the row as given, so one longer than [`MAX_TOOL_USE_ID`] or holding
//!   anything but printable ASCII is dropped, with a warning.
//!
//! The future [`RequestPath::respond`] returns owns everything it uses and is `Send +
//! 'static`. The HTTP layer must spawn it as its own task rather than await it on the
//! request's future: a client that disconnects then cannot stop a call half way, between
//! running the tool and completing its row. A disconnect reaches the call only through the
//! [`Disconnect`], and only where decision 0009 says it may.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use gateway_core::audit::{self, Answer, AuditRowId, Begun, RequestMetadata, RowStart};
use gateway_core::{
    ApprovedTool, CallContext, CallerContext, Classification, Connector, Decision,
    IDENTITY_FAILURE, Principal, Proved, RequestedTool, Resources, SurfaceName, ToolUseId, decide,
    list_tools,
};
use gateway_identity::{Clock, Verification};
use gateway_mcp::{
    Call, HttpResponse, Inbound, Rejection, Reply, Request, ServerInfo, ToolCall, ToolEntry,
};
use http::header::AUTHORIZATION;
use http::{HeaderMap, Method};
use serde_json::Value;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::boot::{DEFAULT_CALL_DEADLINE, GateState, Gates, Reads, Results};
use crate::catalog::ToolDefinition;
use crate::policy::ServedPolicy;
use crate::proxied::{CheckedArguments, registry_resources};
use crate::telemetry::{Event, Surface, Telemetry};

/// The longest tool-use identifier written to an audit row, in bytes. A longer one is dropped.
pub const MAX_TOOL_USE_ID: usize = 128;

/// The sentence every `tools/call` is refused with while identity is disabled. No principal was
/// proved, so nothing can be decided and no row can be written.
pub const IDENTITY_DISABLED: &str = "This gateway is running with identity checking turned off, so it cannot tell who is calling and refuses every tool call. Nothing ran.";

/// What `initialize` and `server/discover` say while identity is disabled.
pub const IDENTITY_DISABLED_NOTE: &str = "Identity checking is turned off on this gateway: callers are not verified, no tools are listed and every tool call is refused.";

/// What `initialize` and `server/discover` say while audit is disabled.
pub const AUDIT_DISABLED_NOTE: &str =
    "Audit is turned off on this gateway: tool calls run with no record of them.";

/// The name the gateway gives itself in `serverInfo`.
pub const SERVER_NAME: &str = "switchboard";

/// What a call is answered with when its client disconnected before it ran. Nobody is left to
/// read it; its row is completed as `error`.
pub const DISCONNECTED_BEFORE_RUN: &str =
    "The caller disconnected before the call ran, so nothing ran.";

/// What a call whose connector is not registered is answered with, 500.
const NO_CONNECTOR: &str =
    "The gateway has no connector for this tool. This is a fault in the gateway's configuration.";

/// Whether the client that sent a request has disconnected, for [`RequestPath::respond`].
///
/// [`Disconnect::pair`] makes one with the [`DisconnectOnDrop`] that fires it, and
/// [`Disconnect::never`] one that never fires. It works with or without an async runtime.
#[derive(Debug)]
pub struct Disconnect(Signal);

#[derive(Debug)]
enum Signal {
    /// Not fired yet, and it may.
    Waiting(oneshot::Receiver<()>),
    /// Fired.
    Fired,
    /// It never will: it was disarmed, or made by [`Disconnect::never`].
    Never,
}

/// Fires its [`Disconnect`] when it is dropped, unless it was disarmed first. The HTTP layer
/// holds it in the request's handler, whose future is dropped when the client goes away.
#[derive(Debug)]
pub struct DisconnectOnDrop(Option<oneshot::Sender<()>>);

impl Disconnect {
    /// A signal and what fires it.
    pub fn pair() -> (DisconnectOnDrop, Disconnect) {
        let (sender, receiver) = oneshot::channel();
        (
            DisconnectOnDrop(Some(sender)),
            Disconnect(Signal::Waiting(receiver)),
        )
    }

    /// A signal that never fires: for a caller with no connection to lose.
    pub fn never() -> Self {
        Self(Signal::Never)
    }

    /// Whether it has fired.
    fn has_fired(&mut self) -> bool {
        if let Signal::Waiting(receiver) = &mut self.0 {
            match receiver.try_recv() {
                Ok(()) => self.0 = Signal::Fired,
                Err(oneshot::error::TryRecvError::Closed) => self.0 = Signal::Never,
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        matches!(self.0, Signal::Fired)
    }

    /// Completes when it fires, and never if it cannot.
    async fn fired(self) {
        let fired = match self.0 {
            Signal::Waiting(receiver) => receiver.await.is_ok(),
            Signal::Fired => true,
            Signal::Never => false,
        };
        if !fired {
            std::future::pending::<()>().await;
        }
    }
}

impl DisconnectOnDrop {
    /// The client is still here: dropping this no longer fires the signal.
    pub fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for DisconnectOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // The receiver may be gone already, with the answer it belonged to.
            let _ = sender.send(());
        }
    }
}

/// The request path over one configuration that passed the boot gates. Cheap to clone; clones
/// share the gates.
#[derive(Clone)]
pub struct RequestPath {
    inner: Arc<Inner>,
}

struct Inner {
    gates: Gates,
    server: ServerInfo,
    telemetry: Telemetry,
}

impl fmt::Debug for RequestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestPath")
            .field("gates", &self.inner.gates)
            .field("server", &self.inner.server)
            .field("telemetry", &self.inner.telemetry)
            .finish()
    }
}

/// Where a request came from, as its telemetry events record it: the surface its URL named,
/// escaped and capped, and the peer's address. Either can be unknown: the URL's surface may not
/// decode to text, and a request that did not come over a connection has no peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Source {
    /// The surface the URL named.
    pub surface: Option<Surface>,
    /// The peer's address.
    pub address: Option<SocketAddr>,
}

impl Source {
    /// The source of a request for `surface`, as the URL named it, from `address`.
    pub fn new(surface: Option<&str>, address: Option<SocketAddr>) -> Self {
        Self {
            surface: surface.map(Surface::new),
            address,
        }
    }
}

/// A request [`RequestPath::admit`] let through: a JSON POST from a caller who was verified,
/// or from anyone while identity is disabled.
///
/// Its fields are private and `admit` is the only way to make one, so [`RequestPath::respond`]
/// cannot be reached without the identity check having run. It carries the [`Source`] `admit`
/// was given, for the events `respond` emits.
#[derive(Debug)]
pub struct Admitted {
    caller: Caller,
    source: Source,
}

impl Admitted {
    /// The proved caller, or `None` while identity is disabled.
    pub fn principal(&self) -> Option<&Proved<Principal>> {
        match &self.caller {
            Caller::Proved(principal) => Some(principal),
            Caller::Unchecked => None,
        }
    }
}

#[derive(Debug)]
enum Caller {
    Proved(Proved<Principal>),
    /// Identity is disabled: nobody was checked.
    Unchecked,
}

impl RequestPath {
    /// The path for `gates`, with [`Telemetry::detached`]: its events are counted, and dropped.
    /// `serverInfo` names the gateway [`SERVER_NAME`] at this crate's version, and its
    /// instructions say which gates are turned off.
    pub fn new(gates: Gates) -> Self {
        Self::with_telemetry(gates, Telemetry::detached())
    }

    /// The path for `gates`, emitting its events to `telemetry`.
    pub fn with_telemetry(gates: Gates, telemetry: Telemetry) -> Self {
        let server = server_info(&gates);
        Self {
            inner: Arc::new(Inner {
                gates,
                server,
                telemetry,
            }),
        }
    }

    /// The gates the path serves.
    pub fn gates(&self) -> &Gates {
        &self.inner.gates
    }

    /// Where the path emits its events.
    pub fn telemetry(&self) -> &Telemetry {
        &self.inner.telemetry
    }

    /// How the gateway describes itself to clients.
    pub fn server_info(&self) -> &ServerInfo {
        &self.inner.server
    }

    /// The checks that need only the method and headers, in order: the transport checks
    /// (405, 415, 406), then identity. Call it before reading the body.
    ///
    /// The token is the one `Authorization: Bearer` header; the scheme is matched without
    /// regard to case. A missing header, two of them, a value that is not text, or another
    /// scheme count as no token. Every identity failure is the same 401, with the core's one
    /// sentence and a `Bearer` challenge. No audit row is written: decision 0009 makes an
    /// identity failure telemetry. Each one emits one `identity_failed` event naming `source`,
    /// the cause, and the issuer and subject the token claimed, as the identity crate escaped
    /// and capped them. None of that is sent.
    // The error is the response to send, which is large. It is built at most once per request
    // and sent as it is, so boxing it would only add an allocation.
    #[allow(clippy::result_large_err)]
    pub fn admit(
        &self,
        method: &Method,
        headers: &HeaderMap,
        source: &Source,
    ) -> Result<Admitted, HttpResponse> {
        gateway_mcp::check_transport(method, headers).map_err(|rejection| rejection.response())?;
        let gates = &self.inner.gates;
        let caller = match gates.identity().check(bearer_token(headers)) {
            Verification::Proved(principal) => Caller::Proved(principal),
            Verification::Disabled => Caller::Unchecked,
            Verification::Failed(failure) => {
                self.emit(Event::IdentityFailed {
                    deployment: gates.deployment().clone(),
                    surface: source.surface.clone(),
                    source: source.address,
                    cause: failure.detail().clone(),
                    claimed: failure.claimed().clone(),
                });
                return Err(Rejection::unauthorized(IDENTITY_FAILURE).response());
            }
        };
        Ok(Admitted {
            caller,
            source: source.clone(),
        })
    }

    /// Parses the request and returns the future that answers it.
    ///
    /// `surface` is the surface the URL named. The parse runs now; the future owns everything
    /// else it needs and is `Send + 'static`, so the HTTP layer can spawn it, and should, so
    /// that a client that goes away cannot cancel a call between running the tool and
    /// completing its row. `disconnect` fires when the client goes away; see the
    /// [module documentation](self) for what that does to a call.
    pub fn respond(
        &self,
        admitted: Admitted,
        surface: &str,
        headers: &HeaderMap,
        body: &[u8],
        disconnect: Disconnect,
    ) -> impl Future<Output = HttpResponse> + Send + 'static + use<> {
        let parsed = gateway_mcp::parse(&Method::POST, headers, body);
        let path = self.clone();
        let surface = SurfaceName::new(surface);
        async move {
            let Admitted { caller, source } = admitted;
            match parsed {
                Err(rejection) => {
                    tracing::debug!(%rejection, "refused a request at the protocol layer");
                    path.emit(Event::Unparsable {
                        deployment: path.inner.gates.deployment().clone(),
                        surface: source.surface,
                        source: source.address,
                        rejection: rejection.kind(),
                    });
                    rejection.response()
                }
                Ok(Inbound::Notification { method }) => {
                    tracing::debug!(%method, "accepted a notification");
                    HttpResponse::accepted()
                }
                Ok(Inbound::Request(request)) => {
                    path.answer(caller, source, surface, request, disconnect)
                        .await
                }
            }
        }
    }

    /// [`admit`](Self::admit), then [`respond`](Self::respond): the whole path, for a caller
    /// that already holds the body. There is no connection to lose, so nothing is cancelled.
    pub async fn handle(
        &self,
        method: &Method,
        headers: &HeaderMap,
        surface: &str,
        body: &[u8],
    ) -> HttpResponse {
        let source = Source::new(Some(surface), None);
        let admitted = match self.admit(method, headers, &source) {
            Ok(admitted) => admitted,
            Err(response) => return response,
        };
        self.respond(admitted, surface, headers, body, Disconnect::never())
            .await
    }

    /// Counts `event` and queues it for the log. Never waits.
    fn emit(&self, event: Event) {
        self.inner.telemetry.emit(event);
    }

    async fn answer(
        self,
        caller: Caller,
        source: Source,
        surface: SurfaceName,
        request: Request,
        disconnect: Disconnect,
    ) -> HttpResponse {
        let Request { id, era, call } = request;
        let deployment = || self.inner.gates.deployment().clone();
        let (reply, row) = match call {
            Call::Initialize => {
                self.emit(Event::Initialize {
                    deployment: deployment(),
                    surface: source.surface,
                    source: source.address,
                });
                (Reply::Initialized, None)
            }
            Call::Ping => {
                self.emit(Event::Ping {
                    deployment: deployment(),
                    surface: source.surface,
                    source: source.address,
                });
                (Reply::Pong, None)
            }
            Call::Discover => {
                self.emit(Event::Discover {
                    deployment: deployment(),
                    surface: source.surface,
                    source: source.address,
                });
                (Reply::Discovered, None)
            }
            Call::ToolsList => self.list(caller, surface).await,
            Call::ToolsCall(call) => self.call(caller, surface, call, disconnect).await,
        };
        let row = row.as_ref().map(AuditRowId::as_str);
        gateway_mcp::render_with_row(&self.inner.server, era, &id, reply, row)
    }

    /// `tools/list`: design section 6's steps 1 to 5 for every tool on the surface, keeping
    /// those that pass, then the row of kind `list` (decision 0009). The answer, and the row
    /// to name in it.
    ///
    /// The answer is built from what [`audit::listed`] returns once the row is written, never
    /// from the list handed to it, so nothing is listed without its row.
    async fn list(&self, caller: Caller, surface: SurfaceName) -> (Reply, Option<AuditRowId>) {
        let Caller::Proved(principal) = caller else {
            return (Reply::Tools(Vec::new()), None);
        };
        let gates = &self.inner.gates;
        let policy = gates.policy();
        let caller = self.caller_context(&policy, principal, surface);
        let tools = list_tools(policy.snapshot(), &caller);
        // One identifier per list, made here. A list row has no deadline, so none is given.
        let start = RowStart {
            row: AuditRowId::new(Uuid::now_v7().to_string()),
            instance: gates.instance().clone(),
            call_deadline_ms: 0,
        };
        let writing = Instant::now();
        let written = audit::listed(
            gates.audit_store().as_ref(),
            start,
            &caller,
            policy.revision().clone(),
            tools,
            None,
        )
        .await;
        let list_us = micros(writing.elapsed());
        match written {
            Err(failure) => {
                tracing::error!(
                    %failure,
                    list_us,
                    "refused a tool list: its audit row could not be written"
                );
                (Reply::Denied(failure.sentence().to_owned()), None)
            }
            Ok(listed) => {
                tracing::info!(
                    row = listed.row().as_str(),
                    tools = listed.tools().len(),
                    list_us,
                    "listed tools"
                );
                let row = self.quotable(listed.row());
                (Reply::Tools(entries(&policy, listed.tools())), row)
            }
        }
    }

    /// `tools/call`: design section 6's steps 1 to 9. The answer, and the row to name in it.
    async fn call(
        &self,
        caller: Caller,
        surface: SurfaceName,
        call: ToolCall,
        disconnect: Disconnect,
    ) -> (Reply, Option<AuditRowId>) {
        let gates = &self.inner.gates;
        let Caller::Proved(principal) = caller else {
            tracing::warn!(
                deployment = %gates.deployment(),
                "refused a tool call because identity is disabled"
            );
            return (Reply::Denied(IDENTITY_DISABLED.to_owned()), None);
        };
        let policy = gates.policy();
        self.decide_and_run(&policy, principal, surface, call, disconnect)
            .await
    }
}

fn entries(policy: &ServedPolicy, tools: &[ApprovedTool]) -> Vec<ToolEntry> {
    let catalog = policy.catalog();
    tools
        .iter()
        .filter_map(|tool| match catalog.definition(&tool.name) {
            Some(definition) => Some(entry(tool, definition)),
            None => {
                // The boot gates refuse an approved tool without a definition.
                tracing::error!(tool = %tool.name, "an approved tool has no definition");
                None
            }
        })
        .collect()
}

impl RequestPath {
    /// The answer to a call from a proved caller, and the row to name in it: the denial's row,
    /// or the row of the call that ran or was given up, whether or not it could be completed.
    async fn decide_and_run(
        &self,
        policy: &ServedPolicy,
        principal: Proved<Principal>,
        surface: SurfaceName,
        call: ToolCall,
        mut disconnect: Disconnect,
    ) -> (Reply, Option<AuditRowId>) {
        let gates = &self.inner.gates;
        let snapshot = policy.snapshot();
        let ToolCall {
            name,
            arguments,
            tool_use_id,
        } = call;
        let arguments = Value::Object(arguments);
        let requested = RequestedTool::new(name);
        let resources = self.resources(policy, &requested, &arguments);
        let context = CallContext {
            caller: self.caller_context(policy, principal, surface),
            tool: requested,
            resources,
        };
        let decided = Instant::now();
        let decision = decide(snapshot, &context);
        let decide_us = micros(decided.elapsed());
        let metadata = RequestMetadata {
            tool_use_id: bounded_tool_use_id(tool_use_id),
            claimed_team: None,
        };

        let store = gates.audit_store().as_ref();
        // One identifier per call, made here and nowhere else (decision 0009). A retry of
        // begin, when there is one, reuses it; it is never made again for the same call.
        let start = RowStart {
            row: AuditRowId::new(Uuid::now_v7().to_string()),
            instance: gates.instance().clone(),
            call_deadline_ms: millis(self.call_deadline(&decision)),
        };
        let begun = Instant::now();
        let begin = audit::begin(store, start, decision, arguments, metadata).await;
        let begin_us = micros(begun.elapsed());
        let guard = match begin {
            Err(failure) => {
                tracing::error!(
                    %failure,
                    decide_us,
                    begin_us,
                    "refused a tool call: its audit row could not be written"
                );
                // No row is named. The row may not exist, or may exist and later be completed
                // as an error by recovery, so its identifier would point the caller at a row
                // that says something other than this refusal, or at nothing.
                return (Reply::Denied(failure.sentence().to_owned()), None);
            }
            Ok(Begun::Denied(refusal)) => {
                tracing::info!(
                    row = refusal.row().as_str(),
                    reason = ?refusal.reason().kind(),
                    decide_us,
                    begin_us,
                    "denied a tool call"
                );
                let row = self.quotable(refusal.row());
                return (Reply::Denied(refusal.sentence().to_owned()), row);
            }
            Ok(Begun::Allowed(guard)) => guard,
        };
        let row = guard.row().clone();
        let named = self.quotable(&row);
        let tool = guard.tool().name.clone();
        // Decision 0009: a client gone before the connector is called is not called for.
        if disconnect.has_fired() {
            let gave_up = audit::give_up(store, guard).await;
            if let Some(failure) = gave_up.failure() {
                tracing::error!(
                    %failure,
                    row = row.as_str(),
                    "a tool call was given up but its audit row could not be completed"
                );
            }
            tracing::info!(
                row = row.as_str(),
                %tool,
                decide_us,
                begin_us,
                "gave up a tool call: its client disconnected before it ran, and its row was \
                 completed as error"
            );
            return (Reply::ToolError(DISCONNECTED_BEFORE_RUN.to_owned()), named);
        }
        let Some(registered) = gates.registered(&guard.tool().connector) else {
            // The boot gates and every reload refuse a tool on a surface whose connector is not
            // registered, so this is a fault in the gateway. Nothing can run; the row is
            // completed as error rather than left open.
            let connector = guard.tool().connector.clone();
            let gave_up = audit::give_up(store, guard).await;
            tracing::error!(
                row = row.as_str(),
                %connector,
                "an allowed tool's connector is not registered; its row was completed as error"
            );
            if let Some(failure) = gave_up.failure() {
                tracing::error!(
                    %failure,
                    row = row.as_str(),
                    "a tool call was given up but its audit row could not be completed"
                );
            }
            return (Reply::Internal(NO_CONNECTOR.to_owned()), named);
        };
        let results = Some(registered.results);
        // A proxied server's call is checked against the schema of the policy this request
        // took, the one its decision was made from, never a version served since.
        let checked;
        let connector: &dyn Connector = match &registered.reads {
            Reads::Adapter(_) => registered.connector.as_ref(),
            Reads::Registry => {
                checked = CheckedArguments::new(
                    registered.connector.as_ref(),
                    policy,
                    gates.live_policy(),
                );
                &checked
            }
        };

        let started = gates.clock().now();
        let running = Instant::now();
        // A read is cancelled if its client goes; a side effect runs to completion.
        let ran = audit::run_unless(connector, guard, disconnect.fired()).await;
        let run_us = micros(running.elapsed());
        let latency_ms = elapsed_millis(gates.clock().as_ref(), started);
        // No answer budget: the core gives out the answer when the store's finish returns.
        let finishing = Instant::now();
        let finished = audit::finish(store, ran, latency_ms).await;
        let finish_us = micros(finishing.elapsed());
        if let Some(failure) = finished.failure() {
            tracing::error!(%failure, "a tool call ran but its audit row could not be completed");
        }
        tracing::info!(
            row = row.as_str(),
            %tool,
            outcome = outcome_name(finished.answer()),
            latency_ms,
            decide_us,
            begin_us,
            run_us,
            finish_us,
            "ran a tool call"
        );
        let reply = match finished.answer().clone() {
            Answer::Ok(value) if results == Some(Results::ToolResults) => passed_on(value),
            Answer::Ok(value) => Reply::ToolOk(value),
            Answer::Error(message) => Reply::ToolError(message),
            Answer::Refused(sentence) => Reply::Denied(sentence),
            Answer::AuditFailed { sentence } => Reply::Denied(sentence.to_owned()),
        };
        (reply, named)
    }

    /// The row to name in the answer: `row`, unless audit is disabled. The disabled store
    /// writes nothing, so its identifier would name no row.
    fn quotable(&self, row: &AuditRowId) -> Option<AuditRowId> {
        (self.inner.gates.audit_state() == GateState::On).then(|| row.clone())
    }

    /// The resources the call names, from the adapter registered with the connector of the
    /// approved tool the call names. Never chosen by anything else in the request.
    ///
    /// For a name that is not an approved tool there is no adapter, so nobody can say what the
    /// call names: [`Resources::Unknown`], which its row records as `unknown`. Recording none
    /// would read as a call that named nothing. The decision denies the call before it looks.
    ///
    /// A proxied server's tools are read with the adapter the request's own policy version
    /// approved, the version the decision is made from.
    fn resources(
        &self,
        policy: &ServedPolicy,
        requested: &RequestedTool,
        arguments: &Value,
    ) -> Resources {
        let gates = &self.inner.gates;
        let Some(approved) = requested
            .name()
            .ok()
            .and_then(|name| policy.snapshot().tool(&name))
        else {
            return Resources::Unknown;
        };
        match gates
            .registered(&approved.connector)
            .map(|registered| &registered.reads)
        {
            Some(Reads::Adapter(adapter)) => adapter.resources(approved, arguments),
            Some(Reads::Registry) => registry_resources(policy, approved, arguments),
            // Every connector is registered with an adapter, and the boot gates refuse an
            // approved tool whose connector is not registered.
            None => Resources::Named(Vec::new()),
        }
    }

    /// The call deadline of the connector serving the tool `decision` approved, which the row's
    /// deadline includes. A call denied before any tool was found, such as one naming no
    /// approved tool, runs nothing; its row has [`DEFAULT_CALL_DEADLINE`].
    fn call_deadline(&self, decision: &Decision) -> Duration {
        decision
            .tool()
            .and_then(|tool| self.inner.gates.registered(&tool.connector))
            .map_or(DEFAULT_CALL_DEADLINE, |registered| registered.call_deadline)
    }

    /// Design section 6's step 3: the profile, from the configured rules. There is no
    /// delegation verifier yet.
    fn caller_context(
        &self,
        policy: &ServedPolicy,
        principal: Proved<Principal>,
        surface: SurfaceName,
    ) -> CallerContext {
        let gates = &self.inner.gates;
        CallerContext {
            profile: policy.select(principal.get()),
            principal,
            delegation: None,
            surface,
            deployment: gates.deployment().clone(),
        }
    }
}

/// The token from the one `Authorization: Bearer` header, or `None`.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

/// The caller's tool-use identifier, if it is 1 to [`MAX_TOOL_USE_ID`] printable ASCII
/// characters other than space. Anything else is dropped rather than cut, because a cut
/// identifier would point the caller's control plane at the wrong row.
fn bounded_tool_use_id(value: Option<String>) -> Option<ToolUseId> {
    let value = value?;
    let acceptable = !value.is_empty()
        && value.len() <= MAX_TOOL_USE_ID
        && value.bytes().all(|byte| byte.is_ascii_graphic());
    if acceptable {
        Some(ToolUseId::new(value))
    } else {
        // The value is the caller's text, so only its length is logged.
        tracing::warn!(
            length = value.len(),
            "dropped a tool-use identifier that is not 1 to {MAX_TOOL_USE_ID} printable ASCII characters"
        );
        None
    }
}

fn entry(tool: &ApprovedTool, definition: &ToolDefinition) -> ToolEntry {
    ToolEntry {
        name: tool.name.to_string(),
        title: definition.title.clone(),
        description: definition.description.clone(),
        input_schema: definition.input_schema.clone(),
        read_only: tool.classification == Classification::Read,
    }
}

/// A proxied server's tool result as the caller gets it: the server's content blocks and
/// structured content, as it sent them, not wrapped in another text block. The connector hands
/// on only a result with a content list; anything else is logged and sent as a value, wrapped.
fn passed_on(value: Value) -> Reply {
    if let Value::Object(result) = &value
        && let Some(Value::Array(content)) = result.get("content")
    {
        return Reply::ToolResult {
            content: content.clone(),
            structured_content: result.get("structuredContent").cloned(),
        };
    }
    tracing::error!("a proxied server's tool result has no content list; it is sent as a value");
    Reply::ToolOk(value)
}

/// How an answer is named in the log.
fn outcome_name(answer: &Answer) -> &'static str {
    match answer {
        Answer::Ok(_) => "ok",
        Answer::Error(_) => "error",
        Answer::Refused(_) => "refused",
        Answer::AuditFailed { .. } => "audit_failed",
    }
}

/// A duration in whole microseconds, for the log.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn elapsed_millis(clock: &dyn Clock, since: SystemTime) -> u64 {
    clock.now().duration_since(since).map_or(0, |elapsed| {
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
    })
}

fn server_info(gates: &Gates) -> ServerInfo {
    let mut notes = Vec::new();
    if gates.identity_state() == GateState::Disabled {
        notes.push(IDENTITY_DISABLED_NOTE);
    }
    if gates.audit_state() == GateState::Disabled {
        notes.push(AUDIT_DISABLED_NOTE);
    }
    ServerInfo {
        name: SERVER_NAME.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        instructions: (!notes.is_empty()).then(|| notes.join(" ")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use http::HeaderValue;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn the_bearer_token_is_read_from_one_header_with_any_case_of_scheme() {
        assert_eq!(bearer_token(&headers(&["Bearer abc"])), Some("abc"));
        assert_eq!(bearer_token(&headers(&["bearer abc"])), Some("abc"));
        assert_eq!(bearer_token(&headers(&["BEARER  abc "])), Some("abc"));
    }

    #[test]
    fn anything_but_one_bearer_header_is_no_token() {
        assert_eq!(bearer_token(&headers(&[])), None);
        assert_eq!(bearer_token(&headers(&["Bearer abc", "Bearer abc"])), None);
        assert_eq!(bearer_token(&headers(&["Basic abc"])), None);
        assert_eq!(bearer_token(&headers(&["Bearerabc"])), None);
        assert_eq!(bearer_token(&headers(&["abc"])), None);
        let mut binary = HeaderMap::new();
        binary.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xffabc").unwrap(),
        );
        assert_eq!(bearer_token(&binary), None);
    }

    #[test]
    fn a_tool_use_identifier_is_kept_only_within_its_bound() {
        let kept = |value: &str| bounded_tool_use_id(Some(value.to_owned()));
        assert_eq!(kept("toolu_01"), Some(ToolUseId::new("toolu_01")));
        let longest = "a".repeat(MAX_TOOL_USE_ID);
        assert_eq!(kept(&longest), Some(ToolUseId::new(longest.clone())));
        assert_eq!(kept(&"a".repeat(MAX_TOOL_USE_ID + 1)), None);
        assert_eq!(kept(""), None);
        assert_eq!(kept("tool use"), None);
        assert_eq!(kept("toolu\n01"), None);
        assert_eq!(kept("toolu\u{1b}[31m"), None);
        assert_eq!(kept("toolu_é"), None);
        assert_eq!(bounded_tool_use_id(None), None);
    }

    struct FixtureResources;

    impl crate::ResourceAdapter for FixtureResources {
        fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
            gateway_testkit::FixtureConnector::resources_of(tool.name.as_str(), arguments)
        }
    }

    /// The boot gates and every reload refuse a policy serving a tool whose connector is not
    /// registered, so this is reached only by taking the connector out of gates that passed.
    #[test]
    fn an_allowed_call_whose_connector_is_not_registered_completes_its_row_as_error() {
        use gateway_core::audit::{Completion, DecisionKind, Outcome};
        use gateway_testkit::{
            AUDIENCE, CONNECTOR, Caller, FakeCredentialSource, Fixture, FixtureConnector,
            InMemoryAuditStore, SCOPED_READ_TOOL, SURFACE_READ, TEAM_A, TEAM_A_SUBJECT,
        };
        use serde_json::json;

        let fixture = Fixture::new().unwrap();
        let connector = Arc::new(FixtureConnector::new(Arc::new(FakeCredentialSource::new())));
        let store = Arc::new(InMemoryAuditStore::new());
        let issuer = &fixture.workload_issuer;
        let definition = |name: &str| {
            json!({
                "name": name,
                "description": "A fixture tool.",
                "input_schema": {"type": "object"},
            })
        };
        let config: crate::Config = serde_json::from_value(json!({
            "deployment": "path-unit-test",
            "identity": {"enforce": [{
                "issuer": issuer.issuer(),
                "audiences": [AUDIENCE],
                "kind": {"workload": {"subjects": {TEAM_A_SUBJECT: TEAM_A}}},
                "algorithm": "ES256",
                "keys": serde_json::to_value(issuer.jwk_set()).unwrap(),
                "max_lifetime_secs": gateway_testkit::DEFAULT_MAX_LIFETIME,
                "leeway_secs": gateway_testkit::DEFAULT_LEEWAY,
            }]},
            "audit": {},
            "http": {"allowed_hosts": ["localhost"]},
            "policy": gateway_testkit::policy_data(),
            "catalog": [
                definition(gateway_testkit::READ_TOOL),
                definition(gateway_testkit::DRAFT_TOOL),
                definition(gateway_testkit::WRITE_TOOL),
                definition(SCOPED_READ_TOOL),
            ],
            "profiles": {"workloads": [{
                "issuer": gateway_testkit::WORKLOAD_ISSUER,
                "team": TEAM_A,
                "profile": gateway_testkit::PROFILE_TEAM_A,
            }]},
        }))
        .unwrap();
        let wiring = crate::Wiring::new(Arc::new(fixture.clock.clone()))
            .audit_store(store.clone())
            .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources));
        let gates = crate::boot::check(config, wiring)
            .unwrap()
            .without_connector(&CONNECTOR.into());
        let path = RequestPath::new(gates);

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("accept", HeaderValue::from_static("application/json"));
        let token = format!("Bearer {}", fixture.token(Caller::TeamA));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&token).unwrap());
        // The scoped read tool checks its own scope, so a call that names no resource reaches
        // the connector lookup rather than being denied for naming none.
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": SCOPED_READ_TOOL, "arguments": {}}});
        let response = gateway_testkit::block_on(path.handle(
            &Method::POST,
            &headers,
            SURFACE_READ,
            body.to_string().as_bytes(),
        ));

        assert_eq!(response.status, http::StatusCode::INTERNAL_SERVER_ERROR);
        let answer: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(answer["error"]["code"], json!(gateway_mcp::INTERNAL_ERROR));
        assert_eq!(answer["error"]["message"], json!(NO_CONNECTOR));
        assert!(connector.received().is_empty(), "a connector was called");
        let rows = store.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, DecisionKind::Allow);
        assert_eq!(
            rows[0].completion,
            Some(Completion {
                outcome: Outcome::Error,
                latency_ms: 0,
            }),
            "the row was left open"
        );
        assert_eq!(store.finish_attempts(), 1);
        let row = answer["error"]["data"][gateway_mcp::AUDIT_ROW_DATA]
            .as_str()
            .expect("the answer names its row");
        assert_eq!(
            store
                .row_with_id(&AuditRowId::new(row))
                .and_then(|row| row.completion),
            rows[0].completion
        );
    }

    #[test]
    fn a_disconnect_fires_when_dropped_and_not_once_disarmed() {
        let (connected, mut disconnect) = Disconnect::pair();
        assert!(!disconnect.has_fired());
        drop(connected);
        assert!(disconnect.has_fired());

        let (connected, mut disconnect) = Disconnect::pair();
        connected.disarm();
        assert!(!disconnect.has_fired());
        let fired = std::pin::pin!(disconnect.fired());
        assert!(
            gateway_testkit::poll_once(fired).is_pending(),
            "a disarmed signal fired"
        );

        let (connected, disconnect) = Disconnect::pair();
        drop(connected);
        assert!(gateway_testkit::poll_once(std::pin::pin!(disconnect.fired())).is_ready());
        assert!(
            gateway_testkit::poll_once(std::pin::pin!(Disconnect::never().fired())).is_pending()
        );
    }

    #[test]
    fn only_a_read_tool_is_marked_read_only() {
        let snapshot = gateway_testkit::policy().unwrap();
        let definition = |name: &str| ToolDefinition {
            name: name.parse().unwrap(),
            title: Some("Title".to_owned()),
            description: "Does a thing.".to_owned(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        for (name, read_only) in [
            (gateway_testkit::READ_TOOL, true),
            (gateway_testkit::SCOPED_READ_TOOL, true),
            (gateway_testkit::DRAFT_TOOL, false),
            (gateway_testkit::WRITE_TOOL, false),
        ] {
            let tool = snapshot.tool(&name.parse().unwrap()).unwrap();
            let entry = entry(tool, &definition(name));
            assert_eq!(entry.read_only, read_only, "{name}");
            assert_eq!(entry.name, name);
            assert_eq!(entry.title.as_deref(), Some("Title"));
            assert_eq!(entry.description, "Does a thing.");
        }
    }
}
