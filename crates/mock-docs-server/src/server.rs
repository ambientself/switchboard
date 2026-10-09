//! The HTTP endpoints: `POST /mcp`, and the admin endpoint that changes the tool list.

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};

use crate::config::{Config, Credential, logged_prefix, sha256};
use crate::documents::{Content, Documents, FAIL_CODE, FAIL_DOC, HUGE_BYTES, SLOW_DOC};
use crate::jwt::{JwtVerifier, Refusal};
use crate::tools::ToolName;

/// The protocol version `initialize` answers with.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// The `MCP-Protocol-Version` header values accepted. A request without the header is
/// accepted too, as the 2025-06-18 specification asks; any other value gets a 400.
pub const ACCEPTED_PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2025-03-26"];
/// The server's name in `initialize`.
pub const SERVER_NAME: &str = "mock-docs-server";

/// The largest request body read, once the caller is accepted: axum's default for a buffered
/// body.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const PARSE_ERROR: i64 = -32700;

/// Where log lines go: one JSON object per line on standard output, or kept in memory for a
/// test to read.
#[derive(Clone, Debug, Default)]
pub struct Log {
    kept: Option<Arc<Mutex<Vec<Value>>>>,
}

impl Log {
    /// Writes each line to standard output.
    pub fn stdout() -> Self {
        Self { kept: None }
    }

    /// Keeps each line in memory, for [`Log::lines`].
    pub fn kept() -> Self {
        Self {
            kept: Some(Arc::default()),
        }
    }

    /// Writes one line.
    pub fn write(&self, line: Value) {
        match &self.kept {
            Some(kept) => kept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line),
            None => {
                use std::io::Write as _;
                // A closed standard output must not take the server down with it.
                let _ = writeln!(std::io::stdout().lock(), "{line}");
            }
        }
    }

    /// The lines kept so far. Empty for a log that writes to standard output.
    pub fn lines(&self) -> Vec<Value> {
        self.kept.as_ref().map_or_else(Vec::new, |kept| {
            kept.lock().unwrap_or_else(PoisonError::into_inner).clone()
        })
    }
}

/// The server. Cheap to clone; every clone serves the same documents and tool list.
#[derive(Clone, Debug)]
pub struct MockDocs {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    accepted: Credential,
    slow: std::time::Duration,
    documents: Documents,
    tools: RwLock<Vec<ToolName>>,
    log: Log,
}

/// Who sent a request, as far as the server can tell.
struct Caller {
    /// The logged prefix of the bearer's SHA-256, or `None` if no bearer came.
    bearer_sha256: Option<String>,
    accepted: bool,
    /// In the JWT mode, what verification found. `None` in the static mode, whose log lines
    /// carry no more than they did before the JWT mode existed.
    jwt: Option<JwtOutcome>,
}

/// What the JWT mode logs about a request beyond the bearer's hash.
struct JwtOutcome {
    /// The verified subject of an accepted token. Nothing is read from a token that failed.
    caller: Option<String>,
    /// Why the token was refused, if it was.
    refusal: Option<Refusal>,
}

/// A JSON-RPC error answer.
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl MockDocs {
    /// A server with the seeded documents, configured by `config`, logging to `log`.
    pub fn new(config: Config, log: Log) -> Self {
        Self {
            inner: Arc::new(Inner {
                accepted: config.accepted,
                slow: config.slow,
                documents: Documents::seeded(),
                tools: RwLock::new(config.tools),
                log,
            }),
        }
    }

    /// The MCP endpoint, `POST /mcp`. Every path answers only the accepted credential.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/mcp", post(mcp_post).fallback(other_request))
            .fallback(other_request)
            .with_state(self.clone())
    }

    /// The admin endpoint: `GET /admin/tools` and `PUT /admin/tools` with
    /// `{"tools": ["list_documents", …]}`. It also answers only the accepted credential. Serve
    /// it on its own listener, so a network policy can keep it apart from the MCP endpoint.
    pub fn admin_router(&self) -> Router {
        Router::new()
            .route("/admin/tools", get(admin_get_tools).put(admin_put_tools))
            .fallback(other_request)
            .with_state(self.clone())
    }

    /// The tools offered now, in order.
    pub fn tools(&self) -> Vec<ToolName> {
        self.inner
            .tools
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Changes the tools offered, from the next request on.
    pub fn set_tools(&self, tools: Vec<ToolName>) {
        *self
            .inner
            .tools
            .write()
            .unwrap_or_else(PoisonError::into_inner) = tools;
    }

    /// The server's log.
    pub fn log(&self) -> &Log {
        &self.inner.log
    }

    fn offers(&self, tool: ToolName) -> bool {
        self.inner
            .tools
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&tool)
    }

    fn authenticate(&self, headers: &HeaderMap) -> Caller {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(bearer_token);
        let accepted = match &self.inner.accepted {
            Credential::Static(accepted) => accepted,
            Credential::Jwt(verifier) => return jwt_caller(verifier, token),
        };
        match token {
            Some(token) => Caller {
                bearer_sha256: Some(logged_prefix(&sha256(token))),
                accepted: accepted.accepts(token),
                jwt: None,
            },
            None => Caller {
                bearer_sha256: None,
                accepted: false,
                jwt: None,
            },
        }
    }

    async fn dispatch(&self, method: &str, params: Option<&Value>) -> Result<Value, RpcError> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => {
                let tools: Vec<Value> =
                    self.tools().into_iter().map(ToolName::definition).collect();
                Ok(json!({ "tools": tools }))
            }
            "tools/call" => self.call_tool(params).await,
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("Method not found: {other}"),
            )),
        }
    }

    async fn call_tool(&self, params: Option<&Value>) -> Result<Value, RpcError> {
        let params = params
            .and_then(Value::as_object)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "params must be an object"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "params.name must be a string"))?;
        let tool = ToolName::parse(name)
            .filter(|tool| self.offers(*tool))
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("Unknown tool: {name}")))?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    "params.arguments must be an object",
                ));
            }
        };
        let values = string_arguments(tool, arguments)?;
        let documents = &self.inner.documents;
        match (tool, values.as_slice()) {
            (ToolName::ListDocuments, [project]) => Ok(match documents.list(project) {
                Some(names) => listing(project, &names),
                None => tool_error(format!("There is no project `{project}`.")),
            }),
            (ToolName::SearchDocuments, [project, query]) => {
                Ok(match documents.search(project, query) {
                    Some(names) => listing(project, &names),
                    None => tool_error(format!("There is no project `{project}`.")),
                })
            }
            (ToolName::ReadDocument, [project, document]) => self.read(project, document).await,
            _ => Err(RpcError::new(INVALID_PARAMS, "wrong number of arguments")),
        }
    }

    async fn read(&self, project: &str, document: &str) -> Result<Value, RpcError> {
        match self.inner.documents.get(project, document) {
            None => Ok(tool_error(format!(
                "There is no document `{document}` in project `{project}`."
            ))),
            Some(Content::Text(text)) => Ok(text_result(text.clone())),
            Some(Content::Slow) => {
                tokio::time::sleep(self.inner.slow).await;
                Ok(text_result(format!(
                    "{SLOW_DOC} answered after {} ms.",
                    self.inner.slow.as_millis()
                )))
            }
            Some(Content::Hang) => std::future::pending().await,
            Some(Content::Fail) => Err(RpcError::new(
                FAIL_CODE,
                format!("{FAIL_DOC} fails on purpose."),
            )),
            Some(Content::Huge) => Ok(text_result("x".repeat(HUGE_BYTES))),
        }
    }
}

/// A caller in the JWT mode: accepted if and only if `token` verifies.
fn jwt_caller(verifier: &JwtVerifier, token: Option<&str>) -> Caller {
    let verdict = match token {
        Some(token) => verifier.verify(token),
        None => Err(Refusal::NoBearer),
    };
    let accepted = verdict.is_ok();
    let (caller, refusal) = match verdict {
        Ok(subject) => (Some(subject), None),
        Err(refusal) => (None, Some(refusal)),
    };
    Caller {
        bearer_sha256: token.map(|token| logged_prefix(&sha256(token))),
        accepted,
        jwt: Some(JwtOutcome { caller, refusal }),
    }
}

/// The token of an `Authorization: Bearer <token>` header. The scheme is matched without
/// regard to case, as RFC 9110 says; any other scheme, or an empty token, is no bearer.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Each declared argument of `tool`, in order. A missing or non-string argument, or one the
/// tool does not declare, is refused.
fn string_arguments(tool: ToolName, arguments: &Map<String, Value>) -> Result<Vec<&str>, RpcError> {
    if let Some(extra) = arguments
        .keys()
        .find(|key| !tool.arguments().contains(&key.as_str()))
    {
        return Err(RpcError::new(
            INVALID_PARAMS,
            format!("{tool} takes no argument `{extra}`"),
        ));
    }
    tool.arguments()
        .iter()
        .map(|name| {
            arguments.get(*name).and_then(Value::as_str).ok_or_else(|| {
                RpcError::new(
                    INVALID_PARAMS,
                    format!("{tool} needs the string argument `{name}`"),
                )
            })
        })
        .collect()
}

fn text_result(text: String) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

fn tool_error(text: String) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

fn listing(project: &str, names: &[&str]) -> Value {
    let structured = json!({"project": project, "documents": names});
    json!({
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
        "isError": false,
    })
}

fn request_line(event: &str, method: &Method, uri: &Uri, caller: &Caller) -> Value {
    let mut line = json!({
        "event": event,
        "http_method": method.as_str(),
        "path": uri.path(),
        "bearer_sha256": caller.bearer_sha256,
        "accepted": caller.accepted,
    });
    if let (Some(jwt), Some(fields)) = (&caller.jwt, line.as_object_mut()) {
        fields.insert("caller".into(), json!(jwt.caller));
        fields.insert("refusal".into(), json!(jwt.refusal.map(Refusal::as_str)));
    }
    line
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"mock-docs\""),
        )],
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn rpc_error(status: StatusCode, id: Value, code: i64, message: &str) -> Response {
    (
        status,
        Json(json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})),
    )
        .into_response()
}

/// The body of a request, read only after its caller was accepted.
async fn read_body(body: Body) -> Result<Bytes, axum::Error> {
    axum::body::to_bytes(body, MAX_BODY_BYTES).await
}

/// `POST /mcp`. The caller is checked from the headers alone; a refused caller's body is never
/// read.
async fn mcp_post(State(server): State<MockDocs>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Parts {
        method,
        uri,
        headers,
        ..
    } = parts;
    let caller = server.authenticate(&headers);
    let mut line = request_line("request", &method, &uri, &caller);
    if !caller.accepted {
        server.log().write(line);
        return unauthorized();
    }
    let log = |mut line: Value, fields: Value| {
        if let (Some(line), Value::Object(fields)) = (line.as_object_mut(), fields) {
            line.extend(fields);
        }
        server.log().write(line);
    };
    let Ok(body) = read_body(body).await else {
        log(line, json!({"refused": "body_unreadable"}));
        return rpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            INVALID_REQUEST,
            "The request body could not be read, or is larger than 2 MiB",
        );
    };

    if let Some(version) = headers.get("mcp-protocol-version") {
        let version = version.to_str().unwrap_or_default();
        if !ACCEPTED_PROTOCOL_VERSIONS.contains(&version) {
            log(line, json!({"refused": "protocol_version"}));
            return rpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                INVALID_REQUEST,
                &format!("Unsupported MCP-Protocol-Version: {version}"),
            );
        }
    }
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        log(line, json!({"refused": "parse_error"}));
        return rpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            PARSE_ERROR,
            "Parse error",
        );
    };
    let Some(message) = message.as_object() else {
        log(line, json!({"refused": "not_one_message"}));
        return rpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            INVALID_REQUEST,
            "Send one JSON-RPC message per request; 2025-06-18 has no batches",
        );
    };
    let id = message.get("id").cloned();
    let rpc_method = message.get("method");
    if message.get("jsonrpc") != Some(&json!("2.0"))
        || matches!(id, Some(Value::Null))
        || rpc_method.is_some_and(|method| !method.is_string())
    {
        log(line, json!({"refused": "invalid_request"}));
        return rpc_error(
            StatusCode::BAD_REQUEST,
            id.unwrap_or(Value::Null),
            INVALID_REQUEST,
            "Invalid Request",
        );
    }
    let rpc_method = rpc_method.and_then(Value::as_str);
    if let Some(fields) = line.as_object_mut() {
        fields.insert("rpc_method".into(), json!(rpc_method));
        fields.insert("rpc_id".into(), json!(id));
    }
    let (Some(rpc_method), Some(id)) = (rpc_method, id) else {
        // A notification, or a client's answer to a request: nothing to answer.
        server.log().write(line);
        return StatusCode::ACCEPTED.into_response();
    };
    let params = message.get("params");
    if rpc_method == "tools/call" {
        let call = params.and_then(Value::as_object);
        let argument = |name: &str| {
            call.and_then(|call| call.get("arguments"))
                .and_then(|arguments| arguments.get(name))
                .cloned()
        };
        log(
            line,
            json!({
                "tool": call.and_then(|call| call.get("name")),
                "project": argument("project"),
                "document": argument("document"),
            }),
        );
    } else {
        server.log().write(line);
    }

    let answer = match server.dispatch(rpc_method, params).await {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": error.code, "message": error.message},
        }),
    };
    Json(answer).into_response()
}

/// Any other method or path: authenticated and logged like `POST /mcp`, then refused.
async fn other_request(
    State(server): State<MockDocs>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = server.authenticate(&headers);
    server
        .log()
        .write(request_line("request", &method, &uri, &caller));
    if !caller.accepted {
        return unauthorized();
    }
    if uri.path() == "/mcp" {
        // No event stream and no session, so no GET and no DELETE.
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, HeaderValue::from_static("POST"))],
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

fn tool_names(tools: &[ToolName]) -> Value {
    json!({"tools": tools.iter().map(|tool| tool.as_str()).collect::<Vec<_>>()})
}

async fn admin_get_tools(
    State(server): State<MockDocs>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let caller = server.authenticate(&headers);
    server
        .log()
        .write(request_line("admin", &method, &uri, &caller));
    if !caller.accepted {
        return unauthorized();
    }
    Json(tool_names(&server.tools())).into_response()
}

/// `PUT /admin/tools`. As with `POST /mcp`, a refused caller's body is never read.
async fn admin_put_tools(State(server): State<MockDocs>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Parts {
        method,
        uri,
        headers,
        ..
    } = parts;
    let caller = server.authenticate(&headers);
    let line = request_line("admin", &method, &uri, &caller);
    if !caller.accepted {
        server.log().write(line);
        return unauthorized();
    }
    let parsed = read_body(body)
        .await
        .ok()
        .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
        .and_then(|body| body.get("tools").and_then(Value::as_array).cloned())
        .ok_or_else(|| "send {\"tools\": [\"list_documents\", …]}".to_owned())
        .and_then(|names| {
            let mut tools = Vec::new();
            for name in &names {
                let tool = name
                    .as_str()
                    .and_then(ToolName::parse)
                    .ok_or_else(|| format!("unknown tool {name}"))?;
                if tools.contains(&tool) {
                    return Err(format!("tool {name} is named twice"));
                }
                tools.push(tool);
            }
            Ok(tools)
        });
    match parsed {
        Ok(tools) => {
            server.set_tools(tools.clone());
            let mut line = line;
            if let Some(fields) = line.as_object_mut() {
                fields.insert("tools".into(), tool_names(&tools)["tools"].clone());
            }
            server.log().write(line);
            Json(tool_names(&tools)).into_response()
        }
        Err(reason) => {
            server.log().write(line);
            (StatusCode::BAD_REQUEST, Json(json!({"error": reason}))).into_response()
        }
    }
}
