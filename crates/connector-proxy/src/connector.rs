//! The connector: one allowed `tools/call`, forwarded to the proxied server.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gateway_core::{
    BoxFuture, Connector, ConnectorName, CredentialError, ToolCall, ToolName, ToolOutcome,
};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::credentials::{FileCredentials, Secret};
use crate::outcome;

/// How long a call may take, from sending the request to the last byte of the answer, unless
/// configured otherwise.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(5);

/// The largest answer accepted, in bytes of HTTP body, unless configured otherwise.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The MCP revision the connector speaks to the proxied server.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// One proxied server: where it is, which tools the gateway exposes from it, and the bounds on
/// each call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// The connector name approved tools route by. The gateway's credential for the server is
    /// found under the same name.
    pub connector: ConnectorName,
    /// The server's MCP endpoint, an `http://` URL.
    pub url: String,
    /// Each exposed tool and the name the server knows it by.
    pub tools: BTreeMap<ToolName, String>,
    /// How long a call may take before it is abandoned.
    pub deadline: Duration,
    /// The largest answer accepted, in bytes.
    pub max_response_bytes: usize,
}

impl Upstream {
    /// A server at `url`, routed to by `connector`, with no tools yet and the default bounds:
    /// [`DEFAULT_DEADLINE`] and [`DEFAULT_MAX_RESPONSE_BYTES`].
    pub fn new(connector: impl Into<ConnectorName>, url: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            url: url.into(),
            tools: BTreeMap::new(),
            deadline: DEFAULT_DEADLINE,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Adds the exposed tool `exposed`, which the server calls `upstream`.
    pub fn tool(mut self, exposed: ToolName, upstream: impl Into<String>) -> Self {
        self.tools.insert(exposed, upstream.into());
        self
    }
}

/// Why a proxied server's configuration was refused.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum UpstreamError {
    /// The URL is not an `http://` URL with a host, or it carries a user name or password.
    #[error(
        "the upstream URL for connector `{connector}` must be http:// with a host and no user information: {url}"
    )]
    BadUrl {
        /// The connector.
        connector: ConnectorName,
        /// The URL as configured.
        url: String,
    },
    /// No tools are exposed from the server.
    #[error("connector `{0}` exposes no tools")]
    NoTools(ConnectorName),
    /// A tool's upstream name is empty.
    #[error("tool `{0}` has an empty upstream name")]
    EmptyUpstreamName(ToolName),
    /// The deadline is zero.
    #[error("the deadline for connector `{0}` is zero")]
    ZeroDeadline(ConnectorName),
    /// The answer cap is zero.
    #[error("the answer size cap for connector `{0}` is zero")]
    ZeroCap(ConnectorName),
    /// The credential source holds no credential for the connector.
    #[error("no gateway credential is configured for connector `{0}`")]
    NoCredential(ConnectorName),
}

/// The [`Connector`] for a proxied MCP server.
///
/// It forwards each call as one JSON-RPC `tools/call` request, `POST`ed to the server's
/// endpoint with the gateway's own bearer credential. The caller's token cannot be forwarded:
/// a [`ToolCall`] does not carry it. It speaks session-less streamable HTTP and reads only a
/// JSON answer, not an event stream. It follows no redirect and uses no proxy.
///
/// Each call is bounded inside the connector: it is abandoned at the deadline, and an answer
/// larger than the cap is discarded unread. Either way the outcome is
/// [`ToolOutcome::Error`]. So is any failure of the server or of the exchange, and so are
/// arguments that are not an object, which are never sent. A `403` from the server is its
/// refusal of the call's scope and becomes [`ToolOutcome::Refused`], as does a call this
/// connector does not serve or has no credential for; see [`outcome`](crate::outcome) for
/// every sentence.
///
/// Running a call needs a Tokio runtime.
pub struct ProxyConnector {
    connector: ConnectorName,
    endpoint: Uri,
    tools: BTreeMap<ToolName, String>,
    deadline: Duration,
    max_response_bytes: usize,
    credentials: Arc<FileCredentials>,
    client: Client<HttpConnector, Full<Bytes>>,
    next_id: AtomicU64,
}

impl fmt::Debug for ProxyConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConnector")
            .field("connector", &self.connector)
            .field("endpoint", &self.endpoint)
            .field("tools", &self.tools)
            .field("deadline", &self.deadline)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

impl ProxyConnector {
    /// A connector for `upstream`, using the gateway credential `credentials` holds for its
    /// connector name. Refuses a configuration that could not forward a call.
    pub fn new(
        upstream: Upstream,
        credentials: Arc<FileCredentials>,
    ) -> Result<Self, UpstreamError> {
        let Upstream {
            connector,
            url,
            tools,
            deadline,
            max_response_bytes,
        } = upstream;
        let endpoint = parse_endpoint(&url).ok_or_else(|| UpstreamError::BadUrl {
            connector: connector.clone(),
            url,
        })?;
        if tools.is_empty() {
            return Err(UpstreamError::NoTools(connector));
        }
        if let Some((exposed, _)) = tools.iter().find(|(_, upstream)| upstream.is_empty()) {
            return Err(UpstreamError::EmptyUpstreamName(exposed.clone()));
        }
        if deadline.is_zero() {
            return Err(UpstreamError::ZeroDeadline(connector));
        }
        if max_response_bytes == 0 {
            return Err(UpstreamError::ZeroCap(connector));
        }
        if !credentials.connectors().any(|held| *held == connector) {
            return Err(UpstreamError::NoCredential(connector));
        }
        // The legacy client follows no redirect and reads no proxy setting from the
        // environment, so the credential goes to the configured endpoint or nowhere.
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build_http();
        Ok(Self {
            connector,
            endpoint,
            tools,
            deadline,
            max_response_bytes,
            credentials,
            client,
            next_id: AtomicU64::new(1),
        })
    }

    /// The connector name this connector serves.
    pub fn connector(&self) -> &ConnectorName {
        &self.connector
    }

    async fn forward(&self, call: ToolCall) -> ToolOutcome {
        let tool = call.tool();
        if tool.connector != self.connector {
            return ToolOutcome::Refused(outcome::NOT_SERVED.to_owned());
        }
        let Some(upstream_name) = self.tools.get(&tool.name) else {
            return ToolOutcome::Refused(outcome::NOT_SERVED.to_owned());
        };
        let Value::Object(arguments) = call.arguments() else {
            return ToolOutcome::Error(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned());
        };
        let secret = match self
            .credentials
            .issue(&self.connector, &call.call().caller.principal)
        {
            Ok((_handle, secret)) => secret,
            Err(CredentialError::Refused(_)) => {
                return ToolOutcome::Refused(outcome::NO_CREDENTIAL.to_owned());
            }
            Err(CredentialError::Unavailable(_)) => {
                return ToolOutcome::Error(outcome::CREDENTIAL_UNAVAILABLE.to_owned());
            }
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let Some(request) = self.request(id, upstream_name, arguments, secret) else {
            return ToolOutcome::Error(outcome::NOT_SENT.to_owned());
        };
        match tokio::time::timeout(self.deadline, self.exchange(request)).await {
            Err(_elapsed) => ToolOutcome::Error(outcome::TIMED_OUT.to_owned()),
            Ok(Err(failed)) => failed,
            Ok(Ok(received)) => {
                outcome::interpret(received.content_type.as_deref(), &received.body, id)
            }
        }
    }

    fn request(
        &self,
        id: u64,
        upstream_name: &str,
        arguments: &Map<String, Value>,
        secret: &Secret,
    ) -> Option<Request<Full<Bytes>>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": upstream_name, "arguments": arguments},
        });
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", secret.bearer())).ok()?;
        authorization.set_sensitive(true);
        Request::post(self.endpoint.clone())
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .body(Full::new(Bytes::from(body.to_string())))
            .ok()
    }

    /// Sends the request and reads a `200` answer's body, up to the cap. Any other status, and
    /// any failure, is the call's outcome.
    async fn exchange(&self, request: Request<Full<Bytes>>) -> Result<Received, ToolOutcome> {
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_| ToolOutcome::Error(outcome::UNREACHABLE.to_owned()))?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ToolOutcome::Error(outcome::CREDENTIAL_REJECTED.to_owned()));
        }
        if status == StatusCode::FORBIDDEN {
            return Err(ToolOutcome::Refused(outcome::UPSTREAM_REFUSED.to_owned()));
        }
        if status != StatusCode::OK {
            return Err(ToolOutcome::Error(outcome::status(status.as_u16())));
        }
        self.read(response).await
    }

    /// Reads the body, refusing as soon as it is known to be larger than the cap: from its
    /// declared length if it has one, and otherwise as it arrives.
    async fn read(&self, response: Response<Incoming>) -> Result<Received, ToolOutcome> {
        let too_large = || ToolOutcome::Error(outcome::TOO_LARGE.to_owned());
        if declared_length(response.headers())
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(too_large());
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = response.into_body();
        let mut received = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| ToolOutcome::Error(outcome::BROKEN_OFF.to_owned()))?;
            if let Ok(data) = frame.into_data() {
                if received.len() + data.len() > self.max_response_bytes {
                    return Err(too_large());
                }
                received.extend_from_slice(&data);
            }
        }
        Ok(Received {
            content_type,
            body: received,
        })
    }
}

impl Connector for ProxyConnector {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        Box::pin(self.forward(call))
    }
}

/// A `200` answer, read in full.
struct Received {
    content_type: Option<String>,
    body: Vec<u8>,
}

fn parse_endpoint(url: &str) -> Option<Uri> {
    let endpoint: Uri = url.parse().ok()?;
    let authority = endpoint.authority()?;
    let acceptable = endpoint.scheme_str() == Some("http")
        && !authority.host().is_empty()
        && !authority.as_str().contains('@');
    acceptable.then_some(endpoint)
}

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}
