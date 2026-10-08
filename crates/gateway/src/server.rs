//! The HTTP endpoint: `POST /mcp/{surface}` over the [`RequestPath`].
//!
//! [`serve`] takes a bound listener and the [`Gates`], so nothing is served for a configuration
//! that did not pass the boot gates. A connection has [`HEADER_READ_TIMEOUT`] to send each
//! request's line and headers, or it is closed: nothing below runs until they have arrived, so
//! this is what bounds a client that has proved nothing. Each request then goes through these
//! steps, and each step answers before the next one runs:
//!
//! 1. **Host**: the one `Host` header, without its port, must be in `http.allowed_hosts`.
//!    Otherwise 403. This and the next check stop a web page from reaching the gateway through
//!    DNS rebinding.
//! 2. **Origin**: a request with no `Origin`, as command-line clients send, is not refused for
//!    it. One that has an `Origin` must have exactly one, and it must be in
//!    `http.allowed_origins`. Otherwise 403.
//! 3. **Transport**: not a POST is 405, a body not declared as JSON is 415, and an `Accept`
//!    that excludes JSON is 406.
//! 4. **Declared size**: a `Content-Length` over [`MAX_BODY_BYTES`] is 413.
//! 5. **Identity**, from the headers alone ([`RequestPath::admit`]). The body has not been read.
//! 6. **The body** is read, up to [`MAX_BODY_BYTES`]; a body that grows past it is 413, and one
//!    that has not arrived within [`BODY_READ_TIMEOUT`] is 408, with a sentence saying nothing
//!    ran, and the connection is closed.
//! 7. **The answer** ([`RequestPath::respond`]) runs on its own task, which the handler waits
//!    for. A client that disconnects drops the handler, but not that task, so a tool call that
//!    started still completes its audit row.
//!
//! Shutting down stops taking connections, and waits up to [`SHUTDOWN_GRACE`] for those still
//! open, such as one whose client stopped part way through a request. It then closes any still
//! open, so a request on them that has not started its answer never will. Last, it waits for
//! the answer tasks, however long they take: a call whose client has gone is still running, and
//! a process that exited under it would leave its row open.
//!
//! Every request is logged once it is answered, with its status and how long it took. A
//! disabled gate is logged at boot, and again every [`DISABLED_GATE_REMINDER`] while the
//! gateway serves.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::response::Response;
use axum::routing::any;
use gateway_mcp::{HttpResponse, INTERNAL_ERROR, Rejection};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, ORIGIN};
use http::request::Parts;
use http::{HeaderMap, HeaderValue, StatusCode};
use http_body_util::LengthLimitError;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::boot::{GateState, Gates};
use crate::path::RequestPath;

/// The largest request body read, in bytes: 1 MiB.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// How often a disabled gate is logged again while the gateway serves.
pub const DISABLED_GATE_REMINDER: Duration = Duration::from_secs(60);

/// How long a connection may take to send a request's line and headers before it is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a request's body may take to arrive once identity has passed. Longer is 408.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long shutting down waits for connections still open before it closes them.
/// Answer tasks already running are waited for however long they take.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// The time limits the server applies. [`Timeouts::default`] is [`HEADER_READ_TIMEOUT`],
/// [`BODY_READ_TIMEOUT`] and [`SHUTDOWN_GRACE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// How long a connection may take to send a request's line and headers.
    pub header_read: Duration,
    /// How long a request's body may take to arrive once identity has passed.
    pub body_read: Duration,
    /// How long shutting down waits for connections still open before it closes them.
    pub shutdown_grace: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            header_read: HEADER_READ_TIMEOUT,
            body_read: BODY_READ_TIMEOUT,
            shutdown_grace: SHUTDOWN_GRACE,
        }
    }
}

/// Serves `gates` on `listener`, with the default [`Timeouts`], until the process ends.
pub async fn serve(listener: TcpListener, gates: Gates) -> io::Result<()> {
    serve_with_shutdown(listener, gates, std::future::pending()).await
}

/// Serves `gates` on `listener`, with the default [`Timeouts`], until `shutdown` completes. See
/// [`serve_with_timeouts`].
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    gates: Gates,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with_timeouts(listener, gates, shutdown, Timeouts::default()).await
}

/// Serves `gates` on `listener` until `shutdown` completes, then stops taking connections. It
/// waits for the connections still open to close, up to `timeouts.shutdown_grace`, and then
/// closes those that have not, so no tool call starts after it returns. It returns once every
/// tool call started has completed its audit row, including calls whose clients have gone.
pub async fn serve_with_timeouts<F>(
    listener: TcpListener,
    gates: Gates,
    shutdown: F,
    timeouts: Timeouts,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let address = listener.local_addr()?;
    tracing::info!(
        %address,
        deployment = %gates.deployment(),
        revision = %gates.snapshot().revision(),
        identity = ?gates.identity_state(),
        audit = ?gates.audit_state(),
        "listening"
    );
    let path = RequestPath::new(gates);
    let reminder = tokio::spawn(remind(path.clone()));
    let answers = Answers::default();
    let service = TowerToHyperService::new(router(Endpoint {
        path,
        answers: answers.clone(),
        body_read: timeouts.body_read,
    }));
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(timeouts.header_read);
    let connections = GracefulShutdown::new();
    // Every connection's task, so that those still open after the grace can be closed.
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut shutdown = pin!(shutdown);
    loop {
        // Forget the connections that have closed, so the set holds only those still open.
        while tasks.try_join_next().is_some() {}
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    accept_failed(&error).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let connection =
            connections.watch(http.serve_connection(TokioIo::new(stream), service.clone()));
        tasks.spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "a connection ended with an error");
            }
        });
    }
    drop(listener);
    reminder.abort();
    tracing::info!(%address, "stopped listening");
    if tokio::time::timeout(timeouts.shutdown_grace, connections.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(
            %address,
            grace_ms = u64::try_from(timeouts.shutdown_grace.as_millis()).unwrap_or(u64::MAX),
            "closing the connections still open after the grace period"
        );
    }
    // A handler that has not started its answer is dropped with its connection. One that has
    // started it holds a counted task, which goes on without the handler.
    tasks.shutdown().await;
    let running = answers.running();
    if running > 0 {
        tracing::info!(
            %address,
            running,
            "waiting for the answers still running to complete their rows"
        );
    }
    answers.finished().await;
    Ok(())
}

/// A connection that could not be accepted. One the client reset or aborted is its own
/// problem; anything else, such as running out of file descriptors, is logged and waited out
/// for a second, so the loop does not spin.
async fn accept_failed(error: &io::Error) {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(%error, "cannot accept a connection");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// What the endpoint's handler holds: the request path, the answers it has started, and how
/// long a body may take.
#[derive(Clone)]
struct Endpoint {
    path: RequestPath,
    answers: Answers,
    body_read: Duration,
}

/// Counts the answer tasks that are running, whether or not anyone is still waiting for them.
#[derive(Clone)]
struct Answers(Arc<watch::Sender<usize>>);

impl Default for Answers {
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(0)))
    }
}

impl Answers {
    /// Counts one more answer running, until the returned guard is dropped.
    fn start(&self) -> Running {
        self.0.send_modify(|running| *running += 1);
        Running(self.0.clone())
    }

    fn running(&self) -> usize {
        *self.0.borrow()
    }

    /// Returns once no answer is running.
    async fn finished(&self) {
        let mut running = self.0.subscribe();
        // The sender is held here, so the channel cannot close while this waits.
        let _ = running.wait_for(|running| *running == 0).await;
    }
}

/// One answer running. Dropped when its task ends, however it ends.
struct Running(Arc<watch::Sender<usize>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0
            .send_modify(|running| *running = running.saturating_sub(1));
    }
}

fn router(endpoint: Endpoint) -> Router {
    Router::new()
        .route("/mcp/{surface}", any(handle))
        .with_state(endpoint)
}

/// Logs each disabled gate every [`DISABLED_GATE_REMINDER`]. Returns at once if none is.
async fn remind(path: RequestPath) {
    let gates = path.gates();
    let identity = gates.identity_state() == GateState::Disabled;
    let audit = gates.audit_state() == GateState::Disabled;
    if !identity && !audit {
        return;
    }
    let mut interval = tokio::time::interval(DISABLED_GATE_REMINDER);
    // The first tick is immediate; boot has just logged the same warning.
    interval.tick().await;
    loop {
        interval.tick().await;
        if identity {
            tracing::warn!(
                deployment = %gates.deployment(),
                "identity is disabled: callers are not verified, no tools are listed and every \
                 call is refused"
            );
        }
        if audit {
            tracing::warn!(
                deployment = %gates.deployment(),
                "audit is disabled: calls are allowed and run with no record of them"
            );
        }
    }
}

async fn handle(State(endpoint): State<Endpoint>, request: Request) -> Response {
    let started = Instant::now();
    let (mut parts, body) = request.into_parts();
    let method = parts.method.clone();
    let uri_path = parts.uri.path().to_owned();
    let span = tracing::info_span!("request", %method, path = %uri_path);
    let response = answer(&endpoint, &mut parts, body)
        .instrument(span.clone())
        .await;
    span.in_scope(|| {
        tracing::info!(
            status = response.status.as_u16(),
            elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            "answered a request"
        );
    });
    into_response(response)
}

/// The steps in the [module documentation](self), in order.
async fn answer(endpoint: &Endpoint, parts: &mut Parts, body: Body) -> HttpResponse {
    let path = &endpoint.path;
    let gates = path.gates();
    if let Err(rejection) = check_host(gates, parts) {
        return refused(&rejection);
    }
    if let Err(rejection) = check_origin(gates, &parts.headers) {
        return refused(&rejection);
    }
    if let Err(rejection) = gateway_mcp::check_transport(&parts.method, &parts.headers) {
        return refused(&rejection);
    }
    if declared_length(&parts.headers).is_some_and(|length| length > MAX_BODY_BYTES) {
        return refused(&Rejection::payload_too_large());
    }
    let admitted = match path.admit(&parts.method, &parts.headers) {
        Ok(admitted) => admitted,
        Err(response) => return response,
    };
    let Ok(Path(surface)) = Path::<String>::from_request_parts(parts, &()).await else {
        // The surface in the URL does not decode to text, so it names no surface.
        return not_found();
    };
    let reading = axum::body::to_bytes(body, MAX_BODY_BYTES);
    let Ok(read) = tokio::time::timeout(endpoint.body_read, reading).await else {
        return refused(&Rejection::request_timeout());
    };
    let body = match read {
        Ok(body) => body,
        Err(error) => {
            let error = error.into_inner();
            if error.downcast_ref::<LengthLimitError>().is_some() {
                return refused(&Rejection::payload_too_large());
            }
            tracing::debug!(%error, "the request body could not be read");
            return unreadable();
        }
    };
    let answering = path.respond(admitted, &surface, &parts.headers, &body);
    let span = tracing::info_span!("answer", %surface);
    // Its own task, so a client that goes away cannot stop a call between running the tool
    // and completing its row; counted, so that shutting down waits for it. Nothing awaits
    // between counting it and spawning it, so a handler dropped at shutdown has done both or
    // neither.
    let running = endpoint.answers.start();
    let answering = async move {
        let _running = running;
        answering.await
    };
    match tokio::spawn(answering.instrument(span)).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "the task answering a request failed");
            internal_error()
        }
    }
}

fn refused(rejection: &Rejection) -> HttpResponse {
    tracing::debug!(%rejection, "refused a request at the HTTP layer");
    rejection.response()
}

/// Refuses a request whose host, without its port, is not an allowed host. The host is the one
/// `Host` header, or the request target's authority when there is no header; two `Host`
/// headers, or none and no authority, are refused.
fn check_host(gates: &Gates, parts: &Parts) -> Result<(), Rejection> {
    let mut values = parts.headers.get_all(HOST).iter();
    let host = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        (None, _) => parts.uri.authority().map(|authority| authority.as_str()),
        (Some(_), Some(_)) => None,
    };
    let allowed = host.map(without_port).is_some_and(|host| {
        gates
            .allowed_hosts()
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    });
    if allowed {
        Ok(())
    } else {
        Err(Rejection::forbidden_host())
    }
}

/// A `Host` value without its port: `localhost:8080` is `localhost`, `[::1]:8080` is `[::1]`.
/// A port is one or more digits after the last `:`, or after the `]` that closes a bracketed
/// host. A value with anything else there, such as `localhost:` or `[::1].evil.example`, is
/// kept whole, so it matches no allowed host unless that exact value is allowed.
fn without_port(host: &str) -> &str {
    let (name, port) = if host.starts_with('[') {
        match host.find(']') {
            Some(close) => host.split_at(close + 1),
            None => return host,
        }
    } else {
        match host.rfind(':') {
            Some(colon) => host.split_at(colon),
            None => return host,
        }
    };
    let is_port = |port: &str| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit());
    if port.is_empty() || port.strip_prefix(':').is_some_and(is_port) {
        name
    } else {
        host
    }
}

/// No `Origin` passes. Otherwise exactly one, and an allowed one.
fn check_origin(gates: &Gates, headers: &HeaderMap) -> Result<(), Rejection> {
    let mut values = headers.get_all(ORIGIN).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    let allowed = values.next().is_none()
        && first.to_str().is_ok_and(|origin| {
            gates
                .allowed_origins()
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(origin))
        });
    if allowed {
        Ok(())
    } else {
        Err(Rejection::forbidden_origin())
    }
}

/// The declared `Content-Length`, when there is one that reads as a number. Anything else is
/// left to the body reader, which applies the limit as it reads.
fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn not_found() -> HttpResponse {
    HttpResponse {
        status: StatusCode::NOT_FOUND,
        headers: HeaderMap::new(),
        body: Vec::new(),
    }
}

/// The client stopped sending, or sent a body that is not well-formed HTTP. There is likely
/// nobody left to read this.
fn unreadable() -> HttpResponse {
    HttpResponse {
        status: StatusCode::BAD_REQUEST,
        headers: HeaderMap::new(),
        body: Vec::new(),
    }
}

fn internal_error() -> HttpResponse {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {"code": INTERNAL_ERROR, "message": "Internal error"},
    });
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    HttpResponse {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        headers,
        body: body.to_string().into_bytes(),
    }
}

fn into_response(response: HttpResponse) -> Response {
    let HttpResponse {
        status,
        headers,
        body,
    } = response;
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_is_taken_off_a_host() {
        assert_eq!(without_port("localhost"), "localhost");
        assert_eq!(without_port("localhost:8080"), "localhost");
        assert_eq!(without_port("127.0.0.1:0"), "127.0.0.1");
        assert_eq!(without_port("[::1]:8080"), "[::1]");
        assert_eq!(without_port("[::1]"), "[::1]");
        assert_eq!(without_port("localhost:http"), "localhost:http");
    }

    #[test]
    fn what_follows_a_host_must_be_a_port_or_nothing() {
        for kept in [
            "[::1].evil.example",
            "[::1]:garbage",
            "[::1]:",
            "[::1]evil",
            "[::1]:80:80",
            "[::1",
            "localhost:",
            "localhost:8o80",
        ] {
            assert_eq!(without_port(kept), kept);
        }
    }

    #[test]
    fn only_a_numeric_content_length_is_declared() {
        let declared = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("x")),
            );
            declared_length(&headers)
        };
        assert_eq!(declared("12"), Some(12));
        assert_eq!(declared("lots"), None);
        assert_eq!(declared_length(&HeaderMap::new()), None);
    }
}
