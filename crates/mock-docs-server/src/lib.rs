//! A mock third-party MCP server. It plays the document system the gateway calls, in tests and
//! in the demo, and shares no code with the gateway.
//!
//! - **Protocol.** Session-less streamable HTTP, protocol version 2025-06-18: `POST /mcp` takes
//!   one JSON-RPC message and answers with JSON. It handles `initialize`, `ping`, `tools/list`
//!   and `tools/call`; notifications get 202. There is no session ID and no event stream, so
//!   `GET` and `DELETE` get 405.
//! - **Tools.** `list_documents {project}` and `read_document {project, document}`, both
//!   read-only. A third, `search_documents {project, query}`, is offered only when configured.
//!   The list can be set at start ([`config::TOOLS_VAR`]) and changed while running, through
//!   the admin endpoint or [`MockDocs::set_tools`]. A tool not offered is an unknown tool.
//!   Each tool's definition is [`ToolName::definition`], unless the admin endpoint or
//!   [`MockDocs::set_description`] has set another description in its place, to play a
//!   definition that drifts.
//! - **Documents.** Projects `atlas` and `borealis`, each with a `plan` and the four documents
//!   that misbehave on purpose: `slow-doc` answers after a delay (10 s by default), `hang-doc`
//!   never answers, `fail-doc` answers with a JSON-RPC error, and `huge-doc` answers with
//!   1 MiB of text. A document is found only by its project and name together. A missing
//!   project or document is a tool result with `isError: true`.
//! - **Credentials.** Every request on every path must carry `Authorization: Bearer` with
//!   an accepted token, or it gets a 401 from its headers alone: its body is never read, nor
//!   waited for. The server runs in one of two modes ([`Credential`]). In the static mode it
//!   accepts some tokens and holds only their SHA-256 digests. In the JWT mode it accepts the
//!   tokens of some subjects, signed with RS256 by a key in a fixed JWK set, from one issuer,
//!   for one audience, and in date; see [`JwtVerifier`].
//! - **Projects per caller.** Each accepted caller may name every project, or only some
//!   ([`Projects`]): a team's identity limited to its team's project. A `tools/call` naming a
//!   project outside its caller's list gets a bare 403, with no JSON-RPC body, as a vendor
//!   refuses a call its credential may not make. The variables that name one credential or one
//!   subject allow every project. The admin endpoint or [`MockDocs::set_projects`] changes a
//!   caller's projects while the server runs, to play a reach that changes.
//! - **The admin endpoint.** With an admin credential ([`Config::admin`]) it answers only that
//!   bearer, and no caller's, so no caller can widen its own projects or change a definition.
//!   Without one it answers the callers, and the binary refuses to serve it anywhere but on
//!   loopback, where no caller can reach it.
//! - **A log line per request.** Each line is a JSON object on standard output with
//!   `bearer_sha256`, the first 12 hex digits of the SHA-256 of the bearer the request carried
//!   (`null` if none), and `accepted`. A script can count these to show which credentials ever
//!   reached the server. In the JWT mode each line also has `caller`, the verified subject of
//!   an accepted token (`null` otherwise), and `refusal`, why a token was refused (`null` if it
//!   was not; see [`Refusal`]). Nothing from a token that failed verification is logged. A
//!   call refused for its project is logged with its `project` and `"refused": "project"`.
//!   Each change made through the admin endpoint is logged too, as an `admin` line.
//!
//! The binary, `mock-docs-server`, reads its settings from environment variables; see
//! [`Settings::from_vars`]. Tests can run the server on loopback with [`start`].

#![forbid(unsafe_code)]

pub mod config;
mod documents;
mod jwt;
mod server;
mod tools;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

pub use config::{
    AcceptedCredential, Config, ConfigError, Credential, Projects, Settings, named_projects,
    parse_projects,
};
pub use documents::{
    FAIL_CODE, FAIL_DOC, HANG_DOC, HUGE_BYTES, HUGE_DOC, PLAN, PROJECTS, SLOW_DOC,
};
pub use jwt::{JwtVerifier, LEEWAY_SECONDS, Refusal};
pub use server::{ACCEPTED_PROTOCOL_VERSIONS, Log, MockDocs, PROTOCOL_VERSION, SERVER_NAME};
pub use tools::{ALL_TOOLS, DEFAULT_TOOLS, ToolName, parse_tool_list};

/// A server running on loopback, with its log kept in memory. Dropping it stops the server.
#[derive(Debug)]
pub struct Running {
    address: SocketAddr,
    admin_address: SocketAddr,
    server: MockDocs,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Starts a server configured by `config` on two free loopback ports, one for `POST /mcp` and
/// one for the admin endpoint. Needs a Tokio runtime.
pub async fn start(config: Config) -> io::Result<Running> {
    let server = MockDocs::new(config, Log::kept());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let admin_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let admin_address = admin_listener.local_addr()?;
    let tasks = vec![
        tokio::spawn(serve(listener, server.router())),
        tokio::spawn(serve(admin_listener, server.admin_router())),
    ];
    Ok(Running {
        address,
        admin_address,
        server,
        tasks,
    })
}

async fn serve(listener: tokio::net::TcpListener, router: axum::Router) {
    // Serving on loopback fails only if the runtime is going away; there is nobody to tell.
    let _ = axum::serve(listener, router).await;
}

impl Running {
    /// The MCP endpoint, `http://127.0.0.1:<port>/mcp`.
    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.address)
    }

    /// The admin endpoint's tool list, `http://127.0.0.1:<port>/admin/tools`.
    pub fn admin_url(&self) -> String {
        format!("http://{}/admin/tools", self.admin_address)
    }

    /// The address of the admin endpoint.
    pub fn admin_address(&self) -> SocketAddr {
        self.admin_address
    }

    /// The address of the MCP endpoint.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The running server, to change its tools or read its log.
    pub fn server(&self) -> &MockDocs {
        &self.server
    }

    /// The log lines so far.
    pub fn log_lines(&self) -> Vec<serde_json::Value> {
        self.server.log().lines()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
