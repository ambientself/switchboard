//! `mock-docs-server`: the mock document server, configured by environment variables.
//!
//! - `MOCK_DOCS_TOKEN_FILE`: a file holding the one accepted bearer token; or
//! - `MOCK_DOCS_TOKEN_SHA256`: the token's SHA-256 in hex; or
//! - `MOCK_DOCS_TOKEN_SHA256_FILE`: a file holding the token's SHA-256 in hex, or several
//!   tokens' digests, one per line, each alone or followed by a space and the projects that
//!   token may name: `<hex> atlas,borealis`. Exactly one of the three, in the static mode. A
//!   token named alone may name every project.
//! - `MOCK_DOCS_JWT_ISSUER`, `MOCK_DOCS_JWT_AUDIENCE`, `MOCK_DOCS_JWT_SUBJECT` and
//!   `MOCK_DOCS_JWKS_FILE`: the JWT mode, in place of the static one. All four together: the
//!   issuer and audience a token must name, the one subject accepted, which may name every
//!   project, and a file holding the JWK set of the keys that sign tokens.
//! - `MOCK_DOCS_JWT_SUBJECTS`: in place of `MOCK_DOCS_JWT_SUBJECT`, the subjects accepted, each
//!   with the projects it may name: `<subject>=<project>[,<project>]`, entries separated by
//!   `;`. A subject named twice, an unknown project or a malformed entry is refused.
//! - `MOCK_DOCS_LISTEN`: the MCP endpoint's address, default `0.0.0.0:8080`.
//! - `MOCK_DOCS_ADMIN_LISTEN`: the admin endpoint's address. Unset, there is none. Without
//!   `MOCK_DOCS_ADMIN_TOKEN_SHA256_FILE` it must be a loopback address, since the admin
//!   endpoint then answers the callers, who could otherwise widen their own projects.
//! - `MOCK_DOCS_ADMIN_TOKEN_SHA256_FILE`: a file holding the hex SHA-256 of the admin
//!   credential. The admin endpoint then answers only that bearer, and no caller's. It must
//!   differ from every caller's, and needs `MOCK_DOCS_ADMIN_LISTEN`. The static mode checks
//!   that at start. The JWT mode cannot, since a caller's token is not known in advance: it
//!   refuses, on each admin request, a bearer that verifies as a caller's, and the boot line
//!   says so with `"admin_separation": "per_request"`.
//! - `MOCK_DOCS_TOOLS`: the tools offered at start, comma-separated, default
//!   `list_documents,read_document`. Empty, it offers none.
//! - `MOCK_DOCS_SLOW_MS`: how long `slow-doc` takes, default 10000.
//!
//! It logs one JSON object per line on standard output and exits with status 2, before binding
//! anything, if the settings are missing, blank or contradictory. Every variable but
//! `MOCK_DOCS_TOOLS` that is set must hold more than whitespace.

use std::process::ExitCode;

use mock_docs_server::{AcceptedCredential, Config, Credential, Log, MockDocs, Settings};
use serde_json::{Map, Value, json};

#[tokio::main]
async fn main() -> ExitCode {
    let settings = match Settings::from_vars(|name| std::env::var(name).ok()) {
        Ok(settings) => settings,
        Err(error) => return refuse(&error.to_string()),
    };
    let server = MockDocs::new(settings.config.clone(), Log::stdout());
    let listener = match tokio::net::TcpListener::bind(settings.listen).await {
        Ok(listener) => listener,
        Err(error) => return refuse(&format!("cannot listen on {}: {error}", settings.listen)),
    };
    let admin_listener = match settings.admin_listen {
        Some(address) => match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => Some(listener),
            Err(error) => return refuse(&format!("cannot listen on {address}: {error}")),
        },
        None => None,
    };
    let tools: Vec<&str> = settings
        .config
        .tools
        .iter()
        .map(|tool| tool.as_str())
        .collect();
    let mut boot = json!({
        "event": "boot",
        "listen": bound(Some(&listener)),
        "admin_listen": bound(admin_listener.as_ref()),
        "admin_credential": settings
            .config
            .admin
            .as_ref()
            .map(AcceptedCredential::logged_prefix),
        "admin_separation": admin_separation(&settings.config),
        "tools": tools,
        "slow_ms": settings.config.slow.as_millis(),
    });
    let callers: Map<String, Value> = settings
        .config
        .accepted
        .callers()
        .into_iter()
        .map(|(name, projects)| (name, projects.to_json()))
        .collect();
    let mode = match &settings.config.accepted {
        Credential::Static(_) => json!({
            "mode": "static",
            "callers": callers,
        }),
        Credential::Jwt(verifier) => json!({
            "mode": "jwt",
            "issuer": verifier.issuer(),
            "audience": verifier.audience(),
            "callers": callers,
            "key_ids": verifier.key_ids(),
        }),
    };
    if let (Some(boot), Value::Object(mode)) = (boot.as_object_mut(), mode) {
        boot.extend(mode);
    }
    server.log().write(boot);

    let admin = async {
        match admin_listener {
            Some(listener) => axum::serve(listener, server.admin_router()).await,
            None => std::future::pending().await,
        }
    };
    let result = tokio::select! {
        result = axum::serve(listener, server.router()) => result,
        result = admin => result,
        () = shutdown() => Ok(()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            server
                .log()
                .write(json!({"event": "stopped", "reason": error.to_string()}));
            ExitCode::FAILURE
        }
    }
}

/// How the admin credential is kept apart from the callers', if one is set: checked once at
/// start in the static mode, and on each admin request in the JWT mode, where a caller's token
/// is not known in advance. The server refuses a caller's bearer on the admin endpoint in both.
fn admin_separation(config: &Config) -> Option<&'static str> {
    config.admin.as_ref().map(|_| match config.accepted {
        Credential::Static(_) => "at_start",
        Credential::Jwt(_) => "per_request",
    })
}

/// The address a listener is bound to, which differs from the configured one for port 0.
fn bound(listener: Option<&tokio::net::TcpListener>) -> Option<String> {
    listener
        .and_then(|listener| listener.local_addr().ok())
        .map(|address| address.to_string())
}

fn refuse(reason: &str) -> ExitCode {
    eprintln!("{}", json!({"event": "boot_refused", "reason": reason}));
    ExitCode::from(2)
}

/// Waits for Ctrl-C or, on Unix, SIGTERM. Requests in flight are dropped: `hang-doc` would
/// otherwise hold the process up for ever.
async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
