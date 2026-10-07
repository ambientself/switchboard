//! `mock-docs-server`: the mock document server, configured by environment variables.
//!
//! - `MOCK_DOCS_TOKEN_FILE`: a file holding the one accepted bearer token; or
//! - `MOCK_DOCS_TOKEN_SHA256`: the token's SHA-256 in hex. Exactly one of the two.
//! - `MOCK_DOCS_LISTEN`: the MCP endpoint's address, default `0.0.0.0:8080`.
//! - `MOCK_DOCS_ADMIN_LISTEN`: the admin endpoint's address. Unset, there is none.
//! - `MOCK_DOCS_TOOLS`: the tools offered at start, comma-separated, default
//!   `list_documents,read_document`.
//! - `MOCK_DOCS_SLOW_MS`: how long `slow-doc` takes, default 10000.
//!
//! It logs one JSON object per line on standard output and exits with status 2, before binding
//! anything, if the settings are missing or contradictory.

use std::process::ExitCode;

use mock_docs_server::{Log, MockDocs, Settings};
use serde_json::json;

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
    server.log().write(json!({
        "event": "boot",
        "listen": bound(Some(&listener)),
        "admin_listen": bound(admin_listener.as_ref()),
        "tools": tools,
        "slow_ms": settings.config.slow.as_millis(),
        "accepted_sha256": settings.config.accepted.logged_prefix(),
    }));

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
