//! `switchboard-custodian`: the key custodian as a process.
//!
//! ```text
//! switchboard-custodian --config=FILE
//! ```
//!
//! Reads the configuration file (see [`key_custodian::start`](mod@key_custodian::start)), the
//! App's private key and the registry file, binds the socket and serves token requests until
//! interrupted or terminated. It refuses to start when the configuration's `peer_uid` is its
//! own UID.
//! The record, one JSON line per request, goes to standard output; logs go to standard error
//! as JSON lines, and a refusal to start to standard error as plain text as well.
//!
//! Exit status: 0 after a clean shutdown, 1 when the custodian refuses to start, 2 for a usage
//! error.

use std::path::PathBuf;
use std::process::ExitCode;

use key_custodian::{Config, start_process};

const USAGE: &str = "usage: switchboard-custodian --config=FILE";

fn config_path() -> Option<PathBuf> {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next()?;
    if arguments.next().is_some() {
        return None;
    }
    first.strip_prefix("--config=").map(PathBuf::from)
}

async fn terminated() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> ExitCode {
    let Some(path) = config_path() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let started = match Config::load(&path) {
        Ok(config) => start_process(config, Box::new(std::io::stdout())).await,
        Err(error) => Err(error),
    };
    let running = match started {
        Ok(running) => running,
        Err(error) => {
            tracing::error!(%error, "the custodian refused to start");
            eprintln!("switchboard-custodian refused to start: {error}");
            return ExitCode::from(1);
        }
    };
    terminated().await;
    tracing::info!("shutting down");
    let stopped = running.stop().await;
    tracing::info!(
        revoked = stopped.revoked,
        not_revoked = stopped.not_revoked,
        in_flight = stopped.in_flight,
        "stopped"
    );
    ExitCode::SUCCESS
}
