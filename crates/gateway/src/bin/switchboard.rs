//! `switchboard`: the gateway as a process.
//!
//! ```text
//! switchboard [--listen ADDRESS] CONFIG
//! ```
//!
//! Reads the JSON configuration at `CONFIG`, runs the boot gates, and serves
//! `POST /mcp/{surface}` on `ADDRESS` (default [`DEFAULT_LISTEN`]) until interrupted. Logs go to
//! standard output as JSON lines; a refusal to start goes to standard error as well, as plain
//! text.
//!
//! This build has no durable audit store and no connectors. So it starts only when the
//! configuration sets `"audit": {"disabled": true}`, and a policy that puts a tool on a surface
//! is refused at boot, because that tool's connector is not registered.
//!
//! Exit status: 0 after a clean shutdown, 1 when the gateway refuses to start or the listener
//! fails, 2 for a usage error.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use gateway::{Config, Wiring, boot, serve_with_shutdown, telemetry};
use gateway_identity::SystemClock;
use tokio::net::TcpListener;

/// Where the gateway listens unless `--listen` says otherwise: loopback only.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

const USAGE: &str = "usage: switchboard [--listen ADDRESS] CONFIG";

/// Why this build refuses a configuration that does not disable audit.
const NO_AUDIT_STORE: &str = "this build of switchboard has no durable audit store yet, so it \
     starts only with `\"audit\": {\"disabled\": true}` in its configuration";

struct Arguments {
    config: PathBuf,
    listen: SocketAddr,
}

/// Reads the command line, without the program's name. An empty error asks for the usage.
fn arguments(mut arguments: impl Iterator<Item = String>) -> Result<Arguments, String> {
    let mut config = None;
    let mut listen = DEFAULT_LISTEN.to_owned();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => {
                listen = arguments
                    .next()
                    .ok_or("--listen needs an address, such as 127.0.0.1:8080")?;
            }
            "-h" | "--help" => return Err(String::new()),
            _ if argument.starts_with('-') => return Err(format!("unknown option `{argument}`")),
            _ if config.is_none() => config = Some(PathBuf::from(argument)),
            _ => return Err("more than one configuration file was given".to_owned()),
        }
    }
    Ok(Arguments {
        config: config.ok_or("no configuration file was given")?,
        listen: listen
            .parse()
            .map_err(|error| format!("`{listen}` is not an address: {error}"))?,
    })
}

/// Logs why the gateway will not start, and says it on standard error too.
fn refuse(reason: &str) -> ExitCode {
    tracing::error!(reason, "switchboard refused to start");
    eprintln!("switchboard: refused to start: {reason}");
    ExitCode::from(1)
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = match arguments(std::env::args().skip(1)) {
        Ok(arguments) => arguments,
        Err(problem) => {
            if problem.is_empty() {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            eprintln!("switchboard: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    telemetry::init();

    let json = match std::fs::read_to_string(&arguments.config) {
        Ok(json) => json,
        Err(error) => {
            return refuse(&format!(
                "cannot read `{}`: {error}",
                arguments.config.display()
            ));
        }
    };
    let config = match Config::from_json(&json) {
        Ok(config) => config,
        Err(error) => {
            return refuse(&format!(
                "`{}` is not a valid configuration: {error}",
                arguments.config.display()
            ));
        }
    };
    if !config.audit.disabled {
        return refuse(NO_AUDIT_STORE);
    }
    let gates = match boot::check(config, Wiring::new(Arc::new(SystemClock))) {
        Ok(gates) => gates,
        Err(error) => return refuse(&error.to_string()),
    };

    let listener = match TcpListener::bind(arguments.listen).await {
        Ok(listener) => listener,
        Err(error) => return refuse(&format!("cannot listen on {}: {error}", arguments.listen)),
    };
    match serve_with_shutdown(listener, gates, shutdown()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "the listener failed");
            ExitCode::from(1)
        }
    }
}

/// Completes on Ctrl-C, or on SIGTERM where there is one.
async fn shutdown() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "cannot wait for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot wait for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("interrupted; shutting down"),
        () = terminate => tracing::info!("terminated; shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn parse(command_line: &[&str]) -> Result<Arguments, String> {
        arguments(command_line.iter().map(|argument| (*argument).to_owned()))
    }

    /// With no `--listen`, the gateway is reachable from this machine only: it binds the IPv4
    /// loopback address, never every interface.
    #[test]
    fn the_default_listen_address_is_loopback_only() {
        let parsed = parse(&["config.json"]).unwrap();
        assert_eq!(parsed.config, PathBuf::from("config.json"));
        assert_eq!(parsed.listen.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!parsed.listen.ip().is_unspecified());
        assert_eq!(parsed.listen.port(), 8080);
    }

    #[test]
    fn listen_replaces_the_default() {
        let parsed = parse(&["--listen", "0.0.0.0:9000", "config.json"]).unwrap();
        assert_eq!(parsed.listen, "0.0.0.0:9000".parse::<SocketAddr>().unwrap());
    }
}
