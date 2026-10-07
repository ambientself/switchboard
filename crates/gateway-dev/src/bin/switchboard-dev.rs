//! `switchboard-dev`: the gateway on the testkit's fakes, in one command.
//!
//! ```text
//! switchboard-dev [--port PORT] [--tokens PATH] [--once]
//! ```
//!
//! 1. Starts the gateway on `127.0.0.1:PORT` (default [`DEFAULT_PORT`]; 0 picks a free one)
//!    over the fixture world: two in-process issuers on the system clock, the fixture policy and
//!    connector, and an in-memory audit store that prints each row to standard output as a JSON
//!    line as it is written.
//! 2. Writes a token for team A, team B and the user to `PATH` (default
//!    `target/switchboard-dev/tokens.json` in the workspace), valid for an hour.
//! 3. Runs the scripted client against itself as team A on `fixture-read`, once in each MCP
//!    era, then once with no token, printing every request and answer.
//! 4. With `--once`, stops. Otherwise it serves until interrupted, writing fresh tokens every
//!    half hour.
//!
//! Logs go to standard error as text, at `warn` unless `RUST_LOG` says otherwise.
//!
//! Exit status: 0 when every answer was as expected and the gateway stopped cleanly; 1 when it
//! did not start, the tokens file could not be written, or an answer was not as expected; 2 for
//! a usage error.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use gateway_core::audit::DecisionKind;
use gateway_dev::client::{Client, caller_name, script, unauthenticated};
use gateway_dev::tokens::{REMINT_EVERY, write_tokens};
use gateway_dev::{FixtureGateway, Options, start_fixture_gateway_with};
use gateway_mcp::Era;
use gateway_testkit::{Caller, SURFACE_ALL, SURFACE_READ};
use tracing_subscriber::EnvFilter;

/// The port the gateway listens on unless `--port` says otherwise.
const DEFAULT_PORT: u16 = 8471;

const USAGE: &str = "usage: switchboard-dev [--port PORT] [--tokens PATH] [--once]";

struct Arguments {
    port: u16,
    tokens: PathBuf,
    once: bool,
}

/// `target/switchboard-dev/tokens.json` in the workspace this binary was built from.
fn default_tokens() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.ancestors().nth(2).unwrap_or(manifest);
    workspace.join("target/switchboard-dev/tokens.json")
}

fn arguments() -> Result<Arguments, String> {
    let mut parsed = Arguments {
        port: DEFAULT_PORT,
        tokens: default_tokens(),
        once: false,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--port" => {
                let port = arguments.next().ok_or("--port needs a number")?;
                parsed.port = port
                    .parse()
                    .map_err(|_| format!("`{port}` is not a port"))?;
            }
            "--tokens" => {
                parsed.tokens = arguments.next().ok_or("--tokens needs a path")?.into();
            }
            "--once" => parsed.once = true,
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown argument `{argument}`")),
        }
    }
    Ok(parsed)
}

fn init_logs() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .try_init();
}

fn fail(what: &str) -> ExitCode {
    eprintln!("switchboard-dev: {what}");
    ExitCode::from(1)
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = match arguments() {
        Ok(arguments) => arguments,
        Err(problem) if problem.is_empty() => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(problem) => {
            eprintln!("switchboard-dev: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    init_logs();

    let options = Options::new()
        .port(arguments.port)
        .print_audit_to(Box::new(io::stdout()));
    let gateway = match start_fixture_gateway_with(options).await {
        Ok(gateway) => gateway,
        Err(error) => return fail(&format!("did not start: {error}")),
    };
    if let Err(error) = write_tokens(&arguments.tokens, &gateway) {
        return fail(&format!(
            "cannot write `{}`: {error}",
            arguments.tokens.display()
        ));
    }
    introduce(&gateway, &arguments.tokens);

    let as_expected = run_script(&gateway).await;
    if arguments.once {
        if let Err(error) = gateway.shutdown().await {
            return fail(&format!("did not stop cleanly: {error}"));
        }
        return if as_expected {
            ExitCode::SUCCESS
        } else {
            fail("an answer was not as expected")
        };
    }

    println!(
        "\nServing until interrupted. The tokens in {} are written afresh every {} minutes.",
        arguments.tokens.display(),
        REMINT_EVERY.as_secs() / 60
    );
    tokio::select! {
        () = remint(&gateway, &arguments.tokens) => {}
        () = interrupted() => {}
    }
    match gateway.shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("did not stop cleanly: {error}")),
    }
}

fn introduce(gateway: &FixtureGateway, tokens: &Path) {
    let read = gateway.url(SURFACE_READ);
    println!(
        "switchboard-dev: the gateway on the testkit's fakes, at {}",
        gateway.address()
    );
    println!("  {SURFACE_READ}: {read}");
    println!("  {SURFACE_ALL}:  {}", gateway.url(SURFACE_ALL));
    println!("  tokens for team_a, team_b and user: {}", tokens.display());
    println!("To point Claude Code at it as team A:");
    println!(
        "  claude mcp add --transport http switchboard-a {read} \\\n    --header \"Authorization: Bearer $(jq -r .team_a {})\"",
        tokens.display()
    );
    println!("Audit rows are printed below as JSON lines, as they are written.");
    let _ = io::stdout().flush();
}

/// The scripted client as team A on `fixture-read`, in each era, then with no token. Whether
/// every answer was as expected.
async fn run_script(gateway: &FixtureGateway) -> bool {
    let caller = Caller::TeamA;
    let client = match Client::new(
        gateway.url(SURFACE_READ),
        caller_name(caller),
        gateway.token(caller),
    ) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("switchboard-dev: cannot make the client: {error}");
            return false;
        }
    };
    let mut out = io::stdout();
    let mut as_expected = true;
    for steps in [
        script(Era::Legacy, caller),
        script(Era::Modern, caller),
        vec![unauthenticated(Era::Legacy)],
    ] {
        if let Err(error) = client.run(&steps, &mut out).await {
            eprintln!("switchboard-dev: {error}");
            as_expected = false;
        }
    }

    let rows = gateway.store().rows();
    let allowed = rows
        .iter()
        .filter(|row| row.decision == DecisionKind::Allow)
        .count();
    let completed = rows.iter().filter(|row| row.completion.is_some()).count();
    println!(
        "\naudit: {} rows, {allowed} allowed ({completed} completed) and {} denied",
        rows.len(),
        rows.len() - allowed
    );
    let _ = out.flush();
    as_expected
}

/// Writes fresh tokens every [`REMINT_EVERY`]. Never returns.
async fn remint(gateway: &FixtureGateway, tokens: &Path) {
    let mut interval = tokio::time::interval(REMINT_EVERY);
    // The first tick is immediate, and the tokens were just written.
    interval.tick().await;
    loop {
        interval.tick().await;
        match write_tokens(tokens, gateway) {
            Ok(()) => tracing::info!(path = %tokens.display(), "wrote fresh tokens"),
            Err(error) => {
                tracing::error!(path = %tokens.display(), %error, "cannot write fresh tokens");
            }
        }
    }
}

/// Completes on Ctrl-C, or on SIGTERM where there is one.
async fn interrupted() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
