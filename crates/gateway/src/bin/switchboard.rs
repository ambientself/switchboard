//! `switchboard`: the gateway as a process.
//!
//! ```text
//! switchboard --config=FILE    serve the deployment FILE describes
//! switchboard migrate          bring the audit schema up to date, then exit
//! ```
//!
//! **Serving.** Reads the deployment file (see [`gateway::deployment`]) and every file it
//! names, names the instance from `SWITCHBOARD_INSTANCE` or else `HOSTNAME` and refuses to
//! start with neither (see [`gateway::start::instance`]), fetches the keys of each issuer
//! with a keys URL, connects the audit store and runs its checks, runs the boot gates, and
//! serves `POST /mcp/{surface}` on the address the file gives until interrupted. The registry
//! file is read again every `registry.poll_seconds`, and a new version that passes is served
//! from the next request. Each keys URL is fetched again every `keys_refresh_seconds` (see
//! [`gateway::keys`]). Both stop when the gateway shuts down. Logs go to standard output as JSON lines; a refusal to start goes to standard
//! error as well, as plain text. Shutting down waits for the answers still running, and for the
//! audit store to complete the rows it is still writing, up to its finish deadline.
//!
//! **Migrating.** Connects with the URL in `SWITCHBOARD_MIGRATE_DATABASE_URL`, which must log
//! in as `switchboard_owner`, applies every audit migration not yet applied, prints one JSON
//! line saying which, and exits.
//!
//! Exit status: 0 after a clean shutdown or migration, 1 when the gateway refuses to start, the
//! listener fails or the migration fails, 2 for a usage error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use gateway::{Deployment, serve_with_shutdown, start, telemetry};
use gateway_identity::SystemClock;
use serde_json::json;
use tokio::net::TcpListener;

const USAGE: &str = "usage: switchboard --config=FILE\n       switchboard migrate";

/// The environment variable `switchboard migrate` reads its database URL from.
const MIGRATE_URL_VAR: &str = "SWITCHBOARD_MIGRATE_DATABASE_URL";

/// How long `switchboard migrate` waits for the database to accept its connection.
const MIGRATE_CONNECT_BUDGET: Duration = Duration::from_secs(30);

enum Command {
    Serve { config: PathBuf },
    Migrate,
    Help,
}

fn command() -> Result<Command, String> {
    let mut arguments = std::env::args().skip(1);
    let mut config = None;
    let mut migrate = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "migrate" if config.is_none() && !migrate => migrate = true,
            "--config" => {
                config = Some(arguments.next().ok_or("--config needs a file")?.into());
            }
            _ => match argument.strip_prefix("--config=") {
                Some(path) if !path.is_empty() => config = Some(path.into()),
                _ => return Err(format!("unexpected argument `{argument}`")),
            },
        }
    }
    match (config, migrate) {
        (Some(config), false) => Ok(Command::Serve { config }),
        (None, true) => Ok(Command::Migrate),
        (None, false) => Err("no deployment file was given".to_owned()),
        (Some(_), true) => Err("`migrate` takes no deployment file".to_owned()),
    }
}

/// Logs why the gateway will not start, and says it on standard error too.
fn refuse(reason: &str) -> ExitCode {
    tracing::error!(
        event = "boot_refused",
        reason,
        "switchboard refused to start"
    );
    eprintln!("switchboard: refused to start: {reason}");
    ExitCode::from(1)
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match command() {
        Ok(command) => command,
        Err(problem) => {
            eprintln!("switchboard: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Migrate => {
            telemetry::init();
            migrate().await
        }
        Command::Serve { config } => {
            telemetry::init();
            serve(config).await
        }
    }
}

async fn serve(config: PathBuf) -> ExitCode {
    let deployment = match Deployment::load(&config, |name| std::env::var(name).ok()) {
        Ok(deployment) => deployment,
        Err(error) => return refuse(&error.to_string()),
    };
    let listen = deployment.listen;
    let instance = match start::instance(|name| std::env::var(name).ok()) {
        Ok(instance) => instance,
        Err(error) => return refuse(&error.to_string()),
    };
    let prepared = match start::prepare(deployment, instance, Arc::new(SystemClock)).await {
        Ok(prepared) => prepared,
        Err(error) => return refuse(&error.to_string()),
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => return refuse(&format!("cannot listen on {listen}: {error}")),
    };
    let watching = tokio::spawn(prepared.watch.run());
    let refreshing = tokio::spawn(prepared.keys.run());
    let served = serve_with_shutdown(listener, prepared.gates, shutdown()).await;
    watching.abort();
    refreshing.abort();
    if let Some(store) = &prepared.store {
        finish_rows(store).await;
    }
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "the listener failed");
            ExitCode::from(1)
        }
    }
}

/// Waits for the rows the store is still completing, up to its finish deadline and one answer
/// budget more, the longest any of them can take.
async fn finish_rows(store: &audit_postgres::PgAuditStore) {
    let deadline = tokio::time::Instant::now() + store.budgets().shutdown_wait();
    loop {
        let finishes = store.finishes();
        if finishes.in_flight == 0 {
            if finishes.given_up > 0 {
                tracing::error!(
                    given_up = finishes.given_up,
                    "audit rows were left without their completion"
                );
            }
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::error!(
                in_flight = finishes.in_flight,
                "stopping with audit rows still being completed"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn migrate() -> ExitCode {
    let fail = |reason: String| {
        tracing::error!(event = "migrate_failed", %reason, "the audit schema was not migrated");
        eprintln!("switchboard migrate: {reason}");
        ExitCode::from(1)
    };
    let Some(url) = std::env::var(MIGRATE_URL_VAR)
        .ok()
        .filter(|url| !url.is_empty())
    else {
        return fail(format!("set {MIGRATE_URL_VAR} to the owner's database URL"));
    };
    let connecting = tokio_postgres::connect(&url, tokio_postgres::NoTls);
    let (mut client, connection) =
        match tokio::time::timeout(MIGRATE_CONNECT_BUDGET, connecting).await {
            Err(_elapsed) => return fail("the database did not accept a connection".to_owned()),
            Ok(Err(error)) => return fail(format!("cannot connect: {error}")),
            Ok(Ok(connected)) => connected,
        };
    let connection = tokio::spawn(connection);
    let migrated = audit_postgres::migrate(&mut client).await;
    drop(client);
    let _ = connection.await;
    match migrated {
        Ok(applied) => {
            let line = json!({
                "event": "migrated",
                "schema": audit_postgres::SCHEMA,
                "applied": applied,
                "known": audit_postgres::MIGRATIONS.len(),
            });
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error.to_string()),
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
