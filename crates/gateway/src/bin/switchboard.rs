//! `switchboard`: the gateway as a process.
//!
//! ```text
//! switchboard --config=FILE                      serve the deployment FILE describes
//! switchboard probe --config=FILE --server=NAME  probe server NAME and print its record
//! switchboard migrate                            bring the audit schema up to date, then exit
//! ```
//!
//! **Serving.** Reads the deployment file (see [`gateway::deployment`]) and every file it
//! names, names the instance from `SWITCHBOARD_INSTANCE` or else `HOSTNAME` and refuses to
//! start with neither (see [`gateway::start::instance`]), fetches the keys of each issuer
//! with a keys URL, connects the audit store and runs its checks, runs the boot gates, and
//! serves `POST /mcp/{surface}` on the address the file gives until interrupted. The registry
//! file is read again every `registry.poll_seconds`, and a new version that passes is served
//! from the next request; with no successful read for `registry.max_age_seconds`, the policy is
//! stale, readiness fails and tools are refused (see [`gateway::reload`]). The release build
//! refuses the identity and audit opt-outs before it connects to anything (see
//! [`gateway::start`]). Each keys URL is fetched again every `keys_refresh_seconds` (see
//! [`gateway::keys`]). Each proxied server's tool list is read once before the listener is
//! bound and again every `drift.interval_seconds`, and a tool that no longer matches its
//! approval is withdrawn (see [`gateway::drift`]). All three stop when the gateway shuts down.
//! Requests in flight, and calls in flight to each proxied server and from each team, are
//! capped as `[limits]` says (see [`gateway::deployment`] and [`gateway::bulkhead`]). Logs go
//! to standard output as JSON lines; a refusal to start goes to standard error as well, as
//! plain text. Shutting down waits for the answers still running, and for the audit store to
//! complete the rows it is still writing, up to its finish deadline. Within the same time it
//! waits for the side effects answered `unknown` at their deadline that still run on tasks of
//! their own (see [`gateway::bound`]), and never cancels one: one still running when that time
//! is up leaves its receipt `unknown`, logged as `late_side_effects_left_running`. With `[metrics]`,
//! `GET /metrics` is served on an address of its own (see [`gateway::metrics`]); it stops after
//! the MCP listener, once those rows are done.
//!
//! **Probing.** Reads the deployment file and server NAME's entry in its registry file, and no
//! other, sends decision 0010's three calls to the server, and prints each call's verdict, the
//! result and the registry's record line, such as
//! `probe = { result = "refused", date = 2026-10-12 }` (see [`gateway::probe`]). The entry
//! need not have a record yet.
//!
//! **Migrating.** Connects with the URL in `SWITCHBOARD_MIGRATE_DATABASE_URL`, which must log
//! in as `switchboard_owner`, applies every audit migration not yet applied, prints one JSON
//! line saying which, and exits.
//!
//! Exit status: 0 after a clean shutdown or migration, or a probe the server refused; 1 when
//! the gateway refuses to start, the listener fails, the migration fails, or a probe could not
//! be made or found the server anything but refused; 2 for a usage error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use audit_postgres::Budgets;
use connector_proxy::ProbeFinding;
use gateway::{
    Deployment, Metrics, Reconciler, TELEMETRY_QUEUE, Telemetry, Timeouts, probe, serve_metrics,
    serve_with_telemetry, start, telemetry,
};
use gateway_core::ConnectorName;
use gateway_identity::SystemClock;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const USAGE: &str = "usage: switchboard --config=FILE\n       switchboard probe --config=FILE --server=NAME\n       switchboard migrate";

/// The environment variable `switchboard migrate` reads its database URL from.
const MIGRATE_URL_VAR: &str = "SWITCHBOARD_MIGRATE_DATABASE_URL";

/// How long `switchboard migrate` waits for the database to accept its connection.
const MIGRATE_CONNECT_BUDGET: Duration = Duration::from_secs(30);

enum Command {
    Serve { config: PathBuf },
    Probe { config: PathBuf, server: String },
    Migrate,
    Help,
}

fn command() -> Result<Command, String> {
    let mut arguments = std::env::args().skip(1);
    let mut config = None;
    let mut server = None;
    let mut migrate = false;
    let mut probe = false;
    while let Some(argument) = arguments.next() {
        // A subcommand comes first.
        let first = config.is_none() && server.is_none() && !migrate && !probe;
        match argument.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "migrate" if first => migrate = true,
            "probe" if first => probe = true,
            "--config" => {
                config = Some(arguments.next().ok_or("--config needs a file")?.into());
            }
            "--server" => {
                server = Some(arguments.next().ok_or("--server needs a name")?);
            }
            _ => {
                if let Some(path) = argument.strip_prefix("--config=").filter(|p| !p.is_empty()) {
                    config = Some(path.into());
                } else if let Some(name) =
                    argument.strip_prefix("--server=").filter(|n| !n.is_empty())
                {
                    server = Some(name.to_owned());
                } else {
                    return Err(format!("unexpected argument `{argument}`"));
                }
            }
        }
    }
    match (config, server, migrate, probe) {
        (Some(config), None, false, false) => Ok(Command::Serve { config }),
        (Some(config), Some(server), false, true) => Ok(Command::Probe { config, server }),
        (None, None, true, false) => Ok(Command::Migrate),
        (_, Some(_), _, false) => Err("only `probe` takes a server".to_owned()),
        (_, _, true, _) => Err("`migrate` takes no deployment file".to_owned()),
        (None, _, _, true) => Err("`probe` needs a deployment file".to_owned()),
        (Some(_), None, _, true) => Err("`probe` needs a server".to_owned()),
        (None, None, false, false) => Err("no deployment file was given".to_owned()),
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
        Command::Probe { config, server } => probe(&config, server).await,
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
    let metrics_listener = match prepared.metrics {
        None => None,
        Some(address) => match TcpListener::bind(address).await {
            Ok(listener) => Some(listener),
            Err(error) => {
                return refuse(&format!("cannot serve metrics on {address}: {error}"));
            }
        },
    };
    let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
    let (stop_metrics, metrics_stopped) = oneshot::channel::<()>();
    let freshness = prepared.gates.freshness().clone();
    let proxied = prepared.proxied.clone();
    let drift = prepared.drift.signals();
    let reconciliation = prepared.reconciler.as_ref().map(Reconciler::signals);
    let grants = prepared.gates.grant_signals();
    let in_process = prepared.gates.in_process_signals();
    let late = prepared.gates.late_calls();
    let resolver = prepared.gates.resolver().cloned();
    let metrics = metrics_listener.map(|listener| {
        let metrics = Metrics::new(telemetry.clone(), prepared.store.clone())
            .with_issuer_keys(prepared.keys.ages());
        let metrics = metrics.with_policy(freshness);
        let metrics = metrics.with_proxied(proxied).with_in_process(in_process);
        let metrics = metrics.with_drift(drift).with_grants(grants);
        let metrics = match resolver {
            Some(resolver) => metrics.with_resolver(resolver),
            None => metrics,
        };
        let metrics = match reconciliation {
            Some(signals) => metrics.with_reconciliation(signals),
            None => metrics,
        };
        tokio::spawn(serve_metrics(listener, metrics, async {
            let _ = metrics_stopped.await;
        }))
    });
    let watching = tokio::spawn(prepared.watch.run());
    let refreshing = tokio::spawn(prepared.keys.run());
    let drifting = tokio::spawn(prepared.drift.run());
    let reconciling = prepared
        .reconciler
        .map(|reconciler| tokio::spawn(reconciler.run()));
    let served = serve_with_telemetry(
        listener,
        prepared.gates,
        telemetry,
        drain,
        shutdown(),
        Timeouts::default(),
        prepared.max_in_flight,
    )
    .await;
    watching.abort();
    refreshing.abort();
    drifting.abort();
    // A pass stopped mid-way leaves at most one receipt claimed, which any instance takes again
    // once its lease runs out.
    if let Some(reconciling) = reconciling {
        reconciling.abort();
    }
    // Within the time the rows are waited for, the grace period already counts: the side
    // effects still running past their deadline are waited for, and never cancelled.
    let within = prepared.store.as_ref().map_or_else(
        || Budgets::default().shutdown_wait(),
        |store| store.budgets().shutdown_wait(),
    );
    let rows = async {
        if let Some(store) = &prepared.store {
            finish_rows(store).await;
        }
    };
    let ((), running) = tokio::join!(rows, late.wait(within));
    if running > 0 {
        tracing::error!(
            event = "late_side_effects_left_running",
            running,
            "stopping with side effects answered unknown still running; their receipts stay \
             unknown for reconciliation or a person"
        );
    }
    // After the MCP listener, and after the rows it began are done, so the last of them can
    // still be read.
    let _ = stop_metrics.send(());
    if let Some(metrics) = metrics {
        match metrics.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "the metrics listener failed"),
            Err(error) => tracing::error!(%error, "the task serving metrics failed"),
        }
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

/// Probes `server` and prints what each call came to, the result and the record line. Exits 0
/// only when the server refused all three calls.
async fn probe(config: &std::path::Path, server: String) -> ExitCode {
    let server = ConnectorName::new(server);
    let probed = match probe::run(config, &server).await {
        Ok(probed) => probed,
        Err(error) => {
            eprintln!("switchboard probe: {error}");
            return ExitCode::from(1);
        }
    };
    println!("server {} at {}", probed.server, probed.address);
    for (call, verdict) in probed.report.calls() {
        println!("{call}: {verdict}");
    }
    let finding = probed.report.finding();
    println!("result: {finding}");
    println!("{}", probed.record());
    if finding == ProbeFinding::Refused {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "switchboard probe: server `{}` was not shown to refuse a caller it does not know \
             ({finding}); the registry loads only a refused probe",
            probed.server
        );
        ExitCode::from(1)
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
