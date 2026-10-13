//! Building a running gateway from a [`Deployment`]: what the `switchboard` binary does
//! before it binds a socket.
//!
//! [`instance`] names the gateway instance from the environment, once, before anything else
//! is prepared: `SWITCHBOARD_INSTANCE`, or else `HOSTNAME`, which Kubernetes sets to the pod's
//! name and Docker to the container's. With neither, the gateway refuses to start. Every audit
//! row records the instance that began it.
//!
//! [`prepare`] reads the registry file. Before anything else, it refuses the identity and audit
//! opt-outs outside a development build, and runs the receipt-store gate (decision 0014,
//! section 4), so that a refusal of either comes before any connection is made. Then it checks
//! where each proxied server is reached (decision 0013, section 3): an `https` server needs the
//! CA file `[servers.<name>] ca_file` names, an `http` server may have none, and an address
//! that is an IP literal the connector would never connect to is refused, loopback among them
//! outside a development build. It refuses a registry whose entries have a reach check when the
//! deployment file gives no `[drift] reach_*` settings, naming those entries, since their reach
//! would never be checked (decision 0011, section 4). Then it loads each proxied server's
//! credential, builds a [`ProxyConnector`] per server with its destination and CA file and with
//! the deadline and answer cap the deployment file's `[servers.<name>]` sets for it, wraps each
//! in a [`Bulkhead`] holding it to the caps of `[limits]`, loads each server's probe credential
//! ([`probe_credentials`]), fetches the keys of each issuer configured with a keys URL,
//! connects the Postgres audit store and runs its boot checks (or, in a development build,
//! takes audit as explicitly disabled), and then runs the boot gates
//! ([`boot::check_registry`]). Any failure refuses to start, naming the reason,
//! before anything is served. A `[servers.<name>]` for a server the registry does not name is
//! refused: a bound meant for a server that is not there would be one nobody holds.
//!
//! Each keys URL is checked first, every one before any is fetched: it must be on its issuer's
//! own origin, an `https` one must have a CA file that reads as a PEM bundle of certificates,
//! and an `http` one may have neither a CA file nor a token file. Then each issuer's keys are
//! fetched once, and a fetch that fails refuses to start, naming the issuer and the cause. The [`KeyRefresher`] in [`Prepared`] fetches them again on a timer.
//!
//! It logs one `"event":"boot"` line per gate, which an operator (and the demo) reads to see
//! how the gateway was started: identity enforced or disabled, with how many issuers and
//! subjects; each issuer whose keys were fetched, with how many keys and how often they are
//! fetched again; audit in Postgres, with the role and its check, or disabled; and the
//! registry's revision, with the revision, tools and withdrawals actually served once the first
//! drift pass has run.
//!
//! The Postgres store reports each audit row it stops trying to complete. The gateway logs each
//! report as [`GIVEN_UP_EVENT`] at `ERROR`, naming the row, so an open row is found when it is
//! left open and not only by querying for it (decision 0009).
//!
//! It logs a boot line for the caps on calls in flight, and one for each server's bounds.
//!
//! Last, before it returns, it runs the drift pass's first pass ([`crate::drift`]): it reads
//! every proxied server's tool list, each within its call deadline, and withdraws each approved
//! tool the server no longer serves as approved. The binary binds its listener only after, so a
//! tool withdrawn then is never served, and nothing is answered, `/readyz` included, until the
//! pass ends. A poll that fails does not stop the start: the server's tools stay served.
//! [`Prepared::drift`] polls each server again every interval, each on its own schedule.
//!
//! It logs a boot line for metrics too: the address `GET /metrics` will be served on, or that
//! none is, since `[metrics]` is optional. [`Prepared::metrics`] carries the address to the
//! binary, which binds it and serves it with [`crate::metrics::serve_metrics`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use audit_postgres::{BootCheckError, GivenUp, PgAuditError, PgAuditStore, PoolSizes};
use connector_proxy::{
    CredentialFileError, FileCredentials, Loopback, ProxyConnector, Refusal, Upstream,
    UpstreamError,
};
use gateway_core::{ConnectorName, CredentialMode, InstanceName, Issuer, Narrowing};
use gateway_identity::Clock;
use gateway_registry::{Destination, Registry, RegistryError};
use issuer_keys::{FetchError, FetchOptions, KeySource, SourceError, SourceFiles};
use thiserror::Error;

use crate::boot::{self, BootError, Gates, Settings, Wiring};
use crate::bulkhead::{Bulkhead, ProxiedSignals};
use crate::config::{IdentitySection, IssuerKindEntry};
use crate::deployment::{AuditChoice, Deployment, KeysUrl, Limits, ServerLimits};
use crate::drift::{DriftPass, ProbeCredentialError, probe_credentials};
use crate::keys::KeyRefresher;
use crate::reach::{ReachCaller, ReachSettings};
use crate::reload::Reloader;

/// The `event` field of the error logged for each audit row the Postgres store stops trying to
/// complete: the finish deadline passed, or the database refused the completion. It names the
/// `row`, the `outcome` that was not written (`ok`, `error` or `refused`), and the `cause`.
/// The row keeps an empty outcome.
pub const GIVEN_UP_EVENT: &str = "audit_row_given_up";

/// The environment variable that names the gateway instance, before [`HOSTNAME_VAR`].
pub const INSTANCE_VAR: &str = "SWITCHBOARD_INSTANCE";

/// The environment variable [`instance`] falls back to. Kubernetes sets it to the pod's name and
/// Docker to the container's; a shell may not export it, so nothing should rely on one doing so.
pub const HOSTNAME_VAR: &str = "HOSTNAME";

/// How long the audit store's boot checks may take, connecting included.
pub const AUDIT_CHECK_BUDGET: Duration = Duration::from_secs(15);

/// Why the gateway refused to start.
#[derive(Debug, Error)]
pub enum StartError {
    /// Nothing names the gateway instance, so its audit rows could not say which instance
    /// began them.
    #[error(
        "nothing names this gateway instance: set {INSTANCE_VAR}, or {HOSTNAME_VAR} as \
         Kubernetes and Docker do, so each audit row can record the instance that began it"
    )]
    NoInstance,
    /// The registry file could not be read or does not load.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// A server's credential reference has no file in the deployment file.
    #[error(
        "server `{server}` uses credential `{reference}`, which `[credentials]` does not give a \
         file for"
    )]
    NoCredentialFile {
        /// The server.
        server: ConnectorName,
        /// Its credential reference.
        reference: String,
    },
    /// The deployment file sets bounds for a server the registry does not name.
    #[error(
        "`[servers.{0}]` sets bounds for a server the registry does not name; remove it, or \
         name a server the registry has"
    )]
    UnknownServerLimits(ConnectorName),
    /// A server's credential is a per-user grant, which is not built until milestone 5.
    #[error(
        "server `{0}`'s credential is a per-user grant, which this gateway does not support yet"
    )]
    PerUserGrant(ConnectorName),
    /// A server's credential is to be narrowed per call or to the caller's limit. The gateway
    /// sends one credential for every call to a server until the custodian client (#12)
    /// narrows them, so such an entry would skip rule 5 with a credential that is not narrowed.
    #[error(
        "server `{0}` says its credential is narrowed per call or to the caller's limit, which \
         this gateway cannot do yet: it sends the same credential on every call, so only \
         narrowing \"none\" is supported"
    )]
    NarrowingNotBuilt(ConnectorName),
    /// A credential file is given that no server uses.
    #[error("credential `{0}` is given a file in `[credentials]` but no server uses it")]
    UnusedCredential(String),
    /// A credential file could not be loaded.
    #[error(transparent)]
    Credentials(#[from] CredentialFileError),
    /// A proxied server has no probe credential, or its file could not be loaded.
    #[error(transparent)]
    ProbeCredentials(#[from] ProbeCredentialError),
    /// Registry entries have a reach check, and the deployment file does not say how to make
    /// it (decision 0011, section 4): their reach would never be checked.
    #[error(
        "the registry gives {} a reach check, but the deployment file has no `[drift] \
         reach_token_file`, `reach_url` and `reach_host`; give all three, so that each entry's \
         reach is checked",
        named(.0)
    )]
    NoReachSettings(Vec<ConnectorName>),
    /// An `https` server has no CA file in the deployment file (decision 0013, section 3).
    #[error(
        "server `{0}` has an https address, so `[servers.{0}]` must name the CA file its \
         certificate is verified against in `ca_file`"
    )]
    NoCaFile(ConnectorName),
    /// The deployment file names a CA file for an `http` server, where nothing would be
    /// verified against it.
    #[error(
        "`[servers.{0}]` names a CA file, but server `{0}` has a plain http address; remove \
         `ca_file`, or give the server an https address"
    )]
    CaFileForHttp(ConnectorName),
    /// A server's address is an IP literal the gateway does not connect to.
    #[error("server `{server}`: the gateway does not connect to {address}, {refusal}")]
    DestinationRefused {
        /// The server.
        server: ConnectorName,
        /// The address in its URL.
        address: IpAddr,
        /// Why it is refused.
        refusal: Refusal,
    },
    /// A server's connector could not be built.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    /// An issuer's keys URL breaks a rule of the key source, such as being off the issuer's
    /// origin, or its CA file cannot be used.
    #[error(transparent)]
    KeysUrl(SourceError),
    /// An issuer's keys could not be fetched at boot.
    #[error("cannot fetch the keys of issuer `{issuer}` at boot: {cause}")]
    KeysFetch {
        /// The issuer.
        issuer: Issuer,
        /// Why the fetch failed.
        cause: FetchError,
    },
    /// The database URL does not parse.
    #[error("the audit database URL does not parse: {0}")]
    DatabaseUrl(String),
    /// The audit store could not be built.
    #[error(transparent)]
    AuditStore(#[from] PgAuditError),
    /// The audit store's boot checks refused.
    #[error(transparent)]
    AuditCheck(#[from] BootCheckError),
    /// The audit store's boot checks did not finish in time.
    #[error(
        "the audit store's boot checks did not finish within {} s; is the database reachable?",
        AUDIT_CHECK_BUDGET.as_secs()
    )]
    AuditCheckTimedOut,
    /// A boot gate refused.
    #[error(transparent)]
    Boot(#[from] BootError),
}

/// A gateway that passed every check, ready to serve.
pub struct Prepared {
    /// What the HTTP server serves.
    pub gates: Gates,
    /// The Postgres store, when audit is on, so shutting down can wait for its finishes.
    pub store: Option<Arc<PgAuditStore>>,
    /// What keeps the policy in step with the registry file.
    pub watch: Watch,
    /// What fetches the keys of each issuer with a keys URL again, on its timer. Run it beside
    /// the watch, and stop it when the gateway shuts down.
    pub keys: KeyRefresher,
    /// Where to serve metrics, or `None` when the deployment file has no `[metrics]`.
    pub metrics: Option<SocketAddr>,
    /// How many requests may be in flight in this instance, which the HTTP server holds it to.
    pub max_in_flight: usize,
    /// What each proxied server's bulkhead counts, for the metrics.
    pub proxied: ProxiedSignals,
    /// The drift pass, its first pass already run. Run it beside the watch, and stop it when the
    /// gateway shuts down.
    pub drift: DriftPass,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("gates", &self.gates)
            .field("store", &self.store.is_some())
            .field("watch", &self.watch)
            .field("keys", &self.keys)
            .field("metrics", &self.metrics)
            .field("max_in_flight", &self.max_in_flight)
            .field("drift", &self.drift)
            .finish_non_exhaustive()
    }
}

/// The registry file, how often to read it, and what it held at boot.
#[derive(Debug)]
pub struct Watch {
    /// Replaces the served policy.
    pub reloader: Reloader,
    /// The registry file.
    pub file: PathBuf,
    /// How often to read it.
    pub every: Duration,
    /// Its bytes at boot.
    pub loaded: Vec<u8>,
}

impl Watch {
    /// Reads the registry file for ever, serving each new version that passes.
    pub async fn run(self) {
        self.reloader
            .watch(self.file, self.every, self.loaded)
            .await;
    }
}

/// The gateway instance's name, from `env`: [`INSTANCE_VAR`], or else [`HOSTNAME_VAR`]. An
/// empty value counts as unset. With neither, [`StartError::NoInstance`]: the gateway does
/// not make a name up.
pub fn instance(env: impl Fn(&str) -> Option<String>) -> Result<InstanceName, StartError> {
    [INSTANCE_VAR, HOSTNAME_VAR]
        .into_iter()
        .filter_map(env)
        .find(|value| !value.is_empty())
        .map(InstanceName::new)
        .ok_or(StartError::NoInstance)
}

/// Builds the gateway `deployment` describes, as `instance`, on `clock`. See the [module
/// documentation](self).
pub async fn prepare(
    deployment: Deployment,
    instance: InstanceName,
    clock: Arc<dyn Clock>,
) -> Result<Prepared, StartError> {
    prepare_with(deployment, instance, clock, cfg!(feature = "test-support")).await
}

/// [`prepare`], with a development build's exemptions given, so a test in one can start the
/// gateway as the release build does.
async fn prepare_with(
    deployment: Deployment,
    instance: InstanceName,
    clock: Arc<dyn Clock>,
    development: bool,
) -> Result<Prepared, StartError> {
    let loaded = std::fs::read(&deployment.registry_file).map_err(|error| RegistryError::Read {
        path: deployment.registry_file.display().to_string(),
        message: error.to_string(),
    })?;
    // The policy's age counts from this read (decision 0013, section 8), not from when the
    // gates pass after the keys are fetched and the database checked.
    let read_at = Instant::now();
    let text = std::str::from_utf8(&loaded).map_err(|error| RegistryError::Read {
        path: deployment.registry_file.display().to_string(),
        message: error.to_string(),
    })?;
    let registry = Registry::from_toml_str(text)?;
    boot::before_connecting(
        &deployment.identity,
        &deployment.audit.section(),
        registry.snapshot(),
        development,
    )?;
    let loopback = if development {
        Loopback::of_this_build()
    } else {
        Loopback::Refused
    };
    destinations(&registry, &deployment.ca_files, loopback)?;
    reach_settings(&registry, deployment.reach.as_ref())?;

    let credentials = Arc::new(credentials(&registry, &deployment.credentials)?);
    let probes = probe_credentials(&registry, &deployment.probe_credentials)?;
    let (wiring, proxied_signals, connectors) = proxied(
        &registry,
        &credentials,
        &deployment.limits,
        &Reaching {
            bounds: &deployment.servers,
            ca_files: &deployment.ca_files,
            loopback,
        },
        Wiring::new(clock),
    )?;
    let mut wiring = wiring.instance(instance.clone());

    let mut identity = deployment.identity;
    let fetched = fetch_keys(&deployment.keys_urls, &mut identity).await?;

    let store = match &deployment.audit {
        AuditChoice::Disabled => None,
        AuditChoice::Postgres { url } => Some(audit_store(url).await?),
    };
    if let Some(store) = &store {
        wiring = wiring.audit_store(store.clone());
    }

    let (issuers, subjects) = identity_counts(&identity);
    let identity_enforced = !identity.disabled;
    let settings = Settings {
        deployment: deployment.deployment,
        identity,
        audit: deployment.audit.section(),
        http: deployment.http,
        max_age: Some(deployment.max_age),
        read_at,
    };
    let revision = registry.snapshot().revision().clone();
    let tools = registry.routes().len();
    let servers = registry.servers().len();
    let (gates, reloader) = boot::check_registry_with(settings, registry, wiring, development)?;
    let mut keys = KeyRefresher::new(gates.shared_identity());
    for Fetched {
        source,
        refresh,
        count,
    } in fetched
    {
        tracing::info!(
            event = "boot",
            keys_issuer = source.issuer().as_str(),
            keys = count,
            refresh_seconds = refresh.as_secs(),
            "fetched the issuer's keys from its keys URL"
        );
        keys.add(source, refresh);
    }

    if identity_enforced {
        tracing::info!(
            event = "boot",
            identity = "enforce",
            issuers,
            subjects,
            "identity is enforced"
        );
    } else {
        tracing::warn!(
            event = "boot",
            identity = "disabled",
            "identity is disabled"
        );
    }
    if store.is_some() {
        tracing::info!(
            event = "boot",
            audit = "postgres",
            role = %database_user(&deployment.audit),
            role_check = "passed",
            "audit rows go to Postgres"
        );
    } else {
        tracing::warn!(event = "boot", audit = "disabled", "audit is disabled");
    }
    let limits = deployment.limits;
    tracing::info!(
        event = "boot",
        max_in_flight = limits.max_in_flight,
        per_server_in_flight = limits.per_server_in_flight,
        per_team_per_server_in_flight = limits.per_team_per_server_in_flight,
        "calls in flight are capped in this instance, per server and per team per server"
    );
    for (server, bounds) in &deployment.servers {
        tracing::info!(
            event = "boot",
            server = server.as_str(),
            deadline_seconds = bounds.deadline.as_secs(),
            max_result_bytes = bounds.max_result_bytes,
            "the server's calls have the bounds the deployment file sets"
        );
    }
    match deployment.metrics {
        Some(address) => tracing::info!(
            event = "boot",
            metrics = %address,
            "metrics are served in Prometheus text at /metrics, on their own listener"
        ),
        None => tracing::info!(
            event = "boot",
            metrics = "off",
            "no metrics listener: the deployment file has no [metrics]"
        ),
    }
    tracing::info!(
        event = "boot",
        %instance,
        "audit rows record this instance as the one that began them"
    );
    // The first drift pass, before the binary binds the listener (decision 0013, section 5).
    let mut drift = DriftPass::new(
        reloader.withdrawals(),
        connectors,
        probes,
        deployment.drift_interval,
    );
    // The reach check calls the listener, so it runs only once the binary has bound it, in
    // `DriftPass::run`.
    match deployment.reach {
        Some(reach) => {
            tracing::info!(
                event = "boot",
                reach_url = %reach.url,
                reach_host = %reach.host,
                "each entry's reach is checked through this listener, as the registry's workload, once it is bound and then every interval"
            );
            drift = drift.with_reach(ReachCaller::new(reach), &deployment.servers);
        }
        None => tracing::info!(
            event = "boot",
            reach = "none",
            "no entry has a reach check, and the deployment file gives no [drift] reach settings"
        ),
    }
    drift.pass().await;
    tracing::info!(
        event = "boot",
        drift_interval_seconds = deployment.drift_interval.as_secs(),
        "read each proxied server's tool list before serving, and again every interval"
    );
    // What is served: the registry file's policy, less what the first pass withdrew.
    let withdrawn = drift.withdrawals().standing().len();
    let served = gates.policy().revision().clone();
    tracing::info!(
        event = "boot",
        registry = %deployment.registry_file.display(),
        registry_revision = %revision,
        revision = %served,
        tools = tools.saturating_sub(withdrawn),
        withdrawn,
        servers,
        poll_seconds = deployment.poll.as_secs(),
        max_age_seconds = deployment.max_age.as_secs(),
        "serving the registry file's policy, less any tool the first drift pass withdrew"
    );

    Ok(Prepared {
        gates,
        store,
        watch: Watch {
            reloader,
            file: deployment.registry_file,
            every: deployment.poll,
            loaded,
        },
        keys,
        metrics: deployment.metrics,
        max_in_flight: limits.max_in_flight,
        proxied: proxied_signals,
        drift,
    })
}

/// The connector of each proxied server, by name, for the drift pass.
type Connectors = BTreeMap<ConnectorName, Arc<ProxyConnector>>;

/// `servers`, each in backquotes, separated by commas.
fn named(servers: &[ConnectorName]) -> String {
    servers
        .iter()
        .map(|server| format!("`{server}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Refuses a registry with an entry that has a reach check when the deployment file gives no
/// reach settings: that entry's reach would never be checked (decision 0011, section 4).
fn reach_settings(registry: &Registry, reach: Option<&ReachSettings>) -> Result<(), StartError> {
    let checked: Vec<ConnectorName> = registry
        .servers()
        .iter()
        .filter(|(_, server)| server.reach_check.is_some())
        .map(|(name, _)| name.clone())
        .collect();
    if reach.is_none() && !checked.is_empty() {
        return Err(StartError::NoReachSettings(checked));
    }
    Ok(())
}

/// The connector's class of a registry entry's destination.
pub(crate) fn destination(destination: Destination) -> connector_proxy::Destination {
    match destination {
        Destination::InCluster => connector_proxy::Destination::InCluster,
        Destination::Public => connector_proxy::Destination::Public,
    }
}

/// Checks where each of the registry's servers is reached, before anything is read or
/// connected to (decision 0013, section 3). An `https` server needs a CA file in `ca_files`,
/// and an `http` server may not have one. An address that is an IP literal is refused if the
/// connector would not connect to it, under `loopback`: an address named by DNS is checked
/// each time it is resolved instead.
fn destinations(
    registry: &Registry,
    ca_files: &BTreeMap<ConnectorName, PathBuf>,
    loopback: Loopback,
) -> Result<(), StartError> {
    for server in registry.servers().values() {
        let https = server.address.starts_with("https://");
        match (https, ca_files.contains_key(&server.name)) {
            (true, false) => return Err(StartError::NoCaFile(server.name.clone())),
            (false, true) => return Err(StartError::CaFileForHttp(server.name.clone())),
            _ => {}
        }
        let Some(host) = gateway_registry::address_host(&server.address) else {
            continue;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = host.parse::<IpAddr>()
            && let Some(refusal) =
                connector_proxy::refusal(address, destination(server.destination), loopback)
        {
            return Err(StartError::DestinationRefused {
                server: server.name.clone(),
                address,
                refusal,
            });
        }
    }
    Ok(())
}

/// How each proxied server is reached: the bounds the deployment file sets for its calls, its
/// CA file, and whether loopback is allowed.
struct Reaching<'a> {
    bounds: &'a BTreeMap<ConnectorName, ServerLimits>,
    ca_files: &'a BTreeMap<ConnectorName, PathBuf>,
    loopback: Loopback,
}

/// `wiring` with a [`ProxyConnector`] for each of the registry's servers, built with the bounds
/// `reaching` sets for it or the defaults, its destination, its CA file, in a [`Bulkhead`]
/// holding it to `limits`. Each is given the call deadline its connector was built with, which
/// every row of its calls includes in its deadline. Refuses bounds for a server the registry
/// does not name. Each connector is returned too, for the drift pass, which reads the server's
/// tool list and probes it with it.
fn proxied(
    registry: &Registry,
    credentials: &Arc<FileCredentials>,
    limits: &Limits,
    reaching: &Reaching<'_>,
    mut wiring: Wiring,
) -> Result<(Wiring, ProxiedSignals, Connectors), StartError> {
    let servers = reaching.bounds;
    if let Some(unknown) = servers
        .keys()
        .find(|name| !registry.servers().contains_key(*name))
    {
        return Err(StartError::UnknownServerLimits(unknown.clone()));
    }
    let mut signals = BTreeMap::new();
    let mut connectors = BTreeMap::new();
    for server in registry.servers().values() {
        let bounds = servers.get(&server.name).copied().unwrap_or_default();
        let mut upstream = Upstream::new(server.name.clone(), server.address.clone());
        upstream.destination = destination(server.destination);
        upstream.ca_file = reaching.ca_files.get(&server.name).cloned();
        upstream.loopback = reaching.loopback;
        upstream.deadline = bounds.deadline;
        upstream.max_response_bytes = bounds.max_result_bytes;
        for (tool, route) in registry.routes() {
            if route.server == server.name {
                upstream = upstream.tool(tool.clone(), route.upstream_name.clone());
            }
        }
        let deadline = upstream.deadline;
        let connector = Arc::new(ProxyConnector::new(upstream, credentials.clone())?);
        connectors.insert(server.name.clone(), Arc::clone(&connector));
        let bulkhead = Bulkhead::new(
            server.name.clone(),
            connector,
            limits.per_server_in_flight,
            limits.per_team_per_server_in_flight,
        );
        signals.insert(server.name.clone(), bulkhead.signals());
        wiring = wiring
            .proxied(server.name.clone(), Arc::new(bulkhead))
            .call_deadline(server.name.clone(), deadline);
    }
    Ok((wiring, ProxiedSignals::new(signals), connectors))
}

/// An issuer's key source, with how often to fetch again and how many keys its first fetch
/// returned.
struct Fetched {
    source: KeySource,
    refresh: Duration,
    count: usize,
}

/// Checks every keys URL, then fetches each issuer's keys once and puts them in its entry in
/// `identity`. Refuses a URL the key source refuses, with its CA and token files, and a fetch
/// that fails.
async fn fetch_keys(
    keys_urls: &[KeysUrl],
    identity: &mut IdentitySection,
) -> Result<Vec<Fetched>, StartError> {
    let mut sources = Vec::with_capacity(keys_urls.len());
    for keys_url in keys_urls {
        let files = SourceFiles {
            ca_file: keys_url.ca_file.clone(),
            token_file: keys_url.token_file.clone(),
        };
        let source = KeySource::with_files(
            &keys_url.issuer,
            &keys_url.url,
            &files,
            FetchOptions::default(),
        )
        .map_err(StartError::KeysUrl)?;
        sources.push((source, keys_url.refresh));
    }
    let mut fetched = Vec::with_capacity(sources.len());
    for (source, refresh) in sources {
        let issuer = source.issuer().clone();
        let keys = source
            .fetch()
            .await
            .map_err(|cause| StartError::KeysFetch {
                issuer: issuer.clone(),
                cause,
            })?;
        let count = keys.keys.len();
        let entry = identity
            .enforce
            .iter_mut()
            .flatten()
            .find(|entry| entry.issuer == issuer);
        if let Some(entry) = entry {
            // A JWK set always serializes. If it somehow did not, `null` is not a JWK set, and
            // the identity gate refuses to build.
            entry.keys = serde_json::to_value(&keys).unwrap_or_default();
        }
        fetched.push(Fetched {
            source,
            refresh,
            count,
        });
    }
    Ok(fetched)
}

/// The gateway's credential for each server, from the file the deployment gives for its
/// reference. Every server's reference must have a file, and every file must be used.
fn credentials(
    registry: &Registry,
    files: &BTreeMap<String, PathBuf>,
) -> Result<FileCredentials, StartError> {
    let mut used = BTreeSet::new();
    let mut pairs = Vec::new();
    for server in registry.servers().values() {
        // A team service identity and a gateway token are each a secret the gateway holds,
        // read from the file the deployment names. Per-user grants arrive in milestone 5.
        let reference = match server.credential.mode {
            CredentialMode::TeamServiceIdentity | CredentialMode::GatewayToken => {
                &server.credential.reference
            }
            CredentialMode::PerUserGrant => {
                return Err(StartError::PerUserGrant(server.name.clone()));
            }
        };
        // Decision 0011 lets an entry narrowed per call or to the limit skip the whole-reach
        // check (rule 5) only because its credential really is narrowed. Nothing narrows one
        // yet: the same credential goes on every call to a server.
        if server.narrowing != Narrowing::None {
            return Err(StartError::NarrowingNotBuilt(server.name.clone()));
        }
        let Some(path) = files.get(reference) else {
            return Err(StartError::NoCredentialFile {
                server: server.name.clone(),
                reference: reference.clone(),
            });
        };
        used.insert(reference.clone());
        pairs.push((server.name.clone(), path.clone()));
    }
    if let Some(unused) = files.keys().find(|reference| !used.contains(*reference)) {
        return Err(StartError::UnusedCredential(unused.clone()));
    }
    Ok(FileCredentials::load(pairs)?)
}

/// Connects the Postgres store and runs its boot checks, within [`AUDIT_CHECK_BUDGET`]. TLS is
/// not used: the demo's database is on the same private network as the gateway.
async fn audit_store(url: &str) -> Result<Arc<PgAuditStore>, StartError> {
    let config: tokio_postgres::Config = url
        .parse()
        .map_err(|error: tokio_postgres::Error| StartError::DatabaseUrl(error.to_string()))?;
    let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())?
        .on_given_up(log_given_up);
    match tokio::time::timeout(AUDIT_CHECK_BUDGET, store.check_at_boot()).await {
        Err(_elapsed) => Err(StartError::AuditCheckTimedOut),
        Ok(Err(refused)) => Err(StartError::AuditCheck(refused)),
        Ok(Ok(())) => Ok(Arc::new(store)),
    }
}

/// Logs one finish the store gave up as [`GIVEN_UP_EVENT`]. Called on the finish's own task.
fn log_given_up(given_up: GivenUp<'_>) {
    tracing::error!(
        event = GIVEN_UP_EVENT,
        row = given_up.row.as_str(),
        outcome = given_up.outcome,
        cause = %given_up.error,
        "an audit row's completion was not written, and the store has stopped trying"
    );
}

/// The role the store connects as, for the boot line. Never the password.
fn database_user(audit: &AuditChoice) -> String {
    match audit {
        AuditChoice::Postgres { url } => url
            .parse::<tokio_postgres::Config>()
            .ok()
            .and_then(|config| config.get_user().map(str::to_owned))
            .unwrap_or_default(),
        AuditChoice::Disabled => String::new(),
    }
}

/// How many issuers are configured, and how many workload subjects their manifests list.
fn identity_counts(identity: &IdentitySection) -> (usize, usize) {
    let issuers = identity.enforce.as_deref().unwrap_or_default();
    let subjects = issuers
        .iter()
        .map(|issuer| match &issuer.kind {
            IssuerKindEntry::Workload { subjects } => subjects.len(),
            IssuerKindEntry::User { .. } => 0,
        })
        .sum();
    (issuers.len(), subjects)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment holding only `pairs`.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(set, _)| set == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// The wiring of the boot test registry's one server, `mock-docs`, with `servers` as the
    /// deployment file's bounds.
    fn wired(
        name: &str,
        servers: &BTreeMap<ConnectorName, ServerLimits>,
    ) -> Result<Wiring, StartError> {
        let registry = crate::boot::tests::registry("read", true);
        let directory = std::env::temp_dir().join(format!(
            "switchboard-start-deadline-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let credential = directory.join("docs-credential");
        std::fs::write(&credential, "dummy-credential-for-tests-only\n").unwrap();
        let credentials = Arc::new(
            FileCredentials::load([(ConnectorName::new("mock-docs"), &credential)]).unwrap(),
        );
        let wiring = proxied(
            &registry,
            &credentials,
            &Limits::default(),
            &Reaching {
                bounds: servers,
                ca_files: &BTreeMap::new(),
                loopback: Loopback::of_this_build(),
            },
            Wiring::new(Arc::new(gateway_identity::SystemClock)),
        );
        std::fs::remove_dir_all(&directory).unwrap();
        wiring.map(|(wiring, _, _)| wiring)
    }

    /// Each proxied server's connector deadline reaches the wiring, which gives it to every row
    /// of that server's calls: the default, or the one its entry in the deployment file sets.
    /// The boot gates' own fallback for a server given none is the default, so only a deadline
    /// set in the file tells this wiring from its absence.
    #[test]
    fn each_proxied_server_is_wired_with_the_deadline_its_connector_was_built_with() {
        assert_eq!(
            wired("default", &BTreeMap::new()).unwrap().call_deadlines(),
            &BTreeMap::from([(
                ConnectorName::new("mock-docs"),
                connector_proxy::DEFAULT_DEADLINE
            )])
        );
        let set = BTreeMap::from([(
            ConnectorName::new("mock-docs"),
            ServerLimits {
                deadline: Duration::from_secs(17),
                max_result_bytes: 1000,
            },
        )]);
        assert_eq!(
            wired("set", &set).unwrap().call_deadlines(),
            &BTreeMap::from([(ConnectorName::new("mock-docs"), Duration::from_secs(17))])
        );
    }

    /// Bounds for a server the registry does not name refuse the start, naming it.
    #[test]
    fn bounds_for_a_server_the_registry_lacks_are_refused() {
        let servers = BTreeMap::from([
            (ConnectorName::new("mock-docs"), ServerLimits::default()),
            (ConnectorName::new("mock-dcos"), ServerLimits::default()),
        ]);
        let refused = wired("unknown", &servers).unwrap_err();
        assert!(
            matches!(&refused, StartError::UnknownServerLimits(name) if name.as_str() == "mock-dcos"),
            "{refused}"
        );
        assert_eq!(
            refused.to_string(),
            "`[servers.mock-dcos]` sets bounds for a server the registry does not name; remove \
             it, or name a server the registry has"
        );
    }

    /// The boot test registry with its one server at an `https` address, its identity the
    /// address's host.
    fn https_registry() -> Registry {
        let text = registry_text_at(
            "docs.example.test",
            "https://docs.example.test/mcp",
            "in_cluster",
        );
        Registry::from_toml_str(&text).unwrap()
    }

    /// The boot test registry's text with its one server's identity, address and destination
    /// replaced, and its tool's binding hash to match.
    fn registry_text_at(identity: &str, address: &str, destination: &str) -> String {
        let mut server = crate::boot::tests::server();
        let before = gateway_registry::binding_sha256(&server);
        server.identity = identity.into();
        server.address = address.into();
        server.destination = match destination {
            "public" => gateway_registry::Destination::Public,
            _ => gateway_registry::Destination::InCluster,
        };
        crate::boot::tests::registry_text("read", true, "r1")
            .replace(
                "identity = \"127.0.0.1\"",
                &format!("identity = \"{identity}\""),
            )
            .replace(
                "address = \"http://127.0.0.1:9/mcp\"",
                &format!("address = \"{address}\""),
            )
            .replace(
                "destination = \"in_cluster\"",
                &format!("destination = \"{destination}\""),
            )
            .replace(&before, &gateway_registry::binding_sha256(&server))
    }

    /// Decision 0013, section 3: an `https` server needs the CA file its certificate is
    /// verified against, and an `http` server, where nothing would be verified, takes none.
    #[test]
    fn an_https_server_needs_a_ca_file_and_an_http_server_takes_none() {
        let https = https_registry();
        let http = crate::boot::tests::registry("read", true);
        let named = BTreeMap::from([(ConnectorName::new("mock-docs"), PathBuf::from("ca.pem"))]);
        let none = BTreeMap::new();

        let refused = destinations(&https, &none, Loopback::Refused).unwrap_err();
        assert!(
            matches!(&refused, StartError::NoCaFile(server) if server.as_str() == "mock-docs"),
            "{refused}"
        );
        assert_eq!(
            refused.to_string(),
            "server `mock-docs` has an https address, so `[servers.mock-docs]` must name the CA \
             file its certificate is verified against in `ca_file`"
        );
        assert!(destinations(&https, &named, Loopback::Refused).is_ok());

        let refused = destinations(&http, &named, Loopback::of_this_build()).unwrap_err();
        assert!(
            matches!(&refused, StartError::CaFileForHttp(server) if server.as_str() == "mock-docs"),
            "{refused}"
        );
        assert!(destinations(&http, &none, Loopback::of_this_build()).is_ok());
    }

    /// The CA file the deployment names reaches the server's connector, which is built with it
    /// and could not be built without it.
    #[test]
    fn an_https_servers_connector_is_built_with_the_ca_file_the_deployment_names() {
        let directory =
            std::env::temp_dir().join(format!("switchboard-start-ca-file-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let credential = directory.join("docs-credential");
        std::fs::write(&credential, "dummy-credential-for-tests-only\n").unwrap();
        let ca_file = directory.join("ca.pem");
        let key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let credentials = Arc::new(
            FileCredentials::load([(ConnectorName::new("mock-docs"), &credential)]).unwrap(),
        );
        let registry = https_registry();
        let built = |ca_files: &BTreeMap<ConnectorName, PathBuf>| {
            proxied(
                &registry,
                &credentials,
                &Limits::default(),
                &Reaching {
                    bounds: &BTreeMap::new(),
                    ca_files,
                    loopback: Loopback::Refused,
                },
                Wiring::new(Arc::new(gateway_identity::SystemClock)),
            )
            .map(|_| ())
        };

        let named = built(&BTreeMap::from([(
            ConnectorName::new("mock-docs"),
            ca_file,
        )]));
        let unnamed = built(&BTreeMap::new());
        std::fs::remove_dir_all(&directory).unwrap();

        assert!(named.is_ok(), "{named:?}");
        assert!(
            matches!(
                unnamed,
                Err(StartError::Upstream(UpstreamError::NoCaFile(_)))
            ),
            "{unnamed:?}"
        );
    }

    /// Decision 0013, section 3: a server whose entry is `public` is held to that class. Plain
    /// `http` is refused as the registry loads, and a private address before anything is
    /// connected to. The connector built for each server takes its entry's destination: a
    /// `public` entry's connector refuses the private address too, and an `in_cluster` entry's
    /// connector accepts it, which it would not if the destination were left at the default.
    #[tokio::test]
    async fn a_public_server_on_http_or_a_private_address_is_refused() {
        let counted = Counted::start().await;
        let directory =
            std::env::temp_dir().join(format!("switchboard-start-public-{}", std::process::id()));
        let started = |text: String, ca_file: Option<PathBuf>| {
            let mut deployment = deployment(&directory, &text, &counted, false, false);
            if let Some(ca_file) = ca_file {
                deployment.ca_files = BTreeMap::from([(ConnectorName::new("mock-docs"), ca_file)]);
            }
            prepare_with(
                deployment,
                InstanceName::new("start-test"),
                Arc::new(gateway_identity::SystemClock),
                true,
            )
        };
        let ca_file = directory.join("ca.pem");

        let http = started(
            registry_text_at("127.0.0.1", "http://127.0.0.1:9/mcp", "public"),
            None,
        )
        .await
        .map(|_| ())
        .unwrap_err();
        let private = started(
            registry_text_at("10.0.0.1", "https://10.0.0.1/mcp", "public"),
            Some(ca_file.clone()),
        )
        .await
        .map(|_| ())
        .unwrap_err();

        assert!(
            matches!(
                &http,
                StartError::Registry(RegistryError::DestinationScheme { server, .. })
                    if server.as_str() == "mock-docs"
            ),
            "{http}"
        );
        assert!(
            matches!(
                &private,
                StartError::DestinationRefused {
                    refusal: Refusal::Private,
                    ..
                }
            ),
            "{private}"
        );
        assert_eq!(
            private.to_string(),
            "server `mock-docs`: the gateway does not connect to 10.0.0.1, a private address, \
             which only a server whose destination is in_cluster may use"
        );
        assert_eq!(counted.connections(), 0, "something was connected to first");

        // The connectors, past the start's own check.
        let key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let credentials = Arc::new(
            FileCredentials::load([(
                ConnectorName::new("mock-docs"),
                directory.join("docs-credential"),
            )])
            .unwrap(),
        );
        let ca_files = BTreeMap::from([(ConnectorName::new("mock-docs"), ca_file)]);
        let built = |destination: &str| {
            let text = registry_text_at("10.0.0.1", "https://10.0.0.1/mcp", destination);
            proxied(
                &Registry::from_toml_str(&text).unwrap(),
                &credentials,
                &Limits::default(),
                &Reaching {
                    bounds: &BTreeMap::new(),
                    ca_files: &ca_files,
                    loopback: Loopback::Refused,
                },
                Wiring::new(Arc::new(gateway_identity::SystemClock)),
            )
            .map(|_| ())
        };
        let public = built("public");
        let in_cluster = built("in_cluster");
        std::fs::remove_dir_all(&directory).unwrap();

        assert!(
            matches!(
                public,
                Err(StartError::Upstream(UpstreamError::DestinationRefused {
                    refusal: Refusal::Private,
                    ..
                }))
            ),
            "{public:?}"
        );
        assert!(in_cluster.is_ok(), "{in_cluster:?}");
    }

    /// A listener that counts the connections made to it and closes each at once: the audit
    /// database and the issuer's keys URL, which a refusal before connecting never reaches.
    struct Counted {
        address: std::net::SocketAddr,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Counted {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counting = accepted.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(stream);
                }
            });
            Self { address, accepted }
        }

        fn connections(&self) -> usize {
            self.accepted.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A deployment of `registry_text`, written to `directory`, whose audit database and
    /// issuer's keys URL are both `counted`, with identity and audit disabled as given.
    fn deployment(
        directory: &std::path::Path,
        registry_text: &str,
        counted: &Counted,
        identity_disabled: bool,
        audit_disabled: bool,
    ) -> Deployment {
        std::fs::create_dir_all(directory).unwrap();
        let registry_file = directory.join("registry.toml");
        std::fs::write(&registry_file, registry_text).unwrap();
        let credential = directory.join("docs-credential");
        std::fs::write(&credential, "dummy-credential-for-tests-only\n").unwrap();
        let probe = directory.join("probe-credential");
        std::fs::write(&probe, "dummy-probe-credential-for-tests-only\n").unwrap();
        let issuer = format!("http://{}", counted.address);
        let identity = if identity_disabled {
            IdentitySection {
                enforce: None,
                disabled: true,
            }
        } else {
            IdentitySection {
                enforce: Some(vec![crate::config::IssuerEntry {
                    issuer: Issuer::new(issuer.as_str()),
                    audiences: ["switchboard".to_owned()].into(),
                    kind: IssuerKindEntry::User {
                        groups_claim: "groups".to_owned(),
                    },
                    algorithm: crate::config::Algorithm::Es256,
                    keys: serde_json::Value::Null,
                    max_lifetime_secs: 3600,
                    leeway_secs: 30,
                }]),
                disabled: false,
            }
        };
        let keys_urls = if identity_disabled {
            Vec::new()
        } else {
            vec![KeysUrl {
                issuer: Issuer::new(issuer.as_str()),
                url: format!("{issuer}/keys"),
                refresh: Duration::from_secs(300),
                ca_file: None,
                token_file: None,
            }]
        };
        let audit = if audit_disabled {
            AuditChoice::Disabled
        } else {
            AuditChoice::Postgres {
                url: format!(
                    "postgres://switchboard_gateway:dummy@{}/switchboard?connect_timeout=2",
                    counted.address
                ),
            }
        };
        Deployment {
            deployment: "start-test".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            http: crate::config::HttpSection {
                allowed_hosts: ["localhost".to_owned()].into(),
                allowed_origins: BTreeSet::new(),
            },
            registry_file,
            poll: Duration::from_secs(2),
            max_age: Duration::from_secs(60),
            identity,
            keys_urls,
            audit,
            metrics: None,
            limits: Limits::default(),
            servers: BTreeMap::new(),
            ca_files: BTreeMap::new(),
            drift_interval: crate::drift::DEFAULT_DRIFT_INTERVAL,
            probe_credentials: BTreeMap::from([(ConnectorName::new("mock-docs"), probe)]),
            reach: None,
            credentials: BTreeMap::from([("docs-credential".to_owned(), credential)]),
        }
    }

    /// What `deployment` refuses with, started as the release build starts.
    async fn refused_as_release(deployment: Deployment) -> StartError {
        prepare_with(
            deployment,
            InstanceName::new("start-test"),
            Arc::new(gateway_identity::SystemClock),
            false,
        )
        .await
        .unwrap_err()
    }

    /// A release build refuses a registry serving a proxied `propose` tool as the registry
    /// loads (decision 0011, rule 2), before it fetches a key or connects to the audit
    /// database. The receipt-store gate, which `boot::before_connecting` also runs there, is
    /// not reached: every registry tool is proxied.
    #[tokio::test]
    async fn a_registry_the_loader_refuses_is_refused_before_anything_is_connected() {
        let counted = Counted::start().await;
        let directory =
            std::env::temp_dir().join(format!("switchboard-start-loader-{}", std::process::id()));
        let text = crate::boot::tests::registry_text("propose", true, "r1");
        let refused =
            refused_as_release(deployment(&directory, &text, &counted, false, false)).await;
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            matches!(
                refused,
                StartError::Registry(RegistryError::Snapshot(
                    gateway_core::SnapshotError::ProxiedNotRead { .. }
                ))
            ),
            "{refused}"
        );
        assert_eq!(counted.connections(), 0, "something was connected to first");
    }

    /// A per-user grant is refused at start, even with a file for its reference: it is not
    /// built until milestone 5. A team service identity and a gateway token each read theirs.
    #[test]
    fn a_per_user_grant_is_refused_and_the_other_modes_read_their_file() {
        let directory =
            std::env::temp_dir().join(format!("switchboard-start-per-user-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let credential = directory.join("docs-credential");
        std::fs::write(&credential, "dummy-credential-for-tests-only\n").unwrap();
        let files = BTreeMap::from([("docs-credential".to_owned(), credential)]);
        let text = crate::boot::tests::registry_text("read", false, "r1");
        let before = gateway_registry::binding_sha256(&crate::boot::tests::server());
        let mut outcomes = Vec::new();
        for mode in [
            CredentialMode::PerUserGrant,
            CredentialMode::TeamServiceIdentity,
            CredentialMode::GatewayToken,
        ] {
            let mut server = crate::boot::tests::server();
            server.credential.mode = mode;
            let written = match mode {
                CredentialMode::PerUserGrant => "per_user_grant",
                CredentialMode::TeamServiceIdentity => "team_service_identity",
                CredentialMode::GatewayToken => "gateway_token",
            };
            let text = text
                .replace("mode = \"gateway_token\"", &format!("mode = \"{written}\""))
                .replace(&before, &gateway_registry::binding_sha256(&server));
            let registry = Registry::from_toml_str(&text).unwrap();
            outcomes.push(credentials(&registry, &files).map(|_| ()));
        }
        std::fs::remove_dir_all(&directory).unwrap();
        match &outcomes[0] {
            Err(refused @ StartError::PerUserGrant(server)) => {
                assert_eq!(server.as_str(), "mock-docs");
                assert_eq!(
                    refused.to_string(),
                    "server `mock-docs`'s credential is a per-user grant, which this gateway \
                     does not support yet"
                );
            }
            other => panic!("expected the per-user refusal, got {other:?}"),
        }
        assert!(outcomes[1].is_ok(), "{:?}", outcomes[1]);
        assert!(outcomes[2].is_ok(), "{:?}", outcomes[2]);
    }

    /// An entry whose credential is to be narrowed per call or to the caller's limit is
    /// refused at start: the gateway sends the same credential on every call, so the entry
    /// would skip rule 5's whole-reach check with a credential that is not narrowed. Narrowing
    /// "none" starts.
    #[test]
    fn a_narrowed_credential_is_refused_and_none_starts() {
        let directory = std::env::temp_dir().join(format!(
            "switchboard-start-narrowing-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let credential = directory.join("docs-credential");
        std::fs::write(&credential, "dummy-credential-for-tests-only\n").unwrap();
        let files = BTreeMap::from([("docs-credential".to_owned(), credential)]);
        // No tool is approved, so rule 7 (a tool on an entry narrowed per call declares its
        // resources from its arguments) has nothing to refuse and each narrowing loads.
        let text = crate::boot::tests::registry_text("read", false, "r1");
        let tools = text.find("[[tools]]").unwrap();
        let surfaces = text.find("[[surfaces]]").unwrap();
        let text = format!("tools = []\n{}{}", &text[..tools], &text[surfaces..]);
        let before = gateway_registry::binding_sha256(&crate::boot::tests::server());
        let mut outcomes = Vec::new();
        for (narrowing, written) in [
            (Narrowing::Call, "call"),
            (Narrowing::Limit, "limit"),
            (Narrowing::None, "none"),
        ] {
            let mut server = crate::boot::tests::server();
            server.narrowing = narrowing;
            let text = text
                .replace(
                    "narrowing = \"none\"",
                    &format!("narrowing = \"{written}\""),
                )
                .replace(&before, &gateway_registry::binding_sha256(&server));
            let registry = Registry::from_toml_str(&text).unwrap();
            assert_eq!(
                registry.servers().values().next().unwrap().narrowing,
                narrowing
            );
            outcomes.push(credentials(&registry, &files).map(|_| ()));
        }
        std::fs::remove_dir_all(&directory).unwrap();
        for outcome in &outcomes[..2] {
            match outcome {
                Err(refused @ StartError::NarrowingNotBuilt(server)) => {
                    assert_eq!(server.as_str(), "mock-docs");
                    assert_eq!(
                        refused.to_string(),
                        "server `mock-docs` says its credential is narrowed per call or to the \
                         caller's limit, which this gateway cannot do yet: it sends the same \
                         credential on every call, so only narrowing \"none\" is supported"
                    );
                }
                other => panic!("expected the narrowing refusal, got {other:?}"),
            }
        }
        assert!(outcomes[2].is_ok(), "{:?}", outcomes[2]);
    }

    /// Decision 0014, section 4: a release build refuses each opt-out before it connects to
    /// anything.
    #[tokio::test]
    async fn the_opt_outs_are_refused_before_anything_is_connected() {
        let counted = Counted::start().await;
        let text = crate::boot::tests::registry_text("read", true, "r1");
        for (name, identity_disabled, audit_disabled) in
            [("identity", true, false), ("audit", false, true)]
        {
            let directory = std::env::temp_dir().join(format!(
                "switchboard-start-opt-out-{name}-{}",
                std::process::id()
            ));
            let refused = refused_as_release(deployment(
                &directory,
                &text,
                &counted,
                identity_disabled,
                audit_disabled,
            ))
            .await;
            std::fs::remove_dir_all(&directory).unwrap();
            let expected = if identity_disabled {
                matches!(refused, StartError::Boot(BootError::IdentityOptOut))
            } else {
                matches!(refused, StartError::Boot(BootError::AuditOptOut))
            };
            assert!(expected, "{name}: {refused}");
        }
        assert_eq!(counted.connections(), 0, "something was connected to first");
    }

    /// Decision 0013, section 3: a release build refuses a server whose address is a loopback
    /// literal before it reads a credential or connects to anything. A development build, as
    /// these tests are, allows it for the tests' local servers.
    #[tokio::test]
    async fn a_release_build_refuses_a_server_on_loopback_before_anything_is_connected() {
        let counted = Counted::start().await;
        let directory =
            std::env::temp_dir().join(format!("switchboard-start-loopback-{}", std::process::id()));
        let text = crate::boot::tests::registry_text("read", true, "r1");
        let mut deployment = deployment(&directory, &text, &counted, false, false);
        // A credential file that would refuse the start, were it read first.
        deployment.credentials = BTreeMap::from([(
            "docs-credential".to_owned(),
            directory.join("no-such-credential"),
        )]);
        let refused = refused_as_release(deployment).await;
        std::fs::remove_dir_all(&directory).unwrap();

        assert!(
            matches!(
                &refused,
                StartError::DestinationRefused {
                    refusal: Refusal::Loopback,
                    ..
                }
            ),
            "{refused}"
        );
        assert_eq!(
            refused.to_string(),
            "server `mock-docs`: the gateway does not connect to 127.0.0.1, a loopback address"
        );
        assert_eq!(counted.connections(), 0, "something was connected to first");
        let registry = Registry::from_toml_str(&text).unwrap();
        assert!(destinations(&registry, &BTreeMap::new(), Loopback::of_this_build()).is_ok());
    }

    #[test]
    fn the_instance_is_switchboard_instance_or_else_the_hostname() {
        let named = |pairs: &[(&str, &str)]| instance(env(pairs)).ok();
        assert_eq!(
            named(&[(INSTANCE_VAR, "gateway-a"), (HOSTNAME_VAR, "pod-1")]),
            Some(InstanceName::new("gateway-a"))
        );
        assert_eq!(
            named(&[(HOSTNAME_VAR, "pod-1")]),
            Some(InstanceName::new("pod-1"))
        );
        assert_eq!(
            named(&[(INSTANCE_VAR, ""), (HOSTNAME_VAR, "pod-1")]),
            Some(InstanceName::new("pod-1"))
        );
    }

    #[test]
    fn with_nothing_naming_the_instance_the_gateway_refuses_to_start() {
        for pairs in [
            &[][..],
            &[(INSTANCE_VAR, "")],
            &[(INSTANCE_VAR, ""), (HOSTNAME_VAR, "")],
            &[("SWITCHBOARD_INSTANCE_NAME", "gateway-a")],
        ] {
            let refused = instance(env(pairs));
            assert!(
                matches!(refused, Err(StartError::NoInstance)),
                "{pairs:?}: {refused:?}"
            );
        }
        assert_eq!(
            StartError::NoInstance.to_string(),
            "nothing names this gateway instance: set SWITCHBOARD_INSTANCE, or HOSTNAME as \
             Kubernetes and Docker do, so each audit row can record the instance that began it"
        );
    }
}
