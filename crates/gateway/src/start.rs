//! Building a running gateway from a [`Deployment`]: what the `switchboard` binary does
//! before it binds a socket.
//!
//! [`instance`] names the gateway instance from the environment, once, before anything else
//! is prepared: `SWITCHBOARD_INSTANCE`, or else `HOSTNAME`, which Kubernetes sets to the pod's
//! name and Docker to the container's. With neither, the gateway refuses to start. Every audit
//! row records the instance that began it.
//!
//! [`prepare`] reads the registry file, loads each proxied server's credential, builds a
//! [`ProxyConnector`] per server, fetches the keys of each issuer configured with a keys URL,
//! connects the Postgres audit store and runs its boot checks (or takes audit as explicitly
//! disabled), and then runs the boot gates ([`boot::check_registry`]). Any failure refuses to
//! start, naming the reason, before anything is served.
//!
//! Each keys URL is checked first, every one before any is fetched: it must be on its issuer's
//! own origin, and plain `http`, since this build cannot fetch over TLS (issue #88). Then each
//! issuer's keys are fetched once, and a fetch that fails refuses to start, naming the issuer
//! and the cause. The [`KeyRefresher`] in [`Prepared`] fetches them again on a timer.
//!
//! It logs one `"event":"boot"` line per gate, which an operator (and the demo) reads to see
//! how the gateway was started: identity enforced or disabled, with how many issuers and
//! subjects; each issuer whose keys were fetched, with how many keys and how often they are
//! fetched again; audit in Postgres, with the role and its check, or disabled; and the
//! registry's revision.
//!
//! The Postgres store reports each audit row it stops trying to complete. The gateway logs each
//! report as [`GIVEN_UP_EVENT`] at `ERROR`, naming the row, so an open row is found when it is
//! left open and not only by querying for it (decision 0009).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use audit_postgres::{BootCheckError, GivenUp, PgAuditError, PgAuditStore, PoolSizes};
use connector_proxy::{
    CredentialFileError, FileCredentials, ProxyConnector, Upstream, UpstreamError,
};
use gateway_core::{ConnectorName, InstanceName, Issuer};
use gateway_identity::Clock;
use gateway_registry::{Credential, Registry, RegistryError};
use issuer_keys::{FetchError, FetchOptions, KeySource, SourceError};
use thiserror::Error;

use crate::boot::{self, BootError, Gates, Settings, Wiring};
use crate::config::{IdentitySection, IssuerKindEntry};
use crate::deployment::{AuditChoice, Deployment, KeysUrl};
use crate::keys::KeyRefresher;
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
    /// A credential file is given that no server uses.
    #[error("credential `{0}` is given a file in `[credentials]` but no server uses it")]
    UnusedCredential(String),
    /// A credential file could not be loaded.
    #[error(transparent)]
    Credentials(#[from] CredentialFileError),
    /// A server's connector could not be built.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    /// An issuer's keys URL is `https`, and this build cannot fetch over TLS.
    #[error(
        "the keys URL for issuer `{0}` is https, and this gateway cannot fetch keys over TLS \
         yet (issue #88); give the issuer a keys_file instead"
    )]
    KeysOverTls(Issuer),
    /// An issuer's keys URL breaks a rule of the key source, such as being off the issuer's
    /// origin.
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
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("gates", &self.gates)
            .field("store", &self.store.is_some())
            .field("watch", &self.watch)
            .field("keys", &self.keys)
            .finish()
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
    let loaded = std::fs::read(&deployment.registry_file).map_err(|error| RegistryError::Read {
        path: deployment.registry_file.display().to_string(),
        message: error.to_string(),
    })?;
    let text = std::str::from_utf8(&loaded).map_err(|error| RegistryError::Read {
        path: deployment.registry_file.display().to_string(),
        message: error.to_string(),
    })?;
    let registry = Registry::from_toml_str(text)?;

    let credentials = Arc::new(credentials(&registry, &deployment.credentials)?);
    let mut wiring = Wiring::new(clock).instance(instance.clone());
    for server in registry.servers().values() {
        let mut upstream = Upstream::new(server.name.clone(), server.address.clone());
        for (tool, route) in registry.routes() {
            if route.server == server.name {
                upstream = upstream.tool(tool.clone(), route.upstream_name.clone());
            }
        }
        let deadline = upstream.deadline;
        let connector = ProxyConnector::new(upstream, credentials.clone())?;
        wiring = wiring
            .proxied(server.name.clone(), Arc::new(connector))
            .call_deadline(server.name.clone(), deadline);
    }

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
    };
    let revision = registry.snapshot().revision().clone();
    let tools = registry.routes().len();
    let servers = registry.servers().len();
    let (gates, reloader) = boot::check_registry(settings, registry, wiring)?;
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
    tracing::info!(
        event = "boot",
        %instance,
        "audit rows record this instance as the one that began them"
    );
    tracing::info!(
        event = "boot",
        registry = %deployment.registry_file.display(),
        %revision,
        tools,
        servers,
        poll_seconds = deployment.poll.as_secs(),
        "serving the registry file's policy"
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
    })
}

/// An issuer's key source, with how often to fetch again and how many keys its first fetch
/// returned.
struct Fetched {
    source: KeySource,
    refresh: Duration,
    count: usize,
}

/// Checks every keys URL, then fetches each issuer's keys once and puts them in its entry in
/// `identity`. Refuses a URL the key source refuses, an `https` one by name, and a fetch that
/// fails.
async fn fetch_keys(
    keys_urls: &[KeysUrl],
    identity: &mut IdentitySection,
) -> Result<Vec<Fetched>, StartError> {
    let mut sources = Vec::with_capacity(keys_urls.len());
    for keys_url in keys_urls {
        let source = KeySource::new(&keys_url.issuer, &keys_url.url, FetchOptions::default())
            .map_err(|error| match error {
                SourceError::TlsUnavailable(issuer) => StartError::KeysOverTls(issuer),
                other => StartError::KeysUrl(other),
            })?;
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
        let Credential::Bearer { reference } = &server.credential;
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
