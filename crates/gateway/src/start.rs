//! Building a running gateway from a [`Deployment`]: what the `switchboard` binary does
//! before it binds a socket.
//!
//! [`prepare`] reads the registry file, loads each proxied server's credential, builds a
//! [`ProxyConnector`] per server, connects the Postgres audit store and runs its boot checks
//! (or takes audit as explicitly disabled), and then runs the boot gates
//! ([`boot::check_registry`]). Any failure refuses to start, naming the reason, before
//! anything is served.
//!
//! It logs one `"event":"boot"` line per gate, which an operator (and the demo) reads to see
//! how the gateway was started: identity enforced or disabled, with how many issuers and
//! subjects; audit in Postgres, with the role and its check, or disabled; and the registry's
//! revision.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use audit_postgres::{BootCheckError, PgAuditError, PgAuditStore, PoolSizes};
use connector_proxy::{
    CredentialFileError, FileCredentials, ProxyConnector, Upstream, UpstreamError,
};
use gateway_core::ConnectorName;
use gateway_identity::Clock;
use gateway_registry::{Credential, Registry, RegistryError};
use thiserror::Error;

use crate::boot::{self, BootError, Gates, Settings, Wiring};
use crate::config::{IdentitySection, IssuerKindEntry};
use crate::deployment::{AuditChoice, Deployment};
use crate::reload::Reloader;

/// How long the audit store's boot checks may take, connecting included.
pub const AUDIT_CHECK_BUDGET: Duration = Duration::from_secs(15);

/// Why the gateway refused to start.
#[derive(Debug, Error)]
pub enum StartError {
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
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("gates", &self.gates)
            .field("store", &self.store.is_some())
            .field("watch", &self.watch)
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

/// Builds the gateway `deployment` describes, on `clock`. See the [module
/// documentation](self).
pub async fn prepare(
    deployment: Deployment,
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
    let mut wiring = Wiring::new(clock);
    for server in registry.servers().values() {
        let mut upstream = Upstream::new(server.name.clone(), server.address.clone());
        for (tool, route) in registry.routes() {
            if route.server == server.name {
                upstream = upstream.tool(tool.clone(), route.upstream_name.clone());
            }
        }
        let connector = ProxyConnector::new(upstream, credentials.clone())?;
        wiring = wiring.proxied(server.name.clone(), Arc::new(connector));
    }

    let store = match &deployment.audit {
        AuditChoice::Disabled => None,
        AuditChoice::Postgres { url } => Some(audit_store(url).await?),
    };
    if let Some(store) = &store {
        wiring = wiring.audit_store(store.clone());
    }

    let (issuers, subjects) = identity_counts(&deployment.identity);
    let identity_enforced = !deployment.identity.disabled;
    let settings = Settings {
        deployment: deployment.deployment,
        identity: deployment.identity,
        audit: deployment.audit.section(),
        http: deployment.http,
    };
    let revision = registry.snapshot().revision().clone();
    let tools = registry.routes().len();
    let servers = registry.servers().len();
    let (gates, reloader) = boot::check_registry(settings, registry, wiring)?;

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
    })
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
    let store = PgAuditStore::connect(config, tokio_postgres::NoTls, PoolSizes::default())?;
    match tokio::time::timeout(AUDIT_CHECK_BUDGET, store.check_at_boot()).await {
        Err(_elapsed) => Err(StartError::AuditCheckTimedOut),
        Ok(Err(refused)) => Err(StartError::AuditCheck(refused)),
        Ok(Ok(())) => Ok(Arc::new(store)),
    }
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
