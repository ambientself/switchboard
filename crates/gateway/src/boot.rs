//! The boot gates, design section 12: everything checked before a socket is bound.
//!
//! [`check`] takes the configuration and the [`Wiring`] and returns [`Gates`], or the first
//! reason the gateway must not start. In order:
//!
//! 1. **Identity** is enforced against configured issuers, or explicitly disabled. Neither, or
//!    both, is refused, and so is an issuer the identity crate refuses.
//! 2. **Audit** has a store supplied by the wiring, or is explicitly disabled. Neither, or
//!    both, is refused.
//! 3. **HTTP** names at least one allowed host.
//! 4. **Policy** becomes a snapshot through the core's own checks.
//! 5. **Tool definitions**: every approved tool has exactly one, and every one is for an
//!    approved tool.
//! 6. **Connectors**: none is registered twice, and every tool on a surface has its connector
//!    registered. A connector and its resource adapter are registered together, so neither
//!    can be configured without the other.
//! 7. **Profile selection**: with identity enforced, every rule's issuer is a configured issuer
//!    of the rule's kind; no two rules share a key; the snapshot does not hold [`NO_PROFILE`];
//!    and every profile a rule names exists.
//!
//! A disabled gate starts with a warning logged here; the HTTP layer repeats it while the
//! gateway runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gateway_core::{
    AuditStore, Connector, ConnectorName, DeploymentName, Issuer, PolicySnapshot, ProfileName,
    SnapshotError, ToolName,
};
use gateway_identity::{Clock, ConfigError, Identity, IdentityConfig};
use thiserror::Error;

use crate::audit::DisabledAuditStore;
use crate::catalog::{CatalogError, ToolCatalog};
use crate::config::{AuditSection, Config, HttpSection, IdentitySection};
use crate::resources::ResourceAdapter;
use crate::selector::{NO_PROFILE, ProfileSelector, SelectorError, SelectorRules};

/// Whether a gate is on, or explicitly turned off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GateState {
    /// Identity: callers must prove themselves. Audit: every call is recorded.
    On,
    /// Turned off by an explicit opt-out in configuration.
    Disabled,
}

/// Why the gateway refused to start.
#[derive(Debug, Error)]
pub enum BootError {
    /// Identity is neither enforced nor disabled.
    #[error(
        "identity is not configured: set `identity.enforce` to the trusted issuers, or \
         `identity.disabled` to true to run without checking callers"
    )]
    IdentityUnconfigured,
    /// Identity is both enforced and disabled.
    #[error("identity is both enforced and disabled; choose one")]
    IdentityContradiction,
    /// An issuer's keys are not a JWK set.
    #[error("issuer `{issuer}` has keys that are not a JWK set: {error}")]
    IssuerKeys {
        /// The issuer.
        issuer: Issuer,
        /// What the JWK parser said.
        error: serde_json::Error,
    },
    /// The identity crate refused the issuers.
    #[error(transparent)]
    Identity(#[from] ConfigError),
    /// No audit store is supplied and audit is not disabled.
    #[error(
        "audit is not configured: supply an audit store, or set `audit.disabled` to true to \
         run without recording calls"
    )]
    AuditUnconfigured,
    /// An audit store is supplied and audit is also disabled.
    #[error("an audit store is supplied but `audit.disabled` is true; choose one")]
    AuditContradiction,
    /// No host is allowed, so every request would be refused.
    #[error("`http.allowed_hosts` is empty")]
    NoAllowedHosts,
    /// The policy data was refused by the core.
    #[error(transparent)]
    Policy(#[from] SnapshotError),
    /// The tool definitions were refused.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// Two connectors were registered under one name.
    #[error("connector `{0}` is registered more than once")]
    DuplicateConnector(ConnectorName),
    /// A tool on a surface whose connector is not registered.
    #[error("tool `{tool}` is served but its connector `{connector}` is not registered")]
    UnregisteredConnector {
        /// The tool.
        tool: ToolName,
        /// The connector it names.
        connector: ConnectorName,
    },
    /// The profile rules were refused.
    #[error(transparent)]
    Selector(#[from] SelectorError),
    /// A profile rule names a profile the snapshot does not hold.
    #[error("a profile rule selects `{0}`, which the policy does not define")]
    UnknownProfile(ProfileName),
    /// The snapshot defines the profile given to callers no rule selects.
    #[error("the policy defines a profile named `{NO_PROFILE}`, which is reserved")]
    ReservedProfile,
    /// With identity enforced, a profile rule names an issuer that is not configured as an
    /// issuer of that kind, so the rule could never match.
    #[error(
        "a {kind} profile rule names issuer `{issuer}`, which is not a configured {kind} issuer"
    )]
    RuleIssuerNotConfigured {
        /// `workload` or `user`.
        kind: &'static str,
        /// The issuer the rule names.
        issuer: Issuer,
    },
}

/// What code supplies to the gateway, beside its configuration: the clock, the audit store, and
/// each connector with its resource adapter.
pub struct Wiring {
    clock: Arc<dyn Clock>,
    audit_store: Option<Arc<dyn AuditStore>>,
    connectors: Vec<(ConnectorName, Registered)>,
}

impl Wiring {
    /// Wiring with `clock`, no audit store and no connectors.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            audit_store: None,
            connectors: Vec::new(),
        }
    }

    /// Records every call in `store`. Configuration must not also disable audit.
    pub fn audit_store(mut self, store: Arc<dyn AuditStore>) -> Self {
        self.audit_store = Some(store);
        self
    }

    /// Registers the connector named `name` with the adapter that reads its tools' arguments.
    pub fn connector(
        mut self,
        name: impl Into<ConnectorName>,
        connector: Arc<dyn Connector>,
        resources: Arc<dyn ResourceAdapter>,
    ) -> Self {
        self.connectors.push((
            name.into(),
            Registered {
                connector,
                resources,
            },
        ));
        self
    }
}

impl fmt::Debug for Wiring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let connectors: Vec<&ConnectorName> =
            self.connectors.iter().map(|(name, _)| name).collect();
        f.debug_struct("Wiring")
            .field("audit_store", &self.audit_store.is_some())
            .field("connectors", &connectors)
            .finish_non_exhaustive()
    }
}

struct Registered {
    connector: Arc<dyn Connector>,
    resources: Arc<dyn ResourceAdapter>,
}

/// A configuration that passed every boot gate, with what serving it needs.
///
/// Its fields are private and [`check`] is the only way to make one, so holding a `Gates` means
/// the checks passed. The HTTP server takes one, so it cannot bind a socket for a configuration
/// that was refused.
pub struct Gates {
    deployment: DeploymentName,
    clock: Arc<dyn Clock>,
    identity: Identity,
    identity_state: GateState,
    audit_store: Arc<dyn AuditStore>,
    audit_state: GateState,
    http: HttpSection,
    snapshot: Arc<PolicySnapshot>,
    catalog: ToolCatalog,
    selector: ProfileSelector,
    connectors: BTreeMap<ConnectorName, Registered>,
}

impl fmt::Debug for Gates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gates")
            .field("deployment", &self.deployment)
            .field("identity_state", &self.identity_state)
            .field("audit_state", &self.audit_state)
            .field("revision", self.snapshot.revision())
            .field("connectors", &self.connectors.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Gates {
    /// The deployment's name.
    pub fn deployment(&self) -> &DeploymentName {
        &self.deployment
    }

    /// The clock calls are timed with.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The identity gate.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether identity is enforced or disabled.
    pub fn identity_state(&self) -> GateState {
        self.identity_state
    }

    /// The audit store: the one the wiring supplied, or a [`DisabledAuditStore`].
    pub fn audit_store(&self) -> &Arc<dyn AuditStore> {
        &self.audit_store
    }

    /// Whether audit is on or disabled.
    pub fn audit_state(&self) -> GateState {
        self.audit_state
    }

    /// The `Host` values served.
    pub fn allowed_hosts(&self) -> &BTreeSet<String> {
        &self.http.allowed_hosts
    }

    /// The `Origin` values served.
    pub fn allowed_origins(&self) -> &BTreeSet<String> {
        &self.http.allowed_origins
    }

    /// The policy snapshot.
    pub fn snapshot(&self) -> &Arc<PolicySnapshot> {
        &self.snapshot
    }

    /// Every approved tool's definition.
    pub fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    /// The profile selector.
    pub fn selector(&self) -> &ProfileSelector {
        &self.selector
    }

    /// The connector registered as `name`.
    pub fn connector(&self, name: &ConnectorName) -> Option<&Arc<dyn Connector>> {
        self.connectors
            .get(name)
            .map(|registered| &registered.connector)
    }

    /// The resource adapter registered with the connector `name`.
    pub fn resource_adapter(&self, name: &ConnectorName) -> Option<&Arc<dyn ResourceAdapter>> {
        self.connectors
            .get(name)
            .map(|registered| &registered.resources)
    }
}

/// Runs every boot gate, in the order the [module documentation](self) gives.
pub fn check(config: Config, wiring: Wiring) -> Result<Gates, BootError> {
    let Wiring {
        clock,
        audit_store,
        connectors: registrations,
    } = wiring;
    let issuers = configured_issuers(&config.identity);
    let (identity, identity_state) = identity_gate(config.identity, clock.clone())?;
    let (audit_store, audit_state) = audit_gate(&config.audit, audit_store)?;
    if config.http.allowed_hosts.is_empty() {
        return Err(BootError::NoAllowedHosts);
    }

    let approved: Vec<ToolName> = config
        .policy
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect();
    let served: BTreeSet<ToolName> = config
        .policy
        .surfaces
        .iter()
        .flat_map(|surface| surface.tools.iter().cloned())
        .collect();
    let snapshot = PolicySnapshot::new(config.policy)?;

    let catalog = ToolCatalog::new(config.catalog)?;
    catalog.check(&approved)?;

    let mut connectors = BTreeMap::new();
    for (name, registered) in registrations {
        if connectors.insert(name.clone(), registered).is_some() {
            return Err(BootError::DuplicateConnector(name));
        }
    }
    for tool in served.iter().filter_map(|name| snapshot.tool(name)) {
        if !connectors.contains_key(&tool.connector) {
            return Err(BootError::UnregisteredConnector {
                tool: tool.name.clone(),
                connector: tool.connector.clone(),
            });
        }
    }

    if let Some(issuers) = &issuers {
        rules_name_configured_issuers(&config.profiles, issuers)?;
    }
    let selector = ProfileSelector::new(config.profiles)?;
    if snapshot.profile(&ProfileName::new(NO_PROFILE)).is_some() {
        return Err(BootError::ReservedProfile);
    }
    if let Some(unknown) = selector
        .profiles()
        .into_iter()
        .find(|profile| snapshot.profile(profile).is_none())
    {
        return Err(BootError::UnknownProfile(unknown.clone()));
    }

    if identity_state == GateState::Disabled {
        tracing::warn!(
            deployment = %config.deployment,
            "identity is disabled: callers are not verified, no tools are listed and every call \
             is refused"
        );
    }
    if audit_state == GateState::Disabled {
        tracing::warn!(
            deployment = %config.deployment,
            "audit is disabled: calls are allowed and run with no record of them"
        );
    }
    Ok(Gates {
        deployment: config.deployment,
        clock,
        identity,
        identity_state,
        audit_store,
        audit_state,
        http: config.http,
        snapshot: Arc::new(snapshot),
        catalog,
        selector,
        connectors,
    })
}

fn identity_gate(
    section: IdentitySection,
    clock: Arc<dyn Clock>,
) -> Result<(Identity, GateState), BootError> {
    let (config, state) = match (section.enforce, section.disabled) {
        (Some(entries), false) => {
            let mut issuers = Vec::with_capacity(entries.len());
            for entry in entries {
                let issuer = entry.issuer.clone();
                let config = entry
                    .into_config()
                    .map_err(|error| BootError::IssuerKeys { issuer, error })?;
                issuers.push(config);
            }
            (IdentityConfig::Enforce(issuers), GateState::On)
        }
        (None, true) => (IdentityConfig::Disabled, GateState::Disabled),
        (None, false) => return Err(BootError::IdentityUnconfigured),
        (Some(_), true) => return Err(BootError::IdentityContradiction),
    };
    Ok((Identity::new(config, clock)?, state))
}

fn audit_gate(
    section: &AuditSection,
    store: Option<Arc<dyn AuditStore>>,
) -> Result<(Arc<dyn AuditStore>, GateState), BootError> {
    match (store, section.disabled) {
        (Some(store), false) => Ok((store, GateState::On)),
        (None, true) => Ok((Arc::new(DisabledAuditStore::new()), GateState::Disabled)),
        (None, false) => Err(BootError::AuditUnconfigured),
        (Some(_), true) => Err(BootError::AuditContradiction),
    }
}

/// The configured workload and user issuers, or `None` when identity is not enforced.
struct Issuers {
    workloads: BTreeSet<Issuer>,
    users: BTreeSet<Issuer>,
}

fn configured_issuers(section: &IdentitySection) -> Option<Issuers> {
    let entries = section.enforce.as_ref()?;
    let (workloads, users): (Vec<_>, Vec<_>) =
        entries.iter().partition(|entry| entry.is_workload());
    Some(Issuers {
        workloads: workloads
            .into_iter()
            .map(|entry| entry.issuer.clone())
            .collect(),
        users: users
            .into_iter()
            .map(|entry| entry.issuer.clone())
            .collect(),
    })
}

fn rules_name_configured_issuers(
    rules: &SelectorRules,
    issuers: &Issuers,
) -> Result<(), BootError> {
    let unconfigured = |kind, issuer: &Issuer| BootError::RuleIssuerNotConfigured {
        kind,
        issuer: issuer.clone(),
    };
    if let Some(rule) = rules
        .workloads
        .iter()
        .find(|rule| !issuers.workloads.contains(&rule.issuer))
    {
        return Err(unconfigured("workload", &rule.issuer));
    }
    if let Some(rule) = rules
        .users
        .iter()
        .find(|rule| !issuers.users.contains(&rule.issuer))
    {
        return Err(unconfigured("user", &rule.issuer));
    }
    Ok(())
}
