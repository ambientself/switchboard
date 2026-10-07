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
//! [`check_registry`] runs the same gates for a deployment whose policy comes from the registry
//! file (`gateway-registry`), which has already checked its own tools, definitions, adapters
//! and rules. Its connectors are registered with [`Wiring::proxied`]: each one is wrapped in
//! the registry's argument check, and its resource adapter is the one the registry approved
//! for each tool. Every approved tool's server must have a connector.
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
use gateway_registry::{Registry, RulePrincipal};
use thiserror::Error;

use crate::audit::DisabledAuditStore;
use crate::catalog::{CatalogError, ToolCatalog};
use crate::config::{AuditSection, Config, HttpSection, IdentitySection};
use crate::policy::{LivePolicy, ServedPolicy};
use crate::proxied::{CheckedArguments, RegistryResources};
use crate::reload::Reloader;
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
    /// A connector registered with [`Wiring::proxied`] in a deployment whose policy is not the
    /// registry's, so nothing would read its tools' arguments.
    #[error(
        "connector `{0}` is registered as a proxied server, which needs the policy to come from \
         the registry"
    )]
    ProxiedWithoutRegistry(ConnectorName),
    /// A connector registered with its own resource adapter in a deployment whose policy is the
    /// registry's, where every tool's adapter comes from the registry.
    #[error(
        "connector `{0}` is registered with its own resource adapter, but this deployment's \
         tools read their resources as the registry says"
    )]
    AdapterBesideRegistry(ConnectorName),
}

/// The parts of a deployment's configuration that are not its policy, for [`check_registry`].
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// The deployment's name, recorded on every audit row.
    pub deployment: DeploymentName,
    /// Whether and how callers are verified.
    pub identity: IdentitySection,
    /// Whether audit is explicitly disabled.
    pub audit: AuditSection,
    /// What the HTTP endpoint accepts.
    pub http: HttpSection,
}

/// What code supplies to the gateway, beside its configuration: the clock, the audit store, and
/// each connector with its resource adapter.
pub struct Wiring {
    clock: Arc<dyn Clock>,
    audit_store: Option<Arc<dyn AuditStore>>,
    connectors: Vec<(ConnectorName, Registered)>,
    proxied: Vec<(ConnectorName, Arc<dyn Connector>)>,
}

impl Wiring {
    /// Wiring with `clock`, no audit store and no connectors.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            audit_store: None,
            connectors: Vec::new(),
            proxied: Vec::new(),
        }
    }

    /// Registers the connector for the registry's server `name`. [`check_registry`] wraps it
    /// in the registry's argument check, and reads its tools' resources with the adapters the
    /// registry approved; [`check`] refuses it.
    pub fn proxied(
        mut self,
        name: impl Into<ConnectorName>,
        connector: Arc<dyn Connector>,
    ) -> Self {
        self.proxied.push((name.into(), connector));
        self
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
                results: Results::Values,
            },
        ));
        self
    }
}

impl fmt::Debug for Wiring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let connectors: Vec<&ConnectorName> =
            self.connectors.iter().map(|(name, _)| name).collect();
        let proxied: Vec<&ConnectorName> = self.proxied.iter().map(|(name, _)| name).collect();
        f.debug_struct("Wiring")
            .field("audit_store", &self.audit_store.is_some())
            .field("connectors", &connectors)
            .field("proxied", &proxied)
            .finish_non_exhaustive()
    }
}

struct Registered {
    connector: Arc<dyn Connector>,
    resources: Arc<dyn ResourceAdapter>,
    results: Results,
}

/// What a connector's successful result is, which decides how it reaches the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Results {
    /// Any JSON value. The caller gets it as text holding the JSON, and as structured content.
    Values,
    /// A proxied MCP server's tool result. The caller gets its content and structured content
    /// as the server sent them.
    ToolResults,
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
    policy: Arc<LivePolicy>,
    connectors: BTreeMap<ConnectorName, Registered>,
}

/// What the gateway was started with that a policy reload cannot change: the issuers, which
/// profile rules must name, and the registry's servers and routes, which the connectors were
/// built for.
pub(crate) struct Basis {
    pub(crate) issuers: Option<Issuers>,
    pub(crate) registry: Registry,
    pub(crate) connectors: BTreeSet<ConnectorName>,
}

impl fmt::Debug for Gates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gates")
            .field("deployment", &self.deployment)
            .field("identity_state", &self.identity_state)
            .field("audit_state", &self.audit_state)
            .field("revision", self.policy.current().revision())
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

    /// The policy served now: its snapshot, definitions and profile rules, taken together.
    pub fn policy(&self) -> Arc<ServedPolicy> {
        self.policy.current()
    }

    /// The policy snapshot served now.
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        self.policy.current().snapshot().clone()
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

    /// What the connector `name`'s successful results are.
    pub(crate) fn results(&self, name: &ConnectorName) -> Option<Results> {
        self.connectors
            .get(name)
            .map(|registered| registered.results)
    }
}

/// Runs every boot gate, in the order the [module documentation](self) gives.
pub fn check(config: Config, wiring: Wiring) -> Result<Gates, BootError> {
    let Wiring {
        clock,
        audit_store,
        connectors: registrations,
        proxied,
    } = wiring;
    if let Some((name, _)) = proxied.into_iter().next() {
        return Err(BootError::ProxiedWithoutRegistry(name));
    }
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

    warn_disabled(&config.deployment, identity_state, audit_state);
    Ok(Gates {
        deployment: config.deployment,
        clock,
        identity,
        identity_state,
        audit_store,
        audit_state,
        http: config.http,
        policy: Arc::new(LivePolicy::new(ServedPolicy::from_config(
            snapshot, catalog, selector,
        ))),
        connectors,
    })
}

/// Runs the boot gates for a deployment whose policy is the registry file's, in the order the
/// [module documentation](self) gives. Returns the gates, and the [`Reloader`] that replaces
/// their policy with a new version of the registry file.
pub fn check_registry(
    settings: Settings,
    registry: Registry,
    wiring: Wiring,
) -> Result<(Gates, Reloader), BootError> {
    let Wiring {
        clock,
        audit_store,
        connectors: registrations,
        proxied,
    } = wiring;
    if let Some((name, _)) = registrations.into_iter().next() {
        return Err(BootError::AdapterBesideRegistry(name));
    }
    let issuers = configured_issuers(&settings.identity);
    let (identity, identity_state) = identity_gate(settings.identity, clock.clone())?;
    let (audit_store, audit_state) = audit_gate(&settings.audit, audit_store)?;
    if settings.http.allowed_hosts.is_empty() {
        return Err(BootError::NoAllowedHosts);
    }

    let served = ServedPolicy::from_registry(&registry)?;
    let live = Arc::new(LivePolicy::new(served));
    let mut connectors = BTreeMap::new();
    for (name, connector) in proxied {
        let registered = Registered {
            connector: Arc::new(CheckedArguments::new(connector, live.clone())),
            resources: Arc::new(RegistryResources::new(live.clone())),
            results: Results::ToolResults,
        };
        if connectors.insert(name.clone(), registered).is_some() {
            return Err(BootError::DuplicateConnector(name));
        }
    }
    let basis = Basis {
        issuers,
        registry,
        connectors: connectors.keys().cloned().collect(),
    };
    check_registry_policy(&basis.registry, &live.current(), &basis)?;

    warn_disabled(&settings.deployment, identity_state, audit_state);
    let reloader = Reloader::new(live.clone(), basis);
    let gates = Gates {
        deployment: settings.deployment,
        clock,
        identity,
        identity_state,
        audit_store,
        audit_state,
        http: settings.http,
        policy: live,
        connectors,
    };
    Ok((gates, reloader))
}

/// The gates a registry's policy must pass, at boot and on every reload: every approved tool's
/// server has a connector; with identity enforced, every rule names a configured issuer of its
/// kind; the snapshot does not define [`NO_PROFILE`]; and every profile a rule names exists.
pub(crate) fn check_registry_policy(
    registry: &Registry,
    policy: &ServedPolicy,
    basis: &Basis,
) -> Result<(), BootError> {
    for (tool, route) in registry.routes() {
        if !basis.connectors.contains(&route.server) {
            return Err(BootError::UnregisteredConnector {
                tool: tool.clone(),
                connector: route.server.clone(),
            });
        }
    }
    if let Some(issuers) = &basis.issuers {
        for rule in registry.profile_rules().rules() {
            let (kind, configured) = match rule.principal {
                RulePrincipal::Workload => ("workload", &issuers.workloads),
                RulePrincipal::UserInGroup(_) => ("user", &issuers.users),
            };
            if !configured.contains(&rule.issuer) {
                return Err(BootError::RuleIssuerNotConfigured {
                    kind,
                    issuer: rule.issuer.clone(),
                });
            }
        }
    }
    if policy
        .snapshot()
        .profile(&ProfileName::new(NO_PROFILE))
        .is_some()
    {
        return Err(BootError::ReservedProfile);
    }
    if let Some(unknown) = policy
        .selected_profiles()
        .into_iter()
        .find(|profile| policy.snapshot().profile(profile).is_none())
    {
        return Err(BootError::UnknownProfile(unknown));
    }
    Ok(())
}

/// Logs a warning for each gate that is turned off.
fn warn_disabled(deployment: &DeploymentName, identity: GateState, audit: GateState) {
    if identity == GateState::Disabled {
        tracing::warn!(
            %deployment,
            "identity is disabled: callers are not verified, no tools are listed and every call \
             is refused"
        );
    }
    if audit == GateState::Disabled {
        tracing::warn!(
            %deployment,
            "audit is disabled: calls are allowed and run with no record of them"
        );
    }
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
#[derive(Clone)]
pub(crate) struct Issuers {
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
