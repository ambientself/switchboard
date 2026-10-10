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
//! 4. **Policy** becomes a snapshot through the core's own checks, and passes the
//!    receipt-store gate (decision 0009): until receipts exist, a tool not classified `read`
//!    is served only by a development build, one with the `test-support` feature.
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
//! and rules. Its connectors are registered with [`Wiring::proxied`]: each call to one runs
//! behind the registry's argument check, and its resources are read with the adapter the
//! registry approved for its tool, both from the policy version the call's request took.
//! Every approved tool's server must have a connector. The receipt-store gate runs there too,
//! at boot and on every reload.
//!
//! A disabled gate starts with a warning logged here; the HTTP layer repeats it while the
//! gateway runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use connector_proxy::DEFAULT_DEADLINE;
use gateway_core::{
    AuditStore, Classification, Connector, ConnectorName, DeploymentName, InstanceName, Issuer,
    PolicySnapshot, ProfileName, SnapshotError, ToolName,
};
use gateway_identity::{Clock, ConfigError, Identity, IdentityConfig};
use gateway_registry::{Registry, RulePrincipal};
use thiserror::Error;

use crate::audit::DisabledAuditStore;
use crate::catalog::{CatalogError, ToolCatalog};
use crate::config::{AuditSection, Config, HttpSection, IdentitySection};
use crate::policy::{LivePolicy, ServedPolicy};
use crate::reload::Reloader;
use crate::resources::ResourceAdapter;
use crate::selector::{NO_PROFILE, ProfileSelector, SelectorError, SelectorRules};

/// The call deadline of a connector registered with [`Wiring::connector`], which runs in the
/// gateway's own process. It only feeds the allowance each audit row's deadline is set from:
/// nothing stops such a connector at it yet (milestone 3).
pub const DEFAULT_CALL_DEADLINE: Duration = Duration::from_secs(5);

/// The instance [`Wiring::new`] names until [`Wiring::instance`] is called. The `switchboard`
/// binary always names one, from its environment, and refuses to start without one
/// ([`crate::start::instance`]).
pub const UNNAMED_INSTANCE: &str = "unnamed";

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
    /// A tool not classified `read` is on a surface, and there is no receipt store to make its
    /// calls safe to answer after a lost outcome (decision 0009). Only a development build,
    /// one with the `test-support` feature, serves such a tool.
    #[error(
        "tool `{tool}` is classified `{classification}` and served on a surface, but no receipt \
         store is configured: until receipts exist only tools classified `read` may be served \
         (decision 0009)"
    )]
    NoReceiptStore {
        /// The tool.
        tool: ToolName,
        /// Its classification.
        classification: Classification,
    },
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

/// What code supplies to the gateway, beside its configuration: the clock, the instance, the
/// audit store, and each connector with its resource adapter.
pub struct Wiring {
    clock: Arc<dyn Clock>,
    instance: InstanceName,
    audit_store: Option<Arc<dyn AuditStore>>,
    connectors: Vec<(ConnectorName, Registered)>,
    proxied: Vec<(ConnectorName, Arc<dyn Connector>)>,
    call_deadlines: BTreeMap<ConnectorName, Duration>,
}

impl Wiring {
    /// Wiring with `clock`, the instance [`UNNAMED_INSTANCE`], no audit store and no
    /// connectors.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            instance: InstanceName::new(UNNAMED_INSTANCE),
            audit_store: None,
            connectors: Vec::new(),
            proxied: Vec::new(),
            call_deadlines: BTreeMap::new(),
        }
    }

    /// Names the gateway instance, which every audit row records as the one that began it.
    pub fn instance(mut self, instance: InstanceName) -> Self {
        self.instance = instance;
        self
    }

    /// Gives the connector registered as `name` the call deadline it runs under, which each of
    /// its rows' deadlines includes: for a proxied server, the deadline its connector was built
    /// with. A proxied server not given one has the proxy's [`DEFAULT_DEADLINE`], and a
    /// connector registered with [`connector`](Self::connector) has [`DEFAULT_CALL_DEADLINE`].
    /// A deadline for a name nothing is registered under is ignored.
    pub fn call_deadline(mut self, name: impl Into<ConnectorName>, deadline: Duration) -> Self {
        self.call_deadlines.insert(name.into(), deadline);
        self
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
                reads: Reads::Adapter(resources),
                results: Results::Values,
                call_deadline: DEFAULT_CALL_DEADLINE,
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
            .field("instance", &self.instance)
            .field("audit_store", &self.audit_store.is_some())
            .field("connectors", &connectors)
            .field("proxied", &proxied)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Registered {
    pub(crate) connector: Arc<dyn Connector>,
    pub(crate) reads: Reads,
    pub(crate) results: Results,
    /// How long a call may run, which each row's deadline includes.
    pub(crate) call_deadline: Duration,
}

/// How a connector's calls are read.
pub(crate) enum Reads {
    /// With the resource adapter registered beside the connector.
    Adapter(Arc<dyn ResourceAdapter>),
    /// With the registry's argument adapters, from the policy version each request took: its
    /// resources for the decision, and its argument check around the run
    /// ([`crate::proxied::CheckedArguments`]). The connector never runs without that check.
    Registry,
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
    instance: InstanceName,
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
/// built for. And whether this build is exempt from the receipt-store gate, which only a
/// development build is.
pub(crate) struct Basis {
    pub(crate) issuers: Option<Issuers>,
    pub(crate) registry: Registry,
    pub(crate) connectors: BTreeSet<ConnectorName>,
    pub(crate) receipt_exempt: bool,
}

impl fmt::Debug for Gates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gates")
            .field("deployment", &self.deployment)
            .field("instance", &self.instance)
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

    /// The gateway instance, which every audit row records.
    pub fn instance(&self) -> &InstanceName {
        &self.instance
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

    /// The connector registered as `name` with its own resource adapter. A proxied server's
    /// connector is not handed out: it runs only behind the argument check of the policy
    /// version a request took.
    pub fn connector(&self, name: &ConnectorName) -> Option<&Arc<dyn Connector>> {
        self.connectors
            .get(name)
            .filter(|registered| matches!(registered.reads, Reads::Adapter(_)))
            .map(|registered| &registered.connector)
    }

    /// The resource adapter registered with the connector `name`. A proxied server's tools
    /// are read with the registry's adapters instead.
    pub fn resource_adapter(&self, name: &ConnectorName) -> Option<&Arc<dyn ResourceAdapter>> {
        match &self.connectors.get(name)?.reads {
            Reads::Adapter(adapter) => Some(adapter),
            Reads::Registry => None,
        }
    }

    /// What is registered as `name`: the connector, how its calls are read, and its results.
    pub(crate) fn registered(&self, name: &ConnectorName) -> Option<&Registered> {
        self.connectors.get(name)
    }

    /// The policy served now, which the argument check reads to see whether a tool was
    /// withdrawn while a call was being decided.
    pub(crate) fn live_policy(&self) -> &LivePolicy {
        &self.policy
    }

    /// These gates with the connector `name` unregistered, while the policy still serves its
    /// tools: what the boot gates and every reload refuse, for the path's test of it.
    #[cfg(test)]
    pub(crate) fn without_connector(mut self, name: &ConnectorName) -> Self {
        self.connectors.remove(name);
        self
    }
}

/// Runs every boot gate, in the order the [module documentation](self) gives.
pub fn check(config: Config, wiring: Wiring) -> Result<Gates, BootError> {
    check_with(config, wiring, cfg!(feature = "test-support"))
}

/// [`check`], with the receipt-store gate's exemption given, so a test in a development build
/// can run the gate as the release build does.
fn check_with(config: Config, wiring: Wiring, receipt_exempt: bool) -> Result<Gates, BootError> {
    let Wiring {
        clock,
        instance,
        audit_store,
        connectors: registrations,
        proxied,
        call_deadlines,
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
    receipt_gate(&snapshot, receipt_exempt)?;

    let catalog = ToolCatalog::new(config.catalog)?;
    catalog.check(&approved)?;

    let mut connectors = BTreeMap::new();
    for (name, mut registered) in registrations {
        if let Some(deadline) = call_deadlines.get(&name) {
            registered.call_deadline = *deadline;
        }
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
        instance,
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
        instance,
        audit_store,
        connectors: registrations,
        proxied,
        call_deadlines,
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
            connector,
            reads: Reads::Registry,
            results: Results::ToolResults,
            call_deadline: call_deadlines
                .get(&name)
                .copied()
                .unwrap_or(DEFAULT_DEADLINE),
        };
        if connectors.insert(name.clone(), registered).is_some() {
            return Err(BootError::DuplicateConnector(name));
        }
    }
    let basis = Basis {
        issuers,
        registry,
        connectors: connectors.keys().cloned().collect(),
        receipt_exempt: cfg!(feature = "test-support"),
    };
    check_registry_policy(&basis.registry, &live.current(), &basis)?;

    warn_disabled(&settings.deployment, identity_state, audit_state);
    let reloader = Reloader::new(live.clone(), basis);
    let gates = Gates {
        deployment: settings.deployment,
        instance,
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

/// The gates a registry's policy must pass, at boot and on every reload: the
/// [receipt-store gate](receipt_gate); every approved tool's server has a connector; with
/// identity enforced, every rule names a configured issuer of its kind; the snapshot does not
/// define [`NO_PROFILE`]; and every profile a rule names exists.
pub(crate) fn check_registry_policy(
    registry: &Registry,
    policy: &ServedPolicy,
    basis: &Basis,
) -> Result<(), BootError> {
    receipt_gate(policy.snapshot(), basis.receipt_exempt)?;
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

/// The receipt-store gate (decision 0009, "Until receipts exist"; design section 12). A
/// snapshot that serves a tool not classified `read` (on any surface) is refused unless a
/// receipt store is configured, which none can be yet. A tool approved but on no surface is
/// not served, and passes. It runs at boot and at every snapshot swap, whatever the snapshot's
/// source, and no policy setting changes it.
///
/// `exempt` is true only in a development build, one with the `test-support` feature, which
/// the release build never enables: the callers pass `cfg!(feature = "test-support")`.
pub(crate) fn receipt_gate(snapshot: &PolicySnapshot, exempt: bool) -> Result<(), BootError> {
    if exempt || receipt_store_configured() {
        return Ok(());
    }
    for surface in snapshot.surfaces() {
        for tool in surface.tools.iter().filter_map(|name| snapshot.tool(name)) {
            if tool.classification != Classification::Read {
                return Err(BootError::NoReceiptStore {
                    tool: tool.name.clone(),
                    classification: tool.classification,
                });
            }
        }
    }
    Ok(())
}

/// Whether a receipt store is configured. None exists yet: receipts are #10 stage 2. That
/// change makes this true only when a receipt store is configured, audit is on and identity is
/// on, as decision 0009 requires, and passes it what it needs to tell.
fn receipt_store_configured() -> bool {
    false
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

#[cfg(test)]
pub(crate) mod tests {
    //! The receipt-store gate as a release build runs it. These tests are in a development
    //! build, which is exempt, so each passes the exemption itself.
    #![allow(clippy::unwrap_used)]

    use gateway_identity::SystemClock;
    use serde_json::json;

    use super::*;

    /// A registry file with one server and one tool of `classification`, on the `docs` surface
    /// when `on_surface`, at `revision`.
    pub(crate) fn registry_text(classification: &str, on_surface: bool, revision: &str) -> String {
        let sha = gateway_registry::definition_sha256(
            "list_documents",
            None,
            "Lists the documents.",
            &json!({"type": "object"}),
        );
        let served = if on_surface {
            "\"docs__list_documents\""
        } else {
            ""
        };
        format!(
            r#"revision = "{revision}"
profiles = []
profile_rules = []

[[servers]]
name = "mock-docs"
system = "docs"
owner = "platform"
identity = "mock-docs"
address = "http://127.0.0.1:9/mcp"
credential = {{ mode = "bearer", reference = "docs-credential" }}

[[tools]]
name = "docs__list_documents"
server = "mock-docs"
upstream_name = "list_documents"
classification = "{classification}"
description = "Lists the documents."
approved_by = "approver@example.test"
approved_at = 2026-10-06T00:00:00Z
definition_sha256 = "{sha}"
resources = "no_resources"

[tools.input_schema]
type = "object"

[[surfaces]]
name = "docs"
tools = [{served}]
teams = ["team-a"]
principals = "any_in_teams_and_groups"

[limits]
"#
        )
    }

    pub(crate) fn registry(classification: &str, on_surface: bool) -> Registry {
        Registry::from_toml_str(&registry_text(classification, on_surface, "r1")).unwrap()
    }

    /// What a release build of `registry` starts with: no issuers, its one server connected,
    /// and no exemption from the receipt-store gate.
    pub(crate) fn release_basis(registry: Registry) -> Basis {
        Basis {
            issuers: None,
            connectors: registry.servers().keys().cloned().collect(),
            registry,
            receipt_exempt: false,
        }
    }

    fn refused_as(result: Result<(), BootError>, classification: Classification) {
        match result {
            Err(BootError::NoReceiptStore {
                tool,
                classification: refused,
            }) => {
                assert_eq!(tool.as_str(), "docs__list_documents");
                assert_eq!(refused, classification);
            }
            other => panic!("expected the receipt-store refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_read_only_snapshot_passes_the_receipt_gate() {
        assert!(receipt_gate(registry("read", true).snapshot(), false).is_ok());
    }

    #[test]
    fn a_served_propose_tool_is_refused_without_a_receipt_store() {
        refused_as(
            receipt_gate(registry("propose", true).snapshot(), false),
            Classification::Propose,
        );
    }

    #[test]
    fn a_served_write_tool_is_refused_without_a_receipt_store() {
        refused_as(
            receipt_gate(registry("write", true).snapshot(), false),
            Classification::Write,
        );
    }

    #[test]
    fn a_tool_not_classified_read_but_on_no_surface_is_not_served_and_passes() {
        for classification in ["propose", "write", "destructive"] {
            let registry = registry(classification, false);
            assert!(
                receipt_gate(registry.snapshot(), false).is_ok(),
                "{classification}"
            );
        }
    }

    #[test]
    fn only_a_development_build_is_exempt() {
        assert!(receipt_gate(registry("propose", true).snapshot(), true).is_ok());
    }

    #[test]
    fn the_refusal_names_the_tool_its_classification_and_the_reason() {
        let error = receipt_gate(registry("propose", true).snapshot(), false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("`docs__list_documents`"), "{message}");
        assert!(message.contains("classified `propose`"), "{message}");
        assert!(
            message.contains("no receipt store is configured"),
            "{message}"
        );
    }

    #[test]
    fn the_json_configuration_path_runs_the_receipt_gate() {
        let config = Config::from_json(
            &json!({
                "deployment": "receipt-gate",
                "identity": {"disabled": true},
                "audit": {"disabled": true},
                "http": {"allowed_hosts": ["localhost"]},
                "policy": {
                    "revision": "r1",
                    "tools": [{
                        "name": "docs__list_documents",
                        "classification": "propose",
                        "connector": "mock-docs",
                        "resources": "no_resources"
                    }],
                    "surfaces": [{
                        "name": "docs",
                        "tools": ["docs__list_documents"],
                        "teams": ["team-a"],
                        "principals": "any_in_teams_and_groups"
                    }],
                    "profiles": []
                },
                "catalog": [{
                    "name": "docs__list_documents",
                    "description": "Lists the documents.",
                    "input_schema": {"type": "object"}
                }],
                "profiles": {}
            })
            .to_string(),
        )
        .unwrap();
        let refused = check_with(config, Wiring::new(Arc::new(SystemClock)), false);
        assert!(
            matches!(refused, Err(BootError::NoReceiptStore { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn the_registry_path_runs_the_receipt_gate_at_boot_and_on_every_reload() {
        for (classification, refused) in [("read", false), ("propose", true), ("write", true)] {
            let registry = registry(classification, true);
            let policy = ServedPolicy::from_registry(&registry).unwrap();
            let checked =
                check_registry_policy(&registry, &policy, &release_basis(registry.clone()));
            assert_eq!(
                matches!(checked, Err(BootError::NoReceiptStore { .. })),
                refused,
                "{classification}: {checked:?}"
            );
        }
    }
}
