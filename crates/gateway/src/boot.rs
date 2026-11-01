//! The boot gates, design section 12: everything checked before a socket is bound.
//!
//! [`check`] takes the configuration and the [`Wiring`] and returns [`Gates`], or the first
//! reason the gateway must not start. In order:
//!
//! 1. **Identity** is enforced against configured issuers, or explicitly disabled. Neither, or
//!    both, is refused, and so is an issuer the identity crate refuses. Only a development
//!    build, one with the `test-support` feature, may disable it (decision 0014).
//! 2. **Audit** has a store supplied by the wiring, or is explicitly disabled. Neither, or
//!    both, is refused. Only a development build may disable it.
//! 3. **HTTP** names at least one allowed host.
//! 4. **Policy** becomes a snapshot through the core's own checks, and passes the
//!    receipt-store gate (decision 0009, "Until receipts exist"): a tool not classified `read`
//!    is served only when the audit store is the Postgres store, which keeps receipts, audit
//!    is on and identity is on, or by a development build, one with the `test-support`
//!    feature. The JSON configuration cannot name the Postgres store, so on its path only a
//!    development build serves one. It then passes the narrowing gate (decision 0011): a proxied
//!    server's entry narrowed per call or to the caller's limit is refused in every build,
//!    since the gateway sends a server one credential for every call. A built-in entry may be
//!    narrowed: its connector asks for a credential narrowed as it says.
//! 5. **Tool definitions**: every approved tool has exactly one, and every one is for an
//!    approved tool.
//! 6. **Connectors**: none is registered twice, and every tool on a surface has its connector
//!    registered. A connector and its resource adapter are registered together, so neither
//!    can be configured without the other. Each such connector runs in the gateway's own
//!    process, and is wrapped in its [`Bounded`]: a deadline, a result size bound and the rate
//!    quotas ([`crate::bound`]). A bound of zero, or past decision 0014's ceilings, is refused.
//! 7. **Profile selection**: with identity enforced, every rule's issuer is a configured issuer
//!    of the rule's kind; no two rules share a key; the snapshot does not hold [`NO_PROFILE`];
//!    and every profile a rule names exists.
//!
//! [`check_registry`] runs the same gates for a deployment whose policy comes from the registry
//! file (`gateway-registry`), which has already checked its own tools, definitions, adapters
//! and rules. Its connectors are registered with [`Wiring::proxied`]: each call to one runs
//! behind the registry's argument check, and its resources are read with the adapter the
//! registry approved for its tool, both from the policy version the call's request took.
//! Every approved tool's server must have a connector. The receipt-store gate and the narrowing
//! gate run there too, at boot and on every reload.
//!
//! A built-in connector, gateway code in the gateway's own process such as the GitHub
//! connector, is registered there with [`Wiring::built_in`], under the name of a built-in
//! connector entry of the registry, `[[connectors]]`, with the definition of each tool it
//! serves. Its calls are read as a proxied server's are, by the registry's argument adapters
//! and behind its argument check, and it is wrapped in its [`Bounded`], as every connector in
//! the gateway's own process is: the deadline and result bound
//! [`Wiring::in_process_limits`] gives it, and the rate quotas [`Wiring::quotas`] gives. Every
//! approved built-in tool's entry must have its connector registered, and its approved
//! definition must be the one the connector serves, at boot and on every reload.
//!
//! A disabled gate starts, in a development build, with a warning logged here; the HTTP layer
//! repeats it while the gateway runs. The release build refuses both opt-outs.
//! [`start::prepare`](crate::start::prepare) runs the opt-out refusals, the narrowing gate and
//! the receipt-store gate as soon as the registry loads, before it connects to anything;
//! [`check_registry`] runs them again, as [`check`] does for the JSON configuration's path, and
//! every reload runs the receipt-store gate and the narrowing gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use connector_proxy::DEFAULT_DEADLINE;
use gateway_core::{
    AuditStore, Classification, Connector, ConnectorName, DeploymentName, EntryKind, InstanceName,
    Issuer, Lookup, Narrowing, PolicySnapshot, ProfileName, ReceiptQueue, SnapshotError, TeamId,
    ToolName,
};
use gateway_identity::{Clock, ConfigError, Identity, IdentityConfig};
use gateway_otto::{HttpResolver, KeyConfigError};
use gateway_registry::{Registry, RulePrincipal};
use thiserror::Error;

use crate::audit::DisabledAuditStore;
use crate::bound::{Bounded, DEFAULT_IN_PROCESS_DEADLINE, InProcessLimits, InProcessSignals};
use crate::catalog::{CatalogError, ToolCatalog};
use crate::config::{AuditSection, Config, HttpSection, IdentitySection, IssuerKindEntry};
use crate::currency::profile_requiring_currency;
use crate::grants::{
    GrantChecking, GrantGateError, GrantPolicyError, GrantSignals, GrantsSection,
    WorkloadSelection, issuer_gate, pod_gate,
};
use crate::policy::{LivePolicy, ServedPolicy};
use crate::quota::RateQuotas;
use crate::reconcile::{ReconcileSettings, Reconciler};
use crate::reload::{Freshness, Reloader};
use crate::resources::ResourceAdapter;
use crate::selector::{NO_PROFILE, ProfileSelector, SelectorError, SelectorRules};

/// The call deadline of a connector registered with [`Wiring::connector`], which runs in the
/// gateway's own process, unless the wiring sets another: the deadline its [`Bounded`] wrapper
/// holds each call to, which each audit row's deadline includes ([`crate::bound`]).
pub const DEFAULT_CALL_DEADLINE: Duration = DEFAULT_IN_PROCESS_DEADLINE;

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
    /// Identity is disabled in a release build (decision 0014, section 4).
    #[error(
        "identity is disabled, which only a development build allows: the release build checks \
         every caller, so configure the trusted issuers"
    )]
    IdentityOptOut,
    /// Audit is disabled in a release build (decision 0014, section 4).
    #[error(
        "audit is disabled, which only a development build allows: the release build records \
         every call, so configure an audit store"
    )]
    AuditOptOut,
    /// Turn-grant checking is disabled in a release build (decision 0012, "Keys").
    #[error(
        "turn-grant checking is disabled, which only a development build allows: the release \
         build verifies every turn grant, so configure the grant issuers, or leave `[grants]` \
         out while no profile requires a delegation"
    )]
    GrantOptOut,
    /// Turn-grant checking is both enforced and disabled.
    #[error("turn-grant checking is both enforced and disabled; choose one")]
    GrantContradiction,
    /// The turn-grant keys were refused.
    #[error(transparent)]
    GrantKeys(#[from] KeyConfigError),
    /// The grant configuration and the policy cannot serve together (decision 0012, "Keys").
    /// Boxed: its refusal names a tool, a surface, a team, a profile and an issuer.
    #[error(transparent)]
    GrantPolicy(Box<GrantPolicyError>),
    /// A profile a rule selects requires currency, and no resolver is configured, so every
    /// side effect under it would be denied as unconfirmed (decision 0012, "Currency").
    #[error(
        "profile `{0}`, which a profile rule selects, requires currency, but no resolver is \
         configured: name Otto's resolver interface in `[resolver]` (decision 0012)"
    )]
    NoResolver(ProfileName),
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
    /// A connector in the gateway's own process was given a deadline or a result bound of
    /// zero, or past decision 0014's ceilings of 60 s and 1 MiB.
    #[error(
        "connector `{connector}` was given a deadline of {deadline:?} and a result bound of \
         {max_result_bytes} bytes; each must be at least 1 and at most 60 s and 1 MiB"
    )]
    InProcessLimitsOutOfRange {
        /// The connector.
        connector: ConnectorName,
        /// The deadline given.
        deadline: Duration,
        /// The result bound given, in bytes.
        max_result_bytes: usize,
    },
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
    /// calls safe to answer after a lost outcome (decision 0009): the audit store is not the
    /// Postgres store, which keeps receipts, or audit or identity is off. Only a development
    /// build, one with the `test-support` feature, serves such a tool without one.
    #[error(
        "tool `{tool}` is classified `{classification}` and served on a surface, but no receipt \
         store is configured: a tool not classified `read` is served only with audit in \
         Postgres, which keeps receipts, and identity on (decision 0009)"
    )]
    NoReceiptStore {
        /// The tool.
        tool: ToolName,
        /// Its classification.
        classification: Classification,
    },
    /// A built-in connector was registered in a deployment whose policy is not the registry's,
    /// where no built-in entry or approval exists for it.
    #[error(
        "connector `{0}` is registered as a built-in connector, which needs the policy to come          from the registry"
    )]
    BuiltInWithoutRegistry(ConnectorName),
    /// A built-in connector was registered under a name the registry has no built-in entry for.
    #[error(
        "connector `{0}` is registered as a built-in connector, but the registry has no          `[[connectors]]` entry of that name"
    )]
    NotABuiltInEntry(ConnectorName),
    /// A built-in tool's approved definition is not the one its connector serves: the
    /// connector's code changed after the approval, or the approval was edited.
    #[error(
        "built-in tool `{0}`'s approved definition is not the one its connector serves; approve          the connector's definition again"
    )]
    BuiltInDefinitionDiffers(ToolName),
    /// A proxied server's credential is to be narrowed per call or to the caller's limit. The
    /// gateway sends one credential for every call to a server, so such an entry would skip
    /// rule 5 with a credential that is not narrowed.
    #[error(
        "server `{0}` says its credential is narrowed per call or to the caller's limit, which \
         this gateway cannot do yet: it sends the same credential on every call, so only \
         narrowing \"none\" is supported"
    )]
    NarrowingNotBuilt(ConnectorName),
}

impl From<GrantPolicyError> for BootError {
    fn from(error: GrantPolicyError) -> Self {
        BootError::GrantPolicy(Box::new(error))
    }
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
    /// Whether and how turn grants are verified.
    pub grants: GrantsSection,
    /// What the HTTP endpoint accepts.
    pub http: HttpSection,
    /// How long after the registry file was last read the policy is stale (decision 0013,
    /// section 8), or `None` for never.
    pub max_age: Option<Duration>,
    /// When the registry file the policy comes from was read. The policy's age counts from
    /// this read, not from when the gates pass, so a slow boot (keys fetched, the database
    /// checked) cannot start a replica whose policy is already stale as if it were fresh.
    pub read_at: Instant,
}

/// What code supplies to the gateway, beside its configuration: the clock, the instance, the
/// audit store, each connector with its resource adapter, and each connector's lookup by marker.
pub struct Wiring {
    clock: Arc<dyn Clock>,
    instance: InstanceName,
    audit_store: Option<Arc<dyn AuditStore>>,
    connectors: Vec<(ConnectorName, Registered)>,
    proxied: Vec<(ConnectorName, Arc<dyn Connector>)>,
    built_in: Vec<BuiltIn>,
    call_deadlines: BTreeMap<ConnectorName, Duration>,
    in_process_limits: BTreeMap<ConnectorName, InProcessLimits>,
    quotas: RateQuotas,
    lookups: BTreeMap<ConnectorName, Arc<dyn Lookup>>,
    resolver: Option<Arc<HttpResolver>>,
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
            built_in: Vec::new(),
            call_deadlines: BTreeMap::new(),
            in_process_limits: BTreeMap::new(),
            quotas: RateQuotas::default(),
            lookups: BTreeMap::new(),
            resolver: None,
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
    /// connector registered with [`connector`](Self::connector) has [`DEFAULT_CALL_DEADLINE`],
    /// or the deadline [`in_process_limits`](Self::in_process_limits) gave it. For such a
    /// connector this is also the deadline its [`Bounded`] wrapper holds each call to, and it
    /// takes the place of the one `in_process_limits` gave. A deadline for a name nothing is
    /// registered under is ignored.
    pub fn call_deadline(mut self, name: impl Into<ConnectorName>, deadline: Duration) -> Self {
        self.call_deadlines.insert(name.into(), deadline);
        self
    }

    /// Holds the connector registered as `name` with [`connector`](Self::connector), which runs
    /// in the gateway's own process, to `limits`: its deadline and its result bound, in place of
    /// [`InProcessLimits::default`]. The boot gates refuse a bound of zero or past decision
    /// 0014's ceilings. Limits for a name nothing is registered under that way are ignored.
    pub fn in_process_limits(
        mut self,
        name: impl Into<ConnectorName>,
        limits: InProcessLimits,
    ) -> Self {
        self.in_process_limits.insert(name.into(), limits);
        self
    }

    /// Holds every connector registered with [`connector`](Self::connector) to `quotas`, in
    /// place of [`RateQuotas::default`] ([`crate::quota`]). A proxied server's quotas are its
    /// [`Bulkhead`](crate::bulkhead::Bulkhead)'s.
    pub fn quotas(mut self, quotas: RateQuotas) -> Self {
        self.quotas = quotas;
        self
    }

    /// The call deadline each name was given with [`call_deadline`](Self::call_deadline).
    #[cfg(test)]
    pub(crate) fn call_deadlines(&self) -> &BTreeMap<ConnectorName, Duration> {
        &self.call_deadlines
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

    /// Registers `connector`, a built-in connector in the gateway's own process, for the
    /// registry's built-in entry `name`, serving the tools in `definitions`, each with the
    /// SHA-256 of its definition as its approval must record it. [`check_registry`] reads its
    /// calls with the registry's adapters and wraps it in its [`Bounded`]; [`check`] refuses
    /// it. One connector may be registered under several entries' names.
    pub fn built_in(
        mut self,
        name: impl Into<ConnectorName>,
        connector: Arc<dyn Connector>,
        definitions: impl IntoIterator<Item = (ToolName, String)>,
    ) -> Self {
        self.built_in.push(BuiltIn {
            name: name.into(),
            connector,
            definitions: definitions.into_iter().collect(),
        });
        self
    }

    /// Registers `lookup` as the connector `name`'s lookup by marker, which reconciliation asks
    /// to settle an `unknown` receipt of its tools (decision 0009, "Reconciliation"). A
    /// connector with none has each such receipt handed to a person at once. No connector has
    /// one until the built-in GitHub and Jira connectors (#12).
    pub fn lookup(mut self, name: impl Into<ConnectorName>, lookup: Arc<dyn Lookup>) -> Self {
        self.lookups.insert(name.into(), lookup);
        self
    }

    /// Asks Otto's resolver interface through `resolver` whether a call's turn is current
    /// (decision 0012, "Currency"; [`crate::currency`]). Without one, the boot gates refuse a
    /// policy with a profile that requires currency.
    pub fn resolver(mut self, resolver: Arc<HttpResolver>) -> Self {
        self.resolver = Some(resolver);
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
        let built_in: Vec<&ConnectorName> = self.built_in.iter().map(|b| &b.name).collect();
        f.debug_struct("Wiring")
            .field("instance", &self.instance)
            .field("audit_store", &self.audit_store.is_some())
            .field("connectors", &connectors)
            .field("proxied", &proxied)
            .field("built_in", &built_in)
            .field("resolver", &self.resolver.is_some())
            .finish_non_exhaustive()
    }
}

/// A built-in connector as [`Wiring::built_in`] registered it.
struct BuiltIn {
    name: ConnectorName,
    connector: Arc<dyn Connector>,
    definitions: BTreeMap<ToolName, String>,
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
    /// Shared with the [`KeyRefresher`](crate::keys::KeyRefresher), which replaces its keys.
    identity: Arc<Identity>,
    identity_state: GateState,
    audit_store: Arc<dyn AuditStore>,
    audit_state: GateState,
    grants: GrantChecking,
    http: HttpSection,
    policy: Arc<LivePolicy>,
    connectors: BTreeMap<ConnectorName, Registered>,
    in_process: Arc<InProcessSignals>,
    lookups: BTreeMap<ConnectorName, Arc<dyn Lookup>>,
    resolver: Option<Arc<HttpResolver>>,
    freshness: Freshness,
}

/// What the gateway was started with that a policy reload cannot change: the issuers, which
/// profile rules must name, and the registry's servers and routes, which the connectors were
/// built for. And, for the receipt-store gate, whether this build is exempt from it, which only
/// a development build is, and whether a receipt store is configured. And the grant issuers,
/// which are read at boot only, for the pod gate.
pub(crate) struct Basis {
    pub(crate) issuers: Option<Issuers>,
    pub(crate) registry: Registry,
    pub(crate) connectors: BTreeSet<ConnectorName>,
    pub(crate) receipt_exempt: bool,
    pub(crate) receipt_store: bool,
    /// Each configured grant issuer, and whether its grants must carry `pod`.
    pub(crate) grant_issuers: Vec<(String, bool)>,
    /// Whether Otto's resolver is configured, for the currency gate.
    pub(crate) resolver: bool,
    /// The SHA-256 of each tool's definition as the built-in connectors serve it, by tool.
    pub(crate) built_in_definitions: BTreeMap<ToolName, String>,
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

    /// The identity gate, for the key refresher to replace keys in while the gates serve.
    pub(crate) fn shared_identity(&self) -> Arc<Identity> {
        Arc::clone(&self.identity)
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

    /// The turn-grant gate: whether grants are verified, and the verifier.
    pub fn grants(&self) -> &GrantChecking {
        &self.grants
    }

    /// What the turn-grant gate counts, for the metrics.
    pub fn grant_signals(&self) -> GrantSignals {
        self.grants.signals().clone()
    }

    /// What the connectors in the gateway's own process count, summed over them, for the
    /// metrics ([`crate::bound`]).
    pub fn in_process_signals(&self) -> Arc<InProcessSignals> {
        self.in_process.clone()
    }

    /// The client for Otto's resolver interface, which a call under a profile that requires
    /// currency asks (decision 0012), or `None` when none is configured.
    pub fn resolver(&self) -> Option<&Arc<HttpResolver>> {
        self.resolver.as_ref()
    }

    /// The `Host` values served.
    pub fn allowed_hosts(&self) -> &BTreeSet<String> {
        &self.http.allowed_hosts
    }

    /// The `Origin` values served.
    pub fn allowed_origins(&self) -> &BTreeSet<String> {
        &self.http.allowed_origins
    }

    /// When the registry file was last read, and whether the policy is stale for it.
    pub fn freshness(&self) -> &Freshness {
        &self.freshness
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

    /// This instance's reconciliation of `unknown` receipts over `queue`, the store's queue,
    /// with the lookups the wiring registered and `settings`. It follows the policy these gates
    /// serve to find each receipt's connector. See [`crate::reconcile`].
    pub fn reconciler(
        &self,
        queue: Arc<dyn ReceiptQueue>,
        settings: ReconcileSettings,
    ) -> Reconciler {
        Reconciler::new(
            queue,
            self.policy.clone(),
            self.lookups.clone(),
            &self.instance,
            settings,
        )
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

/// [`check`], with the exemption of a development build given: from the receipt-store gate
/// and from the refusal of the identity and audit opt-outs. A test in a development build
/// passes false to run the gates as the release build does.
fn check_with(config: Config, wiring: Wiring, development: bool) -> Result<Gates, BootError> {
    let Wiring {
        clock,
        instance,
        audit_store,
        connectors: registrations,
        proxied,
        built_in,
        call_deadlines,
        in_process_limits,
        quotas,
        lookups,
        resolver,
    } = wiring;
    if let Some((name, _)) = proxied.into_iter().next() {
        return Err(BootError::ProxiedWithoutRegistry(name));
    }
    if let Some(built_in) = built_in.into_iter().next() {
        return Err(BootError::BuiltInWithoutRegistry(built_in.name));
    }
    let issuers = configured_issuers(&config.identity);
    let receipt_store = receipt_store_configured(&config.identity, &config.audit);
    let (identity, identity_state) = identity_gate(config.identity, clock.clone(), development)?;
    let (audit_store, audit_state) = audit_gate(&config.audit, audit_store, development)?;
    let grants = grant_gate(config.grants, &config.deployment, development)?;
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
    receipt_gate(&snapshot, development, receipt_store)?;
    narrowing_gate(&snapshot)?;

    let catalog = ToolCatalog::new(config.catalog)?;
    catalog.check(&approved)?;

    let in_process = Arc::new(InProcessSignals::default());
    let mut connectors = BTreeMap::new();
    for (name, mut registered) in registrations {
        let limits = in_process_bound(&name, &in_process_limits, &call_deadlines)?;
        registered.call_deadline = limits.deadline;
        // No connector in the gateway's own process runs without its bound (decision 0014).
        registered.connector = Arc::new(Bounded::new(
            name.clone(),
            registered.connector,
            limits,
            quotas,
            in_process.clone(),
        ));
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

    let policy = ServedPolicy::from_config(snapshot, catalog, selector);
    let selections = covered_teams(policy.workload_selections(), issuers.as_ref());
    issuer_gate(policy.snapshot(), &selections, &grants)?;
    pod_gate(policy.snapshot(), &selections, grants.issuers())?;
    currency_gate(&policy, resolver.is_some())?;

    warn_disabled(&config.deployment, identity_state, audit_state);
    warn_grants_disabled(&config.deployment, grants.state());
    Ok(Gates {
        deployment: config.deployment,
        instance,
        clock,
        identity,
        identity_state,
        audit_store,
        audit_state,
        grants,
        http: config.http,
        policy: Arc::new(LivePolicy::new(policy)),
        connectors,
        in_process,
        lookups,
        resolver,
        // No file is read again, so the policy never goes stale.
        freshness: Freshness::new(None, Instant::now()),
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
    check_registry_with(settings, registry, wiring, cfg!(feature = "test-support"))
}

/// [`check`] and [`check_registry`] as the release build runs them, with no exemption from the
/// receipt-store gate or the refusal of the opt-outs. Only a development build has them, so
/// that its tests can run the gates as the release build does.
#[cfg(feature = "test-support")]
pub mod as_release {
    use super::*;

    /// [`check`](super::check) as the release build runs it.
    pub fn check(config: Config, wiring: Wiring) -> Result<Gates, BootError> {
        check_with(config, wiring, false)
    }

    /// [`check_registry`](super::check_registry) as the release build runs it.
    pub fn check_registry(
        settings: Settings,
        registry: Registry,
        wiring: Wiring,
    ) -> Result<(Gates, Reloader), BootError> {
        check_registry_with(settings, registry, wiring, false)
    }
}

/// [`check_registry`], with the exemption of a development build given, as [`check_with`].
pub(crate) fn check_registry_with(
    settings: Settings,
    registry: Registry,
    wiring: Wiring,
    development: bool,
) -> Result<(Gates, Reloader), BootError> {
    let Wiring {
        clock,
        instance,
        audit_store,
        connectors: registrations,
        proxied,
        built_in,
        call_deadlines,
        // Only a connector in the gateway's own process takes these: here, a built-in one. A
        // proxied server's quotas are its bulkhead's.
        in_process_limits,
        quotas,
        lookups,
        resolver,
    } = wiring;
    if let Some((name, _)) = registrations.into_iter().next() {
        return Err(BootError::AdapterBesideRegistry(name));
    }
    let issuers = configured_issuers(&settings.identity);
    let receipt_store = receipt_store_configured(&settings.identity, &settings.audit);
    let (identity, identity_state) = identity_gate(settings.identity, clock.clone(), development)?;
    let (audit_store, audit_state) = audit_gate(&settings.audit, audit_store, development)?;
    let grants = grant_gate(settings.grants, &settings.deployment, development)?;
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
    let in_process = Arc::new(InProcessSignals::default());
    let mut built_in_definitions = BTreeMap::new();
    for BuiltIn {
        name,
        connector,
        definitions,
    } in built_in
    {
        if !registry.connectors().contains_key(&name) {
            return Err(BootError::NotABuiltInEntry(name));
        }
        let limits = in_process_bound(&name, &in_process_limits, &call_deadlines)?;
        // No connector in the gateway's own process runs without its bound (decision 0014).
        let registered = Registered {
            connector: Arc::new(Bounded::new(
                name.clone(),
                connector,
                limits,
                quotas,
                in_process.clone(),
            )),
            reads: Reads::Registry,
            results: Results::Values,
            call_deadline: limits.deadline,
        };
        if connectors.insert(name.clone(), registered).is_some() {
            return Err(BootError::DuplicateConnector(name));
        }
        built_in_definitions.extend(definitions);
    }
    let basis = Basis {
        issuers,
        registry,
        connectors: connectors.keys().cloned().collect(),
        receipt_exempt: development,
        receipt_store,
        grant_issuers: grants.issuers().to_vec(),
        resolver: resolver.is_some(),
        built_in_definitions,
    };
    check_registry_policy(&basis.registry, &live.current(), &basis)?;
    let served = live.current();
    let selections = covered_teams(served.workload_selections(), basis.issuers.as_ref());
    issuer_gate(served.snapshot(), &selections, &grants)?;

    warn_disabled(&settings.deployment, identity_state, audit_state);
    warn_grants_disabled(&settings.deployment, grants.state());
    let freshness = Freshness::new(settings.max_age, settings.read_at);
    let reloader = Reloader::new(live.clone(), basis, freshness.clone());
    let gates = Gates {
        deployment: settings.deployment,
        instance,
        clock,
        identity,
        identity_state,
        audit_store,
        audit_state,
        grants,
        http: settings.http,
        policy: live,
        connectors,
        in_process,
        lookups,
        resolver,
        freshness,
    };
    Ok((gates, reloader))
}

/// The bound of the connector `name` in the gateway's own process: the limits the wiring gave
/// it, or the defaults, with the call deadline the wiring gave it in place of theirs. Refused
/// when zero or past decision 0014's ceilings.
fn in_process_bound(
    name: &ConnectorName,
    limits: &BTreeMap<ConnectorName, InProcessLimits>,
    deadlines: &BTreeMap<ConnectorName, Duration>,
) -> Result<InProcessLimits, BootError> {
    let mut bound = limits.get(name).copied().unwrap_or_default();
    if let Some(deadline) = deadlines.get(name) {
        bound.deadline = *deadline;
    }
    if !bound.within_ceilings() {
        return Err(BootError::InProcessLimitsOutOfRange {
            connector: name.clone(),
            deadline: bound.deadline,
            max_result_bytes: bound.max_result_bytes,
        });
    }
    Ok(bound)
}

/// The gates a registry's policy must pass, at boot and on every reload: the
/// [receipt-store gate](receipt_gate); the [narrowing gate](narrowing_gate); every approved
/// tool's server has a connector; every approved built-in tool's entry has its connector, and
/// its approved definition is the one that connector serves; with identity enforced, every rule
/// names a configured issuer
/// of its kind; the snapshot does not define [`NO_PROFILE`]; every profile a rule names exists;
/// the [pod gate](pod_gate), with the rules beside the snapshot and the grant issuers the
/// gateway started with; and the [currency gate](currency_gate), with the resolver it started
/// with or without.
pub(crate) fn check_registry_policy(
    registry: &Registry,
    policy: &ServedPolicy,
    basis: &Basis,
) -> Result<(), BootError> {
    receipt_gate(policy.snapshot(), basis.receipt_exempt, basis.receipt_store)?;
    narrowing_gate(policy.snapshot())?;
    for (tool, route) in registry.routes() {
        if !basis.connectors.contains(&route.server) {
            return Err(BootError::UnregisteredConnector {
                tool: tool.clone(),
                connector: route.server.clone(),
            });
        }
    }
    for (tool, entry) in registry.built_in_tools() {
        if !basis.connectors.contains(entry) {
            return Err(BootError::UnregisteredConnector {
                tool: tool.clone(),
                connector: entry.clone(),
            });
        }
        let approved = registry
            .approvals()
            .get(tool)
            .map(|approval| &approval.definition_sha256);
        if basis.built_in_definitions.get(tool) != approved {
            return Err(BootError::BuiltInDefinitionDiffers(tool.clone()));
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
    let selections = covered_teams(policy.workload_selections(), basis.issuers.as_ref());
    pod_gate(policy.snapshot(), &selections, &basis.grant_issuers)?;
    currency_gate(policy, basis.resolver)?;
    Ok(())
}

/// The currency gate (decision 0012, "Currency"; [`crate::currency`]): no profile a rule
/// selects may require currency while no resolver is configured, since every side effect under
/// it would be denied as unconfirmed. Checked at boot on both paths, and on every registry
/// reload, which keeps the running policy when it refuses.
pub(crate) fn currency_gate(policy: &ServedPolicy, resolver: bool) -> Result<(), BootError> {
    if resolver {
        return Ok(());
    }
    match profile_requiring_currency(policy) {
        Some(profile) => Err(BootError::NoResolver(profile)),
        None => Ok(()),
    }
}

/// The receipt-store gate (decision 0009, "Until receipts exist"; design section 12). A
/// snapshot that serves a tool not classified `read` (on any surface) is refused unless a
/// receipt store is configured: `store`, as [`receipt_store_configured`] says. A tool approved
/// but on no surface is not served, and passes. It runs at boot and at every snapshot swap,
/// whatever the snapshot's source, and no policy setting changes it.
///
/// `exempt` is true only in a development build, one with the `test-support` feature, which
/// the release build never enables: the callers pass `cfg!(feature = "test-support")`.
///
/// A registry's snapshot does not reach this gate with such a tool today: the loader's rule 2
/// (decision 0011) refuses every proxied tool not classified `read` first, and only built-in
/// connectors (milestone 4) will serve one.
pub(crate) fn receipt_gate(
    snapshot: &PolicySnapshot,
    exempt: bool,
    store: bool,
) -> Result<(), BootError> {
    if exempt || store {
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

/// Whether a receipt store is configured, as decision 0009 requires before a tool not
/// classified `read` is served: the audit store is the Postgres store, which keeps receipts,
/// audit is on, and identity is on, so every call has a proved principal to scope its key to.
/// Read from what the deployment configures, its audit database and its identity section; no
/// setting of its own turns it on.
pub(crate) fn receipt_store_configured(identity: &IdentitySection, audit: &AuditSection) -> bool {
    audit.postgres && !audit.disabled && identity.enforce.is_some() && !identity.disabled
}

/// The narrowing gate. Decision 0011 lets an entry narrowed per call or to the caller's limit
/// skip the whole-reach check (rule 5) only because its credential really is narrowed. The
/// gateway sends a proxied server the same credential on every call, so a proxied entry whose
/// narrowing is not `none` is refused at boot, by [`check`] and by [`check_registry`], on every
/// reload, and by [`before_connecting`] before a credential is read, whoever wires the
/// connectors. No build is exempt. A built-in entry's connector asks for its credential
/// narrowed as the entry says, as the GitHub connector asks the key custodian for each token,
/// so a built-in entry passes.
pub(crate) fn narrowing_gate(snapshot: &PolicySnapshot) -> Result<(), BootError> {
    match snapshot
        .entries()
        .find(|entry| entry.kind == EntryKind::Proxied && entry.narrowing != Narrowing::None)
    {
        Some(entry) => Err(BootError::NarrowingNotBuilt(entry.name.clone())),
        None => Ok(()),
    }
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

/// The refusals that need only the configuration and the registry's snapshot, which
/// [`start::prepare`](crate::start::prepare) runs as soon as the registry loads, before it
/// reads a credential, fetches a key or connects to the audit store: the identity, audit and
/// turn-grant opt-outs outside a development build (decisions 0014, section 4, and 0012,
/// "Keys"), then the
/// [narrowing gate](narrowing_gate) and the [receipt-store gate](receipt_gate). The boot gates
/// run each again.
pub(crate) fn before_connecting(
    identity: &IdentitySection,
    audit: &AuditSection,
    grants: &GrantsSection,
    snapshot: &PolicySnapshot,
    development: bool,
) -> Result<(), BootError> {
    if identity.disabled {
        opt_out(BootError::IdentityOptOut, development)?;
    }
    if audit.disabled {
        opt_out(BootError::AuditOptOut, development)?;
    }
    if grants.disabled {
        opt_out(BootError::GrantOptOut, development)?;
    }
    narrowing_gate(snapshot)?;
    receipt_gate(
        snapshot,
        development,
        receipt_store_configured(identity, audit),
    )
}

/// An opt-out of the identity or audit gate: refused with `refusal` unless this is a
/// development build. The callers pass `cfg!(feature = "test-support")`, as for the
/// receipt-store gate.
fn opt_out(refusal: BootError, development: bool) -> Result<(), BootError> {
    if development { Ok(()) } else { Err(refusal) }
}

fn identity_gate(
    section: IdentitySection,
    clock: Arc<dyn Clock>,
    development: bool,
) -> Result<(Arc<Identity>, GateState), BootError> {
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
        (None, true) => {
            opt_out(BootError::IdentityOptOut, development)?;
            (IdentityConfig::Disabled, GateState::Disabled)
        }
        (None, false) => return Err(BootError::IdentityUnconfigured),
        (Some(_), true) => return Err(BootError::IdentityContradiction),
    };
    Ok((Arc::new(Identity::new(config, clock)?), state))
}

fn audit_gate(
    section: &AuditSection,
    store: Option<Arc<dyn AuditStore>>,
    development: bool,
) -> Result<(Arc<dyn AuditStore>, GateState), BootError> {
    match (store, section.disabled) {
        (Some(store), false) => Ok((store, GateState::On)),
        (None, true) => {
            opt_out(BootError::AuditOptOut, development)?;
            Ok((Arc::new(DisabledAuditStore::new()), GateState::Disabled))
        }
        (None, false) => Err(BootError::AuditUnconfigured),
        (Some(_), true) => Err(BootError::AuditContradiction),
    }
}

/// The configured workload and user issuers, or `None` when identity is not enforced.
#[derive(Clone)]
pub(crate) struct Issuers {
    workloads: BTreeSet<Issuer>,
    users: BTreeSet<Issuer>,
    /// Each workload issuer's teams, from its team manifest.
    teams: BTreeMap<Issuer, BTreeSet<TeamId>>,
}

fn configured_issuers(section: &IdentitySection) -> Option<Issuers> {
    let entries = section.enforce.as_ref()?;
    let (workloads, users): (Vec<_>, Vec<_>) =
        entries.iter().partition(|entry| entry.is_workload());
    Some(Issuers {
        teams: workloads
            .iter()
            .filter_map(|entry| match &entry.kind {
                IssuerKindEntry::Workload { subjects } => {
                    Some((entry.issuer.clone(), subjects.values().cloned().collect()))
                }
                IssuerKindEntry::User { .. } => None,
            })
            .collect(),
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

/// `selections` with each rule that covers every team its issuer vouches for narrowed to the
/// teams in that issuer's manifest. Without the manifests, with identity disabled, such a rule
/// is taken to cover every team.
fn covered_teams(
    selections: Vec<WorkloadSelection>,
    issuers: Option<&Issuers>,
) -> Vec<WorkloadSelection> {
    selections
        .into_iter()
        .map(|mut selection| {
            if selection.teams.is_none()
                && let Some(teams) =
                    issuers.and_then(|issuers| issuers.teams.get(&selection.issuer))
            {
                selection.teams = Some(teams.clone());
            }
            selection
        })
        .collect()
}

/// The turn-grant gate (decision 0012, "Keys"): enforced with the configured issuers, enforced
/// with none, or, in a development build only, disabled. Both is refused.
fn grant_gate(
    section: GrantsSection,
    deployment: &DeploymentName,
    development: bool,
) -> Result<GrantChecking, BootError> {
    GrantChecking::new(section, deployment, development).map_err(|error| match error {
        GrantGateError::Keys(error) => BootError::GrantKeys(error),
        GrantGateError::Contradiction => BootError::GrantContradiction,
        GrantGateError::OptOut => BootError::GrantOptOut,
    })
}

/// Logs a warning when turn-grant checking is turned off.
fn warn_grants_disabled(deployment: &DeploymentName, grants: GateState) {
    if grants == GateState::Disabled {
        tracing::warn!(
            %deployment,
            "turn-grant checking is disabled: grants are not read, so a profile that requires a \
             delegation denies every call"
        );
    }
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
    //!
    //! The snapshot loader refuses a proxied tool not classified `read` (decision 0011, rule 2)
    //! before this gate runs, and the only built-in connector, GitHub's, serves reads alone so
    //! far. So the gate's own tests run it on snapshots whose tool has an in-process connector
    //! and no connector entry, as the JSON configuration's do.
    #![allow(clippy::unwrap_used)]

    use gateway_core::{
        ApprovedTool, CredentialMode, Narrowing, PrincipalRestriction, ResourceDeclaration,
        SnapshotData, Surface,
    };
    use gateway_identity::SystemClock;
    use serde_json::json;

    use super::*;
    use crate::catalog::ToolDefinition;

    /// The server every test registry here registers: on loopback, never connected to, with a
    /// gateway token and a reach of nothing.
    pub(crate) fn server() -> gateway_registry::Server {
        gateway_registry::Server {
            name: "mock-docs".into(),
            system: "docs".into(),
            owner: "platform".into(),
            identity: "127.0.0.1".into(),
            address: "http://127.0.0.1:9/mcp".into(),
            credential: gateway_registry::Credential {
                mode: CredentialMode::GatewayToken,
                reference: "docs-credential".into(),
                principal: "docs-reader".into(),
            },
            narrowing: Narrowing::None,
            permits: Classification::Read,
            reach: BTreeSet::new(),
            reach_test: None,
            destination: gateway_registry::Destination::InCluster,
            probe: None,
            reach_check: None,
        }
    }

    /// A registry file with one server and one tool of `classification`, on the `docs` surface
    /// when `on_surface`, at `revision`. Only `read` loads: the loader refuses a proxied tool
    /// classified anything else (rule 2).
    pub(crate) fn registry_text(classification: &str, on_surface: bool, revision: &str) -> String {
        let sha = gateway_registry::definition_sha256(
            "list_documents",
            None,
            "Lists the documents.",
            &json!({"type": "object"}),
        );
        let binding = gateway_registry::binding_sha256(&server());
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
identity = "127.0.0.1"
address = "http://127.0.0.1:9/mcp"
credential = {{ mode = "gateway_token", reference = "docs-credential", principal = "docs-reader" }}
narrowing = "none"
permits = "read"
reach = []
destination = "in_cluster"
probe = {{ result = "refused", date = 2026-10-06 }}

[[tools]]
name = "docs__list_documents"
server = "mock-docs"
upstream_name = "list_documents"
classification = "{classification}"
description = "Lists the documents."
approved_by = "approver@example.test"
approved_at = 2026-10-06T00:00:00Z
definition_sha256 = "{sha}"
binding_sha256 = "{binding}"
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

    /// [`registry_text`] with no tool approved and its server's narrowing `written`, at
    /// `revision`. With no tool, rule 7 (a tool on an entry narrowed per call is declared from
    /// its arguments) has nothing to refuse, so each narrowing loads.
    pub(crate) fn narrowed_registry_text(written: &str, revision: &str) -> String {
        let text = registry_text("read", false, revision);
        let tools = text.find("[[tools]]").unwrap();
        let surfaces = text.find("[[surfaces]]").unwrap();
        let line = "narrowing = \"none\"\n";
        assert_eq!(text.matches(line).count(), 1);
        format!("tools = []\n{}{}", &text[..tools], &text[surfaces..])
            .replace(line, &format!("narrowing = \"{written}\"\n"))
    }

    /// The refusal of a narrowed credential, naming the test registry's server.
    pub(crate) fn assert_narrowing_refused(refused: &BootError) {
        match refused {
            BootError::NarrowingNotBuilt(server) => assert_eq!(server.as_str(), "mock-docs"),
            other => panic!("expected the narrowing refusal, got {other:?}"),
        }
        assert_eq!(
            refused.to_string(),
            "server `mock-docs` says its credential is narrowed per call or to the caller's \
             limit, which this gateway cannot do yet: it sends the same credential on every \
             call, so only narrowing \"none\" is supported"
        );
    }

    /// A snapshot with one tool of `classification` on an in-process connector, with no
    /// connector entry, on the `docs` surface when `on_surface`.
    fn in_process(classification: Classification, on_surface: bool) -> PolicySnapshot {
        let name = ToolName::parse("docs__list_documents").unwrap();
        PolicySnapshot::new(SnapshotData {
            revision: "r1".into(),
            tools: vec![ApprovedTool {
                name: name.clone(),
                classification,
                connector: "mock-docs".into(),
                resources: ResourceDeclaration::NoResources,
                declared_from: None,
                settlement: (classification != Classification::Read)
                    .then_some(gateway_core::Settlement::Person),
            }],
            surfaces: vec![Surface {
                name: "docs".into(),
                tools: if on_surface {
                    [name].into()
                } else {
                    BTreeSet::new()
                },
                teams: ["team-a".into()].into(),
                groups: BTreeSet::new(),
                principals: PrincipalRestriction::AnyInTeamsAndGroups,
            }],
            profiles: Vec::new(),
            limits: Default::default(),
            entries: Vec::new(),
        })
        .unwrap()
    }

    /// [`in_process`] served, with its tool's definition and no profile rules.
    fn served_in_process(classification: Classification) -> ServedPolicy {
        let catalog = ToolCatalog::new(vec![ToolDefinition {
            name: ToolName::parse("docs__list_documents").unwrap(),
            title: None,
            description: "Lists the documents.".into(),
            input_schema: json!({"type": "object"}),
        }])
        .unwrap();
        let selector = ProfileSelector::new(SelectorRules::default()).unwrap();
        ServedPolicy::from_config(in_process(classification, true), catalog, selector)
    }

    /// What a release build of `registry` starts with: no issuers, its one server connected,
    /// no exemption from the receipt-store gate and no receipt store.
    pub(crate) fn release_basis(registry: Registry) -> Basis {
        Basis {
            issuers: None,
            connectors: registry.servers().keys().cloned().collect(),
            registry,
            receipt_exempt: false,
            receipt_store: false,
            grant_issuers: Vec::new(),
            resolver: false,
            built_in_definitions: BTreeMap::new(),
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
        assert!(receipt_gate(&in_process(Classification::Read, true), false, false).is_ok());
        assert!(receipt_gate(registry("read", true).snapshot(), false, false).is_ok());
    }

    #[test]
    fn a_served_propose_tool_is_refused_without_a_receipt_store() {
        refused_as(
            receipt_gate(&in_process(Classification::Propose, true), false, false),
            Classification::Propose,
        );
    }

    #[test]
    fn a_served_write_tool_is_refused_without_a_receipt_store() {
        refused_as(
            receipt_gate(&in_process(Classification::Write, true), false, false),
            Classification::Write,
        );
    }

    #[test]
    fn a_tool_not_classified_read_but_on_no_surface_is_not_served_and_passes() {
        for classification in [
            Classification::Propose,
            Classification::Write,
            Classification::Destructive,
        ] {
            assert!(
                receipt_gate(&in_process(classification, false), false, false).is_ok(),
                "{classification}"
            );
        }
    }

    #[test]
    fn only_a_development_build_is_exempt() {
        assert!(receipt_gate(&in_process(Classification::Propose, true), true, false).is_ok());
    }

    /// The identity and audit sections a deployment with each of the three conditions has, or
    /// lacks: identity on, audit on, and the audit store the Postgres store.
    fn configured(
        identity_on: bool,
        audit_on: bool,
        postgres: bool,
    ) -> (IdentitySection, AuditSection) {
        (
            IdentitySection {
                enforce: identity_on.then(Vec::new),
                disabled: !identity_on,
            },
            AuditSection {
                disabled: !audit_on,
                postgres,
            },
        )
    }

    /// A receipt store is configured only when the audit store is the Postgres store, which
    /// keeps receipts, audit is on and identity is on (decision 0009, "Until receipts exist"),
    /// and then a release build serves a `propose` tool. Without any one of the three it is
    /// refused.
    #[test]
    fn a_receipt_store_needs_the_postgres_store_audit_and_identity() {
        let propose = in_process(Classification::Propose, true);
        for (identity_on, audit_on, postgres) in [
            (true, true, true),
            (false, true, true),
            (true, false, true),
            (true, true, false),
            (false, false, false),
        ] {
            let (identity, audit) = configured(identity_on, audit_on, postgres);
            let store = receipt_store_configured(&identity, &audit);
            let all = identity_on && audit_on && postgres;
            assert_eq!(
                store, all,
                "identity on: {identity_on}, audit on: {audit_on}, postgres: {postgres}"
            );
            let gated = receipt_gate(&propose, false, store);
            if all {
                assert!(gated.is_ok(), "{gated:?}");
            } else {
                refused_as(gated, Classification::Propose);
            }
        }
        // Identity both enforced and disabled is no identity, whatever the gate does with it.
        let identity = IdentitySection {
            enforce: Some(Vec::new()),
            disabled: true,
        };
        let audit = AuditSection {
            disabled: false,
            postgres: true,
        };
        assert!(!receipt_store_configured(&identity, &audit));
        // So is audit both in Postgres and disabled.
        let (identity, mut audit) = configured(true, true, true);
        audit.disabled = true;
        assert!(!receipt_store_configured(&identity, &audit));
    }

    /// The deployment file's Postgres store is the receipt store, and the JSON configuration
    /// cannot name one.
    #[test]
    fn only_the_deployment_files_postgres_store_is_a_receipt_store() {
        let postgres = crate::deployment::AuditChoice::Postgres {
            url: "postgres://switchboard_gateway@db.fixture.test/switchboard".into(),
        };
        assert!(postgres.section().postgres);
        assert!(!crate::deployment::AuditChoice::Disabled.section().postgres);
        let section: AuditSection = serde_json::from_str("{}").unwrap();
        assert!(!section.postgres);
        assert!(serde_json::from_str::<AuditSection>(r#"{"postgres": true}"#).is_err());
    }

    /// Before it connects, the start of a release build serves a `propose` snapshot with the
    /// Postgres store, audit and identity on, and refuses it without the Postgres store.
    #[test]
    fn before_connecting_runs_the_receipt_gate_with_what_the_deployment_configures() {
        let propose = in_process(Classification::Propose, true);
        let (identity, audit) = configured(true, true, true);
        let started = before_connecting(
            &identity,
            &audit,
            &GrantsSection::default(),
            &propose,
            false,
        );
        assert!(started.is_ok(), "{started:?}");
        let (identity, audit) = configured(true, true, false);
        refused_as(
            before_connecting(
                &identity,
                &audit,
                &GrantsSection::default(),
                &propose,
                false,
            ),
            Classification::Propose,
        );
    }

    #[test]
    fn the_refusal_names_the_tool_its_classification_and_the_reason() {
        let error =
            receipt_gate(&in_process(Classification::Propose, true), false, false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("`docs__list_documents`"), "{message}");
        assert!(message.contains("classified `propose`"), "{message}");
        assert!(
            message.contains("no receipt store is configured"),
            "{message}"
        );
    }

    /// A registry cannot reach the gate: the loader refuses its proxied `propose` tool first.
    #[test]
    fn a_registry_serving_a_propose_tool_is_refused_by_rule_2_as_it_loads() {
        for classification in ["propose", "write"] {
            let loaded = Registry::from_toml_str(&registry_text(classification, false, "r1"));
            assert!(
                matches!(
                    loaded,
                    Err(gateway_registry::RegistryError::Snapshot(
                        SnapshotError::ProxiedNotRead { .. }
                    ))
                ),
                "{classification}: {loaded:?}"
            );
        }
    }

    /// A JSON configuration with identity and audit on, serving `tool` on the `docs` surface
    /// with the connector `entries` given, and the wiring it boots with: an audit store and no
    /// connector registered.
    fn json_config(tool: serde_json::Value, entries: serde_json::Value) -> (Config, Wiring) {
        // The release build refuses the identity and audit opt-outs, so both gates are on.
        let issuer = gateway_testkit::LocalIssuer::new(
            "https://issuer.example.test",
            gateway_identity::SigningAlgorithm::Es256,
        )
        .unwrap();
        let config = Config::from_json(
            &json!({
                "deployment": "boot-gates",
                "identity": {"enforce": [{
                    "issuer": issuer.issuer(),
                    "audiences": ["switchboard"],
                    "kind": {"user": {}},
                    "algorithm": "ES256",
                    "keys": serde_json::to_value(issuer.jwk_set()).unwrap(),
                    "max_lifetime_secs": 3600,
                    "leeway_secs": 30,
                }]},
                "audit": {},
                "http": {"allowed_hosts": ["localhost"]},
                "policy": {
                    "revision": "r1",
                    "tools": [tool],
                    "surfaces": [{
                        "name": "docs",
                        "tools": ["docs__list_documents"],
                        "teams": ["team-a"],
                        "principals": "any_in_teams_and_groups"
                    }],
                    "profiles": [],
                    "entries": entries
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
        let wiring = Wiring::new(Arc::new(SystemClock))
            .audit_store(Arc::new(gateway_testkit::InMemoryAuditStore::new()));
        (config, wiring)
    }

    #[test]
    fn the_json_configuration_path_runs_the_receipt_gate() {
        let (config, wiring) = json_config(
            json!({
                "name": "docs__list_documents",
                "classification": "propose",
                "connector": "mock-docs",
                "resources": "no_resources",
                "settlement": "person"
            }),
            json!([]),
        );
        let refused = check_with(config, wiring, false);
        assert!(
            matches!(refused, Err(BootError::NoReceiptStore { .. })),
            "{refused:?}"
        );
    }

    /// The JSON configuration's boot runs the narrowing gate, through [`check`] and as the
    /// release build runs it: an entry narrowed per call or to the caller's limit is refused,
    /// with the registry's refusal. Narrowing "none" passes it, and the boot goes on to find no
    /// connector registered.
    #[test]
    fn the_json_configuration_path_runs_the_narrowing_gate() {
        // A proxied entry narrowed per call or to the limit is refused; a built-in entry is
        // not, since its connector narrows, and its tool is refused here only for having no
        // connector registered.
        for (kind, written) in [
            ("proxied", "call"),
            ("proxied", "limit"),
            ("proxied", "none"),
            ("built_in", "call"),
            ("built_in", "limit"),
            ("built_in", "none"),
        ] {
            // Rule 7: an entry narrowed per call serves only tools declared from arguments.
            let tool = json!({
                "name": "docs__list_documents",
                "classification": "read",
                "connector": "mock-docs",
                "resources": "declared",
                "declared_from": "arguments"
            });
            let entries = json!([{
                "name": "mock-docs",
                "kind": kind,
                "credential": "gateway_token",
                "principal": "docs-reader",
                "narrowing": written,
                "permits": "read",
                "reach": []
            }]);
            let (config, wiring) = json_config(tool.clone(), entries.clone());
            let checked = check(config, wiring);
            let (config, wiring) = json_config(tool, entries);
            let released = check_with(config, wiring, false);
            for result in [checked, released] {
                match (kind, written, result) {
                    ("proxied", "call" | "limit", Err(refused)) => {
                        assert_narrowing_refused(&refused);
                    }
                    (_, _, Err(BootError::UnregisteredConnector { connector, .. })) => {
                        assert_eq!(connector.as_str(), "mock-docs");
                    }
                    (_, _, other) => panic!("{kind} {written}: {other:?}"),
                }
            }
        }
    }

    /// The gates a registry's policy meets at boot and on every reload run the receipt-store
    /// gate on the policy given, whatever the registry holds.
    #[test]
    fn the_registry_path_runs_the_receipt_gate_at_boot_and_on_every_reload() {
        let registry = registry("read", true);
        for (classification, refused) in [
            (Classification::Read, false),
            (Classification::Propose, true),
            (Classification::Write, true),
        ] {
            let policy = served_in_process(classification);
            let checked =
                check_registry_policy(&registry, &policy, &release_basis(registry.clone()));
            assert_eq!(
                matches!(checked, Err(BootError::NoReceiptStore { .. })),
                refused,
                "{classification}: {checked:?}"
            );
        }
    }

    /// The gates a registry's policy meets at boot and on every reload refuse an entry whose
    /// credential is to be narrowed per call or to the caller's limit, in every build, and the
    /// refusal that runs before connecting does too. Narrowing "none" passes both.
    #[test]
    fn a_narrowed_entry_is_refused_by_the_shared_gates_and_before_connecting() {
        // Neither gate opted out, so only the snapshot's refusals apply before connecting.
        let identity = IdentitySection {
            enforce: None,
            disabled: false,
        };
        let audit = AuditSection {
            disabled: false,
            postgres: false,
        };
        for (written, narrowing) in [
            ("call", Narrowing::Call),
            ("limit", Narrowing::Limit),
            ("none", Narrowing::None),
        ] {
            let registry = Registry::from_toml_str(&narrowed_registry_text(written, "r1")).unwrap();
            assert_eq!(
                registry.servers().values().next().unwrap().narrowing,
                narrowing
            );
            let policy = ServedPolicy::from_registry(&registry).unwrap();
            for exempt in [false, true] {
                let basis = Basis {
                    receipt_exempt: exempt,
                    ..release_basis(registry.clone())
                };
                let checked = check_registry_policy(&registry, &policy, &basis);
                let before = before_connecting(
                    &identity,
                    &audit,
                    &GrantsSection::default(),
                    registry.snapshot(),
                    exempt,
                );
                if narrowing == Narrowing::None {
                    assert!(checked.is_ok(), "{checked:?}");
                    assert!(before.is_ok(), "{before:?}");
                } else {
                    assert_narrowing_refused(&checked.unwrap_err());
                    assert_narrowing_refused(&before.unwrap_err());
                }
            }
        }
    }

    /// An in-process policy whose `docs` surface serves one tool of `classification` to team A,
    /// whose workloads of `https://cluster.example.test` get the profile `sandbox`, which
    /// requires a delegation, at `revision`.
    fn requiring_policy(classification: Classification, revision: &str) -> ServedPolicy {
        sandbox_policy(classification, false, revision)
    }

    /// [`requiring_policy`], with the profile `sandbox` requiring currency or not.
    fn sandbox_policy(
        classification: Classification,
        requires_currency: bool,
        revision: &str,
    ) -> ServedPolicy {
        let name = ToolName::parse("docs__list_documents").unwrap();
        let snapshot = PolicySnapshot::new(SnapshotData {
            revision: revision.into(),
            tools: vec![ApprovedTool {
                name: name.clone(),
                classification,
                connector: "mock-docs".into(),
                resources: ResourceDeclaration::NoResources,
                declared_from: None,
                settlement: (classification != Classification::Read)
                    .then_some(gateway_core::Settlement::Person),
            }],
            surfaces: vec![Surface {
                name: "docs".into(),
                tools: [name.clone()].into(),
                teams: ["team-a".into()].into(),
                groups: BTreeSet::new(),
                principals: PrincipalRestriction::AnyInTeamsAndGroups,
            }],
            profiles: vec![gateway_core::Profile {
                name: "sandbox".into(),
                classifications: [Classification::Read, Classification::Propose].into(),
                requires_delegation: true,
                requires_currency,
                idempotency_key_header: false,
                exceptions: Vec::new(),
            }],
            limits: Default::default(),
            entries: Vec::new(),
        })
        .unwrap();
        let catalog = ToolCatalog::new(vec![ToolDefinition {
            name,
            title: None,
            description: "Lists the documents.".into(),
            input_schema: json!({"type": "object"}),
        }])
        .unwrap();
        let selector = ProfileSelector::new(SelectorRules {
            workloads: vec![crate::selector::WorkloadRule {
                issuer: "https://cluster.example.test".into(),
                team: "team-a".into(),
                profile: "sandbox".into(),
            }],
            users: Vec::new(),
        })
        .unwrap();
        ServedPolicy::from_config(snapshot, catalog, selector)
    }

    /// A development basis, so the receipt-store gate passes, with one grant issuer that
    /// requires `pod` or does not.
    fn grant_basis(registry: Registry, require_pod: bool) -> Basis {
        Basis {
            receipt_exempt: true,
            grant_issuers: vec![("otto-test".into(), require_pod)],
            ..release_basis(registry)
        }
    }

    /// The pod gate (decision 0012, "Keys") runs wherever a registry's policy is checked, at
    /// boot and on every reload: a `propose` or `write` tool served to a team whose profile
    /// requires a delegation is refused while a grant issuer does not require `pod`. Requiring
    /// it passes, and so does a read tool, and so does no grant issuer at all.
    #[test]
    fn the_pod_gate_runs_on_every_registry_policy() {
        let registry = registry("read", true);
        for classification in [Classification::Propose, Classification::Write] {
            let policy = requiring_policy(classification, "r2");
            let refused =
                check_registry_policy(&registry, &policy, &grant_basis(registry.clone(), false));
            match refused.map_err(|error| match error {
                BootError::GrantPolicy(policy) => Ok(*policy),
                other => Err(other),
            }) {
                Err(Ok(GrantPolicyError::PodNotRequired {
                    tool,
                    team,
                    grant_issuer,
                    ..
                })) => {
                    assert_eq!(tool.as_str(), "docs__list_documents");
                    assert_eq!(team.as_str(), "team-a");
                    assert_eq!(grant_issuer, "otto-test");
                }
                other => panic!("{classification}: expected the pod gate, got {other:?}"),
            }
            let bound =
                check_registry_policy(&registry, &policy, &grant_basis(registry.clone(), true));
            assert!(bound.is_ok(), "{classification}: {bound:?}");
            let basis = Basis {
                receipt_exempt: true,
                ..release_basis(registry.clone())
            };
            let no_issuer = check_registry_policy(&registry, &policy, &basis);
            assert!(no_issuer.is_ok(), "{classification}: {no_issuer:?}");
        }
        let read = requiring_policy(Classification::Read, "r2");
        let checked =
            check_registry_policy(&registry, &read, &grant_basis(registry.clone(), false));
        assert!(checked.is_ok(), "{checked:?}");
    }

    /// A version that breaks the pod gate is refused when it is loaded, and the running policy
    /// is kept; one that keeps it is served.
    #[test]
    fn a_reload_that_breaks_the_pod_gate_keeps_the_running_policy() {
        let registry = registry("read", true);
        let live = Arc::new(LivePolicy::new(requiring_policy(
            Classification::Read,
            "r1",
        )));
        let reloader = Reloader::new(
            live.clone(),
            grant_basis(registry.clone(), false),
            Freshness::new(None, Instant::now()),
        );
        let refused =
            reloader.apply_policy(&registry, requiring_policy(Classification::Propose, "r2"));
        assert!(
            matches!(
                &refused,
                Err(crate::reload::ReloadError::Boot(BootError::GrantPolicy(policy)))
                    if matches!(**policy, GrantPolicyError::PodNotRequired { .. })
            ),
            "{refused:?}"
        );
        assert_eq!(live.current().revision().as_str(), "r1");

        let served = reloader.apply_policy(&registry, requiring_policy(Classification::Read, "r3"));
        assert!(served.is_ok(), "{served:?}");
        assert_eq!(live.current().revision().as_str(), "r3");
    }

    /// A development basis, so the receipt-store gate passes, with Otto's resolver configured
    /// or not.
    fn resolver_basis(registry: Registry, resolver: bool) -> Basis {
        Basis {
            receipt_exempt: true,
            resolver,
            ..release_basis(registry)
        }
    }

    /// The currency gate (decision 0012, "Currency") runs wherever a registry's policy is
    /// checked, at boot and on every reload: a profile a rule selects that requires currency is
    /// refused while no resolver is configured, naming the profile. With a resolver it passes,
    /// and a profile that does not require currency needs none.
    #[test]
    fn the_currency_gate_runs_on_every_registry_policy() {
        let registry = registry("read", true);
        let requiring = sandbox_policy(Classification::Read, true, "r2");
        match check_registry_policy(
            &registry,
            &requiring,
            &resolver_basis(registry.clone(), false),
        ) {
            Err(BootError::NoResolver(profile)) => assert_eq!(profile.as_str(), "sandbox"),
            other => panic!("expected the currency gate, got {other:?}"),
        }
        let with = check_registry_policy(
            &registry,
            &requiring,
            &resolver_basis(registry.clone(), true),
        );
        assert!(with.is_ok(), "{with:?}");
        let not_requiring = sandbox_policy(Classification::Read, false, "r2");
        let without = check_registry_policy(
            &registry,
            &not_requiring,
            &resolver_basis(registry.clone(), false),
        );
        assert!(without.is_ok(), "{without:?}");
    }

    /// A version that makes a profile require currency, while the gateway runs without a
    /// resolver, is refused when it is loaded, and the running policy is kept.
    #[test]
    fn a_reload_that_needs_a_resolver_keeps_the_running_policy() {
        let registry = registry("read", true);
        let live = Arc::new(LivePolicy::new(sandbox_policy(
            Classification::Read,
            false,
            "r1",
        )));
        let reloader = Reloader::new(
            live.clone(),
            resolver_basis(registry.clone(), false),
            Freshness::new(None, Instant::now()),
        );
        let refused =
            reloader.apply_policy(&registry, sandbox_policy(Classification::Read, true, "r2"));
        assert!(
            matches!(
                &refused,
                Err(crate::reload::ReloadError::Boot(BootError::NoResolver(profile)))
                    if profile.as_str() == "sandbox"
            ),
            "{refused:?}"
        );
        assert_eq!(live.current().revision().as_str(), "r1");
    }
}
