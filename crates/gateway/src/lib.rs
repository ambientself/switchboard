//! The gateway: the crate that puts the policy core, the identity verifier and the connectors
//! together and decides whether a deployment may start.
//!
//! This is design section 5's `gateway` crate:
//!
//! - [`Config`] is the deployment's configuration as data: identity, audit, the policy
//!   snapshot, tool definitions and the rules that select a profile.
//! - [`boot::check`] is design section 12's boot gates. It turns a [`Config`] and a [`Wiring`]
//!   (what code supplies: the clock, the audit store, the connectors) into [`Gates`], or
//!   refuses. Identity and audit must each be configured or explicitly disabled; neither, or
//!   both, is refused. [`Gates`] has private fields, so the only way to hold one is to have
//!   passed every check.
//! - [`ProfileSelector`] chooses a caller's profile from configured rules.
//! - [`ToolCatalog`] holds each approved tool's definition, the description and input schema
//!   `tools/list` returns, beside the snapshot. Boot refuses a tool without one.
//! - [`ResourceAdapter`] turns a call's arguments into the resources the decision checks.
//! - [`DisabledAuditStore`] is the explicit no-op store, made only when configuration opts out
//!   of audit.
//! - [`RequestPath`] is design section 6's request path over the [`Gates`]: identity, the MCP
//!   adapter, profile selection, the decision, the audit row and the connector, from a
//!   request's method, headers and body to its HTTP response.
//! - [`serve`] is the HTTP endpoint, `POST /mcp/{surface}`, over a listener and the [`Gates`]:
//!   the host and origin checks, the body limit, time limits on a request's head and body, and
//!   a task per answer, so a client that disconnects cannot cut a tool call off from its audit
//!   row. `GET /readyz` is its readiness check, which fails first when it shuts down.
//! - [`telemetry::init`] sends logs to standard output as JSON lines. [`Telemetry`] is
//!   decision 0009's telemetry: structured events and counters, off the request path, through
//!   a bounded queue that a [`Drain`] writes to the log. Drops are counted.
//! - [`serve_metrics`] exports the counters, and the audit store's, in Prometheus text at
//!   `GET /metrics` on a listener of its own, never the MCP listener ([`metrics`]).
//! - [`Bulkhead`] holds each proxied server to its cap on calls in flight, and each team to its
//!   cap on calls to the server, and counts each server's calls ([`bulkhead`]). [`serve`] holds
//!   the instance to its cap on requests in flight.
//!
//! The first slice (decision 0008) runs from files:
//!
//! - [`Deployment`] reads the deployment file and every file it names: each issuer's keys and
//!   team manifest, the registry file, the audit database's URL from the environment, and each
//!   proxied server's credential file.
//! - [`ServedPolicy`] is one version of the policy, from the JSON configuration or from the
//!   registry file (`gateway-registry`): snapshot, approved definitions, profile rules and
//!   argument adapters. The [`Gates`] serve the current version, and [`boot::check_registry`]
//!   hands back a [`Reloader`] that replaces it when the registry file changes.
//! - [`start::prepare`] builds the gateway: a `ProxyConnector` per registry server, with the
//!   bounds the deployment file sets for it, in a [`Bulkhead`], behind the registry's argument
//!   check; each keys URL's first fetch; the Postgres audit store after its
//!   boot checks, or audit explicitly disabled; and the boot gates.
//! - [`KeyRefresher`] fetches the keys of each issuer configured with a keys URL again on a
//!   timer, from the issuer's own origin, and keeps the keys in use when a fetch fails.
//! - [`DriftPass`] reads each proxied server's tool list, once during boot before the listener
//!   is bound and then on a timer, and withdraws each approved tool whose served definition no
//!   longer hashes to its approval, or that the server no longer lists ([`drift`]). Each poll
//!   also probes the server; an open server is logged and counted, and its tools stay listed.
//!   Once the listener is bound it also checks each entry's reach, by a call outside it through
//!   the gateway's own listener as the registry's workload ([`reach`]); an entry whose server
//!   answers has every tool withdrawn.
//! - [`probe`] is `switchboard probe`: decision 0010's three calls to one registry entry, and
//!   the probe record they make.
//! - [`Reconciler`] works the queue of `unknown` receipts in every instance with audit in
//!   Postgres ([`reconcile`]): it claims each receipt with a short lease, asks its connector's
//!   lookup for the marker, records what was found, and hands a receipt to a person when there
//!   is nothing to look in or its attempts are used up. It only looks: nothing is sent again.
//!
//! The `switchboard` binary is that, as a process: `switchboard --config=FILE` serves,
//! `switchboard probe` probes one entry, and `switchboard migrate` brings the audit schema up
//! to date. Nothing in it comes from the testkit; `tests/dependencies.rs` holds the crate's
//! dependencies to an allowlist.

#![forbid(unsafe_code)]

mod audit;
pub mod boot;
pub mod bulkhead;
mod catalog;
mod config;
pub mod deployment;
pub mod drift;
pub mod keys;
pub mod metrics;
pub mod path;
mod policy;
pub mod probe;
mod proxied;
pub mod reach;
pub mod reconcile;
pub mod reload;
mod resources;
mod selector;
pub mod server;
pub mod start;
pub mod telemetry;

pub use audit::DisabledAuditStore;
pub use boot::{BootError, GateState, Gates, Settings, Wiring};
pub use bulkhead::{
    Bulkhead, ProxiedSignals, ServerCounts, ServerSignals, server_at_capacity, team_at_capacity,
};
pub use catalog::{CatalogError, ToolCatalog, ToolDefinition};
pub use config::{
    Algorithm, AuditSection, Config, HttpSection, IdentitySection, IssuerEntry, IssuerKindEntry,
};
pub use deployment::{
    AuditChoice, DEFAULT_MAX_AGE, DEFAULT_MAX_IN_FLIGHT, DEFAULT_PER_SERVER_IN_FLIGHT,
    DEFAULT_PER_TEAM_PER_SERVER_IN_FLIGHT, Deployment, DeploymentError, KeysUrl, Limits,
    MAX_SERVER_DEADLINE, MAX_SERVER_RESULT_BYTES, MetricsSection, ServerLimits,
};
pub use drift::{
    DEFAULT_DRIFT_INTERVAL, DriftCounts, DriftPass, DriftSection, DriftSignals, MAX_DRIFT_INTERVAL,
    MIN_DRIFT_INTERVAL, PROBE_NOT_SHOWN_EVENT, ProbeCredentialError, ProbeCredentials,
    REACH_FAILED_EVENT, REACH_HELD_EVENT, REACH_MISMATCH_EVENT, SERVER_OPEN_EVENT, Withdrawals,
    probe_credentials, withdrawn_revision,
};
pub use keys::{
    DEFAULT_KEYS_REFRESH, KeyRefresher, MIN_KEYS_REFRESH, REFRESH_FAILED_EVENT, REFRESHED_EVENT,
    RefreshError,
};
pub use metrics::{METRICS_CONTENT_TYPE, Metrics, OPEN_ROWS_POLL, serve_metrics};
pub use path::{
    AUDIT_DISABLED_NOTE, Admitted, DISCONNECTED_BEFORE_RUN, Disconnect, DisconnectOnDrop,
    IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE, MAX_TOOL_USE_ID, POLICY_STALE, RequestPath,
    SERVER_NAME, Source,
};
pub use policy::{LivePolicy, ServedPolicy};
pub use proxied::{invalid_argument, undeclared_argument, withdrawn_while_deciding};
pub use reach::{ReachCaller, ReachSettings, ReachSettingsError};
pub use reconcile::{
    DEFAULT_RECONCILE_ATTEMPTS, DEFAULT_RECONCILE_INTERVAL, DEFAULT_RECONCILE_LEASE,
    HANDED_TO_PERSON_EVENT, MAX_RECONCILE_ATTEMPTS, MAX_RECONCILE_INTERVAL, MAX_RECONCILE_LEASE,
    MIN_RECONCILE_INTERVAL, MIN_RECONCILE_LEASE, PassReport, RECONCILE_BATCH,
    RECONCILE_FAILED_EVENT, ReconcileCounts, ReconcileSettings, ReconcileSettingsError,
    ReconcileSignals, Reconciler, ReconciliationSection, SETTLED_EVENT,
};
pub use reload::{Freshness, ReloadError, Reloader};
pub use resources::ResourceAdapter;
pub use selector::{
    NO_PROFILE, ProfileSelector, SelectorError, SelectorRules, UserRule, WorkloadRule,
};
pub use server::{
    AT_CAPACITY, BODY_READ_TIMEOUT, DISABLED_GATE_REMINDER, HEADER_READ_TIMEOUT, MAX_BODY_BYTES,
    READINESS_REMOVAL, SHUTDOWN_GRACE, SHUTTING_DOWN, Timeouts, serve, serve_with_shutdown,
    serve_with_telemetry, serve_with_timeouts,
};
pub use telemetry::{
    Drain, Event, MAX_SURFACE, Surface, TELEMETRY_QUEUE, Telemetry, TelemetryCounts,
};
