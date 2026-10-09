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
//!   row.
//! - [`telemetry::init`] sends logs to standard output as JSON lines.
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
//! - [`start::prepare`] builds the gateway: a `ProxyConnector` per registry server, behind the
//!   registry's argument check; the Postgres audit store after its boot checks, or audit
//!   explicitly disabled; and the boot gates.
//!
//! The `switchboard` binary is that, as a process: `switchboard --config=FILE` serves, and
//! `switchboard migrate` brings the audit schema up to date. Nothing in it comes from the
//! testkit; `tests/dependencies.rs` holds the crate's dependencies to an allowlist.

#![forbid(unsafe_code)]

mod audit;
pub mod boot;
mod catalog;
mod config;
pub mod deployment;
pub mod path;
mod policy;
mod proxied;
pub mod reload;
mod resources;
mod selector;
pub mod server;
pub mod start;
pub mod telemetry;

pub use audit::DisabledAuditStore;
pub use boot::{BootError, GateState, Gates, Settings, Wiring};
pub use catalog::{CatalogError, ToolCatalog, ToolDefinition};
pub use config::{
    Algorithm, AuditSection, Config, HttpSection, IdentitySection, IssuerEntry, IssuerKindEntry,
};
pub use deployment::{AuditChoice, Deployment, DeploymentError};
pub use path::{
    AUDIT_DISABLED_NOTE, Admitted, IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE, MAX_TOOL_USE_ID,
    RequestPath, SERVER_NAME,
};
pub use policy::{LivePolicy, ServedPolicy};
pub use proxied::{undeclared_argument, withdrawn_while_deciding};
pub use reload::{ReloadError, Reloader};
pub use resources::ResourceAdapter;
pub use selector::{
    NO_PROFILE, ProfileSelector, SelectorError, SelectorRules, UserRule, WorkloadRule,
};
pub use server::{
    BODY_READ_TIMEOUT, DISABLED_GATE_REMINDER, HEADER_READ_TIMEOUT, MAX_BODY_BYTES, SHUTDOWN_GRACE,
    Timeouts, serve, serve_with_shutdown, serve_with_timeouts,
};
