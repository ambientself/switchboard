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
//! The `switchboard` binary reads a configuration file, runs the boot gates and serves. It has
//! no durable audit store and no connectors yet, so it starts only with audit explicitly
//! disabled, and serves no tool.

#![forbid(unsafe_code)]

mod audit;
pub mod boot;
mod catalog;
mod config;
pub mod path;
mod resources;
mod selector;
pub mod server;
pub mod telemetry;

pub use audit::{DISABLED_ROW, DisabledAuditStore};
pub use boot::{BootError, GateState, Gates, Wiring};
pub use catalog::{CatalogError, ToolCatalog, ToolDefinition};
pub use config::{
    Algorithm, AuditSection, Config, HttpSection, IdentitySection, IssuerEntry, IssuerKindEntry,
};
pub use path::{
    AUDIT_DISABLED_NOTE, Admitted, IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE, MAX_TOOL_USE_ID,
    RequestPath, SERVER_NAME,
};
pub use resources::ResourceAdapter;
pub use selector::{
    NO_PROFILE, ProfileSelector, SelectorError, SelectorRules, UserRule, WorkloadRule,
};
pub use server::{
    BODY_READ_TIMEOUT, DISABLED_GATE_REMINDER, HEADER_READ_TIMEOUT, MAX_BODY_BYTES, SHUTDOWN_GRACE,
    Timeouts, serve, serve_with_shutdown, serve_with_timeouts,
};
