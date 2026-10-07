//! The gateway: the crate that puts the policy core, the identity verifier and the connectors
//! together and decides whether a deployment may start.
//!
//! This is design section 5's `gateway` crate. The HTTP server and the `switchboard` binary
//! come later; what is here needs no socket:
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

#![forbid(unsafe_code)]

mod audit;
pub mod boot;
mod catalog;
mod config;
pub mod path;
mod resources;
mod selector;

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
