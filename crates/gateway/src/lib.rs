//! The gateway: the crate that puts the policy core, the identity verifier and the connectors
//! together.
//!
//! - [`ProfileSelector`] chooses a caller's profile from configured rules.
//! - [`ToolCatalog`] holds each approved tool's definition, the description and input schema
//!   `tools/list` returns, beside the snapshot.
//! - [`ResourceAdapter`] turns a call's arguments into the resources the decision checks.

#![forbid(unsafe_code)]

mod catalog;
mod resources;
mod selector;

pub use catalog::{CatalogError, ToolCatalog, ToolDefinition};
pub use resources::ResourceAdapter;
pub use selector::{
    NO_PROFILE, ProfileSelector, SelectorError, SelectorRules, UserRule, WorkloadRule,
};
