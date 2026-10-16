//! The registry file, loaded and checked.
//!
//! One TOML file lists the proxied servers, the tools a person approved on them with their
//! approved definitions, the surfaces, the profiles, the resource limits and the rules that
//! select a profile from a proved principal. [`Registry::load`] turns it into:
//!
//! - a core [`PolicySnapshot`](gateway_core::PolicySnapshot), which decisions are made from;
//! - a [`ToolDefinition`] per approved tool, which `tools/list` is answered from without
//!   contacting the server. The core holds no definitions; they live here;
//! - an [`ArgumentAdapter`] per approved tool, which names the resources a call reaches and
//!   checks a call's arguments against the approved schema;
//! - a [`Route`] and an [`Approval`] per tool, the [`Server`] records, and the
//!   [`ProfileRules`];
//! - a [`BuiltInEntry`] per built-in connector entry, which states the vendor permissions its
//!   credential may be asked for, and, for an entry that serves approved tools, its credential
//!   as decision 0011 records it. The key custodian reads the permissions; the gateway wires a
//!   built-in connector for each entry and serves the tools `[[built_in_tools]]` approves on
//!   it, with their definitions and adapters among the others above.
//!
//! A file that is wrong in any way the loader can see is refused whole, with a
//! [`RegistryError`] that names the first problem. Nothing is half-loaded.
//!
//! # Why TOML
//!
//! TOML has no implicit typing, so `no`, `on` or `1.10` stay what they look like, and a value
//! cannot change type because of how it is spelt; in a policy file that is worth more than
//! brevity. Its date-times are a type of their own, which `approved_at` uses. Its `serde`
//! support honours `deny_unknown_fields` everywhere, and the `toml` crate is maintained, which
//! the YAML crates for `serde` no longer reliably are. The cost is that a nested input schema
//! is written as nested tables; the demo registry shows the shape.
//!
//! The file format is in `demo/registry.toml`, which is also the demo's registry.

#![forbid(unsafe_code)]

mod adapter;
mod builtin;
mod definition;
mod file;
mod registry;
mod selection;

pub use adapter::{ArgumentAdapter, ArgumentError, JsonPointer, ResourceSource};
pub use builtin::{Access, BuiltInEntry, EntryDeclaration, REPORTED_KIND, ReachReport};
pub use definition::{
    Approval, Route, SCHEMA_DIALECT, ToolDefinition, binding_sha256, built_in_binding_sha256,
    definition_sha256,
};
pub use registry::{
    Credential, Destination, Probe, ProbeResult, ReachCheck, ReachTest, Registry, RegistryError,
    Server, address_host,
};
pub use selection::{NoProfile, ProfileRule, ProfileRules, RulePrincipal};
