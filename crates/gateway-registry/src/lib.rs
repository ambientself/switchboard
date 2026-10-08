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
//!   refuses arguments its schema does not declare;
//! - a [`Route`] and an [`Approval`] per tool, the [`Server`] records, and the
//!   [`ProfileRules`].
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
mod definition;
mod file;
mod registry;
mod selection;

pub use adapter::{ArgumentAdapter, ArgumentError, JsonPointer, ResourceSource};
pub use definition::{Approval, Route, ToolDefinition, definition_sha256};
pub use registry::{Credential, Registry, RegistryError, Server};
pub use selection::{NoProfile, ProfileRule, ProfileRules, RulePrincipal};
