//! The connector for a proxied MCP server.
//!
//! A [`ProxyConnector`] implements the core's [`Connector`](gateway_core::Connector) for one
//! upstream server. It forwards an allowed `tools/call` as a JSON-RPC request, `POST`ed with
//! the gateway's own bearer credential; the caller's token never leaves the gateway, and the
//! connector could not forward it if it tried, because a [`ToolCall`](gateway_core::ToolCall)
//! does not carry it.
//!
//! - **Credential.** [`FileCredentials`] reads one bearer token per connector from a file at
//!   boot. It implements the core's [`CredentialSource`](gateway_core::CredentialSource), whose
//!   handles carry only a label; the token stays inside this crate.
//! - **Bounds.** Each call is abandoned at its deadline, 5 s by default, and an answer larger
//!   than its cap, 64 KiB by default, is discarded. Both are enforced here, inside the
//!   connector, not by the core.
//! - **Outcomes.** A failure, a timeout, or arguments that are not an object is
//!   [`ToolOutcome::Error`](gateway_core::ToolOutcome); the server's `403`, and a call for a
//!   tool the connector does not serve or has no credential for, is
//!   [`ToolOutcome::Refused`](gateway_core::ToolOutcome). The [`outcome`] module lists each
//!   sentence.
//!
//! The server is reached over session-less streamable HTTP, revision 2025-06-18, at an
//! `http://` URL. An answer must be JSON; an event stream is not read.

#![forbid(unsafe_code)]

mod connector;
mod credentials;
pub mod outcome;

pub use connector::{
    DEFAULT_DEADLINE, DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION, ProxyConnector, Upstream,
    UpstreamError,
};
pub use credentials::{CredentialFileError, FileCredentials, MAX_CREDENTIAL_BYTES};
