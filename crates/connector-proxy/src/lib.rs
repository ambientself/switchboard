//! The connector for a proxied MCP server.
//!
//! A [`ProxyConnector`] implements the core's [`Connector`](gateway_core::Connector) for one
//! upstream server. It forwards an allowed `tools/call` as a JSON-RPC request, `POST`ed with
//! the gateway's own bearer credential; the caller's token never leaves the gateway, and the
//! connector could not forward it if it tried, because a [`ToolCall`](gateway_core::ToolCall)
//! does not carry it.
//!
//! - **Credential.** [`FileCredentials`] reads one bearer token per connector from a file,
//!   once at boot to check it and again on every call. It implements the core's
//!   [`CredentialSource`](gateway_core::CredentialSource), whose handles carry only a label;
//!   the token stays inside this crate.
//! - **Where it connects.** An `https` server's certificate is verified against the server's
//!   identity, the host in its URL, trusting only the CA file the deployment names for it.
//!   Plain `http` is allowed only for a server whose destination is `in_cluster`. Each address
//!   is checked when the connector connects, and the checked address is the one connected to;
//!   loopback, link-local and other addresses are refused, and private ones are refused for a
//!   server outside the cluster. The [`destination`] module lists them (decision 0013,
//!   section 3).
//! - **Bounds.** Each call is abandoned at its deadline, 5 s by default, and an answer larger
//!   than its cap, 64 KiB by default, is discarded. Both are enforced here, inside the
//!   connector, not by the core. A call is sent once: the client never retries it.
//! - **Outcomes.** A failure, a timeout, arguments that are not an object, or the server's
//!   `403` is [`ToolOutcome::Error`](gateway_core::ToolOutcome), with an
//!   [`ErrorKind`](gateway_core::ErrorKind) for the row: the `403` is a vendor refusal. A call
//!   for a tool the connector does not serve or has no credential for is
//!   [`ToolOutcome::Refused`](gateway_core::ToolOutcome). The [`outcome`] module lists each
//!   sentence and kind.
//! - **The tool list.** [`ProxyConnector::list_tools`] reads the server's `tools/list` for the
//!   gateway itself, for the drift pass, with the same credential and the same bounds. It
//!   returns the tools as served, or a [`ListError`]; a list it could not read whole is never
//!   returned in part.
//! - **The probe.** [`probe()`] and [`ProxyConnector::probe`] send decision 0010's three calls
//!   for a tool that does not exist: with no credential, a malformed one, and a stranger's
//!   [`ProbeCredential`]. The [`ProbeReport`] says whether the server refused all three,
//!   dispatched one (open), or showed neither. A call that could not be made is never counted
//!   as refused.
//!
//! Calls, tool lists and probes all go out on the connector's one client, so each is held to
//! the same checks. The server is reached over session-less streamable HTTP, revision
//! 2025-06-18, at an `http://` or `https://` URL, over HTTP/1.1. The answer to a forwarded call
//! or a tool list must be JSON; an event stream is not read there. The probe does read an event
//! stream's data, to look for a JSON-RPC answer that shows a call was dispatched.
//!
//! The `test-support` feature makes a development build, the only one that can let a connector
//! reach a loopback address ([`Loopback::Allowed`]), for the tests' local servers.

#![forbid(unsafe_code)]

mod connector;
mod credentials;
pub mod destination;
mod list;
pub mod outcome;
mod probe;
mod transport;

pub use connector::{
    DEFAULT_DEADLINE, DEFAULT_MAX_RESPONSE_BYTES, PROTOCOL_VERSION, ProxyConnector,
    SIDE_EFFECT_UNKNOWN_EVENT, Upstream, UpstreamError,
};
pub use credentials::{
    CredentialFileError, FileCredentials, MAX_CREDENTIAL_BYTES, ProbeCredential,
};
pub use destination::{Destination, Loopback, Refusal, refusal};
pub use list::{ListError, ListedTool};
pub use probe::{
    CallVerdict, MALFORMED_CREDENTIAL, NotShown, PROBE_TOOL, ProbeBounds, ProbeCall, ProbeError,
    ProbeFinding, ProbeReport, probe,
};
pub use transport::CaFault;
