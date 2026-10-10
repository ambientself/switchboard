//! The gateway's MCP protocol adapter.
//!
//! Decision 0007: one hand-written POST endpoint serves two MCP revisions, `2026-07-28`
//! ([`MODERN`]) and `2025-06-18` ([`LEGACY`]), with no sessions in either. This crate is the
//! protocol half of that endpoint, as pure functions:
//!
//! - [`check_transport`] refuses what is not a JSON POST: 405, 415 and 406. The HTTP layer
//!   runs it before identity, and so before the body is read.
//! - [`parse`] turns a method, headers and body into an [`Inbound`] request or notification, or
//!   a [`Rejection`]. Every POST is classified into an [`Era`] on its own; nothing is kept
//!   between requests.
//! - [`render`] turns a [`Reply`] into the [`HttpResponse`] for that era, and
//!   [`render_with_row`] also names the audit row the gateway wrote for it.
//! - [`Rejection`] also builds the envelopes the HTTP layer sends itself: 401 for an identity
//!   failure, 403 for a host or origin, 413 for a body that is too large.
//!
//! It names no policy type. Denial sentences come from the core through the `gateway` crate,
//! which maps between the two; this crate writes no sentence about policy of its own.

#![forbid(unsafe_code)]

mod constants;
mod headers;
mod message;
mod parse;
mod rejection;
mod reply;

pub use constants::{
    AUDIT_ROW_DATA, AUDIT_ROW_META, CHALLENGE, CLIENT_CAPABILITIES_META, DENIAL_CODE,
    HEADER_MISMATCH, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, LAST_EVENT_ID_HEADER, LEGACY,
    LIST_TTL_MS, METHOD_HEADER, METHOD_NOT_FOUND, MODERN, NAME_HEADER, PARSE_ERROR,
    PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, SERVER_INFO_META, SESSION_ID_HEADER,
    TOOL_USE_ID_META, UNSUPPORTED_VERSION,
};
pub use message::{Call, Era, Inbound, Request, RequestId, ToolCall};
pub use parse::{check_transport, parse};
pub use rejection::{Rejection, RejectionKind};
pub use reply::{HttpResponse, Reply, ServerInfo, ToolEntry, render, render_with_row};
