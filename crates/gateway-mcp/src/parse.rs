//! From a method, headers and body to a request, a notification or a refusal.

use http::{HeaderMap, Method};

use crate::message::Inbound;
use crate::rejection::Rejection;

/// Refuses what is not a JSON POST, from the method and headers alone: 405 for any method but
/// POST, 415 for a body not declared as `application/json`, and 406 for an `Accept` header that
/// does not admit `application/json`. An absent `Accept` is allowed, because Otto's callers send
/// none.
///
/// The HTTP layer runs this before identity, so before the body is read. [`parse`] runs it too.
pub fn check_transport(method: &Method, headers: &HeaderMap) -> Result<(), Rejection> {
    let _ = (method, headers);
    unimplemented!("published signature; implemented in the next commit")
}

/// Parses one POST: the transport checks, the JSON-RPC envelope, the era, the 2026-07-28
/// header checks and the method's parameters, in that order.
pub fn parse(method: &Method, headers: &HeaderMap, body: &[u8]) -> Result<Inbound, Rejection> {
    check_transport(method, headers)?;
    let _ = body;
    unimplemented!("published signature; implemented in the next commit")
}
