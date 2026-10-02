//! The interface for running a tool.

use std::future::Future;

use crate::audit::AuditGuard;

/// Code that runs a group of tools against one external system, or forwards them to a proxied
/// server.
///
/// [`run`](Connector::run) requires an [`AuditGuard`], which only
/// [`audit::begin`](crate::audit::begin) hands out, after the row is written and only for an
/// allowed decision. The guard carries the decided call and the approved tool, so a connector
/// runs what was decided and recorded, and nothing else. A connector may still refuse because
/// of what the call names; it can never allow what the decision function denied, because a
/// denied call has no guard to give it.
pub trait Connector {
    /// What running a tool produces. The core does not prescribe it.
    type Output;

    /// Runs `guard.tool()` with the call's arguments, which the core passes through unread.
    fn run(
        &self,
        guard: &AuditGuard,
        arguments: &serde_json::Value,
    ) -> impl Future<Output = Self::Output> + Send;
}
