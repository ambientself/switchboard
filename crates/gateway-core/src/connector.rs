//! The interface for running a tool.

use std::future::Future;
use std::pin::Pin;

use crate::decision::CallContext;
use crate::policy::ApprovedTool;

/// A boxed future that can move between threads.
///
/// The traits here return one rather than `impl Future`, so they can be used as trait objects:
/// a registry of different connectors keyed by name, or one store shared in server state. The
/// cost is an allocation per call, beside network I/O; the gain is that the core still needs
/// no async runtime.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Code that runs a group of tools against one external system, or forwards them to a proxied
/// server.
///
/// [`run`](Connector::run) takes a [`ToolCall`], which only [`audit::run`](crate::audit::run)
/// can make, and only by consuming the [`AuditGuard`](crate::AuditGuard) that
/// [`audit::begin`](crate::audit::begin) handed out once the row was written. So a connector
/// cannot be invoked outside the audited path, one guard runs one call once, and what runs is
/// the tool and arguments the row was written for. A connector may still refuse because of
/// what the call names; it can never allow what the decision function denied, because a denied
/// call has no guard.
pub trait Connector: Send + Sync {
    /// Runs `call.tool()` with `call.arguments()`.
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome>;
}

/// One allowed call, handed to its connector. Made only by consuming an audit guard.
#[derive(Debug)]
pub struct ToolCall {
    call: CallContext,
    tool: ApprovedTool,
    arguments: serde_json::Value,
}

impl ToolCall {
    pub(crate) fn new(call: CallContext, tool: ApprovedTool, arguments: serde_json::Value) -> Self {
        Self {
            call,
            tool,
            arguments,
        }
    }

    /// The decided call: who is calling, under which profile, on which surface.
    pub fn call(&self) -> &CallContext {
        &self.call
    }

    /// The approved tool to run. The connector runs this tool and no other.
    pub fn tool(&self) -> &ApprovedTool {
        &self.tool
    }

    /// The call's arguments, passed through unread by the core.
    pub fn arguments(&self) -> &serde_json::Value {
        &self.arguments
    }
}

/// What running a tool came to. A closed set: the audit record's outcome is derived from it,
/// so a connector cannot report something the record has no column for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolOutcome {
    /// The tool ran and succeeded; its result, for the caller.
    Ok(serde_json::Value),
    /// The tool ran and failed; a message for the caller.
    Error(String),
    /// The connector refused because of what the call names. The sentence is returned to the
    /// caller and recorded on the row, and reaches the caller only after that row is finished.
    Refused(String),
}
