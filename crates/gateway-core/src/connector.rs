//! The interface for running a tool.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::decision::CallContext;
use crate::policy::ApprovedTool;
use crate::receipt::VendorReference;

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
    /// The tool ran and failed: the kind of failure, which the row records, and a message for
    /// the caller, which it does not.
    ///
    /// From a tool not classified `read`, a side effect, it means nothing took effect: nothing
    /// was sent, or the vendor answered that it did not do it. The call's receipt is settled as
    /// `not_performed` (decision 0009), and the caller may try again under a new key. A
    /// side-effecting connector reports [`Unknown`](Self::Unknown) instead once anything may
    /// have been sent and no definite answer came back.
    Error(ErrorKind, String),
    /// The connector refused because of what the call names. The sentence is returned to the
    /// caller and recorded on the row, and reaches the caller only after that row is finished.
    Refused(String),
    /// A side effect the vendor confirmed, with the vendor's reference for what it made, such
    /// as a pull request's number: its result, for the caller, and the reference, which the
    /// call's receipt records. Recorded as `ok`. From a `read` tool, which has no receipt, the
    /// reference is dropped.
    Completed(serde_json::Value, VendorReference),
    /// A side effect's request may have been sent, and no definite answer came back: a timeout,
    /// a connection broken off, a server error after the request was sent, an answer that
    /// cannot be read, or a result over the gateway's bound (decision 0009). Recorded as
    /// `unknown`, its receipt is `unknown`, and the caller is told not to repeat the call. A
    /// side-effecting connector reports this, never [`Error`](Self::Error), for every failure
    /// once anything may have been sent, unless the vendor answered that it did not do it. A
    /// read never reports it: from a `read` tool it is recorded as an error of the kind
    /// `other`.
    Unknown,
}

impl ToolOutcome {
    /// A failure of `kind`, with `message` for the caller.
    pub fn error(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::Error(kind, message.into())
    }
}

/// The kind of an `error` outcome (decisions 0009 and 0011). A closed set, so each kind can be
/// counted from the rows. The row records the kind, not the caller's message. For a side
/// effect, an error of any kind means nothing took effect: see [`ToolOutcome::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The call's arguments failed a check, so nothing was sent.
    InvalidArguments,
    /// A tool classified `read` gave an answer too large to accept, or none by its deadline.
    /// Only a read's error has this kind. From a tool of any other classification the same
    /// failure is not an error at all: the request may have been sent, so its connector reports
    /// [`ToolOutcome::Unknown`], and its receipt is `unknown`.
    OversizedOrLateRead,
    /// The credential custodian refused the credential an allowed call needed. Nothing reports
    /// it yet: no connector asks a custodian.
    CustodianRefusal,
    /// The vendor refused the call, as each connector defines a refusal: for a proxied server,
    /// its `403`.
    VendorRefusal,
    /// Any other failure.
    Other,
}
