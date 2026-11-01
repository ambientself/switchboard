//! The interface for running a tool.

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::audit::AuditRowId;
use crate::classification::Classification;
use crate::decision::CallContext;
use crate::names::PolicyRevision;
use crate::policy::{ApprovedTool, Resource};
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

/// What the decision that allowed a call grants its connector beside the call itself: the
/// policy revision it was made under, the limit to narrow its credential to, and the row begun
/// for it. Taken from the decision by [`audit::begin`](crate::audit::begin), so a connector
/// reads them from the same snapshot the checks read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Granted {
    pub(crate) policy_revision: PolicyRevision,
    pub(crate) caller_limit: Option<Vec<Resource>>,
    pub(crate) row: AuditRowId,
}

/// One allowed call, handed to its connector. Made only by consuming an audit guard.
#[derive(Debug)]
pub struct ToolCall {
    call: CallContext,
    tool: ApprovedTool,
    arguments: serde_json::Value,
    granted: Granted,
}

impl ToolCall {
    pub(crate) fn new(
        call: CallContext,
        tool: ApprovedTool,
        arguments: serde_json::Value,
        granted: Granted,
    ) -> Self {
        Self {
            call,
            tool,
            arguments,
            granted,
        }
    }

    /// The revision of the policy snapshot the call was decided under, as its row records it. A
    /// connector that asks a custodian for a credential sends it, so the custodian checks the
    /// request against its own copy of that revision (design section 9).
    pub fn policy_revision(&self) -> &PolicyRevision {
        &self.granted.policy_revision
    }

    /// The caller's limit, as the snapshot the call was decided under holds it, when the tool's
    /// connector entry narrows its credential to the caller's limit (decision 0011, section 1),
    /// and `None` otherwise. A connector narrowing a credential `limit` asks for exactly these
    /// resources of its system.
    pub fn caller_limit(&self) -> Option<&[Resource]> {
        self.granted.caller_limit.as_deref()
    }

    /// The audit row begun for the call. For a tool not classified `read` it is also the
    /// identifier of the call's receipt, which a lookup finds the effect by (decision 0009,
    /// "Reconciliation"), and which the gateway's bound holds while a side effect it answered
    /// `unknown` runs on past its deadline ([`ReceiptQueue::hold`](crate::ReceiptQueue::hold)).
    pub fn row(&self) -> &AuditRowId {
        &self.granted.row
    }

    /// The receipt the call reserved, which is its row: `Some` exactly for a tool not
    /// classified `read`, whose allowed call [`audit::begin`](crate::audit::begin) hands out a
    /// guard for only once its receipt is reserved, and `None` for a read, which has none. A
    /// side-effecting connector attaches it to what it sends as the marker a lookup finds the
    /// effect by (decision 0009, "Reconciliation"), and sends nothing without one.
    pub fn receipt(&self) -> Option<&AuditRowId> {
        (self.tool.classification != Classification::Read).then_some(&self.granted.row)
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
    /// From a tool not classified `read`, a side effect, it means the connector knows nothing
    /// took effect: the request failed before it was sent, or the vendor definitely rejected it
    /// (decision 0009). The call's receipt is settled as `not_performed`, and the caller may
    /// try again under a new key. A side-effecting connector reports
    /// [`Unknown`](Self::Unknown) instead whenever it cannot know that. A proxied tool's error
    /// is `unknown` unless its approval says its errors are safe, and no approval can say so
    /// yet, so a proxied side effect is an error only when nothing was sent.
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
    /// once anything may have been sent, unless the vendor definitely rejected the call; from
    /// a proxied tool, for every outcome but a success once anything may have been sent. A
    /// read never reports it: from a `read` tool it is recorded as an error of the kind
    /// `other`.
    Unknown,
    /// A tool declared `checks_own_scope` succeeded: its result, for the caller, and the
    /// resources it reached, which its row records when it finishes, in place of the `unknown`
    /// it was begun with (decision 0011). Recorded as `ok`. An empty list says the tool reached
    /// nothing, and the row records it as an empty list, not as `unknown`. Only such a tool may
    /// report what it reached: from any other tool this is a broken contract, recorded as an
    /// `error` of the kind `other` with the result withheld, or, from a side effect, as
    /// `unknown` (see [`audit::finish`](crate::audit::finish)).
    Reached(serde_json::Value, Vec<Resource>),
}

impl ToolOutcome {
    /// A failure of `kind`, with `message` for the caller.
    pub fn error(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::Error(kind, message.into())
    }
}

/// The kind of an `error` outcome (decisions 0009 and 0011). A closed set, so each kind can be
/// counted from the rows. The row records the kind, not the caller's message. For a side
/// effect, an error of any kind means the connector knows nothing took effect: see
/// [`ToolOutcome::Error`].
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
    /// The credential custodian refused the credential an allowed call needed: the GitHub
    /// connector reports it when the key custodian refuses its token request.
    CustodianRefusal,
    /// The vendor refused the call, as each connector defines a refusal: for a proxied server,
    /// its `403` to a read. A proxied side effect's `403` is the outcome `unknown`.
    VendorRefusal,
    /// Any other failure.
    Other,
}
