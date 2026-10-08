//! The interface that reads a call's arguments for the resources it names.

use gateway_core::{ApprovedTool, Resources};

/// Reads a call's arguments and names the resources the call reaches, for the decision's
/// resource check (decision 0006, check 6).
///
/// The core never reads a tool's arguments, so each connector comes with an adapter that does.
/// One is registered beside each connector in the wiring, so a connector cannot be configured
/// without one. It is chosen by the connector of the approved tool the call names, never by
/// anything else in the request.
///
/// An adapter must not guess. For a tool that declares its resources, arguments it cannot read
/// are [`Resources::Unknown`] or an empty list, both of which the decision denies; a guess
/// could name a resource the call does not reach and let it through.
pub trait ResourceAdapter: Send + Sync {
    /// The resources a call to `tool` with `arguments` names.
    fn resources(&self, tool: &ApprovedTool, arguments: &serde_json::Value) -> Resources;
}
