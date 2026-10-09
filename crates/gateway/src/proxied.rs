//! What a proxied server's connector is wrapped in when the policy comes from the registry:
//! the resources a call names, and the check of its arguments against the tool's approved
//! schema, both read from the policy version the call's request took. A call whose arguments
//! fail the check is outcome `error` and nothing is sent upstream; a call whose tool was
//! withdrawn meanwhile is outcome `refused`.

use gateway_core::{ApprovedTool, BoxFuture, Connector, Resources, ToolCall, ToolOutcome};
use gateway_registry::ArgumentError;
use serde_json::Value;

use crate::policy::{LivePolicy, ServedPolicy};

/// The sentence for a call whose arguments carry something the tool's approved schema does
/// not declare. The call is not sent (decision 0011: the server is never trusted to check its
/// own scope, so it is never handed arguments nobody approved).
pub fn undeclared_argument(tool: &str) -> String {
    format!(
        "Tool `{tool}` was called with an argument its approved definition does not declare, so \
         the call was not sent. Call `tools/list` to see the arguments it takes."
    )
}

/// The sentence for a call whose tool was withdrawn between the decision and the run. The call
/// is not sent.
pub fn withdrawn_while_deciding(tool: &str) -> String {
    format!(
        "Tool `{tool}` was withdrawn while this call was being decided, so the call was not \
         sent. Call `tools/list` to see the tools this surface serves."
    )
}

/// The resources a call to `tool` names, read with the argument adapter `policy` approved for
/// it. `policy` is the version the call's request took, the one its decision is made from.
///
/// A tool with no adapter in that policy, or arguments that are not an object, name no
/// resources: check 6 denies that for a tool that declares its resources, and it never
/// guesses.
pub(crate) fn registry_resources(
    policy: &ServedPolicy,
    tool: &ApprovedTool,
    arguments: &Value,
) -> Resources {
    match (policy.arguments(&tool.name), arguments.as_object()) {
        (Some(adapter), Some(arguments)) => adapter.resources(arguments),
        _ => Resources::Named(Vec::new()),
    }
}

/// A proxied server's connector, behind the registry's argument check, for one request.
///
/// The arguments are checked against the schema in the policy version the request took, the
/// one its decision was made from, never a version served later: a reload between the
/// decision and the run must not let through an argument no decision saw. The policy served
/// now is read only to see whether the tool was withdrawn meanwhile.
///
/// The check runs inside the audited run, so its answer completes the call's row, and nothing
/// is sent upstream. Arguments that fail the check are outcome `error` (decision 0011:
/// `refused` is kept for calls that could never be allowed). The row records only the outcome
/// and the latency; the sentence goes to the caller and is not on the row. A tool withdrawn
/// meanwhile is outcome `refused`, and its sentence is recorded on the row.
pub(crate) struct CheckedArguments<'a> {
    inner: &'a dyn Connector,
    policy: &'a ServedPolicy,
    live: &'a LivePolicy,
}

impl<'a> CheckedArguments<'a> {
    pub(crate) fn new(
        inner: &'a dyn Connector,
        policy: &'a ServedPolicy,
        live: &'a LivePolicy,
    ) -> Self {
        Self {
            inner,
            policy,
            live,
        }
    }
}

impl Connector for CheckedArguments<'_> {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let tool = call.tool().name.clone();
        let withdrawn = self.live.current().arguments(&tool).is_none();
        let adapter = self.policy.arguments(&tool);
        let checked: Result<(), ToolOutcome> = match adapter {
            Some(adapter) if !withdrawn => {
                adapter.check_arguments(call.arguments()).map_err(|error| {
                    // The path is the caller's own text, so only the tool goes in the sentence;
                    // the log has the rest.
                    match &error {
                        ArgumentError::Undeclared { path, .. } => tracing::warn!(
                            %tool,
                            path = path.as_str(),
                            "a call with an undeclared argument failed the argument check"
                        ),
                        ArgumentError::NotAnObject { .. } => tracing::warn!(
                            %tool,
                            "a call whose arguments are not an object failed the argument check"
                        ),
                    }
                    ToolOutcome::Error(undeclared_argument(tool.as_str()))
                })
            }
            // Withdrawn from the policy served now. The request's own version always holds an
            // adapter for a tool its decision allowed.
            _ => Err(ToolOutcome::Refused(withdrawn_while_deciding(
                tool.as_str(),
            ))),
        };
        match checked {
            Ok(()) => self.inner.run(call),
            Err(outcome) => Box::pin(std::future::ready(outcome)),
        }
    }
}
