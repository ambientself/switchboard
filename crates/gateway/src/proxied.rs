//! What a proxied server's connector is wrapped in when the policy comes from the registry:
//! the resources a call names, and the check that refuses arguments a tool's approved schema
//! does not declare, both read from the policy version the call's request took.

use gateway_core::{ApprovedTool, BoxFuture, Connector, Resources, ToolCall, ToolOutcome};
use gateway_registry::ArgumentError;
use serde_json::Value;

use crate::policy::{LivePolicy, ServedPolicy};

/// The sentence for a call whose arguments carry something the tool's approved schema does
/// not declare. The call is not sent (draft 0011: the server is never trusted to check its own
/// scope, so it is never handed arguments nobody approved).
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
/// The check runs inside the audited run, so a refusal is recorded on the call's row with its
/// sentence, as outcome `refused`, and nothing is sent upstream.
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
        let checked = match adapter {
            Some(adapter) if !withdrawn => {
                adapter.check_arguments(call.arguments()).map_err(|error| {
                    // The path is the caller's own text, so only the tool goes in the sentence;
                    // the log has the rest.
                    match &error {
                        ArgumentError::Undeclared { path, .. } => tracing::warn!(
                            %tool,
                            path = path.as_str(),
                            "refused a call with an argument its tool does not declare"
                        ),
                        ArgumentError::NotAnObject { .. } => tracing::warn!(
                            %tool,
                            "refused a call whose arguments are not an object"
                        ),
                    }
                    undeclared_argument(tool.as_str())
                })
            }
            // Withdrawn from the policy served now. The request's own version always holds an
            // adapter for a tool its decision allowed.
            _ => Err(withdrawn_while_deciding(tool.as_str())),
        };
        match checked {
            Ok(()) => self.inner.run(call),
            Err(sentence) => Box::pin(std::future::ready(ToolOutcome::Refused(sentence))),
        }
    }
}
