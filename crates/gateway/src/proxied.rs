//! What a proxied server's connector is wrapped in when the policy comes from the registry:
//! the resources a call names, and the check that refuses arguments a tool's approved schema
//! does not declare, both read from the policy served now.

use std::sync::Arc;

use gateway_core::{ApprovedTool, BoxFuture, Connector, Resources, ToolCall, ToolOutcome};
use gateway_registry::ArgumentError;
use serde_json::Value;

use crate::policy::LivePolicy;
use crate::resources::ResourceAdapter;

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

/// Names a call's resources with the argument adapter the registry approved for its tool.
///
/// A tool with no adapter in the policy served now, or arguments that are not an object, name
/// no resources: check 6 denies that for a tool that declares its resources, and it never
/// guesses.
pub(crate) struct RegistryResources {
    live: Arc<LivePolicy>,
}

impl RegistryResources {
    pub(crate) fn new(live: Arc<LivePolicy>) -> Self {
        Self { live }
    }
}

impl ResourceAdapter for RegistryResources {
    fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
        let policy = self.live.current();
        match (policy.arguments(&tool.name), arguments.as_object()) {
            (Some(adapter), Some(arguments)) => adapter.resources(arguments),
            _ => Resources::Named(Vec::new()),
        }
    }
}

/// A proxied server's connector, behind the registry's argument check.
///
/// The check runs inside the audited run, so a refusal is recorded on the call's row with its
/// sentence, as outcome `refused`, and nothing is sent upstream.
pub(crate) struct CheckedArguments {
    inner: Arc<dyn Connector>,
    live: Arc<LivePolicy>,
}

impl CheckedArguments {
    pub(crate) fn new(inner: Arc<dyn Connector>, live: Arc<LivePolicy>) -> Self {
        Self { inner, live }
    }
}

impl Connector for CheckedArguments {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let tool = call.tool().name.clone();
        let checked = match self.live.current().arguments(&tool) {
            None => Err(withdrawn_while_deciding(tool.as_str())),
            Some(adapter) => adapter.check_arguments(call.arguments()).map_err(|error| {
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
            }),
        };
        match checked {
            Ok(()) => self.inner.run(call),
            Err(sentence) => Box::pin(std::future::ready(ToolOutcome::Refused(sentence))),
        }
    }
}
