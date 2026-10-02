//! A connector with three tools, that records what reaches it and can be told to fail or hang.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use gateway_core::{
    BoxFuture, Connector, ConnectorName, CredentialSource, PrincipalId, Resource, Resources,
    TeamId, ToolCall, ToolOutcome,
};
use serde_json::{Value, json};

use crate::clock::SteppableClock;
use crate::gate::Gate;

/// The connector's name in policy data and in audit rows.
pub const CONNECTOR: &str = "fixture";
/// A read tool: echoes its arguments and the credential it was given.
pub const READ_TOOL: &str = "fixture__read";
/// A write tool: records that a write happened.
pub const WRITE_TOOL: &str = "fixture__write";
/// A read tool that checks its own scope, and refuses a forbidden document when it runs.
pub const SCOPED_READ_TOOL: &str = "fixture__scoped_read";
/// The argument that names the document a call reaches.
pub const DOCUMENT_ARGUMENT: &str = "document";
/// The system a fixture resource belongs to.
pub const RESOURCE_SYSTEM: &str = "fixture";
/// The kind of resource a document is.
pub const RESOURCE_KIND: &str = "document";
/// The document the scoped tool refuses unless told otherwise.
pub const FORBIDDEN_DOCUMENT: &str = "restricted-notes";

/// One call that reached the connector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedCall {
    /// The tool the call ran.
    pub tool: String,
    /// The arguments it was given, as the caller sent them.
    pub arguments: Value,
    /// The proved caller.
    pub principal: PrincipalId,
    /// The caller's team, if it is a workload.
    pub team: Option<TeamId>,
}

/// One write the write tool performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRecord {
    /// The arguments the write was made with.
    pub arguments: Value,
    /// The label of the credential it was made under.
    pub credential: String,
    /// The proved caller.
    pub principal: PrincipalId,
}

#[derive(Clone, Debug, Default)]
enum Hang {
    #[default]
    Never,
    Next(Gate),
    All(Gate),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Failing {
    #[default]
    Never,
    Next,
    Always,
}

struct State {
    received: Vec<ReceivedCall>,
    writes: Vec<WriteRecord>,
    failing: Failing,
    hang: Hang,
    forbidden: BTreeSet<String>,
    work: Option<(SteppableClock, Duration)>,
}

/// A [`Connector`] serving [`READ_TOOL`], [`WRITE_TOOL`] and [`SCOPED_READ_TOOL`].
///
/// - Every call it receives is recorded first, before anything else it does, so a test can
///   show that a denied call never arrived: `received()` and `writes()` stay empty.
/// - It asks its [`CredentialSource`] for the caller's credential, as a real connector would,
///   and answers with an error if none is issued. The read tools echo the credential's label
///   back.
/// - The scoped tool refuses, with a sentence, a document it was told is forbidden. That is
///   the connector-side refusal the audit record calls `refused`.
/// - It can be told to fail, once or always, and to hang until a [`Gate`] opens. A hung call
///   has been received but has done nothing yet, so a held write has not happened.
pub struct FixtureConnector {
    credentials: Arc<dyn CredentialSource>,
    state: Mutex<State>,
}

impl FixtureConnector {
    /// A connector that gets credentials from `credentials`.
    pub fn new(credentials: Arc<dyn CredentialSource>) -> Self {
        Self {
            credentials,
            state: Mutex::new(State {
                received: Vec::new(),
                writes: Vec::new(),
                failing: Failing::Never,
                hang: Hang::Never,
                forbidden: BTreeSet::from([FORBIDDEN_DOCUMENT.to_owned()]),
                work: None,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every call received, in order, including ones that then failed or hung.
    pub fn received(&self) -> Vec<ReceivedCall> {
        self.state().received.clone()
    }

    /// Every write the write tool performed.
    pub fn writes(&self) -> Vec<WriteRecord> {
        self.state().writes.clone()
    }

    /// The scoped tool refuses `document` too.
    pub fn forbid(&self, document: &str) {
        self.state().forbidden.insert(document.to_owned());
    }

    /// The next call returns an error, and later ones work.
    pub fn fail_next(&self) {
        self.state().failing = Failing::Next;
    }

    /// Every call returns an error until [`stop_failing`](Self::stop_failing).
    pub fn fail_all(&self) {
        self.state().failing = Failing::Always;
    }

    /// Calls work again.
    pub fn stop_failing(&self) {
        self.state().failing = Failing::Never;
    }

    /// The next call hangs until the returned gate opens.
    pub fn hang_next(&self) -> Gate {
        let gate = Gate::closed();
        self.state().hang = Hang::Next(gate.clone());
        gate
    }

    /// Every call hangs until the returned gate opens.
    pub fn hang_all(&self) -> Gate {
        let gate = Gate::closed();
        self.state().hang = Hang::All(gate.clone());
        gate
    }

    /// Each call that completes moves `clock` forward by `duration` first, so a test measures
    /// a latency it chose without waiting for it.
    pub fn take_time(&self, clock: SteppableClock, duration: Duration) {
        self.state().work = Some((clock, duration));
    }

    /// What a resource adapter for these tools finds in a call's arguments, which the caller
    /// of the gateway puts in the call context. The read and write tools declare their
    /// resources, so a call that names no document names none, and is denied by the decision
    /// function. The scoped tool checks its own scope, so its resources are not known
    /// beforehand.
    pub fn resources_of(tool: &str, arguments: &Value) -> Resources {
        if tool == SCOPED_READ_TOOL {
            return Resources::Unknown;
        }
        let named = arguments
            .get(DOCUMENT_ARGUMENT)
            .and_then(Value::as_str)
            .map(document)
            .into_iter()
            .collect();
        Resources::Named(named)
    }
}

/// The resource a document is.
pub fn document(identifier: &str) -> Resource {
    Resource {
        system: RESOURCE_SYSTEM.to_owned(),
        kind: RESOURCE_KIND.to_owned(),
        identifier: identifier.to_owned(),
    }
}

impl Connector for FixtureConnector {
    fn run(&self, call: ToolCall) -> BoxFuture<'_, ToolOutcome> {
        let tool = call.tool().name.to_string();
        let arguments = call.arguments().clone();
        let caller = call.call().caller.principal.clone();
        let connector: ConnectorName = call.tool().connector.clone();

        // Recorded before anything else, and before the future is first polled: a call that
        // was handed to this connector is on the record whatever it then does.
        let (hang, fail, forbidden, work) = {
            let mut state = self.state();
            state.received.push(ReceivedCall {
                tool: tool.clone(),
                arguments: arguments.clone(),
                principal: caller.get().id.clone(),
                team: caller.get().team().cloned(),
            });
            let hang = match &state.hang {
                Hang::Never => None,
                Hang::All(gate) => Some(gate.clone()),
                Hang::Next(gate) => {
                    let gate = gate.clone();
                    state.hang = Hang::Never;
                    Some(gate)
                }
            };
            let fail = match state.failing {
                Failing::Never => false,
                Failing::Next => {
                    state.failing = Failing::Never;
                    true
                }
                Failing::Always => true,
            };
            (hang, fail, state.forbidden.clone(), state.work.clone())
        };

        Box::pin(async move {
            if let Some(gate) = hang {
                gate.wait().await;
            }
            if fail {
                return ToolOutcome::Error("the fixture connector was told to fail".into());
            }
            let credential = match self.credentials.credential_for(&connector, &caller).await {
                Ok(handle) => handle.label().to_owned(),
                Err(_) => {
                    return ToolOutcome::Error(
                        "the fixture connector could not get a credential".into(),
                    );
                }
            };
            if let Some((clock, duration)) = work {
                clock.advance(duration);
            }
            match tool.as_str() {
                READ_TOOL => ToolOutcome::Ok(echo(&tool, &arguments, &credential)),
                WRITE_TOOL => {
                    self.state().writes.push(WriteRecord {
                        arguments: arguments.clone(),
                        credential: credential.clone(),
                        principal: caller.get().id.clone(),
                    });
                    ToolOutcome::Ok(
                        json!({"tool": tool, "written": true, "credential": credential}),
                    )
                }
                SCOPED_READ_TOOL => {
                    let named = arguments.get(DOCUMENT_ARGUMENT).and_then(Value::as_str);
                    match named.filter(|name| forbidden.contains(*name)) {
                        // Echoes the document only because it is one the connector itself
                        // was told is forbidden, never text the caller chose.
                        Some(name) => ToolOutcome::Refused(format!(
                            "The fixture connector refused this call: the document `{name}` is outside the scope of the caller's team."
                        )),
                        None => ToolOutcome::Ok(echo(&tool, &arguments, &credential)),
                    }
                }
                _ => ToolOutcome::Error(format!("the fixture connector has no tool `{tool}`")),
            }
        })
    }
}

fn echo(tool: &str, arguments: &Value, credential: &str) -> Value {
    json!({"tool": tool, "echo": arguments, "credential": credential})
}
