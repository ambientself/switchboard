//! A connector with four tools, that records what reaches it and can be told to fail or hang.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use gateway_core::{
    BoxFuture, Connector, ConnectorName, CredentialSource, GroupId, PrincipalId, PrincipalKind,
    Resource, Resources, TeamId, ToolCall, ToolOutcome,
};
use serde_json::{Value, json};

use crate::clock::SteppableClock;
use crate::fixture::{GROUP_G, GROUP_G_DOCUMENT, TEAM_A, TEAM_A_DOCUMENT, TEAM_B, TEAM_B_DOCUMENT};
use crate::gate::Gate;

/// The connector's name in policy data and in audit rows.
pub const CONNECTOR: &str = "fixture";
/// A read tool: echoes its arguments and the credential it was given.
pub const READ_TOOL: &str = "fixture__read";
/// A `propose` tool: opens a draft against a document for a person to review, or revises a
/// draft it opened, and refuses any other draft when it runs.
pub const DRAFT_TOOL: &str = "fixture__draft";
/// A direct write: records that a document was changed. Classified `write`, so the decision
/// function denies it in every profile and it never reaches the connector.
pub const WRITE_TOOL: &str = "fixture__write";
/// A read tool that checks its own scope, and refuses a document outside the caller's scope
/// when it runs.
pub const SCOPED_READ_TOOL: &str = "fixture__scoped_read";
/// The argument that names the document a call reaches.
pub const DOCUMENT_ARGUMENT: &str = "document";
/// The argument that names the draft a call to [`DRAFT_TOOL`] revises. A call without it opens a
/// new draft.
pub const DRAFT_ARGUMENT: &str = "draft";
/// A draft the gateway did not open, such as one a person opened. The draft tool refuses it.
pub const FOREIGN_DRAFT: &str = "draft-by-a-person";
/// The system a fixture resource belongs to.
pub const RESOURCE_SYSTEM: &str = "fixture";
/// The kind of resource a document is.
pub const RESOURCE_KIND: &str = "document";
/// A document in no caller's scope, which the scoped tool refuses unless told otherwise.
pub const FORBIDDEN_DOCUMENT: &str = "restricted-notes";
/// The sentence the scoped tool refuses with. It does not repeat the document, which is text
/// the caller chose.
pub const SCOPE_REFUSAL: &str =
    "The fixture connector refused this call: the document it names is outside the caller's scope.";
/// The sentence the draft tool refuses with. It does not repeat the draft, which is text the
/// caller chose.
pub const DRAFT_REFUSAL: &str = "The fixture connector refused this call: the draft it names was not opened by the gateway for the document the call names.";

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

/// One write a tool performed: a draft the draft tool opened or revised, or a direct write. The
/// design calls both a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRecord {
    /// The tool that made it.
    pub tool: String,
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
    /// The drafts the draft tool opened, each with the document it was opened against.
    drafts: BTreeMap<String, Option<String>>,
    failing: Failing,
    hang: Hang,
    team_scopes: BTreeMap<TeamId, BTreeSet<String>>,
    group_scopes: BTreeMap<GroupId, BTreeSet<String>>,
    work: Option<(SteppableClock, Duration)>,
}

/// A [`Connector`] serving [`READ_TOOL`], [`DRAFT_TOOL`], [`WRITE_TOOL`] and
/// [`SCOPED_READ_TOOL`].
///
/// - Every call it receives is recorded first, before anything else it does, so a test can
///   show that a denied call never arrived: `received()` and `writes()` stay empty.
/// - It asks its [`CredentialSource`] for the caller's credential, as a real connector would,
///   and answers with an error if none is issued. The read tools echo the credential's label
///   back.
/// - The draft tool acts only on what the gateway created, as a `propose` tool must (design
///   section 8). A call that names no draft opens one, `draft-1`, `draft-2` and so on, against
///   the document the call names. A call that names a draft revises it only if this connector
///   opened it against the same document, and is refused with [`DRAFT_REFUSAL`] otherwise:
///   [`FOREIGN_DRAFT`], a draft not yet opened, or another document's draft. The document is
///   checked against the caller's limit by the decision function, so a team cannot revise
///   another team's draft. Opening and revising each record a write.
/// - The write tool is never reached through the fixture policy, because the decision function
///   denies a `write` tool in every profile. It records a write the same way the draft tool
///   does, so a write that did reach it would show in `writes()`.
/// - The scoped tool serves a document only to a caller whose scope holds it, and refuses any
///   other with [`SCOPE_REFUSAL`]. That is the connector-side refusal the audit record calls
///   `refused`. A workload's scope is its team's documents; a user's is the documents of all
///   of its groups. To begin with, each team and group G hold their own document from the
///   fixture policy, and [`FORBIDDEN_DOCUMENT`] is in no one's scope. A call that names no
///   document is served.
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
                drafts: BTreeMap::new(),
                failing: Failing::Never,
                hang: Hang::Never,
                team_scopes: BTreeMap::from([
                    (TEAM_A.into(), BTreeSet::from([TEAM_A_DOCUMENT.to_owned()])),
                    (TEAM_B.into(), BTreeSet::from([TEAM_B_DOCUMENT.to_owned()])),
                ]),
                group_scopes: BTreeMap::from([(
                    GROUP_G.into(),
                    BTreeSet::from([GROUP_G_DOCUMENT.to_owned()]),
                )]),
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

    /// Every write performed, by the draft tool or the write tool, in order.
    pub fn writes(&self) -> Vec<WriteRecord> {
        self.state().writes.clone()
    }

    /// The scoped tool serves `document` to `team`'s workloads too.
    pub fn grant_to_team(&self, team: &str, document: &str) {
        self.state()
            .team_scopes
            .entry(team.into())
            .or_default()
            .insert(document.to_owned());
    }

    /// The scoped tool serves `document` to users in `group` too.
    pub fn grant_to_group(&self, group: &str, document: &str) {
        self.state()
            .group_scopes
            .entry(group.into())
            .or_default()
            .insert(document.to_owned());
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
    /// of the gateway puts in the call context. The read, draft and write tools declare their
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
        let (hang, fail, scope, work) = {
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
            // What the caller may reach through the scoped tool, read now so that a held call
            // is checked against the scope it was received under.
            let scope: BTreeSet<String> = match &caller.get().kind {
                PrincipalKind::Workload { team } => {
                    state.team_scopes.get(team).cloned().unwrap_or_default()
                }
                PrincipalKind::User { groups } => groups
                    .iter()
                    .filter_map(|group| state.group_scopes.get(group))
                    .flatten()
                    .cloned()
                    .collect(),
            };
            (hang, fail, scope, state.work.clone())
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
            let write = WriteRecord {
                tool: tool.clone(),
                arguments: arguments.clone(),
                credential: credential.clone(),
                principal: caller.get().id.clone(),
            };
            match tool.as_str() {
                READ_TOOL => ToolOutcome::Ok(echo(&tool, &arguments, &credential)),
                DRAFT_TOOL => match self.draft(&arguments) {
                    Some(draft) => {
                        self.record(write);
                        ToolOutcome::Ok(
                            json!({"tool": tool, "draft": draft, "credential": credential}),
                        )
                    }
                    None => ToolOutcome::Refused(DRAFT_REFUSAL.to_owned()),
                },
                WRITE_TOOL => {
                    self.record(write);
                    ToolOutcome::Ok(
                        json!({"tool": tool, "written": true, "credential": credential}),
                    )
                }
                SCOPED_READ_TOOL => {
                    let named = arguments.get(DOCUMENT_ARGUMENT).and_then(Value::as_str);
                    match named.filter(|name| !scope.contains(*name)) {
                        Some(_) => ToolOutcome::Refused(SCOPE_REFUSAL.to_owned()),
                        None => ToolOutcome::Ok(echo(&tool, &arguments, &credential)),
                    }
                }
                _ => ToolOutcome::Error(format!("the fixture connector has no tool `{tool}`")),
            }
        })
    }
}

impl FixtureConnector {
    /// The draft a call to the draft tool opens or revises, or `None` if it names a draft this
    /// connector did not open against the document the call names.
    fn draft(&self, arguments: &Value) -> Option<String> {
        let document = arguments
            .get(DOCUMENT_ARGUMENT)
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = self.state();
        match arguments.get(DRAFT_ARGUMENT) {
            None => {
                let draft = format!("draft-{}", state.drafts.len() + 1);
                state.drafts.insert(draft.clone(), document);
                Some(draft)
            }
            Some(named) => named
                .as_str()
                .filter(|draft| state.drafts.get(*draft) == Some(&document))
                .map(str::to_owned),
        }
    }

    fn record(&self, write: WriteRecord) {
        self.state().writes.push(write);
    }
}

fn echo(tool: &str, arguments: &Value, credential: &str) -> Value {
    json!({"tool": tool, "echo": arguments, "credential": credential})
}
