//! A lookup by marker that answers what a test tells it, and records what it was asked.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use gateway_core::audit::{AuditRowId, RecordedResources};
use gateway_core::{BoxFuture, Lookup, LookupAnswer, LookupRequest, Resource, ToolName};

use crate::gate::Gate;

/// One lookup the fake was asked to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookedUp {
    /// The marker: the receipt's identifier.
    pub marker: AuditRowId,
    /// Where it was asked to look.
    pub target: Resource,
    /// The tool whose effect it looked for.
    pub tool: ToolName,
    /// The resources the call named.
    pub resources: RecordedResources,
}

struct State {
    looked_up: Vec<LookedUp>,
    next: VecDeque<LookupAnswer>,
    otherwise: LookupAnswer,
    gate: Option<Gate>,
}

/// A [`Lookup`] for tests. It sends nothing anywhere: it records each request, in order, and
/// answers the next of the answers it was given ([`then`](Self::then)), or, once they are used
/// up, the one it was made with. It can be held at a [`Gate`] to stand in for a slow vendor.
pub struct FakeLookup {
    state: Mutex<State>,
}

impl FakeLookup {
    /// A lookup that answers `answer` to every request.
    pub fn answering(answer: LookupAnswer) -> Self {
        Self {
            state: Mutex::new(State {
                looked_up: Vec::new(),
                next: VecDeque::new(),
                otherwise: answer,
                gate: None,
            }),
        }
    }

    /// The same lookup, answering `answers` first, in order.
    #[must_use]
    pub fn then(self, answers: impl IntoIterator<Item = LookupAnswer>) -> Self {
        self.state().next.extend(answers);
        self
    }

    /// From here on, every request answers `answer`, once any answers given with
    /// [`then`](Self::then) are used up.
    pub fn answer(&self, answer: LookupAnswer) {
        self.state().otherwise = answer;
    }

    /// Holds every request from here on at a gate, which is returned. A held request is
    /// recorded, and answered once the gate opens.
    pub fn hold(&self) -> Gate {
        let gate = Gate::closed();
        self.state().gate = Some(gate.clone());
        gate
    }

    /// Every request made, in order.
    pub fn looked_up(&self) -> Vec<LookedUp> {
        self.state().looked_up.clone()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Lookup for FakeLookup {
    fn look<'a>(&'a self, request: LookupRequest<'a>) -> BoxFuture<'a, LookupAnswer> {
        let (gate, answer) = {
            let mut state = self.state();
            state.looked_up.push(LookedUp {
                marker: request.marker.clone(),
                target: request.target.clone(),
                tool: request.tool.clone(),
                resources: request.resources.clone(),
            });
            let answer = state
                .next
                .pop_front()
                .unwrap_or_else(|| state.otherwise.clone());
            (state.gate.clone(), answer)
        };
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            answer
        })
    }
}
