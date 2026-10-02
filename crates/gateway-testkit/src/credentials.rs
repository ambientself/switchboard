//! A credential source that hands out labelled dummies, records who asked, and can refuse.

use std::sync::{Mutex, MutexGuard, PoisonError};

use gateway_core::{
    BoxFuture, ConnectorName, CredentialError, CredentialHandle, CredentialSource, Principal,
    PrincipalId, Proved, TeamId,
};

/// One request a [`FakeCredentialSource`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    /// The connector that asked.
    pub connector: ConnectorName,
    /// The proved caller it asked for.
    pub principal: PrincipalId,
    /// The caller's team, if it is a workload.
    pub team: Option<TeamId>,
    /// The label of what was issued, or `None` if the request was refused.
    pub issued: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Refusing {
    #[default]
    Never,
    Next,
    Always,
}

#[derive(Default)]
struct State {
    requests: Vec<CredentialRequest>,
    issued: usize,
    refusing: Refusing,
}

/// A [`CredentialSource`] with no secrets in it.
///
/// A credential it issues is labelled `fake-credential-for-<connector>-<team>-<n>`, where
/// `n` counts the credentials it has issued, from 1; for a user, whose credential is a
/// per-user grant, the team is replaced by `user-<subject>`. The label says what a real
/// credential would have been for, which is how a test shows a connector used the credential
/// of the caller's own team and no other. Every request is recorded, refused ones included.
#[derive(Default)]
pub struct FakeCredentialSource {
    state: Mutex<State>,
}

impl FakeCredentialSource {
    /// A source that issues.
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every request received, in order.
    pub fn requests(&self) -> Vec<CredentialRequest> {
        self.state().requests.clone()
    }

    /// The next request is refused, and later ones are issued.
    pub fn refuse_next(&self) {
        self.state().refusing = Refusing::Next;
    }

    /// Every request is refused until [`stop_refusing`](Self::stop_refusing).
    pub fn refuse_all(&self) {
        self.state().refusing = Refusing::Always;
    }

    /// Requests are issued again.
    pub fn stop_refusing(&self) {
        self.state().refusing = Refusing::Never;
    }
}

impl CredentialSource for FakeCredentialSource {
    fn credential_for<'a>(
        &'a self,
        connector: &'a ConnectorName,
        caller: &'a Proved<Principal>,
    ) -> BoxFuture<'a, Result<CredentialHandle, CredentialError>> {
        let principal = caller.get();
        let mut state = self.state();
        let refused = match state.refusing {
            Refusing::Never => false,
            Refusing::Next => {
                state.refusing = Refusing::Never;
                true
            }
            Refusing::Always => true,
        };
        let result = if refused {
            Err(CredentialError::Refused(
                "the fake credential source was told to refuse".into(),
            ))
        } else {
            state.issued += 1;
            let holder = match principal.team() {
                Some(team) => team.to_string(),
                None => format!("user-{}", principal.id.subject),
            };
            Ok(CredentialHandle::new(format!(
                "fake-credential-for-{connector}-{holder}-{}",
                state.issued
            )))
        };
        state.requests.push(CredentialRequest {
            connector: connector.clone(),
            principal: principal.id.clone(),
            team: principal.team().cloned(),
            issued: result.as_ref().ok().map(|handle| handle.label().to_owned()),
        });
        Box::pin(std::future::ready(result))
    }
}
