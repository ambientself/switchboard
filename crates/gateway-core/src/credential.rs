//! The interface for asking the gateway's credential broker for a credential.
//!
//! The caller never holds a downstream credential (design section 9, invariant 2): the gateway
//! holds it, per team, and a connector asks for one when it runs. This module states only the
//! question and what comes back; where credentials are kept, and how they are narrowed or
//! exchanged, belongs to the crates that implement [`CredentialSource`].
//!
//! The question takes a [`Proved<Principal>`](crate::Proved), so a connector cannot ask on
//! behalf of a team a caller merely claimed: the argument that reaches it came from a
//! verifier, through the decision, the audit guard and the [`ToolCall`](crate::ToolCall).

use std::fmt;

use thiserror::Error;

use crate::connector::BoxFuture;
use crate::names::ConnectorName;
use crate::principal::Principal;
use crate::proof::Proved;

/// Where a connector gets the credential it runs a call with.
///
/// Usable as `dyn CredentialSource`, so one source can be shared by every connector.
pub trait CredentialSource: Send + Sync {
    /// The credential `connector` should use for a call by `caller`: the team's service
    /// identity for a workload, or the user's own grant for a user.
    ///
    /// An `Err` means no credential was issued, and the connector must not run the call.
    fn credential_for<'a>(
        &'a self,
        connector: &'a ConnectorName,
        caller: &'a Proved<Principal>,
    ) -> BoxFuture<'a, Result<CredentialHandle, CredentialError>>;
}

/// A reference to a credential the gateway holds, for one call.
///
/// Opaque on purpose: it is never the caller's own token (invariant 3), and its [`Debug`]
/// output is its label, never anything secret. The label names what was issued, for logs and
/// tests; a source that holds real secret material carries it beside the label in its own
/// type, which this crate does not need to know about.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialHandle {
    label: String,
}

impl CredentialHandle {
    /// A handle with a label that is safe to log.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    /// The label: which credential this is, never its contents.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CredentialHandle")
            .field(&self.label)
            .finish()
    }
}

/// Why a credential was not issued.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum CredentialError {
    /// The source declined to issue one for this connector and caller.
    #[error("the credential source refused: {0}")]
    Refused(String),
    /// The source could not be reached or could not answer.
    #[error("the credential source is unavailable: {0}")]
    Unavailable(String),
}
