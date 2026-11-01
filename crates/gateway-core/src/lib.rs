//! The gateway's policy core.
//!
//! Principals, classification, the decision function, the policy snapshot, denial sentences
//! and the audit record. It performs no I/O: no clock, no network, no files, no database, and
//! it depends on no HTTP, MCP, database or async-runtime crate. That is what lets its tests run
//! in seconds with nothing else running.
//!
//! The interface is decision 0006, `docs/decisions/0006-what-the-decision-function-sees.md` in
//! this repository: [`decide`] takes a [`CallContext`] and returns a [`Decision`].
//!
//! Guarantees carried by types rather than by checks, each with compile-fail tests under
//! `tests/compile-fail`:
//!
//! - A [`Proved`] value can only be made by a [`Verifier`], so a [`Claimed`] value or a header
//!   cannot be passed where a proved one is required. See [`proof`] for what that does and
//!   does not establish.
//! - A [`Classification`] has no unset state, and an [`ApprovedTool`] cannot be built from
//!   text that has not been parsed into one.
//! - A denial's sentence, running a tool, and completing a row each require a value that only
//!   the step before can make, starting from the audit begin step. See [`audit`].

#![forbid(unsafe_code)]

pub mod audit;
mod canonical;
mod classification;
mod connector;
mod credential;
mod decision;
mod names;
mod policy;
mod principal;
pub mod proof;
pub mod receipt;
pub mod reconcile;
mod sentences;

pub use audit::{AuditGuard, AuditRecord, AuditStore, CredentialIdentity, GaveUp, give_up};
pub use classification::{Classification, UnrecognizedClassification};
pub use connector::{BoxFuture, Connector, ErrorKind, ToolCall, ToolOutcome};
pub use credential::{CredentialError, CredentialHandle, CredentialSource};
pub use decision::{
    CallContext, CallKey, CallerContext, Currency, CurrencyAnswer, Decision, DelegationProblem,
    Reason, ReasonKind, ResourceProblem, Verdict, decide, list_tools,
};
pub use names::{
    ConnectorName, DelegationIssuer, DeploymentName, ExceptionName, ExecutionId, GroupId,
    InstanceName, InvalidExceptionName, InvalidPodUid, InvalidToolName, Issuer, KeyId,
    MAX_EXCEPTION_NAME, MAX_TOOL_NAME, Person, PodUid, PolicyRevision, ProfileName, RequestedTool,
    SessionId, Subject, SurfaceName, TeamId, ToolName, ToolUseId, TurnId,
};
pub use policy::{
    Admitted, ApprovedTool, ConnectorEntry, CredentialMode, DeclaredFrom, EntryKind, Exception,
    Narrowing, PolicySnapshot, PrincipalRestriction, Profile, Resource, ResourceDeclaration,
    ResourceLimits, Resources, SnapshotData, SnapshotError, Surface,
};
pub use principal::{
    Delegation, DelegationDigest, DelegationFailure, DigestBeforeSignature, Egress,
    InvalidDelegationDigest, PresentedDelegation, Principal, PrincipalId, PrincipalKind,
    UnverifiedDelegation,
};
pub use proof::{Claimed, Provable, Proved, Verifier, WasProved};
pub use receipt::{
    ArgumentDigest, DelegationKeyScope, IdempotencyKey, InvalidIdempotencyKey, KeyScope,
    MAX_IDEMPOTENCY_KEY, Receipt, ReceiptState, Reuse, VendorReference,
};
pub use reconcile::{
    LeaseHolder, Lookup, LookupAnswer, LookupRecord, LookupRequest, ReceiptQueue, Recorded,
    Settlement, TargetKind,
};
pub use sentences::{IDENTITY_FAILURE, MAX_RENDERED, escape};
