//! The gateway's policy core.
//!
//! Principals, classification, the decision function, the policy snapshot, denial sentences
//! and the audit record. It performs no I/O: no clock, no network, no files, no database, and
//! it depends on no HTTP, MCP, database or async-runtime crate. That is what lets its tests run
//! in seconds with nothing else running.
//!
//! The interface is [decision 0006](https://github.com/ambientself/switchboard/blob/main/docs/decisions/0006-what-the-decision-function-sees.md):
//! [`decide`] takes a [`CallContext`] and returns a [`Decision`].
//!
//! Three guarantees are carried by types rather than by checks, and each has a compile-fail
//! test under `tests/compile-fail`:
//!
//! - A [`Proved`] value can only be made by a [`Verifier`], so a [`Claimed`] value or a header
//!   cannot be passed where a proved one is required. See [`proof`].
//! - A [`Classification`] has no unset state, and an [`ApprovedTool`] cannot be built from
//!   text that has not been parsed into one.
//! - Running a tool requires an [`AuditGuard`], which only [`audit::begin`] returns, after the
//!   audit row is written. See [`audit`].

#![forbid(unsafe_code)]

pub mod audit;
mod classification;
mod connector;
mod decision;
mod names;
mod policy;
mod principal;
pub mod proof;
pub mod sentences;

pub use audit::{AuditGuard, AuditRecord, AuditStore};
pub use classification::{Classification, UnrecognizedClassification};
pub use connector::Connector;
pub use decision::{
    CallContext, CallerContext, Decision, DelegationProblem, Reason, ReasonKind, ResourceProblem,
    Verdict, decide, list_tools,
};
pub use names::{
    ConnectorName, DeploymentName, GroupId, Issuer, Person, PolicyRevision, ProfileName, Subject,
    SurfaceName, TeamId, ToolName, ToolUseId,
};
pub use policy::{
    ApprovedTool, PolicySnapshot, Profile, Resource, ResourceLimits, Resources, SnapshotData,
    SnapshotError, Surface,
};
pub use principal::{Delegation, Principal, PrincipalId, PrincipalKind};
pub use proof::{Claimed, Provable, Proved, Verifier};
