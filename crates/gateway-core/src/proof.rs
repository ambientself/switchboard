//! Proved and claimed values, and the verifier capability that is the only way to make a
//! proved one.
//!
//! # What sealing `Proved` does, and what it does not
//!
//! [`Proved<T>`] has a private field and no public constructor, no `Default`, no `From` and no
//! `Deserialize`. Outside this module, the one way to obtain a `Proved` value is
//! [`Proved::verify`], which runs a [`Verifier`] over its evidence and wraps what the verifier
//! returns. Inside the crate, the only other constructors are the projections at the bottom of
//! this file, which narrow an already proved value to one of its parts. There is no generic
//! `map`, because `proved.map(|_| anything)` would fabricate a proved value from any input.
//!
//! What a verifier can prove is closed: [`Verifier::Fact`] must be [`Provable`], which is
//! sealed and implemented only for [`Principal`] and [`Delegation`]. A proved team therefore
//! exists only as part of a proved principal or delegation.
//!
//! That is all the type system gives. **A `Verifier` implementation can return a principal
//! with any issuer, subject, team or groups it likes**, and the types will call it proved.
//! Nothing here ties a verifier to the issuer it was configured for, or checks that it looked
//! at a signature at all. Real verifiers live in later crates and test fakes in another, so
//! the capability cannot be private to this crate, and Rust cannot restrict a trait to a list
//! of implementing crates. The control is therefore review: every `impl Verifier for` in the
//! workspace is a place where proof is created, and each one has to be read.
//!
//! What sealing does buy is that code which merely holds a header value, a [`Claimed`] value
//! or a deserialized principal has no path to a `Proved` without writing such an impl.

use serde::{Deserialize, Serialize, Serializer};

use crate::names::{Person, TeamId};
use crate::principal::{Delegation, Principal};

/// A value a [`Verifier`] accepted, from a signed token or a signed delegation.
///
/// Only a verifier can make one; see the [module documentation](self) for what that does and
/// does not guarantee. Two proved values
/// compare equal when their contents do. A proved value never compares equal to a claimed one,
/// because no comparison between the two types exists: code that wants to compare them has to
/// unwrap both with [`get`](Proved::get) and say so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proved<T>(T);

impl<T> Proved<T> {
    /// The verified value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// Gives up the proof and returns the plain value. There is no way back.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Provable> Proved<T> {
    /// Runs `verifier` over `evidence` and, if it succeeds, holds the result as proved.
    ///
    /// This is the only public way to construct a `Proved` value.
    pub fn verify<V>(verifier: &V, evidence: &V::Evidence) -> Result<Self, V::Error>
    where
        V: Verifier<Fact = T> + ?Sized,
    {
        verifier.verify(evidence).map(Proved)
    }
}

// Serialized as the bare value: whether a column is proved or claimed is carried by which
// column it is, so the audit record keeps the two in separate fields rather than tagging each
// value.
impl<T: Serialize> Serialize for Proved<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// A value the caller stated and the gateway did not verify, such as a team in a header or the
/// person a delegation names.
///
/// Anyone can make one, and nothing converts a `Claimed` into a [`Proved`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Claimed<T>(T);

impl<T> Claimed<T> {
    /// Records `value` as claimed.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The claimed value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// The plain value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::principal::Principal {}
    impl Sealed for crate::principal::Delegation {}
}

/// A value a [`Verifier`] may prove. Sealed: implemented for [`Principal`] and [`Delegation`]
/// only.
pub trait Provable: sealed::Sealed {}

impl Provable for Principal {}
impl Provable for Delegation {}

/// The capability to turn evidence into a proved fact.
///
/// Implementing this trait is the act of becoming a verifier, and is the only way code outside
/// this crate can produce a [`Proved`] value. See the [module documentation](self) for why the
/// boundary is drawn here and what to check in review.
///
/// Verification is synchronous: section 7 of the design makes it offline, with signing keys
/// fetched and cached before a token is checked, not while it is.
pub trait Verifier {
    /// What the verifier checks, such as a token's bytes.
    type Evidence: ?Sized;
    /// What a successful check establishes.
    type Fact: Provable;
    /// Why a check failed.
    type Error;

    /// Checks `evidence` and returns the fact it establishes, or why it does not.
    fn verify(&self, evidence: &Self::Evidence) -> Result<Self::Fact, Self::Error>;
}

impl Proved<Principal> {
    /// The workload's team, still proved, or `None` for a user.
    pub fn team(&self) -> Option<Proved<TeamId>> {
        self.0.team().cloned().map(Proved)
    }
}

impl Proved<Delegation> {
    /// The team the delegation was issued for. The signature covers it, so it is proved.
    pub fn team(&self) -> Proved<TeamId> {
        Proved(self.0.team.clone())
    }

    /// The person the delegation names. Only attested by the delegating control plane, so it
    /// stays claimed.
    pub fn acting_person(&self) -> Claimed<Person> {
        self.0.acting_person.clone()
    }
}

/// A value that was proved when an audit row was written, as read back from the row.
///
/// Reading a row is not verification, so a row's proved columns come back as this type: not
/// [`Proved`], which only a verifier can make, and not [`Claimed`], which would erase the
/// difference between the columns. It converts from a `Proved` value and never into one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WasProved<T>(T);

impl<T> WasProved<T> {
    /// The value as it was proved.
    pub fn get(&self) -> &T {
        &self.0
    }
}

impl<T> From<Proved<T>> for WasProved<T> {
    fn from(proved: Proved<T>) -> Self {
        Self(proved.0)
    }
}
