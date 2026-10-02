//! Proved and claimed values, and the verifier capability that is the only way to make a
//! proved one.
//!
//! # How `Proved` is sealed
//!
//! [`Proved<T>`] has a private field and no public constructor, no `Default`, no `From`, and no
//! `Deserialize`. The one way to obtain a `Proved` value from outside this module is
//! [`Proved::verify`], which runs a [`Verifier`] over its evidence and wraps what the
//! verifier returns. Inside the crate, the only other constructors are the projections at the
//! bottom of this file, which narrow an already proved value to one of its parts.
//!
//! Real verifiers live in later crates (an identity crate with one verifier per issuer type, a
//! delegation verifier for Otto's turn grants) and test fakes live in another, so the
//! capability cannot be private to this crate. Rust cannot restrict a constructor to a named
//! list of downstream crates, so the boundary is drawn where it can be seen instead: a crate
//! that wants to produce proved values must write `impl Verifier for ...`. That line is the
//! thing to look for in review, and it is enumerable. Code that merely holds a header value, a
//! [`Claimed`] value or a deserialized principal has no path to a `Proved` without writing one.
//!
//! What a verifier can prove is also closed. [`Verifier::Fact`] must be [`Provable`], which is
//! sealed and implemented only for [`Principal`] and [`Delegation`], the two values decision
//! 0006 says verifiers fill. A proved team or proved subject therefore exists only as a
//! projection of a proved principal or delegation; nobody can write a verifier that proves an
//! arbitrary team.
//!
//! A generic `map` on `Proved` is deliberately absent: `proved.map(|_| anything)` would
//! fabricate a proved value from any input.

use serde::{Deserialize, Serialize, Serializer};

use crate::names::{Person, TeamId};
use crate::principal::{Delegation, Principal};

/// A value the gateway verified, from a signed token or a signed delegation.
///
/// Only a [`Verifier`] can make one; see the [module documentation](self). Two proved values
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
