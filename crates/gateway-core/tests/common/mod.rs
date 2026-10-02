//! Helpers shared by the integration tests. Each test file uses a different subset.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use gateway_core::{Provable, Proved, Verifier};

/// A stand-in verifier that accepts its fixture as given.
///
/// This is the route a test-fakes crate will take, and it is deliberately the same route a
/// real verifier takes: `impl Verifier`. There is no back door for tests.
pub struct FixtureVerifier<T>(PhantomData<T>);

impl<T: Provable + Clone> Verifier for FixtureVerifier<T> {
    type Evidence = T;
    type Fact = T;
    type Error = Infallible;

    fn verify(&self, evidence: &T) -> Result<T, Infallible> {
        Ok(evidence.clone())
    }
}

/// `fact`, as a fixture verifier proves it.
pub fn proved<T: Provable + Clone>(fact: &T) -> Proved<T> {
    match Proved::verify(&FixtureVerifier(PhantomData), fact) {
        Ok(proved) => proved,
        Err(never) => match never {},
    }
}

/// Runs a future that is ready without waiting, as every in-memory store here is. The core
/// depends on no async runtime, so its tests do not either.
pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("an in-memory future was not ready"),
    }
}
