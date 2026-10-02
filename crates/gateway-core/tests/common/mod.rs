//! Helpers shared by the integration tests. Each test file uses a different subset.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::future::{Future, ready as now};
use std::marker::PhantomData;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use gateway_core::audit::{AuditRowId, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture, Provable, Proved, ToolName, Verifier};

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

/// A tool name the test knows is valid.
pub fn tool_name(name: &str) -> ToolName {
    ToolName::parse(name).unwrap()
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

/// An audit store in memory. Row identifiers are positions, so a test can see which row a
/// write reached. Either half can be told to fail.
#[derive(Default)]
pub struct MemoryStore {
    pub fail_begin: bool,
    pub fail_finish: bool,
    pub rows: Mutex<Vec<AuditRecord>>,
}

impl MemoryStore {
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.rows.lock().unwrap().clone()
    }

    pub fn last(&self) -> AuditRecord {
        self.rows().pop().expect("no row was written")
    }
}

impl AuditStore for MemoryStore {
    fn begin<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        let result = if self.fail_begin {
            Err("the store is down".into())
        } else {
            let mut rows = self.rows.lock().unwrap();
            rows.push(record.clone());
            Ok(AuditRowId::new((rows.len() - 1).to_string()))
        };
        Box::pin(now(result))
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let result = if self.fail_finish {
            Err("the store is down".into())
        } else {
            let index: usize = completion.row().as_str().parse().unwrap();
            let mut rows = self.rows.lock().unwrap();
            let row = &mut rows[index];
            assert!(row.completion.is_none(), "row {index} finished twice");
            row.completion = Some(completion.completion().clone());
            Ok(())
        };
        Box::pin(now(result))
    }
}
