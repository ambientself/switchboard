//! Helpers shared by the integration tests. Each test file uses a different subset.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::future::{Future, ready as now};
use std::marker::PhantomData;
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use gateway_core::audit::{AuditRowId, RowCompletion, RowStart, StoreError};
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

/// A row identifier no other call in this test process has: the gateway chooses one per call,
/// and the core only carries it.
pub fn start() -> RowStart {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    RowStart {
        row: AuditRowId::new(format!("row-{}", NEXT.fetch_add(1, Ordering::Relaxed))),
    }
}

/// An audit store in memory, keeping rows by identifier in the order they were begun. Begin is
/// idempotent on the identifier as the interface says, comparing only the decision. Finish
/// accepts an identical repeat and refuses a different one. Either half can be told to fail.
#[derive(Default)]
pub struct MemoryStore {
    pub fail_begin: bool,
    pub fail_finish: bool,
    pub rows: Mutex<Vec<(AuditRowId, AuditRecord)>>,
}

impl MemoryStore {
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }

    pub fn ids(&self) -> Vec<AuditRowId> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn last(&self) -> AuditRecord {
        self.rows().pop().expect("no row was written")
    }
}

impl AuditStore for MemoryStore {
    fn begin<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let result = if self.fail_begin {
            Err("the store is down".into())
        } else {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter().find(|(id, _)| id == row) {
                Some((_, stored)) if stored.decision == record.decision => Ok(()),
                Some(_) => {
                    Err(format!("row {} was begun with another decision", row.as_str()).into())
                }
                None => {
                    rows.push((row.clone(), record.clone()));
                    Ok(())
                }
            }
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
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|(id, _)| id == completion.row()) {
                None => Err("no such row".into()),
                Some((_, row)) => match &row.completion {
                    None => {
                        row.completion = Some(completion.completion().clone());
                        Ok(())
                    }
                    Some(done) if done == completion.completion() => Ok(()),
                    Some(_) => Err("the row was already finished differently".into()),
                },
            }
        };
        Box::pin(now(result))
    }
}
