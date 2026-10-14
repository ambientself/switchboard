//! Helpers shared by the integration tests. Each test file uses a different subset.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::future::{Future, ready as now};
use std::marker::PhantomData;
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use gateway_core::audit::{
    AuditRowId, DecisionKind, ListRecord, Outcome, RowCompletion, RowStart, StoreError,
};
use gateway_core::receipt::{EstablishedBy, ReceiptRequest, Reservation, may_move};
use gateway_core::{
    AuditRecord, AuditStore, BoxFuture, IdempotencyKey, Provable, Proved, Receipt, ReceiptState,
    Reuse, ToolName, Verifier,
};

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

/// The instance every [`start`] names.
pub const INSTANCE: &str = "test-instance";

/// The call deadline every [`start`] gives, in milliseconds.
pub const CALL_DEADLINE_MS: u64 = 5_000;

/// A row identifier no other call in this test process has: the gateway chooses one per call,
/// and the core only carries it. With [`INSTANCE`] and [`CALL_DEADLINE_MS`].
pub fn start() -> RowStart {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    RowStart {
        row: AuditRowId::new(format!("row-{}", NEXT.fetch_add(1, Ordering::Relaxed))),
        instance: INSTANCE.into(),
        call_deadline_ms: CALL_DEADLINE_MS,
        credential: None,
    }
}

/// An idempotency key no other call in this test process has: the caller chooses one per call.
pub fn fresh_key() -> IdempotencyKey {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    IdempotencyKey::parse(&format!("key-{}", NEXT.fetch_add(1, Ordering::Relaxed))).unwrap()
}

/// An audit store in memory, keeping rows by identifier in the order they were begun. Begin is
/// idempotent on the identifier as the interface says, comparing only the decision. Finish
/// accepts an identical repeat and refuses a different one. Either half can be told to fail.
/// List rows are kept apart, idempotent on the identifier too, and fail with begin.
///
/// It keeps receipts as the interface says (decision 0009, part 2): a begin with a receipt
/// checks the key's scope for a receipt under another row, and either writes the row complete
/// with the answer or writes it open and reserves the receipt, all under one lock; finish
/// settles the row's receipt with the row's completion. Its receipts are never past a deadline:
/// it keeps none.
#[derive(Default)]
pub struct MemoryStore {
    pub fail_begin: bool,
    pub fail_finish: bool,
    pub rows: Mutex<Vec<(AuditRowId, AuditRecord)>>,
    pub list_rows: Mutex<Vec<(AuditRowId, ListRecord)>>,
    pub receipts: Mutex<Vec<Receipt>>,
    /// The answer each row written as the answer to a reused key was written with.
    pub reused: Mutex<Vec<(AuditRowId, Reuse)>>,
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

    pub fn list_rows(&self) -> Vec<(AuditRowId, ListRecord)> {
        self.list_rows.lock().unwrap().clone()
    }

    pub fn receipts(&self) -> Vec<Receipt> {
        self.receipts.lock().unwrap().clone()
    }

    /// The receipt reserved under `row`, if one was.
    pub fn receipt(&self, row: &AuditRowId) -> Option<Receipt> {
        self.receipts()
            .into_iter()
            .find(|receipt| receipt.row == *row)
    }

    fn begin_with_receipt_now(
        &self,
        row: &AuditRowId,
        record: &AuditRecord,
        request: &ReceiptRequest,
    ) -> Result<Reservation, StoreError> {
        if self.fail_begin {
            return Err("the store is down".into());
        }
        if record.decision != DecisionKind::Allow {
            return Err("a denial reserves no receipt".into());
        }
        let mut rows = self.rows.lock().unwrap();
        let mut receipts = self.receipts.lock().unwrap();
        let mut reused = self.reused.lock().unwrap();
        if self
            .list_rows
            .lock()
            .unwrap()
            .iter()
            .any(|(id, _)| id == row)
        {
            return Err(format!("row {} is a list row", row.as_str()).into());
        }
        if let Some((_, stored)) = rows.iter().find(|(id, _)| id == row) {
            if stored.decision != record.decision {
                return Err(format!("row {} was begun with another decision", row.as_str()).into());
            }
            if let Some((_, reuse)) = reused.iter().find(|(id, _)| id == row) {
                return Ok(Reservation::Reused(reuse.clone()));
            }
            return match receipts.iter().find(|receipt| receipt.row == *row) {
                Some(receipt) if receipt.state == ReceiptState::Pending => {
                    Ok(Reservation::Reserved)
                }
                Some(_) => {
                    Err("the row's receipt has left pending; its call must not run again".into())
                }
                None => Err("the row was begun with no receipt".into()),
            };
        }
        let earlier = receipts
            .iter()
            .find(|receipt| receipt.row != *row && request.same_key(receipt));
        if let Some(earlier) = earlier {
            let reuse = Reuse::answer(request, earlier);
            let mut complete = record.clone();
            complete.completion = Some(reuse.completion());
            rows.push((row.clone(), complete));
            reused.push((row.clone(), reuse.clone()));
            return Ok(Reservation::Reused(reuse));
        }
        rows.push((row.clone(), record.clone()));
        receipts.push(request.reserve(row));
        Ok(Reservation::Reserved)
    }

    fn finish_now(&self, completion: &RowCompletion) -> Result<(), StoreError> {
        if self.fail_finish {
            return Err("the store is down".into());
        }
        let mut rows = self.rows.lock().unwrap();
        let mut receipts = self.receipts.lock().unwrap();
        let receipt = receipts
            .iter_mut()
            .find(|receipt| receipt.row == *completion.row());
        let outcome = &completion.completion().outcome;
        let Some(settled) = ReceiptState::settled_by(outcome) else {
            return Err("a duplicate is written at begin, never by finish".into());
        };
        if receipt.is_none() && *outcome == Outcome::Unknown {
            return Err("a row with no receipt cannot be unknown".into());
        }
        if receipt.is_none() && completion.reference().is_some() {
            return Err("a row with no receipt has no vendor reference to keep".into());
        }
        match rows.iter_mut().find(|(id, _)| id == completion.row()) {
            None => return Err("no such row".into()),
            Some((_, row)) => match &row.completion {
                None => row.completion = Some(completion.completion().clone()),
                Some(done) if done == completion.completion() => {}
                Some(_) => return Err("the row was already finished differently".into()),
            },
        }
        // It keeps no deadlines, so no receipt of its is ever past one.
        if let Some(receipt) = receipt
            && may_move(receipt.state, settled, &EstablishedBy::Call, false)
        {
            receipt.state = settled;
            receipt.established_by = EstablishedBy::Call;
            receipt.reference = completion.reference().cloned();
        }
        Ok(())
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
            let listed = self
                .list_rows
                .lock()
                .unwrap()
                .iter()
                .any(|(id, _)| id == row);
            match rows.iter().find(|(id, _)| id == row) {
                _ if listed => Err(format!("row {} is a list row", row.as_str()).into()),
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

    fn begin_with_receipt<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
        receipt: &'a ReceiptRequest,
    ) -> BoxFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(now(self.begin_with_receipt_now(row, record, receipt)))
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(now(self.finish_now(completion)))
    }

    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let result = if self.fail_begin {
            Err("the store is down".into())
        } else if self.rows.lock().unwrap().iter().any(|(id, _)| id == row) {
            Err(format!("row {} is a call row", row.as_str()).into())
        } else {
            let mut rows = self.list_rows.lock().unwrap();
            if !rows.iter().any(|(id, _)| id == row) {
                rows.push((row.clone(), record.clone()));
            }
            Ok(())
        };
        Box::pin(now(result))
    }
}
