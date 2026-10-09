//! An audit store in memory that a test can read back and tell to fail or to wait.

use std::sync::{Mutex, MutexGuard, PoisonError};

use gateway_core::audit::{AuditRowId, RowCompletion, RowStart, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};
use rand_core::{OsRng, RngCore};

use crate::gate::Gate;

/// A row start with a fresh identifier, for a test that calls the core's `audit::begin` itself
/// rather than through the gateway, which makes one per call.
///
/// The identifier is a random UUID (version 4) in the lowercase hyphenated form, so every
/// store accepts it, the Postgres store included, which refuses an identifier that is not a
/// UUID. The gateway's own are UUIDv7s; a test needs only one no other row has.
pub fn row_start() -> RowStart {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    RowStart {
        row: AuditRowId::new(format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32]
        )),
    }
}

/// Whether the next operations of one kind fail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Failing {
    #[default]
    Never,
    Next,
    Always,
}

impl Failing {
    /// Whether this operation fails, and what the setting becomes afterwards.
    fn take(&mut self) -> bool {
        match self {
            Failing::Never => false,
            Failing::Next => {
                *self = Failing::Never;
                true
            }
            Failing::Always => true,
        }
    }
}

#[derive(Default)]
struct State {
    rows: Vec<(AuditRowId, AuditRecord)>,
    begin_attempts: usize,
    finish_attempts: usize,
    begin_failing: Failing,
    finish_failing: Failing,
    begin_gate: Option<Gate>,
    finish_gate: Option<Gate>,
}

/// An [`AuditStore`] that keeps its rows in memory, in the order they were begun.
///
/// It behaves as the interface says a store must. A row exists only once `begin` has returned
/// `Ok`: a failed begin leaves nothing behind, and a begin that is being held has not written
/// yet. A failed `finish` leaves the row as it was, with its outcome empty. A row cannot be
/// finished before it was begun.
///
/// Rows are kept under the identifier begin was given. A second begin with a known identifier
/// writes nothing: it succeeds if the stored decision is the same, and fails if it differs. It
/// compares the decision and nothing more, as the Postgres store can. A second finish
/// succeeds if it is identical to the completion the row has, and otherwise fails and leaves
/// the first completion standing.
///
/// Both operations can be told to fail, once or until told otherwise, and both can be held
/// at a [`Gate`] to stand in for a slow database without a real sleep.
#[derive(Default)]
pub struct InMemoryAuditStore {
    state: Mutex<State>,
}

impl InMemoryAuditStore {
    /// An empty store that works.
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every row, in the order its begin was written, with its completion once finished.
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.state()
            .rows
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// The row at `position` in the order written.
    pub fn row(&self, position: usize) -> Option<AuditRecord> {
        self.state()
            .rows
            .get(position)
            .map(|(_, record)| record.clone())
    }

    /// The row stored under `id`, if begin wrote one.
    pub fn row_with_id(&self, id: &AuditRowId) -> Option<AuditRecord> {
        self.state()
            .rows
            .iter()
            .find(|(stored, _)| stored == id)
            .map(|(_, record)| record.clone())
    }

    /// How many times `begin` was called, whether or not it wrote.
    pub fn begin_attempts(&self) -> usize {
        self.state().begin_attempts
    }

    /// How many times `finish` was called, whether or not it wrote.
    pub fn finish_attempts(&self) -> usize {
        self.state().finish_attempts
    }

    /// The next `begin` fails, and later ones work.
    pub fn fail_next_begin(&self) {
        self.state().begin_failing = Failing::Next;
    }

    /// Every `begin` fails until [`stop_failing`](Self::stop_failing).
    pub fn fail_all_begins(&self) {
        self.state().begin_failing = Failing::Always;
    }

    /// The next `finish` fails, and later ones work.
    pub fn fail_next_finish(&self) {
        self.state().finish_failing = Failing::Next;
    }

    /// Every `finish` fails until [`stop_failing`](Self::stop_failing).
    pub fn fail_all_finishes(&self) {
        self.state().finish_failing = Failing::Always;
    }

    /// Both operations work again.
    pub fn stop_failing(&self) {
        let mut state = self.state();
        state.begin_failing = Failing::Never;
        state.finish_failing = Failing::Never;
    }

    /// Holds every `begin` from here on at a gate, which is returned. The row is not written,
    /// and a failure setting is not consumed, until the gate opens.
    pub fn hold_begins(&self) -> Gate {
        let gate = Gate::closed();
        self.state().begin_gate = Some(gate.clone());
        gate
    }

    /// Holds every `finish` from here on at a gate, which is returned.
    pub fn hold_finishes(&self) -> Gate {
        let gate = Gate::closed();
        self.state().finish_gate = Some(gate.clone());
        gate
    }
}

fn down() -> StoreError {
    "the in-memory audit store was told to fail".into()
}

impl AuditStore for InMemoryAuditStore {
    fn begin<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let gate = {
            let mut state = self.state();
            state.begin_attempts += 1;
            state.begin_gate.clone()
        };
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let mut state = self.state();
            if state.begin_failing.take() {
                return Err(down());
            }
            match state.rows.iter().find(|(id, _)| id == row) {
                None => {
                    state.rows.push((row.clone(), record.clone()));
                    Ok(())
                }
                Some((_, stored)) if stored.decision == record.decision => Ok(()),
                Some(_) => Err(format!(
                    "audit row {} was already begun, with another decision",
                    row.as_str()
                )
                .into()),
            }
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let gate = {
            let mut state = self.state();
            state.finish_attempts += 1;
            state.finish_gate.clone()
        };
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let mut state = self.state();
            if state.finish_failing.take() {
                return Err(down());
            }
            let (_, row) = state
                .rows
                .iter_mut()
                .find(|(id, _)| id == completion.row())
                .ok_or_else(|| StoreError::from("no such row"))?;
            match &row.completion {
                None => {
                    row.completion = Some(completion.completion().clone());
                    Ok(())
                }
                Some(written) if written == completion.completion() => Ok(()),
                Some(_) => Err("the row was already finished, with a different completion".into()),
            }
        })
    }
}
