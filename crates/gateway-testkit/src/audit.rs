//! An audit store in memory that a test can read back and tell to fail or to wait.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use gateway_core::audit::{AuditRowId, ListRecord, RowCompletion, RowKind, RowStart, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture, InstanceName};
use gateway_identity::Clock;
use rand_core::{OsRng, RngCore};

use crate::clock::FixedClock;
use crate::gate::Gate;

/// The instance [`row_start`] names.
pub const FIXTURE_INSTANCE: &str = "fixture-instance";

/// The call deadline [`row_start`] gives, in milliseconds: the proxy connector's default.
pub const FIXTURE_CALL_DEADLINE_MS: u64 = 5_000;

/// A row start with a fresh identifier, for a test that calls the core's `audit::begin` itself
/// rather than through the gateway, which makes one per call.
///
/// The identifier is a random UUID (version 4) in the lowercase hyphenated form, so every
/// store accepts it, the Postgres store included, which refuses an identifier that is not a
/// UUID. The gateway's own are UUIDv7s; a test needs only one no other row has. The row is
/// begun by [`FIXTURE_INSTANCE`] with a call deadline of [`FIXTURE_CALL_DEADLINE_MS`].
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
        instance: InstanceName::new(FIXTURE_INSTANCE),
        call_deadline_ms: FIXTURE_CALL_DEADLINE_MS,
    }
}

/// The store's own time budgets, which the deadline of each call row includes. The defaults
/// are the Postgres store's: 2 s to begin and 30 s to finish (decision 0009 point 9). The
/// testkit cannot use that store's type, so it has its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreBudgets {
    /// Begin, from the call to begin to the written row.
    pub begin: Duration,
    /// How long, from the call to finish, a store keeps trying to complete the row.
    pub finish_deadline: Duration,
}

impl Default for StoreBudgets {
    fn default() -> Self {
        Self {
            begin: Duration::from_secs(2),
            finish_deadline: Duration::from_secs(30),
        }
    }
}

/// The times the store gave a row when it was begun, from its own clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Times {
    begun_at: SystemTime,
    deadline: Option<SystemTime>,
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
    rows: Vec<(AuditRowId, AuditRecord, Times)>,
    list_rows: Vec<(AuditRowId, ListRecord, SystemTime)>,
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
///
/// Like the Postgres store, it sets each row's time at begin and deadline itself, from its
/// own clock and never from the record: the time at begin, plus the begin budget, the call
/// deadline the record carries and the finish deadline. A row of kind `list` has no deadline.
/// The clock is a [`FixedClock`] at [`FIXTURE_NOW`](crate::FIXTURE_NOW) unless set.
///
/// List rows, which `list` writes, are kept apart and read back with
/// [`list_rows`](Self::list_rows). They share identifiers with call rows, as one Postgres table
/// does: a second list with a known list row's identifier writes nothing and succeeds, and a
/// list or a begin with the identifier of a row of the other kind fails. A list counts as a
/// begin for the failure settings and the gate: it fails when a begin would, and is held with
/// the begins. It is not counted in [`begin_attempts`](Self::begin_attempts).
pub struct InMemoryAuditStore {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    budgets: StoreBudgets,
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self {
            state: Mutex::default(),
            clock: Arc::new(FixedClock::default()),
            budgets: StoreBudgets::default(),
        }
    }
}

impl InMemoryAuditStore {
    /// An empty store that works, on a [`FixedClock`] with the default [`StoreBudgets`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The same store, reading the time at begin from `clock`.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The same store, with `budgets` in each call row's deadline.
    pub fn with_budgets(mut self, budgets: StoreBudgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// The time the store gave the row `id` when it was begun, if begin wrote one.
    pub fn begun_at(&self, id: &AuditRowId) -> Option<SystemTime> {
        self.times(id).map(|times| times.begun_at)
    }

    /// The deadline the store gave the row `id`: its time at begin plus the begin budget, its
    /// call deadline and the finish deadline. `None` if begin wrote no such row, or for a row
    /// of kind `list`, which has none.
    pub fn deadline(&self, id: &AuditRowId) -> Option<SystemTime> {
        self.times(id).and_then(|times| times.deadline)
    }

    fn times(&self, id: &AuditRowId) -> Option<Times> {
        let state = self.state();
        let call = state
            .rows
            .iter()
            .find(|(stored, _, _)| stored == id)
            .map(|(_, _, times)| *times);
        call.or_else(|| {
            state
                .list_rows
                .iter()
                .find(|(stored, _, _)| stored == id)
                .map(|(_, _, begun_at)| Times {
                    begun_at: *begun_at,
                    deadline: None,
                })
        })
    }

    /// The times for a row begun now. `None` when the deadline is past what a time can hold.
    fn times_for(&self, record: &AuditRecord) -> Option<Times> {
        let begun_at = self.clock.now();
        let deadline = match record.kind {
            RowKind::Call => Some(
                begun_at
                    .checked_add(self.budgets.begin)?
                    .checked_add(Duration::from_millis(record.call_deadline_ms))?
                    .checked_add(self.budgets.finish_deadline)?,
            ),
            RowKind::List => None,
        };
        Some(Times { begun_at, deadline })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every row, in the order its begin was written, with its completion once finished.
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.state()
            .rows
            .iter()
            .map(|(_, record, _)| record.clone())
            .collect()
    }

    /// Every list row, with its identifier, in the order written.
    pub fn list_rows(&self) -> Vec<(AuditRowId, ListRecord)> {
        self.state()
            .list_rows
            .iter()
            .map(|(id, record, _)| (id.clone(), record.clone()))
            .collect()
    }

    /// The row at `position` in the order written.
    pub fn row(&self, position: usize) -> Option<AuditRecord> {
        self.state()
            .rows
            .get(position)
            .map(|(_, record, _)| record.clone())
    }

    /// The row stored under `id`, if begin wrote one.
    pub fn row_with_id(&self, id: &AuditRowId) -> Option<AuditRecord> {
        self.state()
            .rows
            .iter()
            .find(|(stored, _, _)| stored == id)
            .map(|(_, record, _)| record.clone())
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
            if state.list_rows.iter().any(|(id, _, _)| id == row) {
                return Err(format!("audit row {} is a list row", row.as_str()).into());
            }
            match state.rows.iter().find(|(id, _, _)| id == row) {
                None => {
                    let times = self
                        .times_for(record)
                        .ok_or_else(|| StoreError::from("the row's deadline is out of range"))?;
                    state.rows.push((row.clone(), record.clone(), times));
                    Ok(())
                }
                Some((_, stored, _)) if stored.decision == record.decision => Ok(()),
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
            let (_, row, _) = state
                .rows
                .iter_mut()
                .find(|(id, _, _)| id == completion.row())
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

    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let gate = self.state().begin_gate.clone();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let mut state = self.state();
            if state.begin_failing.take() {
                return Err(down());
            }
            if state.rows.iter().any(|(id, _, _)| id == row) {
                return Err(format!("audit row {} is a call row", row.as_str()).into());
            }
            if !state.list_rows.iter().any(|(id, _, _)| id == row) {
                state
                    .list_rows
                    .push((row.clone(), record.clone(), self.clock.now()));
            }
            Ok(())
        })
    }
}
