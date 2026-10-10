//! An audit store in memory that a test can read back and tell to fail or to wait.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use gateway_core::audit::{
    AuditRowId, Completion, DecisionKind, ListRecord, Outcome, RowCompletion, RowKind, RowStart,
    StoreError,
};
use gateway_core::{AuditRecord, AuditStore, BoxFuture, InstanceName};
use gateway_identity::Clock;
use rand_core::{OsRng, RngCore};
use serde_json::Value;

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

/// How long past its time at begin a call row's deadline is, in milliseconds, as the Postgres
/// store works it out: the begin budget and the finish deadline each in whole milliseconds,
/// and the call deadline, added without wrapping. A sum past what a Postgres `bigint` holds
/// is refused at begin.
fn allowance_ms(budgets: &StoreBudgets, call_deadline_ms: u64) -> u64 {
    millis(budgets.begin)
        .saturating_add(call_deadline_ms)
        .saturating_add(millis(budgets.finish_deadline))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Whether `value` holds U+0000 in any string, which Postgres text, text arrays and jsonb
/// cannot hold.
fn holds_nul(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('\0'),
        Value::Array(items) => items.iter().any(holds_nul),
        Value::Object(fields) => fields
            .iter()
            .any(|(name, value)| name.contains('\0') || holds_nul(value)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Refuses a record, list record or completion with U+0000 in any text value, naming the
/// field, as the Postgres store refuses it before it writes.
fn refuse_nul(record: Result<Value, serde_json::Error>) -> Result<(), StoreError> {
    let Value::Object(fields) = record? else {
        return Err("the record is not a set of fields".into());
    };
    match fields.iter().find(|(_, value)| holds_nul(value)) {
        Some((field, _)) => Err(format!(
            "the record's {field} holds U+0000, which a Postgres text value cannot hold"
        )
        .into()),
        None => Ok(()),
    }
}

/// Refuses a count or a latency past what a Postgres `bigint` holds.
fn refuse_past_bigint(what: &str, value: u64) -> Result<(), StoreError> {
    if i64::try_from(value).is_err() {
        return Err(format!("{what} is past what a Postgres bigint holds").into());
    }
    Ok(())
}

fn as_u64(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// The allowance for `record`'s deadline, or why the Postgres store would refuse to write it:
/// a text value with U+0000, or a count or an allowance past a `bigint`.
fn refused_at_begin(record: &AuditRecord, budgets: &StoreBudgets) -> Result<u64, StoreError> {
    refuse_nul(serde_json::to_value(record))?;
    refuse_past_bigint(
        "the count of resources left out",
        as_u64(record.resources_omitted),
    )?;
    let allowance = allowance_ms(budgets, record.call_deadline_ms);
    refuse_past_bigint("the row's allowance", allowance)?;
    Ok(allowance)
}

/// Why the Postgres store would refuse to write `record`, if it would.
fn refused_at_list(record: &ListRecord) -> Result<(), StoreError> {
    refuse_nul(serde_json::to_value(record))?;
    refuse_past_bigint("the count of tools left out", as_u64(record.tools_omitted))
}

/// Why the Postgres store would refuse to write `completion`, if it would.
fn refused_at_finish(completion: &Completion) -> Result<(), StoreError> {
    refuse_nul(serde_json::to_value(completion))?;
    refuse_past_bigint("the latency", completion.latency_ms)
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

/// A completion still being tried after finish answered past the answer budget: written once
/// its gate opens.
struct Late {
    gate: Gate,
    row: AuditRowId,
    completion: Completion,
}

#[derive(Default)]
struct State {
    rows: Vec<(AuditRowId, AuditRecord, Times)>,
    list_rows: Vec<(AuditRowId, ListRecord, SystemTime)>,
    begin_attempts: usize,
    finish_attempts: usize,
    begin_failing: Failing,
    finish_failing: Failing,
    confirmation_lost: Failing,
    finishes_forgotten: bool,
    begin_gate: Option<Gate>,
    finish_gate: Option<Gate>,
    answer_gate: Option<Gate>,
    late: Vec<Late>,
}

impl State {
    /// Writes each late completion whose gate has opened, as the Postgres store's own task
    /// does once the database answers.
    fn settle(&mut self) {
        let (ready, waiting) = std::mem::take(&mut self.late)
            .into_iter()
            .partition::<Vec<_>, _>(|late| late.gate.is_open());
        self.late = waiting;
        for late in ready {
            // A completion the row refuses is not written; the Postgres store's task gives
            // it up the same way.
            let _ = self.complete(&late.row, &late.completion);
        }
    }

    /// Completes the row `id` with `completion`, unless it is complete already.
    fn complete(&mut self, id: &AuditRowId, completion: &Completion) -> Result<(), StoreError> {
        let (_, row, _) = self
            .rows
            .iter_mut()
            .find(|(stored, _, _)| stored == id)
            .ok_or_else(|| StoreError::from("no such row"))?;
        match &row.completion {
            None => {
                row.completion = Some(completion.clone());
                Ok(())
            }
            Some(written) if written == completion => Ok(()),
            Some(_) => Err("the row was already finished, with a different completion".into()),
        }
    }
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
/// It refuses what the Postgres store cannot write exactly, and writes nothing: a record, list
/// record or completion with U+0000 in a text value, a count of resources or tools left out
/// or a latency past a Postgres `bigint`, and a call row whose allowance is past one.
///
/// It fails the ways decision 0009 says the fake must, each until told otherwise or once:
///
/// - Before writing ([`fail_next_begin`](Self::fail_next_begin),
///   [`fail_next_finish`](Self::fail_next_finish) and their `all` forms).
/// - After writing, a lost confirmation
///   ([`lose_next_begin_confirmation`](Self::lose_next_begin_confirmation)): begin writes the
///   row and then fails, and the store completes an allowed row as `error`, as the Postgres
///   store's finish pool does.
/// - Slowly: both operations can be held at a [`Gate`] to stand in for a slow database without
///   a real sleep, and finish can answer past the answer budget and write later
///   ([`finish_past_answer_budget`](Self::finish_past_answer_budget)).
/// - By losing the process between run and finish
///   ([`forget_finishes`](Self::forget_finishes)). The store can be shared by [`Arc`] with a
///   second gateway built over it, which sees the row still open.
///
/// Like the Postgres store, it sets each row's time at begin and deadline itself, from its
/// own clock and never from the record: the time at begin, plus the begin budget, the call
/// deadline the record carries and the finish deadline, in whole milliseconds. A row of kind
/// `list` has no deadline. The clock is a [`FixedClock`] at [`FIXTURE_NOW`](crate::FIXTURE_NOW)
/// unless set.
///
/// List rows, which `list` writes, are kept apart and read back with
/// [`list_rows`](Self::list_rows). They share identifiers with call rows, as one Postgres table
/// does: a second list with a known list row's identifier writes nothing and succeeds, and a
/// list or a begin with the identifier of a row of the other kind fails. A list counts as a
/// begin for the failure settings, a lost confirmation and the gate: it fails when a begin
/// would, and is held with the begins. It is not counted in
/// [`begin_attempts`](Self::begin_attempts).
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

    /// The times for a row of `kind` begun now, with `allowance_ms` to its deadline. `None`
    /// when the deadline is past what a time can hold.
    fn times_for(&self, kind: RowKind, allowance_ms: u64) -> Option<Times> {
        let begun_at = self.clock.now();
        let deadline = match kind {
            RowKind::Call => Some(begun_at.checked_add(Duration::from_millis(allowance_ms))?),
            RowKind::List => None,
        };
        Some(Times { begun_at, deadline })
    }

    /// The state, with every late completion whose gate has opened written.
    fn state(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.settle();
        state
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

    /// The next `begin` or `list` that would succeed writes its row and then fails: its
    /// confirmation is lost, as when the connection drops after the commit. An allowed call's
    /// row is then completed as `error` with a latency of zero, as the Postgres store
    /// completes it on its finish pool. A denial and a list row are complete records already,
    /// and are left as they are. Later begins work.
    pub fn lose_next_begin_confirmation(&self) {
        self.state().confirmation_lost = Failing::Next;
    }

    /// Every `begin` and `list` loses its confirmation, as
    /// [`lose_next_begin_confirmation`](Self::lose_next_begin_confirmation) says, until
    /// [`stop_failing`](Self::stop_failing).
    pub fn lose_all_begin_confirmations(&self) {
        self.state().confirmation_lost = Failing::Always;
    }

    /// Every `finish` from here on is swallowed, until [`stop_failing`](Self::stop_failing):
    /// it fails and writes nothing, and a completion still being tried past the answer budget
    /// is dropped. This is the process lost between run and finish. A test drops the gateway
    /// that ran the call, builds a new one over the same store, and sees the row stay open:
    /// nothing completes it but the call's own finish.
    pub fn forget_finishes(&self) {
        let mut state = self.state();
        state.finishes_forgotten = true;
        state.late.clear();
    }

    /// Every operation works again, and finishes are no longer forgotten. A store holding
    /// calls at a gate, or answering past the answer budget, still does.
    pub fn stop_failing(&self) {
        let mut state = self.state();
        state.begin_failing = Failing::Never;
        state.finish_failing = Failing::Never;
        state.confirmation_lost = Failing::Never;
        state.finishes_forgotten = false;
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

    /// Every `finish` from here on, while the returned gate is closed, takes longer than the
    /// answer budget: it fails at once with an error naming the budget, and its completion is
    /// written once the gate opens, as the Postgres store keeps trying on a task of its own
    /// after the answer has gone out. No time passes; the gate stands in for it. Once the
    /// gate is open, finish writes at once again.
    pub fn finish_past_answer_budget(&self) -> Gate {
        let gate = Gate::closed();
        self.state().answer_gate = Some(gate.clone());
        gate
    }
}

fn down() -> StoreError {
    "the in-memory audit store was told to fail".into()
}

fn lost() -> StoreError {
    "the in-memory audit store wrote the row and was told to lose the confirmation".into()
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
            let allowance_ms = refused_at_begin(record, &self.budgets)?;
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
                        .times_for(record.kind, allowance_ms)
                        .ok_or_else(|| StoreError::from("the row's deadline is out of range"))?;
                    state.rows.push((row.clone(), record.clone(), times));
                }
                Some((_, stored, _)) if stored.decision == record.decision => {}
                Some(_) => {
                    return Err(format!(
                        "audit row {} was already begun, with another decision",
                        row.as_str()
                    )
                    .into());
                }
            }
            if state.confirmation_lost.take() {
                if record.decision == DecisionKind::Allow {
                    let error = Completion {
                        outcome: Outcome::Error,
                        latency_ms: 0,
                    };
                    // A row completed before keeps its completion, as complete_once keeps it.
                    let _ = state.complete(row, &error);
                }
                return Err(lost());
            }
            Ok(())
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
            refused_at_finish(completion.completion())?;
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let mut state = self.state();
            if state.finishes_forgotten {
                return Err("the process that would have finished this row was lost".into());
            }
            if state.finish_failing.take() {
                return Err(down());
            }
            if let Some(gate) = state.answer_gate.clone().filter(|gate| !gate.is_open()) {
                state.late.push(Late {
                    gate,
                    row: completion.row().clone(),
                    completion: completion.completion().clone(),
                });
                return Err(format!(
                    "audit row {} was not completed within the answer budget; the store is still trying",
                    completion.row().as_str()
                )
                .into());
            }
            state.complete(completion.row(), completion.completion())
        })
    }

    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        let gate = self.state().begin_gate.clone();
        Box::pin(async move {
            refused_at_list(record)?;
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
            if state.confirmation_lost.take() {
                return Err(lost());
            }
            Ok(())
        })
    }
}
