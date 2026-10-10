//! An audit store in memory that a test can read back and tell to fail or to wait.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::audit::{
    AuditRowId, Completion, DecisionKind, ListRecord, Outcome, RecordedResources, RowCompletion,
    RowKind, RowStart, StoreError,
};
use gateway_core::{AuditRecord, AuditStore, BoxFuture, InstanceName};
use gateway_identity::Clock;
use rand_core::{OsRng, RngCore};
use serde_json::Value;

use crate::clock::FixedClock;
use crate::contract::StoredRecord;
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
/// is refused at begin, and so is one whose deadline Postgres's `set_times` cannot work out:
/// see [`postgres_deadline`].
fn allowance_ms(budgets: &StoreBudgets, call_deadline_ms: u64) -> u64 {
    millis(budgets.begin)
        .saturating_add(call_deadline_ms)
        .saturating_add(millis(budgets.finish_deadline))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The Postgres epoch, 2000-01-01 00:00:00 UTC, in seconds after the Unix epoch.
const POSTGRES_EPOCH_SECS: u64 = 946_684_800;

/// The end of what a Postgres `timestamptz` holds, in microseconds after the Postgres epoch:
/// 294277-01-01 00:00:00 UTC, which is itself out of range (Postgres's `END_TIMESTAMP`).
const POSTGRES_END_MICROS: i128 = 9_223_371_331_200_000_000;

/// 2^63, the first value past what a Postgres interval's `int64` of microseconds holds, as a
/// `float8`.
const TWO_TO_THE_63: f64 = 9_223_372_036_854_775_808.0;

/// The deadline Postgres's `set_times` gives a call row begun at `begun_at` with
/// `allowance_ms`: `begun_at + allowance_ms * interval '1 millisecond'`. `None` where Postgres
/// refuses the insert.
///
/// The arithmetic is Postgres's own. The `bigint` is cast to `float8`, which is exact only up
/// to 2^53, multiplied by the interval's 1000 microseconds and rounded to whole ones; a
/// product of 2^63 microseconds or more is "interval out of range". The sum, in whole
/// microseconds, must fall before 294277-01-01 UTC, or it is "timestamp out of range". With
/// the default budgets and a row begun at [`FIXTURE_NOW`](crate::FIXTURE_NOW), the largest
/// allowance accepted is 9,222,518,015,999,998 ms, whose deadline is 294276-12-31
/// 23:59:59.997952 UTC.
fn postgres_deadline(begun_at: SystemTime, allowance_ms: u64) -> Option<SystemTime> {
    // The same cast, product and rounding as Postgres's interval_mul, which rounds half to
    // even. The product is a whole number from 0 to below 2^63, so the cast back is exact.
    let product = (1000.0 * allowance_ms as f64).round_ties_even();
    if product >= TWO_TO_THE_63 {
        return None;
    }
    let span_micros = product as u64;
    // Postgres keeps a time in whole microseconds.
    let begun_micros = match begun_at.duration_since(UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).ok()?,
        Err(before) => -i128::try_from(before.duration().as_nanos()).ok()?,
    }
    .div_euclid(1000)
        - i128::from(POSTGRES_EPOCH_SECS) * 1_000_000;
    if begun_micros + i128::from(span_micros) >= POSTGRES_END_MICROS {
        return None;
    }
    begun_at.checked_add(Duration::from_micros(span_micros))
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

/// Refuses an identifier that is not a UUID in the lowercase hyphenated form: 8, 4, 4, 4 and
/// 12 hex digits. The Postgres store refuses other spellings, so that one row has one.
fn refuse_non_uuid(id: &AuditRowId) -> Result<(), StoreError> {
    let id = id.as_str();
    let uuid = id.len() == 36
        && id.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => matches!(c, '0'..='9' | 'a'..='f'),
        });
    if !uuid {
        return Err(format!(
            "audit row identifier {id:?} is not a UUID in the lowercase hyphenated form"
        )
        .into());
    }
    Ok(())
}

/// The allowance for `record`'s deadline, or why the Postgres store would refuse to write it
/// as the row `id`: an identifier that is not a lowercase hyphenated UUID, a record already
/// complete, a text value with U+0000, a count or an allowance past a `bigint`, or unknown
/// resources with a count left out.
fn refused_at_begin(
    id: &AuditRowId,
    record: &AuditRecord,
    budgets: &StoreBudgets,
) -> Result<u64, StoreError> {
    if record.completion.is_some() {
        return Err("begin was handed a record that is already complete".into());
    }
    refuse_non_uuid(id)?;
    refuse_nul(serde_json::to_value(record))?;
    refuse_past_bigint(
        "the count of resources left out",
        as_u64(record.resources_omitted),
    )?;
    if record.resources == RecordedResources::Unknown && record.resources_omitted != 0 {
        return Err("unknown resources cannot have a count left out".into());
    }
    let allowance = allowance_ms(budgets, record.call_deadline_ms);
    refuse_past_bigint("the row's allowance", allowance)?;
    Ok(allowance)
}

/// Why the Postgres store would refuse to write `record` as the row `id`, if it would.
fn refused_at_list(id: &AuditRowId, record: &ListRecord) -> Result<(), StoreError> {
    refuse_non_uuid(id)?;
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

    /// Completes the row `id` with `completion`, unless it is complete already. Every
    /// completion comes through here, a late one and a lost begin's included. As Postgres's
    /// `complete_once` does, it refuses a row of kind `list` and a denial, whatever the
    /// completion: neither is ever completed.
    fn complete(&mut self, id: &AuditRowId, completion: &Completion) -> Result<(), StoreError> {
        let listing = || {
            StoreError::from(format!(
                "audit row {} records a listing, which is never completed",
                id.as_str()
            ))
        };
        if self.list_rows.iter().any(|(stored, _, _)| stored == id) {
            return Err(listing());
        }
        let (_, row, _) = self
            .rows
            .iter_mut()
            .find(|(stored, _, _)| stored == id)
            .ok_or_else(|| StoreError::from("no such row"))?;
        if row.kind != RowKind::Call {
            return Err(listing());
        }
        if row.decision != DecisionKind::Allow {
            return Err(format!(
                "audit row {} records a denial, which is never completed",
                id.as_str()
            )
            .into());
        }
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
/// It behaves as the interface says a store must. A begin that is being held has not written
/// yet, and a begin told to fail leaves nothing behind. A begin told to lose its confirmation
/// ([`lose_next_begin_confirmation`](Self::lose_next_begin_confirmation) and
/// [`lose_all_begin_confirmations`](Self::lose_all_begin_confirmations)) is the exception: it
/// fails after writing its row, as decision 0009 says a begin may. A failed `finish` leaves
/// the row as it was, with its outcome empty, except one that answered past the answer budget
/// ([`finish_past_answer_budget`](Self::finish_past_answer_budget)): its completion is written
/// later, once the gate opens. A row cannot be finished before it was begun, and a denial or a
/// list row cannot be finished at all, as Postgres's `complete_once` refuses them. That holds
/// for every completion, a late one and a lost begin's included.
///
/// Rows are kept under the identifier begin was given. A second begin with a known identifier
/// writes nothing: it succeeds if the stored decision is the same, and fails if it differs. It
/// compares the decision and nothing more, as the Postgres store can. A second finish
/// succeeds if it is identical to the completion the row has, and otherwise fails and leaves
/// the first completion standing.
///
/// It refuses what the Postgres store's column mapping refuses, and writes nothing: an
/// identifier that is not a UUID in the lowercase hyphenated form, a record handed to begin
/// already complete, a record, list record or completion with U+0000 in a text value, a count
/// of resources or tools left out or a latency past a Postgres `bigint`, and a call row whose
/// allowance is past one. Of the table's own constraints it checks only one: unknown resources
/// with a count left out. Of its triggers it follows both: `set_times`, which refuses a
/// deadline past what a Postgres time holds, and `complete_once`.
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
/// deadline the record carries and the finish deadline, in whole milliseconds. It adds that
/// allowance to the time at begin as Postgres's `set_times` does, through `float8`, and
/// refuses a call row whose deadline Postgres would refuse: one at or past 294277-01-01 UTC,
/// or an allowance of 2^63 microseconds or more. A row of kind
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
    /// when the deadline is past what Postgres's `set_times` accepts.
    fn times_for(&self, kind: RowKind, allowance_ms: u64) -> Option<Times> {
        let begun_at = self.clock.now();
        let deadline = match kind {
            RowKind::Call => Some(postgres_deadline(begun_at, allowance_ms)?),
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

    /// Every row stored under `id`, of either kind, with the time at begin and the deadline the
    /// store gave it: for the contract suite's read-back, which refuses more than one.
    pub(crate) fn stored_under(
        &self,
        id: &AuditRowId,
    ) -> Vec<(StoredRecord, SystemTime, Option<SystemTime>)> {
        let state = self.state();
        let calls =
            state
                .rows
                .iter()
                .filter(|(stored, _, _)| stored == id)
                .map(|(_, record, times)| {
                    (
                        StoredRecord::Call(record.clone()),
                        times.begun_at,
                        times.deadline,
                    )
                });
        let lists = state
            .list_rows
            .iter()
            .filter(|(stored, _, _)| stored == id)
            .map(|(_, record, begun_at)| (StoredRecord::List(record.clone()), *begun_at, None));
        calls.chain(lists).collect()
    }

    /// The budgets in each call row's deadline.
    pub(crate) fn store_budgets(&self) -> StoreBudgets {
        self.budgets
    }

    /// The time on the clock the store reads for a row's times.
    pub(crate) fn store_now(&self) -> SystemTime {
        self.clock.now()
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
    /// confirmation is lost. An allowed call's row is then completed as `error` with a latency
    /// of zero, as the Postgres store completes it on its finish pool. A denial and a list row
    /// are complete records already, and are left as they are. Later begins work.
    ///
    /// This is a begin that the Postgres store reports as failed after writing: every attempt
    /// within its begin budget lost its confirmation, or the budget ran out once the row was
    /// written. One lost confirmation alone is not that. The Postgres store retries begin by
    /// identifier within its budget, a retry finds the row it wrote, and begin succeeds with
    /// the row open. The fake does not retry. A test that begins again under the same
    /// identifier gets a guard for a row already completed as `error`, and that guard's finish
    /// is refused unless it too is `error` with a latency of zero.
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
            let allowance_ms = refused_at_begin(row, record, &self.budgets)?;
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
                let error = Completion {
                    outcome: Outcome::Error,
                    latency_ms: 0,
                };
                // Only an allowed row is completed. A denial is refused, and a row completed
                // before keeps its completion, as complete_once refuses and keeps them.
                let _ = state.complete(row, &error);
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
            refused_at_list(row, record)?;
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
