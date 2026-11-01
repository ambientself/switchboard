//! An audit store in memory that a test can read back and tell to fail or to wait.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gateway_core::audit::{
    AuditRowId, Completion, DecisionKind, ErrorKind, ListRecord, Outcome, ReachedResources,
    RecordedResources, RowCompletion, RowKind, RowStart, StoreError,
};
use gateway_core::receipt::{EstablishedBy, ReceiptRequest, Reservation, may_move};
use gateway_core::{
    AuditRecord, AuditStore, BoxFuture, Classification, IdempotencyKey, InstanceName,
    LeaseHolder, LookupAnswer, LookupRecord, ReasonKind, Receipt, ReceiptQueue, ReceiptState,
    Recorded, Reuse, VendorReference,
};
use gateway_identity::Clock;
use rand_core::{OsRng, RngCore};
use serde_json::Value;

use crate::clock::FixedClock;
use crate::contract::StoredRecord;
use crate::gate::Gate;
use crate::row_bound::{
    MAX_BEGUN_ROW_BYTES, MAX_ROW_BYTES, call_row_sizes, list_row_sizes, refuse_long_reach,
    refuse_long_sentence, refuse_over,
};

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
        credential: None,
    }
}

/// An idempotency key no other call has, for a test that calls a tool not classified `read`:
/// the caller chooses one per call, as a client sends a fresh tool-use identifier with each.
/// `toolu_` and 24 random hex digits, the shape of Claude Code's tool-use identifiers.
pub fn fresh_key() -> IdempotencyKey {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    IdempotencyKey::parse(&format!("toolu_{hex}"))
        .unwrap_or_else(|_| unreachable!("24 hex digits and a prefix are a valid key"))
}

/// The store's own time budgets, which the deadline of each call row includes. The defaults
/// are the Postgres store's: 2 s to begin, 2 s for the answer and 30 s to finish (decision
/// 0009 point 9). The testkit cannot use that store's type, so it has its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreBudgets {
    /// Begin, from the call to begin to the written row.
    pub begin: Duration,
    /// The most one attempt to complete a row may take. The Postgres store's last attempt to
    /// complete a failed begin's row is made at the finish deadline and may take this long past
    /// it. The in-memory store uses it only in the deadline: it answers past the answer budget
    /// only when told to
    /// ([`finish_past_answer_budget`](InMemoryAuditStore::finish_past_answer_budget)).
    pub answer: Duration,
    /// How long, from the call to finish, a store keeps trying to complete the row.
    pub finish_deadline: Duration,
}

impl Default for StoreBudgets {
    fn default() -> Self {
        Self {
            begin: Duration::from_secs(2),
            answer: Duration::from_secs(2),
            finish_deadline: Duration::from_secs(30),
        }
    }
}

/// How long past its time at begin a call row's deadline is, in milliseconds, as the Postgres
/// store works it out: the begin budget, the finish deadline and the answer budget each in
/// whole milliseconds, and the call deadline, added without wrapping. The answer budget is for
/// the last attempt to complete a failed begin's row, made at the finish deadline (decision
/// 0009, as amended on 2026-10-11). A sum past what a Postgres `bigint` holds is refused at begin, and so is one
/// whose deadline Postgres's `set_times` cannot work out: see [`postgres_deadline`].
fn allowance_ms(budgets: &StoreBudgets, call_deadline_ms: u64) -> u64 {
    millis(budgets.begin)
        .saturating_add(call_deadline_ms)
        .saturating_add(millis(budgets.finish_deadline))
        .saturating_add(millis(budgets.answer))
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
/// complete, a text value with U+0000, a count or an allowance past a `bigint`, a row over
/// [`MAX_BEGUN_ROW_BYTES`], unknown resources or a reach with a count left out, a reach naming
/// no entry, or a call record of kind `list`, which the table's `kind_shape` refuses whatever
/// row the identifier already names. It checks the allowance before the row bound, and the
/// row bound before the table's own constraints, as that store does. Its other checks do not
/// follow that store's order, so a record that breaks more than one rule may be refused for a
/// different one of them.
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
    if let Some(delegation) = &record.delegation {
        refuse_past_bigint("a delegation's epoch", delegation.epoch)?;
    }
    let allowance = allowance_ms(budgets, record.call_deadline_ms);
    refuse_past_bigint("the row's allowance", allowance)?;
    refuse_over(&call_row_sizes(id, record), MAX_BEGUN_ROW_BYTES)?;
    if record.resources == RecordedResources::Unknown && record.resources_omitted != 0 {
        return Err("unknown resources cannot have a count left out".into());
    }
    if let RecordedResources::Reach(entry) = &record.resources {
        if record.resources_omitted != 0 {
            return Err("a reach cannot have a count left out".into());
        }
        if entry.as_str().is_empty() {
            return Err("a reach must name its connector entry".into());
        }
    }
    if record.kind != RowKind::Call {
        return Err(format!(
            "audit row {} is a call record of kind list, which violates the check constraint \"kind_shape\"",
            id.as_str()
        )
        .into());
    }
    refused_delegation(
        id,
        record.delegation.is_some(),
        record.proved_delegation_team.is_some(),
        record.claimed_acting_person.is_some(),
    )?;
    refused_failure(id, record)?;
    refused_exception(id, record)?;
    Ok(allowance)
}

/// Why the Postgres store would refuse a row's verified delegation, if it would: its table's
/// `delegation_shape` writes one with its team and its person.
fn refused_delegation(
    id: &AuditRowId,
    delegation: bool,
    team: bool,
    person: bool,
) -> Result<(), StoreError> {
    if delegation && !(team && person) {
        return Err(violates(id, "delegation_shape"));
    }
    Ok(())
}

/// Why the Postgres store would refuse a call record's delegation failure, if it would, as its
/// table's constraints say (migration 0010): a failure is recorded exactly on a row check 3
/// denied for a delegation that did not verify (`delegation_failure_shape`), beside nothing from
/// the delegation's claims (`delegation_failure_unclaimed`), and with a digest only for a
/// failure that follows a verified signature (`delegation_digest_shape`).
fn refused_failure(id: &AuditRowId, record: &AuditRecord) -> Result<(), StoreError> {
    let at_check_3 = record.reason == Some(ReasonKind::DelegationUnverified);
    let Some(failure) = &record.delegation_failure else {
        return if at_check_3 {
            Err(violates(id, "delegation_failure_shape"))
        } else {
            Ok(())
        };
    };
    if !at_check_3 || record.decision != DecisionKind::Deny {
        return Err(violates(id, "delegation_failure_shape"));
    }
    if record.delegation.is_some()
        || record.proved_delegation_team.is_some()
        || record.claimed_acting_person.is_some()
    {
        return Err(violates(id, "delegation_failure_unclaimed"));
    }
    if failure.digest.is_some() && !failure.failure.follows_signature() {
        return Err(violates(id, "delegation_digest_shape"));
    }
    Ok(())
}

/// Why the Postgres store would refuse a call record's exception, if it would, as its table's
/// `allowed_by_exception_shape` says (migration 0012): an exception is recorded only on an
/// allowed call of a `write` or `destructive` tool, never on a denial, a read or a proposal.
fn refused_exception(id: &AuditRowId, record: &AuditRecord) -> Result<(), StoreError> {
    let side_effect_check_5_denies = matches!(
        record.classification,
        Some(Classification::Write | Classification::Destructive)
    );
    if record.allowed_by_exception.is_some()
        && !(record.decision == DecisionKind::Allow && side_effect_check_5_denies)
    {
        return Err(violates(id, "allowed_by_exception_shape"));
    }
    Ok(())
}

/// The Postgres store's refusal of a row that breaks the check constraint `constraint`.
fn violates(id: &AuditRowId, constraint: &str) -> StoreError {
    format!(
        "audit row {} violates the check constraint \"{constraint}\"",
        id.as_str()
    )
    .into()
}

/// Why the Postgres store would refuse to write `record` as the row `id`, if it would: a list
/// row is written complete, so one over [`MAX_ROW_BYTES`] is refused.
fn refused_at_list(id: &AuditRowId, record: &ListRecord) -> Result<(), StoreError> {
    refuse_non_uuid(id)?;
    refuse_nul(serde_json::to_value(record))?;
    refuse_past_bigint("the count of tools left out", as_u64(record.tools_omitted))?;
    if let Some(delegation) = &record.delegation {
        refuse_past_bigint("a delegation's epoch", delegation.epoch)?;
    }
    refuse_over(&list_row_sizes(id, record), MAX_ROW_BYTES)?;
    refused_delegation(
        id,
        record.delegation.is_some(),
        record.proved_delegation_team.is_some(),
        record.claimed_acting_person.is_some(),
    )
}

/// Why the Postgres store would refuse to write `completion`, and what its tool `reached`, if
/// it would: a refusal's sentence is refused, never cut, when it holds U+0000 or is longer than
/// [`MAX_OUTCOME_SENTENCE_BYTES`](crate::row_bound::MAX_OUTCOME_SENTENCE_BYTES), and a reach
/// when it is longer than [`MAX_REACHED_BYTES`](crate::row_bound::MAX_REACHED_BYTES).
fn refused_at_finish(
    completion: &Completion,
    reached: Option<&ReachedResources>,
) -> Result<(), StoreError> {
    refuse_nul(serde_json::to_value(completion))?;
    if let Outcome::Refused { sentence } = &completion.outcome {
        refuse_long_sentence(sentence)?;
    }
    if let Some(reached) = reached {
        refuse_long_reach(reached)?;
    }
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
    reference: Option<VendorReference>,
    reached: Option<ReachedResources>,
}

#[derive(Default)]
struct State {
    rows: Vec<(AuditRowId, AuditRecord, Times)>,
    list_rows: Vec<(AuditRowId, ListRecord, SystemTime)>,
    receipts: Vec<Receipt>,
    /// The answer each row written as the answer to a reused key was written with.
    reused: Vec<(AuditRowId, Reuse)>,
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
    /// Each receipt's lease: who holds it, and until when.
    leases: Vec<(AuditRowId, LeaseHolder, SystemTime)>,
    claim_gate: Option<Gate>,
    claims_failing: Failing,
}

impl State {
    /// Writes each late completion whose gate has opened, as the Postgres store's own task
    /// does once the database answers, at `now`.
    fn settle(&mut self, now: SystemTime) {
        let (ready, waiting) = std::mem::take(&mut self.late)
            .into_iter()
            .partition::<Vec<_>, _>(|late| late.gate.is_open());
        self.late = waiting;
        for late in ready {
            // A completion the row refuses is not written; the Postgres store's task gives
            // it up the same way.
            let _ = self.complete_with(
                &late.row,
                &late.completion,
                late.reference.as_ref(),
                late.reached.as_ref(),
                now,
            );
        }
    }

    /// What a begin with a receipt answers for the row `id`, which an earlier attempt wrote:
    /// the answer it was written with, if it was written as the answer to a reused key, and
    /// [`Reservation::Reserved`] while its receipt reads as `pending` at `now`. A row whose
    /// receipt has left `pending` is refused, since its call has run or has been settled
    /// without running, and so is one whose receipt is still `pending` past its row's
    /// deadline, which reads as `unknown`: its call is no longer the call's to run or settle.
    /// So is a row begun with no receipt.
    ///
    /// `reuse` is the reuse check's answer for this begin. Since the row reserved its key or
    /// was answered, the check finds no receipt under another row unless the row was answered
    /// from it, and then the answer it was written with stands. One found otherwise is
    /// answered as it says, as a retried begin that did not pass over its own receipt would be.
    fn found(
        &self,
        id: &AuditRowId,
        reuse: Option<Reuse>,
        now: SystemTime,
    ) -> Result<Reservation, StoreError> {
        if let Some((_, reuse)) = self.reused.iter().find(|(row, _)| row == id) {
            return Ok(Reservation::Reused(reuse.clone()));
        }
        if let Some(reuse) = reuse {
            return Ok(Reservation::Reused(reuse));
        }
        let receipt = self
            .receipts
            .iter()
            .find(|receipt| receipt.row == *id)
            .map(|receipt| self.as_read(receipt, now));
        match receipt {
            Some(receipt) if receipt.state == ReceiptState::Pending => Ok(Reservation::Reserved),
            Some(_) => Err(format!(
                "audit row {}'s receipt has left pending, or is pending past its row's deadline, \
                 so its call must not run again",
                id.as_str()
            )
            .into()),
            None => Err(format!("audit row {} was begun with no receipt", id.as_str()).into()),
        }
    }

    /// The reuse check for a begin of the row `id` with `request`, at `now`: the answer, if the
    /// key already has a receipt in its scope reserved under another row, read as it reads at
    /// `now`. A receipt reserved under `id` itself is passed over, so a retried begin never
    /// refuses itself. `None` with no request. An answer whose completion the Postgres store
    /// would refuse is refused.
    fn reuse_answer(
        &self,
        id: &AuditRowId,
        request: Option<&ReceiptRequest>,
        now: SystemTime,
    ) -> Result<Option<Reuse>, StoreError> {
        let Some(request) = request else {
            return Ok(None);
        };
        let earlier = self
            .receipts
            .iter()
            .find(|receipt| receipt.row != *id && request.same_key(receipt));
        let Some(earlier) = earlier else {
            return Ok(None);
        };
        let reuse = Reuse::answer(request, &self.as_read(earlier, now));
        refused_at_finish(&reuse.completion(), None)?;
        Ok(Some(reuse))
    }

    /// Whether the deadline of the row `id` has passed at `now`, as Postgres reads it:
    /// `deadline < clock_timestamp()`. A row with no deadline, or no row, has not.
    fn past_deadline(&self, id: &AuditRowId, now: SystemTime) -> bool {
        self.rows
            .iter()
            .find(|(stored, _, _)| stored == id)
            .and_then(|(_, _, times)| times.deadline)
            .is_some_and(|deadline| deadline < now)
    }

    /// `receipt` as it reads at `now` (decision 0009, "What a receipt is"): a `pending`
    /// receipt whose row's deadline has passed reads as `unknown`, wherever it is read. Every
    /// other state reads as itself.
    fn as_read(&self, receipt: &Receipt, now: SystemTime) -> Receipt {
        let mut read = receipt.clone();
        read.state = receipt.state.as_read(self.past_deadline(&receipt.row, now));
        read
    }

    /// For the row `id`, just written open: completes it with `reuse`'s answer if there is one,
    /// and otherwise reserves `request`'s receipt under it, if there is a request. In the same
    /// write as the row, since the state is held throughout.
    fn reserve(
        &mut self,
        id: &AuditRowId,
        request: Option<&ReceiptRequest>,
        reuse: Option<Reuse>,
    ) -> Option<Reservation> {
        let request = request?;
        if let Some(reuse) = reuse {
            if let Some((_, row, _)) = self.rows.iter_mut().find(|(stored, _, _)| stored == id) {
                row.completion = Some(reuse.completion());
            }
            self.reused.push((id.clone(), reuse.clone()));
            return Some(Reservation::Reused(reuse));
        }
        self.receipts.push(request.reserve(id));
        Some(Reservation::Reserved)
    }

    /// [`complete_with`](Self::complete_with), with no vendor reference.
    fn complete(
        &mut self,
        id: &AuditRowId,
        completion: &Completion,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        self.complete_with(id, completion, None, None, now)
    }

    /// Completes the row `id` with `completion`, unless it is complete already, and settles
    /// the receipt reserved under it, if one was, in the same write. Every completion comes
    /// through here, a late one and a lost begin's included. As Postgres's `complete_once`
    /// does, it refuses a list row and a denial, whatever the completion: neither is ever
    /// completed. Every call row is of kind `call`, since begin refuses any other.
    ///
    /// The receipt moves, established by the call, to the state the outcome settles it in,
    /// with `reference`, only as [`may_move`] allows: one already settled, or one still
    /// `pending` once its row's deadline has passed at `now` (which is then left to
    /// reconciliation or a person), is left as it is, and the row is completed all the same.
    /// A `duplicate` is refused, since only begin writes one, and so is `unknown` for a row
    /// with no receipt, since a read never reports it.
    ///
    /// `reached`, the resources a tool that checks its own scope reached, replaces the row's
    /// `unknown` resources in the same write, as Postgres's `complete_once` lets it.
    fn complete_with(
        &mut self,
        id: &AuditRowId,
        completion: &Completion,
        reference: Option<&VendorReference>,
        reached: Option<&ReachedResources>,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let Some(settled) = ReceiptState::settled_by(&completion.outcome) else {
            return Err("a duplicate is written at begin, never by finish".into());
        };
        let receipt = self.receipts.iter().position(|receipt| receipt.row == *id);
        if receipt.is_none() && completion.outcome == Outcome::Unknown {
            return Err(format!(
                "audit row {} reserved no receipt, so its outcome cannot be unknown",
                id.as_str()
            )
            .into());
        }
        if receipt.is_none() && reference.is_some() {
            return Err(format!(
                "audit row {} reserved no receipt, so it has no vendor reference to keep",
                id.as_str()
            )
            .into());
        }
        self.complete_row(id, completion, reached)?;
        let past_deadline = self.past_deadline(id, now);
        if let Some(receipt) = receipt.map(|at| &mut self.receipts[at])
            && may_move(receipt.state, settled, &EstablishedBy::Call, past_deadline)
        {
            receipt.state = settled;
            receipt.established_by = EstablishedBy::Call;
            receipt.reference = reference.cloned();
        }
        Ok(())
    }

    /// Whether the receipt `receipt` reads as `unknown` at `now`, as
    /// [`as_read`](Self::as_read) reads it: the state `unknown`, or `pending` past its row's
    /// deadline, as Postgres reads `deadline < clock_timestamp()`.
    fn reads_as_unknown(&self, receipt: &Receipt, now: SystemTime) -> bool {
        receipt.state.as_read(self.past_deadline(&receipt.row, now)) == ReceiptState::Unknown
    }

    /// Whether the lease on the receipt `row` is free at `now`: never set, or ended.
    fn lease_free(&self, row: &AuditRowId, now: SystemTime) -> bool {
        self.leases
            .iter()
            .filter(|(leased, _, _)| leased == row)
            .all(|(_, _, until)| *until <= now)
    }

    /// Whether `holder` holds the lease on the receipt `row` at `now`.
    fn holds(&self, row: &AuditRowId, holder: &LeaseHolder, now: SystemTime) -> bool {
        self.leases
            .iter()
            .any(|(leased, by, until)| leased == row && by == holder && *until > now)
    }

    /// Whether `receipt` is due at `now`: it reads as `unknown`, was not handed to a person,
    /// and its lease is free.
    fn due(&self, receipt: &Receipt, now: SystemTime) -> bool {
        self.reads_as_unknown(receipt, now)
            && receipt.handed_to_person.is_none()
            && self.lease_free(&receipt.row, now)
    }

    /// The position of the receipt `row` if `holder` holds its lease at `now` and it reads as
    /// `unknown`, not handed to a person; refused otherwise, as Postgres refuses it.
    fn held(
        &self,
        row: &AuditRowId,
        holder: &LeaseHolder,
        now: SystemTime,
    ) -> Result<usize, StoreError> {
        self.receipts
            .iter()
            .position(|receipt| {
                receipt.row == *row
                    && self.holds(row, holder, now)
                    && receipt.handed_to_person.is_none()
                    && self.reads_as_unknown(receipt, now)
            })
            .ok_or_else(|| {
                format!(
                    "receipt {} is not held under this lease, or no longer reads as unknown, or \
                     was handed to a person; nothing was written",
                    row.as_str()
                )
                .into()
            })
    }

    /// Completes the row `id`, writing `reached` in place of its resources, which must be
    /// `unknown`. A repeat is compared on its completion alone: Postgres's role cannot read a
    /// row's resources to compare them.
    fn complete_row(
        &mut self,
        id: &AuditRowId,
        completion: &Completion,
        reached: Option<&ReachedResources>,
    ) -> Result<(), StoreError> {
        if self.list_rows.iter().any(|(stored, _, _)| stored == id) {
            return Err(format!(
                "audit row {} records a listing, which is never completed",
                id.as_str()
            )
            .into());
        }
        let (_, row, _) = self
            .rows
            .iter_mut()
            .find(|(stored, _, _)| stored == id)
            .ok_or_else(|| StoreError::from("no such row"))?;
        if row.decision != DecisionKind::Allow {
            return Err(format!(
                "audit row {} records a denial, which is never completed",
                id.as_str()
            )
            .into());
        }
        match &row.completion {
            None => {
                if let Some(reached) = reached {
                    if row.resources != RecordedResources::Unknown {
                        return Err(format!(
                            "audit row {} was begun with resources that are not unknown, so \
                             what its tool reached cannot replace them",
                            id.as_str()
                        )
                        .into());
                    }
                    row.resources = RecordedResources::Named(reached.resources.clone());
                    row.resources_omitted = reached.omitted;
                }
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
/// succeeds if it is identical to the completion the row has, an error's kind included, and
/// otherwise fails and leaves the first completion standing.
///
/// It refuses what the Postgres store's column mapping refuses, and writes nothing: an
/// identifier that is not a UUID in the lowercase hyphenated form, a record handed to begin
/// already complete, a record, list record or completion with U+0000 in a text value, a count
/// of resources or tools left out or a latency past a Postgres `bigint`, and a call row whose
/// allowance is past one. It holds that store's row bound, as [`row_bound`](crate::row_bound)
/// counts it: begin refuses a call row over 522,203 bytes and list a list row over 512 KiB,
/// naming the row's largest column, and finish refuses a refusal's sentence over 2,048 bytes,
/// leaving the row open. Of the table's own constraints it checks these: unknown resources or
/// a reach with a count left out, a reach naming no entry, `kind_shape`, which refuses a call
/// record of kind `list` at begin, and the delegation's (migration 0010): a verified
/// delegation's columns only with its team and person, and a delegation's failure only on a
/// row check 3 denied for it, beside nothing from its claims, and with a digest only after a
/// verified signature. An epoch past a Postgres `bigint` is refused too. It keeps a row's
/// credential identity as begin was
/// given it, its mode and principal together, as the table's `credential_shape` requires.
/// Of its triggers it follows both: `set_times`, which refuses a deadline past what a Postgres
/// time holds, and `complete_once`.
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
/// deadline the record carries, the finish deadline and the answer budget, in whole
/// milliseconds. It adds that allowance to the time at begin as Postgres's `set_times` does,
/// through `float8`, and refuses a call row whose deadline Postgres would refuse: one at or
/// past 294277-01-01 UTC, or an allowance of 2^63 microseconds or more. A row of kind `list`
/// has no deadline. The clock is a [`FixedClock`] at [`FIXTURE_NOW`](crate::FIXTURE_NOW)
/// unless set.
///
/// List rows, which `list` writes, are kept apart and read back with
/// [`list_rows`](Self::list_rows). They share identifiers with call rows, as one Postgres table
/// does: a second list with a known list row's identifier writes nothing and succeeds, and a
/// list or a begin with the identifier of a row of the other kind fails. A list counts as a
/// begin for the failure settings, a lost confirmation and the gate: it fails when a begin
/// would, and is held with the begins. It is not counted in
/// [`begin_attempts`](Self::begin_attempts).
///
/// It keeps receipts (decision 0009, part 2), as the Postgres store does, and reads
/// them back with [`receipts`](Self::receipts) and [`receipt`](Self::receipt). A begin with a
/// receipt is a begin like any other, through the same checks, switches and gate, and in the
/// same write it either reserves the receipt as `pending` or, when the key already has a
/// receipt in its scope under another row, writes the row complete with the answer of the
/// core's [`Reuse::answer`] and reserves nothing. A receipt reserved under the row being begun
/// is passed over, so a retried begin finds its own receipt and is answered as reserved while
/// it is `pending`; once it has left `pending` the retry is refused. A denial reserves nothing:
/// a begin with a receipt for one is refused. Every completion settles the row's receipt in the
/// same write, a lost begin's as `not_performed`, only as the core's
/// [`may_move`] allows; and a completion `unknown` for a row with no receipt, or `duplicate`,
/// is refused. A receipt still `pending` past its row's deadline, by the store's clock, reads
/// as `unknown` wherever the store reads it (decision 0009): in [`receipts`](Self::receipts)
/// and [`receipt`](Self::receipt), in the reuse check's answer, and on a retried begin of its
/// own row, which is refused rather than answered as reserved. The contract suite's runner
/// reads them as held, with [`held_receipts`](Self::held_receipts).
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
    /// call deadline, the finish deadline and the answer budget. `None` if begin wrote no such
    /// row, or for a row of kind `list`, which has none.
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

    /// The times for a call row begun now, with `allowance_ms` to its deadline. `None` when
    /// the deadline is past what Postgres's `set_times` accepts.
    fn times_for(&self, allowance_ms: u64) -> Option<Times> {
        let begun_at = self.clock.now();
        let deadline = Some(postgres_deadline(begun_at, allowance_ms)?);
        Some(Times { begun_at, deadline })
    }

    /// The state, with every late completion whose gate has opened written.
    fn state(&self) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.settle(self.clock.now());
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

    /// Every receipt, in the order reserved, with its state as it reads now: a `pending`
    /// receipt past its row's deadline, by the store's clock, reads as `unknown` (decision
    /// 0009).
    pub fn receipts(&self) -> Vec<Receipt> {
        let now = self.clock.now();
        let state = self.state();
        state
            .receipts
            .iter()
            .map(|receipt| state.as_read(receipt, now))
            .collect()
    }

    /// The receipt reserved under the row `id`, if one was, with its state as it reads now, as
    /// [`receipts`](Self::receipts) says.
    pub fn receipt(&self, id: &AuditRowId) -> Option<Receipt> {
        let now = self.clock.now();
        let state = self.state();
        state
            .receipts
            .iter()
            .find(|receipt| receipt.row == *id)
            .map(|receipt| state.as_read(receipt, now))
    }

    /// Every receipt, in the order reserved, as the store holds it: a `pending` receipt past
    /// its row's deadline is still `pending` here. For the contract suite, whose runner reports
    /// what a store holds and reads each state itself.
    pub fn held_receipts(&self) -> Vec<Receipt> {
        self.state().receipts.clone()
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

    /// Holds every [`claim`](ReceiptQueue::claim) from here on at a gate, which is returned. No
    /// lease is set until it opens, so a test can see that nothing is looked up before a claim
    /// is committed.
    pub fn hold_claims(&self) -> Gate {
        let gate = Gate::closed();
        self.state().claim_gate = Some(gate.clone());
        gate
    }

    /// The next [`claim`](ReceiptQueue::claim) fails, writing nothing, and later ones work.
    pub fn fail_next_claim(&self) {
        self.state().claims_failing = Failing::Next;
    }

    /// Who holds the lease on the receipt `row` now, if anyone does.
    pub fn lease_holder(&self, row: &AuditRowId) -> Option<LeaseHolder> {
        let now = self.clock.now();
        let state = self.state();
        state
            .leases
            .iter()
            .find(|(leased, _, until)| leased == row && *until > now)
            .map(|(_, holder, _)| holder.clone())
    }

    /// When the last lease set on the receipt `row` ends, or ended, if one was set.
    pub fn lease_until(&self, row: &AuditRowId) -> Option<SystemTime> {
        self.state()
            .leases
            .iter()
            .find(|(leased, _, _)| leased == row)
            .map(|(_, _, until)| *until)
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

impl InMemoryAuditStore {
    /// Begin, with a receipt to reserve or not: what [`AuditStore::begin`] and
    /// [`AuditStore::begin_with_receipt`] each do, in one body, so that every switch and check
    /// holds for both. `None` when it was given no receipt.
    fn begin_row<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
        receipt: Option<&'a ReceiptRequest>,
    ) -> BoxFuture<'a, Result<Option<Reservation>, StoreError>> {
        let gate = {
            let mut state = self.state();
            state.begin_attempts += 1;
            state.begin_gate.clone()
        };
        Box::pin(async move {
            let allowance_ms = refused_at_begin(row, record, &self.budgets)?;
            if receipt.is_some() && record.decision != DecisionKind::Allow {
                return Err(format!(
                    "audit row {} records a denial, which reserves no receipt",
                    row.as_str()
                )
                .into());
            }
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
            let now = self.clock.now();
            // The reuse check comes first, for a retried begin too, and passes over a receipt
            // reserved under this row, so that a retried begin never refuses itself.
            let reuse = state.reuse_answer(row, receipt, now)?;
            let mut reservation = None;
            match state.rows.iter().find(|(id, _, _)| id == row) {
                None => {
                    let times = self
                        .times_for(allowance_ms)
                        .ok_or_else(|| StoreError::from("the row's deadline is out of range"))?;
                    // The row and its receipt, or its answer, in one write.
                    state.rows.push((row.clone(), record.clone(), times));
                    reservation = state.reserve(row, receipt, reuse.clone());
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
            if receipt.is_some() && reservation.is_none() {
                reservation = Some(state.found(row, reuse, now)?);
            }
            if state.confirmation_lost.take() {
                // As the Postgres store completes a lost begin's row, and the core gives up a
                // guard: an error of the kind `other`.
                let error = Completion {
                    outcome: Outcome::Error {
                        error_kind: ErrorKind::Other,
                    },
                    latency_ms: 0,
                };
                // Only an allowed row is completed, and its receipt settled as `not_performed`
                // with it. A denial is refused, and a row completed before, the answer to a
                // reused key included, keeps its completion, as complete_once refuses and keeps
                // them.
                let _ = state.complete(row, &error, self.clock.now());
                return Err(lost());
            }
            Ok(reservation)
        })
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
        let begun = self.begin_row(row, record, None);
        Box::pin(async move { begun.await.map(|_| ()) })
    }

    fn begin_with_receipt<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
        receipt: &'a ReceiptRequest,
    ) -> BoxFuture<'a, Result<Reservation, StoreError>> {
        let begun = self.begin_row(row, record, Some(receipt));
        Box::pin(async move {
            begun
                .await?
                .ok_or_else(|| StoreError::from("a begin with a receipt reserved nothing"))
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
            refused_at_finish(completion.completion(), completion.reached())?;
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
                    reference: completion.reference().cloned(),
                    reached: completion.reached().cloned(),
                });
                return Err(format!(
                    "audit row {} was not completed within the answer budget; the store is still trying",
                    completion.row().as_str()
                )
                .into());
            }
            state.complete_with(
                completion.row(),
                completion.completion(),
                completion.reference(),
                completion.reached(),
                self.clock.now(),
            )
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

/// The queue of `unknown` receipts as the Postgres store keeps it (decision 0009,
/// "Reconciliation"), by this store's clock: a receipt is due when it reads as `unknown`, was
/// not handed to a person and its lease is free; a claim sets a lease only on a receipt still
/// due; a lookup is appended, never changed, and moves the receipt as the core's
/// [`LookupAnswer::settles`] says, or hands it to a person on its last attempt; and nothing is
/// written for a holder whose lease has ended. A claim can be held at a gate
/// ([`hold_claims`](InMemoryAuditStore::hold_claims)) or told to fail
/// ([`fail_next_claim`](InMemoryAuditStore::fail_next_claim)).
impl ReceiptQueue for InMemoryAuditStore {
    fn due<'a>(&'a self, limit: usize) -> BoxFuture<'a, Result<Vec<Receipt>, StoreError>> {
        Box::pin(async move {
            let now = self.clock.now();
            let state = self.state();
            Ok(state
                .receipts
                .iter()
                .filter(|receipt| state.due(receipt, now))
                .take(limit)
                .cloned()
                .collect())
        })
    }

    fn claim<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        lease: Duration,
    ) -> BoxFuture<'a, Result<Option<Receipt>, StoreError>> {
        let gate = self.state().claim_gate.clone();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let now = self.clock.now();
            let mut state = self.state();
            if state.claims_failing.take() {
                return Err(down());
            }
            let Some(receipt) = state
                .receipts
                .iter()
                .find(|receipt| receipt.row == *row && state.due(receipt, now))
                .cloned()
            else {
                return Ok(None);
            };
            let until = now.checked_add(lease).unwrap_or(now);
            state.leases.retain(|(leased, _, _)| leased != row);
            state.leases.push((row.clone(), holder.clone(), until));
            Ok(Some(receipt))
        })
    }

    fn record_lookup<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
        answer: &'a LookupAnswer,
        attempts: u32,
    ) -> BoxFuture<'a, Result<Recorded, StoreError>> {
        Box::pin(async move {
            let now = self.clock.now();
            let mut state = self.state();
            let at = state.held(row, holder, now)?;
            let receipt = &mut state.receipts[at];
            let made = receipt.lookups.len();
            if made >= usize::try_from(attempts).unwrap_or(usize::MAX) {
                return Err(format!(
                    "receipt {} already has {attempts} lookups, all it may have; nothing was \
                     written",
                    row.as_str()
                )
                .into());
            }
            let answer = answer.recorded();
            receipt.lookups.push(LookupRecord {
                at: now,
                answer: answer.clone(),
            });
            Ok(match answer.settles() {
                Some(settled) => {
                    receipt.state = settled;
                    receipt.established_by = EstablishedBy::Reconciliation;
                    receipt.reference = answer.reference().cloned();
                    Recorded::Settled(settled)
                }
                None if made + 1 >= usize::try_from(attempts).unwrap_or(usize::MAX) => {
                    receipt.handed_to_person = Some(now);
                    Recorded::HandedToPerson
                }
                None => Recorded::Left,
            })
        })
    }

    fn hand_to_person<'a>(
        &'a self,
        row: &'a AuditRowId,
        holder: &'a LeaseHolder,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let now = self.clock.now();
            let mut state = self.state();
            let at = state.held(row, holder, now)?;
            state.receipts[at].handed_to_person = Some(now);
            Ok(())
        })
    }
}
