//! Receipts for side effects (decision 0009, part 2): the key a call carries, the scope a key is
//! unique in, the digest of a call's arguments, a receipt's states and the moves between them,
//! and the answers to a reused key.
//!
//! A receipt is the gateway's durable record of one side effect it was asked to cause: one call
//! of a tool not classified `read`. [`audit::begin`](crate::audit::begin) asks the store to
//! reserve one, as `pending`, in the same write as the call's row, through
//! [`AuditStore::begin_with_receipt`](crate::AuditStore::begin_with_receipt), and the store
//! first checks whether the call's key already has a receipt in its scope. If it has, the call
//! does not run: [`Reuse::answer`] says what the caller reads, and the row is written already
//! complete with [`Reuse::completion`]. [`audit::finish`](crate::audit::finish) settles the
//! receipt in the same write as the row's completion, as [`ReceiptState::settled_by`] says.
//!
//! What is not built here: reconciliation, which settles an `unknown` receipt by a lookup; the
//! vendor target a lookup needs and the lookups made, which a receipt will record once it
//! exists; and resolution records, by which a person settles one (decision 0009, Still open
//! 10). [`may_move`] already says which moves reconciliation and a person may make.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::audit::{AuditRowId, Completion, Outcome, RecordedResources};
use crate::canonical::canonical;
use crate::names::{Person, ToolName, ToolUseId};
use crate::principal::PrincipalId;
use crate::sentences;

/// The longest an [`IdempotencyKey`] may be, in characters.
///
/// The key's first carrier is the caller's tool-use identifier, which the gateway keeps only
/// when it is 1 to 128 printable ASCII characters, so every tool-use identifier the gateway
/// keeps is a valid key. A key is chosen by the caller, and is written into the receipt and
/// into the sentences that answer a reused key, so it is bounded like every other value a
/// caller chooses. Claude Code's tool-use identifiers are about 30 characters.
pub const MAX_IDEMPOTENCY_KEY: usize = 128;

/// The key a call of a tool not classified `read` carries, chosen per request by the caller,
/// so that a retry of the call is answered from its receipt instead of running again (decision
/// 0009, "The key").
///
/// 1 to [`MAX_IDEMPOTENCY_KEY`] printable ASCII characters other than space. A key outside
/// that rule is not a key, rather than one cut or escaped: two different keys must never be
/// recorded alike, and a key reads the same in a receipt, a sentence and a log line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdempotencyKey(String);

/// A string that is not a valid [`IdempotencyKey`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error(
    "not a valid idempotency key: a key is 1 to {MAX_IDEMPOTENCY_KEY} printable ASCII characters other than space"
)]
pub struct InvalidIdempotencyKey;

impl IdempotencyKey {
    /// Checks `value` against the rule.
    pub fn parse(value: &str) -> Result<Self, InvalidIdempotencyKey> {
        let valid = !value.is_empty()
            && value.len() <= MAX_IDEMPOTENCY_KEY
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidIdempotencyKey)
        }
    }

    /// The key as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = InvalidIdempotencyKey;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<IdempotencyKey> for String {
    fn from(key: IdempotencyKey) -> Self {
        key.0
    }
}

/// The identifying fields of a delegation, as one value, that scope a key along with the
/// principal: for Otto, the session and the turn, and the execution if a turn is unique only
/// within one, as Otto's owners agree (decision 0009, Still open 8).
///
/// The core's [`Delegation`](crate::Delegation) does not carry Otto's session, turn and
/// execution yet. The turn-grant verifier fills this once it does (#22). Until then no
/// delegation has one, so a key is scoped to the principal alone.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DelegationKeyScope(String);

impl DelegationKeyScope {
    /// Wraps the delegation's identifying fields, as the verifier that proved the delegation
    /// writes them.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The fields as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a key is unique: the proved principal and, when a delegation is present, the
/// delegation's identifying fields. Within its scope a key is unique across all tools, and a
/// key in one scope never answers a call in another, so two principals, or two delegations of
/// one principal, may each use the same key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyScope {
    /// The proved principal's issuer and subject.
    pub principal: PrincipalId,
    /// The delegation's identifying fields. `None` without a delegation, and, until #22, with
    /// one: see [`DelegationKeyScope`].
    pub delegation: Option<DelegationKeyScope>,
}

/// SHA-256 over a call's arguments in canonical form: RFC 8785, with integers written exactly
/// (decision 0009, "The argument digest"). The core hashes the arguments the guard carries and
/// does not parse a tool's argument format. See the canonical form's limits in the
/// [`canonical`](crate::canonical) module: an integer outside 64 bits reaches the core as the
/// nearest double.
///
/// Written as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArgumentDigest([u8; 32]);

/// A string that is not 64 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("not an argument digest: a digest is 64 lowercase hex digits")]
pub struct InvalidArgumentDigest;

impl ArgumentDigest {
    /// The digest of `arguments`.
    pub fn of(arguments: &serde_json::Value) -> Self {
        Self(Sha256::digest(canonical(arguments).as_bytes()).into())
    }

    /// The digest as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Debug for ArgumentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArgumentDigest({})", self.to_hex())
    }
}

impl TryFrom<String> for ArgumentDigest {
    type Error = InvalidArgumentDigest;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex = value.as_bytes();
        if hex.len() != 64 || !hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(InvalidArgumentDigest);
        }
        let nibble = |c: u8| {
            if c.is_ascii_digit() {
                c - b'0'
            } else {
                c - b'a' + 10
            }
        };
        let mut bytes = [0u8; 32];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = nibble(hex[2 * at]) << 4 | nibble(hex[2 * at + 1]);
        }
        Ok(Self(bytes))
    }
}

impl From<ArgumentDigest> for String {
    fn from(digest: ArgumentDigest) -> Self {
        digest.to_hex()
    }
}

/// The vendor's reference for what a side effect made: a pull request number, a comment
/// identifier. A connector reports it with
/// [`ToolOutcome::Completed`](crate::ToolOutcome::Completed), and the receipt records it, made
/// safe and capped at 128 characters, since it comes from the vendor's answer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VendorReference(String);

impl VendorReference {
    /// Wraps the vendor's reference.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The reference as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The reference as a receipt records it: escaped and capped.
    pub(crate) fn recorded(&self) -> Self {
        Self(sentences::escape(&self.0, sentences::MAX_RENDERED))
    }
}

/// A receipt's state (decision 0009, "What a receipt is").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    /// Reserved; no outcome yet. Past its row's deadline it reads as [`Unknown`](Self::Unknown)
    /// wherever it is read: see [`as_read`](Self::as_read).
    Pending,
    /// The vendor confirmed the effect. Its reference is recorded, if the vendor gave one.
    Completed,
    /// Established, not assumed, that nothing took effect.
    NotPerformed,
    /// The request may have reached the vendor, and the result is not known.
    Unknown,
}

impl ReceiptState {
    /// The state a receipt in this state reads as, once its row's deadline has passed or not:
    /// a `pending` receipt past its row's deadline reads as `unknown`. Every other state reads
    /// as itself.
    pub fn as_read(self, past_deadline: bool) -> ReceiptState {
        match self {
            ReceiptState::Pending if past_deadline => ReceiptState::Unknown,
            state => state,
        }
    }

    /// The state a call's outcome settles its receipt in (decision 0009, "Outcomes"): `ok` as
    /// `completed`, `error` and `refused` as `not_performed`, and `unknown` as `unknown`.
    /// `None` for `duplicate`, which is never the outcome of a call that reserved a receipt.
    pub fn settled_by(outcome: &Outcome) -> Option<ReceiptState> {
        match outcome {
            Outcome::Ok => Some(ReceiptState::Completed),
            Outcome::Error { .. } | Outcome::Refused { .. } => Some(ReceiptState::NotPerformed),
            Outcome::Unknown => Some(ReceiptState::Unknown),
            Outcome::Duplicate { .. } => None,
        }
    }
}

/// How a receipt's state was established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "by")]
pub enum EstablishedBy {
    /// By the call that reserved it: its reservation, and its finish.
    Call,
    /// By reconciliation, from a lookup.
    Reconciliation,
    /// By a named person, in a resolution record.
    Person {
        /// Who.
        person: Person,
    },
}

/// Whether a receipt may move from `from` to `to`, established `by`, when its row's deadline
/// has passed or not (decision 0009, "What a receipt is"):
///
/// - A receipt leaves `pending` once, for any of the other three. The call that reserved it
///   may settle it so at any time, its deadline passed or not.
/// - A receipt leaves `unknown`, or a `pending` past its deadline, only by reconciliation or a
///   person, and only for `completed` or `not_performed`.
/// - Nothing returns to `pending`, and `completed` and `not_performed` are final.
///
/// A store moves a receipt only as this allows.
pub fn may_move(
    from: ReceiptState,
    to: ReceiptState,
    by: &EstablishedBy,
    past_deadline: bool,
) -> bool {
    let settled = matches!(to, ReceiptState::Completed | ReceiptState::NotPerformed);
    match (from, by) {
        (ReceiptState::Pending, EstablishedBy::Call) => to != ReceiptState::Pending,
        (ReceiptState::Pending, _) => past_deadline && settled,
        (ReceiptState::Unknown, EstablishedBy::Call) => false,
        (ReceiptState::Unknown, _) => settled,
        (ReceiptState::Completed | ReceiptState::NotPerformed, _) => false,
    }
}

/// A receipt, as a store keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// The audit row that reserved it, which is also the receipt's identifier: one row
    /// reserves at most one receipt, and every receipt is reserved by one row.
    pub row: AuditRowId,
    /// Where its key is unique.
    pub scope: KeyScope,
    /// The key the call carried.
    pub key: IdempotencyKey,
    /// The tool the call ran.
    pub tool: ToolName,
    /// The caller's tool-use identifier, if it sent one.
    pub tool_use_id: Option<ToolUseId>,
    /// The digest of the call's arguments.
    pub digest: ArgumentDigest,
    /// The resources the call named, as its row records them.
    pub resources: RecordedResources,
    /// How many distinct named resources were left out of `resources`, as on its row.
    pub resources_omitted: usize,
    /// Its state.
    pub state: ReceiptState,
    /// How that state was established.
    pub established_by: EstablishedBy,
    /// The vendor's reference for what was made, once known.
    pub reference: Option<VendorReference>,
}

impl Receipt {
    /// The receipt's identifier: the row that reserved it.
    pub fn id(&self) -> &AuditRowId {
        &self.row
    }
}

/// What [`audit::begin`](crate::audit::begin) asks a store to reserve for an allowed call of a
/// tool not classified `read`. Made only by the core, from the decided call, its arguments and
/// its row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRequest {
    scope: KeyScope,
    key: IdempotencyKey,
    tool: ToolName,
    tool_use_id: Option<ToolUseId>,
    digest: ArgumentDigest,
    resources: RecordedResources,
    resources_omitted: usize,
}

impl ReceiptRequest {
    pub(crate) fn new(
        scope: KeyScope,
        key: IdempotencyKey,
        tool: ToolName,
        tool_use_id: Option<ToolUseId>,
        digest: ArgumentDigest,
        resources: (RecordedResources, usize),
    ) -> Self {
        Self {
            scope,
            key,
            tool,
            tool_use_id,
            digest,
            resources: resources.0,
            resources_omitted: resources.1,
        }
    }

    /// Where the key is unique.
    pub fn scope(&self) -> &KeyScope {
        &self.scope
    }

    /// The key.
    pub fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// The tool the call names.
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// The caller's tool-use identifier, if it sent one.
    pub fn tool_use_id(&self) -> Option<&ToolUseId> {
        self.tool_use_id.as_ref()
    }

    /// The digest of the call's arguments.
    pub fn digest(&self) -> &ArgumentDigest {
        &self.digest
    }

    /// Whether `receipt` is for this request's key in its scope.
    pub fn same_key(&self, receipt: &Receipt) -> bool {
        receipt.scope == self.scope && receipt.key == self.key
    }

    /// The receipt this request reserves under `row`: `pending`, established by the call, with
    /// no reference yet.
    pub fn reserve(&self, row: &AuditRowId) -> Receipt {
        Receipt {
            row: row.clone(),
            scope: self.scope.clone(),
            key: self.key.clone(),
            tool: self.tool.clone(),
            tool_use_id: self.tool_use_id.clone(),
            digest: self.digest,
            resources: self.resources.clone(),
            resources_omitted: self.resources_omitted,
            state: ReceiptState::Pending,
            established_by: EstablishedBy::Call,
            reference: None,
        }
    }
}

/// The answer to a call whose key already has a receipt in its scope (decision 0009, "Reuse").
/// The call does not run. Its row is written already complete, with [`completion`](Self::completion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reuse {
    /// The earlier receipt recorded a different tool-use identifier: the key was reused for a
    /// different call, as a key fixed in a client's configuration is. `refused`.
    DifferentCall {
        /// The key.
        key: IdempotencyKey,
    },
    /// A different tool, or different arguments. `refused`, naming the key.
    Conflicting {
        /// The key.
        key: IdempotencyKey,
    },
    /// The same tool and arguments, `completed`: it was already done. `duplicate`, and
    /// answered as a success, because an error invites the caller to try again another way,
    /// under a new key.
    Duplicate {
        /// The key.
        key: IdempotencyKey,
        /// The earlier receipt.
        receipt: AuditRowId,
        /// The vendor's reference for what it made, if the vendor gave one.
        reference: Option<VendorReference>,
    },
    /// The same tool and arguments, `pending` or `unknown`: it may already have happened, must
    /// not be repeated, and will be checked as that receipt. `refused`.
    MayHaveHappened {
        /// The key.
        key: IdempotencyKey,
        /// The earlier receipt.
        receipt: AuditRowId,
    },
    /// The same tool and arguments, `not_performed`: nothing was done, and a new attempt needs
    /// a new key. `refused`.
    NotPerformed {
        /// The key.
        key: IdempotencyKey,
        /// The earlier receipt.
        receipt: AuditRowId,
    },
}

impl Reuse {
    /// The answer to `request`, whose key already has `earlier` in its scope. The first line of
    /// decision 0009's table that matches decides. A store calls this in the same write as the
    /// check, and passes over a receipt reserved under the call's own row, so that a retried
    /// begin never refuses itself.
    ///
    /// An earlier receipt that recorded a tool-use identifier matches the first line unless
    /// this call carries the same one; this call carrying none is a different call. One that
    /// recorded none goes on to the next line.
    pub fn answer(request: &ReceiptRequest, earlier: &Receipt) -> Reuse {
        let key = request.key.clone();
        let receipt = earlier.row.clone();
        if let Some(recorded) = &earlier.tool_use_id
            && request.tool_use_id.as_ref() != Some(recorded)
        {
            return Reuse::DifferentCall { key };
        }
        if earlier.tool != request.tool || earlier.digest != request.digest {
            return Reuse::Conflicting { key };
        }
        match earlier.state {
            ReceiptState::Completed => Reuse::Duplicate {
                key,
                receipt,
                reference: earlier.reference.clone(),
            },
            ReceiptState::Pending | ReceiptState::Unknown => {
                Reuse::MayHaveHappened { key, receipt }
            }
            ReceiptState::NotPerformed => Reuse::NotPerformed { key, receipt },
        }
    }

    /// The sentence the caller reads, which a refusal's row also holds.
    pub fn sentence(&self) -> String {
        sentences::render_reuse(self)
    }

    /// Whether this is a `duplicate`, answered as a success.
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Reuse::Duplicate { .. })
    }

    /// The completion the row of a call answered so is written with, at begin: `duplicate`
    /// naming the earlier receipt, or `refused` with [`sentence`](Self::sentence), and a
    /// latency of zero, since nothing ran.
    pub fn completion(&self) -> Completion {
        let outcome = match self {
            Reuse::Duplicate { receipt, .. } => Outcome::Duplicate {
                receipt: receipt.clone(),
            },
            _ => Outcome::Refused {
                sentence: self.sentence(),
            },
        };
        Completion {
            outcome,
            latency_ms: 0,
        }
    }
}

/// What a store did with [`AuditStore::begin_with_receipt`](crate::AuditStore::begin_with_receipt).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The row was written open, and a `pending` receipt reserved under it. A retried begin
    /// that finds both, written by an earlier attempt whose confirmation was lost, answers
    /// this too.
    Reserved,
    /// The key already had a receipt in its scope, reserved under another row. This call's
    /// row was written complete, with the answer's [`completion`](Reuse::completion), and no
    /// receipt was reserved. A retried begin that finds such a row answers what it was written
    /// with.
    Reused(Reuse),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_key_follows_its_rule() {
        let longest = "k".repeat(MAX_IDEMPOTENCY_KEY);
        for valid in ["k", "toolu_01ABC", "a-b_c.d:e/f", longest.as_str()] {
            assert!(
                IdempotencyKey::parse(valid).is_ok(),
                "{valid:?} was refused"
            );
        }
        let too_long = "k".repeat(MAX_IDEMPOTENCY_KEY + 1);
        for invalid in ["", too_long.as_str(), "a b", "a\nb", "caf\u{e9}", "\u{0}"] {
            assert_eq!(
                IdempotencyKey::parse(invalid),
                Err(InvalidIdempotencyKey),
                "{invalid:?} was accepted"
            );
        }
        assert!(serde_json::from_str::<IdempotencyKey>(r#""a b""#).is_err());
    }

    #[test]
    fn the_digest_ignores_order_and_whitespace() {
        let one: serde_json::Value =
            serde_json::from_str("{\"b\": [1, {\"d\": 2, \"c\": 3}],\n \"a\": \"x\"}").unwrap();
        let other: serde_json::Value =
            serde_json::from_str("{\"a\":\"x\",\"b\":[1,{\"c\":3,\"d\":2}]}").unwrap();
        assert_eq!(ArgumentDigest::of(&one), ArgumentDigest::of(&other));
        assert_ne!(
            ArgumentDigest::of(&one),
            ArgumentDigest::of(&json!({"a": "x", "b": [{"c": 3, "d": 2}, 1]})),
            "the order of an array is part of its value"
        );
    }

    /// Two different integers above 2^53, which one double holds, have different digests: they
    /// are written exactly, not as the double nearest each.
    #[test]
    fn integers_above_two_to_the_53_keep_different_digests() {
        let one: serde_json::Value = serde_json::from_str(r#"{"n": 9007199254740993}"#).unwrap();
        let other: serde_json::Value = serde_json::from_str(r#"{"n": 9007199254740992}"#).unwrap();
        assert_ne!(ArgumentDigest::of(&one), ArgumentDigest::of(&other));
        let large: serde_json::Value =
            serde_json::from_str(r#"{"n": 18446744073709551615}"#).unwrap();
        let below: serde_json::Value =
            serde_json::from_str(r#"{"n": 18446744073709551614}"#).unwrap();
        assert_ne!(ArgumentDigest::of(&large), ArgumentDigest::of(&below));
    }

    /// A string's escaping is canonical: the same string written with different JSON escapes
    /// has one digest, and different strings have different ones.
    #[test]
    fn string_escaping_is_canonical() {
        let escaped: serde_json::Value =
            serde_json::from_str("{\"s\": \"\\u0041\\u00e9\\/\\u000A\"}").unwrap();
        let plain: serde_json::Value = serde_json::from_str("{\"s\": \"A\u{e9}/\\n\"}").unwrap();
        assert_eq!(ArgumentDigest::of(&escaped), ArgumentDigest::of(&plain));
        assert_ne!(
            ArgumentDigest::of(&json!({"s": "a\nb"})),
            ArgumentDigest::of(&json!({"s": "a\\nb"}))
        );
    }

    /// The digest is SHA-256 over the canonical form, written in hex: pinned for one value, so a
    /// change to either shows.
    #[test]
    fn the_digest_is_sha256_of_the_canonical_form() {
        // SHA-256 of the 8 bytes `{"a":1}` is this, as `printf '{"a":1}' | shasum -a 256` gives.
        let digest = ArgumentDigest::of(&json!({"a": 1}));
        assert_eq!(
            digest.to_hex(),
            "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
        );
        let text = serde_json::to_string(&digest).unwrap();
        assert_eq!(
            serde_json::from_str::<ArgumentDigest>(&text).unwrap(),
            digest
        );
        assert!(serde_json::from_str::<ArgumentDigest>("\"00\"").is_err());
    }

    const STATES: [ReceiptState; 4] = [
        ReceiptState::Pending,
        ReceiptState::Completed,
        ReceiptState::NotPerformed,
        ReceiptState::Unknown,
    ];

    /// Every move, by everyone, before and after the deadline, against the state table.
    #[test]
    fn a_receipt_moves_only_as_the_state_table_allows() {
        use ReceiptState::{Completed, NotPerformed, Pending, Unknown};
        let person = EstablishedBy::Person {
            person: "someone@example.test".into(),
        };
        for from in STATES {
            for to in STATES {
                for by in [
                    EstablishedBy::Call,
                    EstablishedBy::Reconciliation,
                    person.clone(),
                ] {
                    for past in [false, true] {
                        let by_call = by == EstablishedBy::Call;
                        let settled = matches!(to, Completed | NotPerformed);
                        let expected = match from {
                            Pending if by_call => to != Pending,
                            Pending => past && settled,
                            Unknown => !by_call && settled,
                            Completed | NotPerformed => false,
                        };
                        assert_eq!(
                            may_move(from, to, &by, past),
                            expected,
                            "{from:?} to {to:?} by {by:?}, past the deadline: {past}"
                        );
                    }
                }
            }
        }
        // Spelled out: nothing returns to pending; reconciliation cannot take a pending
        // receipt still in its deadline; the call cannot settle an unknown one.
        for by in [EstablishedBy::Call, EstablishedBy::Reconciliation] {
            assert!(!may_move(Unknown, Pending, &by, true));
        }
        assert!(!may_move(
            Pending,
            Completed,
            &EstablishedBy::Reconciliation,
            false
        ));
        assert!(!may_move(Unknown, Completed, &EstablishedBy::Call, true));
        assert!(may_move(Pending, Unknown, &EstablishedBy::Call, true));
    }

    #[test]
    fn a_pending_receipt_past_its_deadline_reads_as_unknown() {
        assert_eq!(ReceiptState::Pending.as_read(false), ReceiptState::Pending);
        assert_eq!(ReceiptState::Pending.as_read(true), ReceiptState::Unknown);
        for state in [
            ReceiptState::Completed,
            ReceiptState::NotPerformed,
            ReceiptState::Unknown,
        ] {
            assert_eq!(state.as_read(true), state);
            assert_eq!(state.as_read(false), state);
        }
    }

    #[test]
    fn each_outcome_settles_a_receipt_as_decision_0009_says() {
        use crate::ErrorKind;
        assert_eq!(
            ReceiptState::settled_by(&Outcome::Ok),
            Some(ReceiptState::Completed)
        );
        assert_eq!(
            ReceiptState::settled_by(&Outcome::Error {
                error_kind: ErrorKind::Other
            }),
            Some(ReceiptState::NotPerformed)
        );
        assert_eq!(
            ReceiptState::settled_by(&Outcome::Refused {
                sentence: "No.".into()
            }),
            Some(ReceiptState::NotPerformed)
        );
        assert_eq!(
            ReceiptState::settled_by(&Outcome::Unknown),
            Some(ReceiptState::Unknown)
        );
        assert_eq!(
            ReceiptState::settled_by(&Outcome::Duplicate {
                receipt: AuditRowId::new("r")
            }),
            None
        );
    }

    fn request(
        tool_use_id: Option<&str>,
        tool: &str,
        arguments: serde_json::Value,
    ) -> ReceiptRequest {
        ReceiptRequest::new(
            KeyScope {
                principal: PrincipalId {
                    issuer: "https://issuer.example.test".into(),
                    subject: "sandbox".into(),
                },
                delegation: None,
            },
            IdempotencyKey::parse("key-1").unwrap(),
            ToolName::parse(tool).unwrap(),
            tool_use_id.map(ToolUseId::from),
            ArgumentDigest::of(&arguments),
            (RecordedResources::Named(Vec::new()), 0),
        )
    }

    /// Each receipt state against each line of the reuse table, and the first line that
    /// matches decides.
    #[test]
    fn each_receipt_state_is_answered_by_the_first_line_that_matches() {
        let key = IdempotencyKey::parse("key-1").unwrap();
        let receipt = AuditRowId::new("earlier");
        let original = request(Some("toolu-1"), "sys__draft", json!({"a": 1}));
        for state in STATES {
            let mut earlier = original.reserve(&receipt);
            earlier.state = state;
            earlier.reference = Some(VendorReference::new("PR-7"));
            let answer = |call: &ReceiptRequest| Reuse::answer(call, &earlier);

            // Line 1, whatever else matches or not.
            for call in [
                request(Some("toolu-2"), "sys__draft", json!({"a": 1})),
                request(None, "sys__draft", json!({"a": 1})),
                request(Some("toolu-2"), "sys__other", json!({"a": 2})),
            ] {
                assert_eq!(
                    answer(&call),
                    Reuse::DifferentCall { key: key.clone() },
                    "{state:?}"
                );
            }
            // Line 2: another tool, or other arguments.
            for call in [
                request(Some("toolu-1"), "sys__other", json!({"a": 1})),
                request(Some("toolu-1"), "sys__draft", json!({"a": 2})),
            ] {
                assert_eq!(
                    answer(&call),
                    Reuse::Conflicting { key: key.clone() },
                    "{state:?}"
                );
            }
            // Lines 3 to 5: the same call, by the earlier receipt's state.
            let expected = match state {
                ReceiptState::Completed => Reuse::Duplicate {
                    key: key.clone(),
                    receipt: receipt.clone(),
                    reference: Some(VendorReference::new("PR-7")),
                },
                ReceiptState::Pending | ReceiptState::Unknown => Reuse::MayHaveHappened {
                    key: key.clone(),
                    receipt: receipt.clone(),
                },
                ReceiptState::NotPerformed => Reuse::NotPerformed {
                    key: key.clone(),
                    receipt: receipt.clone(),
                },
            };
            assert_eq!(answer(&original), expected, "{state:?}");
        }
        // An earlier receipt with no tool-use identifier goes on to the other lines.
        let mut earlier = request(None, "sys__draft", json!({"a": 1})).reserve(&receipt);
        earlier.state = ReceiptState::Unknown;
        assert_eq!(
            Reuse::answer(&original, &earlier),
            Reuse::MayHaveHappened {
                key,
                receipt: receipt.clone()
            }
        );
    }

    /// A `duplicate` is written as such, naming the earlier receipt, and every other answer as
    /// `refused` with the sentence the caller reads, each with a latency of zero.
    #[test]
    fn a_reused_keys_row_is_written_with_its_answer() {
        let key = IdempotencyKey::parse("key-1").unwrap();
        let receipt = AuditRowId::new("earlier");
        let duplicate = Reuse::Duplicate {
            key: key.clone(),
            receipt: receipt.clone(),
            reference: None,
        };
        assert_eq!(
            duplicate.completion(),
            Completion {
                outcome: Outcome::Duplicate {
                    receipt: receipt.clone()
                },
                latency_ms: 0
            }
        );
        for refused in [
            Reuse::DifferentCall { key: key.clone() },
            Reuse::Conflicting { key: key.clone() },
            Reuse::MayHaveHappened {
                key: key.clone(),
                receipt: receipt.clone(),
            },
            Reuse::NotPerformed {
                key: key.clone(),
                receipt: receipt.clone(),
            },
        ] {
            assert_eq!(
                refused.completion(),
                Completion {
                    outcome: Outcome::Refused {
                        sentence: refused.sentence()
                    },
                    latency_ms: 0
                }
            );
            assert!(!refused.is_duplicate());
        }
    }
}
