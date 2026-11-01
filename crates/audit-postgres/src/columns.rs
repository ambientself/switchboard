//! What each column of `switchboard_audit.call_rows` holds, taken from the core's record.
//!
//! No I/O here, so the mapping is tested without a database.
//!
//! A row is exactly its record, or it is not written. Postgres text, text arrays and jsonb
//! cannot hold U+0000, and callers choose some values, such as their tool-use identifier. A
//! record with U+0000 in any text value is refused with [`PgAuditError::Nul`], naming the
//! column, rather than written with another character in its place: begin fails, so the core
//! refuses the call. A latency or a count past its column's range is refused the same way. So
//! is a row over its bound, naming its largest column: [`MAX_BEGUN_ROW_BYTES`] for a call row
//! at begin, and [`MAX_ROW_BYTES`] for a list row. At finish, a refusal's sentence holding
//! U+0000 or longer than [`MAX_OUTCOME_SENTENCE_BYTES`], and a reach longer than
//! [`MAX_REACHED_BYTES`], are refused, never cut: finish fails and gives up, and the row keeps
//! no completion.
//!
//! The testkit's in-memory store refuses the same rows and completions with copies of these
//! constants and of [`BeginRow::sizes`] and [`ListRow::sizes`] (`gateway_testkit::row_bound`).
//! A test here checks that the copies agree.

use std::time::Duration;

use gateway_core::audit::{
    AuditRecord, AuditRowId, Completion, DecisionKind, ErrorKind, ListRecord,
    MAX_RECORDED_RESOURCES, Outcome, ReachedResources, RecordedDelegation, RecordedFailure,
    RecordedResources, RowKind,
};
use gateway_core::receipt::ReceiptRequest;
use gateway_core::{
    ArgumentDigest, CredentialIdentity, CredentialMode, DelegationKeyScope, Principal,
    PrincipalKind, Receipt, ReceiptState, Reuse, ToolName, ToolUseId, VendorReference,
};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

use crate::store::{Budgets, PgAuditError};

/// The most a row may hold, in bytes (decision 0014, section 7): 512 KiB, counted as the bytes
/// of the values the store sends, the completion finish writes included. A text value counts
/// its UTF-8, a text array its elements' UTF-8, a JSON value its JSON text, and an integer its
/// 8 bytes.
///
/// Finish cannot see the row begin wrote, so begin leaves room for the completion: it refuses a
/// row over [`MAX_BEGUN_ROW_BYTES`], this bound less [`COMPLETION_RESERVE`], and finish refuses
/// the one completion value that has no fixed size, the refusal sentence, when it is longer
/// than [`MAX_OUTCOME_SENTENCE_BYTES`]. An allowed call whose resources are `unknown`, one whose
/// tool checks its own scope, may have them replaced at finish by the resources its tool
/// reached (decision 0011), so begin counts that row's resources as [`MAX_REACHED_BYTES`], the
/// most a reach may hold, and finish refuses a reach longer than that. A list row is written
/// complete and never completed, so list refuses one over this bound itself. Either refusal at
/// begin or list names the row's largest column, and the call or the list is refused.
///
/// The values a caller chooses, and the ones it can make long, are capped before they reach a
/// row, so in the largest row a call can begin they take at most 316,129 bytes, leaving 206,074
/// of the 522,203 a begun row may hold for the rest, and a reserve of 2,085 bytes for the
/// completion after that:
///
/// - `resources`: 298,049 for named resources. At most 64 resources (`MAX_RECORDED_RESOURCES`),
///   each a system and a kind of at most 128 escaped characters and an identifier of at most
///   2,048, each cut with a 3-byte `…`. Escaped text is ASCII, and JSON doubles at most each
///   character, a backslash or a quote: so 2 + 2 × 128 + 3 = 261 bytes for a system or kind
///   and 2 + 2 × 2,048 + 3 = 4,101 for an identifier, quotes included; with the keys, braces
///   and commas, 4,656 a resource, and 64 × 4,656 + 63 commas + 2 brackets in all. A reach is
///   written as `{"reach": entry}`, and the entry is a connector name from the registry, which
///   has no cap of its own: an operator may name one long enough that the row is over the
///   bound, and begin then refuses it, naming `resources`. Nothing a caller chooses can make a
///   reach that long. An allowed call's `unknown` resources are counted as
///   [`MAX_REACHED_BYTES`], the same 298,049, since finish may write what its tool reached in
///   their place.
/// - `proved_subject` and `proved_groups`: 16,384 together. Both come from one token, which is
///   at most 16 KiB (`gateway_identity::MAX_TOKEN_BYTES`), and decoding it only shortens them.
/// - `sentence`: 1,046. The longest denial, a resource outside the caller's limit, is its
///   template's text and seven escaped values, the tool, the resource's system, kind and
///   identifier, and the workload's subject, team and issuer, each at most 128 characters and a
///   `…`, 131 bytes.
/// - `tool_use_id`: 128 printable ASCII characters at most. `surface`, `tool` and `instance`:
///   131 each, 128 escaped characters and a `…`.
/// - The fixed words and numbers: `id` 36, `reason` 28, `credential_mode` 21, `classification`
///   11, `proved_kind` 8, `decision` 5, `kind` 4, and `resources_omitted` and `allowance_ms` 8
///   each.
/// - Decision 0012's columns (migration 0010), 801 at most together: `delegation_issuer`,
///   `delegation_key_id`, `delegation_session`, `delegation_turn` and `delegation_execution`
///   131 each, escaped and capped by the core; `delegation_digest` 64, `proved_pod` 36,
///   `delegation_failure` 21, `currency` 11, `delegation_epoch` 8 and `delegation_egress` 6. A
///   verified delegation's values come from the control plane that signed it, and nothing from
///   a delegation that did not verify reaches a row.
///
/// The rest have no cap of their own. `deployment`, `profile`, `connector`, `policy_revision`,
/// `proved_issuer`, `proved_team` and `credential_principal` come from the gateway's own
/// configuration, its deployment file and registry, not from a caller.
/// `proved_delegation_team`, `claimed_acting_person` and `claimed_team` are not set by the
/// gateway yet.
///
/// So the largest row a call can make, begun at 522,203 bytes and finished with the longest
/// completion finish writes and the longest reach, is at most 524,288 bytes. A denial is never
/// completed, and an allowed call has no `reason` or `sentence`, so a finished row is in fact
/// smaller.
pub const MAX_ROW_BYTES: usize = 512 * 1024;

/// The most bytes finish writes in `outcome_sentence`. A longer refusal sentence is refused
/// with [`PgAuditError::TooLong`], naming the column and this cap, as one holding U+0000 is
/// refused, never cut: finish sends nothing and gives up, and the row keeps no completion.
///
/// A refusal's sentence is one the gateway makes, from these sources:
///
/// - connector-proxy's fixed sentences, `outcome::NOT_SERVED` (84 bytes) and
///   `outcome::NO_CREDENTIAL` (76);
/// - the gateway's bulkhead, `bulkhead::server_at_capacity` and `bulkhead::team_at_capacity`,
///   at most 150 bytes besides the configured server's name and the approved tool's name;
/// - the gateway's argument check, `proxied::withdrawn_while_deciding`, 138 bytes besides the
///   approved tool's name;
/// - a connector built on `gateway_core::Connector` outside this repository, which may return
///   any sentence.
///
/// The server's refusal of a call (`outcome::UPSTREAM_REFUSED`, its `403`) is an error of the
/// kind `vendor_refusal`, not a refusal, and the row records the kind, not a sentence. So does
/// every other error. 2 KiB holds every sentence the gateway makes with a server and a tool name
/// of 900 bytes each (the gateway's `tests/limits.rs` checks this). A configured name long
/// enough to make a sentence longer than this, or a longer sentence from a connector outside
/// this repository, makes that finish refused: the caller is answered with the audit-failure
/// sentence instead, and the row is left open.
pub const MAX_OUTCOME_SENTENCE_BYTES: usize = 2 * 1024;

/// The longest name an outcome has: `refused`.
const LONGEST_OUTCOME: usize = "refused".len();

/// The longest name an error kind has: `oversized_or_late_read`.
const LONGEST_ERROR_KIND: usize = "oversized_or_late_read".len();

/// The most bytes a completion adds to a row, as [`MAX_ROW_BYTES`] counts them: the longest
/// outcome (7), the longest error kind (22), the latency (8) and the longest sentence finish
/// writes ([`MAX_OUTCOME_SENTENCE_BYTES`]), 2,085 in all. No completion has both an error kind
/// and a sentence, so this counts 22 bytes more than one can add.
pub const COMPLETION_RESERVE: usize =
    LONGEST_OUTCOME + LONGEST_ERROR_KIND + INTEGER_BYTES + MAX_OUTCOME_SENTENCE_BYTES;

/// The most a call row may hold when begin writes it, in bytes: [`MAX_ROW_BYTES`] less
/// [`COMPLETION_RESERVE`], 522,203, so the row stays within the bound once finished. An allowed
/// call's `unknown` resources are counted as [`MAX_REACHED_BYTES`] towards it.
pub const MAX_BEGUN_ROW_BYTES: usize = MAX_ROW_BYTES - COMPLETION_RESERVE;

/// The most bytes finish writes in `resources` for a tool that checks its own scope, as
/// [`MAX_ROW_BYTES`] counts them: the most named resources hold, 64 resources of 4,656 bytes
/// each, 63 commas and 2 brackets, 298,049 in all. The core records a reach as begin records
/// named resources, escaped and capped, so no reach it makes is longer. Begin counts an allowed
/// call's `unknown` resources as this, since finish may write the reach in their place, and
/// finish refuses a longer reach with [`PgAuditError::TooLong`], naming `resources` and this
/// cap, rather than write a row over the bound.
pub const MAX_REACHED_BYTES: usize =
    MAX_RECORDED_RESOURCES * MAX_RECORDED_RESOURCE_BYTES + (MAX_RECORDED_RESOURCES - 1) + 2;

/// The most bytes one recorded resource holds as JSON: a system and a kind of at most 128
/// escaped characters and an identifier of at most 2,048, each cut with a 3-byte `…` and each
/// character doubled at most by JSON's escaping, 261, 261 and 4,101 bytes with their quotes,
/// and 33 for the keys, colons, commas and braces: 4,656.
const MAX_RECORDED_RESOURCE_BYTES: usize = 2 * (2 + 2 * 128 + 3) + (2 + 2 * 2_048 + 3) + 33;

/// The bytes of a text value, as the store sends it.
fn text_bytes(text: &str) -> usize {
    text.len()
}

/// The bytes of a text value that may be absent: none when it is.
fn optional_bytes(text: Option<&str>) -> usize {
    text.map_or(0, text_bytes)
}

/// The bytes of a text array: its elements'.
fn array_bytes(texts: Option<&[String]>) -> usize {
    texts.map_or(0, |texts| texts.iter().map(|text| text.len()).sum())
}

/// The bytes of a JSON value: its JSON text, as the store sends it.
fn json_bytes(value: &Value) -> usize {
    /// Counts what is written to it.
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => counter.0,
        Err(_) => usize::MAX,
    }
}

/// The bytes of an integer column.
const INTEGER_BYTES: usize = std::mem::size_of::<i64>();

/// Refuses a row whose columns, as `columns` counts them, hold more than `bound`, naming the
/// largest: [`MAX_BEGUN_ROW_BYTES`] for a call row at begin, [`MAX_ROW_BYTES`] for a list row.
fn within_bound(columns: &[(&'static str, usize)], bound: usize) -> Result<(), PgAuditError> {
    let bytes = columns
        .iter()
        .fold(0_usize, |total, (_, bytes)| total.saturating_add(*bytes));
    if bytes > bound {
        let column = columns
            .iter()
            .max_by_key(|(_, bytes)| *bytes)
            .map_or("", |(column, _)| column);
        return Err(PgAuditError::RowTooLarge {
            column,
            bytes,
            bound,
        });
    }
    Ok(())
}

/// The columns begin writes, in the order of [`BeginRow::INSERT`]'s parameters.
#[derive(Debug, PartialEq)]
pub(crate) struct BeginRow {
    /// The identifier the gateway chose, a UUID in the lowercase hyphenated form.
    pub id: String,
    pub tool_use_id: Option<String>,
    pub deployment: String,
    pub surface: String,
    pub profile: String,
    pub tool: String,
    pub connector: Option<String>,
    pub classification: Option<&'static str>,
    pub resources: Value,
    pub resources_omitted: i64,
    pub decision: &'static str,
    pub reason: Option<String>,
    pub sentence: Option<String>,
    pub policy_revision: String,
    pub proved_issuer: String,
    pub proved_subject: String,
    pub proved_kind: &'static str,
    pub proved_team: Option<String>,
    pub proved_groups: Option<Vec<String>>,
    pub proved_delegation_team: Option<String>,
    pub claimed_acting_person: Option<String>,
    pub claimed_team: Option<String>,
    /// The gateway instance that began the row.
    pub instance: String,
    /// `call` or `list`.
    pub kind: &'static str,
    /// What the database adds to its own time at begin for the row's deadline, in
    /// milliseconds: see [`allowance_ms`].
    pub allowance_ms: i64,
    /// The configured entry identity's credential mode, recorded at begin; with
    /// `credential_principal`, or neither.
    pub credential_mode: Option<&'static str>,
    /// The vendor-side principal the entry states, never the secret.
    pub credential_principal: Option<String>,
    /// The proved pod and the verified delegation's columns.
    pub delegation: DelegationColumns,
    /// Which check a delegation that did not verify failed, on a row check 3 denied.
    pub delegation_failure: Option<&'static str>,
    /// What the control plane answered when asked whether the turn is current.
    pub currency: Option<&'static str>,
}

/// The proved pod and the verified delegation's columns (decision 0012), which a call row and a
/// list row both write, in the order of their parameters. A digest is also written for a
/// delegation that did not verify, when its signature did.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct DelegationColumns {
    pub proved_pod: Option<String>,
    pub delegation_digest: Option<String>,
    pub delegation_issuer: Option<String>,
    pub delegation_key_id: Option<String>,
    pub delegation_session: Option<String>,
    pub delegation_turn: Option<String>,
    pub delegation_execution: Option<String>,
    pub delegation_epoch: Option<i64>,
    pub delegation_egress: Option<&'static str>,
}

impl DelegationColumns {
    /// The columns, in order.
    pub const NAMES: [&'static str; 9] = [
        "proved_pod",
        "delegation_digest",
        "delegation_issuer",
        "delegation_key_id",
        "delegation_session",
        "delegation_turn",
        "delegation_execution",
        "delegation_epoch",
        "delegation_egress",
    ];

    /// The columns for `principal`'s pod, `delegation`, a verified delegation, and `failure`,
    /// one that did not verify, whose digest is written only when it has one. Refuses an epoch
    /// past the column's range, and a text value holding U+0000.
    fn of(
        principal: &Principal,
        delegation: Option<&RecordedDelegation>,
        failure: Option<&RecordedFailure>,
    ) -> Result<Self, PgAuditError> {
        let mut columns = Self {
            proved_pod: principal.pod().map(|pod| pod.as_str().to_owned()),
            delegation_digest: failure
                .and_then(|failure| failure.digest)
                .map(|digest| digest.to_hex()),
            ..Self::default()
        };
        if let Some(delegation) = delegation {
            columns.delegation_digest = Some(delegation.digest.to_hex());
            columns.delegation_issuer =
                Some(stored("delegation_issuer", delegation.issuer.as_str())?);
            columns.delegation_key_id =
                Some(stored("delegation_key_id", delegation.key_id.as_str())?);
            columns.delegation_session =
                Some(stored("delegation_session", delegation.session.as_str())?);
            columns.delegation_turn = Some(stored("delegation_turn", delegation.turn.as_str())?);
            columns.delegation_execution = Some(stored(
                "delegation_execution",
                delegation.execution.as_str(),
            )?);
            columns.delegation_epoch = Some(i64::try_from(delegation.epoch).map_err(|_| {
                PgAuditError::Column("a delegation's epoch past the column's range")
            })?);
            columns.delegation_egress = delegation.egress.map(|egress| egress.as_str());
        }
        Ok(columns)
    }

    /// Each column and its bytes, as [`MAX_ROW_BYTES`] counts them.
    fn sizes(&self) -> [(&'static str, usize); 9] {
        let [
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ] = Self::NAMES;
        [
            (pod, optional_bytes(self.proved_pod.as_deref())),
            (digest, optional_bytes(self.delegation_digest.as_deref())),
            (issuer, optional_bytes(self.delegation_issuer.as_deref())),
            (key_id, optional_bytes(self.delegation_key_id.as_deref())),
            (session, optional_bytes(self.delegation_session.as_deref())),
            (turn, optional_bytes(self.delegation_turn.as_deref())),
            (
                execution,
                optional_bytes(self.delegation_execution.as_deref()),
            ),
            (epoch, self.delegation_epoch.map_or(0, |_| INTEGER_BYTES)),
            (egress, optional_bytes(self.delegation_egress)),
        ]
    }

    /// The values, in order.
    fn parameters(&self) -> [&(dyn ToSql + Sync); 9] {
        [
            &self.proved_pod,
            &self.delegation_digest,
            &self.delegation_issuer,
            &self.delegation_key_id,
            &self.delegation_session,
            &self.delegation_turn,
            &self.delegation_execution,
            &self.delegation_epoch,
            &self.delegation_egress,
        ]
    }
}

impl BeginRow {
    /// Writes the first half of a row under the identifier the gateway chose, unless a row
    /// with that identifier is already stored. Inserts one row or none; when none,
    /// [`DECISION`](Self::DECISION) reads what the stored row decided.
    pub const INSERT: &'static str = "INSERT INTO switchboard_audit.call_rows (
            id, tool_use_id, deployment, surface, profile, tool, connector, classification,
            resources, resources_omitted, decision, reason, sentence, policy_revision,
            proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
            proved_delegation_team, claimed_acting_person, claimed_team, instance, kind,
            allowance_ms, credential_mode, credential_principal,
            proved_pod, delegation_digest, delegation_issuer, delegation_key_id,
            delegation_session, delegation_turn, delegation_execution, delegation_epoch,
            delegation_egress, delegation_failure, currency
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27,
            $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38
        ) ON CONFLICT (id) DO NOTHING";

    /// The first half of a row and the answer to a reused key, in one insert: the row written
    /// complete at begin, with the [`AnswerRow`]'s columns after [`INSERT`](Self::INSERT)'s.
    /// Inserts one row or none, as that does.
    pub const INSERT_ANSWERED: &'static str = "INSERT INTO switchboard_audit.call_rows (
            id, tool_use_id, deployment, surface, profile, tool, connector, classification,
            resources, resources_omitted, decision, reason, sentence, policy_revision,
            proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
            proved_delegation_team, claimed_acting_person, claimed_team, instance, kind,
            allowance_ms, credential_mode, credential_principal,
            proved_pod, delegation_digest, delegation_issuer, delegation_key_id,
            delegation_session, delegation_turn, delegation_execution, delegation_epoch,
            delegation_egress, delegation_failure, currency,
            outcome, outcome_sentence, latency_ms, duplicate_of
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27,
            $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38,
            $39, $40, $41, ($42::text)::uuid
        ) ON CONFLICT (id) DO NOTHING";

    /// The decision of the row already stored under an identifier, read with only the columns
    /// the gateway's role may select. A retried begin compares this and nothing more.
    pub const DECISION: &'static str =
        "SELECT decision FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The decision and the completion of the row already stored under an identifier, for a
    /// retried begin with a receipt: its decision, and the answer it was written with, if it
    /// was written as one. Only columns the gateway's role may select.
    pub const STORED: &'static str = "SELECT decision, outcome, outcome_sentence, latency_ms,
            duplicate_of::text
        FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `record`, as the row `id`, begun by a store with `budgets`. Refuses a
    /// record that is already complete: begin writes the first half of a row, and a
    /// completion handed to it would be silently dropped. Refuses an identifier that is not a
    /// UUID in the lowercase hyphenated form, the form the gateway makes, so that one row has
    /// one spelling. Refuses a row over [`MAX_BEGUN_ROW_BYTES`], which leaves room for the
    /// completion finish writes.
    pub fn from_record(
        id: &AuditRowId,
        record: &AuditRecord,
        budgets: &Budgets,
    ) -> Result<Self, PgAuditError> {
        if record.completion.is_some() {
            return Err(PgAuditError::CompleteAtBegin);
        }
        if !is_uuid(id.as_str()) {
            return Err(PgAuditError::Column("id"));
        }
        let principal = record.proved_principal.get();
        let (proved_kind, proved_team, proved_groups) = principal_kind(principal)?;
        let (resources, resources_omitted) = resources(record)?;
        let (credential_mode, credential_principal) = credential(record.credential.as_ref())?;
        let delegation = DelegationColumns::of(
            principal,
            record.delegation.as_ref(),
            record.delegation_failure.as_ref(),
        )?;
        let row = Self {
            id: id.as_str().to_owned(),
            tool_use_id: optional(
                "tool_use_id",
                record.tool_use_id.as_ref().map(|id| id.as_str()),
            )?,
            deployment: stored("deployment", record.deployment.as_str())?,
            surface: stored("surface", record.surface.as_str())?,
            profile: stored("profile", record.profile.as_str())?,
            tool: stored("tool", &record.tool)?,
            connector: optional("connector", record.connector.as_ref().map(|c| c.as_str()))?,
            classification: record.classification.map(|c| c.as_str()),
            resources,
            resources_omitted,
            decision: decision(record.decision),
            reason: record.reason.map(|kind| name_of(&kind)).transpose()?,
            sentence: optional("sentence", record.sentence.as_deref())?,
            policy_revision: stored("policy_revision", record.policy_revision.as_str())?,
            proved_issuer: stored("proved_issuer", principal.id.issuer.as_str())?,
            proved_subject: stored("proved_subject", principal.id.subject.as_str())?,
            proved_kind,
            proved_team,
            proved_groups,
            proved_delegation_team: optional(
                "proved_delegation_team",
                record
                    .proved_delegation_team
                    .as_ref()
                    .map(|team| team.get().as_str()),
            )?,
            claimed_acting_person: optional(
                "claimed_acting_person",
                record
                    .claimed_acting_person
                    .as_ref()
                    .map(|person| person.get().as_str()),
            )?,
            claimed_team: optional(
                "claimed_team",
                record.claimed_team.as_ref().map(|team| team.get().as_str()),
            )?,
            instance: stored("instance", record.instance.as_str())?,
            kind: kind(record.kind),
            allowance_ms: i64::try_from(allowance_ms(budgets, record.call_deadline_ms))
                .map_err(|_| PgAuditError::Column("an allowance past the column's range"))?,
            credential_mode,
            credential_principal,
            delegation,
            delegation_failure: record
                .delegation_failure
                .as_ref()
                .map(|failure| failure.failure.as_str()),
            currency: record.currency.map(|answer| answer.as_str()),
        };
        within_bound(&row.sizes(), MAX_BEGUN_ROW_BYTES)?;
        Ok(row)
    }

    /// Each column and its bytes, as [`MAX_ROW_BYTES`] counts them: an allowed call's
    /// `unknown` resources as [`MAX_REACHED_BYTES`], which finish may write in their place.
    pub fn sizes(&self) -> [(&'static str, usize); 38] {
        let [
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ] = self.delegation.sizes();
        [
            ("id", text_bytes(&self.id)),
            ("tool_use_id", optional_bytes(self.tool_use_id.as_deref())),
            ("deployment", text_bytes(&self.deployment)),
            ("surface", text_bytes(&self.surface)),
            ("profile", text_bytes(&self.profile)),
            ("tool", text_bytes(&self.tool)),
            ("connector", optional_bytes(self.connector.as_deref())),
            ("classification", optional_bytes(self.classification)),
            ("resources", self.resources_bytes()),
            ("resources_omitted", INTEGER_BYTES),
            ("decision", text_bytes(self.decision)),
            ("reason", optional_bytes(self.reason.as_deref())),
            ("sentence", optional_bytes(self.sentence.as_deref())),
            ("policy_revision", text_bytes(&self.policy_revision)),
            ("proved_issuer", text_bytes(&self.proved_issuer)),
            ("proved_subject", text_bytes(&self.proved_subject)),
            ("proved_kind", text_bytes(self.proved_kind)),
            ("proved_team", optional_bytes(self.proved_team.as_deref())),
            ("proved_groups", array_bytes(self.proved_groups.as_deref())),
            (
                "proved_delegation_team",
                optional_bytes(self.proved_delegation_team.as_deref()),
            ),
            (
                "claimed_acting_person",
                optional_bytes(self.claimed_acting_person.as_deref()),
            ),
            ("claimed_team", optional_bytes(self.claimed_team.as_deref())),
            ("instance", text_bytes(&self.instance)),
            ("kind", text_bytes(self.kind)),
            ("allowance_ms", INTEGER_BYTES),
            ("credential_mode", optional_bytes(self.credential_mode)),
            (
                "credential_principal",
                optional_bytes(self.credential_principal.as_deref()),
            ),
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
            (
                "delegation_failure",
                optional_bytes(self.delegation_failure),
            ),
            ("currency", optional_bytes(self.currency)),
        ]
    }

    /// The bytes `resources` is counted as: its JSON text, or, for an allowed call whose
    /// resources are `unknown`, [`MAX_REACHED_BYTES`], the most the resources its tool reached
    /// may hold when finish writes them in place of `unknown`. Only a tool that checks its own
    /// scope is allowed with `unknown` resources, and a denial is never completed.
    fn resources_bytes(&self) -> usize {
        let held = json_bytes(&self.resources);
        if self.decision == "allow" && self.resources.as_str() == Some("unknown") {
            held.max(MAX_REACHED_BYTES)
        } else {
            held
        }
    }

    /// The values for [`INSERT_ANSWERED`](Self::INSERT_ANSWERED), in order: this row's, and
    /// then `answer`'s.
    pub fn answered_parameters<'a>(&'a self, answer: &'a AnswerRow) -> Vec<&'a (dyn ToSql + Sync)> {
        let mut parameters = self.parameters().to_vec();
        parameters.extend(answer.parameters());
        parameters
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 38] {
        let [
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ] = self.delegation.parameters();
        [
            &self.id,
            &self.tool_use_id,
            &self.deployment,
            &self.surface,
            &self.profile,
            &self.tool,
            &self.connector,
            &self.classification,
            &self.resources,
            &self.resources_omitted,
            &self.decision,
            &self.reason,
            &self.sentence,
            &self.policy_revision,
            &self.proved_issuer,
            &self.proved_subject,
            &self.proved_kind,
            &self.proved_team,
            &self.proved_groups,
            &self.proved_delegation_team,
            &self.claimed_acting_person,
            &self.claimed_team,
            &self.instance,
            &self.kind,
            &self.allowance_ms,
            &self.credential_mode,
            &self.credential_principal,
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
            &self.delegation_failure,
            &self.currency,
        ]
    }
}

/// The credential columns: the configured entry identity's mode and principal, both or neither.
type CredentialColumns = (Option<&'static str>, Option<String>);

/// The credential columns for `credential`, the configured identity of the call's connector
/// entry. A principal holding U+0000 is refused, as every text value is.
fn credential(credential: Option<&CredentialIdentity>) -> Result<CredentialColumns, PgAuditError> {
    let Some(credential) = credential else {
        return Ok((None, None));
    };
    let mode = match credential.mode {
        CredentialMode::TeamServiceIdentity => "team_service_identity",
        CredentialMode::GatewayToken => "gateway_token",
        CredentialMode::PerUserGrant => "per_user_grant",
    };
    Ok((
        Some(mode),
        Some(stored("credential_principal", &credential.principal)?),
    ))
}

/// The columns `proved_kind`, `proved_team` and `proved_groups`.
type PrincipalKindColumns = (&'static str, Option<String>, Option<Vec<String>>);

/// The principal's kind, and its team or its groups.
fn principal_kind(principal: &Principal) -> Result<PrincipalKindColumns, PgAuditError> {
    Ok(match &principal.kind {
        PrincipalKind::Workload { team, .. } => (
            "workload",
            Some(stored("proved_team", team.as_str())?),
            None,
        ),
        PrincipalKind::User { groups } => (
            "user",
            None,
            Some(
                groups
                    .iter()
                    .map(|group| stored("proved_groups", group.as_str()))
                    .collect::<Result<_, _>>()?,
            ),
        ),
    })
}

/// The columns a list row writes, in the order of [`ListRow::INSERT`]'s parameters. Its kind is
/// `list`, written by the statement itself, and it has none of a call's columns.
#[derive(Debug, PartialEq)]
pub(crate) struct ListRow {
    /// The identifier the gateway chose, a UUID in the lowercase hyphenated form.
    pub id: String,
    pub deployment: String,
    pub surface: String,
    pub profile: String,
    pub policy_revision: String,
    pub proved_issuer: String,
    pub proved_subject: String,
    pub proved_kind: &'static str,
    pub proved_team: Option<String>,
    pub proved_groups: Option<Vec<String>>,
    pub proved_delegation_team: Option<String>,
    pub claimed_acting_person: Option<String>,
    pub claimed_team: Option<String>,
    /// The gateway instance that wrote the row.
    pub instance: String,
    /// The names of the tools listed, as a JSON array of strings, in the record's order.
    pub listed_tools: Value,
    /// How many tools were listed past those named.
    pub listed_omitted: i64,
    /// The proved pod and the verified delegation's columns.
    pub delegation: DelegationColumns,
}

impl ListRow {
    /// Writes a list row, complete, under the identifier the gateway chose, unless a row with
    /// that identifier is already stored. Inserts one row or none; when none,
    /// [`KIND`](Self::KIND) reads what kind the stored row is.
    pub const INSERT: &'static str = "INSERT INTO switchboard_audit.call_rows (
            id, deployment, surface, profile, policy_revision, proved_issuer, proved_subject,
            proved_kind, proved_team, proved_groups, proved_delegation_team,
            claimed_acting_person, claimed_team, instance, kind, listed_tools, listed_omitted,
            proved_pod, delegation_digest, delegation_issuer, delegation_key_id,
            delegation_session, delegation_turn, delegation_execution, delegation_epoch,
            delegation_egress
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'list',
            $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
        ) ON CONFLICT (id) DO NOTHING";

    /// The kind of the row already stored under an identifier, read with only the columns the
    /// gateway's role may select. A retried list compares this and nothing more.
    pub const KIND: &'static str =
        "SELECT kind FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `record`, as the row `id`. Refuses an identifier that is not a UUID in
    /// the lowercase hyphenated form, a text value holding U+0000, a count past the column's
    /// range, and a row over [`MAX_ROW_BYTES`]: a list row has no completion to leave room for.
    pub fn from_record(id: &AuditRowId, record: &ListRecord) -> Result<Self, PgAuditError> {
        if !is_uuid(id.as_str()) {
            return Err(PgAuditError::Column("id"));
        }
        let principal = record.proved_principal.get();
        let (proved_kind, proved_team, proved_groups) = principal_kind(principal)?;
        let row = Self {
            id: id.as_str().to_owned(),
            deployment: stored("deployment", record.deployment.as_str())?,
            surface: stored("surface", record.surface.as_str())?,
            profile: stored("profile", record.profile.as_str())?,
            policy_revision: stored("policy_revision", record.policy_revision.as_str())?,
            proved_issuer: stored("proved_issuer", principal.id.issuer.as_str())?,
            proved_subject: stored("proved_subject", principal.id.subject.as_str())?,
            proved_kind,
            proved_team,
            proved_groups,
            proved_delegation_team: optional(
                "proved_delegation_team",
                record
                    .proved_delegation_team
                    .as_ref()
                    .map(|team| team.get().as_str()),
            )?,
            claimed_acting_person: optional(
                "claimed_acting_person",
                record
                    .claimed_acting_person
                    .as_ref()
                    .map(|person| person.get().as_str()),
            )?,
            claimed_team: optional(
                "claimed_team",
                record.claimed_team.as_ref().map(|team| team.get().as_str()),
            )?,
            instance: stored("instance", record.instance.as_str())?,
            listed_tools: Value::Array(
                record
                    .tools
                    .iter()
                    .map(|name| stored("listed_tools", name).map(Value::String))
                    .collect::<Result<_, _>>()?,
            ),
            listed_omitted: i64::try_from(record.tools_omitted).map_err(|_| {
                PgAuditError::Column("a count of tools left out past the column's range")
            })?,
            delegation: DelegationColumns::of(principal, record.delegation.as_ref(), None)?,
        };
        // A list row is written complete and never completed, so it needs no room for one.
        within_bound(&row.sizes(), MAX_ROW_BYTES)?;
        Ok(row)
    }

    /// Each column and its bytes, as [`MAX_ROW_BYTES`] counts them: each parameter, and the
    /// kind `list`, which [`INSERT`](Self::INSERT) writes itself.
    pub fn sizes(&self) -> [(&'static str, usize); 26] {
        let [
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ] = self.delegation.sizes();
        [
            ("id", text_bytes(&self.id)),
            ("deployment", text_bytes(&self.deployment)),
            ("surface", text_bytes(&self.surface)),
            ("profile", text_bytes(&self.profile)),
            ("policy_revision", text_bytes(&self.policy_revision)),
            ("proved_issuer", text_bytes(&self.proved_issuer)),
            ("proved_subject", text_bytes(&self.proved_subject)),
            ("proved_kind", text_bytes(self.proved_kind)),
            ("proved_team", optional_bytes(self.proved_team.as_deref())),
            ("proved_groups", array_bytes(self.proved_groups.as_deref())),
            (
                "proved_delegation_team",
                optional_bytes(self.proved_delegation_team.as_deref()),
            ),
            (
                "claimed_acting_person",
                optional_bytes(self.claimed_acting_person.as_deref()),
            ),
            ("claimed_team", optional_bytes(self.claimed_team.as_deref())),
            ("instance", text_bytes(&self.instance)),
            ("kind", text_bytes(kind(RowKind::List))),
            ("listed_tools", json_bytes(&self.listed_tools)),
            ("listed_omitted", INTEGER_BYTES),
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ]
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 25] {
        let [
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ] = self.delegation.parameters();
        [
            &self.id,
            &self.deployment,
            &self.surface,
            &self.profile,
            &self.policy_revision,
            &self.proved_issuer,
            &self.proved_subject,
            &self.proved_kind,
            &self.proved_team,
            &self.proved_groups,
            &self.proved_delegation_team,
            &self.claimed_acting_person,
            &self.claimed_team,
            &self.instance,
            &self.listed_tools,
            &self.listed_omitted,
            pod,
            digest,
            issuer,
            key_id,
            session,
            turn,
            execution,
            epoch,
            egress,
        ]
    }
}

/// How long past the database's time at begin a row's deadline is, in milliseconds: the begin
/// budget, the call's deadline, the finish deadline and the answer budget, so a row reads as
/// open only once every step could have ended (decision 0009, as amended on 2026-10-11). The
/// answer budget is there because the last attempt to complete a failed begin's row is made at
/// the finish deadline, counted from when the begin failed, and may take one answer budget
/// past it. No call runs on such a row, so without the answer budget it could be completed
/// after its deadline whenever the call deadline is shorter than the answer budget (#96).
/// Saturating, so a long deadline cannot wrap round to a short one; a sum past the column's
/// range is then refused, not cut.
pub(crate) fn allowance_ms(budgets: &Budgets, call_deadline_ms: u64) -> u64 {
    millis(budgets.begin)
        .saturating_add(call_deadline_ms)
        .saturating_add(millis(budgets.finish_deadline))
        .saturating_add(millis(budgets.answer))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn kind(kind: RowKind) -> &'static str {
    match kind {
        RowKind::Call => "call",
        RowKind::List => "list",
    }
}

/// The resources columns: the named resources as a JSON array of `{system, kind, identifier}`,
/// in the record's order, a reach as the JSON object `{"reach": entry}`, or the JSON string
/// `"unknown"`; and how many were left out. A count past the column's range is refused rather
/// than recorded as less than it was.
fn resources(record: &AuditRecord) -> Result<(Value, i64), PgAuditError> {
    resources_of(&record.resources, record.resources_omitted)
}

/// The resources columns for `resources`, with `omitted` of them left out, as
/// [`resources`] writes a row's and a receipt's alike.
fn resources_of(
    resources: &RecordedResources,
    omitted: usize,
) -> Result<(Value, i64), PgAuditError> {
    let resources = match resources {
        RecordedResources::Named(named) => Value::Array(
            named
                .iter()
                .map(|resource| {
                    Ok(json!({
                        "system": stored("resources", &resource.system)?,
                        "kind": stored("resources", &resource.kind)?,
                        "identifier": stored("resources", &resource.identifier)?,
                    }))
                })
                .collect::<Result<_, PgAuditError>>()?,
        ),
        RecordedResources::Reach(entry) => json!({ "reach": stored("resources", entry.as_str())? }),
        RecordedResources::Unknown => Value::String("unknown".to_owned()),
    };
    let omitted = i64::try_from(omitted).map_err(|_| {
        PgAuditError::Column("a count of resources left out past the column's range")
    })?;
    Ok((resources, omitted))
}

/// Whether `id` is a UUID in the lowercase hyphenated form: 8, 4, 4, 4 and 12 hex digits.
/// Postgres would read other spellings of the same UUID too, so they are refused here.
fn is_uuid(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(at, c)| match at {
            8 | 13 | 18 | 23 => c == '-',
            _ => matches!(c, '0'..='9' | 'a'..='f'),
        })
}

/// `text`, for `column`, which cannot hold U+0000.
fn stored(column: &'static str, text: &str) -> Result<String, PgAuditError> {
    if text.contains('\0') {
        return Err(PgAuditError::Nul { column });
    }
    Ok(text.to_owned())
}

fn optional(column: &'static str, text: Option<&str>) -> Result<Option<String>, PgAuditError> {
    text.map(|text| stored(column, text)).transpose()
}

/// `text`, for `column`, which holds at most `cap` bytes: refused when it is longer, naming the
/// column and the cap, rather than cut.
fn within_cap(column: &'static str, text: String, cap: usize) -> Result<String, PgAuditError> {
    if text.len() > cap {
        return Err(PgAuditError::TooLong {
            column,
            bytes: text.len(),
            cap,
        });
    }
    Ok(text)
}

fn decision(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Allow => "allow",
        DecisionKind::Deny => "deny",
    }
}

/// A unit enum's name as the core serializes it, which is how the record states it.
fn name_of<T: serde::Serialize>(value: &T) -> Result<String, PgAuditError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => Ok(name),
        _ => Err(PgAuditError::Column("a value that is not a name")),
    }
}

/// The completion columns finish writes, in the order of [`FinishRow::UPDATE`]'s parameters
/// after the row's identifier, and what the row's receipt, if it reserved one, moves to with it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FinishRow {
    pub outcome: &'static str,
    pub outcome_sentence: Option<String>,
    pub error_kind: Option<&'static str>,
    pub latency_ms: i64,
    /// The state the outcome settles a receipt in, as the core's `ReceiptState::settled_by`
    /// says.
    pub settles: &'static str,
    /// The vendor's reference for what the call made, for its receipt.
    pub reference: Option<String>,
    /// The resources a tool that checks its own scope reached, and how many were left out,
    /// written in place of the row's `unknown` ones by [`UPDATE_REACHED`](Self::UPDATE_REACHED).
    pub reached: Option<(Value, i64)>,
}

impl FinishRow {
    /// Completes a row that has no completion yet. Matches nothing when the row is missing or
    /// already complete; [`SELECT`](Self::SELECT) then says which.
    pub const UPDATE: &'static str = "UPDATE switchboard_audit.call_rows
        SET outcome = $2, outcome_sentence = $3, error_kind = $4, latency_ms = $5
        WHERE id = ($1::text)::uuid AND outcome IS NULL";

    /// [`UPDATE`](Self::UPDATE), and the resources the call's tool reached in place of the
    /// row's `unknown` ones (decision 0011). `complete_once` refuses it for a row begun with
    /// any other resources.
    pub const UPDATE_REACHED: &'static str = "UPDATE switchboard_audit.call_rows
        SET outcome = $2, outcome_sentence = $3, error_kind = $4, latency_ms = $5,
            resources = $6, resources_omitted = $7
        WHERE id = ($1::text)::uuid AND outcome IS NULL";

    /// The completion a row already has, read back with only the columns the gateway's role
    /// may select.
    pub const SELECT: &'static str = "SELECT outcome, outcome_sentence, error_kind, latency_ms
        FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `completion`. Refuses a sentence holding U+0000, a sentence longer than
    /// [`MAX_OUTCOME_SENTENCE_BYTES`], and a latency past the column's range, rather than write
    /// another value than the completion's. So a completion written is never more than
    /// [`COMPLETION_RESERVE`], the room begin left for it; a reach is held to the room begin
    /// left for it by [`with_reached`](Self::with_reached). Refuses a `duplicate`, which only
    /// begin writes, as the answer to a reused key.
    pub fn from_completion(completion: &Completion) -> Result<Self, PgAuditError> {
        let (outcome_sentence, error_kind) = match &completion.outcome {
            Outcome::Refused { sentence } => (Some(refusal_sentence(sentence)?), None),
            Outcome::Error { error_kind } => (None, Some(Self::error_kind_name(*error_kind))),
            Outcome::Ok | Outcome::Unknown => (None, None),
            Outcome::Duplicate { .. } => return Err(PgAuditError::DuplicateAtFinish),
        };
        let settles = match ReceiptState::settled_by(&completion.outcome) {
            Some(ReceiptState::Completed) => "completed",
            Some(ReceiptState::NotPerformed) => "not_performed",
            Some(ReceiptState::Unknown) => "unknown",
            Some(ReceiptState::Pending) | None => return Err(PgAuditError::DuplicateAtFinish),
        };
        let latency_ms = i64::try_from(completion.latency_ms)
            .map_err(|_| PgAuditError::Column("a latency past the column's range"))?;
        Ok(Self {
            outcome: Self::outcome_of(completion),
            outcome_sentence,
            error_kind,
            latency_ms,
            settles,
            reference: None,
            reached: None,
        })
    }

    /// The same columns, with the vendor's `reference` for the row's receipt. Refuses one
    /// holding U+0000, as every text value is refused.
    pub fn with_reference(
        mut self,
        reference: Option<&VendorReference>,
    ) -> Result<Self, PgAuditError> {
        self.reference = optional("reference", reference.map(VendorReference::as_str))?;
        Ok(self)
    }

    /// The same columns, with the resources the call's tool `reached`, written as begin writes
    /// named resources. Refuses a reach longer than [`MAX_REACHED_BYTES`], the room begin left
    /// for it in place of `unknown`, naming `resources` and the cap, rather than write a row over
    /// the bound. The core caps a reach as it caps named resources, so none it makes is longer.
    pub fn with_reached(
        mut self,
        reached: Option<&ReachedResources>,
    ) -> Result<Self, PgAuditError> {
        self.reached = reached
            .map(|reached| {
                let reach = resources_of(
                    &RecordedResources::Named(reached.resources.clone()),
                    reached.omitted,
                )?;
                let bytes = json_bytes(&reach.0);
                if bytes > MAX_REACHED_BYTES {
                    return Err(PgAuditError::TooLong {
                        column: "resources",
                        bytes,
                        cap: MAX_REACHED_BYTES,
                    });
                }
                Ok(reach)
            })
            .transpose()?;
        Ok(self)
    }

    /// Each completion column and its bytes, as [`MAX_ROW_BYTES`] counts them. Finish need not
    /// count them: [`COMPLETION_RESERVE`] is their most. A reach is held to
    /// [`MAX_REACHED_BYTES`], which begin counted in place of `unknown`.
    #[cfg(test)]
    pub fn sizes(&self) -> [(&'static str, usize); 4] {
        [
            ("outcome", text_bytes(self.outcome)),
            (
                "outcome_sentence",
                optional_bytes(self.outcome_sentence.as_deref()),
            ),
            ("error_kind", optional_bytes(self.error_kind)),
            ("latency_ms", INTEGER_BYTES),
        ]
    }

    /// The name the row gives `completion`'s outcome.
    pub fn outcome_of(completion: &Completion) -> &'static str {
        match completion.outcome {
            Outcome::Ok => "ok",
            Outcome::Error { .. } => "error",
            Outcome::Refused { .. } => "refused",
            Outcome::Unknown => "unknown",
            Outcome::Duplicate { .. } => "duplicate",
        }
    }

    /// The name the row gives an error's kind: the core's name for it.
    pub fn error_kind_name(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::InvalidArguments => "invalid_arguments",
            ErrorKind::OversizedOrLateRead => "oversized_or_late_read",
            ErrorKind::CustodianRefusal => "custodian_refusal",
            ErrorKind::VendorRefusal => "vendor_refusal",
            ErrorKind::Other => "other",
        }
    }

    /// Whether a completion read back from the row is this one: the same outcome, sentence,
    /// error kind and latency.
    pub fn is(
        &self,
        outcome: &str,
        outcome_sentence: Option<&str>,
        error_kind: Option<&str>,
        latency_ms: Option<i64>,
    ) -> bool {
        self.outcome == outcome
            && self.outcome_sentence.as_deref() == outcome_sentence
            && self.error_kind == error_kind
            && Some(self.latency_ms) == latency_ms
    }
}

/// A refusal's sentence as the row holds it: refused, never cut, when it holds U+0000 or is
/// longer than [`MAX_OUTCOME_SENTENCE_BYTES`].
fn refusal_sentence(sentence: &str) -> Result<String, PgAuditError> {
    within_cap(
        "outcome_sentence",
        stored("outcome_sentence", sentence)?,
        MAX_OUTCOME_SENTENCE_BYTES,
    )
}

/// The completion a reused key's row is written with at begin, in the order of the last four of
/// [`BeginRow::INSERT_ANSWERED`]'s parameters: `refused` with the answer's sentence, or
/// `duplicate` naming the earlier receipt, with a latency of zero. It is within
/// [`COMPLETION_RESERVE`]: a refusal's sentence is held to [`MAX_OUTCOME_SENTENCE_BYTES`], and a
/// duplicate is its outcome, 9 bytes, the receipt's identifier, 36, and the latency, 8.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AnswerRow {
    pub outcome: &'static str,
    pub outcome_sentence: Option<String>,
    pub latency_ms: i64,
    /// The earlier receipt a `duplicate` names, a UUID in the lowercase hyphenated form.
    pub duplicate_of: Option<String>,
}

impl AnswerRow {
    /// The columns for the completion of `reuse`.
    pub fn from_reuse(reuse: &Reuse) -> Result<Self, PgAuditError> {
        let completion = reuse.completion();
        let (outcome_sentence, duplicate_of) = match &completion.outcome {
            Outcome::Refused { sentence } => (Some(refusal_sentence(sentence)?), None),
            Outcome::Duplicate { receipt } if is_uuid(receipt.as_str()) => {
                (None, Some(receipt.as_str().to_owned()))
            }
            _ => return Err(PgAuditError::Column("an answer to a reused key")),
        };
        let latency_ms = i64::try_from(completion.latency_ms)
            .map_err(|_| PgAuditError::Column("a latency past the column's range"))?;
        Ok(Self {
            outcome: FinishRow::outcome_of(&completion),
            outcome_sentence,
            latency_ms,
            duplicate_of,
        })
    }

    /// The values for the last four of [`BeginRow::INSERT_ANSWERED`]'s parameters, in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 4] {
        [
            &self.outcome,
            &self.outcome_sentence,
            &self.latency_ms,
            &self.duplicate_of,
        ]
    }

    /// Whether a row read back with [`BeginRow::STORED`] holds this answer: its outcome,
    /// sentence, latency and the receipt a duplicate names.
    pub fn is(
        &self,
        outcome: Option<&str>,
        outcome_sentence: Option<&str>,
        latency_ms: Option<i64>,
        duplicate_of: Option<&str>,
    ) -> bool {
        outcome == Some(self.outcome)
            && outcome_sentence == self.outcome_sentence.as_deref()
            && latency_ms == Some(self.latency_ms)
            && duplicate_of == self.duplicate_of.as_deref()
    }
}

/// The columns a receipt is reserved with, in the order of [`ReceiptRow::RESERVE`]'s
/// parameters. Its state, how it was established and its time of reservation come from the
/// table's defaults and its trigger.
#[derive(Debug, PartialEq)]
pub(crate) struct ReceiptRow {
    /// The row that reserves it, a UUID in the lowercase hyphenated form.
    pub row_id: String,
    pub principal_issuer: String,
    pub principal_subject: String,
    pub delegation_scope: Option<String>,
    pub idempotency_key: String,
    pub tool: String,
    pub tool_use_id: Option<String>,
    pub digest: String,
    pub resources: Value,
    pub resources_omitted: i64,
    /// The vendor target's system, kind and identifier, or none of them for a receipt that
    /// goes to a person.
    pub target_system: Option<String>,
    pub target_kind: Option<String>,
    pub target_identifier: Option<String>,
}

impl ReceiptRow {
    /// Reserves the receipt, unless the row already holds one or its key already has one in its
    /// scope: inserts one receipt or none. Of two reservations of one key in one scope at once,
    /// the unique index makes the second wait for the first to commit, and then insert nothing.
    pub const RESERVE: &'static str = "INSERT INTO switchboard_audit.receipts (
            row_id, principal_issuer, principal_subject, delegation_scope, idempotency_key,
            tool, tool_use_id, digest, resources, resources_omitted, target_system, target_kind,
            target_identifier
        ) VALUES (($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT DO NOTHING";

    /// The reuse check for a key with no delegation scope: the receipt for the key `$3` of the
    /// principal `$1`, `$2`, reserved under a row other than `$4`, the call's own, which it
    /// passes over. Its identifier and what [`Reuse::answer`] reads.
    pub const EARLIER_IN_PRINCIPAL: &'static str = "SELECT row_id::text, tool, tool_use_id,
            digest, state, reference
        FROM switchboard_audit.receipts
        WHERE principal_issuer = $1 AND principal_subject = $2 AND delegation_scope IS NULL
            AND idempotency_key = $3 AND row_id <> ($4::text)::uuid";

    /// The reuse check for a key in the delegation scope `$3`: the receipt for the key `$4`
    /// reserved under a row other than `$5`, as
    /// [`EARLIER_IN_PRINCIPAL`](Self::EARLIER_IN_PRINCIPAL) reads it.
    pub const EARLIER_IN_DELEGATION: &'static str = "SELECT row_id::text, tool, tool_use_id,
            digest, state, reference
        FROM switchboard_audit.receipts
        WHERE principal_issuer = $1 AND principal_subject = $2 AND delegation_scope = $3
            AND idempotency_key = $4 AND row_id <> ($5::text)::uuid";

    /// The state of the receipt reserved under a row, if one was.
    pub const STATE: &'static str =
        "SELECT state FROM switchboard_audit.receipts WHERE row_id = ($1::text)::uuid";

    /// The state of the receipt reserved under the row `$1`, if one was, as it reads (decision
    /// 0009, "What a receipt is"): `unknown` while it is still `pending` past its row's
    /// deadline, which is earlier than `clock_timestamp()` by the database's clock, as the
    /// trigger `receipt_moves` judges it. Otherwise its state.
    pub const STATE_AS_READ: &'static str = "SELECT CASE
            WHEN r.state = 'pending' AND c.deadline < clock_timestamp() THEN 'unknown'
            ELSE r.state END
        FROM switchboard_audit.receipts r
            JOIN switchboard_audit.call_rows c ON c.id = r.row_id
        WHERE r.row_id = ($1::text)::uuid";

    /// Settles the receipt reserved under the row `$1` as `$2`, established by the call, with
    /// the reference `$3`, in the same transaction as the row's completion: only while it is
    /// `pending` and its row's deadline has not passed by the database's clock. Matches nothing
    /// otherwise, and the receipt is left for reconciliation or a person. The trigger
    /// `receipt_moves` judges the same rule again as it writes.
    pub const SETTLE: &'static str = "UPDATE switchboard_audit.receipts r
        SET state = $2, established_by = 'call', reference = $3
        WHERE r.row_id = ($1::text)::uuid AND r.state = 'pending'
            AND NOT EXISTS (SELECT FROM switchboard_audit.call_rows c
                            WHERE c.id = r.row_id AND c.deadline < clock_timestamp())";

    /// The columns for the receipt `request` asks for, reserved under the row `id`. Refuses a
    /// value holding U+0000, as every text value is refused.
    pub fn from_request(id: &AuditRowId, request: &ReceiptRequest) -> Result<Self, PgAuditError> {
        if !is_uuid(id.as_str()) {
            return Err(PgAuditError::Column("id"));
        }
        let receipt = request.reserve(id);
        let (resources, resources_omitted) =
            resources_of(&receipt.resources, receipt.resources_omitted)?;
        let scope = request.scope();
        let target = request.target();
        Ok(Self {
            row_id: id.as_str().to_owned(),
            principal_issuer: stored("principal_issuer", scope.principal.issuer.as_str())?,
            principal_subject: stored("principal_subject", scope.principal.subject.as_str())?,
            delegation_scope: optional(
                "delegation_scope",
                scope.delegation.as_ref().map(DelegationKeyScope::as_str),
            )?,
            idempotency_key: stored("idempotency_key", request.key().as_str())?,
            tool: stored("tool", request.tool().as_str())?,
            tool_use_id: optional("tool_use_id", request.tool_use_id().map(|id| id.as_str()))?,
            digest: request.digest().to_hex(),
            resources,
            resources_omitted,
            target_system: optional("target_system", target.map(|target| target.system.as_str()))?,
            target_kind: optional("target_kind", target.map(|target| target.kind.as_str()))?,
            target_identifier: optional(
                "target_identifier",
                target.map(|target| target.identifier.as_str()),
            )?,
        })
    }

    /// The values for [`RESERVE`](Self::RESERVE), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 13] {
        [
            &self.row_id,
            &self.principal_issuer,
            &self.principal_subject,
            &self.delegation_scope,
            &self.idempotency_key,
            &self.tool,
            &self.tool_use_id,
            &self.digest,
            &self.resources,
            &self.resources_omitted,
            &self.target_system,
            &self.target_kind,
            &self.target_identifier,
        ]
    }

    /// The reuse check's statement for this receipt's scope, and its values in order.
    pub fn earlier(&self) -> (&'static str, Vec<&(dyn ToSql + Sync)>) {
        match &self.delegation_scope {
            None => (
                Self::EARLIER_IN_PRINCIPAL,
                vec![
                    &self.principal_issuer,
                    &self.principal_subject,
                    &self.idempotency_key,
                    &self.row_id,
                ],
            ),
            Some(scope) => (
                Self::EARLIER_IN_DELEGATION,
                vec![
                    &self.principal_issuer,
                    &self.principal_subject,
                    scope,
                    &self.idempotency_key,
                    &self.row_id,
                ],
            ),
        }
    }
}

/// The earlier receipt the reuse check found for `request`, from the columns
/// [`ReceiptRow::EARLIER_IN_PRINCIPAL`] reads: what [`Reuse::answer`] compares. Its scope and
/// key are the request's, which the check matched, and so are its resources, which the answer
/// does not read.
pub(crate) fn earlier_receipt(
    request: &ReceiptRequest,
    row: &tokio_postgres::Row,
) -> Result<Receipt, PgAuditError> {
    let id: String = row.try_get(0)?;
    let tool: String = row.try_get(1)?;
    let tool_use_id: Option<String> = row.try_get(2)?;
    let digest: String = row.try_get(3)?;
    let state: String = row.try_get(4)?;
    let reference: Option<String> = row.try_get(5)?;
    let mut receipt = request.reserve(&AuditRowId::new(id));
    receipt.tool =
        ToolName::parse(&tool).map_err(|_| PgAuditError::Unreadable("a receipt's tool"))?;
    receipt.tool_use_id = tool_use_id.map(ToolUseId::new);
    receipt.digest = ArgumentDigest::try_from(digest)
        .map_err(|_| PgAuditError::Unreadable("a receipt's digest"))?;
    receipt.state = receipt_state(&state)?;
    receipt.reference = reference.map(VendorReference::new);
    Ok(receipt)
}

/// A receipt's state, from its column.
pub(crate) fn receipt_state(state: &str) -> Result<ReceiptState, PgAuditError> {
    Ok(match state {
        "pending" => ReceiptState::Pending,
        "completed" => ReceiptState::Completed,
        "not_performed" => ReceiptState::NotPerformed,
        "unknown" => ReceiptState::Unknown,
        _ => return Err(PgAuditError::Unreadable("a receipt's state")),
    })
}

/// Every answer a reused key's row could have been written with from the earlier receipt
/// `earlier`, under `request`'s key: a retried begin finds the one its row holds, whatever has
/// become of the earlier receipt since. A duplicate carries the receipt's reference as it is
/// now; the row does not hold one.
pub(crate) fn answers(request: &ReceiptRequest, earlier: &Receipt) -> [Reuse; 5] {
    let key = request.key().clone();
    let receipt = earlier.row.clone();
    [
        Reuse::DifferentCall { key: key.clone() },
        Reuse::Conflicting { key: key.clone() },
        Reuse::Duplicate {
            key: key.clone(),
            receipt: receipt.clone(),
            reference: earlier.reference.clone(),
        },
        Reuse::MayHaveHappened {
            key: key.clone(),
            receipt: receipt.clone(),
        },
        Reuse::NotPerformed { key, receipt },
    ]
}

/// The largest call row the gateway can begin, as [`MAX_ROW_BYTES`] counts it: every capped
/// value at its cap, with the values that have no cap short, and `policy_revision`, which has
/// none, as long as it must be for the row to hold `bytes`, which must leave it room. It is a
/// denial, whose reason and sentence an allowed call does not have.
#[cfg(test)]
pub(crate) fn largest_record(bytes: usize) -> AuditRecord {
    padded(largest_denial(), bytes)
}

/// The largest call row an allowed call can begin, the largest that finish completes:
/// [`largest_record`]'s with no reason or sentence, which only a denial has, and
/// `policy_revision` as long as it must be for the row to hold `bytes`.
#[cfg(test)]
pub(crate) fn largest_allowed_record(bytes: usize) -> AuditRecord {
    let mut record = largest_denial();
    record.decision = DecisionKind::Allow;
    record.reason = None;
    record.sentence = None;
    padded(record, bytes)
}

/// The largest call row a tool that checks its own scope can begin: [`largest_allowed_record`]'s
/// with `unknown` resources, which begin counts as [`MAX_REACHED_BYTES`], and `policy_revision`
/// as long as it must be for the row to hold `bytes` as begin counts it.
#[cfg(test)]
pub(crate) fn largest_self_scoped_record(bytes: usize) -> AuditRecord {
    let mut record = largest_denial();
    record.decision = DecisionKind::Allow;
    record.reason = None;
    record.sentence = None;
    record.resources = RecordedResources::Unknown;
    record.resources_omitted = 0;
    padded(record, bytes)
}

/// The longest reach the core can record: [`largest_record`]'s named resources, 64 of them,
/// each value of backslashes at its cap, with one more left out.
#[cfg(test)]
pub(crate) fn largest_reach() -> ReachedResources {
    match largest_denial().resources {
        RecordedResources::Named(resources) => ReachedResources {
            resources,
            omitted: 1,
        },
        other => panic!("the largest denial names its resources, not {other:?}"),
    }
}

/// `record` with `policy_revision` as long as it must be for its row to hold `bytes`.
#[cfg(test)]
fn padded(mut record: AuditRecord, bytes: usize) -> AuditRecord {
    let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &record, &Budgets::default())
        .expect("the largest record without its revision fits");
    let held: usize = row.sizes().iter().map(|(_, bytes)| bytes).sum();
    record.policy_revision = "r".repeat(bytes - held).as_str().into();
    record
}

/// The largest denial, every capped value at its cap and `policy_revision` empty.
#[cfg(test)]
fn largest_denial() -> AuditRecord {
    // Escaped values are cut with `…`. A backslash is escaped again in JSON, so a value of
    // backslashes is the longest JSON a recorded resource can be.
    let cut = |text: &str, chars: usize| format!("{}…", text.repeat(chars));
    let resource = json!({
        "system": cut("\\", 128),
        "kind": cut("\\", 128),
        "identifier": cut("\\", 2048),
    });
    serde_json::from_value(json!({
        "kind": "call",
        "instance": cut("i", 128),
        "call_deadline_ms": 60_000,
        "tool_use_id": "t".repeat(128),
        "deployment": "largest",
        "surface": cut("s", 128),
        "profile": "largest",
        "tool": cut("x", 128),
        "connector": "largest",
        "classification": "destructive",
        "resources": {"named": vec![resource; gateway_core::audit::MAX_RECORDED_RESOURCES]},
        "resources_omitted": 1,
        "decision": "deny",
        "reason": "classification_not_permitted",
        "sentence": "d".repeat(1_046),
        "policy_revision": "",
        "proved_principal": {
            "id": {"issuer": "largest", "subject": "u".repeat(8_192)},
            "kind": "user",
            "groups": (1..=4).map(|n| format!("{n}{}", "g".repeat(2_047))).collect::<Vec<_>>()
        },
        "proved_delegation_team": "largest",
        "claimed_acting_person": "largest",
        "claimed_team": null,
        "delegation": {
            "digest": "f".repeat(64),
            "issuer": cut("i", 128),
            "key_id": cut("k", 128),
            "session": cut("s", 128),
            "turn": cut("t", 128),
            "execution": cut("e", 128),
            "epoch": i64::MAX,
            "egress": "sealed"
        },
        "currency": "unconfirmed",
        "credential": {"mode": "team_service_identity", "principal": "largest"},
        "completion": null
    }))
    .expect("the largest record is a record")
}

/// The identifier [`largest_record`] is counted under: a UUID, as every row's is.
#[cfg(test)]
pub(crate) const LARGEST_ID: &str = "0199c3a2-7b1e-7c3d-9f00-00000000000f";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(value: serde_json::Value) -> AuditRecord {
        serde_json::from_value(value).unwrap()
    }

    /// A UUIDv7, as the gateway makes one.
    const ID: &str = "0199c3a2-7b1e-7c3d-9f00-0123456789ab";

    fn id() -> AuditRowId {
        AuditRowId::new(ID)
    }

    /// Budgets unlike the defaults, so the allowance shows which is which.
    fn budgets() -> Budgets {
        Budgets {
            begin: Duration::from_millis(1_500),
            answer: Duration::from_millis(2_250),
            finish_deadline: Duration::from_secs(20),
        }
    }

    fn denied_user_with_delegation() -> AuditRecord {
        record(json!({
            "kind": "call",
            "instance": "gateway-7f9c",
            "call_deadline_ms": 5000,
            "tool_use_id": "toolu_01",
            "deployment": "fixture",
            "surface": "fixture-read",
            "profile": "user-ro",
            "tool": "fixture__write",
            "connector": "fixture",
            "classification": "write",
            "resources": {"named": [
                {"system": "fixture", "kind": "document", "identifier": "team-b/notes"},
                {"system": "fixture", "kind": "document", "identifier": "back\\slash"}
            ]},
            "resources_omitted": 2,
            "decision": "deny",
            "reason": "classification_not_permitted",
            "sentence": "Denied: a sentence.",
            "policy_revision": "fixture-1",
            "proved_principal": {
                "id": {"issuer": "https://user-issuer.fixture.test", "subject": "user-1"},
                "kind": "user",
                "groups": ["group-g", "group-h"]
            },
            "proved_delegation_team": "team-d",
            "claimed_acting_person": "person@fixture.test",
            "claimed_team": "team-c",
            "delegation": {
                "digest": DIGEST,
                "issuer": "otto-fixture",
                "key_id": "key-1",
                "session": "session-1",
                "turn": "turn-1",
                "execution": "execution-1",
                "epoch": 42,
                "egress": "open"
            },
            "currency": "superseded",
            "credential": {"mode": "gateway_token", "principal": "fixture-token"},
            "completion": null
        }))
    }

    /// The SHA-256 of `test`, as a delegation's digest is written.
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// A workload with a pod, denied at check 3 for a delegation that expired after its
    /// signature verified: the failure and the digest, and nothing from the claims.
    fn denied_unverified() -> AuditRecord {
        let mut record = allowed_workload();
        record.decision = DecisionKind::Deny;
        record.reason = Some(gateway_core::ReasonKind::DelegationUnverified);
        record.sentence = Some("Denied.".into());
        record.delegation_failure = Some(RecordedFailure {
            failure: gateway_core::DelegationFailure::Expired,
            digest: Some(gateway_core::DelegationDigest::parse(DIGEST).unwrap()),
        });
        record
    }

    fn allowed_workload() -> AuditRecord {
        record(json!({
            "kind": "call",
            "instance": "gateway-7f9c",
            "call_deadline_ms": 5000,
            "tool_use_id": null,
            "deployment": "fixture",
            "surface": "fixture-all",
            "profile": "workload-rw",
            "tool": "fixture__read",
            "connector": "fixture",
            "classification": "read",
            "resources": "unknown",
            "resources_omitted": 0,
            "decision": "allow",
            "reason": null,
            "sentence": null,
            "policy_revision": "fixture-1",
            "proved_principal": {
                "id": {"issuer": "https://workload-issuer.fixture.test", "subject": "sa"},
                "kind": "workload",
                "team": "team-a",
                "pod": "0f8fad5b-d9cb-469f-a165-70867728950e"
            },
            "proved_delegation_team": null,
            "claimed_acting_person": null,
            "claimed_team": null,
            "completion": null
        }))
    }

    #[test]
    fn each_value_goes_to_its_own_column() {
        let row = BeginRow::from_record(&id(), &denied_user_with_delegation(), &budgets()).unwrap();
        assert_eq!(
            row,
            BeginRow {
                id: ID.into(),
                tool_use_id: Some("toolu_01".into()),
                deployment: "fixture".into(),
                surface: "fixture-read".into(),
                profile: "user-ro".into(),
                tool: "fixture__write".into(),
                connector: Some("fixture".into()),
                classification: Some("write"),
                resources: json!([
                    {"system": "fixture", "kind": "document", "identifier": "team-b/notes"},
                    {"system": "fixture", "kind": "document", "identifier": "back\\slash"}
                ]),
                resources_omitted: 2,
                decision: "deny",
                reason: Some("classification_not_permitted".into()),
                sentence: Some("Denied: a sentence.".into()),
                policy_revision: "fixture-1".into(),
                proved_issuer: "https://user-issuer.fixture.test".into(),
                proved_subject: "user-1".into(),
                proved_kind: "user",
                proved_team: None,
                proved_groups: Some(vec!["group-g".into(), "group-h".into()]),
                proved_delegation_team: Some("team-d".into()),
                claimed_acting_person: Some("person@fixture.test".into()),
                claimed_team: Some("team-c".into()),
                instance: "gateway-7f9c".into(),
                kind: "call",
                allowance_ms: 1_500 + 5_000 + 20_000 + 2_250,
                credential_mode: Some("gateway_token"),
                credential_principal: Some("fixture-token".into()),
                delegation: DelegationColumns {
                    proved_pod: None,
                    delegation_digest: Some(DIGEST.into()),
                    delegation_issuer: Some("otto-fixture".into()),
                    delegation_key_id: Some("key-1".into()),
                    delegation_session: Some("session-1".into()),
                    delegation_turn: Some("turn-1".into()),
                    delegation_execution: Some("execution-1".into()),
                    delegation_epoch: Some(42),
                    delegation_egress: Some("open"),
                },
                delegation_failure: None,
                currency: Some("superseded"),
            }
        );
    }

    /// A delegation that did not verify writes its failure and, after a verified signature,
    /// its digest, and none of a verified delegation's columns; a workload's pod is written as
    /// its token proves it.
    #[test]
    fn an_unverified_delegation_writes_its_failure_and_digest_alone() {
        let row = BeginRow::from_record(&id(), &denied_unverified(), &budgets()).unwrap();
        assert_eq!(
            row.delegation,
            DelegationColumns {
                proved_pod: Some("0f8fad5b-d9cb-469f-a165-70867728950e".into()),
                delegation_digest: Some(DIGEST.into()),
                ..DelegationColumns::default()
            }
        );
        assert_eq!(row.delegation_failure, Some("expired"));
        assert_eq!(row.reason.as_deref(), Some("delegation_unverified"));
        assert_eq!(row.currency, None);
        let mut before_signature = denied_unverified();
        before_signature.delegation_failure = Some(RecordedFailure {
            failure: gateway_core::DelegationFailure::Signature,
            digest: None,
        });
        let row = BeginRow::from_record(&id(), &before_signature, &budgets()).unwrap();
        assert_eq!(row.delegation.delegation_digest, None);
        assert_eq!(row.delegation_failure, Some("signature"));
    }

    /// Every failure and every currency answer is written as the core names it, and an epoch
    /// past the column's range is refused rather than written as another.
    #[test]
    fn each_failure_and_answer_is_named_as_the_core_names_it_and_an_epoch_past_the_column_is_refused()
     {
        for failure in gateway_core::DelegationFailure::ALL {
            let mut record = denied_unverified();
            record.delegation_failure = Some(RecordedFailure {
                failure,
                digest: None,
            });
            let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
            assert_eq!(row.delegation_failure, Some(failure.as_str()));
            assert_eq!(name_of(&failure).unwrap(), failure.as_str());
        }
        for answer in gateway_core::CurrencyAnswer::ALL {
            let mut record = allowed_workload();
            record.currency = Some(answer);
            let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
            assert_eq!(row.currency, Some(answer.as_str()));
            assert_eq!(name_of(&answer).unwrap(), answer.as_str());
        }
        let mut record = denied_user_with_delegation();
        if let Some(delegation) = &mut record.delegation {
            delegation.epoch = i64::MAX.unsigned_abs();
        }
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(row.delegation.delegation_epoch, Some(i64::MAX));
        if let Some(delegation) = &mut record.delegation {
            delegation.epoch = i64::MAX.unsigned_abs() + 1;
        }
        assert!(matches!(
            BeginRow::from_record(&id(), &record, &budgets()),
            Err(PgAuditError::Column(_))
        ));
    }

    /// A NUL in any text value refuses the record, naming the column, rather than write the
    /// row with something else in its place.
    #[test]
    fn a_nul_in_any_text_value_refuses_the_record() {
        let nul = |text: &str| json!(format!("{text}\u{0}x"));
        let refused = |value: serde_json::Value| match BeginRow::from_record(
            &id(),
            &record(value),
            &budgets(),
        ) {
            Err(PgAuditError::Nul { column }) => column,
            other => panic!("{other:?}"),
        };
        let user = serde_json::to_value(denied_user_with_delegation()).unwrap();
        for field in [
            "instance",
            "tool_use_id",
            "deployment",
            "surface",
            "profile",
            "tool",
            "connector",
            "sentence",
            "policy_revision",
            "proved_delegation_team",
            "claimed_acting_person",
            "claimed_team",
        ] {
            let mut value = user.clone();
            value[field] = nul(field);
            assert_eq!(refused(value), field);
        }
        for (field, column) in [("issuer", "proved_issuer"), ("subject", "proved_subject")] {
            let mut value = user.clone();
            value["proved_principal"]["id"][field] = nul(field);
            assert_eq!(refused(value), column);
        }
        let mut value = user.clone();
        value["proved_principal"]["groups"] = json!(["group-g", nul("group")]);
        assert_eq!(refused(value), "proved_groups");
        for field in ["system", "kind", "identifier"] {
            let mut value = user.clone();
            value["resources"]["named"][1][field] = nul(field);
            assert_eq!(refused(value), "resources");
        }
        let mut value = serde_json::to_value(allowed_workload()).unwrap();
        value["proved_principal"]["team"] = nul("team");
        assert_eq!(refused(value), "proved_team");
        let mut value = user.clone();
        value["credential"]["principal"] = nul("principal");
        assert_eq!(refused(value), "credential_principal");
        let mut value = user.clone();
        value["resources"] = json!({"reach": nul("entry")});
        value["resources_omitted"] = json!(0);
        assert_eq!(refused(value), "resources");

        let refused = FinishRow::from_completion(&Completion {
            outcome: Outcome::Refused {
                sentence: "No.\u{0}".into(),
            },
            latency_ms: 1,
        });
        assert!(
            matches!(
                refused,
                Err(PgAuditError::Nul {
                    column: "outcome_sentence"
                })
            ),
            "{refused:?}"
        );
        assert_eq!(
            PgAuditError::Nul {
                column: "tool_use_id"
            }
            .to_string(),
            "the audit column tool_use_id would hold U+0000, which Postgres cannot store, so the \
             row is not written"
        );
    }

    #[test]
    fn an_identifier_that_is_not_a_lowercase_uuid_is_refused() {
        for accepted in [ID, "00000000-0000-4000-8000-000000000000"] {
            let row =
                BeginRow::from_record(&AuditRowId::new(accepted), &allowed_workload(), &budgets());
            assert_eq!(row.unwrap().id, accepted);
        }
        for refused in [
            "",
            "0",
            "not-a-row",
            "0199C3A2-7B1E-7C3D-9F00-0123456789AB",
            "0199c3a27b1e7c3d9f000123456789ab",
            "{0199c3a2-7b1e-7c3d-9f00-0123456789ab}",
            "0199c3a2-7b1e-7c3d-9f00-0123456789a",
            "0199c3a2-7b1e-7c3d-9f00-0123456789abc",
            "0199c3a2+7b1e-7c3d-9f00-0123456789ab",
            "0199c3a2-7b1e-7c3d-9f00-0123456789ag",
            "0199c3a2-7b1e-7c3d-9f00-0123456789\u{e9}",
        ] {
            let row =
                BeginRow::from_record(&AuditRowId::new(refused), &allowed_workload(), &budgets());
            assert!(
                matches!(row, Err(PgAuditError::Column("id"))),
                "{refused:?}: {row:?}"
            );
        }
    }

    /// The allowance is the begin budget, the call deadline, the finish deadline and the
    /// answer budget. A sum too large for the column is refused, not cut.
    #[test]
    fn the_allowance_is_the_begin_budget_call_deadline_finish_deadline_and_answer_budget() {
        let mut record = allowed_workload();
        record.call_deadline_ms = 7_250;
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(row.allowance_ms, 1_500 + 7_250 + 20_000 + 2_250);
        let defaults = BeginRow::from_record(&id(), &record, &Budgets::default()).unwrap();
        assert_eq!(defaults.allowance_ms, 2_000 + 7_250 + 30_000 + 2_000);

        assert_eq!(allowance_ms(&budgets(), u64::MAX), u64::MAX);
        for huge in [
            Budgets {
                begin: Duration::MAX,
                ..budgets()
            },
            Budgets {
                answer: Duration::MAX,
                ..budgets()
            },
        ] {
            assert_eq!(allowance_ms(&huge, 0), u64::MAX);
        }
        for call_deadline_ms in [u64::MAX, i64::MAX.unsigned_abs()] {
            record.call_deadline_ms = call_deadline_ms;
            assert!(matches!(
                BeginRow::from_record(&id(), &record, &budgets()),
                Err(PgAuditError::Column(_))
            ));
        }
        record.call_deadline_ms = i64::MAX.unsigned_abs() - 23_750;
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .allowance_ms,
            i64::MAX
        );
    }

    /// A failed begin's row is completed by attempts that start when the begin fails, at most
    /// the begin budget after the row's time at begin, and go on until the finish deadline,
    /// the last one taking up to one answer budget more. That latest completion falls at or
    /// before the row's deadline even when the call deadline is shorter than the answer
    /// budget, which per-server call deadlines allow down to 1 s (#96).
    #[test]
    fn a_failed_begins_latest_completion_is_within_the_deadline_with_a_short_call_deadline() {
        for budgets in [budgets(), Budgets::default()] {
            let answer_ms = millis(budgets.answer);
            let latest_completion =
                millis(budgets.begin) + millis(budgets.finish_deadline) + answer_ms;
            for call_deadline_ms in [0, 1, 1_000, answer_ms - 1, answer_ms] {
                assert!(
                    latest_completion <= allowance_ms(&budgets, call_deadline_ms),
                    "{budgets:?} with a call deadline of {call_deadline_ms} ms"
                );
            }
        }
    }

    #[test]
    fn a_list_row_is_of_kind_list() {
        let mut record = allowed_workload();
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .kind,
            "call"
        );
        record.kind = RowKind::List;
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .kind,
            "list"
        );
    }

    fn list_record() -> ListRecord {
        serde_json::from_value(json!({
            "instance": "gateway-7f9c",
            "deployment": "fixture",
            "surface": "fixture-read",
            "profile": "user-ro",
            "policy_revision": "fixture-1",
            "proved_principal": {
                "id": {"issuer": "https://user-issuer.fixture.test", "subject": "user-1"},
                "kind": "user",
                "groups": ["group-g"]
            },
            "proved_delegation_team": "team-d",
            "claimed_acting_person": "person@fixture.test",
            "claimed_team": "team-c",
            "delegation": {
                "digest": DIGEST,
                "issuer": "otto-fixture",
                "key_id": "key-1",
                "session": "session-1",
                "turn": "turn-1",
                "execution": "execution-1",
                "epoch": 42,
                "egress": null
            },
            "tools": ["fixture__read", "fixture__write"],
            "tools_omitted": 3
        }))
        .unwrap()
    }

    #[test]
    fn each_list_value_goes_to_its_own_column() {
        assert_eq!(
            ListRow::from_record(&id(), &list_record()).unwrap(),
            ListRow {
                id: ID.into(),
                deployment: "fixture".into(),
                surface: "fixture-read".into(),
                profile: "user-ro".into(),
                policy_revision: "fixture-1".into(),
                proved_issuer: "https://user-issuer.fixture.test".into(),
                proved_subject: "user-1".into(),
                proved_kind: "user",
                proved_team: None,
                proved_groups: Some(vec!["group-g".into()]),
                proved_delegation_team: Some("team-d".into()),
                claimed_acting_person: Some("person@fixture.test".into()),
                claimed_team: Some("team-c".into()),
                instance: "gateway-7f9c".into(),
                listed_tools: json!(["fixture__read", "fixture__write"]),
                listed_omitted: 3,
                delegation: DelegationColumns {
                    proved_pod: None,
                    delegation_digest: Some(DIGEST.into()),
                    delegation_issuer: Some("otto-fixture".into()),
                    delegation_key_id: Some("key-1".into()),
                    delegation_session: Some("session-1".into()),
                    delegation_turn: Some("turn-1".into()),
                    delegation_execution: Some("execution-1".into()),
                    delegation_epoch: Some(42),
                    delegation_egress: None,
                },
            }
        );
        let row = ListRow::from_record(&id(), &list_record()).unwrap();
        let count = row.parameters().len();
        assert!(ListRow::INSERT.contains(&format!("${count}")));
        assert!(!ListRow::INSERT.contains(&format!("${}", count + 1)));
    }

    /// A list record is refused as a call's is: an identifier that is not a lowercase UUID, a
    /// NUL in any text value, and a count past its column.
    #[test]
    fn a_list_record_the_row_cannot_hold_exactly_is_refused() {
        assert!(matches!(
            ListRow::from_record(&AuditRowId::new("not-a-row"), &list_record()),
            Err(PgAuditError::Column("id"))
        ));
        let list = serde_json::to_value(list_record()).unwrap();
        let refused = |value: serde_json::Value| match ListRow::from_record(
            &id(),
            &serde_json::from_value(value).unwrap(),
        ) {
            Err(PgAuditError::Nul { column }) => column,
            other => panic!("{other:?}"),
        };
        for field in [
            "instance",
            "deployment",
            "surface",
            "profile",
            "policy_revision",
            "proved_delegation_team",
            "claimed_acting_person",
            "claimed_team",
        ] {
            let mut value = list.clone();
            value[field] = json!(format!("{field}\u{0}x"));
            assert_eq!(refused(value), field);
        }
        let mut value = list.clone();
        value["tools"][1] = json!("fixture__\u{0}");
        assert_eq!(refused(value), "listed_tools");
        let mut value = list.clone();
        value["proved_principal"]["groups"] = json!(["group-\u{0}"]);
        assert_eq!(refused(value), "proved_groups");

        let mut record = list_record();
        record.tools_omitted = usize::MAX;
        assert!(matches!(
            ListRow::from_record(&id(), &record),
            Err(PgAuditError::Column(_))
        ));
    }

    /// Decision 0014, section 7: the largest row a call can begin, every capped value at its
    /// cap, fits in 512 KiB with room for the values that have no cap and for the completion,
    /// as [`MAX_ROW_BYTES`] works out; a row at begin's bound is begun, and a row a byte over
    /// it is refused, naming its largest column.
    #[test]
    fn the_largest_row_fits_and_a_row_over_the_bound_is_refused_naming_its_largest_column() {
        assert_eq!(MAX_ROW_BYTES, 524_288);
        assert_eq!(COMPLETION_RESERVE, 2_085);
        assert_eq!(MAX_BEGUN_ROW_BYTES, 522_203);
        assert_eq!(MAX_BEGUN_ROW_BYTES + COMPLETION_RESERVE, MAX_ROW_BYTES);
        let at_bound = largest_record(MAX_BEGUN_ROW_BYTES);
        let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &at_bound, &budgets())
            .expect("a row at begin's bound is begun");
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.values().sum::<usize>(), MAX_BEGUN_ROW_BYTES);
        // Each capped value at the cap the arithmetic counts.
        assert_eq!(sizes["resources"], 298_049);
        assert_eq!(sizes["proved_subject"] + sizes["proved_groups"], 16_384);
        assert_eq!(sizes["sentence"], 1_046);
        assert_eq!(sizes["tool_use_id"], 128);
        for column in ["surface", "tool", "instance"] {
            assert_eq!(sizes[column], 131, "{column}");
        }
        for (column, most) in [
            ("id", 36),
            ("reason", 28),
            ("credential_mode", 21),
            ("classification", 11),
            ("proved_kind", 8),
            ("decision", 5),
            ("kind", 4),
            ("resources_omitted", 8),
            ("allowance_ms", 8),
        ] {
            assert!(sizes[column] <= most, "{column}: {}", sizes[column]);
        }
        assert_eq!(sizes["resources"], MAX_REACHED_BYTES);
        let capped = 298_049 + 16_384 + 1_046 + 128 + 3 * 131 + 36 + 28 + 21 + 11 + 8 + 5 + 4 + 16;
        assert_eq!(capped, 316_129);
        assert_eq!(MAX_BEGUN_ROW_BYTES - capped, 206_074);
        // The resources' JSON is what the store sends: the decision's 298,059 bytes counted 10
        // too many.
        assert_eq!(row.resources.to_string().len(), 298_049);

        // A byte over begin's bound is refused, though the row is under MAX_ROW_BYTES: it would
        // be over it once finished.
        let mut over = at_bound.clone();
        over.policy_revision = format!("{}r", over.policy_revision).as_str().into();
        match BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &over, &budgets()) {
            Err(PgAuditError::RowTooLarge {
                column,
                bytes,
                bound,
            }) => {
                assert_eq!(
                    (column, bytes, bound),
                    ("resources", MAX_BEGUN_ROW_BYTES + 1, MAX_BEGUN_ROW_BYTES)
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            PgAuditError::RowTooLarge {
                column: "resources",
                bytes: MAX_BEGUN_ROW_BYTES + 1,
                bound: MAX_BEGUN_ROW_BYTES,
            }
            .to_string(),
            "the audit row would hold 522204 bytes, more than the 522203 it may hold, so it is \
             not written; its largest column is resources"
        );
    }

    /// The largest row an allowed call can begin, finished with the longest completion finish
    /// writes, is within [`MAX_ROW_BYTES`]: every completion finish writes is at most
    /// [`COMPLETION_RESERVE`], whatever its outcome, and a longer sentence is refused.
    #[test]
    fn the_largest_begun_row_and_the_longest_completion_are_within_the_bound() {
        let begun = largest_allowed_record(MAX_BEGUN_ROW_BYTES);
        let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &begun, &budgets()).unwrap();
        let held: usize = row.sizes().iter().map(|(_, bytes)| bytes).sum();
        assert_eq!(held, MAX_BEGUN_ROW_BYTES);
        let mut completions = vec![
            Outcome::Ok,
            Outcome::Refused {
                sentence: "s".repeat(MAX_OUTCOME_SENTENCE_BYTES),
            },
        ];
        completions.extend(
            [
                ErrorKind::InvalidArguments,
                ErrorKind::OversizedOrLateRead,
                ErrorKind::CustodianRefusal,
                ErrorKind::VendorRefusal,
                ErrorKind::Other,
            ]
            .map(|error_kind| Outcome::Error { error_kind }),
        );
        let mut longest = 0;
        for outcome in completions {
            let finish = FinishRow::from_completion(&Completion {
                outcome,
                latency_ms: u64::from(u32::MAX),
            })
            .unwrap();
            assert!(finish.outcome.len() <= LONGEST_OUTCOME, "{finish:?}");
            assert!(
                finish.error_kind.unwrap_or_default().len() <= LONGEST_ERROR_KIND,
                "{finish:?}"
            );
            let completion: usize = finish.sizes().iter().map(|(_, bytes)| bytes).sum();
            assert!(completion <= COMPLETION_RESERVE, "{finish:?}");
            longest = longest.max(completion);
        }
        // The longest completion is a refusal with its sentence at the cap.
        assert_eq!(longest, "refused".len() + MAX_OUTCOME_SENTENCE_BYTES + 8);
        assert!(held + longest <= MAX_ROW_BYTES);
    }

    /// Decision 0011 and decision 0014, section 7: a row a tool that checks its own scope begins
    /// with `unknown` resources is counted with room for the longest reach finish may write in
    /// their place, so the largest such row begun, finished with the longest reach and the
    /// longest completion, is within [`MAX_ROW_BYTES`]. A row a byte over begin's bound is
    /// refused, naming `resources`. A denial's `unknown`, which is never completed, is counted
    /// as written. Finish refuses a reach longer than [`MAX_REACHED_BYTES`], naming the column
    /// and the cap.
    #[test]
    fn a_self_scoped_row_leaves_room_for_the_longest_reach() {
        let begun = largest_self_scoped_record(MAX_BEGUN_ROW_BYTES);
        let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &begun, &budgets())
            .expect("a self-scoped row at begin's bound is begun");
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.values().sum::<usize>(), MAX_BEGUN_ROW_BYTES);
        assert_eq!(sizes["resources"], MAX_REACHED_BYTES);
        assert_eq!(row.resources, json!("unknown"));
        let written = MAX_BEGUN_ROW_BYTES - MAX_REACHED_BYTES + "\"unknown\"".len();

        let mut over = begun.clone();
        over.policy_revision = format!("{}r", over.policy_revision).as_str().into();
        match BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &over, &budgets()) {
            Err(PgAuditError::RowTooLarge {
                column,
                bytes,
                bound,
            }) => assert_eq!(
                (column, bytes, bound),
                ("resources", MAX_BEGUN_ROW_BYTES + 1, MAX_BEGUN_ROW_BYTES)
            ),
            other => panic!("{other:?}"),
        }

        // The longest reach, with the longest completion: a refusal with its sentence at the cap.
        let finish = FinishRow::from_completion(&Completion {
            outcome: Outcome::Refused {
                sentence: "s".repeat(MAX_OUTCOME_SENTENCE_BYTES),
            },
            latency_ms: u64::from(u32::MAX),
        })
        .unwrap()
        .with_reached(Some(&largest_reach()))
        .expect("the longest reach is written");
        let (reach, omitted) = finish.reached.as_ref().unwrap();
        assert_eq!(*omitted, 1);
        assert_eq!(json_bytes(reach), MAX_REACHED_BYTES);
        assert_eq!(reach.to_string().len(), 298_049);
        let completion: usize = finish.sizes().iter().map(|(_, bytes)| bytes).sum();
        let finished = written - "\"unknown\"".len() + json_bytes(reach) + completion;
        assert!(finished <= MAX_ROW_BYTES, "{finished}");
        assert_eq!(finished, MAX_ROW_BYTES - (COMPLETION_RESERVE - completion));

        // A denial's `unknown` is never replaced, so it is counted as written.
        let mut denied = begun.clone();
        denied.decision = DecisionKind::Deny;
        denied.reason = Some(gateway_core::ReasonKind::ResourceOutsideLimit);
        let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &denied, &budgets()).unwrap();
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes["resources"], "\"unknown\"".len());

        // A reach longer than the room begin left is refused, never cut.
        let mut longer = largest_reach();
        longer.resources.push(longer.resources[0].clone());
        let bytes = MAX_REACHED_BYTES + 1 + 4_656;
        for (reached, bytes) in [
            (longer, bytes),
            (
                ReachedResources {
                    resources: vec![gateway_core::audit::RecordedResource {
                        system: "s".to_owned(),
                        kind: "k".to_owned(),
                        identifier: "i".repeat(MAX_REACHED_BYTES),
                    }],
                    omitted: 0,
                },
                MAX_REACHED_BYTES + r#"[{"system":"s","kind":"k","identifier":""}]"#.len(),
            ),
        ] {
            match FinishRow::from_completion(&Completion {
                outcome: Outcome::Ok,
                latency_ms: 1,
            })
            .unwrap()
            .with_reached(Some(&reached))
            {
                Err(PgAuditError::TooLong {
                    column,
                    bytes: refused,
                    cap,
                }) => assert_eq!(
                    (column, refused, cap),
                    ("resources", bytes, MAX_REACHED_BYTES)
                ),
                other => panic!("{other:?}"),
            }
        }
    }

    /// A refusal's sentence of [`MAX_OUTCOME_SENTENCE_BYTES`] is written whole, and one a byte
    /// longer is refused, naming the column and the cap, never cut: the row is exactly its
    /// record or it is not written. The cap counts bytes, not characters.
    #[test]
    fn an_over_long_sentence_is_refused_at_finish() {
        let finish = |sentence: String| {
            FinishRow::from_completion(&Completion {
                outcome: Outcome::Refused { sentence },
                latency_ms: 1,
            })
        };
        let fits = "f".repeat(MAX_OUTCOME_SENTENCE_BYTES);
        assert_eq!(
            finish(fits.clone()).unwrap().outcome_sentence,
            Some(fits.clone())
        );
        let two_byte = "é".repeat(MAX_OUTCOME_SENTENCE_BYTES / 2);
        assert_eq!(
            finish(two_byte.clone()).unwrap().outcome_sentence,
            Some(two_byte.clone())
        );
        for (over, bytes) in [
            (format!("{fits}o"), MAX_OUTCOME_SENTENCE_BYTES + 1),
            (format!("{two_byte}é"), MAX_OUTCOME_SENTENCE_BYTES + 2),
        ] {
            match finish(over) {
                Err(PgAuditError::TooLong {
                    column,
                    bytes: refused,
                    cap,
                }) => assert_eq!(
                    (column, refused, cap),
                    ("outcome_sentence", bytes, MAX_OUTCOME_SENTENCE_BYTES)
                ),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            PgAuditError::TooLong {
                column: "outcome_sentence",
                bytes: 2_049,
                cap: MAX_OUTCOME_SENTENCE_BYTES,
            }
            .to_string(),
            "the audit column outcome_sentence would hold 2049 bytes, more than the 2048 it may \
             hold, so it is not written"
        );
        // A U+0000 in an over-long sentence is refused as a U+0000.
        let nul = format!("{fits}\u{0}");
        assert!(matches!(
            finish(nul),
            Err(PgAuditError::Nul {
                column: "outcome_sentence"
            })
        ));
    }

    /// A row over the bound names whichever column is largest, a value with no cap of its own
    /// included, and a list row, which is never completed, is bounded at [`MAX_ROW_BYTES`].
    #[test]
    fn a_row_over_the_bound_names_its_largest_column() {
        let mut record = allowed_workload();
        record.policy_revision = "r".repeat(MAX_ROW_BYTES).as_str().into();
        assert!(matches!(
            BeginRow::from_record(&id(), &record, &budgets()),
            Err(PgAuditError::RowTooLarge {
                column: "policy_revision",
                ..
            })
        ));
        // Named resources, not `unknown`, which an allowed call's row counts as the longest
        // reach and which would be its largest column.
        let mut record = allowed_workload();
        record.resources = RecordedResources::Named(Vec::new());
        record.deployment = "d".repeat(MAX_ROW_BYTES / 2).as_str().into();
        record.profile = "p".repeat(MAX_ROW_BYTES / 2 + 1).as_str().into();
        assert!(matches!(
            BeginRow::from_record(&id(), &record, &budgets()),
            Err(PgAuditError::RowTooLarge {
                column: "profile",
                ..
            })
        ));

        let row = ListRow::from_record(&id(), &list_record()).unwrap();
        let held: usize = row.sizes().iter().map(|(_, bytes)| bytes).sum();
        let mut list = list_record();
        list.deployment = "d"
            .repeat(MAX_ROW_BYTES - held + "fixture".len())
            .as_str()
            .into();
        let row = ListRow::from_record(&id(), &list).expect("a list row at the bound is written");
        assert_eq!(
            row.sizes().iter().map(|(_, bytes)| bytes).sum::<usize>(),
            MAX_ROW_BYTES
        );
        list.deployment = format!("{}d", list.deployment).as_str().into();
        match ListRow::from_record(&id(), &list) {
            Err(PgAuditError::RowTooLarge {
                column,
                bytes,
                bound,
            }) => {
                assert_eq!(
                    (column, bytes, bound),
                    ("deployment", MAX_ROW_BYTES + 1, MAX_ROW_BYTES)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    /// The testkit's in-memory store holds this store's row bound with copies of its constants
    /// and of its count, since the testkit cannot depend on this crate. They must agree: each
    /// constant, and each column's bytes, for call rows of each principal kind, each kind of
    /// resources and each credential mode, the largest a call can begin among them, and for list
    /// rows.
    #[test]
    fn the_testkits_row_bound_is_this_stores() {
        use gateway_testkit::row_bound;

        assert_eq!(row_bound::MAX_ROW_BYTES, MAX_ROW_BYTES);
        assert_eq!(row_bound::MAX_BEGUN_ROW_BYTES, MAX_BEGUN_ROW_BYTES);
        assert_eq!(row_bound::COMPLETION_RESERVE, COMPLETION_RESERVE);
        assert_eq!(row_bound::MAX_REACHED_BYTES, MAX_REACHED_BYTES);
        let reach = FinishRow::from_completion(&Completion {
            outcome: Outcome::Ok,
            latency_ms: 1,
        })
        .unwrap()
        .with_reached(Some(&largest_reach()))
        .unwrap()
        .reached
        .unwrap()
        .0;
        assert_eq!(
            row_bound::reached_bytes(&largest_reach()),
            json_bytes(&reach)
        );
        assert_eq!(
            row_bound::MAX_OUTCOME_SENTENCE_BYTES,
            MAX_OUTCOME_SENTENCE_BYTES
        );

        let mut reach = allowed_workload();
        reach.resources = RecordedResources::Reach("fixture-entry".into());
        reach.credential = Some(CredentialIdentity {
            mode: CredentialMode::PerUserGrant,
            principal: "per-user".into(),
        });
        // `allowed_workload` is a self-scoped call's row, its resources `unknown`.
        let mut denied_unknown = allowed_workload();
        denied_unknown.decision = DecisionKind::Deny;
        let mut escaped = denied_user_with_delegation();
        escaped.resources = serde_json::from_value(json!({"named": [
            {"system": "s\"q", "kind": "k\\b", "identifier": "é\n\u{1}"}
        ]}))
        .unwrap();
        escaped.credential = Some(CredentialIdentity {
            mode: CredentialMode::TeamServiceIdentity,
            principal: "service".into(),
        });
        for record in [
            denied_user_with_delegation(),
            allowed_workload(),
            denied_unverified(),
            reach,
            denied_unknown,
            escaped,
            largest_record(MAX_BEGUN_ROW_BYTES),
            largest_allowed_record(MAX_BEGUN_ROW_BYTES),
            largest_self_scoped_record(MAX_BEGUN_ROW_BYTES),
        ] {
            let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
            assert_eq!(
                row_bound::call_row_sizes(&id(), &record),
                row.sizes(),
                "{record:?}"
            );
        }

        let mut workload = list_record();
        workload.proved_principal = allowed_workload().proved_principal;
        workload.tools = vec!["back\\slash \"quoted\" é".to_owned()];
        let mut none = list_record();
        none.tools = Vec::new();
        none.delegation = None;
        for record in [list_record(), workload, none] {
            let row = ListRow::from_record(&id(), &record).unwrap();
            assert_eq!(
                row_bound::list_row_sizes(&id(), &record),
                row.sizes(),
                "{record:?}"
            );
        }
    }

    /// Each value counts as the store sends it: text as its UTF-8, a text array as its
    /// elements', JSON as its JSON text, and each integer as 8 bytes.
    #[test]
    fn each_value_counts_its_bytes_as_the_store_sends_it() {
        let row = BeginRow::from_record(&id(), &denied_user_with_delegation(), &budgets()).unwrap();
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.len(), row.parameters().len());
        assert_eq!(sizes["id"], 36);
        assert_eq!(sizes["tool_use_id"], "toolu_01".len());
        assert_eq!(sizes["proved_groups"], "group-g".len() + "group-h".len());
        assert_eq!(sizes["proved_team"], 0);
        assert_eq!(sizes["resources"], row.resources.to_string().len());
        assert_eq!(sizes["allowance_ms"], 8);
        assert_eq!(sizes["resources_omitted"], 8);
        assert_eq!(sizes["credential_mode"], "gateway_token".len());
        let mut record = denied_user_with_delegation();
        record.sentence = Some("caf\u{e9}".into());
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes["sentence"], 5);

        // A list row counts its parameters and the kind its statement writes itself.
        let row = ListRow::from_record(&id(), &list_record()).unwrap();
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.len(), row.parameters().len() + 1);
        assert!(ListRow::INSERT.contains(" 'list',"));
        assert_eq!(sizes["kind"], "list".len());
        assert_eq!(
            sizes["listed_tools"],
            r#"["fixture__read","fixture__write"]"#.len()
        );
    }

    #[test]
    fn a_workload_has_a_team_and_no_groups() {
        let row = BeginRow::from_record(&id(), &allowed_workload(), &budgets()).unwrap();
        assert_eq!(row.decision, "allow");
        assert_eq!(row.proved_kind, "workload");
        assert_eq!(row.proved_team.as_deref(), Some("team-a"));
        assert_eq!(row.proved_groups, None);
        assert_eq!((row.reason, row.sentence), (None, None));
    }

    #[test]
    fn resources_the_tool_could_not_name_are_the_string_unknown() {
        let row = BeginRow::from_record(&id(), &allowed_workload(), &budgets()).unwrap();
        assert_eq!(row.resources, json!("unknown"));
        assert_eq!(row.resources_omitted, 0);
    }

    /// A reach is the object `{"reach": entry}`, never the list it stands for.
    #[test]
    fn a_reach_is_the_object_naming_its_entry() {
        let mut record = allowed_workload();
        record.resources = RecordedResources::Reach("docs-team-a".into());
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(row.resources, json!({"reach": "docs-team-a"}));
        assert_eq!(row.resources_omitted, 0);
    }

    /// Each credential mode is written by the name the core gives it, with its principal; a row
    /// with no credential identity writes neither column.
    #[test]
    fn the_credential_identity_is_its_mode_and_principal_or_neither() {
        let mut record = allowed_workload();
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(
            (row.credential_mode, row.credential_principal),
            (None, None)
        );
        for mode in [
            CredentialMode::TeamServiceIdentity,
            CredentialMode::GatewayToken,
            CredentialMode::PerUserGrant,
        ] {
            record.credential = Some(CredentialIdentity {
                mode,
                principal: "docs-team-a".into(),
            });
            let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
            assert_eq!(
                row.credential_mode.map(str::to_owned),
                Some(name_of(&mode).unwrap())
            );
            assert_eq!(row.credential_principal.as_deref(), Some("docs-team-a"));
        }
    }

    #[test]
    fn a_call_that_named_no_resource_records_an_empty_list() {
        let mut record = allowed_workload();
        record.resources = RecordedResources::Named(vec![]);
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .resources,
            json!([])
        );
    }

    #[test]
    fn a_count_of_resources_left_out_past_the_column_is_refused() {
        let mut record = allowed_workload();
        record.resources_omitted = usize::try_from(i64::MAX).unwrap();
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .resources_omitted,
            i64::MAX
        );
        record.resources_omitted = usize::MAX;
        assert!(matches!(
            BeginRow::from_record(&id(), &record, &budgets()),
            Err(PgAuditError::Column(_))
        ));
    }

    #[test]
    fn a_user_in_no_group_has_an_empty_list_not_none() {
        let mut record = denied_user_with_delegation();
        record.proved_principal = serde_json::from_value(json!({
            "id": {"issuer": "https://user-issuer.fixture.test", "subject": "user-2"},
            "kind": "user",
            "groups": []
        }))
        .unwrap();
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(row.proved_groups, Some(vec![]));
    }

    #[test]
    fn every_reason_kind_has_a_name() {
        for kind in gateway_core::ReasonKind::ALL {
            let name = name_of(&kind).unwrap();
            assert!(!name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    /// Each outcome finish writes settles a receipt as the core says, `unknown` among them. A
    /// `duplicate` is refused before anything is sent: only begin writes one.
    #[test]
    fn each_outcome_settles_its_receipt_and_a_duplicate_is_refused_at_finish() {
        for (outcome, written, settles) in [
            (Outcome::Ok, "ok", "completed"),
            (
                Outcome::Error {
                    error_kind: ErrorKind::VendorRefusal,
                },
                "error",
                "not_performed",
            ),
            (
                Outcome::Refused {
                    sentence: "No.".into(),
                },
                "refused",
                "not_performed",
            ),
            (Outcome::Unknown, "unknown", "unknown"),
        ] {
            let finish = FinishRow::from_completion(&Completion {
                outcome: outcome.clone(),
                latency_ms: 4,
            })
            .unwrap();
            assert_eq!((finish.outcome, finish.settles), (written, settles));
            assert_eq!(finish.reference, None);
        }
        let refused = FinishRow::from_completion(&Completion {
            outcome: Outcome::Duplicate {
                receipt: AuditRowId::new("01a00000-0000-7000-8000-000000000000"),
            },
            latency_ms: 0,
        });
        assert!(
            matches!(refused, Err(PgAuditError::DuplicateAtFinish)),
            "{refused:?}"
        );
        let finish = FinishRow::from_completion(&Completion {
            outcome: Outcome::Ok,
            latency_ms: 4,
        })
        .unwrap();
        assert!(matches!(
            finish.with_reference(Some(&VendorReference::new("PR\u{0}7"))),
            Err(PgAuditError::Nul {
                column: "reference"
            })
        ));
    }

    /// The answer to a reused key is written as its completion says: `duplicate` naming the
    /// earlier receipt, or `refused` with the sentence the caller reads, each with a latency of
    /// zero, and well within the room begin leaves for a completion.
    #[test]
    fn a_reused_keys_answer_is_written_as_its_completion() {
        let key = gateway_core::IdempotencyKey::parse(&"k".repeat(128)).unwrap();
        let earlier = AuditRowId::new("01a00000-0000-7000-8000-000000000000");
        let duplicate = AnswerRow::from_reuse(&Reuse::Duplicate {
            key: key.clone(),
            receipt: earlier.clone(),
            reference: Some(VendorReference::new("PR-7")),
        })
        .unwrap();
        assert_eq!(
            duplicate,
            AnswerRow {
                outcome: "duplicate",
                outcome_sentence: None,
                latency_ms: 0,
                duplicate_of: Some(earlier.as_str().to_owned()),
            }
        );
        assert!(duplicate.is(Some("duplicate"), None, Some(0), Some(earlier.as_str())));
        assert!(!duplicate.is(Some("duplicate"), None, Some(0), None));
        for reuse in [
            Reuse::DifferentCall { key: key.clone() },
            Reuse::Conflicting { key: key.clone() },
            Reuse::MayHaveHappened {
                key: key.clone(),
                receipt: earlier.clone(),
            },
            Reuse::NotPerformed {
                key: key.clone(),
                receipt: earlier.clone(),
            },
        ] {
            let answer = AnswerRow::from_reuse(&reuse).unwrap();
            assert_eq!(
                (answer.outcome, answer.latency_ms, &answer.duplicate_of),
                ("refused", 0, &None)
            );
            let sentence = answer.outcome_sentence.clone().unwrap();
            assert_eq!(sentence, reuse.sentence());
            assert!(answer.is(Some("refused"), Some(&sentence), Some(0), None));
            assert!(
                "refused".len() + sentence.len() + INTEGER_BYTES <= COMPLETION_RESERVE,
                "{reuse:?}"
            );
        }
        assert!("duplicate".len() + 36 + INTEGER_BYTES <= COMPLETION_RESERVE);
    }

    #[test]
    fn a_complete_record_is_refused_at_begin() {
        let mut record = allowed_workload();
        record.completion = Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 3,
        });
        assert!(matches!(
            BeginRow::from_record(&id(), &record, &budgets()),
            Err(PgAuditError::CompleteAtBegin)
        ));
    }

    #[test]
    fn the_insert_names_one_parameter_per_column() {
        let row = BeginRow::from_record(&id(), &allowed_workload(), &budgets()).unwrap();
        let count = row.parameters().len();
        assert!(BeginRow::INSERT.contains(&format!("${count}")));
        assert!(!BeginRow::INSERT.contains(&format!("${}", count + 1)));
    }

    #[test]
    fn each_outcome_has_its_columns() {
        let finish = |outcome| {
            FinishRow::from_completion(&Completion {
                outcome,
                latency_ms: 7,
            })
            .unwrap()
        };
        assert_eq!(
            finish(Outcome::Ok),
            FinishRow {
                outcome: "ok",
                outcome_sentence: None,
                error_kind: None,
                latency_ms: 7,
                settles: "completed",
                reference: None,
                reached: None,
            }
        );
        assert_eq!(
            finish(Outcome::Error {
                error_kind: ErrorKind::VendorRefusal
            }),
            FinishRow {
                outcome: "error",
                outcome_sentence: None,
                error_kind: Some("vendor_refusal"),
                latency_ms: 7,
                settles: "not_performed",
                reference: None,
                reached: None,
            }
        );
        assert_eq!(
            finish(Outcome::Refused {
                sentence: "Not that one.".into()
            }),
            FinishRow {
                outcome: "refused",
                outcome_sentence: Some("Not that one.".into()),
                error_kind: None,
                latency_ms: 7,
                settles: "not_performed",
                reference: None,
                reached: None,
            }
        );
    }

    #[test]
    fn each_error_kind_is_named_as_the_core_names_it() {
        for kind in [
            ErrorKind::InvalidArguments,
            ErrorKind::OversizedOrLateRead,
            ErrorKind::CustodianRefusal,
            ErrorKind::VendorRefusal,
            ErrorKind::Other,
        ] {
            assert_eq!(
                FinishRow::error_kind_name(kind),
                name_of(&kind).unwrap(),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_latency_past_the_column_is_refused() {
        let latency = |latency_ms| {
            FinishRow::from_completion(&Completion {
                outcome: Outcome::Ok,
                latency_ms,
            })
        };
        assert_eq!(
            latency(i64::MAX.unsigned_abs()).unwrap().latency_ms,
            i64::MAX
        );
        for past in [i64::MAX.unsigned_abs() + 1, u64::MAX] {
            assert!(
                matches!(latency(past), Err(PgAuditError::Column(_))),
                "{past}"
            );
        }
    }

    #[test]
    fn a_completion_is_only_the_same_when_every_column_is() {
        let row = FinishRow {
            outcome: "refused",
            outcome_sentence: Some("No.".into()),
            error_kind: None,
            latency_ms: 4,
            settles: "not_performed",
            reference: None,
            reached: None,
        };
        assert!(row.is("refused", Some("No."), None, Some(4)));
        assert!(!row.is("error", Some("No."), None, Some(4)));
        assert!(!row.is("refused", Some("Other."), None, Some(4)));
        assert!(!row.is("refused", None, None, Some(4)));
        assert!(!row.is("refused", Some("No."), Some("other"), Some(4)));
        assert!(!row.is("refused", Some("No."), None, Some(5)));
        assert!(!row.is("refused", Some("No."), None, None));

        let error = FinishRow {
            outcome: "error",
            outcome_sentence: None,
            error_kind: Some("vendor_refusal"),
            latency_ms: 4,
            settles: "not_performed",
            reference: None,
            reached: None,
        };
        assert!(error.is("error", None, Some("vendor_refusal"), Some(4)));
        assert!(!error.is("error", None, Some("other"), Some(4)));
        assert!(!error.is("error", None, Some("before-0006"), Some(4)));
        assert!(!error.is("error", None, None, Some(4)));
    }
}
