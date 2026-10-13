//! What each column of `switchboard_audit.call_rows` holds, taken from the core's record.
//!
//! No I/O here, so the mapping is tested without a database.
//!
//! A row is exactly its record, or it is not written. Postgres text, text arrays and jsonb
//! cannot hold U+0000, and callers choose some values, such as their tool-use identifier. A
//! record with U+0000 in any text value is refused with [`PgAuditError::Nul`], naming the
//! column, rather than written with another character in its place: begin fails, so the core
//! refuses the call. A latency or a count past its column's range is refused the same way, and
//! so is a row larger than [`MAX_ROW_BYTES`], naming its largest column.

use std::time::Duration;

use gateway_core::audit::{
    AuditRecord, AuditRowId, Completion, DecisionKind, ErrorKind, ListRecord, Outcome,
    RecordedResources, RowKind,
};
use gateway_core::{CredentialIdentity, CredentialMode, Principal, PrincipalKind};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

use crate::store::{Budgets, PgAuditError};

/// The most a row may hold, in bytes (decision 0014, section 7): 512 KiB, counted as the bytes
/// of the values the store sends. A text value counts its UTF-8, a text array its elements'
/// UTF-8, a JSON value its JSON text, and an integer its 8 bytes. Begin and list count the row
/// they write and refuse one over the bound, naming its largest column, so the call or the
/// list is refused.
///
/// The values a caller chooses, and the ones it can make long, are capped before they reach a
/// row, so in the largest row a call can make they take at most 316,129 bytes, leaving 208,159
/// for the rest:
///
/// - `resources`: 298,049. At most 64 resources (`MAX_RECORDED_RESOURCES`), each a system and a
///   kind of at most 128 escaped characters and an identifier of at most 2,048, each cut with a
///   3-byte `…`. Escaped text is ASCII, and JSON doubles at most each character, a backslash or
///   a quote: so 2 + 2 × 128 + 3 = 261 bytes for a system or kind and 2 + 2 × 2,048 + 3 = 4,101
///   for an identifier, quotes included; with the keys, braces and commas, 4,656 a resource, and
///   64 × 4,656 + 63 commas + 2 brackets in all.
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
///
/// The rest have no cap of their own. `deployment`, `profile`, `connector`, `policy_revision`,
/// `proved_issuer`, `proved_team` and `credential_principal` come from the gateway's own
/// configuration, its deployment file and registry, not from a caller.
/// `proved_delegation_team`, `claimed_acting_person` and `claimed_team` are not set by the
/// gateway yet. The completion, which finish writes, is an outcome and an error kind of at most
/// 22 bytes each, a latency of 8, and a refusal sentence the gateway makes: the proxy's fixed
/// sentences, and the capacity and withdrawal sentences, which name a configured server or
/// tool. Finish cannot see the row begin wrote, so the completion is not counted against the
/// bound.
pub const MAX_ROW_BYTES: usize = 512 * 1024;

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

/// Refuses a row whose columns, as `columns` counts them, hold more than [`MAX_ROW_BYTES`],
/// naming the largest.
fn within_bound(columns: &[(&'static str, usize)]) -> Result<(), PgAuditError> {
    let bytes = columns
        .iter()
        .fold(0_usize, |total, (_, bytes)| total.saturating_add(*bytes));
    if bytes > MAX_ROW_BYTES {
        let column = columns
            .iter()
            .max_by_key(|(_, bytes)| *bytes)
            .map_or("", |(column, _)| column);
        return Err(PgAuditError::RowTooLarge { column, bytes });
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
            allowance_ms, credential_mode, credential_principal
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
        ) ON CONFLICT (id) DO NOTHING";

    /// The decision of the row already stored under an identifier, read with only the columns
    /// the gateway's role may select. A retried begin compares this and nothing more.
    pub const DECISION: &'static str =
        "SELECT decision FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `record`, as the row `id`, begun by a store with `budgets`. Refuses a
    /// record that is already complete: begin writes the first half of a row, and a
    /// completion handed to it would be silently dropped. Refuses an identifier that is not a
    /// UUID in the lowercase hyphenated form, the form the gateway makes, so that one row has
    /// one spelling.
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
        };
        within_bound(&row.sizes())?;
        Ok(row)
    }

    /// Each column and its bytes, as [`MAX_ROW_BYTES`] counts them.
    pub fn sizes(&self) -> [(&'static str, usize); 27] {
        [
            ("id", text_bytes(&self.id)),
            ("tool_use_id", optional_bytes(self.tool_use_id.as_deref())),
            ("deployment", text_bytes(&self.deployment)),
            ("surface", text_bytes(&self.surface)),
            ("profile", text_bytes(&self.profile)),
            ("tool", text_bytes(&self.tool)),
            ("connector", optional_bytes(self.connector.as_deref())),
            ("classification", optional_bytes(self.classification)),
            ("resources", json_bytes(&self.resources)),
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
        ]
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 27] {
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
        PrincipalKind::Workload { team } => (
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
}

impl ListRow {
    /// Writes a list row, complete, under the identifier the gateway chose, unless a row with
    /// that identifier is already stored. Inserts one row or none; when none,
    /// [`KIND`](Self::KIND) reads what kind the stored row is.
    pub const INSERT: &'static str = "INSERT INTO switchboard_audit.call_rows (
            id, deployment, surface, profile, policy_revision, proved_issuer, proved_subject,
            proved_kind, proved_team, proved_groups, proved_delegation_team,
            claimed_acting_person, claimed_team, instance, kind, listed_tools, listed_omitted
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'list',
            $15, $16
        ) ON CONFLICT (id) DO NOTHING";

    /// The kind of the row already stored under an identifier, read with only the columns the
    /// gateway's role may select. A retried list compares this and nothing more.
    pub const KIND: &'static str =
        "SELECT kind FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `record`, as the row `id`. Refuses an identifier that is not a UUID in
    /// the lowercase hyphenated form, a text value holding U+0000, a count past the column's
    /// range, and a row over [`MAX_ROW_BYTES`], as begin does.
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
        };
        within_bound(&row.sizes())?;
        Ok(row)
    }

    /// Each column and its bytes, as [`MAX_ROW_BYTES`] counts them.
    pub fn sizes(&self) -> [(&'static str, usize); 16] {
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
            ("listed_tools", json_bytes(&self.listed_tools)),
            ("listed_omitted", INTEGER_BYTES),
        ]
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 16] {
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
    let resources = match &record.resources {
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
    let omitted = i64::try_from(record.resources_omitted).map_err(|_| {
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
/// after the row's identifier.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FinishRow {
    pub outcome: &'static str,
    pub outcome_sentence: Option<String>,
    pub error_kind: Option<&'static str>,
    pub latency_ms: i64,
}

impl FinishRow {
    /// Completes a row that has no completion yet. Matches nothing when the row is missing or
    /// already complete; [`SELECT`](Self::SELECT) then says which.
    pub const UPDATE: &'static str = "UPDATE switchboard_audit.call_rows
        SET outcome = $2, outcome_sentence = $3, error_kind = $4, latency_ms = $5
        WHERE id = ($1::text)::uuid AND outcome IS NULL";

    /// The completion a row already has, read back with only the columns the gateway's role
    /// may select.
    pub const SELECT: &'static str = "SELECT outcome, outcome_sentence, error_kind, latency_ms
        FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `completion`. Refuses a sentence holding U+0000, and a latency past the
    /// column's range, rather than write another value than the completion's.
    pub fn from_completion(completion: &Completion) -> Result<Self, PgAuditError> {
        let (outcome_sentence, error_kind) = match &completion.outcome {
            Outcome::Refused { sentence } => (Some(stored("outcome_sentence", sentence)?), None),
            Outcome::Error { error_kind } => (None, Some(Self::error_kind_name(*error_kind))),
            Outcome::Ok => (None, None),
        };
        let latency_ms = i64::try_from(completion.latency_ms)
            .map_err(|_| PgAuditError::Column("a latency past the column's range"))?;
        Ok(Self {
            outcome: Self::outcome_of(completion),
            outcome_sentence,
            error_kind,
            latency_ms,
        })
    }

    /// The name the row gives `completion`'s outcome.
    pub fn outcome_of(completion: &Completion) -> &'static str {
        match completion.outcome {
            Outcome::Ok => "ok",
            Outcome::Error { .. } => "error",
            Outcome::Refused { .. } => "refused",
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

/// The largest call row the gateway can begin, as [`MAX_ROW_BYTES`] counts it: every capped
/// value at its cap, with the values that have no cap short, and `policy_revision`, which has
/// none, as long as it must be for the row to hold `bytes`, which must leave it room.
#[cfg(test)]
pub(crate) fn largest_record(bytes: usize) -> AuditRecord {
    // Escaped values are cut with `…`. A backslash is escaped again in JSON, so a value of
    // backslashes is the longest JSON a recorded resource can be.
    let cut = |text: &str, chars: usize| format!("{}…", text.repeat(chars));
    let resource = json!({
        "system": cut("\\", 128),
        "kind": cut("\\", 128),
        "identifier": cut("\\", 2048),
    });
    let mut record: AuditRecord = serde_json::from_value(json!({
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
        "proved_delegation_team": null,
        "claimed_acting_person": null,
        "claimed_team": null,
        "credential": {"mode": "team_service_identity", "principal": "largest"},
        "completion": null
    }))
    .expect("the largest record is a record");
    let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &record, &Budgets::default())
        .expect("the largest record without its revision fits");
    let held: usize = row.sizes().iter().map(|(_, bytes)| bytes).sum();
    record.policy_revision = "r".repeat(bytes - held).as_str().into();
    record
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
            "credential": {"mode": "gateway_token", "principal": "fixture-token"},
            "completion": null
        }))
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
                "team": "team-a"
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
            }
        );
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

    /// Decision 0014, section 7: the largest row a call can make, every capped value at its
    /// cap, fits in 512 KiB with room for the values that have no cap, as [`MAX_ROW_BYTES`]
    /// works out; a row at the bound is begun, and a row a byte over it is refused, naming its
    /// largest column.
    #[test]
    fn the_largest_row_fits_and_a_row_over_the_bound_is_refused_naming_its_largest_column() {
        assert_eq!(MAX_ROW_BYTES, 524_288);
        let at_bound = largest_record(MAX_ROW_BYTES);
        let row = BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &at_bound, &budgets())
            .expect("a row at the bound is begun");
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.values().sum::<usize>(), MAX_ROW_BYTES);
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
        let capped = 298_049 + 16_384 + 1_046 + 128 + 3 * 131 + 36 + 28 + 21 + 11 + 8 + 5 + 4 + 16;
        assert_eq!(capped, 316_129);
        assert_eq!(MAX_ROW_BYTES - capped, 208_159);
        // The resources' JSON is what the store sends: the decision's 298,059 bytes counted 10
        // too many.
        assert_eq!(row.resources.to_string().len(), 298_049);

        let mut over = at_bound.clone();
        over.policy_revision = format!("{}r", over.policy_revision).as_str().into();
        match BeginRow::from_record(&AuditRowId::new(LARGEST_ID), &over, &budgets()) {
            Err(PgAuditError::RowTooLarge { column, bytes }) => {
                assert_eq!((column, bytes), ("resources", MAX_ROW_BYTES + 1));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            PgAuditError::RowTooLarge {
                column: "resources",
                bytes: MAX_ROW_BYTES + 1
            }
            .to_string(),
            "the audit row would hold 524289 bytes, more than the 524288 a row may hold, so it \
             is not written; its largest column is resources"
        );
    }

    /// A row over the bound names whichever column is largest, a value with no cap of its own
    /// included, and a list row is bounded as a call row is.
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
        let mut record = allowed_workload();
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
            Err(PgAuditError::RowTooLarge { column, bytes }) => {
                assert_eq!((column, bytes), ("deployment", MAX_ROW_BYTES + 1));
            }
            other => panic!("{other:?}"),
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

        let row = ListRow::from_record(&id(), &list_record()).unwrap();
        let sizes: std::collections::BTreeMap<&str, usize> = row.sizes().into_iter().collect();
        assert_eq!(sizes.len(), row.parameters().len());
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
                latency_ms: 7
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
                latency_ms: 7
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
                latency_ms: 7
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
        };
        assert!(error.is("error", None, Some("vendor_refusal"), Some(4)));
        assert!(!error.is("error", None, Some("other"), Some(4)));
        assert!(!error.is("error", None, Some("before-0006"), Some(4)));
        assert!(!error.is("error", None, None, Some(4)));
    }
}
