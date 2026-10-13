//! The Postgres store's bound on a row (decision 0014, section 7) and its cap on a refusal's
//! sentence, so that [`InMemoryAuditStore`](crate::InMemoryAuditStore) refuses the rows and
//! completions that store refuses.
//!
//! These are copies. The testkit cannot depend on `audit-postgres`, whose tests depend on the
//! testkit, and the count works on what that store writes: the JSON it makes of the resources
//! and the name it gives each value. So the constants and the count are kept here beside
//! `audit_postgres`'s own, and a test in `audit-postgres` checks that the two agree: on each
//! constant, and column by column on the count of call and list records, the largest a call
//! can begin among them.
//!
//! A row is counted as the bytes of every value the store writes: a text value as its UTF-8, a
//! text array as its elements', a JSON value as its JSON text, and an integer as 8 bytes, a
//! list row's kind `list`, which its statement writes itself, included.

use gateway_core::audit::{
    AuditRecord, AuditRowId, DecisionKind, ListRecord, RecordedResources, RowKind, StoreError,
};
use gateway_core::{CredentialMode, Principal, PrincipalKind};
use serde_json::{Value, json};

/// The most a row may hold, in bytes: 512 KiB, the completion finish writes included.
/// `audit_postgres::MAX_ROW_BYTES`. A list row is written complete and never completed, so
/// list refuses one over this bound.
pub const MAX_ROW_BYTES: usize = 512 * 1024;

/// The most bytes finish writes in `outcome_sentence`: a longer refusal sentence is refused,
/// never cut, and the row keeps no completion. `audit_postgres::MAX_OUTCOME_SENTENCE_BYTES`.
pub const MAX_OUTCOME_SENTENCE_BYTES: usize = 2 * 1024;

/// The most bytes a completion adds to a row: the longest outcome, `refused` (7), the longest
/// error kind, `oversized_or_late_read` (22), the latency (8) and the longest sentence finish
/// writes, 2,085 in all. `audit_postgres::COMPLETION_RESERVE`.
pub const COMPLETION_RESERVE: usize =
    "refused".len() + "oversized_or_late_read".len() + INTEGER_BYTES + MAX_OUTCOME_SENTENCE_BYTES;

/// The most a call row may hold when begin writes it, in bytes: [`MAX_ROW_BYTES`] less
/// [`COMPLETION_RESERVE`], 522,203, so the row stays within the bound once finished.
/// `audit_postgres::MAX_BEGUN_ROW_BYTES`.
pub const MAX_BEGUN_ROW_BYTES: usize = MAX_ROW_BYTES - COMPLETION_RESERVE;

/// The bytes of an integer column.
const INTEGER_BYTES: usize = std::mem::size_of::<i64>();

fn optional_bytes(text: Option<&str>) -> usize {
    text.map_or(0, str::len)
}

/// The bytes of a JSON value: its JSON text, as the Postgres store sends it.
fn json_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |json| json.len())
}

/// `proved_kind`, `proved_team` and `proved_groups`, as the Postgres store writes them.
fn principal_sizes(principal: &Principal) -> [(&'static str, usize); 3] {
    match &principal.kind {
        PrincipalKind::Workload { team } => [
            ("proved_kind", "workload".len()),
            ("proved_team", team.as_str().len()),
            ("proved_groups", 0),
        ],
        PrincipalKind::User { groups } => [
            ("proved_kind", "user".len()),
            ("proved_team", 0),
            (
                "proved_groups",
                groups.iter().map(|group| group.as_str().len()).sum(),
            ),
        ],
    }
}

/// The resources as the Postgres store writes them: the named resources as a JSON array of
/// `{system, kind, identifier}`, a reach as `{"reach": entry}`, or the JSON string `"unknown"`.
fn resources(resources: &RecordedResources) -> Value {
    match resources {
        RecordedResources::Named(named) => Value::Array(
            named
                .iter()
                .map(|resource| {
                    json!({
                        "system": resource.system,
                        "kind": resource.kind,
                        "identifier": resource.identifier,
                    })
                })
                .collect(),
        ),
        RecordedResources::Reach(entry) => json!({ "reach": entry.as_str() }),
        RecordedResources::Unknown => Value::String("unknown".to_owned()),
    }
}

/// Each column of the call row begin writes for `record` as the row `id`, and its bytes, as
/// `audit_postgres`'s `BeginRow::sizes` counts them, in the same order.
pub fn call_row_sizes(id: &AuditRowId, record: &AuditRecord) -> [(&'static str, usize); 27] {
    let principal = record.proved_principal.get();
    let [proved_kind, proved_team, proved_groups] = principal_sizes(principal);
    let reason = record
        .reason
        .map_or(0, |reason| match serde_json::to_value(reason) {
            Ok(Value::String(name)) => name.len(),
            _ => 0,
        });
    let credential_mode = record
        .credential
        .as_ref()
        .map(|credential| match credential.mode {
            CredentialMode::TeamServiceIdentity => "team_service_identity",
            CredentialMode::GatewayToken => "gateway_token",
            CredentialMode::PerUserGrant => "per_user_grant",
        });
    let decision = match record.decision {
        DecisionKind::Allow => "allow",
        DecisionKind::Deny => "deny",
    };
    [
        ("id", id.as_str().len()),
        (
            "tool_use_id",
            optional_bytes(record.tool_use_id.as_ref().map(|id| id.as_str())),
        ),
        ("deployment", record.deployment.as_str().len()),
        ("surface", record.surface.as_str().len()),
        ("profile", record.profile.as_str().len()),
        ("tool", record.tool.len()),
        (
            "connector",
            optional_bytes(record.connector.as_ref().map(|c| c.as_str())),
        ),
        (
            "classification",
            optional_bytes(record.classification.map(|c| c.as_str())),
        ),
        ("resources", json_bytes(&resources(&record.resources))),
        ("resources_omitted", INTEGER_BYTES),
        ("decision", decision.len()),
        ("reason", reason),
        ("sentence", optional_bytes(record.sentence.as_deref())),
        ("policy_revision", record.policy_revision.as_str().len()),
        ("proved_issuer", principal.id.issuer.as_str().len()),
        ("proved_subject", principal.id.subject.as_str().len()),
        proved_kind,
        proved_team,
        proved_groups,
        (
            "proved_delegation_team",
            optional_bytes(
                record
                    .proved_delegation_team
                    .as_ref()
                    .map(|team| team.get().as_str()),
            ),
        ),
        (
            "claimed_acting_person",
            optional_bytes(
                record
                    .claimed_acting_person
                    .as_ref()
                    .map(|person| person.get().as_str()),
            ),
        ),
        (
            "claimed_team",
            optional_bytes(record.claimed_team.as_ref().map(|team| team.get().as_str())),
        ),
        ("instance", record.instance.as_str().len()),
        ("kind", kind(record.kind).len()),
        ("allowance_ms", INTEGER_BYTES),
        ("credential_mode", optional_bytes(credential_mode)),
        (
            "credential_principal",
            optional_bytes(
                record
                    .credential
                    .as_ref()
                    .map(|credential| credential.principal.as_str()),
            ),
        ),
    ]
}

/// Each column of the list row list writes for `record` as the row `id`, and its bytes, as
/// `audit_postgres`'s `ListRow::sizes` counts them, in the same order: the kind `list` among
/// them.
pub fn list_row_sizes(id: &AuditRowId, record: &ListRecord) -> [(&'static str, usize); 17] {
    let principal = record.proved_principal.get();
    let [proved_kind, proved_team, proved_groups] = principal_sizes(principal);
    let listed_tools = Value::Array(record.tools.iter().cloned().map(Value::String).collect());
    [
        ("id", id.as_str().len()),
        ("deployment", record.deployment.as_str().len()),
        ("surface", record.surface.as_str().len()),
        ("profile", record.profile.as_str().len()),
        ("policy_revision", record.policy_revision.as_str().len()),
        ("proved_issuer", principal.id.issuer.as_str().len()),
        ("proved_subject", principal.id.subject.as_str().len()),
        proved_kind,
        proved_team,
        proved_groups,
        (
            "proved_delegation_team",
            optional_bytes(
                record
                    .proved_delegation_team
                    .as_ref()
                    .map(|team| team.get().as_str()),
            ),
        ),
        (
            "claimed_acting_person",
            optional_bytes(
                record
                    .claimed_acting_person
                    .as_ref()
                    .map(|person| person.get().as_str()),
            ),
        ),
        (
            "claimed_team",
            optional_bytes(record.claimed_team.as_ref().map(|team| team.get().as_str())),
        ),
        ("instance", record.instance.as_str().len()),
        ("kind", kind(RowKind::List).len()),
        ("listed_tools", json_bytes(&listed_tools)),
        ("listed_omitted", INTEGER_BYTES),
    ]
}

fn kind(kind: RowKind) -> &'static str {
    match kind {
        RowKind::Call => "call",
        RowKind::List => "list",
    }
}

/// Refuses a row whose columns, as [`call_row_sizes`] or [`list_row_sizes`] counts them, hold
/// more than `bound`, naming the largest, in the Postgres store's words.
pub(crate) fn refuse_over(
    columns: &[(&'static str, usize)],
    bound: usize,
) -> Result<(), StoreError> {
    let bytes = columns
        .iter()
        .fold(0_usize, |total, (_, bytes)| total.saturating_add(*bytes));
    if bytes > bound {
        let column = columns
            .iter()
            .max_by_key(|(_, bytes)| *bytes)
            .map_or("", |(column, _)| column);
        return Err(format!(
            "the audit row would hold {bytes} bytes, more than the {bound} it may hold, so it \
             is not written; its largest column is {column}"
        )
        .into());
    }
    Ok(())
}

/// Refuses a refusal's sentence longer than [`MAX_OUTCOME_SENTENCE_BYTES`], in the Postgres
/// store's words.
pub(crate) fn refuse_long_sentence(sentence: &str) -> Result<(), StoreError> {
    if sentence.len() > MAX_OUTCOME_SENTENCE_BYTES {
        return Err(format!(
            "the audit column outcome_sentence would hold {} bytes, more than the \
             {MAX_OUTCOME_SENTENCE_BYTES} it may hold, so it is not written",
            sentence.len()
        )
        .into());
    }
    Ok(())
}
