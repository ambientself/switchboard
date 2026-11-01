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
//! list row's kind `list`, which its statement writes itself, included. An allowed call's
//! `unknown` resources are counted as [`MAX_REACHED_BYTES`], since finish may write what its
//! tool reached in their place.

use gateway_core::audit::{
    AuditRecord, AuditRowId, DecisionKind, ListRecord, MAX_RECORDED_RESOURCES, ReachedResources,
    RecordedDelegation, RecordedFailure, RecordedResources, RowKind, StoreError,
};
use gateway_core::{CredentialMode, CurrencyAnswer, Egress, Principal, PrincipalKind};
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
/// [`COMPLETION_RESERVE`], 522,203, so the row stays within the bound once finished. An allowed
/// call's `unknown` resources are counted as [`MAX_REACHED_BYTES`] towards it.
/// `audit_postgres::MAX_BEGUN_ROW_BYTES`.
pub const MAX_BEGUN_ROW_BYTES: usize = MAX_ROW_BYTES - COMPLETION_RESERVE;

/// The most bytes finish writes in `resources` for a tool that checks its own scope: the most
/// named resources hold, 64 of 4,656 bytes each, 63 commas and 2 brackets, 298,049 in all.
/// Begin counts an allowed call's `unknown` resources as this, and finish refuses a longer
/// reach. `audit_postgres::MAX_REACHED_BYTES`.
pub const MAX_REACHED_BYTES: usize =
    MAX_RECORDED_RESOURCES * MAX_RECORDED_RESOURCE_BYTES + (MAX_RECORDED_RESOURCES - 1) + 2;

/// The most bytes one recorded resource holds as JSON: a system and a kind of 261 bytes, an
/// identifier of 4,101, and 33 for the keys and punctuation.
const MAX_RECORDED_RESOURCE_BYTES: usize = 2 * (2 + 2 * 128 + 3) + (2 + 2 * 2_048 + 3) + 33;

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
        PrincipalKind::Workload { team, .. } => [
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

/// `proved_pod` and a verified delegation's columns, as `audit_postgres`'s `DelegationColumns`
/// counts them, in the same order. A digest is written for a delegation that did not verify,
/// when its signature did.
fn delegation_sizes(
    principal: &Principal,
    delegation: Option<&RecordedDelegation>,
    failure: Option<&RecordedFailure>,
) -> [(&'static str, usize); 9] {
    let digest = delegation
        .map(|delegation| delegation.digest)
        .or_else(|| failure.and_then(|failure| failure.digest))
        .map_or(0, |digest| digest.to_hex().len());
    let text = |value: fn(&RecordedDelegation) -> &str| delegation.map_or(0, |d| value(d).len());
    [
        (
            "proved_pod",
            principal.pod().map_or(0, |pod| pod.as_str().len()),
        ),
        ("delegation_digest", digest),
        ("delegation_issuer", text(|d| d.issuer.as_str())),
        ("delegation_key_id", text(|d| d.key_id.as_str())),
        ("delegation_session", text(|d| d.session.as_str())),
        ("delegation_turn", text(|d| d.turn.as_str())),
        ("delegation_execution", text(|d| d.execution.as_str())),
        ("delegation_epoch", delegation.map_or(0, |_| INTEGER_BYTES)),
        (
            "delegation_egress",
            optional_bytes(delegation.and_then(|d| d.egress).map(Egress::as_str)),
        ),
    ]
}

/// The bytes `record`'s resources are counted as: their JSON text, or, for an allowed call whose
/// resources are `unknown`, [`MAX_REACHED_BYTES`], the most finish may write in their place.
fn resources_bytes(record: &AuditRecord) -> usize {
    let held = json_bytes(&resources(&record.resources));
    if record.decision == DecisionKind::Allow && record.resources == RecordedResources::Unknown {
        held.max(MAX_REACHED_BYTES)
    } else {
        held
    }
}

/// The bytes the resources a tool `reached` hold as the Postgres store writes them in place of
/// a row's `unknown` ones: their JSON text, as it writes named resources.
pub fn reached_bytes(reached: &ReachedResources) -> usize {
    json_bytes(&resources(&RecordedResources::Named(
        reached.resources.clone(),
    )))
}

/// Each column of the call row begin writes for `record` as the row `id`, and its bytes, as
/// `audit_postgres`'s `BeginRow::sizes` counts them, in the same order.
pub fn call_row_sizes(id: &AuditRowId, record: &AuditRecord) -> [(&'static str, usize); 39] {
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
    ] = delegation_sizes(
        principal,
        record.delegation.as_ref(),
        record.delegation_failure.as_ref(),
    );
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
        ("resources", resources_bytes(record)),
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
            optional_bytes(
                record
                    .delegation_failure
                    .as_ref()
                    .map(|failure| failure.failure.as_str()),
            ),
        ),
        (
            "currency",
            optional_bytes(record.currency.map(CurrencyAnswer::as_str)),
        ),
        (
            "allowed_by_exception",
            optional_bytes(
                record
                    .allowed_by_exception
                    .as_ref()
                    .map(|exception| exception.as_str()),
            ),
        ),
    ]
}

/// Each column of the list row list writes for `record` as the row `id`, and its bytes, as
/// `audit_postgres`'s `ListRow::sizes` counts them, in the same order: the kind `list` among
/// them.
pub fn list_row_sizes(id: &AuditRowId, record: &ListRecord) -> [(&'static str, usize); 26] {
    let principal = record.proved_principal.get();
    let [proved_kind, proved_team, proved_groups] = principal_sizes(principal);
    let listed_tools = Value::Array(record.tools.iter().cloned().map(Value::String).collect());
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
    ] = delegation_sizes(principal, record.delegation.as_ref(), None);
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

/// Refuses a reach longer than [`MAX_REACHED_BYTES`], in the Postgres store's words.
pub(crate) fn refuse_long_reach(reached: &ReachedResources) -> Result<(), StoreError> {
    let bytes = reached_bytes(reached);
    if bytes > MAX_REACHED_BYTES {
        return Err(format!(
            "the audit column resources would hold {bytes} bytes, more than the \
             {MAX_REACHED_BYTES} it may hold, so it is not written"
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

#[cfg(test)]
mod tests {
    use gateway_core::audit::RecordedResource;

    use super::*;

    /// A reach of exactly [`MAX_REACHED_BYTES`] as the Postgres store writes it is accepted, and
    /// one a byte longer is refused in that store's words, naming `resources` and the cap.
    #[test]
    fn a_reach_longer_than_the_room_begin_left_is_refused() {
        assert_eq!(MAX_REACHED_BYTES, 298_049);
        let reach = |identifier: usize| ReachedResources {
            resources: vec![RecordedResource {
                system: "s".to_owned(),
                kind: "k".to_owned(),
                identifier: "i".repeat(identifier),
            }],
            omitted: 0,
        };
        let around = r#"[{"system":"s","kind":"k","identifier":""}]"#.len();
        let fits = reach(MAX_REACHED_BYTES - around);
        assert_eq!(reached_bytes(&fits), MAX_REACHED_BYTES);
        refuse_long_reach(&fits).expect("a reach at the cap is written");
        let over = reach(MAX_REACHED_BYTES - around + 1);
        assert_eq!(
            refuse_long_reach(&over).unwrap_err().to_string(),
            format!(
                "the audit column resources would hold {} bytes, more than the \
                 {MAX_REACHED_BYTES} it may hold, so it is not written",
                MAX_REACHED_BYTES + 1
            )
        );
    }
}
