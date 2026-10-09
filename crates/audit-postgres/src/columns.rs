//! What each column of `switchboard_audit.call_rows` holds, taken from the core's record.
//!
//! No I/O here, so the mapping is tested without a database.
//!
//! A row is exactly its record, or it is not written. Postgres text, text arrays and jsonb
//! cannot hold U+0000, and callers choose some values, such as their tool-use identifier. A
//! record with U+0000 in any text value is refused with [`PgAuditError::Nul`], naming the
//! column, rather than written with another character in its place: begin fails, so the core
//! refuses the call. A latency or a count past its column's range is refused the same way.

use std::time::Duration;

use gateway_core::audit::{
    AuditRecord, AuditRowId, Completion, DecisionKind, ListRecord, Outcome, RecordedResources,
    RowKind,
};
use gateway_core::{Principal, PrincipalKind};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

use crate::store::{Budgets, PgAuditError};

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
            allowance_ms
        ) VALUES (
            ($1::text)::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
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
        Ok(Self {
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
        })
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 25] {
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
        ]
    }
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
    /// the lowercase hyphenated form, a text value holding U+0000, and a count past the
    /// column's range, as begin does.
    pub fn from_record(id: &AuditRowId, record: &ListRecord) -> Result<Self, PgAuditError> {
        if !is_uuid(id.as_str()) {
            return Err(PgAuditError::Column("id"));
        }
        let principal = record.proved_principal.get();
        let (proved_kind, proved_team, proved_groups) = principal_kind(principal)?;
        Ok(Self {
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
        })
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
/// budget, the call's deadline and the finish deadline, so a row reads as open only once
/// every step could have ended (decision 0009). Saturating, so a long deadline cannot wrap
/// round to a short one; a sum past the column's range is then refused, not cut.
pub(crate) fn allowance_ms(budgets: &Budgets, call_deadline_ms: u64) -> u64 {
    millis(budgets.begin)
        .saturating_add(call_deadline_ms)
        .saturating_add(millis(budgets.finish_deadline))
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
/// in the record's order, or the JSON string `"unknown"`; and how many were left out. A count
/// past the column's range is refused rather than recorded as less than it was.
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
    pub latency_ms: i64,
}

impl FinishRow {
    /// Completes a row that has no completion yet. Matches nothing when the row is missing or
    /// already complete; [`SELECT`](Self::SELECT) then says which.
    pub const UPDATE: &'static str = "UPDATE switchboard_audit.call_rows
        SET outcome = $2, outcome_sentence = $3, latency_ms = $4
        WHERE id = ($1::text)::uuid AND outcome IS NULL";

    /// The completion a row already has, read back with only the columns the gateway's role
    /// may select.
    pub const SELECT: &'static str = "SELECT outcome, outcome_sentence, latency_ms
        FROM switchboard_audit.call_rows WHERE id = ($1::text)::uuid";

    /// The columns for `completion`. Refuses a sentence holding U+0000, and a latency past the
    /// column's range, rather than write another value than the completion's.
    pub fn from_completion(completion: &Completion) -> Result<Self, PgAuditError> {
        let outcome_sentence = match &completion.outcome {
            Outcome::Refused { sentence } => Some(stored("outcome_sentence", sentence)?),
            Outcome::Ok | Outcome::Error => None,
        };
        let latency_ms = i64::try_from(completion.latency_ms)
            .map_err(|_| PgAuditError::Column("a latency past the column's range"))?;
        Ok(Self {
            outcome: Self::outcome_of(completion),
            outcome_sentence,
            latency_ms,
        })
    }

    /// The name the row gives `completion`'s outcome.
    pub fn outcome_of(completion: &Completion) -> &'static str {
        match completion.outcome {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Refused { .. } => "refused",
        }
    }

    /// Whether a completion read back from the row is this one.
    pub fn is(
        &self,
        outcome: &str,
        outcome_sentence: Option<&str>,
        latency_ms: Option<i64>,
    ) -> bool {
        self.outcome == outcome
            && self.outcome_sentence.as_deref() == outcome_sentence
            && Some(self.latency_ms) == latency_ms
    }
}

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
            answer: Duration::from_secs(2),
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
                allowance_ms: 1_500 + 5_000 + 20_000,
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

    /// The allowance is the begin budget, the call deadline and the finish deadline, and the
    /// answer budget plays no part. A sum too large for the column is refused, not cut.
    #[test]
    fn the_allowance_is_the_begin_budget_the_call_deadline_and_the_finish_deadline() {
        let mut record = allowed_workload();
        record.call_deadline_ms = 7_250;
        let row = BeginRow::from_record(&id(), &record, &budgets()).unwrap();
        assert_eq!(row.allowance_ms, 1_500 + 7_250 + 20_000);
        let defaults = BeginRow::from_record(&id(), &record, &Budgets::default()).unwrap();
        assert_eq!(defaults.allowance_ms, 2_000 + 7_250 + 30_000);

        assert_eq!(allowance_ms(&budgets(), u64::MAX), u64::MAX);
        let huge = Budgets {
            begin: Duration::MAX,
            ..budgets()
        };
        assert_eq!(allowance_ms(&huge, 0), u64::MAX);
        for call_deadline_ms in [u64::MAX, i64::MAX.unsigned_abs()] {
            record.call_deadline_ms = call_deadline_ms;
            assert!(matches!(
                BeginRow::from_record(&id(), &record, &budgets()),
                Err(PgAuditError::Column(_))
            ));
        }
        record.call_deadline_ms = i64::MAX.unsigned_abs() - 21_500;
        assert_eq!(
            BeginRow::from_record(&id(), &record, &budgets())
                .unwrap()
                .allowance_ms,
            i64::MAX
        );
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
                latency_ms: 7
            }
        );
        assert_eq!(finish(Outcome::Error).outcome, "error");
        assert_eq!(
            finish(Outcome::Refused {
                sentence: "Not that one.".into()
            }),
            FinishRow {
                outcome: "refused",
                outcome_sentence: Some("Not that one.".into()),
                latency_ms: 7
            }
        );
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
            latency_ms: 4,
        };
        assert!(row.is("refused", Some("No."), Some(4)));
        assert!(!row.is("error", Some("No."), Some(4)));
        assert!(!row.is("refused", Some("Other."), Some(4)));
        assert!(!row.is("refused", None, Some(4)));
        assert!(!row.is("refused", Some("No."), Some(5)));
        assert!(!row.is("refused", Some("No."), None));
    }
}
