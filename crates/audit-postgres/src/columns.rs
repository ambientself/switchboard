//! What each column of `switchboard_audit.call_rows` holds, taken from the core's record.
//!
//! No I/O here, so the mapping is tested without a database.

use gateway_core::PrincipalKind;
use gateway_core::audit::{AuditRecord, Completion, DecisionKind, Outcome};
use tokio_postgres::types::ToSql;

use crate::store::PgAuditError;

/// The columns begin writes, in the order of [`BeginRow::INSERT`]'s parameters.
#[derive(Debug, PartialEq)]
pub(crate) struct BeginRow {
    pub tool_use_id: Option<String>,
    pub deployment: String,
    pub surface: String,
    pub profile: String,
    pub tool: String,
    pub connector: Option<String>,
    pub classification: Option<&'static str>,
    pub resources: Option<serde_json::Value>,
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
}

impl BeginRow {
    /// Writes the first half of a row and returns the identifier the database assigned.
    pub const INSERT: &'static str = "INSERT INTO switchboard_audit.call_rows (
            tool_use_id, deployment, surface, profile, tool, connector, classification,
            resources, resources_omitted, decision, reason, sentence, policy_revision,
            proved_issuer, proved_subject, proved_kind, proved_team, proved_groups,
            proved_delegation_team, claimed_acting_person, claimed_team
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
            $19, $20, $21
        ) RETURNING id::text";

    /// The columns for `record`. Refuses a record that is already complete: begin writes the
    /// first half of a row, and a completion handed to it would be silently dropped.
    pub fn from_record(record: &AuditRecord) -> Result<Self, PgAuditError> {
        if record.completion.is_some() {
            return Err(PgAuditError::CompleteAtBegin);
        }
        let principal = record.proved_principal.get();
        let (proved_kind, proved_team, proved_groups) = match &principal.kind {
            PrincipalKind::Workload { team } => ("workload", Some(team.to_string()), None),
            PrincipalKind::User { groups } => (
                "user",
                None,
                Some(groups.iter().map(ToString::to_string).collect()),
            ),
        };
        let (resources, resources_omitted) = resources(record);
        Ok(Self {
            tool_use_id: record.tool_use_id.as_ref().map(ToString::to_string),
            deployment: record.deployment.to_string(),
            surface: record.surface.to_string(),
            profile: record.profile.to_string(),
            tool: record.tool.clone(),
            connector: record.connector.as_ref().map(ToString::to_string),
            classification: record.classification.map(|c| c.as_str()),
            resources,
            resources_omitted,
            decision: decision(record.decision),
            reason: record.reason.map(|kind| name_of(&kind)).transpose()?,
            sentence: record.sentence.clone(),
            policy_revision: record.policy_revision.to_string(),
            proved_issuer: principal.id.issuer.to_string(),
            proved_subject: principal.id.subject.to_string(),
            proved_kind,
            proved_team,
            proved_groups,
            proved_delegation_team: record
                .proved_delegation_team
                .as_ref()
                .map(|team| team.get().to_string()),
            claimed_acting_person: record
                .claimed_acting_person
                .as_ref()
                .map(|person| person.get().to_string()),
            claimed_team: record
                .claimed_team
                .as_ref()
                .map(|team| team.get().to_string()),
        })
    }

    /// The values for [`INSERT`](Self::INSERT), in order.
    pub fn parameters(&self) -> [&(dyn ToSql + Sync); 21] {
        [
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
        ]
    }
}

/// The resources columns. The record does not carry resources yet, so a row records none: the
/// column stays empty and nothing is counted as left out. When the record gains them, the
/// named resources become a JSON array of `{system, kind, identifier}` and `unknown` the JSON
/// string `"unknown"`.
fn resources(_record: &AuditRecord) -> (Option<serde_json::Value>, i64) {
    (None, 0)
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

    pub fn from_completion(completion: &Completion) -> Self {
        let (outcome, outcome_sentence) = match &completion.outcome {
            Outcome::Ok => ("ok", None),
            Outcome::Error => ("error", None),
            Outcome::Refused { sentence } => ("refused", Some(sentence.clone())),
        };
        Self {
            outcome,
            outcome_sentence,
            // No call takes 292 million years; a latency past the column's range is recorded
            // as the most it can hold rather than refused.
            latency_ms: i64::try_from(completion.latency_ms).unwrap_or(i64::MAX),
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

    fn denied_user_with_delegation() -> AuditRecord {
        record(json!({
            "tool_use_id": "toolu_01",
            "deployment": "fixture",
            "surface": "fixture-read",
            "profile": "user-ro",
            "tool": "fixture__write",
            "connector": "fixture",
            "classification": "write",
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
            "tool_use_id": null,
            "deployment": "fixture",
            "surface": "fixture-all",
            "profile": "workload-rw",
            "tool": "fixture__read",
            "connector": "fixture",
            "classification": "read",
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
        let row = BeginRow::from_record(&denied_user_with_delegation()).unwrap();
        assert_eq!(
            row,
            BeginRow {
                tool_use_id: Some("toolu_01".into()),
                deployment: "fixture".into(),
                surface: "fixture-read".into(),
                profile: "user-ro".into(),
                tool: "fixture__write".into(),
                connector: Some("fixture".into()),
                classification: Some("write"),
                resources: None,
                resources_omitted: 0,
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
            }
        );
    }

    #[test]
    fn a_workload_has_a_team_and_no_groups() {
        let row = BeginRow::from_record(&allowed_workload()).unwrap();
        assert_eq!(row.decision, "allow");
        assert_eq!(row.proved_kind, "workload");
        assert_eq!(row.proved_team.as_deref(), Some("team-a"));
        assert_eq!(row.proved_groups, None);
        assert_eq!((row.reason, row.sentence), (None, None));
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
        let row = BeginRow::from_record(&record).unwrap();
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
            BeginRow::from_record(&record),
            Err(PgAuditError::CompleteAtBegin)
        ));
    }

    #[test]
    fn the_insert_names_one_parameter_per_column() {
        let row = BeginRow::from_record(&allowed_workload()).unwrap();
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
    fn a_latency_past_the_column_is_held_at_its_most() {
        let row = FinishRow::from_completion(&Completion {
            outcome: Outcome::Ok,
            latency_ms: u64::MAX,
        });
        assert_eq!(row.latency_ms, i64::MAX);
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
