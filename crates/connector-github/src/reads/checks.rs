//! `github__get_checks`: a pull request's checks at its head, bounded as Otto bounds them.
//!
//! The pull request is read for its head commit. Then the head's check runs, the first
//! [`MAX_CHECK_RUNS`]; for each failing one among them, its first [`MAX_ANNOTATIONS`]
//! annotations and, for a GitHub Actions run, its job's steps; and the head's combined status,
//! with its first [`MAX_STATUSES`] statuses. Each list asks for one more than it keeps, so that
//! more can be told from exactly the bound, and says when it was cut. A check run's summary and
//! an annotation's message are cut at [`MAX_CHECK_TEXT_BYTES`], and say so.

use gateway_core::ToolOutcome;
use serde_json::{Map, Value, json};

use super::{at, commit_id, string_or_null};
use crate::connector::{GitHubConnector, unreadable};
use crate::tools::{self, Call, bounded};

/// How many check runs a result holds.
pub const MAX_CHECK_RUNS: usize = 30;

/// How many annotations a failing check run holds.
pub const MAX_ANNOTATIONS: usize = 10;

/// How many commit statuses a result holds.
pub const MAX_STATUSES: usize = 30;

/// The longest check run summary or annotation message a result holds, in bytes.
pub const MAX_CHECK_TEXT_BYTES: usize = 4 * 1024;

/// The conclusions of a failing check run.
const FAILING: &[&str] = &["failure", "timed_out", "startup_failure"];

/// `text`, cut at [`MAX_CHECK_TEXT_BYTES`], as `field` and `{field}Truncated` when cut.
fn text_field(text: Option<&str>, field: &str, into: &mut Map<String, Value>) {
    let Some(text) = text else {
        into.insert(field.into(), Value::Null);
        return;
    };
    let (kept, cut) = bounded(text, MAX_CHECK_TEXT_BYTES);
    into.insert(field.into(), Value::String(kept.to_owned()));
    if cut {
        into.insert(format!("{field}Truncated"), Value::Bool(true));
    }
}

fn run_fields(run: &Value) -> Map<String, Value> {
    let mut kept = Map::new();
    for (to, from) in [
        ("id", "/id"),
        ("name", "/name"),
        ("status", "/status"),
        ("conclusion", "/conclusion"),
        ("url", "/html_url"),
        ("startedAt", "/started_at"),
        ("completedAt", "/completed_at"),
        ("title", "/output/title"),
        ("annotationsCount", "/output/annotations_count"),
    ] {
        kept.insert(to.into(), at(run, from));
    }
    kept.insert("app".into(), string_or_null(run, "/app/slug"));
    text_field(
        run.pointer("/output/summary").and_then(Value::as_str),
        "summary",
        &mut kept,
    );
    kept
}

fn annotation_fields(annotation: &Value) -> Value {
    let mut kept = Map::new();
    for (to, from) in [
        ("path", "/path"),
        ("startLine", "/start_line"),
        ("endLine", "/end_line"),
        ("level", "/annotation_level"),
        ("title", "/title"),
    ] {
        kept.insert(to.into(), at(annotation, from));
    }
    text_field(
        annotation.get("message").and_then(Value::as_str),
        "message",
        &mut kept,
    );
    Value::Object(kept)
}

fn steps(job: &Value) -> Value {
    let steps = job
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .map(|step| {
                    json!({
                        "number": at(step, "/number"),
                        "name": at(step, "/name"),
                        "status": at(step, "/status"),
                        "conclusion": at(step, "/conclusion"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(steps)
}

fn status_fields(status: &Value) -> Value {
    json!({
        "context": at(status, "/context"),
        "state": at(status, "/state"),
        "description": at(status, "/description"),
        "targetUrl": at(status, "/target_url"),
        "updatedAt": at(status, "/updated_at"),
    })
}

/// The checks of pull request `number`.
#[allow(clippy::result_large_err)]
pub(super) async fn read(
    connector: &GitHubConnector,
    call: &Call,
    number: u64,
    token: &str,
) -> Result<Value, ToolOutcome> {
    let base = tools::repo_path(call);
    let pr = connector
        .get(
            &format!("{base}/pulls/{number}"),
            token,
            "pull request",
            call,
        )
        .await?;
    let head = pr
        .pointer("/head/sha")
        .and_then(Value::as_str)
        .filter(|sha| commit_id(sha))
        .ok_or_else(unreadable)?
        .to_owned();

    let answer = connector
        .get(
            &format!(
                "{base}/commits/{head}/check-runs?per_page={}",
                MAX_CHECK_RUNS + 1
            ),
            token,
            "pull request's check runs",
            call,
        )
        .await?;
    let runs = answer
        .get("check_runs")
        .and_then(Value::as_array)
        .ok_or_else(unreadable)?;
    let mut kept = Vec::new();
    for run in runs.iter().take(MAX_CHECK_RUNS) {
        let mut fields = run_fields(run);
        let failing = run
            .get("conclusion")
            .and_then(Value::as_str)
            .is_some_and(|conclusion| FAILING.contains(&conclusion));
        if failing {
            let id = run
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(unreadable)?;
            let annotations = connector
                .get(
                    &format!(
                        "{base}/check-runs/{id}/annotations?per_page={}",
                        MAX_ANNOTATIONS + 1
                    ),
                    token,
                    "check run's annotations",
                    call,
                )
                .await?;
            let annotations = annotations.as_array().ok_or_else(unreadable)?;
            fields.insert(
                "annotations".into(),
                annotations
                    .iter()
                    .take(MAX_ANNOTATIONS)
                    .map(annotation_fields)
                    .collect(),
            );
            fields.insert(
                "annotationsTruncated".into(),
                Value::Bool(annotations.len() > MAX_ANNOTATIONS),
            );
            if run.pointer("/app/slug").and_then(Value::as_str) == Some("github-actions") {
                // A GitHub Actions check run's ID is its job's.
                let job = connector
                    .get(
                        &format!("{base}/actions/jobs/{id}"),
                        token,
                        "check run's job",
                        call,
                    )
                    .await?;
                fields.insert("steps".into(), steps(&job));
            }
        }
        kept.push(Value::Object(fields));
    }
    let total = answer
        .get("total_count")
        .and_then(Value::as_u64)
        .unwrap_or(runs.len() as u64);
    let runs_cut = runs.len() > kept.len() || total > kept.len() as u64;

    let combined = connector
        .get(
            &format!("{base}/commits/{head}/status?per_page={}", MAX_STATUSES + 1),
            token,
            "pull request's commit statuses",
            call,
        )
        .await?;
    let statuses = combined
        .get("statuses")
        .and_then(Value::as_array)
        .ok_or_else(unreadable)?;
    let kept_statuses: Vec<Value> = statuses
        .iter()
        .take(MAX_STATUSES)
        .map(status_fields)
        .collect();

    Ok(json!({
        "pr": {
            "number": number,
            "state": at(&pr, "/state"),
            "headSha": head,
            "headRef": string_or_null(&pr, "/head/ref"),
        },
        "checkRuns": kept,
        "checkRunsTotal": total,
        "checkRunsTruncated": runs_cut,
        "state": at(&combined, "/state"),
        "statuses": kept_statuses,
        "statusesTruncated": statuses.len() > kept_statuses.len(),
        "provenance": tools::provenance(super::GET_CHECKS),
    }))
}
