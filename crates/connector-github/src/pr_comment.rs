//! `github__pr_comment` (#12): posts a comment on a pull request in a repository of the
//! configured organization, as Otto's `github_pr_comment` does (docs/otto-baseline.md). It is
//! `write`: the comment is posted as soon as the call runs, with no person reading it first.
//! Decision 0006 permits no `write` tool in any profile; decision 0011, section 9, lets this one
//! past check 5 only under a profile whose own list of exceptions names it, a profile that
//! requires currency, and only once the exception's register entry is signed. Nothing here
//! decides that: the gateway's check 5 does, and no shipped registry lists the exception.
//!
//! Before anything is asked of the key custodian or of GitHub:
//!
//! - the tool must be approved `write` and its call must carry its receipt
//!   (`writes::receipt`), or nothing is sent: `error`;
//! - its arguments are parsed into its own types, and a malformed one is `invalid_arguments`:
//!   an argument the schema does not list; a missing number, or one below 1; a body that is
//!   missing or empty, or that, with the marker line, is over [`MAX_BODY_CHARS`] characters,
//!   GitHub's own bound. The schema's `required` is Otto's, `owner`, `repo` and `body`, and the
//!   number is checked here;
//! - an owner other than the configured organization is `refused`, with Otto's sentence;
//! - a body Atlantis could read as a command ([`crate::writes::command_text`]: a first word of
//!   `atlantis`, `@atlantis` or `/atlantis`, in any case, after any whitespace or format
//!   character) is `refused`, with a sentence naming Atlantis; and so is a body that holds the
//!   marker's text ([`crate::writes::holds_marker`]).
//!
//! Then one token is asked for: narrowed to the call's one repository, with the tool's own set,
//! `pull_requests: write` alone ([`PERMISSIONS`]), never its entry's whole set, and the revision
//! the call was decided under. With it, the connector reads the pull request,
//! `GET /repos/{owner}/{repo}/pulls/{number}`, so that a number that is an issue, or no pull
//! request at all, gets nothing posted: any answer but the pull request is `error`.
//!
//! The write is `POST /repos/{owner}/{repo}/issues/{number}/comments`, whose body is the
//! caller's, a blank line, and the marker line carrying the call's receipt
//! ([`crate::writes::marker`]): appended, so the comment's first word is still the caller's and
//! what Atlantis reads is unchanged. It is sent once, never again. Its outcome follows the rule
//! in [`crate::writes`]: a definite refusal is `error`, and every answer after the request may
//! have been sent that is not GitHub's 201 with the comment's id is `unknown`. The result is
//! `{comment: {id, url}, provenance}`, the provenance naming the classification the tool was
//! approved with, `write`, and tagged as external evidence; the receipt records
//! `comment/<id>`.
//!
//! A comment is only ever posted: no tool edits one, which would need decision 0011, section 6's
//! check that the gateway made it.
//!
//! # The lookup
//!
//! Reconciliation settles an `unknown` receipt of this tool by [`crate::lookup`], which reads,
//! with a token of its own for the receipt's team and repository and `pull_requests: read`, the
//! repository's comments made since a little before the receipt was reserved, oldest first:
//! `GET /repos/{owner}/{repo}/issues/comments?since=…&sort=created&direction=asc&per_page=100`,
//! at most [`MAX_LOOKUP_PAGES`] pages. The receipt is the call's audit row, a UUIDv7, whose
//! first 48 bits are when it was made; `since` is that, less [`LOOKUP_SINCE_MARGIN`]. The first
//! comment whose body has a line exactly equal to the marker is found, with `comment/<id>`.
//! Nothing found is `not_found`, never authoritative, so a lookup never settles a receipt
//! `not_performed`; a receipt that is not a UUIDv7, and any error or answer that cannot be
//! read, are `failed`.

use std::time::Duration;

use gateway_core::{
    ErrorKind, LookupAnswer, Narrowing, PrincipalKind, ToolCall, ToolOutcome, VendorReference,
};
use gateway_registry::{Access, Assurance};
use hyper::StatusCode;
use key_custodian::TokenRequest;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::{Answered, WriteMethod};
use crate::connector::GitHubConnector;
use crate::tools::{self, Definition, bounded};
use crate::writes::{self, Writes};

/// `github__pr_comment`.
pub const PR_COMMENT: &str = "github__pr_comment";

/// The permission `github__pr_comment` asks for: its own, within its entry's.
pub const PERMISSIONS: &[(&str, Access)] = &[("pull_requests", Access::Write)];

/// The longest comment GitHub takes, in characters: the caller's body and the marker line.
pub const MAX_BODY_CHARS: usize = 65_536;

/// The longest body a caller may give, in characters, leaving room for the marker line.
pub const MAX_CALLER_BODY_CHARS: usize = 65_000;

/// How many comments a lookup reads a page.
pub const COMMENTS_PER_PAGE: usize = 100;

/// The most pages a lookup reads.
pub const MAX_LOOKUP_PAGES: usize = 10;

/// How long before its receipt was reserved a lookup reads comments from, for the gateway's
/// clock and GitHub's to differ by.
pub const LOOKUP_SINCE_MARGIN: Duration = Duration::from_secs(10 * 60);

/// The arguments the schema lists.
const ARGUMENTS: &[&str] = &["owner", "repo", "number", "body"];

/// The definition of `github__pr_comment`.
pub(crate) fn definition() -> Definition {
    let mut properties = tools::owner_and_repo();
    properties.insert(
        "number".into(),
        json!({
            "type": "integer",
            "minimum": 1,
            "description": "The pull request's number."
        }),
    );
    properties.insert(
        "body".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_CALLER_BODY_CHARS,
            "description": "The comment, in GitHub Markdown. A line carrying the gateway's receipt for the call is added after it."
        }),
    );
    Definition {
        name: PR_COMMENT,
        description: "Comments on a pull request in a repository of the configured \
                      organization. It is refused when the comment begins with a word Atlantis \
                      would read as a command. The comment ends with a line carrying the \
                      gateway's receipt for the call.",
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": ["owner", "repo", "body"],
            "additionalProperties": false
        }),
        assurance: Assurance {
            classification: gateway_core::Classification::Write,
            resources: tools::repository_read().resources,
        },
    }
}

/// A call's arguments, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrComment {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) number: u64,
    pub(crate) body: String,
}

/// Parses `arguments`, or says why they are malformed.
pub(crate) fn parse(arguments: &Value) -> Result<PrComment, String> {
    let arguments = tools::object(arguments)?;
    if let Some(unlisted) = arguments
        .keys()
        .find(|name| !ARGUMENTS.contains(&name.as_str()))
    {
        return Err(format!(
            "{:?} is not an argument of {PR_COMMENT}",
            bounded(unlisted, 64).0
        ));
    }
    let (owner, repo) = tools::owner_repo(arguments)?;
    let number = match arguments.get("number") {
        None => return Err("number is required".into()),
        Some(number) => number
            .as_u64()
            .filter(|number| *number >= 1)
            .ok_or_else(|| "number must be a positive number".to_owned())?,
    };
    let body = tools::required(arguments, "body")?;
    if body.trim().is_empty() {
        return Err("body must not be empty".into());
    }
    Ok(PrComment {
        owner,
        repo,
        number,
        body,
    })
}

/// The comment GitHub is sent: the caller's body, a blank line, and `marker`. Or why it cannot
/// be sent.
fn with_marker(body: &str, marker: &str) -> Result<String, String> {
    let sent = format!("{body}\n\n{marker}");
    let length = sent.chars().count();
    if length > MAX_BODY_CHARS {
        return Err(format!(
            "body is {length} characters with the line carrying the gateway's receipt, and \
             GitHub takes at most {MAX_BODY_CHARS}"
        ));
    }
    Ok(sent)
}

/// The sentence a body Atlantis could read as a command is refused with.
fn command_sentence() -> String {
    "the body begins with a word Atlantis would read as a command addressed to it (\"atlantis\", \
     \"@atlantis\" or \"/atlantis\"); this gateway does not post a comment Atlantis would run"
        .to_owned()
}

/// The comment GitHub is asked to post: built from the connector's own types.
#[derive(Serialize)]
struct NewComment<'a> {
    body: &'a str,
}

impl GitHubConnector {
    /// `github__pr_comment`'s call. See the [module documentation](self).
    pub(crate) async fn pr_comment(&self, call: &ToolCall) -> ToolOutcome {
        // Not the approval alone: a comment not approved `write`, or with no receipt, sends
        // nothing.
        let receipt = match writes::receipt(call) {
            Ok(receipt) => receipt,
            Err(outcome) => return outcome,
        };
        let parsed = match parse(call.arguments()) {
            Ok(parsed) => parsed,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        let body = match with_marker(&parsed.body, &writes::marker(receipt)) {
            Ok(body) => body,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        // One organization, before anything is asked of anyone (docs/otto-baseline.md).
        if parsed.owner != self.organization() {
            return ToolOutcome::Refused(self.other_organization(&parsed.owner));
        }
        if writes::command_text(&parsed.body) {
            return ToolOutcome::Refused(command_sentence());
        }
        if writes::holds_marker(&parsed.body) {
            return ToolOutcome::Refused(writes::marker_sentence("body"));
        }
        let connector = &call.tool().connector;
        if self.narrowing(connector) != Some(Narrowing::Call) {
            return writes::not_narrowed(connector);
        }
        let PrincipalKind::Workload { team, .. } = &call.call().caller.principal.get().kind else {
            return ToolOutcome::error(
                ErrorKind::Other,
                "the GitHub connector serves a team's workloads only: a token is asked for the \
                 caller's team, and a person has none",
            );
        };
        let repository = format!("{}/{}", parsed.owner, parsed.repo);
        let request = TokenRequest {
            team: team.clone(),
            tool: call.tool().name.clone(),
            repositories: vec![repository.clone()],
            permissions: PERMISSIONS
                .iter()
                .map(|(permission, access)| ((*permission).to_owned(), *access))
                .collect(),
            revision: call.policy_revision().clone(),
        };
        let token = match self.token(&request).await {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        let base = format!("/repos/{repository}");
        let pull = format!("{base}/pulls/{}", parsed.number);
        match self.api().get(&pull, token.expose()).await {
            Answered::Json(_) => {}
            other => return pull_failed(other, &parsed),
        }
        let mut writes = Writes::new();
        let posted = match writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{base}/issues/{}/comments", parsed.number),
                &NewComment { body: &body },
                token.expose(),
                "the comment",
            )
            .await
        {
            Ok(posted) => posted,
            Err(outcome) => return outcome,
        };
        let id = posted.get("id").and_then(Value::as_u64);
        let mut comment = Map::new();
        comment.insert("id".into(), id.map_or(Value::Null, Value::from));
        comment.insert(
            "url".into(),
            posted
                .get("html_url")
                .and_then(Value::as_str)
                .map_or(Value::Null, |url| Value::String(url.to_owned())),
        );
        let result = json!({
            "comment": comment,
            "provenance": tools::provenance_as(PR_COMMENT, call.tool().classification),
        });
        completed(result, id)
    }

    /// The lookup by marker of a comment this tool posted, in `repository`, with `token`: see
    /// the [module documentation](self).
    pub(crate) async fn find_comment(
        &self,
        receipt: &gateway_core::audit::AuditRowId,
        repository: &str,
        token: &str,
    ) -> LookupAnswer {
        let Some(reserved) = reserved_at(receipt.as_str()) else {
            tracing::warn!(
                receipt = receipt.as_str(),
                "a comment's receipt is not a UUIDv7, so when to read comments from is not known"
            );
            return LookupAnswer::Failed;
        };
        let since = rfc3339(reserved.saturating_sub(LOOKUP_SINCE_MARGIN.as_secs()));
        let marker = writes::marker(receipt);
        for page in 1..=MAX_LOOKUP_PAGES {
            let path = format!(
                "/repos/{repository}/issues/comments?since={since}&sort=created&direction=asc&\
                 per_page={COMMENTS_PER_PAGE}&page={page}"
            );
            let Answered::Json(Value::Array(comments)) = self.api().get(&path, token).await else {
                return LookupAnswer::Failed;
            };
            if let Some(found) = comments
                .iter()
                .find(|comment| crate::lookup::marked(comment, &marker))
            {
                return match found.get("id").and_then(Value::as_u64) {
                    Some(id) => LookupAnswer::Found {
                        reference: reference(id),
                    },
                    None => LookupAnswer::Failed,
                };
            }
            if comments.len() < COMMENTS_PER_PAGE {
                break;
            }
        }
        LookupAnswer::NotFound {
            authoritative: false,
        }
    }
}

/// The receipt's reference to the comment `id`.
fn reference(id: u64) -> VendorReference {
    VendorReference::new(format!("comment/{id}"))
}

/// A comment GitHub posted: `result` for the caller, with the reference `comment/<id>`, or
/// `unknown` when the id could not be read from its answer, since something was posted.
fn completed(result: Value, id: Option<u64>) -> ToolOutcome {
    match id {
        Some(id) => ToolOutcome::Completed(result, reference(id)),
        None => ToolOutcome::Unknown,
    }
}

/// The outcome when the pull request could not be read: `error`, since nothing was posted. No
/// sentence quotes GitHub's answer.
fn pull_failed(answered: Answered, call: &PrComment) -> ToolOutcome {
    let repository = format!("{}/{}", call.owner, call.repo);
    let number = call.number;
    let (kind, why) = match answered {
        Answered::Json(_) | Answered::Unreadable => (
            ErrorKind::Other,
            format!("GitHub's answer for pull request #{number} in {repository} could not be read"),
        ),
        Answered::Unreachable => (
            ErrorKind::Other,
            "GitHub could not be reached to read the pull request".to_owned(),
        ),
        Answered::Status {
            status,
            rate_limited: true,
        } => (
            ErrorKind::Other,
            format!(
                "GitHub's rate limit for this App's installation is used up (HTTP {})",
                status.as_u16()
            ),
        ),
        Answered::Status { status, .. } if status == StatusCode::NOT_FOUND => (
            ErrorKind::Other,
            format!(
                "GitHub found no pull request #{number} in {repository}, or the token cannot see \
                 the repository (HTTP 404)"
            ),
        ),
        Answered::Status { status, .. } if status == StatusCode::FORBIDDEN => (
            ErrorKind::VendorRefusal,
            format!("GitHub refused to show pull request #{number} in {repository} to this App (HTTP 403)"),
        ),
        Answered::Status { status, .. } => (
            ErrorKind::Other,
            format!(
                "GitHub could not show pull request #{number} in {repository} (HTTP {})",
                status.as_u16()
            ),
        ),
    };
    ToolOutcome::error(kind, format!("{why}, so no comment was posted"))
}

/// When the UUIDv7 `id` was made, in seconds since the Unix epoch: its first 48 bits are the
/// milliseconds. `None` for anything but a UUIDv7.
fn reserved_at(id: &str) -> Option<u64> {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    let well_formed = id.len() == 36
        && hex.len() == 32
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        && [8, 13, 18, 23].iter().all(|at| id.as_bytes()[*at] == b'-');
    if !well_formed || hex.as_bytes()[12] != b'7' {
        return None;
    }
    let millis = u64::from_str_radix(&hex[..12], 16).ok()?;
    Some(millis / 1000)
}

/// `seconds` since the Unix epoch as GitHub's `since` takes it: `YYYY-MM-DDTHH:MM:SSZ`, in UTC.
pub fn rfc3339(seconds: u64) -> String {
    let days = seconds / 86_400;
    let in_day = seconds % 86_400;
    // Howard Hinnant's civil_from_days, for days on or after 1970-01-01.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let of_era = shifted % 146_097;
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let day_of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        in_day / 3_600,
        in_day % 3_600 / 60,
        in_day % 60
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn arguments(changes: Value) -> Value {
        let mut arguments = json!({
            "owner": "example-org",
            "repo": "atlas",
            "number": 7,
            "body": "Looks good.",
        });
        for (name, value) in changes.as_object().unwrap() {
            if value.is_null() {
                arguments.as_object_mut().unwrap().remove(name);
            } else {
                arguments[name] = value.clone();
            }
        }
        arguments
    }

    #[test]
    fn well_formed_arguments_parse() {
        assert_eq!(
            parse(&arguments(json!({}))).unwrap(),
            PrComment {
                owner: "example-org".into(),
                repo: "atlas".into(),
                number: 7,
                body: "Looks good.".into(),
            }
        );
        parse(&arguments(json!({"body": "line one\nline two"}))).unwrap();
    }

    #[test]
    fn each_malformed_argument_is_told_apart() {
        for (changes, why) in [
            (json!({"number": null}), "number is required"),
            (json!({"number": 0}), "number must be a positive number"),
            (json!({"number": -1}), "number must be a positive number"),
            (json!({"number": 1.5}), "number must be a positive number"),
            (json!({"number": "7"}), "number must be a positive number"),
            (json!({"body": null}), "body is required"),
            (json!({"body": ""}), "body must not be empty"),
            (json!({"body": " \n\t"}), "body must not be empty"),
            (json!({"body": 7}), "body must be a string"),
            (json!({"owner": "a/b"}), "login charset"),
            (json!({"repo": ".."}), "repository charset"),
            (json!({"edit": 1}), "\"edit\" is not an argument"),
        ] {
            let error = parse(&arguments(changes.clone())).unwrap_err();
            assert!(error.contains(why), "{changes}: {error}");
        }
    }

    #[test]
    fn the_marker_is_appended_after_a_blank_line_and_bounded_with_it() {
        let marker = "<!-- switchboard-receipt: r -->";
        let sent = with_marker("atlantis? no: please look", marker).unwrap();
        assert_eq!(sent, format!("atlantis? no: please look\n\n{marker}"));
        assert!(sent.starts_with("atlantis? no"));
        let room = MAX_BODY_CHARS - marker.chars().count() - 2;
        assert_eq!(
            with_marker(&"é".repeat(room), marker)
                .unwrap()
                .chars()
                .count(),
            MAX_BODY_CHARS
        );
        assert!(
            with_marker(&"é".repeat(room + 1), marker)
                .unwrap_err()
                .contains("65536")
        );
    }

    #[test]
    fn the_definition_is_a_write_declared_from_its_owner_and_repo_with_otto_s_required() {
        let definition = definition();
        assert_eq!(
            definition.assurance.classification,
            gateway_core::Classification::Write
        );
        assert_eq!(
            definition.assurance.resources,
            tools::repository_read().resources
        );
        assert_eq!(
            definition.input_schema["required"],
            json!(["owner", "repo", "body"])
        );
        assert_eq!(definition.input_schema["additionalProperties"], false);
    }

    #[test]
    fn a_comment_needs_its_id_to_be_completed() {
        assert_eq!(completed(Value::Null, None), ToolOutcome::Unknown);
        assert_eq!(
            completed(Value::Null, Some(73)),
            ToolOutcome::Completed(Value::Null, VendorReference::new("comment/73"))
        );
    }

    #[test]
    fn a_uuidv7_gives_when_it_was_made_and_nothing_else_does() {
        // 0x0190f5a27c3e ms is 2024-07-27T19:19:44.830Z.
        assert_eq!(
            reserved_at("0190f5a2-7c3e-7d4e-9a1b-2c3d4e5f6a7b"),
            Some(0x0190_f5a2_7c3e / 1000)
        );
        assert_eq!(
            rfc3339(reserved_at("0190f5a2-7c3e-7d4e-9a1b-2c3d4e5f6a7b").unwrap()),
            "2024-07-27T19:19:44Z"
        );
        for id in [
            "",
            "r1",
            "0190f5a2-7c3e-4d4e-9a1b-2c3d4e5f6a7b",
            "0190f5a27c3e7d4e9a1b2c3d4e5f6a7b",
            "0190f5a2-7c3e-7d4e-9a1b-2c3d4e5f6a7g",
            "0190f5a2-7c3e-7d4e-9a1b_2c3d4e5f6a7b",
        ] {
            assert_eq!(reserved_at(id), None, "{id}");
        }
    }

    #[test]
    fn a_time_is_written_as_github_takes_it() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_793_502_245), "2026-11-01T03:04:05Z");
        assert_eq!(rfc3339(4_107_542_399), "2100-02-28T23:59:59Z");
    }
}
