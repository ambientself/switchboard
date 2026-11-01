//! `github__amend_change` (#12): adds one commit to a draft pull request that
//! `github__propose_change` opened for the same caller, and rewrites its claims block, as
//! Otto's `github_amend_change` does (docs/otto-baseline.md, "Amendments"). It is `propose`
//! only because it changes nothing the gateway did not make for the caller, from the gateway's
//! receipts (design section 8; decision 0011, section 6), and nothing a person has marked
//! ready for review, which Atlantis would plan.
//!
//! Its arguments are `owner`, `repo`, `pr_number` (1 or more), `files` and `unverifiedClaims`,
//! and an optional `expected_head`, 40 lowercase hex digits. The rest, and every refusal before
//! a request, is [`crate::proposals`]'s. Without the App's own login (`[github] bot_login`)
//! there is nothing to check who opened a pull request against, so every call is an `error`,
//! with no request at all.
//!
//! Then, with the token for reads, each read before any write:
//!
//! 1. the pull request, `GET /repos/{owner}/{repo}/pulls/{n}`. Closed is an `error`, not a
//!    refusal. Each of these is `refused`: opened by anyone but the bot login; its head in
//!    another repository; its head branch not under `otto/`; no `completed` receipt of
//!    `github__propose_change` for the caller's issuer and subject, in this repository, for
//!    `pull/<n>`; not a draft; and a body without the line marking that receipt, which a person
//!    removed;
//! 2. the head branch's commit and its tree. An `expected_head` other than that commit is an
//!    `error`;
//! 3. each file's contents at that commit (`GitHubConnector::changes`): a path that is not a
//!    regular file there is `refused`; files all the same as there are an `error` saying
//!    `expected_head` is required, or, with it, `ok` with `state: "no_change"`, nothing written.
//!
//! Then it writes: with the token for git writes, a blob for each file, a tree on the head's
//! tree, a commit `Amend pull request #<n>` whose one parent is the head, and the branch moved
//! to it, `PATCH /git/refs/heads/<branch>` with `force: false`, which GitHub refuses unless it
//! is a fast-forward; and, with the token for reads, `PATCH /pulls/{n}` with the body alone:
//! the new claims block, the marker block it found with this call's marker added, and the
//! description after it. It never deletes or forces a ref, and writes no branch outside
//! `otto/`. The first blob is its first write, so a failure from there on is `unknown`
//! ([`crate::writes`]).
//!
//! The result is `{state: "amended", branch, prNumber, headSha, url, provenance}`, and the
//! receipt records `pull/<number>`.

use gateway_core::{ErrorKind, ToolCall, ToolOutcome};
use gateway_registry::Assurance;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::WriteMethod;
use crate::connector::GitHubConnector;
use crate::create_pr;
use crate::proposals::{
    self, AMEND_CHANGE, BRANCH_PREFIX, File, GIT_PERMISSIONS, PROPOSE_CHANGE, PULL_PERMISSIONS,
    Read, object_name,
};
use crate::tools::{self, Definition, bounded};
use crate::writes::{self, Writes};

/// The arguments the schema lists.
const ARGUMENTS: &[&str] = &[
    "owner",
    "repo",
    "pr_number",
    "files",
    "unverifiedClaims",
    "expected_head",
];

/// The definition of `github__amend_change`.
pub(crate) fn definition() -> Definition {
    let mut properties = tools::owner_and_repo();
    properties.insert(
        "pr_number".into(),
        json!({
            "type": "integer",
            "minimum": 1,
            "description": "The draft pull request github__propose_change opened for this caller."
        }),
    );
    properties.insert("files".into(), proposals::files_schema());
    properties.insert("unverifiedClaims".into(), proposals::claims_schema());
    properties.insert(
        "expected_head".into(),
        json!({
            "type": "string",
            "minLength": 40,
            "maxLength": 40,
            "description": "The commit the branch's head must be, as 40 lowercase hex digits. Required to confirm a repeat that would change nothing."
        }),
    );
    Definition {
        name: AMEND_CHANGE,
        description: "Adds one commit with the given files to a draft pull request that \
                      github__propose_change opened for this caller, moving its branch forward \
                      without force, and rewrites the unverified claims above its description. \
                      It is refused for a pull request marked ready for review, one whose branch \
                      is not under otto/, one this gateway did not open for the caller, and for \
                      CI workflow files, Atlantis configuration, AGENTS.md and .agents/. A closed \
                      pull request is an error.",
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": ["owner", "repo", "pr_number", "files", "unverifiedClaims"],
            "additionalProperties": false
        }),
        assurance: Assurance {
            classification: gateway_core::Classification::Propose,
            resources: tools::repository_read().resources,
        },
    }
}

/// A call's arguments, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AmendChange {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) number: u64,
    pub(crate) files: Vec<File>,
    pub(crate) claims: Vec<String>,
    pub(crate) expected_head: Option<String>,
}

/// Parses `arguments`, or says why they are malformed.
pub(crate) fn parse(arguments: &Value) -> Result<AmendChange, String> {
    let arguments = tools::object(arguments)?;
    proposals::only(arguments, ARGUMENTS, AMEND_CHANGE)?;
    let (owner, repo) = tools::owner_repo(arguments)?;
    let number = match arguments.get("pr_number") {
        None => return Err("pr_number is required".into()),
        Some(number) => number
            .as_u64()
            .filter(|number| *number >= 1)
            .ok_or_else(|| "pr_number must be a positive number".to_owned())?,
    };
    let files = proposals::files(arguments)?;
    let claims = proposals::claims(arguments)?;
    let expected_head = tools::text(arguments, "expected_head")?;
    if let Some(head) = &expected_head
        && !object_name(head)
    {
        return Err(format!(
            "expected_head {:?} must be a commit's 40 lowercase hex digits",
            bounded(head, 64).0
        ));
    }
    Ok(AmendChange {
        owner,
        repo,
        number,
        files,
        claims,
        expected_head,
    })
}

/// A branch moved forward, never forced.
#[derive(Serialize)]
struct MovedRef<'a> {
    sha: &'a str,
    force: bool,
}

/// A pull request's new body, and nothing else of it.
#[derive(Serialize)]
struct NewBody<'a> {
    body: &'a str,
}

impl GitHubConnector {
    /// `github__amend_change`'s call. See the [module documentation](self).
    pub(crate) async fn amend_change(&self, call: &ToolCall) -> ToolOutcome {
        let receipt = match writes::receipt(call) {
            Ok(receipt) => receipt,
            Err(outcome) => return outcome,
        };
        let parsed = match parse(call.arguments()) {
            Ok(parsed) => parsed,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        let texts: Vec<(String, &str)> = parsed
            .claims
            .iter()
            .enumerate()
            .map(|(at, claim)| (format!("unverifiedClaims[{at}]"), claim.as_str()))
            .collect();
        if let Some(refusal) = self.refused_before_any_request(&parsed.owner, &parsed.files, &texts)
        {
            return ToolOutcome::Refused(refusal);
        }
        let Some(bot_login) = self.bot_login() else {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "{AMEND_CHANGE} has no bot login configured to check who opened the pull \
                     request against ([github] bot_login), so nothing was sent"
                ),
            );
        };
        let ready = match self.ready(call) {
            Ok(ready) => ready,
            Err(outcome) => return outcome,
        };
        let repository = format!("{}/{}", parsed.owner, parsed.repo);
        let reads = match self
            .token_for(call, &ready.team, &repository, PULL_PERMISSIONS)
            .await
        {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        let base = format!("/repos/{repository}");
        let number = parsed.number;

        // Every answer that writes nothing, decided from reads before the first write.
        let pull = match self
            .read_json(
                &format!("{base}/pulls/{number}"),
                &reads,
                &format!("pull request #{number}"),
                true,
            )
            .await
        {
            Ok(Read::Found(pull)) => pull,
            Ok(Read::Missing) => {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    format!(
                        "GitHub found no pull request #{number} in {repository}, so nothing was \
                         written"
                    ),
                );
            }
            Err(outcome) => return outcome,
        };
        let text = |pointer: &str| pull.pointer(pointer).and_then(Value::as_str);
        if text("/state") != Some("open") {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "pull request #{number} is closed, not open, so it cannot be amended; \
                     nothing was written"
                ),
            );
        }
        if text("/user/login") != Some(bot_login) {
            return ToolOutcome::Refused(format!(
                "pull request #{number} was not opened by this gateway's GitHub App, so it may \
                 not be amended"
            ));
        }
        let same_repository = text("/head/repo/full_name")
            .is_some_and(|head| Some(head) == text("/base/repo/full_name"));
        if !same_repository {
            return ToolOutcome::Refused(format!(
                "pull request #{number}'s branch is not in {repository}, so it may not be amended"
            ));
        }
        let Some(branch) = text("/head/ref")
            .filter(|branch| create_pr::branch(branch, "head").is_ok())
            .map(str::to_owned)
        else {
            return ToolOutcome::Refused(format!(
                "pull request #{number}'s branch could not be read, so it may not be amended"
            ));
        };
        if !branch.starts_with(BRANCH_PREFIX) {
            return ToolOutcome::Refused(format!(
                "pull request #{number} is from the branch \"{}\", which is not under the \
                 reserved \"{BRANCH_PREFIX}\" prefix",
                gateway_core::escape(&branch, gateway_core::MAX_RENDERED)
            ));
        }
        let proposed = match self
            .proposed_for(&ready.receipts, call, &repository, number)
            .await
        {
            Ok(Some(proposed)) => proposed,
            Ok(None) => {
                return ToolOutcome::Refused(format!(
                    "pull request #{number} is not one {PROPOSE_CHANGE} opened for this caller, \
                     so it may not be amended"
                ));
            }
            Err(outcome) => return outcome,
        };
        if pull.get("draft").and_then(Value::as_bool) != Some(true) {
            return ToolOutcome::Refused(format!(
                "pull request #{number} has been marked ready for review, and a commit to it \
                 would be planned by Atlantis; a person must mark it a draft again first"
            ));
        }
        let own = writes::marker(&proposed.row);
        let Some((mut markers, description)) =
            proposals::marker_block(text("/body").unwrap_or(""), &own)
        else {
            return ToolOutcome::Refused(format!(
                "pull request #{number}'s description no longer holds the line marking the \
                 receipt of the call that opened it, so the gateway cannot keep it; a person \
                 removed it"
            ));
        };
        markers.push(writes::marker(receipt));
        let body = match proposals::body(&parsed.claims, &markers, &description) {
            Ok(body) => body,
            Err(why) => {
                return ToolOutcome::error(ErrorKind::Other, format!("{why}; nothing was written"));
            }
        };
        let (head, head_tree) = match self.branch_head(&base, &branch, &reads).await {
            Ok(head) => head,
            Err(outcome) => return outcome,
        };
        if let Some(expected) = &parsed.expected_head
            && *expected != head
        {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "{branch}'s head is {head}, not the expected_head {expected}; read the pull \
                     request again. Nothing was written"
                ),
            );
        }
        match self.changes(&base, &head, &parsed.files, &reads).await {
            Ok(true) => {}
            Ok(false) => {
                return match &parsed.expected_head {
                    None => ToolOutcome::error(
                        ErrorKind::Other,
                        format!(
                            "the files are the same as at {branch}'s head {head}, so the \
                             amendment would change nothing; expected_head is required to \
                             confirm a repeat. Nothing was written"
                        ),
                    ),
                    Some(_) => {
                        let mut result = Map::new();
                        result.insert("state".into(), "no_change".into());
                        result.insert("branch".into(), branch.into());
                        result.insert("prNumber".into(), number.into());
                        result.insert("headSha".into(), head.into());
                        result.insert(
                            "provenance".into(),
                            tools::provenance_as(AMEND_CHANGE, call.tool().classification),
                        );
                        ToolOutcome::Ok(Value::Object(result))
                    }
                };
            }
            Err(outcome) => return outcome,
        }

        // The writes.
        let git = match self
            .token_for(call, &ready.team, &repository, GIT_PERMISSIONS)
            .await
        {
            Ok(token) => token,
            Err(outcome) => return outcome,
        };
        let mut writes = Writes::new();
        let message = format!("Amend pull request #{number}");
        let commit = match self
            .commit(
                &mut writes,
                &base,
                &git,
                &parsed.files,
                &head_tree,
                &head,
                &message,
            )
            .await
        {
            Ok(commit) => commit,
            Err(outcome) => return outcome,
        };
        if let Err(outcome) = writes
            .send(
                self.api(),
                WriteMethod::Patch,
                &format!("{base}/git/refs/heads/{}", create_pr::branch_path(&branch)),
                &MovedRef {
                    sha: &commit,
                    force: false,
                },
                git.expose(),
                "the branch",
            )
            .await
        {
            return outcome;
        }
        let edited = match writes
            .send(
                self.api(),
                WriteMethod::Patch,
                &format!("{base}/pulls/{number}"),
                &NewBody { body: &body },
                reads.expose(),
                "the pull request's description",
            )
            .await
        {
            Ok(edited) => edited,
            Err(outcome) => return outcome,
        };
        let mut result = Map::new();
        result.insert("state".into(), "amended".into());
        result.insert("branch".into(), branch.into());
        result.insert("prNumber".into(), number.into());
        result.insert("headSha".into(), commit.into());
        result.insert(
            "url".into(),
            edited.get("html_url").cloned().unwrap_or(Value::Null),
        );
        result.insert(
            "provenance".into(),
            tools::provenance_as(AMEND_CHANGE, call.tool().classification),
        );
        writes::completed(Value::Object(result), Some(number))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn arguments(changes: Value) -> Value {
        let mut arguments = json!({
            "owner": "example-org",
            "repo": "atlas",
            "pr_number": 42,
            "files": [{"path": "a.txt", "content": "y"}],
            "unverifiedClaims": [],
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
        let parsed = parse(&arguments(json!({}))).unwrap();
        assert_eq!((parsed.number, parsed.expected_head), (42, None));
        let head = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            parse(&arguments(json!({ "expected_head": head })))
                .unwrap()
                .expected_head
                .as_deref(),
            Some(head)
        );
    }

    #[test]
    fn each_malformed_argument_is_told_apart() {
        for (changes, why) in [
            (
                json!({"pr_number": 0}),
                "pr_number must be a positive number",
            ),
            (
                json!({"pr_number": -1}),
                "pr_number must be a positive number",
            ),
            (
                json!({"pr_number": "42"}),
                "pr_number must be a positive number",
            ),
            (json!({"pr_number": null}), "pr_number is required"),
            (json!({"expected_head": "abc"}), "40 lowercase hex"),
            (
                json!({"expected_head": "0123456789ABCDEF0123456789abcdef01234567"}),
                "40 lowercase hex",
            ),
            (
                json!({"expected_head": 7}),
                "expected_head must be a string",
            ),
            (
                json!({"unverifiedClaims": null}),
                "unverifiedClaims is required",
            ),
            (json!({"files": []}), "at least one file"),
            (
                json!({"title": "x"}),
                "\"title\" is not an argument of github__amend_change",
            ),
        ] {
            let error = parse(&arguments(changes.clone())).unwrap_err();
            assert!(error.contains(why), "{changes}: {error}");
        }
    }

    #[test]
    fn the_definition_is_a_proposal_declared_from_its_owner_and_repo() {
        let definition = definition();
        assert_eq!(
            definition.assurance.classification,
            gateway_core::Classification::Propose
        );
        assert_eq!(
            definition.assurance.resources,
            tools::repository_read().resources
        );
        assert_eq!(definition.input_schema["additionalProperties"], false);
    }
}
