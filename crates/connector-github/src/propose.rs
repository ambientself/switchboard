//! `github__propose_change` (#12): proposes a change to files of a repository of the configured
//! organization as a draft pull request from a branch of its own, as Otto's
//! `github_propose_change` does (docs/otto-baseline.md, "Proposals"). It is `propose`: what it
//! makes is a draft on a branch under `otto/`, which a person reads before anything acts on it
//! (design section 8).
//!
//! Its arguments are `owner`, `repo`, `title`, `idempotency_key`, `files` and
//! `unverifiedClaims`, and an optional `body`. The title is held to `github__create_pr`'s rules;
//! the key is 1 to [`MAX_KEY_CHARS`] of `A-Z a-z 0-9 . _ -`, not beginning with `.`, holding no
//! `..` and not ending with `.` or `.lock`, so that `otto/<key>` is a branch name; the body is
//! at most [`MAX_CALLER_BODY_CHARS`] characters. The key names the branch: it is not the call's
//! idempotency key, which the gateway answers a repeat of before the connector runs. The rest,
//! and every refusal before a request, is [`crate::proposals`]'s.
//!
//! Then, with the token for reads, each read before any write:
//!
//! 1. the repository's default branch, `GET /repos/{owner}/{repo}`;
//! 2. the pull requests of every state whose head is `<org>:otto/<key>`. One the gateway's
//!    receipts say `github__propose_change` opened for the caller is the call's answer, and
//!    nothing is written: closed and not merged is `proposal_declined`, saying it will never be
//!    reopened; merged is `already_proposed` with `merged: true`; open is `already_proposed`
//!    when the call's arguments have the digest of that receipt's, and otherwise
//!    `key_conflict`, naming the recorded copy. A pull request from the branch that the gateway
//!    did not open for the caller is `refused`;
//! 3. with none, the branch `heads/otto/<key>`: one that exists is `refused`;
//! 4. the default branch's head commit and its tree;
//! 5. each file's entry in that commit's tree, by the git trees' modes, and each regular file's
//!    contents there (`GitHubConnector::changes`): a path that is not a regular file there, or
//!    that is under something that is not a directory, is `refused`, and files that are all the
//!    same as there are an `error`, "no change", with nothing written.
//!
//! Then it writes, in Otto's order: with the token for git writes, a blob for each file, a tree
//! on the head's tree, a commit whose message is the title and whose one parent is the head,
//! and the branch `refs/heads/otto/<key>` (`POST /git/refs`); and, with the token for reads, the
//! pull request into the default branch, a draft always, whose body is the claims block, the
//! call's marker, and the caller's body (`proposals::body`). It never deletes, moves or
//! forces a ref, and never opens a second pull request for a key. The first blob is its first
//! write, so a failure from there on is `unknown` ([`crate::writes`]); a 422 on the branch
//! included.
//!
//! The result is `{state: "proposed", branch, prNumber, baseSha, commitSha, url, provenance}`,
//! and the receipt records `pull/<number>`.

use gateway_core::{ArgumentDigest, ErrorKind, ToolCall, ToolOutcome};
use gateway_registry::Assurance;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::WriteMethod;
use crate::connector::GitHubConnector;
use crate::create_pr;
use crate::proposals::{
    self, BRANCH_PREFIX, File, GIT_PERMISSIONS, PROPOSE_CHANGE, PULL_PERMISSIONS, Read,
};
use crate::tools::{self, Definition, bounded};
use crate::writes::{self, Writes};

/// The longest `idempotency_key`, in characters.
pub const MAX_KEY_CHARS: usize = 100;

/// The longest body a caller may give, in characters: GitHub's own bound. The claims block and
/// the marker line are added to it, and the whole is held to the same bound before anything is
/// sent.
pub const MAX_CALLER_BODY_CHARS: usize = create_pr::MAX_BODY_CHARS;

/// The arguments the schema lists.
const ARGUMENTS: &[&str] = &[
    "owner",
    "repo",
    "title",
    "idempotency_key",
    "files",
    "unverifiedClaims",
    "body",
];

/// The definition of `github__propose_change`.
pub(crate) fn definition() -> Definition {
    let mut properties = tools::owner_and_repo();
    properties.insert(
        "title".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": create_pr::MAX_TITLE_CHARS,
            "description": "The pull request's title and the commit's message, with no control character."
        }),
    );
    properties.insert(
        "idempotency_key".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_KEY_CHARS,
            "description": "Names the proposal's branch, otto/<key>: letters, digits, '.', '_' and '-', not beginning with '.', with no '..' and not ending in '.' or '.lock'. A repeat with the same key answers the existing proposal."
        }),
    );
    properties.insert("files".into(), proposals::files_schema());
    properties.insert("unverifiedClaims".into(), proposals::claims_schema());
    properties.insert(
        "body".into(),
        json!({
            "type": "string",
            "maxLength": MAX_CALLER_BODY_CHARS,
            "description": "The pull request's description, after the claims and a line carrying the gateway's receipt for the call. The whole is held to GitHub's 65536 characters."
        }),
    );
    Definition {
        name: PROPOSE_CHANGE,
        description: "Proposes a change to files of a repository of the configured organization: \
                      one commit on a new branch otto/<idempotency_key> from the default branch's \
                      head, and a draft pull request into the default branch, with the declared \
                      unverified claims quoted above the description. It is always a draft. A \
                      repeat with the same key answers the existing proposal. It is refused for \
                      CI workflow files, Atlantis configuration, AGENTS.md and .agents/, and \
                      for a title, description or claim that begins with an Atlantis command.",
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": ["owner", "repo", "title", "idempotency_key", "files", "unverifiedClaims"],
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
pub(crate) struct ProposeChange {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) title: String,
    pub(crate) key: String,
    pub(crate) files: Vec<File>,
    pub(crate) claims: Vec<String>,
    /// The caller's body, empty when it gave none.
    pub(crate) body: String,
}

impl ProposeChange {
    /// The branch the proposal makes.
    pub(crate) fn branch(&self) -> String {
        format!("{BRANCH_PREFIX}{}", self.key)
    }
}

/// Parses `arguments`, or says why they are malformed.
pub(crate) fn parse(arguments: &Value) -> Result<ProposeChange, String> {
    let arguments = tools::object(arguments)?;
    proposals::only(arguments, ARGUMENTS, PROPOSE_CHANGE)?;
    let (owner, repo) = tools::owner_repo(arguments)?;
    let title = create_pr::title(arguments)?;
    let key = tools::required(arguments, "idempotency_key")?;
    branch_key(&key)?;
    let files = proposals::files(arguments)?;
    let claims = proposals::claims(arguments)?;
    let body = tools::text(arguments, "body")?.unwrap_or_default();
    if body.chars().count() > MAX_CALLER_BODY_CHARS {
        return Err(format!(
            "body is longer than {MAX_CALLER_BODY_CHARS} characters"
        ));
    }
    Ok(ProposeChange {
        owner,
        repo,
        title,
        key,
        files,
        claims,
        body,
    })
}

/// Refuses `key` unless `otto/<key>` is a branch name: see the [module documentation](self).
fn branch_key(key: &str) -> Result<(), String> {
    let charset = key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    let well_formed = (1..=MAX_KEY_CHARS).contains(&key.len())
        && charset
        && !key.starts_with('.')
        && !key.contains("..")
        && !key.ends_with('.')
        && !key.ends_with(".lock");
    if well_formed {
        return Ok(());
    }
    Err(format!(
        "idempotency_key {:?} must be 1 to {MAX_KEY_CHARS} of the characters A-Z a-z 0-9 . _ -, \
         not beginning with \".\", holding no \"..\" and not ending with \".\" or \".lock\", since \
         it names the branch otto/<key>",
        bounded(key, 128).0
    ))
}

/// The pull request GitHub is asked to open: a draft always.
#[derive(Serialize)]
struct NewPull<'a> {
    title: &'a str,
    head: &'a str,
    base: &'a str,
    body: &'a str,
    draft: bool,
}

/// A new branch.
#[derive(Serialize)]
struct NewRef<'a> {
    #[serde(rename = "ref")]
    name: &'a str,
    sha: &'a str,
}

impl GitHubConnector {
    /// `github__propose_change`'s call. See the [module documentation](self).
    pub(crate) async fn propose_change(&self, call: &ToolCall) -> ToolOutcome {
        let receipt = match writes::receipt(call) {
            Ok(receipt) => receipt,
            Err(outcome) => return outcome,
        };
        let parsed = match parse(call.arguments()) {
            Ok(parsed) => parsed,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        let marker = writes::marker(receipt);
        let body = match proposals::body(&parsed.claims, &[marker], &parsed.body) {
            Ok(body) => body,
            Err(why) => return ToolOutcome::error(ErrorKind::InvalidArguments, why),
        };
        let mut texts = vec![
            ("title".to_owned(), parsed.title.as_str()),
            ("body".to_owned(), parsed.body.as_str()),
        ];
        for (at, claim) in parsed.claims.iter().enumerate() {
            texts.push((format!("unverifiedClaims[{at}]"), claim.as_str()));
        }
        if let Some(refusal) = self.refused_before_any_request(&parsed.owner, &parsed.files, &texts)
        {
            return ToolOutcome::Refused(refusal);
        }
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
        let branch = parsed.branch();

        // Every answer that writes nothing, decided from reads before the first write.
        let found = match self
            .read_found(&base, &reads, &format!("the repository {repository}"))
            .await
        {
            Ok(found) => found,
            Err(outcome) => return outcome,
        };
        let Some(default) = found
            .get("default_branch")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return ToolOutcome::error(
                ErrorKind::Other,
                format!("GitHub named no default branch for {repository}, so nothing was written"),
            );
        };
        let head = tools::encoded(&format!("{}:{branch}", parsed.owner));
        let pulls = match self
            .read_found(
                &format!("{base}/pulls?state=all&head={head}&per_page=100"),
                &reads,
                &format!("the pull requests from {branch}"),
            )
            .await
        {
            Ok(Value::Array(pulls)) => pulls,
            Ok(_) => {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    format!(
                        "GitHub's list of the pull requests from {branch} could not be read, so \
                         nothing was written"
                    ),
                );
            }
            Err(outcome) => return outcome,
        };
        for pull in &pulls {
            let Some(number) = pull.get("number").and_then(Value::as_u64) else {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    format!(
                        "GitHub listed a pull request from {branch} with no number, so nothing \
                         was written"
                    ),
                );
            };
            let proposed = match self
                .proposed_for(&ready.receipts, call, &repository, number)
                .await
            {
                Ok(proposed) => proposed,
                Err(outcome) => return outcome,
            };
            if let Some(proposed) = proposed {
                return existing(call, &parsed, pull, number, &proposed.digest);
            }
        }
        if let Some(number) = pulls
            .first()
            .and_then(|pull| pull.get("number"))
            .and_then(Value::as_u64)
        {
            return ToolOutcome::Refused(format!(
                "{branch} already has pull request #{number}, which {PROPOSE_CHANGE} did not \
                 open for this caller; choose another idempotency_key"
            ));
        }
        match self
            .read_json(
                &format!("{base}/git/ref/heads/{}", create_pr::branch_path(&branch)),
                &reads,
                &format!("the branch {branch}"),
                true,
            )
            .await
        {
            Ok(Read::Missing) => {}
            Ok(Read::Found(_)) => {
                return ToolOutcome::Refused(format!(
                    "the branch {branch} already exists with no pull request from it, and a \
                     proposal never writes to a branch it did not make; choose another \
                     idempotency_key"
                ));
            }
            Err(outcome) => return outcome,
        }
        let (base_sha, base_tree) = match self.branch_head(&base, &default, &reads).await {
            Ok(head) => head,
            Err(outcome) => return outcome,
        };
        match self
            .changes(&base, &base_sha, &base_tree, &parsed.files, &reads)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return ToolOutcome::error(
                    ErrorKind::Other,
                    format!(
                        "the files are the same as on {default} at {base_sha}, so the proposal \
                         would make no change; nothing was written"
                    ),
                );
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
        let commit = match self
            .commit(
                &mut writes,
                &base,
                &git,
                &parsed.files,
                &base_tree,
                &base_sha,
                &parsed.title,
            )
            .await
        {
            Ok(commit) => commit,
            Err(outcome) => return outcome,
        };
        let reference = format!("refs/heads/{branch}");
        if let Err(outcome) = writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{base}/git/refs"),
                &NewRef {
                    name: &reference,
                    sha: &commit,
                },
                git.expose(),
                "the branch",
            )
            .await
        {
            return outcome;
        }
        let opened = match writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{base}/pulls"),
                &NewPull {
                    title: &parsed.title,
                    head: &branch,
                    base: &default,
                    body: &body,
                    draft: true,
                },
                reads.expose(),
                "the pull request",
            )
            .await
        {
            Ok(opened) => opened,
            Err(outcome) => return outcome,
        };
        let number = opened.get("number").and_then(Value::as_u64);
        let mut result = Map::new();
        result.insert("state".into(), "proposed".into());
        result.insert("branch".into(), branch.into());
        result.insert("prNumber".into(), number.map_or(Value::Null, Value::from));
        result.insert("baseSha".into(), base_sha.into());
        result.insert("commitSha".into(), commit.into());
        result.insert(
            "url".into(),
            opened.get("html_url").cloned().unwrap_or(Value::Null),
        );
        result.insert(
            "provenance".into(),
            tools::provenance_as(PROPOSE_CHANGE, call.tool().classification),
        );
        writes::completed(Value::Object(result), number)
    }
}

/// The answer for the pull request `pull`, number `number`, which the gateway opened for the
/// caller under the receipt whose arguments have `recorded`'s digest. Nothing is written.
fn existing(
    call: &ToolCall,
    parsed: &ProposeChange,
    pull: &Value,
    number: u64,
    recorded: &ArgumentDigest,
) -> ToolOutcome {
    let branch = parsed.branch();
    let merged = pull.get("merged_at").is_some_and(|at| !at.is_null())
        || pull.get("merged").and_then(Value::as_bool) == Some(true);
    let open = pull.get("state").and_then(Value::as_str) == Some("open");
    let mut result = Map::new();
    let (state, message) = if merged {
        (
            "already_proposed",
            format!("{branch} was proposed as pull request #{number}, which has been merged"),
        )
    } else if !open {
        (
            "proposal_declined",
            format!(
                "{branch} was proposed as pull request #{number}, which a person closed without \
                 merging it; the gateway will never reopen it or open another for this key"
            ),
        )
    } else if ArgumentDigest::of(call.arguments()) == *recorded {
        (
            "already_proposed",
            format!("{branch} is already proposed as pull request #{number}"),
        )
    } else {
        (
            "key_conflict",
            format!(
                "{branch} is already proposed as pull request #{number} with other files, \
                 claims, title or body; this call differs from the recorded copy, so nothing was \
                 written. Use another idempotency_key for another proposal"
            ),
        )
    };
    result.insert("state".into(), state.into());
    result.insert("branch".into(), branch.into());
    result.insert("prNumber".into(), number.into());
    result.insert("merged".into(), merged.into());
    result.insert(
        "url".into(),
        pull.get("html_url").cloned().unwrap_or(Value::Null),
    );
    result.insert("message".into(), message.into());
    result.insert(
        "provenance".into(),
        tools::provenance_as(PROPOSE_CHANGE, call.tool().classification),
    );
    ToolOutcome::Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn arguments(changes: Value) -> Value {
        let mut arguments = json!({
            "owner": "example-org",
            "repo": "atlas",
            "title": "Bump the widget",
            "idempotency_key": "widget-1.2",
            "files": [{"path": "a.txt", "content": "x"}],
            "unverifiedClaims": ["the latest widget is 1.2"],
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
        let parsed = parse(&arguments(json!({"body": "Why."}))).unwrap();
        assert_eq!(parsed.branch(), "otto/widget-1.2");
        assert_eq!(parsed.body, "Why.");
        assert_eq!(parse(&arguments(json!({}))).unwrap().body, "");
        for key in ["a", "A_b-c.d", "-x", "_", &"k".repeat(MAX_KEY_CHARS)] {
            parse(&arguments(json!({ "idempotency_key": key }))).unwrap();
        }
    }

    #[test]
    fn each_malformed_argument_is_told_apart() {
        let long_key = "k".repeat(MAX_KEY_CHARS + 1);
        let long_body = "b".repeat(MAX_CALLER_BODY_CHARS + 1);
        for (changes, why) in [
            (
                json!({"idempotency_key": ""}),
                "idempotency_key \"\" must be",
            ),
            (json!({"idempotency_key": long_key}), "must be 1 to 100"),
            (json!({"idempotency_key": ".x"}), "must be 1 to 100"),
            (json!({"idempotency_key": "a..b"}), "must be 1 to 100"),
            (json!({"idempotency_key": "a.lock"}), "must be 1 to 100"),
            (json!({"idempotency_key": "widget."}), "must be 1 to 100"),
            (json!({"idempotency_key": "v1.2."}), "must be 1 to 100"),
            (json!({"idempotency_key": "a/b"}), "must be 1 to 100"),
            (json!({"idempotency_key": "a b"}), "must be 1 to 100"),
            (
                json!({"idempotency_key": null}),
                "idempotency_key is required",
            ),
            (
                json!({"title": "two\nlines"}),
                "title contains a control character",
            ),
            (json!({"title": ""}), "title must not be empty"),
            (
                json!({"unverifiedClaims": null}),
                "unverifiedClaims is required",
            ),
            (
                json!({"files": [{"path": "../x", "content": "x"}]}),
                "contains a \"..\" segment",
            ),
            (json!({"body": long_body}), "body is longer than 65536"),
            (json!({"body": 7}), "body must be a string"),
            (
                json!({"draft": false}),
                "\"draft\" is not an argument of github__propose_change",
            ),
            (json!({"owner": "a/b"}), "login charset"),
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
