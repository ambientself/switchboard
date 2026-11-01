//! `github__create_pr` (#12): opens a draft pull request from one branch into another of a
//! repository of the configured organization, as Otto's `github_create_pr` does
//! (docs/otto-baseline.md, "Pull requests"). It is `propose`: what it makes is a draft, which
//! a person reads before anything acts on it (design section 8).
//!
//! Before anything is asked of the key custodian or of GitHub:
//!
//! - the tool must be approved `propose`, and its call must carry its receipt
//!   (`writes::receipt`), or nothing is sent: `error`;
//! - its arguments are parsed into its own types, and a malformed one is `invalid_arguments`:
//!   an argument the schema does not list; a title that is empty, over [`MAX_TITLE_CHARS`]
//!   characters or holds a control character; a head or base that is not a git branch name
//!   ([`MAX_BRANCH_BYTES`] bytes at most); or a body that, with the marker line, is over
//!   [`MAX_BODY_CHARS`] characters, GitHub's own bound;
//! - an owner other than the configured organization is `refused`, with Otto's sentence; so is
//!   a title or body whose first word is `atlantis` ([`crate::writes::command_text`]), and one
//!   that holds the marker's text ([`crate::writes::holds_marker`]).
//!
//! Then one token is asked for: narrowed to the call's one repository, with the tool's own set,
//! `contents: read` and `pull_requests: write` ([`PERMISSIONS`]), never its entry's whole set,
//! and the revision the call was decided under. With it, the connector reads GitHub's
//! comparison of the base with the head, `GET /repos/{owner}/{repo}/compare/{base}...{head}`,
//! and refuses the call when a file it changes, under its name or its former one, is a CI
//! workflow file or Atlantis configuration ([`crate::writes::refused_path`], the automation
//! group), and when the comparison does not list its files whole: no list, or
//! [`MAX_COMPARED_FILES`] or more, where GitHub cuts its list. Until the automation owners
//! answer, a proposal may not change either (decision 0011, section 6). Otto's gateway makes no
//! such check; it is a difference, and not a complete one: a push to the head between the
//! comparison and the pull request's creation is not seen. A failed comparison, a 404, a 422 or
//! a 5xx among them, is `error`: nothing was written.
//!
//! The write is `POST /repos/{owner}/{repo}/pulls`, with `draft: true` always (no argument or
//! setting turns it off; Otto's `CreateReadyPRs` is not carried over), the title, the head, the
//! base, and the body: the caller's, a blank line, and the marker line carrying the call's
//! receipt ([`crate::writes::marker`]). Its outcome follows the rule in [`crate::writes`]. The
//! result is `{pr: {number, url, draft, head, base}, provenance}`, the provenance naming the
//! classification the tool was approved with, `propose`, and tagged as external evidence, and
//! the receipt records `pull/<number>`.

use gateway_core::{ErrorKind, Narrowing, PrincipalKind, ToolCall, ToolOutcome};
use gateway_registry::{Access, Assurance};
use hyper::StatusCode;
use key_custodian::TokenRequest;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::{Answered, WriteMethod};
use crate::connector::GitHubConnector;
use crate::tools::{self, Definition, bounded};
use crate::writes::{self, PathGroup, Writes};

/// `github__create_pr`.
pub const CREATE_PR: &str = "github__create_pr";

/// The permissions `github__create_pr` asks for: its own set, within its entry's.
pub const PERMISSIONS: &[(&str, Access)] =
    &[("contents", Access::Read), ("pull_requests", Access::Write)];

/// The longest title, in characters.
pub const MAX_TITLE_CHARS: usize = 256;

/// The longest head or base branch name, in bytes, as git's own refs are held.
pub const MAX_BRANCH_BYTES: usize = 255;

/// The longest body GitHub takes, in characters: the caller's body and the marker line.
pub const MAX_BODY_CHARS: usize = 65_536;

/// The longest body a caller may give, in characters, leaving room for the marker line.
pub const MAX_CALLER_BODY_CHARS: usize = 65_000;

/// The number of changed files at which GitHub cuts a comparison's list: a comparison listing
/// this many or more is refused, since what it leaves out cannot be checked.
pub const MAX_COMPARED_FILES: usize = 300;

/// The arguments the schema lists.
const ARGUMENTS: &[&str] = &["owner", "repo", "title", "head", "base", "body"];

/// The definition of `github__create_pr`.
pub(crate) fn definition() -> Definition {
    let mut properties = tools::owner_and_repo();
    properties.insert(
        "title".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_TITLE_CHARS,
            "description": "The pull request's title, with no control character."
        }),
    );
    properties.insert(
        "head".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_BRANCH_BYTES,
            "description": "The branch holding the changes, in the same repository."
        }),
    );
    properties.insert(
        "base".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_BRANCH_BYTES,
            "description": "The branch the changes would be merged into."
        }),
    );
    properties.insert(
        "body".into(),
        json!({
            "type": "string",
            "maxLength": MAX_CALLER_BODY_CHARS,
            "description": "The pull request's description. A line carrying the gateway's receipt for the call is added after it."
        }),
    );
    Definition {
        name: CREATE_PR,
        description: "Opens a draft pull request from a branch into another in a repository of \
                      the configured organization. It is always a draft. It is refused when the \
                      branch changes a CI workflow file or Atlantis configuration, or when the \
                      title or body begins with an Atlantis command. The description ends with a \
                      line carrying the gateway's receipt for the call.",
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": ["owner", "repo", "title", "head", "base"],
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
pub(crate) struct CreatePr {
    pub(crate) owner: String,
    pub(crate) repo: String,
    pub(crate) title: String,
    pub(crate) head: String,
    pub(crate) base: String,
    /// The caller's body, empty when it gave none.
    pub(crate) body: String,
}

/// Parses `arguments`, or says why they are malformed.
pub(crate) fn parse(arguments: &Value) -> Result<CreatePr, String> {
    let arguments = tools::object(arguments)?;
    if let Some(unlisted) = arguments
        .keys()
        .find(|name| !ARGUMENTS.contains(&name.as_str()))
    {
        return Err(format!(
            "{:?} is not an argument of {CREATE_PR}",
            bounded(unlisted, 64).0
        ));
    }
    let (owner, repo) = tools::owner_repo(arguments)?;
    let title = title(arguments)?;
    let head = tools::required(arguments, "head")?;
    branch(&head, "head")?;
    let base = tools::required(arguments, "base")?;
    branch(&base, "base")?;
    let body = tools::text(arguments, "body")?.unwrap_or_default();
    Ok(CreatePr {
        owner,
        repo,
        title,
        head,
        base,
        body,
    })
}

/// The argument `title`: required, not empty, at most [`MAX_TITLE_CHARS`] characters, with no
/// control character. Every proposal tool's title is held to it.
pub(crate) fn title(arguments: &Map<String, Value>) -> Result<String, String> {
    let title = tools::required(arguments, "title")?;
    if title.trim().is_empty() {
        return Err("title must not be empty".into());
    }
    if title.chars().count() > MAX_TITLE_CHARS {
        return Err(format!("title is longer than {MAX_TITLE_CHARS} characters"));
    }
    if title.chars().any(char::is_control) {
        return Err("title contains a control character".into());
    }
    Ok(title)
}

/// Refuses `value`, the argument `name`, unless it is a git branch name: 1 to
/// [`MAX_BRANCH_BYTES`] bytes, with no control character, whitespace, `:`, `~`, `^`, `?`, `*`,
/// `[` or `\`, no `..` or `@{`, not `@`, not beginning with `-`, with no empty segment, no
/// segment beginning with `.` or ending with `.lock`, and not ending with `.` or `/`. Git's own
/// rules, with whitespace refused beside the space.
pub(crate) fn branch(value: &str, name: &str) -> Result<(), String> {
    let refused = |why: &str| {
        Err(format!(
            "{name} {:?} is not a git branch name: {why}",
            bounded(value, 128).0
        ))
    };
    if value.is_empty() || value.len() > MAX_BRANCH_BYTES {
        return refused(&format!("it must be 1 to {MAX_BRANCH_BYTES} bytes long"));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
    {
        return refused("it holds a control character, whitespace, or one of ~ ^ : ? * [ \\");
    }
    if value.contains("..") || value.contains("@{") || value == "@" {
        return refused("it holds \"..\" or \"@{\", or is \"@\"");
    }
    if value.starts_with('-') {
        return refused("it begins with \"-\"");
    }
    if value.ends_with('.') || value.ends_with('/') {
        return refused("it ends with \".\" or \"/\"");
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment.starts_with('.') || segment.ends_with(".lock"))
    {
        return refused(
            "it has an empty segment, or a segment beginning with \".\" or ending with \".lock\"",
        );
    }
    Ok(())
}

/// The body GitHub is sent: the caller's, a blank line, and `marker`; or `marker` alone when
/// the caller gave none. Or why it cannot be sent.
fn with_marker(body: &str, marker: &str) -> Result<String, String> {
    let sent = if body.is_empty() {
        marker.to_owned()
    } else {
        format!("{body}\n\n{marker}")
    };
    let length = sent.chars().count();
    if length > MAX_BODY_CHARS {
        return Err(format!(
            "body is {length} characters with the line carrying the gateway's receipt, and \
             GitHub takes at most {MAX_BODY_CHARS}"
        ));
    }
    Ok(sent)
}

/// `branch` for a path: each segment percent-encoded, the slashes kept.
pub(crate) fn branch_path(branch: &str) -> String {
    branch
        .split('/')
        .map(tools::encoded)
        .collect::<Vec<_>>()
        .join("/")
}

/// The pull request GitHub is asked to open: built from the connector's own types, a draft
/// always.
#[derive(Serialize)]
struct NewPull<'a> {
    title: &'a str,
    head: &'a str,
    base: &'a str,
    body: &'a str,
    draft: bool,
}

impl GitHubConnector {
    /// `github__create_pr`'s call. See the [module documentation](self).
    pub(crate) async fn create_pr(&self, call: &ToolCall) -> ToolOutcome {
        // Not the approval alone: a write that is not `propose`, or has no receipt, sends
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
        for (field, text) in [("title", &parsed.title), ("body", &parsed.body)] {
            if writes::command_text(text) {
                return ToolOutcome::Refused(writes::command_text_sentence(field));
            }
            if writes::holds_marker(text) {
                return ToolOutcome::Refused(writes::marker_sentence(field));
            }
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
        let compared = format!(
            "{base}/compare/{}...{}",
            branch_path(&parsed.base),
            branch_path(&parsed.head)
        );
        let comparison = match self.api().get(&compared, token.expose()).await {
            Answered::Json(comparison) => comparison,
            other => return comparison_failed(other, &parsed),
        };
        if let Some(refusal) = automation_changed(&comparison, &parsed) {
            return ToolOutcome::Refused(refusal);
        }
        let pull = NewPull {
            title: &parsed.title,
            head: &parsed.head,
            base: &parsed.base,
            body: &body,
            draft: true,
        };
        let mut writes = Writes::new();
        let opened = match writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{base}/pulls"),
                &pull,
                token.expose(),
                "the pull request",
            )
            .await
        {
            Ok(opened) => opened,
            Err(outcome) => return outcome,
        };
        let number = opened.get("number").and_then(Value::as_u64);
        let string = |pointer: &str| {
            opened
                .pointer(pointer)
                .and_then(Value::as_str)
                .map_or(Value::Null, |text| Value::String(text.to_owned()))
        };
        let mut pr = Map::new();
        pr.insert("number".into(), number.map_or(Value::Null, Value::from));
        pr.insert("url".into(), string("/html_url"));
        pr.insert(
            "draft".into(),
            opened.get("draft").cloned().unwrap_or(Value::Null),
        );
        pr.insert("head".into(), string("/head/ref"));
        pr.insert("base".into(), string("/base/ref"));
        let result = json!({
            "pr": pr,
            "provenance": tools::provenance_as(CREATE_PR, call.tool().classification),
        });
        writes::completed(result, number)
    }
}

/// The outcome when the comparison gave no JSON answer: `error`, since nothing was written. No
/// sentence quotes GitHub's answer.
fn comparison_failed(answered: Answered, call: &CreatePr) -> ToolOutcome {
    let repository = format!("{}/{}", call.owner, call.repo);
    let (kind, why) = match answered {
        Answered::Json(_) | Answered::Unreadable => (
            ErrorKind::Other,
            "GitHub's comparison could not be read".to_owned(),
        ),
        Answered::Unreachable => (
            ErrorKind::Other,
            "GitHub could not be reached to compare the branches".to_owned(),
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
                "GitHub found no branch {:?} or {:?} to compare in {repository}, or the token \
                 cannot see the repository (HTTP 404)",
                bounded(&call.base, 128).0,
                bounded(&call.head, 128).0
            ),
        ),
        Answered::Status { status, .. } if status == StatusCode::FORBIDDEN => (
            ErrorKind::VendorRefusal,
            format!(
                "GitHub refused to compare the branches in {repository} to this App (HTTP 403)"
            ),
        ),
        Answered::Status { status, .. } => (
            ErrorKind::Other,
            format!(
                "GitHub could not compare the branches in {repository} (HTTP {})",
                status.as_u16()
            ),
        ),
    };
    ToolOutcome::error(kind, format!("{why}, so no pull request was opened"))
}

/// The refusal sentence when `comparison` changes a file in the automation group, under its
/// name or its former one, or does not list its files whole; `None` when it may be proposed.
fn automation_changed(comparison: &Value, call: &CreatePr) -> Option<String> {
    let between = format!(
        "the changes from {:?} into {:?}",
        bounded(&call.head, 128).0,
        bounded(&call.base, 128).0
    );
    let Some(files) = comparison.get("files").and_then(Value::as_array) else {
        return Some(format!(
            "GitHub's comparison of {between} lists no files, so whether they change a CI \
             workflow file or Atlantis configuration cannot be checked"
        ));
    };
    if files.len() >= MAX_COMPARED_FILES {
        return Some(format!(
            "GitHub's comparison of {between} lists {} files, and GitHub cuts the list at \
             {MAX_COMPARED_FILES}, so whether they change a CI workflow file or Atlantis \
             configuration cannot be checked; propose fewer files at once",
            files.len()
        ));
    }
    for file in files {
        for (field, required) in [("filename", true), ("previous_filename", false)] {
            let path = match file.get(field) {
                Some(Value::String(path)) => path,
                None if !required => continue,
                _ => {
                    return Some(format!(
                        "GitHub's comparison of {between} names a file it cannot be read for, \
                         so whether they change a CI workflow file or Atlantis configuration \
                         cannot be checked"
                    ));
                }
            };
            if let Some(refused) = writes::refused_path(path)
                && refused.group == PathGroup::Automation
            {
                return Some(format!(
                    "{between} change \"{}\", and {}; until the automation owners answer, a \
                     proposal may not change CI workflow files or Atlantis configuration",
                    gateway_core::escape(path, gateway_core::MAX_RENDERED),
                    refused.sentence
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn arguments(changes: Value) -> Value {
        let mut arguments = json!({
            "owner": "example-org",
            "repo": "atlas",
            "title": "Add a retry",
            "head": "feature/retry",
            "base": "main",
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
        assert_eq!(
            parsed,
            CreatePr {
                owner: "example-org".into(),
                repo: "atlas".into(),
                title: "Add a retry".into(),
                head: "feature/retry".into(),
                base: "main".into(),
                body: "Why.".into(),
            }
        );
        assert_eq!(parse(&arguments(json!({}))).unwrap().body, "");
        for branch in ["a", "otto/x-1", "release/2026.10", "a_b", "é"] {
            parse(&arguments(json!({ "head": branch }))).unwrap();
        }
        let longest = "b".repeat(MAX_BRANCH_BYTES);
        parse(&arguments(json!({ "head": longest }))).unwrap();
        let longest = "t".repeat(MAX_TITLE_CHARS);
        parse(&arguments(json!({ "title": longest }))).unwrap();
    }

    #[test]
    fn each_malformed_argument_is_told_apart() {
        let long_title = "t".repeat(MAX_TITLE_CHARS + 1);
        let long_branch = "b".repeat(MAX_BRANCH_BYTES + 1);
        let cases = [
            (json!({"title": ""}), "title must not be empty"),
            (json!({"title": "  "}), "title must not be empty"),
            (json!({"title": long_title}), "longer than 256"),
            (
                json!({"title": "a\u{7}b"}),
                "title contains a control character",
            ),
            (
                json!({"title": "a\nb"}),
                "title contains a control character",
            ),
            (json!({"title": null}), "title is required"),
            (json!({"title": 7}), "title must be a string"),
            (json!({"body": 7}), "body must be a string"),
            (json!({"head": null}), "head is required"),
            (json!({"draft": false}), "\"draft\" is not an argument"),
            (json!({"owner": "a/b"}), "login charset"),
        ];
        for (changes, why) in cases {
            let error = parse(&arguments(changes.clone())).unwrap_err();
            assert!(error.contains(why), "{changes}: {error}");
        }
        for (name, branch) in [
            ("head", "a:b"),
            ("head", "a..b"),
            ("head", "a b"),
            ("head", "a\tb"),
            ("head", "a\u{7f}b"),
            ("head", "a~1"),
            ("head", "a^"),
            ("head", "a?"),
            ("head", "a*"),
            ("head", "a[b"),
            ("head", "a\\b"),
            ("head", "-a"),
            ("head", "a/"),
            ("head", "/a"),
            ("head", "a//b"),
            ("head", "a.lock"),
            ("head", "a/b.lock/c"),
            ("head", "a@{1}"),
            ("head", "@"),
            ("head", "a."),
            ("head", ".a"),
            ("head", "a/.b"),
            ("head", ""),
            ("head", long_branch.as_str()),
            ("base", "main:other"),
            ("base", "x..y"),
        ] {
            let error = parse(&arguments(json!({ name: branch }))).unwrap_err();
            assert!(
                error.starts_with(&format!("{name} "))
                    && error.contains("is not a git branch name"),
                "{branch:?}: {error}"
            );
        }
    }

    #[test]
    fn the_body_ends_with_the_marker_and_is_bounded_with_it() {
        let marker = "<!-- switchboard-receipt: r -->";
        assert_eq!(with_marker("", marker).unwrap(), marker);
        assert_eq!(
            with_marker("Why.", marker).unwrap(),
            format!("Why.\n\n{marker}")
        );
        let room = MAX_BODY_CHARS - marker.chars().count() - 2;
        let fits = "é".repeat(room);
        assert_eq!(
            with_marker(&fits, marker).unwrap().chars().count(),
            MAX_BODY_CHARS
        );
        let over = "é".repeat(room + 1);
        assert!(with_marker(&over, marker).unwrap_err().contains("65536"));
    }

    #[test]
    fn a_branch_is_encoded_segment_by_segment() {
        assert_eq!(branch_path("feature/a+b"), "feature/a%2Bb");
        assert_eq!(branch_path("main"), "main");
    }

    #[test]
    fn a_comparison_touching_automation_or_not_listed_whole_is_refused() {
        let call = parse(&arguments(json!({}))).unwrap();
        let files = |names: &[&str]| json!({"files": names.iter().map(|name| json!({"filename": name})).collect::<Vec<_>>()});
        assert_eq!(automation_changed(&files(&["src/lib.rs"]), &call), None);
        // The instruction-authority group is the proposal tools' with files, not this one's.
        assert_eq!(automation_changed(&files(&["AGENTS.md"]), &call), None);
        for path in [".github/workflows/x.yml", "infra/Atlantis.yml", ".github"] {
            let refusal = automation_changed(&files(&["README.md", path]), &call).unwrap();
            assert!(refusal.contains(&format!("\"{path}\"")), "{refusal}");
        }
        let renamed = json!({"files": [{"filename": "ci.yml", "previous_filename": ".github/workflows/ci.yml"}]});
        assert!(automation_changed(&renamed, &call).is_some());
        let unnamed = json!({"files": [{"status": "added"}]});
        assert!(automation_changed(&unnamed, &call).is_some());
        assert!(automation_changed(&json!({}), &call).is_some());
        let names: Vec<String> = (0..MAX_COMPARED_FILES).map(|at| format!("f{at}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let cut = automation_changed(&files(&names), &call).unwrap();
        assert!(cut.contains("cuts the list at 300"), "{cut}");
        assert_eq!(automation_changed(&files(&names[1..]), &call), None);
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
