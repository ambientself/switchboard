//! What the two file-writing proposal tools share, `github__propose_change`
//! ([`crate::propose`]) and `github__amend_change` ([`crate::amend`]) (#12): their arguments,
//! the guards they make before any request, the attribution read that tells a pull request the
//! gateway opened for the caller, the reads that decide every answer that writes nothing, the
//! git writes, and the pull request's body.
//!
//! # Before any request
//!
//! Both parse their arguments into their own types, and a malformed one is `invalid_arguments`:
//! an argument the schema does not list; `files` missing, empty or over [`MAX_FILES`]; a file
//! that is not `{path, content}`; a path held to `github__get_file`'s rules, with no `.git`
//! segment in any case, given once, and not under another file of the call; a content that is
//! not a string or is over [`MAX_CONTENT_BYTES`]; `unverifiedClaims` missing or null, not a
//! list of strings, over [`MAX_CLAIMS`], or a claim over [`MAX_CLAIM_BYTES`]. Then, in this
//! order, each is `refused` before anything is asked of anyone:
//!
//! - an owner other than the configured organization, with Otto's sentence;
//! - a path a proposal may not change ([`crate::writes::refused_path`]), with Otto's sentence;
//! - a title, body or claim whose first word is `atlantis` ([`crate::writes::command_text`]);
//! - a title, body or claim that holds the marker's text ([`crate::writes::holds_marker`]).
//!
//! The write entry must be narrowed `call` (`writes::check_entry`), the caller must
//! be a team's workload, and the connector must have the gateway's receipts to read
//! ([`crate::GitHubConnector::read_receipts_from`]): without them a call is an `error` and
//! nothing is sent, since no pull request could be told to be the caller's.
//!
//! # Two tokens
//!
//! Each call asks the key custodian for at most two tokens, each narrowed to the call's one
//! repository: [`PULL_PERMISSIONS`], `{contents: read, pull_requests: write}`, for every read and
//! the pull request's write; and [`GIT_PERMISSIONS`], `{contents: write}`, for the git writes,
//! asked for only once the reads have decided that something will be written. An entry serving
//! either tool must state [`PERMISSIONS`].
//!
//! # Attribution
//!
//! A pull request is the caller's when the gateway's receipts hold a `completed` receipt of
//! `github__propose_change` for the caller's issuer and subject, in the call's repository, with
//! the reference `pull/<number>` (decision 0011, section 6): never from Otto's records or a
//! resolver.
//!
//! # Every answer that writes nothing is decided first
//!
//! Once a write may have been sent, every failure is `unknown` ([`crate::writes`]). So both
//! tools read everything an answer that writes nothing turns on before their first write: the
//! pull request, its state and its attribution, the branch's head, and each file's contents at
//! the commit the change would sit on. What each path is there comes from the git trees' modes,
//! never from the contents API, which answers a symbolic link to a file of the repository with
//! that file's contents. A path that is a directory, a symbolic link or a submodule there, or
//! that is under something that is not a directory, is `refused`: a proposal writes regular
//! files only, as mode `100644`.
//!
//! # The body
//!
//! A proposal's pull request body is the claims block, a blank line, the marker block, and, after
//! a blank line, the caller's description. The claims block is GitHub's warning alert followed
//! by each claim in a code fence of its own, one backtick longer than the longest run of
//! backticks in the claim, and at least three, so no claim can close its fence; with no claims
//! it is a note saying none were declared. The marker block is one line per receipt that wrote
//! the pull request: the proposal's, and each amendment's after it
//! ([`crate::writes::marker`]). A lookup finds each by its line ([`crate::lookup`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine as _;
use gateway_core::{
    AttributionQuery, ErrorKind, Narrowing, PrincipalKind, Receipt, ReceiptAttribution, Resource,
    TeamId, ToolCall, ToolName, ToolOutcome, VendorReference,
};
use gateway_registry::Access;
use hyper::StatusCode;
use key_custodian::{Token, TokenRequest};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::api::{Answered, WriteMethod};
use crate::connector::GitHubConnector;
use crate::create_pr::MAX_BODY_CHARS;
use crate::tools::{self, bounded};
use crate::writes::{self, Writes};
use crate::{REPOSITORY, SYSTEM};

/// `github__propose_change`.
pub const PROPOSE_CHANGE: &str = "github__propose_change";

/// `github__amend_change`.
pub const AMEND_CHANGE: &str = "github__amend_change";

/// What an entry serving either tool must state, each at this level or above.
pub const PERMISSIONS: &[(&str, Access)] = &[
    ("contents", Access::Write),
    ("pull_requests", Access::Write),
];

/// The git writes' token: blobs, a tree, a commit and the branch.
pub const GIT_PERMISSIONS: &[(&str, Access)] = &[("contents", Access::Write)];

/// Every read's token, and the pull request's write.
pub const PULL_PERMISSIONS: &[(&str, Access)] =
    &[("contents", Access::Read), ("pull_requests", Access::Write)];

/// The prefix of every branch a proposal makes or amends.
pub const BRANCH_PREFIX: &str = "otto/";

/// The most files one call may write.
pub const MAX_FILES: usize = 50;

/// The longest file content, in bytes: within what GitHub's contents API answers whole, so the
/// file it would replace can be compared with it.
pub const MAX_CONTENT_BYTES: usize = 1_000_000;

/// The most unverified claims one call may declare.
pub const MAX_CLAIMS: usize = 20;

/// The longest unverified claim, in bytes.
pub const MAX_CLAIM_BYTES: usize = 1_000;

/// A file a call writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct File {
    pub(crate) path: String,
    pub(crate) content: String,
}

/// Refuses an argument of `tool` that is not in `listed`.
pub(crate) fn only(
    arguments: &Map<String, Value>,
    listed: &[&str],
    tool: &str,
) -> Result<(), String> {
    match arguments
        .keys()
        .find(|name| !listed.contains(&name.as_str()))
    {
        Some(unlisted) => Err(format!(
            "{:?} is not an argument of {tool}",
            bounded(unlisted, 64).0
        )),
        None => Ok(()),
    }
}

/// The argument `files`, parsed: see the [module documentation](self).
pub(crate) fn files(arguments: &Map<String, Value>) -> Result<Vec<File>, String> {
    let files = match arguments.get("files") {
        None | Some(Value::Null) => return Err("files is required".into()),
        Some(Value::Array(files)) => files,
        Some(_) => return Err("files must be a list of files, each a path and a content".into()),
    };
    if files.is_empty() {
        return Err("files must hold at least one file".into());
    }
    if files.len() > MAX_FILES {
        return Err(format!(
            "files holds {} files, and one call may write at most {MAX_FILES}",
            files.len()
        ));
    }
    let mut parsed = Vec::with_capacity(files.len());
    for (at, file) in files.iter().enumerate() {
        let name = format!("files[{at}]");
        let Value::Object(file) = file else {
            return Err(format!(
                "{name} must be an object with a path and a content"
            ));
        };
        if let Some(other) = file.keys().find(|key| *key != "path" && *key != "content") {
            return Err(format!(
                "{:?} is not a field of {name}, which has a path and a content",
                bounded(other, 64).0
            ));
        }
        let field = |field: &str| match file.get(field) {
            Some(Value::String(text)) => Ok(text.clone()),
            None | Some(Value::Null) => Err(format!("{name}.{field} is required")),
            Some(_) => Err(format!("{name}.{field} must be a string")),
        };
        let path = field("path")?;
        tools::checked_path(&path, &format!("{name}.path"))?;
        if path
            .split('/')
            .any(|segment| segment.eq_ignore_ascii_case(".git"))
        {
            return Err(format!(
                "{name}.path has a \".git\" segment, which a repository's files may not have"
            ));
        }
        let content = field("content")?;
        if content.len() > MAX_CONTENT_BYTES {
            return Err(format!(
                "{name}.content is {} bytes, and a file may be at most {MAX_CONTENT_BYTES}",
                content.len()
            ));
        }
        parsed.push(File { path, content });
    }
    let paths: BTreeSet<&str> = parsed.iter().map(|file| file.path.as_str()).collect();
    for (at, file) in parsed.iter().enumerate() {
        if parsed[..at].iter().any(|earlier| earlier.path == file.path) {
            return Err(format!(
                "files[{at}].path {:?} is given twice",
                bounded(&file.path, 128).0
            ));
        }
        // A file under another file of the call: no tree can hold both.
        let mut parent = file.path.as_str();
        while let Some((above, _)) = parent.rsplit_once('/') {
            if paths.contains(above) {
                return Err(format!(
                    "files[{at}].path {:?} is under {:?}, another file of the call",
                    bounded(&file.path, 128).0,
                    bounded(above, 128).0
                ));
            }
            parent = above;
        }
    }
    Ok(parsed)
}

/// The argument `unverifiedClaims`, parsed: see the [module documentation](self).
pub(crate) fn claims(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    let claims = match arguments.get("unverifiedClaims") {
        None | Some(Value::Null) => {
            return Err(
                "unverifiedClaims is required: list each claim the change rests on that was not \
                 verified, or give an empty list"
                    .into(),
            );
        }
        Some(Value::Array(claims)) => claims,
        Some(_) => return Err("unverifiedClaims must be a list of strings".into()),
    };
    if claims.len() > MAX_CLAIMS {
        return Err(format!(
            "unverifiedClaims holds {} claims, and one call may declare at most {MAX_CLAIMS}",
            claims.len()
        ));
    }
    claims
        .iter()
        .enumerate()
        .map(|(at, claim)| match claim {
            Value::String(claim) if claim.len() > MAX_CLAIM_BYTES => Err(format!(
                "unverifiedClaims[{at}] is {} bytes, and a claim may be at most {MAX_CLAIM_BYTES}",
                claim.len()
            )),
            Value::String(claim) => Ok(claim.clone()),
            _ => Err(format!("unverifiedClaims[{at}] must be a string")),
        })
        .collect()
}

/// The fence a claim is quoted in: one backtick longer than its longest run of backticks, and
/// at least three, so nothing in the claim closes it.
pub(crate) fn fence(claim: &str) -> String {
    let longest = claim.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

/// The claims block: see the [module documentation](self).
pub(crate) fn claims_block(claims: &[String]) -> String {
    if claims.is_empty() {
        return "> [!NOTE]\n> No unverified claims were declared for this change.".to_owned();
    }
    let mut block = String::from(
        "> [!WARNING]\n> The agent declared these claims without verifying them. Check each \
         before relying on it.",
    );
    for claim in claims {
        let fence = fence(claim);
        block.push_str(&format!("\n\n{fence}\n{claim}\n{fence}"));
    }
    block
}

/// Whether `line` is a marker line, exactly as [`crate::writes::marker`] writes one.
pub(crate) fn is_marker(line: &str) -> bool {
    line.strip_prefix(&format!("<!-- {}: ", writes::MARKER_PREFIX))
        .and_then(|rest| rest.strip_suffix(" -->"))
        .is_some_and(|receipt| !receipt.is_empty() && !receipt.contains(char::is_whitespace))
}

/// The gateway's marker block in `body`: the run of consecutive marker lines holding `own`, the
/// marker of the receipt that opened the pull request, compared line by line, exactly; and the
/// description after it, its leading blank lines dropped. `None` when no line is `own`: a
/// person removed it.
pub(crate) fn marker_block(body: &str, own: &str) -> Option<(Vec<String>, String)> {
    let lines: Vec<&str> = body.lines().collect();
    let at = lines.iter().position(|line| *line == own)?;
    let mut start = at;
    while start > 0 && is_marker(lines[start - 1]) {
        start -= 1;
    }
    let mut end = at + 1;
    while end < lines.len() && is_marker(lines[end]) {
        end += 1;
    }
    let markers = lines[start..end]
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    let description: Vec<&str> = lines[end..]
        .iter()
        .skip_while(|line| line.trim().is_empty())
        .copied()
        .collect();
    Some((markers, description.join("\n")))
}

/// A proposal's body: the claims block for `claims`, a blank line, `markers` one a line, and,
/// after a blank line, `description` when it is not empty. Or why GitHub would not take it.
pub(crate) fn body(
    claims: &[String],
    markers: &[String],
    description: &str,
) -> Result<String, String> {
    let mut body = claims_block(claims);
    body.push_str("\n\n");
    body.push_str(&markers.join("\n"));
    if !description.is_empty() {
        body.push_str("\n\n");
        body.push_str(description);
    }
    let length = body.chars().count();
    if length > MAX_BODY_CHARS {
        return Err(format!(
            "the pull request's description would be {length} characters with the claims block \
             and the lines carrying the gateway's receipts, and GitHub takes at most \
             {MAX_BODY_CHARS}"
        ));
    }
    Ok(body)
}

/// Whether `text` is a git object name: 40 lowercase hex digits.
pub(crate) fn object_name(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The git object name at `pointer` in `value`, if it is one.
pub(crate) fn sha_at(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|sha| object_name(sha))
        .map(str::to_owned)
}

/// What a call needs before its first request: its team, and the gateway's receipts.
pub(crate) struct Ready {
    pub(crate) team: TeamId,
    pub(crate) receipts: Arc<dyn ReceiptAttribution>,
}

/// One entry of a tree's listing: its mode and object name.
struct Listed {
    mode: String,
    sha: String,
}

/// What a tree entry is, by its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
    Symlink,
    Submodule,
    Other,
}

impl Kind {
    fn described(self) -> &'static str {
        match self {
            Kind::File => "a regular file",
            Kind::Directory => "a directory",
            Kind::Symlink => "a symbolic link",
            Kind::Submodule => "a submodule",
            Kind::Other => "not a regular file",
        }
    }
}

/// What the tree entry of `mode` is.
fn kind(mode: &str) -> Kind {
    match mode {
        "100644" | "100755" => Kind::File,
        "040000" => Kind::Directory,
        "120000" => Kind::Symlink,
        "160000" => Kind::Submodule,
        _ => Kind::Other,
    }
}

/// What a read found.
pub(crate) enum Read {
    Found(Value),
    Missing,
}

/// A blob, as GitHub is asked to make one.
#[derive(Serialize)]
struct NewBlob<'a> {
    content: &'a str,
    encoding: &'static str,
}

/// One entry of a new tree: a regular file.
#[derive(Serialize)]
struct TreeEntry<'a> {
    path: &'a str,
    mode: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    sha: &'a str,
}

/// A tree on top of another.
#[derive(Serialize)]
struct NewTree<'a> {
    base_tree: &'a str,
    tree: Vec<TreeEntry<'a>>,
}

/// A commit with one parent.
#[derive(Serialize)]
struct NewCommit<'a> {
    message: &'a str,
    tree: &'a str,
    parents: [&'a str; 1],
}

impl GitHubConnector {
    /// The refusal of a call before any request, in the order the [module
    /// documentation](self) gives: its owner, its files' paths, then command text and the
    /// marker's text in each of `texts`, named by field. `None` when it may go on.
    pub(crate) fn refused_before_any_request(
        &self,
        owner: &str,
        files: &[File],
        texts: &[(String, &str)],
    ) -> Option<String> {
        if owner != self.organization() {
            return Some(self.other_organization(owner));
        }
        for (at, file) in files.iter().enumerate() {
            if let Some(refused) = writes::refused_path(&file.path) {
                return Some(format!(
                    "files[{at}].path \"{}\" may not be proposed: {}",
                    gateway_core::escape(&file.path, gateway_core::MAX_RENDERED),
                    refused.sentence
                ));
            }
        }
        for (field, text) in texts {
            if writes::command_text(text) {
                return Some(writes::command_text_sentence(field));
            }
        }
        for (field, text) in texts {
            if writes::holds_marker(text) {
                return Some(writes::marker_sentence(field));
            }
        }
        None
    }

    /// What `call` needs before its first request, or its outcome when it cannot have it: an
    /// entry narrowed `call`, a workload's team, and the gateway's receipts.
    #[allow(clippy::result_large_err)]
    pub(crate) fn ready(&self, call: &ToolCall) -> Result<Ready, ToolOutcome> {
        let connector = &call.tool().connector;
        if self.narrowing(connector) != Some(Narrowing::Call) {
            return Err(writes::not_narrowed(connector));
        }
        let PrincipalKind::Workload { team, .. } = &call.call().caller.principal.get().kind else {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                "the GitHub connector serves a team's workloads only: a token is asked for the \
                 caller's team, and a person has none",
            ));
        };
        let Some(receipts) = self.receipts() else {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "`{}` needs the gateway's receipts to tell which pull requests it opened for \
                     the caller, and this gateway has none to read; nothing was sent",
                    call.tool().name
                ),
            ));
        };
        Ok(Ready {
            team: team.clone(),
            receipts,
        })
    }

    /// A token for `call`'s tool, for `team`, narrowed to `repository`, with `permissions` and
    /// the revision the call was decided under; or the call's outcome, with nothing written.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn token_for(
        &self,
        call: &ToolCall,
        team: &TeamId,
        repository: &str,
        permissions: &[(&str, Access)],
    ) -> Result<Token, ToolOutcome> {
        let request = TokenRequest {
            team: team.clone(),
            tool: call.tool().name.clone(),
            repositories: vec![repository.to_owned()],
            permissions: permissions
                .iter()
                .map(|(permission, access)| ((*permission).to_owned(), *access))
                .collect::<BTreeMap<_, _>>(),
            revision: call.policy_revision().clone(),
        };
        self.token(&request).await
    }

    /// The `completed` receipt of `github__propose_change` for `call`'s issuer and subject, in
    /// `repository`, that recorded pull request `number`, if there is one: see the [module
    /// documentation](self). A store that cannot be read is the call's `error`, with nothing
    /// written.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn proposed_for(
        &self,
        receipts: &Arc<dyn ReceiptAttribution>,
        call: &ToolCall,
        repository: &str,
        number: u64,
    ) -> Result<Option<Receipt>, ToolOutcome> {
        let Ok(tool) = ToolName::parse(PROPOSE_CHANGE) else {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                "the proposal tool's name could not be read, so nothing was sent",
            ));
        };
        let query = AttributionQuery::new(
            call.call().caller.principal.get().id.clone(),
            tool,
            Resource {
                system: SYSTEM.to_owned(),
                kind: REPOSITORY.to_owned(),
                identifier: repository.to_owned(),
            },
            &VendorReference::new(format!("pull/{number}")),
        );
        match receipts.completed(&query).await {
            Ok(found) => Ok(found),
            Err(error) => {
                tracing::warn!(%error, "the gateway's receipts could not be read");
                Err(ToolOutcome::error(
                    ErrorKind::Other,
                    "the gateway's receipts could not be read to tell whether it opened the pull \
                     request, so nothing was written",
                ))
            }
        }
    }

    /// `GET {path}` with `token`: its JSON, or, when `missing_ok`, [`Read::Missing`] for a 404;
    /// otherwise the call's `error`, naming `what` and never GitHub's text. Nothing was written.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn read_json(
        &self,
        path: &str,
        token: &Token,
        what: &str,
        missing_ok: bool,
    ) -> Result<Read, ToolOutcome> {
        let (kind, why) = match self.api().get(path, token.expose()).await {
            Answered::Json(found) => return Ok(Read::Found(found)),
            Answered::Status { status, .. } if missing_ok && status == StatusCode::NOT_FOUND => {
                return Ok(Read::Missing);
            }
            Answered::Unreadable => (
                ErrorKind::Other,
                format!("GitHub's answer for {what} could not be read"),
            ),
            Answered::Unreachable => (
                ErrorKind::Other,
                format!("GitHub could not be reached to read {what}"),
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
            Answered::Status { status, .. } if status == StatusCode::FORBIDDEN => (
                ErrorKind::VendorRefusal,
                format!("GitHub refused to show {what} to this App (HTTP 403)"),
            ),
            Answered::Status { status, .. } => (
                ErrorKind::Other,
                format!("GitHub could not show {what} (HTTP {})", status.as_u16()),
            ),
        };
        Err(ToolOutcome::error(
            kind,
            format!("{why}, so nothing was written"),
        ))
    }

    /// `GET {path}` with `token`, which must answer JSON: see [`read_json`](Self::read_json).
    #[allow(clippy::result_large_err)]
    pub(crate) async fn read_found(
        &self,
        path: &str,
        token: &Token,
        what: &str,
    ) -> Result<Value, ToolOutcome> {
        match self.read_json(path, token, what, false).await? {
            Read::Found(found) => Ok(found),
            Read::Missing => Err(ToolOutcome::error(
                ErrorKind::Other,
                format!("GitHub found no {what}, so nothing was written"),
            )),
        }
    }

    /// The head commit of `branch` in the repository at `repository_path` and its tree, from
    /// `GET .../branches/{branch}`: their object names, or the call's `error`.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn branch_head(
        &self,
        repository_path: &str,
        branch: &str,
        token: &Token,
    ) -> Result<(String, String), ToolOutcome> {
        let what = format!("the branch {:?}", bounded(branch, 128).0);
        let path = format!(
            "{repository_path}/branches/{}",
            crate::create_pr::branch_path(branch)
        );
        let found = self.read_found(&path, token, &what).await?;
        match (
            sha_at(&found, "/commit/sha"),
            sha_at(&found, "/commit/commit/tree/sha"),
        ) {
            (Some(commit), Some(tree)) => Ok((commit, tree)),
            _ => Err(ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "GitHub's answer for {what} names no commit and tree, so nothing was written"
                ),
            )),
        }
    }

    /// Whether writing `files` at the commit `at`, whose tree is `tree`, of the repository at
    /// `repository_path` would change anything; or the call's outcome. Reads only.
    ///
    /// What each path is there comes from the git trees, `GET .../git/trees/{sha}`, from `tree`
    /// down each directory of the path, by each entry's mode: never from the contents API, which
    /// answers a symbolic link to a file of the repository with that file's contents. A path
    /// that is a directory (`040000`), a symbolic link (`120000`), a submodule (`160000`) or
    /// anything but a regular file (`100644` or `100755`), or that is under one that is not a
    /// directory, is `refused`; a listing GitHub says it cut short is an `error`. Then each
    /// regular file's contents there, `GET .../contents/{path}?ref={at}`, tell whether it would
    /// change.
    #[allow(clippy::result_large_err)]
    pub(crate) async fn changes(
        &self,
        repository_path: &str,
        at: &str,
        tree: &str,
        files: &[File],
        token: &Token,
    ) -> Result<bool, ToolOutcome> {
        let mut listings: BTreeMap<String, BTreeMap<String, Listed>> = BTreeMap::new();
        let mut changes = false;
        for (index, file) in files.iter().enumerate() {
            let shown = gateway_core::escape(&file.path, gateway_core::MAX_RENDERED);
            let segments: Vec<&str> = file.path.split('/').collect();
            let mut directory = tree.to_owned();
            let mut regular = false;
            for (depth, segment) in segments.iter().enumerate() {
                if !listings.contains_key(&directory) {
                    let listing = self
                        .tree_listing(repository_path, &directory, token)
                        .await?;
                    listings.insert(directory.clone(), listing);
                }
                let Some(entry) = listings
                    .get(&directory)
                    .and_then(|listing| listing.get(*segment))
                else {
                    break;
                };
                let last = depth + 1 == segments.len();
                match (kind(&entry.mode), last) {
                    (Kind::File, true) => regular = true,
                    (Kind::Directory, false) => directory.clone_from(&entry.sha),
                    (found, true) => {
                        return Err(ToolOutcome::Refused(format!(
                            "files[{index}].path \"{shown}\" is {} at {at}, and a proposal \
                             writes regular files only",
                            found.described()
                        )));
                    }
                    (found, false) => {
                        let above = gateway_core::escape(
                            &segments[..=depth].join("/"),
                            gateway_core::MAX_RENDERED,
                        );
                        return Err(ToolOutcome::Refused(format!(
                            "files[{index}].path \"{shown}\" is under \"{above}\", which is {} \
                             and not a directory at {at}, and a proposal writes regular files \
                             only",
                            found.described()
                        )));
                    }
                }
            }
            if !regular {
                changes = true;
                continue;
            }
            let encoded: Vec<String> = segments.iter().map(|s| tools::encoded(s)).collect();
            let path = format!("{repository_path}/contents/{}?ref={at}", encoded.join("/"));
            let what = format!("files[{index}].path \"{shown}\" at {at}");
            let found = self.read_found(&path, token, &what).await?;
            if !same_file(&found, &file.content) {
                changes = true;
            }
        }
        Ok(changes)
    }

    /// The entries of the tree `sha`, `GET .../git/trees/{sha}`, by name; or the call's `error`,
    /// with nothing written, for a listing that cannot be read or that GitHub cut short.
    #[allow(clippy::result_large_err)]
    async fn tree_listing(
        &self,
        repository_path: &str,
        sha: &str,
        token: &Token,
    ) -> Result<BTreeMap<String, Listed>, ToolOutcome> {
        let what = format!("the tree {sha}");
        let found = self
            .read_found(&format!("{repository_path}/git/trees/{sha}"), token, &what)
            .await?;
        if found.get("truncated").and_then(Value::as_bool) != Some(false) {
            return Err(ToolOutcome::error(
                ErrorKind::Other,
                format!(
                    "GitHub's listing of {what} is cut short or says nothing of it, so nothing \
                     was written"
                ),
            ));
        }
        let unreadable = || {
            ToolOutcome::error(
                ErrorKind::Other,
                format!("GitHub's listing of {what} could not be read, so nothing was written"),
            )
        };
        let mut listing = BTreeMap::new();
        for entry in found
            .get("tree")
            .and_then(Value::as_array)
            .ok_or_else(unreadable)?
        {
            let field = |name: &str| entry.get(name).and_then(Value::as_str);
            let (Some(name), Some(mode)) = (field("path"), field("mode")) else {
                return Err(unreadable());
            };
            let sha = field("sha").filter(|sha| object_name(sha)).unwrap_or("");
            if kind(mode) == Kind::Directory && sha.is_empty() {
                return Err(unreadable());
            }
            listing.insert(
                name.to_owned(),
                Listed {
                    mode: mode.to_owned(),
                    sha: sha.to_owned(),
                },
            );
        }
        Ok(listing)
    }

    /// Writes `files` as one commit on top of `parent`, whose tree is `base_tree`, with
    /// `message`: a blob for each, a tree on `base_tree` with each as a regular file (mode
    /// `100644`), and the commit. The commit's object name, or the call's outcome by the rule
    /// in [`crate::writes`]: the first blob is the call's first write.
    #[allow(clippy::result_large_err, clippy::too_many_arguments)]
    pub(crate) async fn commit(
        &self,
        writes: &mut Writes,
        repository_path: &str,
        token: &Token,
        files: &[File],
        base_tree: &str,
        parent: &str,
        message: &str,
    ) -> Result<String, ToolOutcome> {
        let mut blobs = Vec::with_capacity(files.len());
        for file in files {
            let encoded = base64::engine::general_purpose::STANDARD.encode(file.content.as_bytes());
            let made = writes
                .send(
                    self.api(),
                    WriteMethod::Post,
                    &format!("{repository_path}/git/blobs"),
                    &NewBlob {
                        content: &encoded,
                        encoding: "base64",
                    },
                    token.expose(),
                    "the files' contents",
                )
                .await?;
            blobs.push(sha_at(&made, "/sha").ok_or(ToolOutcome::Unknown)?);
        }
        let tree = NewTree {
            base_tree,
            tree: files
                .iter()
                .zip(&blobs)
                .map(|(file, sha)| TreeEntry {
                    path: &file.path,
                    mode: "100644",
                    kind: "blob",
                    sha,
                })
                .collect(),
        };
        let made = writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{repository_path}/git/trees"),
                &tree,
                token.expose(),
                "the tree",
            )
            .await?;
        let tree = sha_at(&made, "/sha").ok_or(ToolOutcome::Unknown)?;
        let made = writes
            .send(
                self.api(),
                WriteMethod::Post,
                &format!("{repository_path}/git/commits"),
                &NewCommit {
                    message,
                    tree: &tree,
                    parents: [parent],
                },
                token.expose(),
                "the commit",
            )
            .await?;
        sha_at(&made, "/sha").ok_or(ToolOutcome::Unknown)
    }
}

/// Whether the contents API's answer `found`, a file, holds exactly `content`. A file GitHub
/// does not answer whole, past what its contents API serves, is taken to differ.
fn same_file(found: &Value, content: &str) -> bool {
    if found.get("size").and_then(Value::as_u64) != u64::try_from(content.len()).ok() {
        return false;
    }
    if found.get("encoding").and_then(Value::as_str) != Some("base64") {
        return false;
    }
    let encoded: String = found
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .is_ok_and(|bytes| bytes == content.as_bytes())
}

/// The schema of `files`.
pub(crate) fn files_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_FILES,
        "items": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": tools::MAX_PATH_BYTES,
                    "description": "The file's path in the repository, with no leading slash. Not a CI workflow file, Atlantis configuration, AGENTS.md or a path under .agents/."
                },
                "content": {
                    "type": "string",
                    "maxLength": MAX_CONTENT_BYTES,
                    "description": "The file's whole new text."
                }
            },
            "required": ["path", "content"],
            "additionalProperties": false
        },
        "description": "The files to write, each a regular file, as a whole."
    })
}

/// The schema of `unverifiedClaims`.
pub(crate) fn claims_schema() -> Value {
    json!({
        "type": "array",
        "maxItems": MAX_CLAIMS,
        "items": {"type": "string", "maxLength": MAX_CLAIM_BYTES},
        "description": "Each claim the change rests on that was not verified, quoted above the description. Required; an empty list declares none."
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn arguments(files: Value) -> Map<String, Value> {
        json!({"files": files}).as_object().unwrap().clone()
    }

    #[test]
    fn well_formed_files_parse() {
        let parsed = files(&arguments(json!([
            {"path": "a.txt", "content": "x"},
            {"path": "dir/b.rs", "content": ""},
        ])))
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                File {
                    path: "a.txt".into(),
                    content: "x".into()
                },
                File {
                    path: "dir/b.rs".into(),
                    content: String::new()
                },
            ]
        );
        let most: Vec<Value> = (0..MAX_FILES)
            .map(|at| json!({"path": format!("f{at}"), "content": "x"}))
            .collect();
        assert_eq!(
            files(&arguments(Value::Array(most))).unwrap().len(),
            MAX_FILES
        );
        let largest = "x".repeat(MAX_CONTENT_BYTES);
        files(&arguments(json!([{"path": "a", "content": largest}]))).unwrap();
    }

    #[test]
    fn each_malformed_file_is_told_apart() {
        let too_many: Vec<Value> = (0..=MAX_FILES)
            .map(|at| json!({"path": format!("f{at}"), "content": "x"}))
            .collect();
        let too_large = "x".repeat(MAX_CONTENT_BYTES + 1);
        for (given, why) in [
            (Value::Null, "files is required"),
            (json!("a.txt"), "files must be a list"),
            (json!([]), "at least one file"),
            (Value::Array(too_many), "at most 50"),
            (json!(["a.txt"]), "files[0] must be an object"),
            (
                json!([{"path": "a", "content": "x", "mode": "100755"}]),
                "\"mode\" is not a field of files[0]",
            ),
            (json!([{"content": "x"}]), "files[0].path is required"),
            (json!([{"path": "a"}]), "files[0].content is required"),
            (
                json!([{"path": "a", "content": 7}]),
                "files[0].content must be a string",
            ),
            (
                json!([{"path": 7, "content": "x"}]),
                "files[0].path must be a string",
            ),
            (
                json!([{"path": "../x", "content": "x"}]),
                "files[0].path contains a \"..\" segment",
            ),
            (json!([{"path": "/x", "content": "x"}]), "an empty segment"),
            (json!([{"path": "a\\b", "content": "x"}]), "a backslash"),
            (
                json!([{"path": ".git/config", "content": "x"}]),
                "\".git\" segment",
            ),
            (
                json!([{"path": "sub/.GIT/hooks/x", "content": "x"}]),
                "\".git\" segment",
            ),
            (
                json!([{"path": "a", "content": too_large}]),
                "at most 1000000",
            ),
            (
                json!([{"path": "a", "content": "x"}, {"path": "a", "content": "y"}]),
                "files[1].path \"a\" is given twice",
            ),
            (
                json!([{"path": "a/b/c", "content": "x"}, {"path": "a", "content": "y"}]),
                "files[0].path \"a/b/c\" is under \"a\"",
            ),
        ] {
            let error = files(&arguments(given.clone())).unwrap_err();
            assert!(error.contains(why), "{given}: {error}");
        }
    }

    #[test]
    fn claims_are_required_strings_and_bounded() {
        let claims_of =
            |given: Value| claims(json!({"unverifiedClaims": given}).as_object().unwrap());
        assert_eq!(claims_of(json!([])).unwrap(), Vec::<String>::new());
        assert_eq!(claims_of(json!(["a", "b"])).unwrap(), vec!["a", "b"]);
        let longest = "c".repeat(MAX_CLAIM_BYTES);
        claims_of(json!([longest])).unwrap();
        let too_long = "c".repeat(MAX_CLAIM_BYTES + 1);
        let too_many: Vec<Value> = (0..=MAX_CLAIMS).map(|_| json!("c")).collect();
        for (given, why) in [
            (Value::Null, "unverifiedClaims is required"),
            (json!("claim"), "must be a list of strings"),
            (json!(["a", 7]), "unverifiedClaims[1] must be a string"),
            (json!([too_long]), "at most 1000"),
            (Value::Array(too_many), "at most 20"),
        ] {
            let error = claims_of(given.clone()).unwrap_err();
            assert!(error.contains(why), "{given}: {error}");
        }
        assert!(
            claims(&Map::new())
                .unwrap_err()
                .contains("unverifiedClaims is required")
        );
    }

    #[test]
    fn a_claims_fence_is_longer_than_any_run_of_backticks_in_it() {
        for (claim, fenced) in [
            ("plain", "```"),
            ("one ` tick", "```"),
            ("two `` ticks", "```"),
            ("```", "````"),
            ("a ```` b ``", "`````"),
            ("``````", "```````"),
        ] {
            assert_eq!(fence(claim), fenced, "{claim}");
        }
        let block = claims_block(&["the widget is ``` 1.2".into(), "plain".into()]);
        assert!(block.starts_with("> [!WARNING]\n"), "{block}");
        assert!(
            block.contains("\n\n````\nthe widget is ``` 1.2\n````"),
            "{block}"
        );
        assert!(block.ends_with("\n\n```\nplain\n```"), "{block}");
        assert!(claims_block(&[]).starts_with("> [!NOTE]\n"));
    }

    #[test]
    fn the_marker_block_is_found_by_its_own_line_and_kept_whole() {
        let own = "<!-- switchboard-receipt: r1 -->";
        let later = "<!-- switchboard-receipt: r2 -->";
        let body = format!("> [!NOTE]\n> none\n\n{own}\n{later}\n\nWhy.\n\nMore.");
        assert_eq!(
            marker_block(&body, own),
            Some((
                vec![own.to_owned(), later.to_owned()],
                "Why.\n\nMore".to_owned() + "."
            ))
        );
        // GitHub's line endings, and a block with nothing after it.
        let crlf = format!("claims\r\n\r\n{own}\r\n\r\nWhy.\r\n");
        assert_eq!(
            marker_block(&crlf, own),
            Some((vec![own.to_owned()], "Why.".to_owned()))
        );
        assert_eq!(
            marker_block(&format!("claims\n\n{later}\n{own}"), own),
            Some((vec![later.to_owned(), own.to_owned()], String::new()))
        );
        // Removed, or no longer a line of its own.
        for body in [
            "claims\n\nWhy.".to_owned(),
            format!("claims\n\n{later}\n\nWhy."),
            format!("claims\n\n see {own}\n\nWhy."),
            format!("claims\n\n{own} \n\nWhy."),
        ] {
            assert_eq!(marker_block(&body, own), None, "{body:?}");
        }
        assert!(is_marker(own));
        for line in [
            "<!-- switchboard-receipt:  -->",
            "<!-- switchboard-receipt: a b -->",
            "<!-- switchboard-receipt: r1-->",
            "<!-- Switchboard-Receipt: r1 -->",
        ] {
            assert!(!is_marker(line), "{line}");
        }
    }

    #[test]
    fn the_body_is_the_claims_the_markers_and_the_description_and_is_bounded() {
        let own = "<!-- switchboard-receipt: r1 -->".to_owned();
        let claims = vec!["the latest widget is 1.2".to_owned()];
        let sent = body(&claims, std::slice::from_ref(&own), "Why this change").unwrap();
        assert!(sent.starts_with("> [!WARNING]"), "{sent}");
        assert!(
            sent.contains("```\nthe latest widget is 1.2\n```"),
            "{sent}"
        );
        assert!(
            sent.ends_with(&format!("\n\n{own}\n\nWhy this change")),
            "{sent}"
        );
        assert_eq!(marker_block(&sent, &own).unwrap().1, "Why this change");
        let bare = body(&[], std::slice::from_ref(&own), "").unwrap();
        assert!(bare.ends_with(&format!("\n\n{own}")), "{bare}");
        let long = "d".repeat(MAX_BODY_CHARS);
        assert!(body(&[], &[own], &long).unwrap_err().contains("65536"));
    }

    #[test]
    fn a_file_is_the_same_only_when_github_shows_exactly_its_content() {
        let encoded = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
        let file = |text: &str, size: usize| json!({"type": "file", "size": size, "encoding": "base64", "content": encoded(text)});
        assert!(same_file(&file("hello\n", 6), "hello\n"));
        let wrapped =
            json!({"type": "file", "size": 6, "encoding": "base64", "content": "aGVs\nbG8K\n"});
        assert!(same_file(&wrapped, "hello\n"));
        assert!(!same_file(&file("hello\n", 6), "hellO\n"));
        assert!(!same_file(&file("hello\n", 6), "hello"));
        assert!(!same_file(
            &json!({"type": "file", "size": 6, "encoding": "none", "content": ""}),
            "hello\n"
        ));
        assert!(object_name(&"a".repeat(40)));
        assert!(!object_name(&"A".repeat(40)));
        assert!(!object_name(&"a".repeat(39)));
    }
}
