//! The fake's git data, for the proposal tools ([`crate::propose`], [`crate::amend`]).
//!
//! A test gives a repository git data with [`FakeRest::git_repository`]: a default branch whose
//! head is one commit holding the files given. From then on the fake answers, for that
//! repository only, as GitHub does:
//!
//! - `GET /repos/{owner}/{repo}`: its name and default branch. No permission is needed.
//! - `GET .../branches/{branch}`: the branch's head commit and that commit's tree.
//! - `GET .../git/ref/heads/{branch}`: the branch's ref, or a 404.
//! - `GET .../contents/{path}?ref={branch or commit}`: at that commit, the default branch's head
//!   if none is given, a file with its content base64-encoded, a directory's listing, a
//!   symbolic link or a submodule; a 404 for a path that is none of them.
//! - `POST .../git/blobs`, base64 or UTF-8: a blob.
//! - `POST .../git/trees`: a tree on `base_tree`, each entry a blob of a known object name at
//!   mode `100644`. A path under a file, or one naming a directory, is refused with a 422, as
//!   git refuses it.
//! - `POST .../git/commits`: a commit of a known tree and known parents.
//! - `POST .../git/refs`: a new branch, `refs/heads/...`, at a known commit; a 422 for one that
//!   exists.
//! - `PATCH .../git/refs/heads/{branch}`: the branch moved to a known commit, and, unless
//!   `force` is true, only forward: a 422 when its head is not an ancestor of the commit.
//!
//! Reads need `contents` at `read` or above, and writes `contents: write`. Each write meets the
//! next fault given ([`super::Fault`]), as the pull request writes do. The fake answers no
//! `DELETE`. Object names are 40 lowercase hex digits, from a count, not from the content: two
//! blobs of one content have two names, which no tool here relies on either way.
//!
//! A test reads the git data back ([`FakeRest::git_head`], [`FakeRest::git_file`],
//! [`FakeRest::git_commit`]), and changes it as someone else might, by a commit on top of a
//! branch ([`FakeRest::git_push`]), a new branch ([`FakeRest::git_branch`]), or a symbolic link
//! or submodule on the default branch ([`FakeRest::git_special`]).

use std::collections::BTreeMap;

use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use key_custodian::fake::IssuedToken;
use serde_json::{Value, json};

use super::writes::{faulted, may};
use super::{FakeRest, Shared, error, lock, percent_decode, query_value};

/// What a path in a tree is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Special {
    /// A symbolic link to this target.
    Symlink(String),
    /// A submodule.
    Submodule,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    File(String),
    Special(Special),
}

#[derive(Clone, Debug)]
struct Commit {
    tree: String,
    parents: Vec<String>,
    message: String,
}

#[derive(Default)]
struct Repo {
    default: String,
    blobs: BTreeMap<String, Vec<u8>>,
    /// Each tree, as the path of every entry in it, directories implied.
    trees: BTreeMap<String, BTreeMap<String, Entry>>,
    commits: BTreeMap<String, Commit>,
    /// Each branch's head.
    refs: BTreeMap<String, String>,
    count: u64,
}

impl Repo {
    /// A new object name, of the kind `kind`.
    fn name(&mut self, kind: u8) -> String {
        self.count += 1;
        format!("{kind:02x}{:038x}", self.count)
    }

    fn blob(&mut self, bytes: Vec<u8>) -> String {
        let sha = self.name(0xb0);
        self.blobs.insert(sha.clone(), bytes);
        sha
    }

    fn tree(&mut self, entries: BTreeMap<String, Entry>) -> String {
        let sha = self.name(0x70);
        self.trees.insert(sha.clone(), entries);
        sha
    }

    fn commit(&mut self, tree: String, parents: Vec<String>, message: &str) -> String {
        let sha = self.name(0xc0);
        self.commits.insert(
            sha.clone(),
            Commit {
                tree,
                parents,
                message: message.to_owned(),
            },
        );
        sha
    }

    /// The commit `reference` names: a branch, a commit's object name, or, when `None`, the
    /// default branch.
    fn resolve(&self, reference: Option<&str>) -> Option<String> {
        let reference = reference.unwrap_or(&self.default);
        if self.commits.contains_key(reference) {
            return Some(reference.to_owned());
        }
        self.refs.get(reference).cloned()
    }

    fn tree_of(&self, commit: &str) -> Option<&BTreeMap<String, Entry>> {
        self.trees.get(&self.commits.get(commit)?.tree)
    }

    /// Commits `changes` on top of `branch`, made from the default branch's head if it does not
    /// exist, and moves it there.
    fn commit_on(&mut self, branch: &str, changes: Vec<(String, Entry)>, message: &str) -> String {
        let parent = self
            .refs
            .get(branch)
            .or_else(|| self.refs.get(&self.default))
            .cloned()
            .unwrap_or_default();
        let mut entries = self.tree_of(&parent).cloned().unwrap_or_default();
        entries.extend(changes);
        let tree = self.tree(entries);
        let parents = if parent.is_empty() {
            Vec::new()
        } else {
            vec![parent]
        };
        let commit = self.commit(tree, parents, message);
        self.refs.insert(branch.to_owned(), commit.clone());
        commit
    }

    /// Whether `ancestor` is `commit` or one of its ancestors.
    fn descends(&self, commit: &str, ancestor: &str) -> bool {
        let mut stack = vec![commit.to_owned()];
        while let Some(at) = stack.pop() {
            if at == ancestor {
                return true;
            }
            if let Some(found) = self.commits.get(&at) {
                stack.extend(found.parents.iter().cloned());
            }
        }
        false
    }
}

/// The git data of each repository given some.
#[derive(Default)]
pub(super) struct Content {
    repos: BTreeMap<String, Repo>,
}

impl FakeRest {
    /// Gives `repo` git data: the default branch `default`, whose head is one commit holding
    /// `files`, each a path and its text.
    pub fn git_repository(&self, repo: &str, default: &str, files: &[(&str, &str)]) {
        let mut found = Repo {
            default: default.to_owned(),
            ..Repo::default()
        };
        let changes = files
            .iter()
            .map(|(path, text)| {
                let blob = found.blob(text.as_bytes().to_vec());
                ((*path).to_owned(), Entry::File(blob))
            })
            .collect();
        found.commit_on(default, changes, "Initial commit");
        lock(&self.shared.git).repos.insert(repo.to_owned(), found);
    }

    /// Commits `files` on top of `branch` of `repo`, as someone else pushing; its object name.
    pub fn git_push(&self, repo: &str, branch: &str, files: &[(&str, &str)]) -> String {
        let mut git = lock(&self.shared.git);
        let found = git
            .repos
            .get_mut(repo)
            .expect("the repository has git data");
        let changes = files
            .iter()
            .map(|(path, text)| {
                let blob = found.blob(text.as_bytes().to_vec());
                ((*path).to_owned(), Entry::File(blob))
            })
            .collect();
        found.commit_on(branch, changes, "Pushed by someone else")
    }

    /// Makes the branch `branch` of `repo` at the default branch's head, as someone else might.
    pub fn git_branch(&self, repo: &str, branch: &str) {
        let mut git = lock(&self.shared.git);
        let found = git
            .repos
            .get_mut(repo)
            .expect("the repository has git data");
        let head = found.refs[&found.default].clone();
        found.refs.insert(branch.to_owned(), head);
    }

    /// Commits `special` at `path` on the default branch of `repo`.
    pub fn git_special(&self, repo: &str, path: &str, special: Special) {
        let mut git = lock(&self.shared.git);
        let found = git
            .repos
            .get_mut(repo)
            .expect("the repository has git data");
        let default = found.default.clone();
        found.commit_on(
            &default,
            vec![(path.to_owned(), Entry::Special(special))],
            "Add a special entry",
        );
    }

    /// The head of `branch` of `repo`, if it exists.
    pub fn git_head(&self, repo: &str, branch: &str) -> Option<String> {
        lock(&self.shared.git)
            .repos
            .get(repo)?
            .refs
            .get(branch)
            .cloned()
    }

    /// Every branch of `repo` and its head.
    pub fn git_branches(&self, repo: &str) -> BTreeMap<String, String> {
        lock(&self.shared.git)
            .repos
            .get(repo)
            .map(|found| found.refs.clone())
            .unwrap_or_default()
    }

    /// The text of the file at `path` on `branch` of `repo`, if there is one.
    pub fn git_file(&self, repo: &str, branch: &str, path: &str) -> Option<String> {
        let git = lock(&self.shared.git);
        let found = git.repos.get(repo)?;
        let head = found.refs.get(branch)?;
        match found.tree_of(head)?.get(path)? {
            Entry::File(blob) => String::from_utf8(found.blobs.get(blob)?.clone()).ok(),
            Entry::Special(_) => None,
        }
    }

    /// The commit `sha` of `repo`: `{parents, message}`.
    pub fn git_commit(&self, repo: &str, sha: &str) -> Option<Value> {
        let git = lock(&self.shared.git);
        let commit = git.repos.get(repo)?.commits.get(sha)?;
        Some(json!({"parents": commit.parents, "message": commit.message}))
    }
}

/// The head of `branch` of `repo`, if the repository has git data and the branch exists.
pub(super) fn head(shared: &Shared, repo: &str, branch: &str) -> Option<String> {
    lock(&shared.git).repos.get(repo)?.refs.get(branch).cloned()
}

/// What a path under a repository with git data names.
enum Endpoint {
    Repository,
    Branch(String),
    Ref(String),
    Contents(String),
    Blobs,
    Trees,
    Commits,
    Refs,
    MoveRef(String),
}

fn route(method: &Method, tail: &str) -> Option<Endpoint> {
    let decoded = |text: &str| percent_decode(text);
    Some(match (method, tail) {
        (&Method::GET, "") => Endpoint::Repository,
        (&Method::GET, _) if tail.starts_with("branches/") => {
            Endpoint::Branch(decoded(tail.strip_prefix("branches/")?)?)
        }
        (&Method::GET, _) if tail.starts_with("git/ref/heads/") => {
            Endpoint::Ref(decoded(tail.strip_prefix("git/ref/heads/")?)?)
        }
        (&Method::GET, _) if tail.starts_with("contents/") => {
            Endpoint::Contents(decoded(tail.strip_prefix("contents/")?)?)
        }
        (&Method::POST, "git/blobs") => Endpoint::Blobs,
        (&Method::POST, "git/trees") => Endpoint::Trees,
        (&Method::POST, "git/commits") => Endpoint::Commits,
        (&Method::POST, "git/refs") => Endpoint::Refs,
        (&Method::PATCH, _) if tail.starts_with("git/refs/heads/") => {
            Endpoint::MoveRef(decoded(tail.strip_prefix("git/refs/heads/")?)?)
        }
        _ => return None,
    })
}

/// The answer to a request of a repository with git data, or `None` for any other.
pub(super) async fn answer(
    shared: &Shared,
    issued: &IssuedToken,
    method: &Method,
    uri: &Uri,
    token: Option<&str>,
    body: &[u8],
) -> Option<Response> {
    let rest = uri.path().strip_prefix("/repos/")?;
    let mut parts = rest.splitn(3, '/');
    let owner = parts.next()?;
    let repo = parts.next()?.to_owned();
    let tail = parts.next().unwrap_or("");
    if !lock(&shared.git).repos.contains_key(&repo) {
        return None;
    }
    let endpoint = route(method, tail)?;
    // GitHub does not say a repository exists to a token that cannot see it.
    if owner != shared.account || !issued.repositories.contains(&repo) {
        return Some(error(StatusCode::NOT_FOUND, "Not Found", token));
    }
    let write = *method != Method::GET;
    let needs: &[&str] = match endpoint {
        Endpoint::Repository => &[],
        _ => &["contents"],
    };
    if !needs.is_empty() && !may(issued, needs, write) {
        return Some(error(
            StatusCode::FORBIDDEN,
            "Resource not accessible by integration",
            token,
        ));
    }
    if !write {
        let git = lock(&shared.git);
        let found = git.repos.get(&repo)?;
        let reference = query_value(uri.query().unwrap_or(""), "ref");
        return Some(read(
            found,
            owner,
            &repo,
            endpoint,
            reference.as_deref(),
            token,
        ));
    }
    let Ok(sent) = serde_json::from_slice::<Value>(body) else {
        return Some(error(
            StatusCode::BAD_REQUEST,
            "Problems parsing JSON",
            token,
        ));
    };
    Some(
        faulted(shared, token, || {
            let mut git = lock(&shared.git);
            let found = git
                .repos
                .get_mut(&repo)
                .ok_or_else(|| error(StatusCode::NOT_FOUND, "Not Found", token))?;
            written(found, endpoint, &sent)
                .map_err(|why| error(StatusCode::UNPROCESSABLE_ENTITY, why, token))
        })
        .await,
    )
}

/// A read's answer.
fn read(
    found: &Repo,
    owner: &str,
    repo: &str,
    endpoint: Endpoint,
    reference: Option<&str>,
    token: Option<&str>,
) -> Response {
    let not_found = || error(StatusCode::NOT_FOUND, "Not Found", token);
    let answer = match endpoint {
        Endpoint::Repository => Some(json!({
            "name": repo,
            "full_name": format!("{owner}/{repo}"),
            "default_branch": found.default,
        })),
        Endpoint::Branch(branch) => found.refs.get(&branch).map(|head| {
            let tree = &found.commits[head].tree;
            json!({"name": branch, "commit": {"sha": head, "commit": {"tree": {"sha": tree}}}})
        }),
        Endpoint::Ref(branch) => found.refs.get(&branch).map(|head| {
            json!({"ref": format!("refs/heads/{branch}"), "object": {"type": "commit", "sha": head}})
        }),
        Endpoint::Contents(path) => found
            .resolve(reference)
            .and_then(|commit| found.tree_of(&commit))
            .and_then(|tree| contents(found, tree, &path)),
        _ => None,
    };
    match answer {
        Some(answer) => (StatusCode::OK, answer.to_string()).into_response(),
        None => not_found(),
    }
}

/// What the contents API answers for `path` in `tree`.
fn contents(found: &Repo, tree: &BTreeMap<String, Entry>, path: &str) -> Option<Value> {
    if let Some(entry) = tree.get(path) {
        return Some(match entry {
            Entry::File(blob) => {
                let bytes = found.blobs.get(blob)?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                let wrapped: Vec<String> = encoded
                    .as_bytes()
                    .chunks(60)
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect();
                json!({
                    "type": "file",
                    "path": path,
                    "sha": blob,
                    "size": bytes.len(),
                    "encoding": "base64",
                    "content": wrapped.join("\n"),
                })
            }
            Entry::Special(Special::Symlink(target)) => {
                json!({"type": "symlink", "path": path, "target": target})
            }
            Entry::Special(Special::Submodule) => json!({"type": "submodule", "path": path}),
        });
    }
    let prefix = format!("{path}/");
    let listed: Vec<Value> = tree
        .keys()
        .filter_map(|key| key.strip_prefix(&prefix))
        .map(|rest| match rest.split_once('/') {
            Some((name, _)) => {
                json!({"name": name, "path": format!("{prefix}{name}"), "type": "dir"})
            }
            None => json!({"name": rest, "path": format!("{prefix}{rest}"), "type": "file"}),
        })
        .collect();
    (!listed.is_empty()).then_some(Value::Array(listed))
}

/// Makes the write `endpoint` names with `sent`: its status and answer, or why it is refused.
fn written(
    found: &mut Repo,
    endpoint: Endpoint,
    sent: &Value,
) -> Result<(StatusCode, Value), &'static str> {
    let text = |pointer: &str| sent.pointer(pointer).and_then(Value::as_str);
    match endpoint {
        Endpoint::Blobs => {
            let content = text("/content").ok_or("Invalid request")?;
            let bytes = match text("/encoding").unwrap_or("utf-8") {
                "base64" => base64::engine::general_purpose::STANDARD
                    .decode(content)
                    .map_err(|_| "Invalid base64")?,
                "utf-8" => content.as_bytes().to_vec(),
                _ => return Err("Invalid encoding"),
            };
            let sha = found.blob(bytes);
            Ok((StatusCode::CREATED, json!({"sha": sha})))
        }
        Endpoint::Trees => {
            let base = text("/base_tree").ok_or("Invalid request")?;
            let mut entries = found.trees.get(base).ok_or("Invalid base_tree")?.clone();
            for entry in sent
                .get("tree")
                .and_then(Value::as_array)
                .ok_or("Invalid request")?
            {
                let path = entry
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or("Invalid tree")?;
                let blob = entry
                    .get("sha")
                    .and_then(Value::as_str)
                    .ok_or("Invalid tree")?;
                let regular = entry.get("mode").and_then(Value::as_str) == Some("100644")
                    && entry.get("type").and_then(Value::as_str) == Some("blob");
                if !regular || !found.blobs.contains_key(blob) {
                    return Err("Invalid tree");
                }
                let mut above = path;
                while let Some((parent, _)) = above.rsplit_once('/') {
                    if entries.contains_key(parent) {
                        return Err("GitRPC::BadObjectState");
                    }
                    above = parent;
                }
                let prefix = format!("{path}/");
                if entries.keys().any(|key| key.starts_with(&prefix)) {
                    return Err("GitRPC::BadObjectState");
                }
                entries.insert(path.to_owned(), Entry::File(blob.to_owned()));
            }
            let sha = found.tree(entries);
            Ok((StatusCode::CREATED, json!({"sha": sha})))
        }
        Endpoint::Commits => {
            let tree = text("/tree").ok_or("Invalid request")?;
            let message = text("/message").ok_or("Invalid request")?;
            let parents: Vec<String> = sent
                .get("parents")
                .and_then(Value::as_array)
                .ok_or("Invalid request")?
                .iter()
                .map(|parent| parent.as_str().map(str::to_owned))
                .collect::<Option<_>>()
                .ok_or("Invalid parents")?;
            if !found.trees.contains_key(tree)
                || parents
                    .iter()
                    .any(|parent| !found.commits.contains_key(parent))
            {
                return Err("Invalid tree or parents");
            }
            let sha = found.commit(tree.to_owned(), parents.clone(), message);
            Ok((
                StatusCode::CREATED,
                json!({"sha": sha, "tree": {"sha": tree}, "parents": parents.iter().map(|parent| json!({"sha": parent})).collect::<Vec<_>>(), "message": message}),
            ))
        }
        Endpoint::Refs => {
            let name = text("/ref").ok_or("Invalid request")?;
            let sha = text("/sha").ok_or("Invalid request")?;
            let branch = name.strip_prefix("refs/heads/").ok_or("Invalid ref")?;
            if !found.commits.contains_key(sha) {
                return Err("Object does not exist");
            }
            if found.refs.contains_key(branch) {
                return Err("Reference already exists");
            }
            found.refs.insert(branch.to_owned(), sha.to_owned());
            Ok((
                StatusCode::CREATED,
                json!({"ref": name, "object": {"type": "commit", "sha": sha}}),
            ))
        }
        Endpoint::MoveRef(branch) => {
            let sha = text("/sha").ok_or("Invalid request")?;
            let force = sent.get("force").and_then(Value::as_bool).unwrap_or(false);
            let head = found.refs.get(&branch).ok_or("Reference does not exist")?;
            if !found.commits.contains_key(sha) {
                return Err("Object does not exist");
            }
            if !force && !found.descends(sha, head) {
                return Err("Update is not a fast forward");
            }
            found.refs.insert(branch.clone(), sha.to_owned());
            Ok((
                StatusCode::OK,
                json!({"ref": format!("refs/heads/{branch}"), "object": {"type": "commit", "sha": sha}}),
            ))
        }
        Endpoint::Repository | Endpoint::Branch(_) | Endpoint::Ref(_) | Endpoint::Contents(_) => {
            Err("Not a write")
        }
    }
}
