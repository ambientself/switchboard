//! The fake's endpoints for the write tools ([`crate::create_pr`]) and the lookup by marker
//! ([`crate::lookup`]).
//!
//! - `POST /repos/{owner}/{repo}/pulls` opens a pull request, numbered from 1 in each
//!   repository, by the author a test sets ([`FakeRest::author`]), with the title, head, base,
//!   body and `draft` it was sent. A token needs `pull_requests: write`. It is then served by
//!   `GET /repos/{owner}/{repo}/pulls/{n}`, as any pull request is.
//! - `GET /repos/{owner}/{repo}/pulls` lists a repository's pull requests, with `state`
//!   (`open`, `closed` or `all`; `open` unless given), `head` (`owner:branch`), `sort`
//!   (`created` or `updated`), `direction` (`asc` or `desc`), `per_page` (30 unless given, 100
//!   at most) and `page`. A token needs `pull_requests` at `read` or above.
//! - `PATCH /repos/{owner}/{repo}/pulls/{n}` changes the title, body or state it is sent,
//!   and nothing else, as the most recently updated from then on. A token needs
//!   `pull_requests: write`. A test changes a pull request as a person or GitHub might with
//!   [`FakeRest::set_pull`]: its state, draft flag, merge, author or head.
//! - `GET /repos/{owner}/{repo}/compare/{base}...{head}` answers what a test set for the
//!   repository ([`FakeRest::compare_files`], [`FakeRest::comparison`]), whatever the branches,
//!   and a 404 when it set nothing. A token needs `contents` at `read` or above.
//!
//! A pull request names its head's and base's repository, its head's commit when the
//! repository has git data (`git`), and `merged_at`, `null` until a test merges it.
//!
//! The next write can be given a fault ([`FakeRest::fault_next_write`], see [`Fault`]): an
//! answer that applies nothing, an answer after applying, a connection closed with no answer
//! after applying, a 201 broken off or not JSON after applying, or applying late. And the fake can be told to stop taking connections once it has answered
//! the next comparison ([`FakeRest::close_after_next_compare`]), so the write after it cannot
//! connect.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hyper::body::{Bytes, Frame};
use key_custodian::fake::IssuedToken;
use serde_json::{Value, json};

use super::{FakeRest, Shared, error, lock, query_value};

/// What the fake does with the next write it is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Answers this status and applies nothing.
    Status(u16),
    /// Applies the write, then answers this status.
    AppliedThen(u16),
    /// Applies the write, then closes the connection before any of an answer is sent: the
    /// client's request fails with no answer.
    AppliedThenClosed,
    /// Applies the write, sends a 201's head and the start of the pull request's JSON, then
    /// breaks the connection off: the client has the 201 and cannot read its body.
    AppliedThenBrokenOff,
    /// Applies the write, then answers 201 with a whole body that is not JSON.
    AppliedThenNotJson,
    /// Waits this long, then applies the write and answers as GitHub does.
    Late(Duration),
}

/// What the write endpoints hold.
pub(super) struct Content {
    /// Each repository's pull requests opened through the fake, by number.
    opened: BTreeMap<String, BTreeMap<u64, Value>>,
    /// When each pull request was last updated, by the fake's own count.
    updated: BTreeMap<(String, u64), u64>,
    /// The fake's count of updates.
    clock: u64,
    /// The login every pull request is opened by.
    author: String,
    /// What a comparison in each repository answers.
    comparisons: BTreeMap<String, Value>,
    /// The faults the next writes meet, in order.
    faults: VecDeque<Fault>,
}

impl Default for Content {
    fn default() -> Self {
        Self {
            opened: BTreeMap::new(),
            updated: BTreeMap::new(),
            clock: 0,
            author: "switchboard-test-app[bot]".into(),
            comparisons: BTreeMap::new(),
            faults: VecDeque::new(),
        }
    }
}

impl FakeRest {
    /// Opens every pull request from here on as `login`.
    pub fn author(&self, login: &str) {
        lock(&self.shared.writes).author = login.to_owned();
    }

    /// Answers every comparison in `repo` with these changed files, as GitHub lists them.
    pub fn compare_files(&self, repo: &str, files: &[&str]) {
        let files: Vec<Value> = files
            .iter()
            .map(|name| json!({"filename": name, "status": "modified"}))
            .collect();
        self.comparison(repo, json!({"status": "ahead", "files": files}));
    }

    /// Answers every comparison in `repo` with `answer`.
    pub fn comparison(&self, repo: &str, answer: Value) {
        lock(&self.shared.writes)
            .comparisons
            .insert(repo.to_owned(), answer);
    }

    /// Gives the next write `fault`, after any given before it.
    pub fn fault_next_write(&self, fault: Fault) {
        lock(&self.shared.writes).faults.push_back(fault);
    }

    /// Stops taking connections once the next comparison is answered: a request after it
    /// cannot connect.
    pub fn close_after_next_compare(&self) {
        self.shared
            .close_after_compare
            .store(true, Ordering::SeqCst);
    }

    /// The pull requests opened in `repo`, in order.
    pub fn opened(&self, repo: &str) -> Vec<Value> {
        lock(&self.shared.writes)
            .opened
            .get(repo)
            .map(|opened| opened.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Opens a pull request in `repo` as if someone else had, with `body`, the most recently
    /// updated from here on; its number.
    pub fn open_elsewhere(&self, repo: &str, body: &str) -> u64 {
        let mut content = lock(&self.shared.writes);
        let author = "someone-else".to_owned();
        let pull = json!({"title": "elsewhere", "head": "x", "base": "main", "body": body, "draft": false});
        open(
            &mut content,
            &self.shared.account,
            repo,
            &pull,
            &author,
            None,
        )
    }

    /// Changes pull request `number` of `repo`, opened through the fake, as a person or GitHub
    /// might: each field of `changes` replaces the pull request's, an object's fields one by
    /// one, such as `{"state": "closed"}`, `{"draft": false}`, `{"merged_at": "..."}`,
    /// `{"user": {"login": "someone"}}` or `{"body": "..."}`. It is the most recently updated
    /// from then on.
    pub fn set_pull(&self, repo: &str, number: u64, changes: Value) {
        let mut content = lock(&self.shared.writes);
        content.clock += 1;
        let clock = content.clock;
        content.updated.insert((repo.to_owned(), number), clock);
        let pull = content
            .opened
            .get_mut(repo)
            .and_then(|opened| opened.get_mut(&number))
            .expect("the pull request was opened through the fake");
        merge(pull, &changes);
        let changed = pull.clone();
        drop(content);
        lock(&self.shared.content)
            .pulls
            .insert((repo.to_owned(), number), changed);
    }
}

/// `changes` written over `target`, an object's fields one by one.
fn merge(target: &mut Value, changes: &Value) {
    match (target, changes) {
        (Value::Object(target), Value::Object(changes)) => {
            for (name, change) in changes {
                merge(target.entry(name.clone()).or_insert(Value::Null), change);
            }
        }
        (target, change) => *target = change.clone(),
    }
}

/// Opens `pull` in `repo` as `author`, and its number.
fn open(
    content: &mut Content,
    account: &str,
    repo: &str,
    pull: &Value,
    author: &str,
    head_sha: Option<String>,
) -> u64 {
    let number = content
        .opened
        .get(repo)
        .and_then(|opened| opened.keys().next_back())
        .map_or(1, |last| last + 1);
    content.clock += 1;
    let made = json!({
        "number": number,
        "state": "open",
        "title": pull["title"],
        "body": pull["body"],
        "draft": pull["draft"],
        "html_url": format!("https://github.example.test/{account}/{repo}/pull/{number}"),
        "head": {
            "ref": pull["head"],
            "label": format!("{account}:{}", pull["head"].as_str().unwrap_or("")),
            "sha": head_sha,
            "repo": {"full_name": format!("{account}/{repo}")},
        },
        "base": {"ref": pull["base"], "repo": {"full_name": format!("{account}/{repo}")}},
        "user": {"login": author},
        "merged_at": null,
    });
    content
        .opened
        .entry(repo.to_owned())
        .or_default()
        .insert(number, made);
    content
        .updated
        .insert((repo.to_owned(), number), content.clock);
    number
}

/// What a path under the repository names.
enum Endpoint {
    Pulls,
    Pull(u64),
    Compare,
}

/// The answer to a request one of these endpoints serves, or `None` for any other.
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
    let endpoint = if tail == "pulls" {
        Endpoint::Pulls
    } else if let Some(number) = tail
        .strip_prefix("pulls/")
        .and_then(|number| number.parse::<u64>().ok())
        .filter(|_| *method == Method::PATCH)
    {
        Endpoint::Pull(number)
    } else if tail.starts_with("compare/") && *method == Method::GET {
        Endpoint::Compare
    } else {
        return None;
    };
    // GitHub does not say a repository exists to a token that cannot see it.
    if owner != shared.account || !issued.repositories.contains(&repo) {
        return Some(error(StatusCode::NOT_FOUND, "Not Found", token));
    }
    let (permissions, write): (&[&str], bool) = match (&endpoint, method) {
        (Endpoint::Pulls, &Method::POST) => (&["pull_requests"], true),
        (Endpoint::Pulls, &Method::GET) => (&["pull_requests"], false),
        (Endpoint::Pull(_), &Method::PATCH) => (&["pull_requests"], true),
        (Endpoint::Compare, _) => (&["contents"], false),
        _ => return Some(error(StatusCode::NOT_FOUND, "Not Found", token)),
    };
    if !may(issued, permissions, write) {
        return Some(error(
            StatusCode::FORBIDDEN,
            "Resource not accessible by integration",
            token,
        ));
    }
    let query = uri.query().unwrap_or("");
    Some(match endpoint {
        Endpoint::Compare => compare(shared, &repo, token),
        Endpoint::Pulls if write => create(shared, &repo, body, token).await,
        Endpoint::Pulls => list(shared, &repo, query),
        Endpoint::Pull(number) => edit(shared, &repo, number, body, token).await,
    })
}

/// Whether `issued` may use `permissions`: at `write` when `write`, or at `read` or above. A
/// token asked for with no permissions has every one the installation has.
pub(super) fn may(issued: &IssuedToken, permissions: &[&str], write: bool) -> bool {
    match &issued.asked_permissions {
        None => true,
        Some(asked) => permissions.iter().any(|permission| {
            asked
                .get(*permission)
                .is_some_and(|level| level == "write" || (!write && level == "read"))
        }),
    }
}

fn compare(shared: &Shared, repo: &str, token: Option<&str>) -> Response {
    let answer = lock(&shared.writes).comparisons.get(repo).cloned();
    if shared.close_after_compare.swap(false, Ordering::SeqCst) {
        shared.close.notify_one();
    }
    match answer {
        Some(answer) => (StatusCode::OK, answer.to_string()).into_response(),
        None => error(StatusCode::NOT_FOUND, "Not Found", token),
    }
}

async fn create(shared: &Shared, repo: &str, body: &[u8], token: Option<&str>) -> Response {
    let Ok(pull) = serde_json::from_slice::<Value>(body) else {
        return error(StatusCode::BAD_REQUEST, "Problems parsing JSON", token);
    };
    let complete = ["title", "head", "base"]
        .iter()
        .all(|field| pull.get(*field).is_some_and(Value::is_string));
    if !complete {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Validation Failed", token);
    }
    let head_sha = pull
        .get("head")
        .and_then(Value::as_str)
        .and_then(|head| super::git::head(shared, repo, head));
    faulted(shared, token, || {
        let (number, made) = {
            let mut content = lock(&shared.writes);
            let author = content.author.clone();
            let number = open(
                &mut content,
                &shared.account,
                repo,
                &pull,
                &author,
                head_sha,
            );
            (number, content.opened[repo][&number].clone())
        };
        // Served by `GET /repos/{owner}/{repo}/pulls/{n}` from here on.
        lock(&shared.content)
            .pulls
            .insert((repo.to_owned(), number), made.clone());
        Ok((StatusCode::CREATED, made))
    })
    .await
}

/// `PATCH` of pull request `number` of `repo`, opened through the fake: its title, body and
/// state, as sent, and nothing else.
async fn edit(
    shared: &Shared,
    repo: &str,
    number: u64,
    body: &[u8],
    token: Option<&str>,
) -> Response {
    let Ok(sent) = serde_json::from_slice::<Value>(body) else {
        return error(StatusCode::BAD_REQUEST, "Problems parsing JSON", token);
    };
    let Some(sent) = sent.as_object() else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Validation Failed", token);
    };
    let changes: serde_json::Map<String, Value> = sent
        .iter()
        .filter(|(name, _)| ["title", "body", "state"].contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    faulted(shared, token, || {
        let mut content = lock(&shared.writes);
        content.clock += 1;
        let clock = content.clock;
        let Some(pull) = content
            .opened
            .get_mut(repo)
            .and_then(|opened| opened.get_mut(&number))
        else {
            return Err(error(StatusCode::NOT_FOUND, "Not Found", token));
        };
        merge(pull, &Value::Object(changes));
        let changed = pull.clone();
        content.updated.insert((repo.to_owned(), number), clock);
        drop(content);
        lock(&shared.content)
            .pulls
            .insert((repo.to_owned(), number), changed.clone());
        Ok((StatusCode::OK, changed))
    })
    .await
}

/// A write's answer, meeting the next fault given, if any (see [`Fault`]): `apply` makes the
/// write and gives its status and answer, or the answer of a write it refused.
pub(super) async fn faulted(
    shared: &Shared,
    token: Option<&str>,
    apply: impl FnOnce() -> Result<(StatusCode, Value), Response>,
) -> Response {
    let fault = lock(&shared.writes).faults.pop_front();
    if let Some(Fault::Status(status)) = fault {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return error(status, "failed", token);
    }
    if let Some(Fault::Late(wait)) = fault {
        tokio::time::sleep(wait).await;
    }
    let (status, made) = match apply() {
        Ok(made) => made,
        Err(refused) => return refused,
    };
    match fault {
        Some(Fault::AppliedThen(status)) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error(status, "failed", token)
        }
        Some(Fault::AppliedThenClosed) => Response::builder()
            .status(status)
            .body(Body::new(Closed))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Some(Fault::AppliedThenBrokenOff) => Response::builder()
            .status(status)
            .body(Body::new(BrokenOff::default()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Some(Fault::AppliedThenNotJson) => (status, "<html>created</html>").into_response(),
        _ => (status, made.to_string()).into_response(),
    }
}

/// A body that fails when first asked for a frame. hyper's server writes an answer's head into
/// its buffer and sends it only when it flushes, which it does not do before a body's error ends
/// the connection: so nothing of the answer is sent, and the client sees the connection close.
struct Closed;

impl hyper::body::Body for Closed {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("closed"))))
    }
}

/// A body that sends the start of a pull request's JSON, then waits once, so that hyper flushes
/// the head and that start to the client, and then fails, which breaks the connection off
/// before the answer ends.
#[derive(Default)]
struct BrokenOff {
    polls: u8,
}

impl hyper::body::Body for BrokenOff {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.polls += 1;
        match self.polls {
            1 => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"{\"number\":"))))),
            2 => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            _ => Poll::Ready(Some(Err(std::io::Error::other("broken off")))),
        }
    }
}

fn list(shared: &Shared, repo: &str, query: &str) -> Response {
    let content = lock(&shared.writes);
    let state = query_value(query, "state").unwrap_or_else(|| "open".into());
    let head = query_value(query, "head");
    let by_updated = query_value(query, "sort").as_deref() == Some("updated");
    let ascending = query_value(query, "direction").as_deref() == Some("asc");
    let number = |name: &str, default: usize| {
        query_value(query, name)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    };
    let per_page = number("per_page", 30).clamp(1, 100);
    let page = number("page", 1).max(1);
    let mut pulls: Vec<(u64, Value)> = content
        .opened
        .get(repo)
        .map(|opened| {
            opened
                .iter()
                .map(|(number, pull)| {
                    let updated = content
                        .updated
                        .get(&(repo.to_owned(), *number))
                        .copied()
                        .unwrap_or(0);
                    (if by_updated { updated } else { *number }, pull.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    pulls.retain(|(_, pull)| {
        (state == "all" || pull["state"] == state.as_str())
            && head
                .as_deref()
                .is_none_or(|head| pull["head"]["label"] == head)
    });
    pulls.sort_by_key(|(key, _)| *key);
    if !ascending {
        pulls.reverse();
    }
    let listed: Vec<Value> = pulls
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .map(|(_, pull)| pull)
        .collect();
    (StatusCode::OK, Value::Array(listed).to_string()).into_response()
}
