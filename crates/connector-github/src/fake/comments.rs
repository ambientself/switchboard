//! The fake's endpoints for the comment tool ([`crate::pr_comment`]) and its lookup.
//!
//! - `POST /repos/{owner}/{repo}/issues/{n}/comments` posts a comment on pull request or issue
//!   `n`, which must be one the fake serves ([`FakeRest::pull`], [`FakeRest::issue`], or a pull
//!   request opened through it), as `switchboard-test-app[bot]`, with the body it was sent; its
//!   answer is 201 with the comment, whose id is numbered from 1001 across the fake. A token needs
//!   `pull_requests` or `issues` at `write`. A body that is not JSON with a string `body` is
//!   422. The next write's fault ([`FakeRest::fault_next_write`]) is met here as by a pull
//!   request. The comment is then served with the pull request's comments as well.
//! - `GET /repos/{owner}/{repo}/issues/comments` lists the repository's comments, those posted
//!   through the fake and those a test added ([`FakeRest::comment_elsewhere`]), with `since` (an
//!   ISO 8601 time; only comments updated at or after it), `sort` (`created`), `direction`
//!   (`asc` unless `desc`), `per_page` (30 unless given, 100 at most) and `page`. A token needs
//!   `issues` or `pull_requests` at `read` or above.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use key_custodian::fake::IssuedToken;
use serde_json::{Value, json};

use super::writes::{BrokenOff, Closed, Fault};
use super::{FakeRest, Shared, error, lock, query_value};

/// The login every comment through the fake is posted by.
const AUTHOR: &str = "switchboard-test-app[bot]";

/// What the comment endpoints hold.
#[derive(Default)]
pub(super) struct Content {
    /// Each repository's comments, in the order made.
    made: BTreeMap<String, Vec<Value>>,
    /// The number of comments made, for their ids.
    count: u64,
}

impl FakeRest {
    /// The comments made in `repo`, posted through the fake or added by a test, in order.
    pub fn posted(&self, repo: &str) -> Vec<Value> {
        lock(&self.shared.comments)
            .made
            .get(repo)
            .cloned()
            .unwrap_or_default()
    }

    /// Adds a comment by someone else on `number` of `repo`, with `body`, now; its id.
    pub fn comment_elsewhere(&self, repo: &str, number: u64, body: &str) -> u64 {
        let comment = make(&self.shared, repo, number, body, "someone-else");
        comment["id"].as_u64().unwrap_or(0)
    }
}

/// Whether `issued` may use `issues` or `pull_requests`: at `write` when `write`, or at `read`
/// or above. A token asked for with no permissions has every one the installation has.
fn may(issued: &IssuedToken, write: bool) -> bool {
    match &issued.asked_permissions {
        None => true,
        Some(asked) => ["issues", "pull_requests"].iter().any(|permission| {
            asked
                .get(*permission)
                .is_some_and(|level| level == "write" || (!write && level == "read"))
        }),
    }
}

/// Now, as GitHub writes a time.
fn now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    crate::pr_comment::rfc3339(seconds)
}

/// Makes a comment on `number` of `repo` by `author`, and the comment.
fn make(shared: &Shared, repo: &str, number: u64, body: &str, author: &str) -> Value {
    let comment = {
        let mut content = lock(&shared.comments);
        content.count += 1;
        let id = 1000 + content.count;
        let at = now();
        let comment = json!({
            "id": id,
            "body": body,
            "user": {"login": author},
            "html_url": format!("https://github.example.test/{}/{repo}/pull/{number}#issuecomment-{id}", shared.account),
            "issue_url": format!("https://api.github.example.test/repos/{}/{repo}/issues/{number}", shared.account),
            "created_at": at,
            "updated_at": at,
        });
        content
            .made
            .entry(repo.to_owned())
            .or_default()
            .push(comment.clone());
        comment
    };
    lock(&shared.content)
        .comments
        .entry((repo.to_owned(), number))
        .or_default()
        .push(comment.clone());
    comment
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
    let posted_on = tail
        .strip_prefix("issues/")
        .and_then(|tail| tail.strip_suffix("/comments"))
        .and_then(|number| number.parse::<u64>().ok());
    let listing = tail == "issues/comments" && *method == Method::GET;
    let posting = posted_on.is_some() && *method == Method::POST;
    if !listing && !posting {
        return None;
    }
    // GitHub does not say a repository exists to a token that cannot see it.
    if owner != shared.account || !issued.repositories.contains(&repo) {
        return Some(error(StatusCode::NOT_FOUND, "Not Found", token));
    }
    if !may(issued, posting) {
        return Some(error(
            StatusCode::FORBIDDEN,
            "Resource not accessible by integration",
            token,
        ));
    }
    Some(match posted_on {
        Some(number) if posting => post(shared, &repo, number, body, token).await,
        _ => list(shared, &repo, uri.query().unwrap_or("")),
    })
}

async fn post(
    shared: &Shared,
    repo: &str,
    number: u64,
    body: &[u8],
    token: Option<&str>,
) -> Response {
    let exists = {
        let content = lock(&shared.content);
        let key = (repo.to_owned(), number);
        content.pulls.contains_key(&key) || content.issues.contains_key(&key)
    };
    if !exists {
        return error(StatusCode::NOT_FOUND, "Not Found", token);
    }
    let text = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|sent| sent.get("body").and_then(Value::as_str).map(str::to_owned));
    let Some(text) = text else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Validation Failed", token);
    };
    let fault = lock(&shared.writes).faults.pop_front();
    if let Some(Fault::Status(status)) = fault {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return error(status, "failed", token);
    }
    if let Some(Fault::Late(wait)) = fault {
        tokio::time::sleep(wait).await;
    }
    let made = make(shared, repo, number, &text, AUTHOR);
    match fault {
        Some(Fault::AppliedThen(status)) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error(status, "failed", token)
        }
        Some(Fault::AppliedThenClosed) => Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::new(Closed))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Some(Fault::AppliedThenBrokenOff) => Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::new(BrokenOff::default()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Some(Fault::AppliedThenNotJson) => {
            (StatusCode::CREATED, "<html>created</html>").into_response()
        }
        _ => (StatusCode::CREATED, made.to_string()).into_response(),
    }
}

fn list(shared: &Shared, repo: &str, query: &str) -> Response {
    let since = query_value(query, "since");
    let descending = query_value(query, "direction").as_deref() == Some("desc");
    let number = |name: &str, default: usize| {
        query_value(query, name)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(default)
    };
    let per_page = number("per_page", 30).clamp(1, 100);
    let page = number("page", 1).max(1);
    let content = lock(&shared.comments);
    // Times written alike compare as text.
    let mut comments: Vec<Value> = content
        .made
        .get(repo)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|comment| {
            since.as_deref().is_none_or(|since| {
                comment["updated_at"]
                    .as_str()
                    .is_some_and(|updated| updated >= since)
            })
        })
        .collect();
    if descending {
        comments.reverse();
    }
    let listed: Vec<Value> = comments
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .collect();
    (StatusCode::OK, Value::Array(listed).to_string()).into_response()
}
