//! The fake's endpoints for the newer reads ([`crate::reads`]), and a fake job log host.
//!
//! The REST endpoints answer as the rest of the fake does: only a token the fake App API
//! issued, a 404 for a repository the token cannot see, and a 403 for a token without the
//! permission the endpoint needs, at `read` or above. Those are `contents` for a directory
//! listing, a branch's ref and the releases; `checks` for check runs and their annotations;
//! `actions` for a job and its log; and `statuses` for a commit's combined status. The
//! repository itself and its tags need no permission, as GitHub gives every installation token
//! `metadata: read`.
//!
//! A job's log is answered with a redirect to wherever the test says, with the log served
//! directly, or with a 404. [`FakeLogHost`] is a host such a redirect can point to: it records
//! every request with any `Authorization` header it carried, and serves the logs it is given.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use key_custodian::fake::IssuedToken;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{FakeRest, Shared, error, lock, percent_decode, permits, query_value};

/// A job's log, as the fake answers for it.
enum Log {
    Redirect(String),
    Direct(String),
}

/// What the newer reads are answered with.
#[derive(Default)]
pub(super) struct Content {
    repositories: BTreeMap<String, (String, String)>,
    releases: BTreeMap<String, Vec<Value>>,
    tags: BTreeMap<String, Vec<Value>>,
    check_runs: BTreeMap<(String, String), Vec<Value>>,
    annotations: BTreeMap<(String, u64), Vec<Value>>,
    jobs: BTreeMap<(String, u64), Value>,
    statuses: BTreeMap<(String, String), (String, Vec<Value>)>,
    logs: BTreeMap<(String, u64), Log>,
}

impl FakeRest {
    /// Gives `repo` the default branch `branch`, whose head is the commit `head`.
    pub fn repository(&self, repo: &str, branch: &str, head: &str) {
        lock(&self.shared.reads)
            .repositories
            .insert(repo.to_owned(), (branch.to_owned(), head.to_owned()));
    }

    /// Serves `releases` as `repo`'s, newest first.
    pub fn releases(&self, repo: &str, releases: Vec<Value>) {
        lock(&self.shared.reads)
            .releases
            .insert(repo.to_owned(), releases);
    }

    /// Serves `tags` as `repo`'s.
    pub fn tags(&self, repo: &str, tags: Vec<Value>) {
        lock(&self.shared.reads).tags.insert(repo.to_owned(), tags);
    }

    /// Serves `runs` as the check runs of commit `commit` of `repo`.
    pub fn check_runs(&self, repo: &str, commit: &str, runs: Vec<Value>) {
        lock(&self.shared.reads)
            .check_runs
            .insert((repo.to_owned(), commit.to_owned()), runs);
    }

    /// Serves `annotations` as those of check run `run` of `repo`.
    pub fn annotations(&self, repo: &str, run: u64, annotations: Vec<Value>) {
        lock(&self.shared.reads)
            .annotations
            .insert((repo.to_owned(), run), annotations);
    }

    /// Serves `job` as GitHub Actions job `id` of `repo`.
    pub fn job(&self, repo: &str, id: u64, job: Value) {
        lock(&self.shared.reads)
            .jobs
            .insert((repo.to_owned(), id), job);
    }

    /// Serves a combined status `state` with `statuses` for commit `commit` of `repo`.
    pub fn statuses(&self, repo: &str, commit: &str, state: &str, statuses: Vec<Value>) {
        lock(&self.shared.reads).statuses.insert(
            (repo.to_owned(), commit.to_owned()),
            (state.to_owned(), statuses),
        );
    }

    /// Answers a request for job `job`'s log in `repo` with a redirect to `location`.
    pub fn log_redirect(&self, repo: &str, job: u64, location: &str) {
        lock(&self.shared.reads)
            .logs
            .insert((repo.to_owned(), job), Log::Redirect(location.to_owned()));
    }

    /// Answers a request for job `job`'s log in `repo` with `text` itself.
    pub fn log_direct(&self, repo: &str, job: u64, text: &str) {
        lock(&self.shared.reads)
            .logs
            .insert((repo.to_owned(), job), Log::Direct(text.to_owned()));
    }
}

/// What a path names.
enum Endpoint {
    Repository,
    Ref(String),
    Listing(String),
    Releases,
    Tags,
    CheckRuns(String),
    Annotations(u64),
    Job(u64),
    Log(u64),
    Status(String),
}

/// The files of `repo` directly in `directory` (`""` for the root), and its directories, as the
/// contents API lists them; `None` when there is no such directory.
fn listing(files: &BTreeSet<String>, directory: &str) -> Option<Value> {
    let prefix = if directory.is_empty() {
        String::new()
    } else {
        format!("{directory}/")
    };
    let mut entries = BTreeMap::new();
    for path in files {
        let Some(rest) = path.strip_prefix(&prefix) else {
            continue;
        };
        let (name, kind) = match rest.split_once('/') {
            Some((name, _)) => (name, "dir"),
            None => (rest, "file"),
        };
        entries.insert(name.to_owned(), kind);
    }
    if entries.is_empty() && !directory.is_empty() {
        return None;
    }
    Some(Value::Array(
        entries
            .into_iter()
            .map(|(name, kind)| {
                json!({"name": name, "path": format!("{prefix}{name}"), "type": kind})
            })
            .collect(),
    ))
}

fn route(shared: &Shared, repo: &str, tail: &str) -> Option<Endpoint> {
    let number = |text: &str| text.parse::<u64>().ok();
    let segments: Vec<&str> = tail.split('/').collect();
    Some(match segments.as_slice() {
        [""] => Endpoint::Repository,
        ["git", "ref", "heads", branch @ ..] if !branch.is_empty() => {
            Endpoint::Ref(percent_decode(&branch.join("/"))?)
        }
        ["contents"] => Endpoint::Listing(String::new()),
        ["contents", ..] => {
            let path = percent_decode(tail.strip_prefix("contents/")?)?;
            let content = lock(&shared.content);
            // A file is the rest of the fake's to answer.
            if content.files.contains_key(&(repo.to_owned(), path.clone())) {
                return None;
            }
            Endpoint::Listing(path)
        }
        ["releases"] => Endpoint::Releases,
        ["tags"] => Endpoint::Tags,
        ["commits", commit, "check-runs"] => Endpoint::CheckRuns((*commit).to_owned()),
        ["commits", commit, "status"] => Endpoint::Status((*commit).to_owned()),
        ["check-runs", run, "annotations"] => Endpoint::Annotations(number(run)?),
        ["actions", "jobs", job] => Endpoint::Job(number(job)?),
        ["actions", "jobs", job, "logs"] => Endpoint::Log(number(job)?),
        _ => return None,
    })
}

/// The answer to a request of the newer reads, or `None` for one that is the rest of the
/// fake's to answer.
pub(super) fn answer(
    shared: &Shared,
    issued: &IssuedToken,
    uri: &Uri,
    token: Option<&str>,
) -> Option<Response> {
    let rest = uri.path().strip_prefix("/repos/")?;
    let mut parts = rest.splitn(3, '/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let tail = parts.next().unwrap_or("");
    let endpoint = route(shared, repo, tail)?;
    // GitHub does not say a repository exists to a token that cannot see it.
    if owner != shared.account || !issued.repositories.contains(repo) {
        return Some(error(StatusCode::NOT_FOUND, "Not Found", token));
    }
    let needs: &[&str] = match endpoint {
        Endpoint::Repository | Endpoint::Tags => &[],
        Endpoint::Ref(_) | Endpoint::Listing(_) | Endpoint::Releases => &["contents"],
        Endpoint::CheckRuns(_) | Endpoint::Annotations(_) => &["checks"],
        Endpoint::Job(_) | Endpoint::Log(_) => &["actions"],
        Endpoint::Status(_) => &["statuses"],
    };
    if !needs.is_empty() && !permits(issued, needs) {
        return Some(error(
            StatusCode::FORBIDDEN,
            "Resource not accessible by integration",
            token,
        ));
    }
    let query = uri.query().unwrap_or("");
    let per_page = query_value(query, "per_page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(30);
    let page = |items: Option<&Vec<Value>>| -> Value {
        Value::Array(
            items
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(per_page)
                .collect(),
        )
    };
    let key = repo.to_owned();
    let reads = lock(&shared.reads);
    let found = match endpoint {
        Endpoint::Repository => reads.repositories.get(&key).map(|(branch, _)| {
            json!({"name": repo, "full_name": format!("{owner}/{repo}"), "default_branch": branch})
        }),
        Endpoint::Ref(branch) => reads
            .repositories
            .get(&key)
            .filter(|(default, _)| *default == branch)
            .map(|(_, head)| {
                json!({"ref": format!("refs/heads/{branch}"),
                       "object": {"type": "commit", "sha": head}})
            }),
        Endpoint::Listing(directory) => {
            let files: BTreeSet<String> = lock(&shared.content)
                .files
                .keys()
                .filter(|(file_repo, _)| *file_repo == key)
                .map(|(_, path)| path.clone())
                .collect();
            listing(&files, &directory)
        }
        Endpoint::Releases => Some(page(reads.releases.get(&key))),
        Endpoint::Tags => Some(page(reads.tags.get(&key))),
        Endpoint::CheckRuns(commit) => {
            let runs = reads.check_runs.get(&(key, commit));
            Some(json!({
                "total_count": runs.map_or(0, Vec::len),
                "check_runs": page(runs),
            }))
        }
        Endpoint::Annotations(run) => Some(page(reads.annotations.get(&(key, run)))),
        Endpoint::Job(job) => reads.jobs.get(&(key, job)).cloned(),
        Endpoint::Status(commit) => {
            let combined = reads.statuses.get(&(key, commit));
            Some(json!({
                "state": combined.map_or("pending", |(state, _)| state.as_str()),
                "total_count": combined.map_or(0, |(_, statuses)| statuses.len()),
                "statuses": page(combined.map(|(_, statuses)| statuses)),
            }))
        }
        Endpoint::Log(job) => {
            return Some(match reads.logs.get(&(key, job)) {
                Some(Log::Redirect(location)) => {
                    let mut response = StatusCode::FOUND.into_response();
                    if let Ok(location) = HeaderValue::from_str(location) {
                        response.headers_mut().insert("location", location);
                    }
                    response
                }
                Some(Log::Direct(text)) => (StatusCode::OK, text.clone()).into_response(),
                None => error(StatusCode::NOT_FOUND, "Not Found", token),
            });
        }
    };
    Some(match found {
        Some(body) => (StatusCode::OK, body.to_string()).into_response(),
        None => error(StatusCode::NOT_FOUND, "Not Found", token),
    })
}

/// One request a [`FakeLogHost`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogHit {
    /// The path, as sent.
    pub path: String,
    /// The query, as sent, or empty.
    pub query: String,
    /// The `Authorization` header, if it had one.
    pub authorization: Option<String>,
    /// Whether it carried any of GitHub's API headers.
    pub github_headers: bool,
}

#[derive(Default)]
struct LogShared {
    hits: Mutex<Vec<LogHit>>,
    logs: Mutex<BTreeMap<String, String>>,
}

/// A host a job log redirect can point to, serving until dropped.
pub struct FakeLogHost {
    address: SocketAddr,
    shared: Arc<LogShared>,
    server: JoinHandle<()>,
}

impl Drop for FakeLogHost {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn serve_log(State(shared): State<Arc<LogShared>>, uri: Uri, headers: HeaderMap) -> Response {
    lock(&shared.hits).push(LogHit {
        path: uri.path().to_owned(),
        query: uri.query().unwrap_or("").to_owned(),
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        github_headers: headers.contains_key("x-github-api-version"),
    });
    match lock(&shared.logs).get(uri.path()) {
        Some(text) => (StatusCode::OK, text.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

impl FakeLogHost {
    /// Starts a log host on a loopback port.
    pub async fn start() -> std::io::Result<Self> {
        let shared = Arc::new(LogShared::default());
        let router = Router::new().fallback(serve_log).with_state(shared.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self {
            address,
            shared,
            server,
        })
    }

    /// The host's URL, with no path.
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Serves `text` at `path`, whatever the query.
    pub fn serve(&self, path: &str, text: &str) {
        lock(&self.shared.logs).insert(path.to_owned(), text.to_owned());
    }

    /// Every request received, in order.
    pub fn hits(&self) -> Vec<LogHit> {
        lock(&self.shared.hits).clone()
    }
}
