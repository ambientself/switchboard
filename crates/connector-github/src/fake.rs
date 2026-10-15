//! A fake GitHub REST API, behind the `test-support` feature, for the read tools.
//!
//! It serves, on a loopback port, what the tools ask for: a file through the contents API, a
//! pull request, an issue, and an issue's or a pull request's comments; and, for the newer
//! reads, what `reads` lists, with a fake job log host ([`FakeLogHost`]). It records every
//! request, with the token it carried, before it looks at anything else.
//!
//! It answers only a token that the key custodian's fake App API ([`FakeGitHub`]) issued, has
//! not revoked and has not seen expire, as GitHub answers only its own installation tokens:
//!
//! - an unknown token is 401;
//! - a repository outside the token's repositories, or on another account, is 404, as GitHub
//!   answers for a repository a token cannot see;
//! - a token without the permission the endpoint needs is 403: `contents` for a file,
//!   `pull_requests` for a pull request, and `issues` or `pull_requests` for an issue and its
//!   comments, each at `read` or above. A token asked for with no permissions has every one
//!   the installation has.
//!
//! It can be told to answer every request with a status, with GitHub's rate-limit answer, or
//! late (see [`Mode`]). Every error it answers carries the token it was sent in its body, as a
//! careless vendor might, so a test can show that nothing the caller reads holds it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use key_custodian::fake::{FakeGitHub, IssuedToken};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

mod reads;

pub use reads::{FakeLogHost, LogHit};

/// One request the fake received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// The method.
    pub method: String,
    /// The path, as sent, percent-encoding and all.
    pub path: String,
    /// The query, as sent, or empty.
    pub query: String,
    /// The bearer token in its `Authorization` header, if it had one.
    pub token: Option<String>,
}

/// What the fake does with the next requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Answers as GitHub does.
    Normal,
    /// Answers every request with this status.
    Status(u16),
    /// Answers every request as GitHub does when an installation's rate limit is used up: 403
    /// with `x-ratelimit-remaining: 0`.
    RateLimited,
    /// Answers as GitHub does, after waiting this long.
    Late(Duration),
}

#[derive(Default)]
struct Content {
    files: BTreeMap<(String, String), String>,
    pulls: BTreeMap<(String, u64), Value>,
    issues: BTreeMap<(String, u64), Value>,
    comments: BTreeMap<(String, u64), Vec<Value>>,
}

struct Shared {
    app: Arc<FakeGitHub>,
    account: String,
    mode: Mutex<Mode>,
    requests: Mutex<Vec<Recorded>>,
    content: Mutex<Content>,
    reads: Mutex<reads::Content>,
}

/// The fake, serving until dropped.
pub struct FakeRest {
    address: SocketAddr,
    shared: Arc<Shared>,
    server: JoinHandle<()>,
}

impl Drop for FakeRest {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeRest {
    /// Starts the fake on a loopback port, for the installation `app` plays on `account`.
    pub async fn start(app: Arc<FakeGitHub>, account: &str) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            app,
            account: account.to_owned(),
            mode: Mutex::new(Mode::Normal),
            requests: Mutex::new(Vec::new()),
            content: Mutex::new(Content::default()),
            reads: Mutex::new(reads::Content::default()),
        });
        let router = Router::new().fallback(answer).with_state(shared.clone());
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

    /// The API's base URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Sets what the fake does with the next requests.
    pub fn set_mode(&self, mode: Mode) {
        *lock(&self.shared.mode) = mode;
    }

    /// Every request received, in order.
    pub fn requests(&self) -> Vec<Recorded> {
        lock(&self.shared.requests).clone()
    }

    /// Serves `text` as the file at `path` in repository `repo` of the account.
    pub fn file(&self, repo: &str, path: &str, text: &str) {
        lock(&self.shared.content)
            .files
            .insert((repo.to_owned(), path.to_owned()), text.to_owned());
    }

    /// Serves `pr` as pull request `number` of `repo`. It is also issue `number`, with a
    /// `pull_request` field, as GitHub has it.
    pub fn pull(&self, repo: &str, number: u64, pr: Value) {
        let mut content = lock(&self.shared.content);
        let mut issue = pr.clone();
        issue["pull_request"] = json!({"url": format!("https://example.invalid/pull/{number}")});
        content.issues.insert((repo.to_owned(), number), issue);
        content.pulls.insert((repo.to_owned(), number), pr);
    }

    /// Serves `issue` as issue `number` of `repo`.
    pub fn issue(&self, repo: &str, number: u64, issue: Value) {
        lock(&self.shared.content)
            .issues
            .insert((repo.to_owned(), number), issue);
    }

    /// Serves `comments` as the comments of issue or pull request `number` of `repo`.
    pub fn comments(&self, repo: &str, number: u64, comments: Vec<Value>) {
        lock(&self.shared.content)
            .comments
            .insert((repo.to_owned(), number), comments);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

/// An error as GitHub writes one, with the token it was sent: see the module documentation.
fn error(status: StatusCode, message: &str, token: Option<&str>) -> Response {
    let body = json!({
        "message": message,
        "documentation_url": "https://docs.github.com/rest",
        "presented": token,
    });
    (status, body.to_string()).into_response()
}

/// Whether `token` may read with `permission` at `read` or above.
fn permits(token: &IssuedToken, permissions: &[&str]) -> bool {
    match &token.asked_permissions {
        None => true,
        Some(asked) => permissions.iter().any(|permission| {
            asked
                .get(*permission)
                .is_some_and(|level| level == "read" || level == "write")
        }),
    }
}

/// The endpoint a path names: the repository, and what in it.
enum Endpoint {
    File(String),
    Pull(u64),
    Issue(u64),
    Comments(u64),
}

fn endpoint(path: &str) -> Option<(String, String, Endpoint)> {
    let rest = path.strip_prefix("/repos/")?;
    let mut parts = rest.splitn(4, '/');
    let owner = parts.next()?.to_owned();
    let repo = parts.next()?.to_owned();
    let kind = parts.next()?;
    let rest = parts.next()?;
    let number = |text: &str| text.parse::<u64>().ok();
    let found = match kind {
        "contents" => {
            let decoded = percent_decode(rest)?;
            Endpoint::File(decoded)
        }
        "pulls" => Endpoint::Pull(number(rest)?),
        "issues" => match rest.split_once('/') {
            Some((n, "comments")) => Endpoint::Comments(number(n)?),
            None => Endpoint::Issue(number(rest)?),
            Some(_) => return None,
        },
        _ => return None,
    };
    Some((owner, repo, found))
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn query_value(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| percent_decode(value))
}

async fn answer(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let token = bearer(&headers);
    lock(&shared.requests).push(Recorded {
        method: method.to_string(),
        path: uri.path().to_owned(),
        query: uri.query().unwrap_or("").to_owned(),
        token: token.clone(),
    });
    let mode = *lock(&shared.mode);
    match mode {
        Mode::Normal => {}
        Mode::Late(wait) => tokio::time::sleep(wait).await,
        Mode::Status(status) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return error(status, "failed", token.as_deref());
        }
        Mode::RateLimited => {
            let mut response = error(
                StatusCode::FORBIDDEN,
                "API rate limit exceeded for installation",
                token.as_deref(),
            );
            response
                .headers_mut()
                .insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
            return response;
        }
    }
    if method != Method::GET {
        return error(StatusCode::NOT_FOUND, "Not Found", token.as_deref());
    }
    let issued = token.as_deref().and_then(|token| {
        let revoked = shared.app.revoked();
        shared
            .app
            .issued()
            .into_iter()
            .find(|issued| issued.token == token && !revoked.iter().any(|r| r == token))
            .filter(|issued| issued.expires_at > now())
    });
    let Some(issued) = issued else {
        return error(
            StatusCode::UNAUTHORIZED,
            "Bad credentials",
            token.as_deref(),
        );
    };
    // The endpoints of the newer reads (`reads`).
    if let Some(response) = reads::answer(&shared, &issued, &uri, token.as_deref()) {
        return response;
    }
    let Some((owner, repo, endpoint)) = endpoint(uri.path()) else {
        return error(StatusCode::NOT_FOUND, "Not Found", token.as_deref());
    };
    // GitHub does not say a repository exists to a token that cannot see it.
    if owner != shared.account || !issued.repositories.contains(&repo) {
        return error(StatusCode::NOT_FOUND, "Not Found", token.as_deref());
    }
    let needs: &[&str] = match endpoint {
        Endpoint::File(_) => &["contents"],
        Endpoint::Pull(_) => &["pull_requests"],
        Endpoint::Issue(_) | Endpoint::Comments(_) => &["issues", "pull_requests"],
    };
    if !permits(&issued, needs) {
        return error(
            StatusCode::FORBIDDEN,
            "Resource not accessible by integration",
            token.as_deref(),
        );
    }
    let content = lock(&shared.content);
    let found = match endpoint {
        Endpoint::File(path) => content
            .files
            .get(&(repo.clone(), path.clone()))
            .map(|text| {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
                // GitHub wraps the base64 at 60 columns.
                let wrapped: Vec<String> = encoded
                    .as_bytes()
                    .chunks(60)
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect();
                let reference = query_value(uri.query().unwrap_or(""), "ref");
                json!({
                    "type": "file",
                    "path": path,
                    "name": path.rsplit('/').next().unwrap_or(&path),
                    "sha": "9".repeat(40),
                    "size": text.len(),
                    "encoding": "base64",
                    "content": wrapped.join("\n"),
                    "ref_asked": reference,
                })
            }),
        Endpoint::Pull(number) => content.pulls.get(&(repo.clone(), number)).cloned(),
        Endpoint::Issue(number) => content.issues.get(&(repo.clone(), number)).cloned(),
        Endpoint::Comments(number) => {
            let per_page = query_value(uri.query().unwrap_or(""), "per_page")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(30);
            let comments = content
                .comments
                .get(&(repo.clone(), number))
                .cloned()
                .unwrap_or_default();
            Some(Value::Array(comments.into_iter().take(per_page).collect()))
        }
    };
    match found {
        Some(body) => (StatusCode::OK, body.to_string()).into_response(),
        None => error(StatusCode::NOT_FOUND, "Not Found", token.as_deref()),
    }
}
