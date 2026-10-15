//! A fake GitHub App API, behind the `test-support` feature, for the tests.
//!
//! It serves the two endpoints the custodian calls, on a loopback port:
//!
//! - `POST /app/installations/{id}/access_tokens`: it checks the App JWT as GitHub does (RS256,
//!   signed by the App's key, `iss` the App, `iat` no later than now, `exp` in the future and no
//!   more than ten minutes away), and that the installation is the App's. It issues a dummy
//!   token scoped exactly as asked: to the repositories named, or every repository of the
//!   installation if none is named; to the permissions named, or every permission the
//!   installation has if none is named. It refuses more than 500 repositories, or one not in
//!   the installation, with 422.
//! - `DELETE /installation/token`: it revokes the token in the `Authorization` header.
//!
//! It can be told to refuse, fail, hang, widen what it issues, or issue tokens that expire
//! sooner than GitHub's hour (see [`Behaviour`]). It keeps every token it issued and revoked,
//! and counts the JWTs it refused, for the tests to inspect.
//!
//! Its tokens look like GitHub's installation tokens, built at run time from parts, so no
//! source file holds one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, post};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::clock;

/// What the fake does with the next token requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Issues tokens as GitHub does, expiring in an hour.
    Issue,
    /// Issues tokens that expire this many seconds after they are issued.
    ExpireIn(u64),
    /// Answers every token request with this status.
    Refuse(u16),
    /// Answers 500.
    Fail,
    /// Never answers.
    Hang,
    /// Issues a token for every repository of the installation, whatever was asked.
    Widen,
}

/// A token the fake issued, and what it is scoped to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedToken {
    /// The token.
    pub token: String,
    /// The repositories asked for, by name, if any were.
    pub asked_repositories: Option<Vec<String>>,
    /// The permissions asked for, if any were.
    pub asked_permissions: Option<BTreeMap<String, String>>,
    /// The repositories the token reaches, by name.
    pub repositories: BTreeSet<String>,
    /// When it expires, in seconds since the epoch.
    pub expires_at: u64,
}

/// The App and installation the fake plays.
#[derive(Clone, Debug)]
pub struct FakeApp {
    /// The App's public key, an RSA public key in PKCS#1 DER, which every JWT must verify
    /// against.
    pub public_key_der: Vec<u8>,
    /// The App's ID, every JWT's `iss`.
    pub app_id: String,
    /// The installation's ID.
    pub installation_id: u64,
    /// The account it is installed on.
    pub account: String,
    /// The repositories it is installed on, by name.
    pub repositories: BTreeSet<String>,
}

struct Shared {
    app: FakeApp,
    key: DecodingKey,
    state: Mutex<FakeState>,
}

struct FakeState {
    behaviour: Behaviour,
    token_requests: usize,
    jwt_refusals: usize,
    issued: Vec<IssuedToken>,
    revoked: Vec<String>,
}

/// The fake, serving until dropped.
pub struct FakeGitHub {
    address: SocketAddr,
    shared: Arc<Shared>,
    server: JoinHandle<()>,
}

impl Drop for FakeGitHub {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Why the fake could not start.
#[derive(Debug, thiserror::Error)]
pub enum FakeError {
    /// The listener could not be bound.
    #[error("the fake could not listen: {0}")]
    Listen(#[from] std::io::Error),
}

impl FakeGitHub {
    /// Starts the fake for `app` on a loopback port.
    pub async fn start(app: FakeApp) -> Result<Self, FakeError> {
        let key = DecodingKey::from_rsa_der(&app.public_key_der);
        let shared = Arc::new(Shared {
            app,
            key,
            state: Mutex::new(FakeState {
                behaviour: Behaviour::Issue,
                token_requests: 0,
                jwt_refusals: 0,
                issued: Vec::new(),
                revoked: Vec::new(),
            }),
        });
        let router = Router::new()
            .route("/app/installations/{id}/access_tokens", post(create))
            .route("/installation/token", delete(revoke))
            .with_state(shared.clone());
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

    /// Sets what the fake does with the next token requests.
    pub fn set_behaviour(&self, behaviour: Behaviour) {
        self.shared.lock().behaviour = behaviour;
    }

    /// How many token requests arrived, whatever came of them.
    pub fn token_requests(&self) -> usize {
        self.shared.lock().token_requests
    }

    /// How many token requests were refused for their JWT.
    pub fn jwt_refusals(&self) -> usize {
        self.shared.lock().jwt_refusals
    }

    /// Every token issued, in order.
    pub fn issued(&self) -> Vec<IssuedToken> {
        self.shared.lock().issued.clone()
    }

    /// Every token revoked, in order.
    pub fn revoked(&self) -> Vec<String> {
        self.shared.lock().revoked.clone()
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A dummy installation token: GitHub's prefix, built from parts, and 36 random characters.
fn dummy_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 36];
    OsRng.fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect();
    format!("{}{body}", concat!("ghs", "_"))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, json!({ "message": message }).to_string()).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    #[serde(default)]
    repositories: Option<Vec<String>>,
    #[serde(default)]
    permissions: Option<BTreeMap<String, String>>,
}

/// The permissions the fake's installation has: what a token asked for without any gets.
fn installation_permissions() -> BTreeMap<String, String> {
    [
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ]
    .into_iter()
    .map(|(name, level)| (name.to_owned(), level.to_owned()))
    .collect()
}

/// Whether `jwt` is an App JWT GitHub would accept from `app` now.
fn jwt_valid(shared: &Shared, jwt: &str) -> bool {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "iat", "iss"]);
    validation.set_issuer(&[shared.app.app_id.as_str()]);
    validation.validate_aud = false;
    validation.leeway = 0;
    let Ok(data) = jsonwebtoken::decode::<Value>(jwt, &shared.key, &validation) else {
        return false;
    };
    let now = clock::now();
    let (Some(iat), Some(exp)) = (data.claims["iat"].as_u64(), data.claims["exp"].as_u64()) else {
        return false;
    };
    iat <= now && exp > now && exp <= now + 600
}

async fn create(
    State(shared): State<Arc<Shared>>,
    Path(installation): Path<u64>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let behaviour = {
        let mut state = shared.lock();
        state.token_requests += 1;
        state.behaviour
    };
    if behaviour == Behaviour::Hang {
        std::future::pending::<()>().await;
    }
    let headers_ok = headers
        .get("accept")
        .is_some_and(|accept| accept == "application/vnd.github+json")
        && headers.contains_key("user-agent")
        && headers.contains_key("x-github-api-version");
    if !headers_ok {
        return error(StatusCode::BAD_REQUEST, "missing a header GitHub requires");
    }
    if !bearer(&headers).is_some_and(|jwt| jwt_valid(&shared, jwt)) {
        shared.lock().jwt_refusals += 1;
        return error(
            StatusCode::UNAUTHORIZED,
            "A JSON web token could not be decoded",
        );
    }
    if installation != shared.app.installation_id {
        return error(StatusCode::NOT_FOUND, "Not Found");
    }
    match behaviour {
        Behaviour::Refuse(status) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
            return error(status, "refused");
        }
        Behaviour::Fail => return error(StatusCode::INTERNAL_SERVER_ERROR, "failed"),
        _ => {}
    }
    let Ok(asked) = serde_json::from_slice::<TokenBody>(&body) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Invalid request");
    };
    if let Some(repositories) = &asked.repositories {
        if repositories.len() > 500 {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Too many repositories requested",
            );
        }
        if repositories
            .iter()
            .any(|name| !shared.app.repositories.contains(name))
        {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "There is at least one repository that does not exist or is not accessible",
            );
        }
    }
    let every = installation_permissions();
    let mut permissions = match &asked.permissions {
        Some(asked) => {
            if asked.iter().any(|(name, level)| {
                every
                    .get(name)
                    .is_none_or(|have| have == "read" && level == "write")
            }) {
                return error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "The permissions requested are not granted to this installation",
                );
            }
            asked.clone()
        }
        None => every,
    };
    permissions.insert("metadata".into(), "read".into());
    let (selection, repositories) = match (&asked.repositories, behaviour) {
        (Some(names), behaviour) if behaviour != Behaviour::Widen => {
            ("selected", names.iter().cloned().collect())
        }
        _ => ("all", shared.app.repositories.clone()),
    };
    let lifetime = match behaviour {
        Behaviour::ExpireIn(seconds) => seconds,
        _ => 3600,
    };
    let token = dummy_token();
    let expires_at = clock::now() + lifetime;
    shared.lock().issued.push(IssuedToken {
        token: token.clone(),
        asked_repositories: asked.repositories.clone(),
        asked_permissions: asked.permissions.clone(),
        repositories: repositories.clone(),
        expires_at,
    });
    let listed: Vec<Value> = repositories
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "full_name": format!("{}/{name}", shared.app.account),
            })
        })
        .collect();
    let answer = json!({
        "token": token,
        "expires_at": clock::format_utc(expires_at),
        "permissions": permissions,
        "repository_selection": selection,
        "repositories": listed,
    });
    (StatusCode::CREATED, answer.to_string()).into_response()
}

async fn revoke(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return error(StatusCode::UNAUTHORIZED, "Bad credentials");
    };
    let mut state = shared.lock();
    let known = state.issued.iter().any(|issued| issued.token == token);
    if !known || state.revoked.iter().any(|revoked| revoked == token) {
        return error(StatusCode::UNAUTHORIZED, "Bad credentials");
    }
    state.revoked.push(token.to_owned());
    StatusCode::NO_CONTENT.into_response()
}
