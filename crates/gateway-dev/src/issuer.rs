//! The development issuer for the Compose demo: `switchboard-dev issuer`.
//!
//! It wraps the testkit's [`LocalIssuer`]: a key pair generated at start and never written
//! down. At start it writes the public half, a JWK set, to a file the gateway reads at boot.
//! Then it answers, over HTTP:
//!
//! - `GET /token?subject=S&audience=A`: a workload token for `S`, for audience `A`, valid for
//!   [`TOKEN_LIFETIME_SECS`], as the bare token. Only the subjects it was started with are
//!   signed; any other is 403. Any audience is signed, so the demo can show a real token for
//!   the wrong audience being refused.
//! - `GET /jwks.json`: the same JWK set it wrote.
//! - `GET /healthz`: 200 once it is serving.
//!
//! It is development only. It signs for anyone who can reach it, so Compose does not publish
//! its port: only services on the Compose network can ask it for a token. The `switchboard`
//! binary never links it (crates/gateway's `tests/dependencies.rs` keeps the testkit out).
//! A restart makes a new key pair, so the gateway must be restarted after it.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use gateway_identity::SigningAlgorithm;
use gateway_testkit::{IssuerError, LocalIssuer};
use serde_json::json;
use tokio::net::TcpListener;

/// How long a token from the development issuer lives, in seconds.
pub const TOKEN_LIFETIME_SECS: u64 = 600;

/// The development issuer: a key pair, its issuer name and the subjects it signs for.
pub struct DevIssuer {
    issuer: LocalIssuer,
    subjects: BTreeSet<String>,
}

impl std::fmt::Debug for DevIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevIssuer")
            .field("issuer", &self.issuer.issuer())
            .field("kid", &self.issuer.key_id())
            .field("subjects", &self.subjects)
            .finish()
    }
}

impl DevIssuer {
    /// An RS256 issuer named `issuer`, with a new key pair, that signs for `subjects` only.
    pub fn new(issuer: &str, subjects: BTreeSet<String>) -> Result<Self, IssuerError> {
        Ok(Self {
            issuer: LocalIssuer::new(issuer, SigningAlgorithm::Rs256)?,
            subjects,
        })
    }

    /// The issuer's name.
    pub fn name(&self) -> &str {
        self.issuer.issuer()
    }

    /// The `kid` of its key.
    pub fn key_id(&self) -> &str {
        self.issuer.key_id()
    }

    /// Its public key, as a JWK set document.
    pub fn jwks_document(&self) -> String {
        self.issuer.jwks_document()
    }

    /// A token for `subject` and `audience`, or `None` if it does not sign for `subject`.
    pub fn token(&self, subject: &str, audience: &str) -> Option<String> {
        self.subjects.contains(subject).then(|| {
            self.issuer
                .workload_token(subject, audience, SystemTime::now())
                .lifetime(TOKEN_LIFETIME_SECS)
                .build()
        })
    }

    /// Writes the JWK set to `path`, beside it first and then renamed over it, so a reader
    /// never sees half a file.
    pub fn write_keys(&self, path: &Path) -> io::Result<()> {
        if let Some(directory) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(directory)?;
        }
        let mut partial = path.as_os_str().to_owned();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        let mut file = fs::File::create(&partial)?;
        file.write_all(self.jwks_document().as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&partial, path)
    }

    /// The HTTP routes in the [module documentation](self).
    pub fn router(self) -> Router {
        Router::new()
            .route("/token", get(token))
            .route("/jwks.json", get(jwks))
            .route("/healthz", get(healthz))
            .with_state(Arc::new(self))
    }
}

/// Serves `issuer` on `listener` until the listener fails.
pub async fn serve(listener: TcpListener, issuer: DevIssuer) -> io::Result<()> {
    axum::serve(listener, issuer.router()).await
}

async fn healthz() -> Response {
    text(StatusCode::OK, "ok".to_owned())
}

async fn jwks(State(issuer): State<Arc<DevIssuer>>) -> Response {
    let mut response = text(StatusCode::OK, issuer.jwks_document());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

async fn token(State(issuer): State<Arc<DevIssuer>>, request: Request) -> Response {
    let (subject, audience) = match token_query(request.uri().query().unwrap_or("")) {
        Ok(asked) => asked,
        Err(problem) => return text(StatusCode::BAD_REQUEST, problem),
    };
    match issuer.token(&subject, &audience) {
        Some(token) => {
            println!(
                "{}",
                json!({"event": "token_issued", "subject": subject, "audience": audience})
            );
            text(StatusCode::OK, token)
        }
        None => {
            println!(
                "{}",
                json!({"event": "token_refused", "subject": subject, "audience": audience})
            );
            text(
                StatusCode::FORBIDDEN,
                format!("this development issuer does not sign for subject `{subject}`"),
            )
        }
    }
}

/// The subject and audience a `/token` query asks for. Each exactly once, both non-empty,
/// nothing else.
fn token_query(query: &str) -> Result<(String, String), String> {
    let mut subject = None;
    let mut audience = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("`{pair}` has no value"))?;
        let value = percent_decode(value).ok_or_else(|| format!("`{name}` is not valid UTF-8"))?;
        let slot = match name {
            "subject" => &mut subject,
            "audience" => &mut audience,
            _ => return Err(format!("unknown parameter `{name}`")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("`{name}` is given more than once"));
        }
    }
    match (subject, audience) {
        (Some(subject), Some(audience)) if !subject.is_empty() && !audience.is_empty() => {
            Ok((subject, audience))
        }
        _ => Err("give `subject` and `audience`, each once and not empty".to_owned()),
    }
}

/// `%XX` escapes decoded; everything else as it is. `None` if an escape is malformed or the
/// result is not UTF-8.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn text(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_names_one_subject_and_one_audience() {
        assert_eq!(
            token_query("subject=workload:team-a:mock-workload&audience=switchboard"),
            Ok(("workload:team-a:mock-workload".into(), "switchboard".into()))
        );
        assert_eq!(
            token_query("audience=a%20b&subject=s%3Ax"),
            Ok(("s:x".into(), "a b".into()))
        );
        for bad in [
            "",
            "subject=s",
            "audience=a",
            "subject=&audience=a",
            "subject=s&audience=",
            "subject=s&audience=a&subject=t",
            "subject=s&audience=a&lifetime=99999",
            "subject&audience=a",
            "subject=%zz&audience=a",
            "subject=%f&audience=a",
            "subject=%ff&audience=a",
        ] {
            assert!(token_query(bad).is_err(), "{bad}");
        }
    }
}
