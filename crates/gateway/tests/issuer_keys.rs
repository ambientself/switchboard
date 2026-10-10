//! Keys fetched from an issuer's own origin (issue #9): once at boot, then only on a timer.
//!
//! Each issuer here is a request-counting HTTP server on loopback, named by its own URL, that
//! serves a [`LocalIssuer`]'s JWK set at `/keys`. A second counting server stands for an issuer
//! the deployment does not list. The tests count every request each server gets, so they show
//! that boot fetches once, that no token causes a fetch, whatever its `iss`, `jku`, `x5u`, `jwk`
//! or `kid` says, and that a refresh which fails keeps the keys in use.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::extract::State;
use files::{AUDIENCE, Files, TEAM_A_SA, cluster_issuer, deployment_file};
use gateway::start::{Prepared, StartError, prepare};
use gateway::{Deployment, REFRESH_FAILED_EVENT, REFRESHED_EVENT, RefreshError};
use gateway_core::InstanceName;
use gateway_identity::{
    ConfigError, Identity, SigningAlgorithm, SystemClock, Verification, VerifyError,
};
use gateway_testkit::LocalIssuer;
use http::{StatusCode, Uri};
use issuer_keys::FetchError;
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// The path each counting server serves its keys at.
const KEYS_PATH: &str = "/keys";

/// The cluster issuer the files' registry rules name. Its keys are in a file; it is here only
/// so the registry's rules name a configured issuer.
fn cluster() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

/// What a counting server answers at [`KEYS_PATH`].
struct Answer {
    status: StatusCode,
    body: String,
}

/// A loopback HTTP server that counts every request it gets, on any path, and answers
/// [`KEYS_PATH`] with whatever the test sets.
struct Counting {
    url: String,
    requests: AtomicUsize,
    paths: Mutex<Vec<String>>,
    answer: Mutex<Answer>,
}

impl Counting {
    /// Starts a server answering `404` until told otherwise.
    async fn start() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Arc::new(Self {
            url: format!("http://{}", listener.local_addr().unwrap()),
            requests: AtomicUsize::new(0),
            paths: Mutex::new(Vec::new()),
            answer: Mutex::new(Answer {
                status: StatusCode::NOT_FOUND,
                body: String::new(),
            }),
        });
        let router = Router::new()
            .fallback(answer)
            .with_state(Arc::clone(&server));
        tokio::spawn(async move { axum::serve(listener, router).await });
        server
    }

    /// Answers `200` with `body`.
    fn serve(&self, body: impl Into<String>) {
        self.answer_with(StatusCode::OK, body);
    }

    fn answer_with(&self, status: StatusCode, body: impl Into<String>) {
        *self.answer.lock().unwrap() = Answer {
            status,
            body: body.into(),
        };
    }

    /// How many requests the server has had, on any path.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The paths requested, in order.
    fn paths(&self) -> Vec<String> {
        self.paths.lock().unwrap().clone()
    }

    fn keys_url(&self) -> String {
        format!("{}{KEYS_PATH}", self.url)
    }
}

async fn answer(State(server): State<Arc<Counting>>, uri: Uri) -> (StatusCode, String) {
    server.requests.fetch_add(1, Ordering::SeqCst);
    server.paths.lock().unwrap().push(uri.path().to_owned());
    if uri.path() != KEYS_PATH {
        return (StatusCode::NOT_FOUND, String::new());
    }
    let answer = server.answer.lock().unwrap();
    (answer.status, answer.body.clone())
}

/// An ES256 issuer named by `server`'s URL, with a new key.
fn issuer_at(server: &Counting) -> LocalIssuer {
    LocalIssuer::new(&server.url, SigningAlgorithm::Es256).unwrap()
}

/// The `[[identity.issuers]]` entry for a workload issuer fetched from `keys_url`, with `extra`
/// lines added.
fn fetched_issuer(issuer: &str, keys_url: &str, extra: &str) -> String {
    format!(
        r#"[[identity.issuers]]
issuer = "{issuer}"
kind = "workload"
audiences = ["{AUDIENCE}"]
algorithm = "ES256"
keys_url = "{keys_url}"
subjects_file = "teams.toml"
max_lifetime_seconds = 3600
leeway_seconds = 30
{extra}
"#
    )
}

/// A deployment trusting the cluster issuer from a file and `entry`, with audit disabled.
fn deployment(name: &str, entry: &str) -> Deployment {
    let files = Files::new(name, &cluster().jwks_document(), "http://127.0.0.1:9/mcp");
    files.write(
        "gateway.toml",
        &deployment_file(&format!("{entry}\n[audit]\nmode = \"disabled\"\n")),
    );
    files.load()
}

async fn boot(deployment: Deployment) -> Result<Prepared, StartError> {
    prepare(
        deployment,
        InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
}

/// A valid token from `issuer` for team A's workload.
fn token(issuer: &LocalIssuer) -> String {
    issuer
        .workload_token(TEAM_A_SA, AUDIENCE, SystemTime::now())
        .build()
}

/// Whether the gate proves `token`, or which check refused it.
fn outcome(identity: &Identity, token: &str) -> Result<(), VerifyError> {
    match identity.check(Some(token)) {
        Verification::Proved(_) => Ok(()),
        Verification::Failed(failure) => Err(failure.detail().clone()),
        Verification::Disabled => panic!("identity is enforced"),
    }
}

/// Waits up to ten seconds for `done`.
async fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn boot_fetches_once_and_no_token_causes_a_fetch() {
    let listed = Counting::start().await;
    let unlisted = Counting::start().await;
    let issuer = issuer_at(&listed);
    let stranger = issuer_at(&unlisted);
    listed.serve(issuer.jwks_document());
    unlisted.serve(stranger.jwks_document());

    let prepared = boot(deployment(
        "keys-never-fetched",
        &fetched_issuer(&listed.url, &listed.keys_url(), ""),
    ))
    .await
    .unwrap();
    assert_eq!(listed.requests(), 1, "{:?}", listed.paths());
    assert_eq!(listed.paths(), [KEYS_PATH]);
    assert_eq!(unlisted.requests(), 0);
    let identity = prepared.gates.identity();

    let now = SystemTime::now();
    let pointing_at = [
        unlisted.keys_url(),
        unlisted.url.clone(),
        format!("{}/.well-known/jwks.json", listed.url),
        format!("{}/openid/v1/jwks", listed.url),
        format!("{}/other", listed.url),
    ];
    let mut valid = vec![token(&issuer)];
    let mut refused = vec![
        // An issuer the deployment does not list, whose own keys are one request away.
        token(&stranger),
        // The listed issuer's name, signed by the unlisted issuer's key.
        issuer
            .workload_token(TEAM_A_SA, AUDIENCE, now)
            .signed_by(&stranger)
            .kid(stranger.key_id())
            .build(),
        // A `kid` the listed issuer has not published.
        issuer
            .workload_token(TEAM_A_SA, AUDIENCE, now)
            .kid("published-later")
            .build(),
        // The unlisted issuer's key, embedded in the header.
        stranger
            .workload_token(TEAM_A_SA, AUDIENCE, now)
            .issuer(&listed.url)
            .header(
                "jwk",
                serde_json::to_value(&stranger.jwk_set().keys[0]).unwrap(),
            )
            .build(),
    ];
    for url in &pointing_at {
        for header in ["jku", "x5u"] {
            // Signed by the listed issuer: the header is not read, so these verify.
            valid.push(
                issuer
                    .workload_token(TEAM_A_SA, AUDIENCE, now)
                    .header(header, json!(url))
                    .build(),
            );
            // Signed by the unlisted issuer, whose keys the header points at.
            refused.push(
                stranger
                    .workload_token(TEAM_A_SA, AUDIENCE, now)
                    .issuer(&listed.url)
                    .header(header, json!(url))
                    .build(),
            );
            // A `kid` the listed issuer has not published, and a header saying where it is.
            refused.push(
                issuer
                    .workload_token(TEAM_A_SA, AUDIENCE, now)
                    .kid("published-later")
                    .header(header, json!(url))
                    .build(),
            );
        }
    }

    let check_all = || {
        for _ in 0..20 {
            for token in &valid {
                assert_eq!(outcome(identity, token), Ok(()));
            }
            for token in &refused {
                assert!(outcome(identity, token).is_err());
            }
        }
    };
    check_all();
    assert_eq!(listed.requests(), 1, "{:?}", listed.paths());
    assert_eq!(unlisted.requests(), 0, "{:?}", unlisted.paths());

    // A refresh is one request, to the keys URL; the checks between refreshes are none.
    let refreshed = prepared.keys.refresh_all().await;
    assert!(
        matches!(refreshed.as_slice(), [Ok(replaced)] if replaced.added.is_empty()),
        "{refreshed:?}"
    );
    assert_eq!(listed.requests(), 2);
    check_all();
    assert_eq!(listed.requests(), 2, "{:?}", listed.paths());
    assert_eq!(listed.paths(), [KEYS_PATH, KEYS_PATH]);
    assert_eq!(unlisted.requests(), 0, "{:?}", unlisted.paths());
}

#[tokio::test]
async fn keys_rotate_on_the_timer_without_a_restart_and_the_timer_stops() {
    let listed = Counting::start().await;
    let old = issuer_at(&listed);
    let new = LocalIssuer::new(&listed.url, SigningAlgorithm::Es256).unwrap();
    assert_ne!(old.key_id(), new.key_id());
    listed.serve(old.jwks_document());

    let mut deployment = deployment(
        "keys-rotate",
        &fetched_issuer(&listed.url, &listed.keys_url(), ""),
    );
    assert_eq!(deployment.keys_urls[0].refresh, Duration::from_secs(300));
    // The test's own interval: the deployment file holds it to at least 30 seconds.
    deployment.keys_urls[0].refresh = Duration::from_millis(50);
    let prepared = boot(deployment).await.unwrap();
    let identity = prepared.gates.identity();
    let (old_token, new_token) = (token(&old), token(&new));
    assert_eq!(outcome(identity, &old_token), Ok(()));
    assert_eq!(
        outcome(identity, &new_token),
        Err(VerifyError::UnknownKeyId)
    );

    let refreshing = tokio::spawn(prepared.keys.run());
    // The new key published and the old one dropped. Two more requests make sure one began
    // after the change.
    listed.serve(new.jwks_document());
    let published = listed.requests();
    until("two refreshes after the new key", || {
        listed.requests() >= published + 2
    })
    .await;
    assert_eq!(outcome(identity, &new_token), Ok(()));
    assert_eq!(
        outcome(identity, &old_token),
        Err(VerifyError::UnknownKeyId)
    );

    // Stopped, as the binary stops it on shutdown, it fetches nothing more.
    refreshing.abort();
    assert!(refreshing.await.unwrap_err().is_cancelled());
    let stopped = listed.requests();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(listed.requests(), stopped);
}

/// Whether a refresh failed the way a case expects.
type Expected = fn(&RefreshError) -> bool;

#[tokio::test]
async fn a_refresh_that_fails_keeps_the_keys_in_use() {
    let listed = Counting::start().await;
    let issuer = issuer_at(&listed);
    let next = LocalIssuer::new(&listed.url, SigningAlgorithm::Es256).unwrap();
    listed.serve(issuer.jwks_document());
    let prepared = boot(deployment(
        "keys-refresh-fails",
        &fetched_issuer(&listed.url, &listed.keys_url(), ""),
    ))
    .await
    .unwrap();
    let identity = prepared.gates.identity();
    let kept = token(&issuer);

    let rsa = cluster().jwks_document();
    let oversize = format!("{{\"keys\": []{}}}", " ".repeat(300 * 1024));
    let failures: [(StatusCode, &str, Expected); 6] = [
        (StatusCode::INTERNAL_SERVER_ERROR, "", |error| {
            matches!(error, RefreshError::Fetch(FetchError::Status(500)))
        }),
        (StatusCode::OK, &oversize, |error| {
            matches!(error, RefreshError::Fetch(FetchError::TooLarge { .. }))
        }),
        (StatusCode::OK, "not json", |error| {
            matches!(error, RefreshError::Fetch(FetchError::NotJson(_)))
        }),
        (StatusCode::OK, r#"{"keys": []}"#, |error| {
            matches!(error, RefreshError::Refused(ConfigError::NoKeys(_)))
        }),
        // Only a key that cannot verify the issuer's algorithm: no usable key is left.
        (StatusCode::OK, &rsa, |error| {
            matches!(error, RefreshError::Refused(_))
        }),
        (StatusCode::FOUND, "", |error| {
            matches!(error, RefreshError::Fetch(FetchError::Status(302)))
        }),
    ];
    for (status, body, expected) in failures {
        listed.answer_with(status, body);
        let refreshed = prepared.keys.refresh_all().await;
        assert!(
            matches!(refreshed.as_slice(), [Err(error)] if expected(error)),
            "{status}: {refreshed:?}"
        );
        assert_eq!(outcome(identity, &kept), Ok(()), "{status}");
    }

    // A good set still replaces them.
    listed.serve(next.jwks_document());
    let refreshed = prepared.keys.refresh_all().await;
    assert!(matches!(refreshed.as_slice(), [Ok(_)]), "{refreshed:?}");
    assert_eq!(outcome(identity, &token(&next)), Ok(()));
    assert_eq!(outcome(identity, &kept), Err(VerifyError::UnknownKeyId));
}

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// The log of every test in this file. A global subscriber, not one per test: a callsite
    /// first reached on another test's thread could otherwise be cached as having no interest.
    fn global() -> &'static Self {
        static CAPTURED: OnceLock<Captured> = OnceLock::new();
        CAPTURED.get_or_init(|| {
            let captured = Captured::default();
            let writer = captured.clone();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            captured
        })
    }

    /// The fields of each line logged as `event` for `issuer`.
    fn events(&self, event: &str, issuer: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|line| line["fields"]["event"] == event && line["fields"]["issuer"] == issuer)
            .map(|line| {
                let mut fields = line["fields"].clone();
                fields["level"] = line["level"].clone();
                fields
            })
            .collect()
    }
}

/// The timer logs a failure once for each cause in a row, and a change of keys with the `kid`s
/// added and removed.
#[tokio::test]
async fn the_timer_logs_each_failure_once_and_each_change() {
    let captured = Captured::global();
    let listed = Counting::start().await;
    let issuer = issuer_at(&listed);
    let next = LocalIssuer::new(&listed.url, SigningAlgorithm::Es256).unwrap();
    listed.serve(issuer.jwks_document());
    let mut deployment = deployment(
        "keys-refresh-logs",
        &fetched_issuer(&listed.url, &listed.keys_url(), ""),
    );
    deployment.keys_urls[0].refresh = Duration::from_millis(20);
    let prepared = boot(deployment).await.unwrap();
    let refreshing = tokio::spawn(prepared.keys.run());

    // The same set again changes nothing, and logs nothing.
    let at = listed.requests();
    until("refreshes of the same set", || listed.requests() >= at + 3).await;
    assert!(captured.events(REFRESHED_EVENT, &listed.url).is_empty());

    // Failing for one cause, then another.
    for (status, failures) in [
        (StatusCode::INTERNAL_SERVER_ERROR, 1),
        (StatusCode::SERVICE_UNAVAILABLE, 2),
    ] {
        listed.answer_with(status, "");
        let at = listed.requests();
        until("failed refreshes", || listed.requests() >= at + 4).await;
        let failed = captured.events(REFRESH_FAILED_EVENT, &listed.url);
        assert_eq!(failed.len(), failures, "{failed:?}");
        let last = &failed[failures - 1];
        assert_eq!(last["level"], "WARN");
        assert_eq!(last["issuer"], listed.url.as_str());
        assert!(
            last["cause"]
                .as_str()
                .unwrap()
                .contains(&status.as_u16().to_string()),
            "{last}"
        );
    }

    // A new key, the old one dropped: logged once, however often the same set comes back.
    listed.serve(next.jwks_document());
    until("the new key in force", || {
        !captured.events(REFRESHED_EVENT, &listed.url).is_empty()
    })
    .await;
    let at = listed.requests();
    until("refreshes after the change", || listed.requests() >= at + 3).await;
    let refreshed = captured.events(REFRESHED_EVENT, &listed.url);
    assert_eq!(refreshed.len(), 1, "{refreshed:?}");
    assert_eq!(refreshed[0]["level"], "INFO");
    assert_eq!(refreshed[0]["issuer"], listed.url.as_str());
    assert_eq!(refreshed[0]["added"], next.key_id());
    assert_eq!(refreshed[0]["removed"], issuer.key_id());
    assert_eq!(outcome(prepared.gates.identity(), &token(&next)), Ok(()));

    // After a success, a cause seen before is logged again.
    listed.answer_with(StatusCode::SERVICE_UNAVAILABLE, "");
    let at = listed.requests();
    until("failed refreshes", || listed.requests() >= at + 4).await;
    refreshing.abort();
    let failed = captured.events(REFRESH_FAILED_EVENT, &listed.url);
    assert_eq!(failed.len(), 3, "{failed:?}");
    assert_eq!(failed[1]["cause"], failed[2]["cause"]);
    assert_eq!(outcome(prepared.gates.identity(), &token(&next)), Ok(()));
}

#[tokio::test]
async fn boot_refuses_a_keys_url_off_the_issuer_https_or_unreachable() {
    let listed = Counting::start().await;
    let elsewhere = Counting::start().await;
    let issuer = issuer_at(&listed);
    listed.serve(issuer.jwks_document());
    elsewhere.serve(issuer.jwks_document());
    let port = listed.url.rsplit(':').next().unwrap();

    let refused = |name: &'static str, entry: String| async move {
        boot(deployment(name, &entry))
            .await
            .map(drop)
            .unwrap_err()
            .to_string()
    };

    // Another host, and another port: refused before anything is fetched.
    let said = refused(
        "keys-other-host",
        fetched_issuer(
            &listed.url,
            &format!("http://localhost:{port}{KEYS_PATH}"),
            "",
        ),
    )
    .await;
    assert!(said.contains("names host `localhost`"), "{said}");
    let said = refused(
        "keys-other-port",
        fetched_issuer(&listed.url, &elsewhere.keys_url(), ""),
    )
    .await;
    assert!(said.contains("names port"), "{said}");
    assert_eq!(listed.requests(), 0);
    assert_eq!(elsewhere.requests(), 0);

    // https, which this build cannot fetch.
    let said = refused(
        "keys-https",
        fetched_issuer(
            "https://issuer.switchboard.test",
            "https://issuer.switchboard.test/keys",
            "",
        ),
    )
    .await;
    assert_eq!(
        said,
        "the keys URL for issuer `https://issuer.switchboard.test` is https, and this gateway \
         cannot fetch keys over TLS yet (issue #88); give the issuer a keys_file instead"
    );

    // Nothing listening, and an answer that is not the keys.
    let said = refused(
        "keys-unreachable",
        fetched_issuer("http://127.0.0.1:1", "http://127.0.0.1:1/keys", ""),
    )
    .await;
    assert_eq!(
        said,
        "cannot fetch the keys of issuer `http://127.0.0.1:1` at boot: the keys URL could not be \
         reached"
    );
    listed.answer_with(StatusCode::INTERNAL_SERVER_ERROR, "");
    let said = refused(
        "keys-boot-500",
        fetched_issuer(&listed.url, &listed.keys_url(), ""),
    )
    .await;
    assert_eq!(
        said,
        format!(
            "cannot fetch the keys of issuer `{}` at boot: the keys URL answered with status \
             500, not 200; redirects are not followed",
            listed.url
        )
    );
    assert_eq!(listed.requests(), 1);
}
