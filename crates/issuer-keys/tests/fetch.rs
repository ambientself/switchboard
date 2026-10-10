//! Fetching an issuer's keys from a local server that counts what it is asked.
//!
//! The server speaks just enough HTTP/1.1 to answer one request per connection, written out by
//! hand so a test can send a body without its end, or nothing at all. It records the request
//! line of every request it reads, so a test can say no request reached it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gateway_core::Issuer;
use issuer_keys::{
    DEFAULT_DEADLINE, DEFAULT_MAX_BODY_BYTES, FetchError, FetchOptions, KeySource, SourceError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The path a Kubernetes API server publishes its keys at.
const KEYS_PATH: &str = "/openid/v1/jwks";

/// A JWK set with one RSA key. The modulus is a dummy: parsing a set does not decode it.
const KEYS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"ZHVtbXk","e":"AQAB"}]}"#;

/// What the server writes for one request, and whether it then holds the connection open
/// without writing anything more.
#[derive(Clone)]
struct Reply {
    bytes: Vec<u8>,
    stall: bool,
}

impl Reply {
    fn status(code: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> Self {
        let mut head = format!("HTTP/1.1 {code} {reason}\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ));
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        Self {
            bytes,
            stall: false,
        }
    }

    fn ok(body: &str) -> Self {
        Self::status(
            200,
            "OK",
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    fn redirect(location: &str) -> Self {
        Self::status(302, "Found", &[("Location", location)], b"")
    }

    /// A `200` head and then `bytes` of body in one chunk, with no end: the body never
    /// finishes.
    fn chunked_without_end(bytes: usize) -> Self {
        let mut written =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        written.extend_from_slice(format!("{bytes:x}\r\n").as_bytes());
        written.extend(std::iter::repeat_n(b' ', bytes));
        written.extend_from_slice(b"\r\n");
        Self {
            bytes: written,
            stall: true,
        }
    }

    /// A `200` head declaring `length` bytes of body, and then only `sent` of them.
    fn declared_then_stall(length: usize, sent: usize) -> Self {
        let mut written = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n"
        )
        .into_bytes();
        written.extend(std::iter::repeat_n(b' ', sent));
        Self {
            bytes: written,
            stall: true,
        }
    }

    /// Reads the request and never answers.
    fn silence() -> Self {
        Self {
            bytes: Vec::new(),
            stall: true,
        }
    }
}

/// A local server answering every request with what `answer` gives for its path.
struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server {
    async fn start(answer: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(answer);
        let seen = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, Arc::clone(&answer), Arc::clone(&seen)));
            }
        });
        Self { address, requests }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    /// The request line of every request read so far.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

async fn serve(
    mut stream: TcpStream,
    answer: Arc<impl Fn(&str) -> Reply>,
    seen: Arc<Mutex<Vec<String>>>,
) {
    let mut head = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let line = head.lines().next().unwrap_or_default().to_owned();
    let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
    seen.lock().unwrap().push(line);
    let reply = answer(&path);
    if stream.write_all(&reply.bytes).await.is_err() {
        return;
    }
    if reply.stall {
        // Hold the connection open, writing nothing more, until the test ends.
        std::future::pending::<()>().await;
    }
    let _ = stream.shutdown().await;
}

fn issuer(origin: &str) -> Issuer {
    Issuer::new(origin)
}

fn source(server: &Server, options: FetchOptions) -> KeySource {
    KeySource::new(&issuer(&server.origin()), &server.url(KEYS_PATH), options).unwrap()
}

/// A port nothing listens on: bound, read, and released.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// --- The happy path -------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_is_one_get_to_the_keys_url_and_returns_the_set() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    let keys = source(&server, FetchOptions::default())
        .fetch()
        .await
        .unwrap();
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].common.key_id.as_deref(), Some("test-key-1"));
    assert_eq!(server.requests(), vec![format!("GET {KEYS_PATH} HTTP/1.1")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn each_fetch_is_one_request() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    let source = source(&server, FetchOptions::default());
    source.fetch().await.unwrap();
    source.fetch().await.unwrap();
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn the_defaults_are_five_seconds_and_256_kib() {
    assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(5));
    assert_eq!(DEFAULT_MAX_BODY_BYTES, 256 * 1024);
    assert_eq!(
        FetchOptions::default(),
        FetchOptions {
            deadline: DEFAULT_DEADLINE,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    );
}

// --- The source rules: only the issuer's own origin -----------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_keys_url_on_another_host_is_refused_and_never_requested() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    let other = format!("http://localhost:{}{KEYS_PATH}", server.address.port());
    let refused =
        KeySource::new(&issuer(&server.origin()), &other, FetchOptions::default()).unwrap_err();
    assert!(
        matches!(&refused, SourceError::OtherHost { found, .. } if found == "localhost"),
        "{refused:?}"
    );
    assert!(server.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keys_url_on_another_port_is_refused_and_never_requested() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    let other = Server::start(|_| Reply::ok(KEYS)).await;
    let refused = KeySource::new(
        &issuer(&server.origin()),
        &other.url(KEYS_PATH),
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(refused, SourceError::OtherPort { found, .. } if found == other.address.port()),
        "{refused:?}"
    );
    assert!(server.requests().is_empty());
    assert!(other.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_port_counts_as_that_port() {
    // `http://h` and `http://h:80` are one origin; `http://h:8080` is another.
    let issuer = issuer("http://keys.example");
    assert!(
        KeySource::new(
            &issuer,
            "http://keys.example:80/jwks",
            FetchOptions::default()
        )
        .is_ok()
    );
    let refused = KeySource::new(
        &issuer,
        "http://keys.example:8080/jwks",
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(
            refused,
            SourceError::OtherPort {
                expected: 80,
                found: 8080,
                ..
            }
        ),
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_keys_url_for_an_https_issuer_is_refused_and_never_requested() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    // The same host and port as the server, so only the scheme differs.
    let https_issuer = issuer(&format!("https://{}", server.address));
    let refused = KeySource::new(
        &https_issuer,
        &server.url(KEYS_PATH),
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(&refused, SourceError::OtherScheme { expected, found, .. }
            if expected == "https" && found == "http"),
        "{refused:?}"
    );
    assert!(server.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_https_keys_url_for_an_http_issuer_is_refused() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    let other = format!("https://{}{KEYS_PATH}", server.address);
    let refused =
        KeySource::new(&issuer(&server.origin()), &other, FetchOptions::default()).unwrap_err();
    assert!(
        matches!(refused, SourceError::OtherScheme { .. }),
        "{refused:?}"
    );
    assert!(server.requests().is_empty());
}

#[test]
fn an_https_source_is_refused_while_there_is_no_tls_client() {
    let refused = KeySource::new(
        &issuer("https://kubernetes.default.svc"),
        "https://kubernetes.default.svc/openid/v1/jwks",
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(refused, SourceError::TlsUnavailable(_)),
        "{refused:?}"
    );
}

#[test]
fn a_keys_url_with_a_user_name_or_password_is_refused_without_repeating_it() {
    let issuer = issuer("http://keys.example");
    for url in [
        "http://someone@keys.example/jwks",
        "http://someone:dummy-password@keys.example/jwks",
    ] {
        let refused = KeySource::new(&issuer, url, FetchOptions::default()).unwrap_err();
        assert!(matches!(refused, SourceError::UserInfo(_)), "{refused:?}");
        assert!(!refused.to_string().contains("someone"), "{refused}");
        assert!(!refused.to_string().contains("dummy-password"), "{refused}");
    }
}

#[test]
fn a_keys_url_with_a_fragment_is_refused() {
    let refused = KeySource::new(
        &issuer("http://keys.example"),
        "http://keys.example/jwks#elsewhere",
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(refused, SourceError::Fragment(_)), "{refused:?}");
}

#[test]
fn an_issuer_that_is_not_an_http_origin_is_refused() {
    for issuer_string in [
        "not a url",
        "spiffe://cluster.local",
        "http://someone@keys.example",
    ] {
        let refused = KeySource::new(
            &issuer(issuer_string),
            "http://keys.example/jwks",
            FetchOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(refused, SourceError::IssuerNotAnOrigin(_)),
            "{issuer_string}: {refused:?}"
        );
    }
}

#[test]
fn a_keys_url_that_is_not_a_url_is_refused() {
    let refused = KeySource::new(
        &issuer("http://keys.example"),
        "/openid/v1/jwks",
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(refused, SourceError::NotAUrl(_)), "{refused:?}");
}

#[test]
fn a_zero_deadline_or_cap_is_refused() {
    let issuer = issuer("http://keys.example");
    let zero_deadline = FetchOptions {
        deadline: Duration::ZERO,
        ..FetchOptions::default()
    };
    let zero_cap = FetchOptions {
        max_body_bytes: 0,
        ..FetchOptions::default()
    };
    assert!(matches!(
        KeySource::new(&issuer, "http://keys.example/jwks", zero_deadline),
        Err(SourceError::ZeroDeadline(_))
    ));
    assert!(matches!(
        KeySource::new(&issuer, "http://keys.example/jwks", zero_cap),
        Err(SourceError::ZeroCap(_))
    ));
}

// --- Redirects are never followed -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_to_the_same_host_is_not_followed() {
    let server = Server::start(|path| {
        if path == KEYS_PATH {
            Reply::redirect("/moved")
        } else {
            Reply::ok(KEYS)
        }
    })
    .await;
    let failed = source(&server, FetchOptions::default())
        .fetch()
        .await
        .unwrap_err();
    assert_eq!(failed, FetchError::Status(302));
    assert_eq!(server.requests(), vec![format!("GET {KEYS_PATH} HTTP/1.1")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_to_another_host_is_not_followed() {
    let elsewhere = Server::start(|_| Reply::ok(KEYS)).await;
    let location = elsewhere.url(KEYS_PATH);
    let server = Server::start(move |_| Reply::redirect(&location)).await;
    let failed = source(&server, FetchOptions::default())
        .fetch()
        .await
        .unwrap_err();
    assert_eq!(failed, FetchError::Status(302));
    assert_eq!(server.requests().len(), 1);
    assert!(elsewhere.requests().is_empty());
}

// --- The body cap -----------------------------------------------------------------------------

/// A deadline long enough that only a body read past its cap reaches it.
const PATIENT: Duration = Duration::from_secs(3);

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_body_over_the_cap_fails_before_it_ends() {
    // The body never ends, so a fetch that kept reading would wait for the deadline.
    let server = Server::start(|_| Reply::chunked_without_end(1025)).await;
    let options = FetchOptions {
        deadline: PATIENT,
        max_body_bytes: 1024,
    };
    let failed = source(&server, options).fetch().await.unwrap_err();
    assert_eq!(failed, FetchError::TooLarge { cap: 1024 });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_body_over_the_default_cap_fails_before_it_ends() {
    let server = Server::start(|_| Reply::chunked_without_end(DEFAULT_MAX_BODY_BYTES + 1)).await;
    let options = FetchOptions {
        deadline: PATIENT,
        ..FetchOptions::default()
    };
    let failed = source(&server, options).fetch().await.unwrap_err();
    assert_eq!(
        failed,
        FetchError::TooLarge {
            cap: DEFAULT_MAX_BODY_BYTES
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_length_over_the_cap_fails_before_any_body_is_read() {
    // The head declares one byte too many and no body follows.
    let server = Server::start(|_| Reply::declared_then_stall(1025, 0)).await;
    let options = FetchOptions {
        deadline: PATIENT,
        max_body_bytes: 1024,
    };
    let failed = source(&server, options).fetch().await.unwrap_err();
    assert_eq!(failed, FetchError::TooLarge { cap: 1024 });
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_of_exactly_the_cap_is_read() {
    let cap = 1024;
    let padded = format!("{KEYS:<cap$}");
    assert_eq!(padded.len(), cap);
    let server = Server::start(move |_| Reply::ok(&padded)).await;
    let options = FetchOptions {
        deadline: PATIENT,
        max_body_bytes: cap,
    };
    assert!(source(&server, options).fetch().await.is_ok());
}

// --- The deadline -----------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_server_that_never_answers_fails_at_the_default_deadline() {
    let server = Server::start(|_| Reply::silence()).await;
    let source = source(&server, FetchOptions::default());
    let started = tokio::time::Instant::now();
    // Bounded here too, so a fetch with no deadline fails the test instead of hanging it.
    let failed = tokio::time::timeout(Duration::from_secs(60), source.fetch())
        .await
        .expect("the fetch was not abandoned at its deadline")
        .unwrap_err();
    assert_eq!(failed, FetchError::Deadline(DEFAULT_DEADLINE));
    assert_eq!(started.elapsed(), DEFAULT_DEADLINE);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_stalls_after_the_head_fails_at_the_deadline() {
    // The head and part of the body arrive at once; the rest never does.
    let server = Server::start(|_| Reply::declared_then_stall(512, 16)).await;
    let deadline = Duration::from_millis(500);
    let options = FetchOptions {
        deadline,
        ..FetchOptions::default()
    };
    let source = source(&server, options);
    let started = std::time::Instant::now();
    let failed = tokio::time::timeout(Duration::from_secs(10), source.fetch())
        .await
        .expect("the fetch was not abandoned at its deadline")
        .unwrap_err();
    assert_eq!(failed, FetchError::Deadline(deadline));
    assert!(started.elapsed() >= deadline);
    assert_eq!(server.requests().len(), 1);
}

// --- What counts as keys ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_status_other_than_200_is_an_error() {
    for (code, reason) in [
        (500, "Internal Server Error"),
        (404, "Not Found"),
        (204, "No Content"),
    ] {
        let server =
            Server::start(move |_| Reply::status(code, reason, &[], KEYS.as_bytes())).await;
        let failed = source(&server, FetchOptions::default())
            .fetch()
            .await
            .unwrap_err();
        assert_eq!(failed, FetchError::Status(code));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_is_not_json_is_an_error_that_does_not_repeat_it() {
    let server = Server::start(|_| Reply::ok("dummy-body-marker, not json")).await;
    let failed = source(&server, FetchOptions::default())
        .fetch()
        .await
        .unwrap_err();
    assert!(matches!(failed, FetchError::NotJson(_)), "{failed:?}");
    assert!(
        !failed.to_string().contains("dummy-body-marker"),
        "{failed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn json_that_is_not_a_jwk_set_is_an_error_that_does_not_repeat_it() {
    for body in [
        r#"{"keys": "dummy-body-marker"}"#,
        r#"{"dummy-body-marker": []}"#,
        r#"["dummy-body-marker"]"#,
    ] {
        let server = Server::start(move |_| Reply::ok(body)).await;
        let failed = source(&server, FetchOptions::default())
            .fetch()
            .await
            .unwrap_err();
        assert!(
            matches!(failed, FetchError::NotAJwkSet(_)),
            "{body}: {failed:?}"
        );
        assert!(
            !failed.to_string().contains("dummy-body-marker"),
            "{failed}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_breaks_off_is_an_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n{\"keys\":")
            .await;
        // Dropped: the connection closes with the body unfinished.
    });
    let origin = format!("http://{address}");
    let source = KeySource::new(
        &issuer(&origin),
        &format!("{origin}{KEYS_PATH}"),
        FetchOptions::default(),
    )
    .unwrap();
    assert_eq!(source.fetch().await.unwrap_err(), FetchError::BrokenOff);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_is_not_there_is_unreachable() {
    let origin = format!("http://127.0.0.1:{}", closed_port().await);
    let source = KeySource::new(
        &issuer(&origin),
        &format!("{origin}{KEYS_PATH}"),
        FetchOptions::default(),
    )
    .unwrap();
    assert_eq!(source.fetch().await.unwrap_err(), FetchError::Unreachable);
}
