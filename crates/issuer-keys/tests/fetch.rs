//! Fetching an issuer's keys from a local server that counts what it is asked.
//!
//! The server speaks just enough HTTP/1.1 to answer one request per connection, written out by
//! hand so a test can send a body without its end, or nothing at all. It records the head of
//! every request it reads, so a test can say no request reached it and which headers one had.
//! Over TLS it presents a certificate made when the test runs, signed by a CA made the same way:
//! no key is checked in.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use gateway_core::Issuer;
use issuer_keys::{
    DEFAULT_DEADLINE, DEFAULT_MAX_BODY_BYTES, FetchError, FetchOptions, KeySource, MAX_TOKEN_BYTES,
    SourceError, SourceFiles, TokenFault,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

/// What the server has seen: the head of every request it read, and the protocol each TLS
/// handshake agreed.
#[derive(Default)]
struct Seen {
    heads: Mutex<Vec<String>>,
    alpn: Mutex<Vec<Option<Vec<u8>>>>,
}

/// A local server answering every request with what `answer` gives for its path, over plain
/// HTTP or, given an acceptor, over TLS.
struct Server {
    address: SocketAddr,
    tls: bool,
    seen: Arc<Seen>,
}

impl Server {
    async fn start(answer: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        Self::listen(None, answer).await
    }

    async fn start_tls(
        acceptor: TlsAcceptor,
        answer: impl Fn(&str) -> Reply + Send + Sync + 'static,
    ) -> Self {
        Self::listen(Some(acceptor), answer).await
    }

    async fn listen(
        acceptor: Option<TlsAcceptor>,
        answer: impl Fn(&str) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = acceptor.is_some();
        let seen = Arc::new(Seen::default());
        let answer = Arc::new(answer);
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (answer, seen) = (Arc::clone(&answer), Arc::clone(&recorder));
                match acceptor.clone() {
                    None => {
                        tokio::spawn(serve(stream, answer, seen));
                    }
                    Some(acceptor) => {
                        tokio::spawn(async move {
                            // A handshake the client abandons is no request.
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let agreed = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                            seen.alpn.lock().unwrap().push(agreed);
                            serve(stream, answer, seen).await;
                        });
                    }
                }
            }
        });
        Self { address, tls, seen }
    }

    fn origin(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    /// The request line of every request read so far.
    fn requests(&self) -> Vec<String> {
        self.heads()
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    /// The whole head of every request read so far.
    fn heads(&self) -> Vec<String> {
        self.seen.heads.lock().unwrap().clone()
    }

    /// The `Authorization` header of every request read so far, if it had one.
    fn authorizations(&self) -> Vec<Option<String>> {
        self.heads()
            .iter()
            .map(|head| {
                head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                })
            })
            .collect()
    }

    /// The protocol each completed TLS handshake agreed by ALPN.
    fn alpn(&self) -> Vec<Option<Vec<u8>>> {
        self.seen.alpn.lock().unwrap().clone()
    }
}

async fn serve(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    answer: Arc<impl Fn(&str) -> Reply>,
    seen: Arc<Seen>,
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
    seen.heads.lock().unwrap().push(head);
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

/// A loopback port that refuses connections, held for as long as this lives. Keep it for as long
/// as the test connects to the port: once it is dropped, nothing holds the port for this test,
/// and another test in the same binary may listen on it.
#[must_use = "the port is held only while this lives"]
struct ClosedPort {
    port: u16,
    _held: socket2::Socket,
    _peer: std::net::TcpStream,
}

/// A port nothing listens on. A port that was only read and released could be taken meanwhile
/// by another test's server, which would then answer this test's requests (#179). So a socket
/// holds it: bound to it without SO_REUSEADDR, and connected to a peer of its own. A connection
/// to a port with no listener is refused, on Linux and macOS alike; a socket bound and never
/// listening would do on Linux, but macOS drops a connection to one. While it lives, Linux lets
/// no other socket bind the port. macOS still lets one that sets SO_REUSEADDR bind it by
/// number, but it hands out the ports for port 0, which the tests' servers bind, in order, and
/// skips this one.
fn closed_port() -> ClosedPort {
    use socket2::{Domain, Protocol, Socket, Type};
    let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    held.bind(&any.into()).unwrap();
    held.connect(&peer.local_addr().unwrap().into()).unwrap();
    let (accepted, _) = peer.accept().unwrap();
    let port = held
        .local_addr()
        .unwrap()
        .as_socket()
        .expect("an IPv4 address")
        .port();
    ClosedPort {
        port,
        _held: held,
        _peer: accepted,
    }
}

/// #179: a closed port refuses connections, and stays reserved while its guard lives: no socket
/// that does not set SO_REUSEADDR can bind it, and on Linux, where CI runs, not even one that
/// does, as tokio's listener does for the tests' servers.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_port_refuses_connections_and_stays_reserved_while_held() {
    let closed = closed_port();
    let address: SocketAddr = ([127, 0, 0, 1], closed.port).into();
    let error = tokio::net::TcpStream::connect(address).await.unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "{error}"
    );
    let plain = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    assert!(
        plain.bind(&address.into()).is_err(),
        "another socket bound the held port {}",
        closed.port
    );
    if cfg!(target_os = "linux") {
        assert!(
            TcpListener::bind(address).await.is_err(),
            "a listener bound the held port {}",
            closed.port
        );
    }
}

/// A directory of its own for one test's files, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "issuer-keys-fetch-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }

    /// Writes `contents` to the file `name` and gives its path.
    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A certificate chain and its key, for a test server to present.
struct Presented {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Presented {
    /// A TLS acceptor presenting this chain, offering HTTP/2 before HTTP/1.1, so a client
    /// that offered HTTP/2 would agree it.
    fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }
}

/// A CA made for one test.
struct TestCa {
    pem: String,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self {
            pem,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A leaf for `names`, each a DNS name or an IP address, signed by this CA.
    fn leaf(&self, names: &[&str]) -> Presented {
        let params = leaf_params(names);
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        Presented {
            chain: vec![certificate.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }

    /// Writes this CA's certificate, as PEM, into `scratch`.
    fn file(&self, scratch: &Scratch) -> PathBuf {
        scratch.write("ca.pem", &self.pem)
    }
}

fn leaf_params(names: &[&str]) -> CertificateParams {
    let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    CertificateParams::new(names).unwrap()
}

/// A leaf for `names` signed by its own key, with no CA.
fn self_signed(names: &[&str]) -> Presented {
    let key = KeyPair::generate().unwrap();
    let certificate = leaf_params(names).self_signed(&key).unwrap();
    Presented {
        chain: vec![certificate.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

/// The source for `server`'s keys URL, trusting the CA in `ca_file`, with `token_file` if
/// given.
fn tls_source(server: &Server, ca_file: &Path, token_file: Option<&Path>) -> KeySource {
    tls_source_at(&server.origin(), server, ca_file, token_file)
}

/// The same, with the issuer and keys URL at `origin`, which names `server`'s port.
fn tls_source_at(
    origin: &str,
    server: &Server,
    ca_file: &Path,
    token_file: Option<&Path>,
) -> KeySource {
    assert!(origin.ends_with(&format!(":{}", server.address.port())));
    let files = SourceFiles {
        ca_file: Some(ca_file.to_owned()),
        token_file: token_file.map(Path::to_owned),
    };
    KeySource::with_files(
        &issuer(origin),
        &format!("{origin}{KEYS_PATH}"),
        &files,
        FetchOptions::default(),
    )
    .unwrap()
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
    // No token file, no token.
    assert_eq!(server.authorizations(), vec![None]);
}

/// A Kubernetes API server serves its keys only as `application/jwk-set+json`, and answers
/// `406` to a request that does not accept it (#88). Each fetch accepts it first, and plain
/// JSON for other issuers.
#[tokio::test(flavor = "multi_thread")]
async fn a_fetch_accepts_a_jwk_set_as_kubernetes_serves_it() {
    let server = Server::start(|_| Reply::ok(KEYS)).await;
    source(&server, FetchOptions::default())
        .fetch()
        .await
        .unwrap();
    let accepts: Vec<Option<String>> = server
        .heads()
        .iter()
        .map(|head| {
            head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("accept")
                    .then(|| value.trim().to_owned())
            })
        })
        .collect();
    assert_eq!(
        accepts,
        vec![Some(
            "application/jwk-set+json, application/json".to_owned()
        )]
    );
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
fn an_https_source_needs_a_ca_file() {
    let refused = KeySource::new(
        &issuer("https://kubernetes.default.svc"),
        "https://kubernetes.default.svc/openid/v1/jwks",
        FetchOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(refused, SourceError::NoCaFile(_)), "{refused:?}");
}

#[test]
fn an_http_source_takes_no_ca_file_and_no_token_file() {
    let scratch = Scratch::new("http-files");
    let ca_file = TestCa::new().file(&scratch);
    let token_file = scratch.write("token", "dummy-token-for-test\n");
    let issuer = issuer("http://keys.example");
    let with = |files: SourceFiles| {
        KeySource::with_files(
            &issuer,
            "http://keys.example/jwks",
            &files,
            FetchOptions::default(),
        )
    };
    let refused = with(SourceFiles {
        ca_file: Some(ca_file),
        token_file: None,
    })
    .unwrap_err();
    assert!(
        matches!(refused, SourceError::CaFileForHttp(_)),
        "{refused:?}"
    );
    let refused = with(SourceFiles {
        ca_file: None,
        token_file: Some(token_file),
    })
    .unwrap_err();
    assert!(
        matches!(refused, SourceError::TokenForHttp(_)),
        "{refused:?}"
    );
    assert!(!refused.to_string().contains("dummy-token"), "{refused}");
}

#[test]
fn a_ca_file_that_cannot_be_read_is_not_pem_or_holds_no_certificate_is_refused() {
    let scratch = Scratch::new("ca-files");
    let issuer = issuer("https://keys.example");
    let with_ca = |ca_file: PathBuf| {
        KeySource::with_files(
            &issuer,
            "https://keys.example/jwks",
            &SourceFiles {
                ca_file: Some(ca_file),
                token_file: None,
            },
            FetchOptions::default(),
        )
        .unwrap_err()
    };
    let refused = with_ca(scratch.0.join("missing.pem"));
    assert!(
        matches!(&refused, SourceError::CaUnreadable { path, .. } if path.ends_with("missing.pem")),
        "{refused:?}"
    );
    for (name, contents) in [
        ("empty", ""),
        ("text", "not a certificate bundle\n"),
        ("unterminated", "-----BEGIN CERTIFICATE-----\nZHVtbXk=\n"),
    ] {
        let refused = with_ca(scratch.write(name, contents));
        assert!(
            matches!(refused, SourceError::CaNotPem { .. }),
            "{name}: {refused:?}"
        );
    }
    // A good certificate does not excuse a broken section after it.
    let broken_after = format!(
        "{}-----BEGIN CERTIFICATE-----\nZHVtbXk=\n",
        TestCa::new().pem
    );
    let refused = with_ca(scratch.write("broken-after", &broken_after));
    assert!(
        matches!(refused, SourceError::CaNotPem { .. }),
        "{refused:?}"
    );
    let refused = with_ca(scratch.write(
        "public-key",
        "-----BEGIN PUBLIC KEY-----\nZHVtbXk=\n-----END PUBLIC KEY-----\n",
    ));
    assert!(
        matches!(refused, SourceError::CaNoCertificate { .. }),
        "{refused:?}"
    );
    let refused = with_ca(scratch.write(
        "bad-certificate",
        "-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----\n",
    ));
    assert!(
        matches!(refused, SourceError::CaBadCertificate { .. }),
        "{refused:?}"
    );
    // A bundle with a certificate is taken.
    let ca_file = TestCa::new().file(&scratch);
    assert!(
        KeySource::with_files(
            &issuer,
            "https://keys.example/jwks",
            &SourceFiles {
                ca_file: Some(ca_file),
                token_file: None,
            },
            FetchOptions::default(),
        )
        .is_ok()
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
    // Another host name, as well as another port.
    let location = format!("http://localhost:{}{KEYS_PATH}", elsewhere.address.port());
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
    let closed = closed_port();
    let origin = format!("http://127.0.0.1:{}", closed.port);
    let source = KeySource::new(
        &issuer(&origin),
        &format!("{origin}{KEYS_PATH}"),
        FetchOptions::default(),
    )
    .unwrap();
    assert_eq!(source.fetch().await.unwrap_err(), FetchError::Unreachable);
}

// --- Over TLS: only the configured CA, for the keys URL's own name ----------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_https_fetch_trusting_the_servers_ca_returns_the_set_over_http_1_1() {
    let scratch = Scratch::new("right-ca");
    let ca = TestCa::new();
    // The keys URL names an IP address, which the certificate must name as one.
    let server = Server::start_tls(ca.leaf(&["127.0.0.1"]).acceptor(), |_| Reply::ok(KEYS)).await;
    let keys = tls_source(&server, &ca.file(&scratch), None)
        .fetch()
        .await
        .unwrap();
    assert_eq!(keys.keys[0].common.key_id.as_deref(), Some("test-key-1"));
    assert_eq!(server.requests(), vec![format!("GET {KEYS_PATH} HTTP/1.1")]);
    assert_eq!(server.authorizations(), vec![None]);
    // The server prefers HTTP/2; the client offered only HTTP/1.1.
    assert_eq!(server.alpn(), vec![Some(b"http/1.1".to_vec())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_https_fetch_by_dns_name_returns_the_set() {
    let scratch = Scratch::new("dns-name");
    let ca = TestCa::new();
    let server = Server::start_tls(ca.leaf(&["localhost"]).acceptor(), |_| Reply::ok(KEYS)).await;
    let origin = format!("https://localhost:{}", server.address.port());
    let source = tls_source_at(&origin, &server, &ca.file(&scratch), None);
    assert!(source.fetch().await.is_ok());
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_from_another_ca_or_self_signed_fails_with_no_request_read() {
    let scratch = Scratch::new("wrong-ca");
    let trusted = TestCa::new();
    let other = TestCa::new();
    for presented in [other.leaf(&["127.0.0.1"]), self_signed(&["127.0.0.1"])] {
        let server = Server::start_tls(presented.acceptor(), |_| Reply::ok(KEYS)).await;
        let failed = tls_source(&server, &trusted.file(&scratch), None)
            .fetch()
            .await
            .unwrap_err();
        assert_eq!(failed, FetchError::Unreachable);
        assert!(server.requests().is_empty(), "{:?}", server.requests());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_for_another_name_fails_with_no_request_read() {
    let scratch = Scratch::new("other-name");
    let ca = TestCa::new();
    let ca_file = ca.file(&scratch);
    // Fetched by IP address: a DNS name, or another address, is not that address.
    for names in [&["localhost"][..], &["127.0.0.2"]] {
        let server = Server::start_tls(ca.leaf(names).acceptor(), |_| Reply::ok(KEYS)).await;
        let failed = tls_source(&server, &ca_file, None)
            .fetch()
            .await
            .unwrap_err();
        assert_eq!(failed, FetchError::Unreachable, "{names:?}");
        assert!(server.requests().is_empty(), "{names:?}");
    }
    // Fetched by DNS name: an address, or another name, is not that name.
    let server = Server::start_tls(ca.leaf(&["127.0.0.1", "keys.example"]).acceptor(), |_| {
        Reply::ok(KEYS)
    })
    .await;
    let origin = format!("https://localhost:{}", server.address.port());
    let failed = tls_source_at(&origin, &server, &ca_file, None)
        .fetch()
        .await
        .unwrap_err();
    assert_eq!(failed, FetchError::Unreachable);
    assert!(server.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_http_server_behind_an_https_url_fails() {
    let scratch = Scratch::new("plain-behind-https");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            // Answers in plain HTTP at once, whatever the client sent.
            let reply = Reply::ok(KEYS);
            let _ = stream.write_all(&reply.bytes).await;
        }
    });
    let origin = format!("https://{address}");
    let source = KeySource::with_files(
        &issuer(&origin),
        &format!("{origin}{KEYS_PATH}"),
        &SourceFiles {
            ca_file: Some(TestCa::new().file(&scratch)),
            token_file: None,
        },
        FetchOptions::default(),
    )
    .unwrap();
    assert_eq!(source.fetch().await.unwrap_err(), FetchError::Unreachable);
}

#[tokio::test(start_paused = true)]
async fn a_handshake_that_stalls_fails_at_the_default_deadline() {
    let scratch = Scratch::new("stalled-handshake");
    // Accepts the connection and never answers the client's hello.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let origin = format!("https://{address}");
    let source = KeySource::with_files(
        &issuer(&origin),
        &format!("{origin}{KEYS_PATH}"),
        &SourceFiles {
            ca_file: Some(TestCa::new().file(&scratch)),
            token_file: None,
        },
        FetchOptions::default(),
    )
    .unwrap();
    let started = tokio::time::Instant::now();
    let failed = tokio::time::timeout(Duration::from_secs(60), source.fetch())
        .await
        .expect("the fetch was not abandoned at its deadline")
        .unwrap_err();
    assert_eq!(failed, FetchError::Deadline(DEFAULT_DEADLINE));
    assert_eq!(started.elapsed(), DEFAULT_DEADLINE);
}

// --- The token ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_sent_to_the_keys_url_and_read_again_on_every_fetch() {
    let scratch = Scratch::new("token");
    let ca = TestCa::new();
    let server = Server::start_tls(ca.leaf(&["127.0.0.1"]).acceptor(), |_| Reply::ok(KEYS)).await;
    let token_file = scratch.write("token", "  dummy-token-first\n");
    let source = tls_source(&server, &ca.file(&scratch), Some(&token_file));
    source.fetch().await.unwrap();
    // Rotated in place, as the kubelet rotates a projected token.
    scratch.write("token", "dummy-token-second\n");
    source.fetch().await.unwrap();
    assert_eq!(
        server.authorizations(),
        vec![
            Some("Bearer dummy-token-first".to_owned()),
            Some("Bearer dummy-token-second".to_owned()),
        ]
    );
    assert!(
        server
            .requests()
            .iter()
            .all(|line| line.contains(KEYS_PATH))
    );
    assert!(!format!("{source:?}").contains("dummy-token"), "{source:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_file_that_holds_no_token_sends_no_request() {
    let scratch = Scratch::new("bad-token");
    let ca = TestCa::new();
    let server = Server::start_tls(ca.leaf(&["127.0.0.1"]).acceptor(), |_| Reply::ok(KEYS)).await;
    let ca_file = ca.file(&scratch);
    let too_large = "x".repeat(8 * 1024 + 1);
    for (name, contents, fault) in [
        ("empty", Some(" \n"), TokenFault::Empty),
        (
            "two-words",
            Some("dummy-token one\n"),
            TokenFault::NotAToken,
        ),
        ("too-large", Some(too_large.as_str()), TokenFault::TooLarge),
        ("missing", None, TokenFault::Unreadable),
    ] {
        let token_file = match contents {
            Some(contents) => scratch.write(name, contents),
            None => scratch.0.join(name),
        };
        let failed = tls_source(&server, &ca_file, Some(&token_file))
            .fetch()
            .await
            .unwrap_err();
        assert_eq!(failed, FetchError::Token(fault), "{name}");
        assert!(!failed.to_string().contains("dummy-token"), "{failed}");
    }
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_of_exactly_the_limit_is_sent() {
    let scratch = Scratch::new("token-at-limit");
    let ca = TestCa::new();
    let server = Server::start_tls(ca.leaf(&["127.0.0.1"]).acceptor(), |_| Reply::ok(KEYS)).await;
    let at_limit = "x".repeat(usize::try_from(MAX_TOKEN_BYTES).unwrap());
    let token_file = scratch.write("token", &at_limit);
    tls_source(&server, &ca.file(&scratch), Some(&token_file))
        .fetch()
        .await
        .unwrap();
    assert_eq!(
        server.authorizations(),
        vec![Some(format!("Bearer {at_limit}"))]
    );
}

/// A token file that never ends: a pipe whose writer sends one byte past the limit and then
/// holds it open. The source stops reading one byte past the limit and refuses the file; a read
/// with no bound would wait for an end that never comes. Nothing is sent either way, so the keys
/// URL names a host that is never reached.
#[test]
fn a_token_file_that_never_ends_is_refused_one_byte_past_the_limit() {
    let scratch = Scratch::new("token-never-ends");
    let ca_file = TestCa::new().file(&scratch);
    let path = scratch.0.join("token");
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");

    let (release, held) = mpsc::channel::<()>();
    let writer = std::thread::spawn({
        let path = path.clone();
        move || {
            let mut pipe = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            let size = usize::try_from(MAX_TOKEN_BYTES).unwrap() + 1;
            pipe.write_all(&vec![b'x'; size]).unwrap();
            // Holds the pipe open, so the file has no end, until the test is done.
            let _ = held.recv();
        }
    });
    let source = KeySource::with_files(
        &issuer("https://keys.example"),
        "https://keys.example/jwks",
        &SourceFiles {
            ca_file: Some(ca_file),
            token_file: Some(path),
        },
        FetchOptions::default(),
    )
    .unwrap();
    let (done, finished) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = done.send(runtime.block_on(source.fetch()));
    });

    let failed = finished.recv_timeout(Duration::from_secs(10));
    drop(release);

    let failed = failed.expect("the source is still waiting for the end of the token file");
    assert_eq!(failed.unwrap_err(), FetchError::Token(TokenFault::TooLarge));
    writer.join().unwrap();
}

// --- Over TLS, redirects are still never followed -----------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn over_tls_a_redirect_to_another_host_is_not_followed() {
    let scratch = Scratch::new("tls-redirect-host");
    let ca = TestCa::new();
    // The certificate names both hosts, so a client that followed would be let in.
    let leaf = ca.leaf(&["127.0.0.1", "localhost"]);
    let port = Arc::new(Mutex::new(0_u16));
    let at = Arc::clone(&port);
    let server = Server::start_tls(leaf.acceptor(), move |path| {
        if path == KEYS_PATH {
            Reply::redirect(&format!("https://localhost:{}/moved", at.lock().unwrap()))
        } else {
            Reply::ok(KEYS)
        }
    })
    .await;
    *port.lock().unwrap() = server.address.port();
    let failed = tls_source(&server, &ca.file(&scratch), None)
        .fetch()
        .await
        .unwrap_err();
    assert_eq!(failed, FetchError::Status(302));
    assert_eq!(server.requests(), vec![format!("GET {KEYS_PATH} HTTP/1.1")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn over_tls_a_redirect_to_another_port_is_not_followed() {
    let scratch = Scratch::new("tls-redirect-port");
    let ca = TestCa::new();
    let leaf = ca.leaf(&["127.0.0.1", "localhost"]);
    let elsewhere = Server::start_tls(leaf.acceptor(), |_| Reply::ok(KEYS)).await;
    let location = elsewhere.url(KEYS_PATH);
    let server = Server::start_tls(leaf.acceptor(), move |_| Reply::redirect(&location)).await;
    let failed = tls_source(&server, &ca.file(&scratch), None)
        .fetch()
        .await
        .unwrap_err();
    assert_eq!(failed, FetchError::Status(302));
    assert_eq!(server.requests().len(), 1);
    assert!(elsewhere.requests().is_empty());
}
