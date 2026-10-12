//! Where the connector connects, and how it uses a connection (decision 0013, sections 2 to 4):
//! an `https` server's certificate verified against its identity with only its CA file, each
//! address checked when it is connected to, no redirect followed, no request sent twice, and a
//! pool for each connector.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{GATEWAY_TOKEN, Harness, TemporaryFile, credentials_for, upstream};
use connector_proxy::{
    CaFault, CallVerdict, Destination, ListError, Loopback, NotShown, ProbeCall, ProbeCredential,
    ProxyConnector, Refusal, Upstream, UpstreamError, outcome, refusal,
};
use gateway_core::ConnectorName;
use gateway_core::audit::{Answer, ErrorKind, Outcome};
use gateway_testkit::{CONNECTOR, READ_TOOL};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const DEADLINE: Duration = Duration::from_secs(2);

fn arguments() -> Value {
    json!({"project": "atlas", "document": "plan"})
}

// --- Local servers ---------------------------------------------------------------------------

/// What a local server does with each connection.
#[derive(Clone)]
enum Serve {
    /// Answers every request on the connection, and keeps it open.
    Answer,
    /// Reads one request, and closes the connection without answering.
    ReadAndDrop,
    /// Answers every request with a redirect to this URL.
    Redirect(String),
}

/// A server on 127.0.0.1, over plain HTTP or, given an acceptor, TLS, counting the connections
/// it accepted and the requests it read. Stops when dropped.
struct Local {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Local {
    async fn start(serve: Serve, acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (accepted, read) = (connections.clone(), requests.clone());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let (serve, read, acceptor) = (serve.clone(), read.clone(), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        None => connection(stream, serve, read).await,
                        Some(acceptor) => {
                            // A handshake the client abandons is no request.
                            if let Ok(stream) = acceptor.accept(stream).await {
                                connection(stream, serve, read).await;
                            }
                        }
                    }
                });
            }
        });
        Self {
            address,
            connections,
            requests,
            task,
        }
    }

    /// The server's endpoint under `scheme` and `host`, with its port.
    fn url(&self, scheme: &str, host: &str) -> String {
        format!("{scheme}://{host}:{}/mcp", self.address.port())
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    serve: Serve,
    read: Arc<AtomicUsize>,
) {
    loop {
        let Some(body) = read_request(&mut stream).await else {
            return;
        };
        read.fetch_add(1, Ordering::SeqCst);
        let bytes = match &serve {
            Serve::ReadAndDrop => return,
            Serve::Answer => answer(&body),
            Serve::Redirect(location) => format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            )
            .into_bytes(),
        };
        if stream.write_all(&bytes).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
    }
}

/// Reads one request's head and body, and gives the body as JSON.
async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> Option<Value> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let length = content_length(&buffer[..head_end]);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    serde_json::from_slice(&body).ok()
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// A `200` answering `request`, kept alive: an empty tool list, or a tool result.
fn answer(request: &Value) -> Vec<u8> {
    let result = if request["method"] == "tools/list" {
        json!({"tools": []})
    } else {
        json!({"content": [{"type": "text", "text": "served"}], "isError": false})
    };
    let body = json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// --- Certificates ----------------------------------------------------------------------------

/// A certificate chain and its key, for a test server to present.
struct Presented {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Presented {
    /// A TLS acceptor presenting this chain, offering HTTP/1.1.
    fn acceptor(&self) -> TlsAcceptor {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
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
        let key = KeyPair::generate().unwrap();
        let certificate = leaf_params(names).signed_by(&key, &self.issuer).unwrap();
        Presented {
            chain: vec![certificate.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }

    /// This CA's certificate, as PEM, in a file of its own.
    fn file(&self) -> TemporaryFile {
        TemporaryFile::new(self.pem.as_bytes())
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

/// The fixture's connector to `url`, trusting the CA in `ca_file`.
fn over_tls(url: &str, ca_file: &TemporaryFile) -> ProxyConnector {
    common::connector(Upstream {
        ca_file: Some(ca_file.path().to_owned()),
        deadline: DEADLINE,
        ..upstream(url)
    })
}

// --- TLS -------------------------------------------------------------------------------------

/// The certificate is verified against the server's identity, the host in its URL, with the
/// CA file the deployment names; the call goes over HTTP/1.1 and is answered.
#[tokio::test]
async fn an_https_server_is_reached_with_its_ca_file() {
    let ca = TestCa::new();
    let ca_file = ca.file();
    let server = Local::start(Serve::Answer, Some(ca.leaf(&["localhost"]).acceptor())).await;
    let connector = over_tls(&server.url("https", "localhost"), &ca_file);

    assert_eq!(connector.list_tools().await, Ok(Vec::new()));
    let answer = Harness::new()
        .call(&connector, READ_TOOL, arguments())
        .await;
    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
    assert_eq!(server.requests(), 2);
}

/// A certificate from a CA the deployment did not name, or signed by its own key, fails the
/// handshake: no request is read, so neither the credential nor the call left the gateway.
#[tokio::test]
async fn a_certificate_from_another_ca_or_self_signed_fails_with_no_request_read() {
    let ca_file = TestCa::new().file();
    let other = TestCa::new();
    for presented in [other.leaf(&["localhost"]), self_signed(&["localhost"])] {
        let server = Local::start(Serve::Answer, Some(presented.acceptor())).await;
        let connector = over_tls(&server.url("https", "localhost"), &ca_file);

        assert_eq!(connector.list_tools().await, Err(ListError::Unreachable));
        let answer = Harness::new()
            .call(&connector, READ_TOOL, arguments())
            .await;
        assert_eq!(answer, Answer::Error(outcome::UNREACHABLE.to_owned()));
        assert_eq!(server.requests(), 0);
    }
}

/// A certificate for a name that is not the server's identity fails, even from the right CA:
/// one for another host, and one for `localhost` when the address names `127.0.0.1`.
#[tokio::test]
async fn a_certificate_for_another_name_fails_with_no_request_read() {
    let ca = TestCa::new();
    let ca_file = ca.file();
    for (names, host) in [
        (&["other.example.test"][..], "localhost"),
        (&["localhost"][..], "127.0.0.1"),
    ] {
        let server = Local::start(Serve::Answer, Some(ca.leaf(names).acceptor())).await;
        let connector = over_tls(&server.url("https", host), &ca_file);

        assert_eq!(
            connector.list_tools().await,
            Err(ListError::Unreachable),
            "{names:?} at {host}"
        );
        assert_eq!(server.requests(), 0, "{names:?} at {host}");
    }
    // The same CA's certificate for the address's own IP is accepted.
    let server = Local::start(Serve::Answer, Some(ca.leaf(&["127.0.0.1"]).acceptor())).await;
    let connector = over_tls(&server.url("https", "127.0.0.1"), &ca_file);
    assert_eq!(connector.list_tools().await, Ok(Vec::new()));
}

/// An `https` URL for a server that speaks plain HTTP fails: nothing is sent in the clear.
#[tokio::test]
async fn an_http_server_behind_an_https_url_fails() {
    let ca_file = TestCa::new().file();
    let server = Local::start(Serve::Answer, None).await;
    let connector = over_tls(&server.url("https", "localhost"), &ca_file);

    // This server waits for a request it never gets, so the handshake ends at the deadline.
    let listed = connector.list_tools().await;
    assert!(
        matches!(listed, Err(ListError::Unreachable | ListError::TimedOut)),
        "{listed:?}"
    );
    assert_eq!(server.requests(), 0);
}

/// A redirect is an answer like any other status, over TLS as over plain HTTP: the place it
/// names is never asked.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let ca = TestCa::new();
    let ca_file = ca.file();
    let elsewhere = Local::start(Serve::Answer, Some(ca.leaf(&["localhost"]).acceptor())).await;
    let redirect = Serve::Redirect(elsewhere.url("https", "localhost"));
    let server = Local::start(redirect, Some(ca.leaf(&["localhost"]).acceptor())).await;
    let connector = over_tls(&server.url("https", "localhost"), &ca_file);

    assert_eq!(connector.list_tools().await, Err(ListError::Status(307)));
    let answer = Harness::new()
        .call(&connector, READ_TOOL, arguments())
        .await;
    assert_eq!(answer, Answer::Error(outcome::status(307)));
    assert_eq!(server.requests(), 2);
    assert_eq!(elsewhere.connections(), 0);
}

/// An `https` URL needs a CA file that holds a certificate, and an `http` one takes none: only
/// an in-cluster server may use plain `http` at all.
#[test]
fn the_ca_file_is_required_for_https_and_refused_for_http() {
    let connector = ConnectorName::new(CONNECTOR);
    let refused = |upstream: Upstream| ProxyConnector::new(upstream, common::credentials());
    let https = "https://docs.example.test/mcp";
    let http = "http://docs.example.test/mcp";
    assert_eq!(
        refused(upstream(https)).unwrap_err(),
        UpstreamError::NoCaFile(connector.clone())
    );
    let ca_file = TestCa::new().file();
    assert_eq!(
        refused(Upstream {
            ca_file: Some(ca_file.path().to_owned()),
            ..upstream(http)
        })
        .unwrap_err(),
        UpstreamError::CaFileForHttp(connector.clone())
    );
    assert_eq!(
        refused(Upstream {
            destination: Destination::Public,
            ..upstream(http)
        })
        .unwrap_err(),
        UpstreamError::HttpNotInCluster(connector.clone())
    );
    assert!(
        refused(Upstream {
            destination: Destination::Public,
            ca_file: Some(ca_file.path().to_owned()),
            ..upstream(https)
        })
        .is_ok()
    );
    let missing = std::env::temp_dir().join("connector-proxy-no-such-ca.pem");
    let not_pem = TemporaryFile::new(b"not a certificate\n");
    let key_only = TemporaryFile::new(KeyPair::generate().unwrap().serialize_pem().as_bytes());
    for (path, fault) in [
        (missing.as_path(), CaFault::Unreadable),
        (not_pem.path(), CaFault::NotPem),
        (key_only.path(), CaFault::NoCertificate),
    ] {
        assert_eq!(
            refused(Upstream {
                ca_file: Some(path.to_owned()),
                ..upstream(https)
            })
            .unwrap_err(),
            UpstreamError::CaFile {
                connector: connector.clone(),
                path: path.to_owned(),
                fault,
            }
        );
    }
}

// --- Addresses -------------------------------------------------------------------------------

/// Decision 0013, section 3, address by address: what is always refused, what only an
/// in-cluster server may reach, and the IPv6 forms that carry an IPv4 address.
#[test]
fn each_range_is_refused_as_decision_0013_says() {
    use Refusal::{Broadcast, LinkLocal, Loopback as Lo, Multicast, Private, Unspecified};
    let always: [(&str, Refusal); 22] = [
        ("127.0.0.1", Lo),
        ("127.255.255.254", Lo),
        ("::1", Lo),
        ("0.0.0.0", Unspecified),
        ("0.1.2.3", Unspecified),
        ("::", Unspecified),
        ("169.254.169.254", LinkLocal),
        ("169.254.0.1", LinkLocal),
        ("fe80::1", LinkLocal),
        ("febf::1", LinkLocal),
        ("224.0.0.1", Multicast),
        ("239.255.255.250", Multicast),
        ("ff02::1", Multicast),
        ("255.255.255.255", Broadcast),
        // IPv4-mapped.
        ("::ffff:127.0.0.1", Lo),
        ("::ffff:169.254.169.254", LinkLocal),
        ("::ffff:0.0.0.0", Unspecified),
        ("::ffff:224.0.0.1", Multicast),
        ("::ffff:255.255.255.255", Broadcast),
        // IPv4-compatible.
        ("::127.0.0.1", Lo),
        ("::169.254.169.254", LinkLocal),
        ("::255.255.255.255", Broadcast),
    ];
    for (address, expected) in always {
        let address: IpAddr = address.parse().unwrap();
        for destination in [Destination::InCluster, Destination::Public] {
            assert_eq!(
                refusal(address, destination, Loopback::Refused),
                Some(expected),
                "{address} for {destination:?}"
            );
        }
    }
    let private = [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "fc00::1",
        "fd12:3456::1",
        "::ffff:10.0.0.1",
        "::ffff:100.64.0.1",
        "::192.168.1.1",
    ];
    for address in private {
        let address: IpAddr = address.parse().unwrap();
        assert_eq!(
            refusal(address, Destination::Public, Loopback::Refused),
            Some(Private),
            "{address}"
        );
        assert_eq!(
            refusal(address, Destination::InCluster, Loopback::Refused),
            None,
            "{address}"
        );
    }
    let public = [
        "203.0.113.7",
        "8.8.8.8",
        "172.32.0.1",
        "172.15.255.255",
        "100.128.0.1",
        "100.63.255.255",
        "169.255.0.1",
        "2001:db8::1",
        "fec0::1",
        "::ffff:8.8.8.8",
    ];
    for address in public {
        let address: IpAddr = address.parse().unwrap();
        for destination in [Destination::InCluster, Destination::Public] {
            assert_eq!(
                refusal(address, destination, Loopback::Refused),
                None,
                "{address} for {destination:?}"
            );
        }
    }
}

/// A development build may reach loopback, in any of its forms, and nothing else that is
/// always refused.
#[test]
fn only_loopback_is_allowed_in_a_development_build() {
    for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "::127.0.0.1"] {
        let address: IpAddr = address.parse().unwrap();
        assert_eq!(
            refusal(address, Destination::Public, Loopback::Allowed),
            None,
            "{address}"
        );
    }
    for address in ["169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1"] {
        let address: IpAddr = address.parse().unwrap();
        assert!(
            refusal(address, Destination::InCluster, Loopback::Allowed).is_some(),
            "{address}"
        );
    }
    assert_eq!(Loopback::of_this_build(), Loopback::Allowed);
    assert_eq!(
        Upstream::new(CONNECTOR, "http://docs/mcp").loopback,
        Loopback::Allowed
    );
}

/// An IP literal never changes, so it is checked when the connector is built.
#[test]
fn an_ip_literal_is_checked_when_the_connector_is_built() {
    let connector = ConnectorName::new(CONNECTOR);
    let built = |url: &str, loopback: Loopback| {
        ProxyConnector::new(
            Upstream {
                loopback,
                ..upstream(url)
            },
            common::credentials(),
        )
    };
    let refused = |url: &str, address: &str, refusal: Refusal| {
        assert_eq!(
            built(url, Loopback::Refused).unwrap_err(),
            UpstreamError::DestinationRefused {
                connector: connector.clone(),
                address: address.parse().unwrap(),
                refusal,
            },
            "{url}"
        );
    };
    refused("http://127.0.0.1:9/mcp", "127.0.0.1", Refusal::Loopback);
    refused("http://[::1]:9/mcp", "::1", Refusal::Loopback);
    refused(
        "http://[::ffff:127.0.0.1]:9/mcp",
        "::ffff:127.0.0.1",
        Refusal::Loopback,
    );
    refused(
        "http://169.254.169.254/mcp",
        "169.254.169.254",
        Refusal::LinkLocal,
    );
    refused(
        "http://[::ffff:169.254.169.254]/mcp",
        "::ffff:169.254.169.254",
        Refusal::LinkLocal,
    );
    refused("http://0.0.0.0:9/mcp", "0.0.0.0", Refusal::Unspecified);
    assert!(built("http://10.0.0.1/mcp", Loopback::Refused).is_ok());
    assert!(built("http://127.0.0.1:9/mcp", Loopback::Allowed).is_ok());
    assert!(built("http://[::1]:9/mcp", Loopback::Allowed).is_ok());
}

/// A name the connector resolves to loopback is refused when it would connect, for a call, a
/// tool list and a probe alike: nothing is connected to, the call is an error of the kind
/// `other`, and the list and the probe say why.
#[tokio::test]
async fn a_name_that_resolves_to_loopback_is_refused_and_nothing_is_sent() {
    let server = Local::start(Serve::Answer, None).await;
    let connector = common::connector(Upstream {
        loopback: Loopback::Refused,
        ..upstream(&server.url("http", "localhost"))
    });

    let harness = Harness::new();
    let answer = harness.call(&connector, READ_TOOL, arguments()).await;
    assert_eq!(
        answer,
        Answer::Error(outcome::DESTINATION_REFUSED.to_owned())
    );
    let row = harness.rows().pop().unwrap();
    assert_eq!(
        row.completion.unwrap().outcome,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(
        connector.list_tools().await,
        Err(ListError::DestinationRefused)
    );
    let file = TemporaryFile::new(b"dummy-stranger-token-for-the-destination-tests\n");
    let credential = ProbeCredential::load(ConnectorName::new(CONNECTOR), file.path()).unwrap();
    let report = connector.probe(&credential).await;
    assert_eq!(
        report.calls(),
        ProbeCall::ALL.map(|call| (call, CallVerdict::NotShown(NotShown::DestinationRefused)))
    );
    assert_eq!(server.connections(), 0);

    // The same name, in a development build, reaches the server.
    let connector = common::connector(upstream(&server.url("http", "localhost")));
    assert_eq!(connector.list_tools().await, Ok(Vec::new()));
    assert_eq!(server.connections(), 1);
}

/// A writer the tests' log lines go to, shared.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Each refused address is logged as a warning that names the server and the address.
#[tokio::test]
async fn a_refused_address_is_logged_naming_the_server() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let captured = captured.clone();
            move || captured.clone()
        })
        .finish();
    // The global default: another test's log line reached first would be remembered as
    // unwatched.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let server = Local::start(Serve::Answer, None).await;
    let name = "docs-loopback-logged";
    let connector = ProxyConnector::new(
        Upstream {
            loopback: Loopback::Refused,
            ..Upstream::new(name, server.url("http", "localhost"))
                .tool(gateway_core::ToolName::parse(READ_TOOL).unwrap(), "read")
        },
        credentials_for(name, GATEWAY_TOKEN),
    )
    .unwrap();

    assert_eq!(
        connector.list_tools().await,
        Err(ListError::DestinationRefused)
    );

    let logged = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    let lines: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("destination_refused") && line.contains(name))
        .collect();
    assert!(!lines.is_empty(), "{logged}");
    for line in lines {
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains("localhost"), "{line}");
        assert!(line.contains("loopback"), "{line}");
        assert!(!line.contains(GATEWAY_TOKEN), "{line}");
    }
    assert_eq!(server.connections(), 0);
}

// --- Sessions --------------------------------------------------------------------------------

/// A server that reads the call and closes the connection without answering sees it once:
/// the call is an error and is never sent again. The case the HTTP client would otherwise
/// retry, a request it knows never reached the server, is tested in `src/transport.rs`, where
/// the test can hold the client's connection task back.
#[tokio::test]
async fn a_call_the_server_read_and_dropped_is_sent_once() {
    let server = Local::start(Serve::ReadAndDrop, None).await;
    let connector = common::connector(Upstream {
        deadline: DEADLINE,
        ..upstream(&server.url("http", "127.0.0.1"))
    });

    let answer = Harness::new()
        .call(&connector, READ_TOOL, arguments())
        .await;

    assert_eq!(answer, Answer::Error(outcome::UNREACHABLE.to_owned()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.requests(), 1);
    assert_eq!(server.connections(), 1);
}

/// Two entries at one address each have their own pool: the server sees a connection from
/// each, and each connector uses its own again.
#[tokio::test]
async fn two_entries_at_one_address_have_separate_pools() {
    let server = Local::start(Serve::Answer, None).await;
    let url = server.url("http", "127.0.0.1");
    let entry = |name: &str| {
        ProxyConnector::new(
            Upstream::new(name, url.clone())
                .tool(gateway_core::ToolName::parse(READ_TOOL).unwrap(), "read"),
            credentials_for(name, GATEWAY_TOKEN),
        )
        .unwrap()
    };
    let (first, second) = (entry("docs-team-a"), entry("docs-team-b"));

    for _ in 0..2 {
        assert_eq!(first.list_tools().await, Ok(Vec::new()));
        assert_eq!(second.list_tools().await, Ok(Vec::new()));
    }

    assert_eq!(server.requests(), 4);
    assert_eq!(server.connections(), 2);
}

// --- The registry ----------------------------------------------------------------------------

/// The registry's rule for plain `http` and the connector's agree: an entry loads with an
/// address and a destination exactly when a connector can be built for them.
#[test]
fn the_registry_and_the_connector_agree_on_http_and_https() {
    let ca_file = TestCa::new().file();
    for scheme in ["http", "https"] {
        for (written, destination) in [
            ("in_cluster", Destination::InCluster),
            ("public", Destination::Public),
        ] {
            let address = format!("{scheme}://docs.example.test/mcp");
            let entry = format!(
                r#"
[[servers]]
name = "docs"
system = "docs"
owner = "platform"
identity = "docs.example.test"
address = "{address}"
credential = {{ mode = "gateway_token", reference = "docs-credential", principal = "docs" }}
narrowing = "none"
permits = "read"
reach = []
destination = "{written}"
"#
            );
            let loaded =
                gateway_registry::Registry::server_entry(&entry, &ConnectorName::new("docs"));
            let built = ProxyConnector::new(
                Upstream {
                    destination,
                    ca_file: (scheme == "https").then(|| ca_file.path().to_owned()),
                    ..upstream(&address)
                },
                common::credentials(),
            );
            assert_eq!(
                loaded.is_ok(),
                built.is_ok(),
                "{address} {written}: {loaded:?} {built:?}"
            );
        }
    }
}
