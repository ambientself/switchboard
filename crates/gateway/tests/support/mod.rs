//! What the loopback tests share: the testkit's world served on `127.0.0.1:0`, and HTTP/1.1
//! written by hand over a TCP socket, so the exact headers and the order of the checks are what
//! a test says, with no client library in between.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gateway::{Config, ResourceAdapter, Timeouts, Wiring, boot, serve_with_timeouts};
use gateway_core::{ApprovedTool, IDENTITY_FAILURE, Resources};
use gateway_mcp::{CHALLENGE, DENIAL_CODE};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, DRAFT_TOOL, FakeCredentialSource, Fixture, FixtureConnector,
    GROUP_G, GROUP_REVIEW, InMemoryAuditStore, PROFILE_REVIEWER, PROFILE_TEAM_A, PROFILE_TEAM_B,
    PROFILE_USER, READ_TOOL, SCOPED_READ_TOOL, TEAM_A, TEAM_A_SUBJECT, TEAM_B, TEAM_B_SUBJECT,
    USER_ISSUER, WORKLOAD_ISSUER, WRITE_TOOL,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// The origin the test configuration accepts.
pub const ALLOWED_ORIGIN: &str = "http://localhost:3000";

/// How long a test waits for something that should happen at once.
pub const PATIENCE: Duration = Duration::from_secs(10);

pub struct FixtureResources;

impl ResourceAdapter for FixtureResources {
    fn resources(&self, tool: &ApprovedTool, arguments: &Value) -> Resources {
        FixtureConnector::resources_of(tool.name.as_str(), arguments)
    }
}

/// The testkit's world, served over loopback.
pub struct Server {
    pub fixture: Fixture,
    pub store: Arc<InMemoryAuditStore>,
    pub credentials: Arc<FakeCredentialSource>,
    pub connector: Arc<FixtureConnector>,
    pub address: SocketAddr,
    pub stop: Option<oneshot::Sender<()>>,
    pub serving: JoinHandle<std::io::Result<()>>,
}

impl Server {
    pub async fn start() -> Self {
        Self::start_with(Timeouts::default()).await
    }

    pub async fn start_with(timeouts: Timeouts) -> Self {
        let fixture = Fixture::new().unwrap();
        let credentials = Arc::new(FakeCredentialSource::new());
        let connector = Arc::new(FixtureConnector::new(credentials.clone()));
        let store = Arc::new(InMemoryAuditStore::new());
        let config: Config = serde_json::from_value(config(&fixture)).unwrap();
        let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
            .audit_store(store.clone())
            .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources));
        let gates = boot::check(config, wiring).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let serving = tokio::spawn(serve_with_timeouts(
            listener,
            gates,
            async {
                let _ = stopped.await;
            },
            timeouts,
        ));
        Self {
            fixture,
            store,
            credentials,
            connector,
            address,
            stop: Some(stop),
            serving,
        }
    }

    pub fn token(&self, caller: Caller) -> String {
        self.fixture.token(caller)
    }

    /// A POST to `surface` as a well-behaved client sends it, with no token.
    pub fn post(&self, surface: &str, body: &Value) -> Http {
        Http::new("POST", &format!("/mcp/{surface}"))
            .header("host", &format!("localhost:{}", self.address.port()))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body.to_string().into_bytes())
    }

    /// A 2025-06-18 `tools/call` from `caller`.
    pub fn call(&self, caller: Caller, surface: &str, tool: &str, arguments: Value) -> Http {
        self.post(
            surface,
            &legacy("tools/call", json!({"name": tool, "arguments": arguments})),
        )
        .bearer(&self.token(caller))
    }

    /// Nothing reached the connector or the credential source, and no row was written.
    pub fn assert_nothing_ran(&self) {
        assert!(
            self.connector.received().is_empty(),
            "the connector received a call"
        );
        assert!(
            self.credentials.requests().is_empty(),
            "a credential was requested"
        );
        assert!(self.store.rows().is_empty(), "a row was written");
        assert_eq!(self.store.begin_attempts(), 0, "a row was begun");
    }
}

pub fn config(fixture: &Fixture) -> Value {
    let issuer = |issuer: &gateway_testkit::LocalIssuer, kind: Value| {
        json!({
            "issuer": issuer.issuer(),
            "audiences": [AUDIENCE],
            "kind": kind,
            "algorithm": "ES256",
            "keys": serde_json::to_value(issuer.jwk_set()).unwrap(),
            "max_lifetime_secs": gateway_testkit::DEFAULT_MAX_LIFETIME,
            "leeway_secs": gateway_testkit::DEFAULT_LEEWAY,
        })
    };
    let definition = |name: &str| {
        json!({
            "name": name,
            "description": format!("The fixture's {name}."),
            "input_schema": {"type": "object"},
        })
    };
    json!({
        "deployment": "server-test",
        "identity": {"enforce": [
            issuer(&fixture.workload_issuer, json!({"workload": {"subjects": {
                TEAM_A_SUBJECT: TEAM_A,
                TEAM_B_SUBJECT: TEAM_B,
            }}})),
            issuer(&fixture.user_issuer, json!({"user": {}})),
        ]},
        "audit": {},
        "http": {
            "allowed_hosts": ["localhost", "127.0.0.1"],
            "allowed_origins": [ALLOWED_ORIGIN],
        },
        "policy": gateway_testkit::policy_data(),
        "catalog": [
            definition(READ_TOOL),
            definition(DRAFT_TOOL),
            definition(WRITE_TOOL),
            definition(SCOPED_READ_TOOL),
        ],
        "profiles": {
            "workloads": [
                {"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": PROFILE_TEAM_A},
                {"issuer": WORKLOAD_ISSUER, "team": TEAM_B, "profile": PROFILE_TEAM_B},
            ],
            "users": [
                {"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_USER},
                {"issuer": USER_ISSUER, "group": GROUP_REVIEW, "profile": PROFILE_REVIEWER},
            ],
        },
    })
}

pub fn legacy(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// One HTTP/1.1 request, written out by hand. Every request asks for the connection to be
/// closed after the answer, so the answer is everything read until the server closes.
pub struct Http {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http {
    pub fn new(method: &str, target: &str) -> Self {
        Self {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: vec![("connection".to_owned(), "close".to_owned())],
            body: Vec::new(),
        }
    }

    /// Adds a header, keeping any of the same name.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Removes every header named `name`.
    pub fn without(mut self, name: &str) -> Self {
        self.headers
            .retain(|(header, _)| !header.eq_ignore_ascii_case(name));
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", &format!("Bearer {token}"))
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The request line and headers, ending with the blank line.
    pub fn head(&self) -> Vec<u8> {
        let mut head = format!("{} {} HTTP/1.1\r\n", self.method, self.target);
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }

    /// Sends the request with its body under `Content-Length`, and reads the answer.
    pub async fn send(self, server: &Server) -> Answer {
        let length = self.body.len().to_string();
        let request = self.header("content-length", &length);
        let mut bytes = request.head();
        bytes.extend_from_slice(&request.body);
        exchange(server.address, &bytes).await
    }
}

/// Writes `bytes`, then reads until the server closes. A write the server cut short, or a reset
/// after the answer, still leaves whatever answer arrived.
pub async fn exchange(address: SocketAddr, bytes: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let _ = stream.write_all(bytes).await;
    read_answer(&mut stream).await
}

pub async fn read_answer(stream: &mut TcpStream) -> Answer {
    let mut received = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        match tokio::time::timeout(PATIENCE, stream.read(&mut buffer)).await {
            Err(_) => panic!(
                "no complete answer within {PATIENCE:?}; got {:?}",
                String::from_utf8_lossy(&received)
            ),
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(read)) => received.extend_from_slice(&buffer[..read]),
        }
    }
    Answer::parse(&received)
}

/// What came back.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn parse(received: &[u8]) -> Self {
        let split = received
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no answer: {:?}", String::from_utf8_lossy(received)));
        let head = std::str::from_utf8(&received[..split]).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers: Vec<(String, String)> = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.trim().to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let answer = Answer {
            status,
            headers,
            body: received[split + 4..].to_vec(),
        };
        assert!(
            answer.header("transfer-encoding").is_none(),
            "answers are not chunked"
        );
        assert!(
            answer.header("mcp-session-id").is_none(),
            "no answer carries a session"
        );
        if let Some(length) = answer.header("content-length") {
            assert_eq!(
                answer.body.len(),
                length.parse::<usize>().unwrap(),
                "{answer:?}"
            );
        }
        answer
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {:?}", String::from_utf8_lossy(&self.body)))
    }

    pub fn result(&self) -> Value {
        assert_eq!(self.status, 200, "{self:?}");
        let body = self.json();
        assert!(body.get("error").is_none(), "{body}");
        body["result"].clone()
    }

    pub fn denial(&self) -> String {
        assert_eq!(self.status, 200, "{self:?}");
        let body = self.json();
        assert_eq!(body["error"]["code"], json!(DENIAL_CODE), "{body}");
        body["error"]["message"].as_str().unwrap().to_owned()
    }

    pub fn error_message(&self) -> String {
        self.json()["error"]["message"].as_str().unwrap().to_owned()
    }

    /// The 401 every identity failure gets.
    pub fn assert_unauthorized(&self) {
        assert_eq!(self.status, 401, "{self:?}");
        assert_eq!(self.header("www-authenticate"), Some(CHALLENGE));
        assert_eq!(
            self.json(),
            json!({"jsonrpc": "2.0", "id": null,
                   "error": {"code": DENIAL_CODE, "message": IDENTITY_FAILURE}})
        );
    }

    pub fn assert_forbidden(&self, message: &str) {
        assert_eq!(self.status, 403, "{self:?}");
        assert_eq!(self.error_message(), message);
    }
}

/// Waits until `done` holds, or fails the test.
pub async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
