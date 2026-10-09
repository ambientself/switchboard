//! What the connector's tests share: the core's audited path to run a call through, the
//! gateway's dummy credential, a credential file laid out as the kubelet lays one out, and an
//! upstream that answers with whatever bytes a test scripts.
#![allow(dead_code)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connector_proxy::{FileCredentials, ProxyConnector, Upstream};
use gateway_core::audit::{self, Answer, Begun, RequestMetadata};
use gateway_core::{
    AuditRecord, CallContext, ConnectorName, Principal, Proved, RequestedTool, Resources, ToolName,
    decide,
};
use gateway_testkit::{
    CONNECTOR, Caller, Fixture, InMemoryAuditStore, READ_TOOL, SCOPED_READ_TOOL, SURFACE_READ,
    TEAM_A_DOCUMENT, document, row_start,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// The gateway's credential for the proxied server. A dummy, made up for these tests; it is
/// not a secret anywhere.
pub const GATEWAY_TOKEN: &str = "dummy-gateway-credential-for-connector-tests";

/// Another dummy credential, one the proxied server does not accept.
pub const WRONG_TOKEN: &str = "dummy-credential-the-server-does-not-accept";

/// The mock server's name for the fixture's read tool.
pub const READ_UPSTREAM: &str = "read_document";

/// The mock server's name for the fixture's scope-checking read tool.
pub const LIST_UPSTREAM: &str = "list_documents";

/// Longer than any call in these tests should take, so a broken bound fails the test instead
/// of hanging it.
pub const TEST_LIMIT: Duration = Duration::from_secs(20);

/// The first 12 hex digits of the SHA-256 of `token`, as the mock server logs it.
pub fn prefix(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()[..12]
        .to_owned()
}

/// Writes `contents` to a fresh file and returns its path.
pub fn temporary_file(contents: &[u8]) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "connector-proxy-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).unwrap();
    path
}

/// A file that is removed when dropped.
pub struct TemporaryFile(PathBuf);

impl TemporaryFile {
    /// Writes `contents` to a fresh file.
    pub fn new(contents: &[u8]) -> Self {
        Self(temporary_file(contents))
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A credential source holding `token` for `connector`, read from a file that ends in a
/// newline, as a mounted secret often does.
///
/// The source reads the file again on every call, so the file stays. It is named for the
/// connector and the token, and every test that asks for the same pair shares it; it is
/// replaced in one rename, so a test reading it never sees it half written.
pub fn credentials_for(connector: &str, token: &str) -> Arc<FileCredentials> {
    let path = std::env::temp_dir().join(format!(
        "connector-proxy-test-credential-{}",
        prefix(&format!("{connector} {token}"))
    ));
    let written = temporary_file(format!("{token}\n").as_bytes());
    std::fs::rename(&written, &path).unwrap();
    Arc::new(FileCredentials::load([(ConnectorName::new(connector), &path)]).unwrap())
}

/// A credential file laid out as the kubelet lays out a projected volume: the file's contents
/// in a timestamped directory, `..data` a symbolic link to that directory, and `token` a
/// symbolic link to `..data/token`. Removed when dropped.
pub struct ProjectedVolume {
    root: PathBuf,
    current: Option<PathBuf>,
    versions: u32,
}

impl ProjectedVolume {
    /// A volume holding `token`, followed by a newline.
    pub fn new(token: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "connector-proxy-test-projected-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let mut volume = Self {
            root,
            current: None,
            versions: 0,
        };
        volume.rotate(token);
        symlink("..data/token", volume.token()).unwrap();
        volume
    }

    /// The path a pod reads: `token`, through `..data`.
    pub fn token(&self) -> PathBuf {
        self.root.join("token")
    }

    /// Replaces the token as the kubelet's atomic writer does: writes it into a new timestamped
    /// directory, points `..data_tmp` at that directory, renames `..data_tmp` over `..data` in
    /// one step, and removes the old directory.
    pub fn rotate(&mut self, token: &str) {
        self.versions += 1;
        let name = format!(
            "..2026_10_08_12_00_{:02}.{:09}",
            self.versions, self.versions
        );
        let directory = self.root.join(&name);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("token"), format!("{token}\n")).unwrap();
        let swap = self.root.join("..data_tmp");
        symlink(&name, &swap).unwrap();
        std::fs::rename(&swap, self.root.join("..data")).unwrap();
        if let Some(old) = self.current.replace(directory) {
            std::fs::remove_dir_all(old).unwrap();
        }
    }
}

impl Drop for ProjectedVolume {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The gateway's credential for the fixture's connector.
pub fn credentials() -> Arc<FileCredentials> {
    credentials_for(CONNECTOR, GATEWAY_TOKEN)
}

/// The fixture's read tools, routed to the mock server's document tools at `url`, with the
/// default bounds.
pub fn upstream(url: &str) -> Upstream {
    Upstream::new(CONNECTOR, url)
        .tool(ToolName::parse(READ_TOOL).unwrap(), READ_UPSTREAM)
        .tool(ToolName::parse(SCOPED_READ_TOOL).unwrap(), LIST_UPSTREAM)
}

/// A connector for `upstream` with the gateway's credential.
pub fn connector(upstream: Upstream) -> ProxyConnector {
    ProxyConnector::new(upstream, credentials()).unwrap()
}

/// The core's audited path, from a proved caller to the answer, with the connector under test
/// as the only part that does I/O.
pub struct Harness {
    pub fixture: Fixture,
    pub store: InMemoryAuditStore,
    caller_token: String,
    principal: Proved<Principal>,
}

impl Harness {
    /// Team A's workload, proved from a token the fixture's issuer signs.
    pub fn new() -> Self {
        let fixture = Fixture::new().unwrap();
        let caller_token = fixture.token(Caller::TeamA);
        let principal = Proved::verify(fixture.verifier(), caller_token.as_str()).unwrap();
        Self {
            fixture,
            store: InMemoryAuditStore::new(),
            caller_token,
            principal,
        }
    }

    /// The token the caller presented to the gateway.
    pub fn caller_token(&self) -> &str {
        &self.caller_token
    }

    /// Decides, begins, runs and finishes one call to `tool` on the read surface, and returns
    /// the answer. The read tool's call names team A's own document, so the decision allows it;
    /// the scope-checking tool's resources are unknown until it runs.
    pub async fn call(&self, connector: &ProxyConnector, tool: &str, arguments: Value) -> Answer {
        let resources = if tool == SCOPED_READ_TOOL {
            Resources::Unknown
        } else {
            Resources::Named(vec![document(TEAM_A_DOCUMENT)])
        };
        let call = CallContext {
            caller: Fixture::context_for(self.principal.clone(), SURFACE_READ),
            tool: RequestedTool::new(tool),
            resources,
        };
        let decision = decide(&self.fixture.policy, &call);
        assert!(decision.is_allowed(), "{decision:?}");
        let begun = audit::begin(
            &self.store,
            row_start(),
            decision,
            arguments,
            RequestMetadata::default(),
        )
        .await
        .unwrap();
        let Begun::Allowed(guard) = begun else {
            panic!("the call was denied: {begun:?}");
        };
        let ran = tokio::time::timeout(TEST_LIMIT, audit::run(connector, guard))
            .await
            .expect("the connector did not return within the test's limit");
        audit::finish(&self.store, ran, 0).await.answer().clone()
    }

    /// The audit rows written so far.
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.store.rows()
    }
}

/// One step of a scripted upstream's answer.
pub enum Step {
    /// Write these bytes.
    Write(Vec<u8>),
    /// Wait this long.
    Sleep(Duration),
    /// Never write anything more, and keep the connection open.
    Hang,
}

/// A request a scripted upstream received.
#[derive(Clone, Debug)]
pub struct Received {
    /// The request line, such as `POST /mcp HTTP/1.1`.
    pub request_line: String,
    /// Each header, with its name in lower case, in the order received.
    pub headers: Vec<(String, String)>,
    /// The body, parsed as JSON.
    pub body: Value,
}

impl Received {
    /// The value of the header `name`, if it was sent once.
    pub fn header(&self, name: &str) -> Option<&str> {
        let mut values = self
            .headers
            .iter()
            .filter(|(header, _)| header == name)
            .map(|(_, value)| value.as_str());
        let value = values.next();
        assert!(values.next().is_none(), "header {name} was sent twice");
        value
    }
}

/// An HTTP server on loopback that answers each request with what `script` makes of the
/// request's JSON body, byte for byte, and records every request. Stops when dropped.
pub struct Scripted {
    url: String,
    received: Arc<Mutex<Vec<Received>>>,
    task: JoinHandle<()>,
}

impl Scripted {
    pub async fn start<F>(script: F) -> Self
    where
        F: Fn(&Value) -> Vec<Step> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let record = received.clone();
        let script = Arc::new(script);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let record = record.clone();
                let script = script.clone();
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    let steps = script(&request.body);
                    record.lock().unwrap().push(request);
                    for step in steps {
                        match step {
                            Step::Write(bytes) => {
                                if stream.write_all(&bytes).await.is_err() {
                                    return;
                                }
                                let _ = stream.flush().await;
                            }
                            Step::Sleep(duration) => tokio::time::sleep(duration).await,
                            Step::Hang => std::future::pending::<()>().await,
                        }
                    }
                });
            }
        });
        Self {
            url,
            received,
            task,
        }
    }

    /// The endpoint, `http://127.0.0.1:<port>/mcp`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Every request received so far.
    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Received> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
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
    let head = String::from_utf8(buffer[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Received {
        request_line,
        headers,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    })
}

/// A complete HTTP response with a `Content-Length`.
pub fn response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// A `200` JSON response carrying `body`.
pub fn json_response(body: &Value) -> Vec<u8> {
    response("200 OK", "application/json", body.to_string().as_bytes())
}

/// The head of a `200` JSON response whose body is sent in chunks, with no `Content-Length`.
pub fn chunked_head() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec()
}

/// One chunk of a chunked body.
pub fn chunk(data: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{:x}\r\n", data.len()).into_bytes();
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(b"\r\n");
    bytes
}

/// The chunk that ends a chunked body.
pub fn last_chunk() -> Vec<u8> {
    b"0\r\n\r\n".to_vec()
}

/// A successful tool result answering the request `request`, with one text item.
pub fn text_result(request: &Value, text: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {"content": [{"type": "text", "text": text}], "isError": false},
    })
}

/// A successful tool result answering `request` whose serialized form is exactly `size` bytes.
pub fn result_of_size(request: &Value, size: usize) -> Vec<u8> {
    let empty = text_result(request, "").to_string().len();
    let body = text_result(request, &"x".repeat(size - empty)).to_string();
    assert_eq!(body.len(), size);
    body.into_bytes()
}
