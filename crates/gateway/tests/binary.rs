//! The `switchboard` binary, run as a process: its arguments, its refusals to start, its boot
//! lines, and requests over loopback forwarded to the mock docs server, with its JSON logs read
//! back.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use files::{AUDIENCE, Files, READ_TOOL, SURFACE, TEAM_A_SA, cluster_issuer, kubernetes_token};
use gateway_core::IDENTITY_FAILURE;
use gateway_testkit::LocalIssuer;
use mock_docs_server::{AcceptedCredential, Config};
use serde_json::{Value, json};

const BINARY: &str = env!("CARGO_BIN_EXE_switchboard");

const PATIENCE: Duration = Duration::from_secs(20);

/// How long a run that should end on its own may take. It is generous because the first run
/// of a freshly built binary can be slow on a loaded machine; it only has to be shorter than
/// forever, so that a refused configuration that starts serving fails the test.
const EXIT_PATIENCE: Duration = Duration::from_secs(120);

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

/// Runs the binary to its exit, with `env` added to its environment. One that is still running
/// after [`EXIT_PATIENCE`] is killed and fails the test, so a configuration that should be
/// refused but starts a server fails the test rather than hanging it.
fn run_with(arguments: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(BINARY);
    command
        .args(arguments)
        .env_remove("SWITCHBOARD_MIGRATE_DATABASE_URL")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + EXIT_PATIENCE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("switchboard {arguments:?} was still running after {EXIT_PATIENCE:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

fn run(arguments: &[&str]) -> Output {
    run_with(arguments, &[])
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn usage_errors_exit_with_two() {
    for arguments in [
        &[][..],
        &["--config"],
        &["--config="],
        &["--listen", "127.0.0.1:0"],
        &["--verbose", "--config=gateway.toml"],
        &["gateway.toml"],
        &["migrate", "--config=gateway.toml"],
        &["--config=gateway.toml", "migrate"],
        &["migrate", "migrate"],
    ] {
        let output = run(arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            stderr(&output).contains("usage: switchboard"),
            "{arguments:?}"
        );
    }
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("usage: switchboard"));
}

#[test]
fn it_refuses_to_start_on_a_deployment_it_cannot_load() {
    let missing = run(&["--config=/nonexistent/gateway.toml"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        stderr(&missing).contains("cannot read"),
        "{}",
        stderr(&missing)
    );
    // The refusal is logged as a JSON line too.
    let logged: Value = serde_json::from_str(stdout(&missing).lines().last().unwrap()).unwrap();
    assert_eq!(logged["fields"]["event"], json!("boot_refused"));

    let files = Files::new(
        "binary-refusals",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let config = files.path("gateway.toml");
    let config = format!("--config={}", config.display());

    files.write("gateway.toml", "listen = 8080\n");
    let invalid = run(&[&config]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(stderr(&invalid).contains("is not a valid deployment file"));

    let deployment = files::deployment_file("[audit]\nmode = \"disabled\"\n");
    files.write(
        "gateway.toml",
        &deployment.replace("mode = \"enforce\"", "mode = \"unchecked\""),
    );
    let unconfigured = run(&[&config]);
    assert_eq!(unconfigured.status.code(), Some(1));
    assert!(stderr(&unconfigured).contains("unknown variant `unchecked`"));

    files.write(
        "gateway.toml",
        &files::deployment_file(
            "[audit]\nmode = \"postgres\"\nurl_env = \"SWITCHBOARD_BINARY_TEST_URL\"\n",
        ),
    );
    let no_url = run(&[&config]);
    assert_eq!(no_url.status.code(), Some(1));
    assert!(
        stderr(&no_url).contains("SWITCHBOARD_BINARY_TEST_URL"),
        "{}",
        stderr(&no_url)
    );
    let unreachable = run_with(
        &[&config],
        &[(
            "SWITCHBOARD_BINARY_TEST_URL",
            "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard?connect_timeout=2",
        )],
    );
    assert_eq!(unreachable.status.code(), Some(1));
    assert!(
        stderr(&unreachable).contains("the audit store will not start"),
        "{}",
        stderr(&unreachable)
    );
}

#[test]
fn migrate_needs_the_owners_database_url() {
    let unset = run(&["migrate"]);
    assert_eq!(unset.status.code(), Some(1));
    assert!(
        stderr(&unset).contains("SWITCHBOARD_MIGRATE_DATABASE_URL"),
        "{}",
        stderr(&unset)
    );
    let unreachable = run_with(
        &["migrate"],
        &[(
            "SWITCHBOARD_MIGRATE_DATABASE_URL",
            "postgres://switchboard_owner:dummy@127.0.0.1:1/switchboard?connect_timeout=2",
        )],
    );
    assert_eq!(unreachable.status.code(), Some(1));
    assert!(
        stderr(&unreachable).contains("cannot connect"),
        "{}",
        stderr(&unreachable)
    );
}

/// The deployment is checked, and the audit store and boot gates run, before a socket is bound.
/// With the address already taken, a deployment the binary refuses is refused for its own
/// reason, not for the address.
#[test]
fn a_refused_deployment_is_refused_before_the_address_is_bound() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = held.local_addr().unwrap().to_string();
    let files = Files::new(
        "binary-held",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let config = format!("--config={}", files.path("gateway.toml").display());
    let listen_line = "listen = \"127.0.0.1:0\"\n";
    let held_at = |audit: &str| {
        let text = files::deployment_file(audit);
        assert_eq!(text.matches(listen_line).count(), 1);
        text.replace(listen_line, &format!("listen = \"{address}\"\n"))
    };

    // The address really is taken: a deployment that passes cannot listen on it.
    files.write("gateway.toml", &held_at("[audit]\nmode = \"disabled\"\n"));
    let started = run(&[&config]);
    assert_eq!(started.status.code(), Some(1));
    assert!(
        stderr(&started).contains("cannot listen on"),
        "{}",
        stderr(&started)
    );

    let unused_credential = held_at("[audit]\nmode = \"disabled\"\n").replace(
        "[credentials]\n",
        "[credentials]\nunused-credential = \"docs-credential\"\n",
    );
    let unreachable_store =
        held_at("[audit]\nmode = \"postgres\"\nurl_env = \"SWITCHBOARD_BINARY_TEST_URL\"\n");
    for (name, deployment, reason) in [
        ("unused-credential", unused_credential, "no server uses it"),
        (
            "unreachable-store",
            unreachable_store,
            "the audit store will not start",
        ),
    ] {
        files.write("gateway.toml", &deployment);
        let output = run_with(
            &[&config],
            &[(
                "SWITCHBOARD_BINARY_TEST_URL",
                "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard?connect_timeout=2",
            )],
        );
        let said = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{name}: {said}");
        assert!(said.contains(reason), "{name}: {said}");
        assert!(!said.contains("cannot listen on"), "{name}: {said}");
    }
    drop(held);
}

/// The binary running, with each line of its standard output parsed as JSON.
struct Running {
    child: Child,
    lines: mpsc::Receiver<Value>,
    seen: Vec<Value>,
    address: SocketAddr,
}

impl Running {
    fn start(files: &Files) -> Self {
        let mut child = Command::new(BINARY)
            .arg(format!("--config={}", files.path("gateway.toml").display()))
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                let parsed = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("a log line that is not JSON: {line}"));
                if send.send(parsed).is_err() {
                    break;
                }
            }
        });
        let mut running = Self {
            child,
            lines,
            seen: Vec::new(),
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let listening = running.event("listening");
        running.address = listening["fields"]["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        running
    }

    /// The next log event whose message is `message`. Every line read is kept in `seen`.
    fn event(&mut self, message: &str) -> Value {
        loop {
            let line = self
                .lines
                .recv_timeout(PATIENCE)
                .unwrap_or_else(|_| panic!("no `{message}` event was logged: {:#?}", self.seen));
            assert!(line["timestamp"].is_string(), "{line}");
            assert!(line["level"].is_string(), "{line}");
            self.seen.push(line.clone());
            if line["fields"]["message"] == json!(message) {
                return line;
            }
        }
    }

    /// The `"event":"boot"` lines logged so far.
    fn boot_lines(&self) -> Vec<&Value> {
        self.seen
            .iter()
            .filter(|line| line["fields"]["event"] == json!("boot"))
            .collect()
    }

    /// Posts `body` to the docs surface with `token`, and returns the status and the body.
    fn post(&self, token: Option<&str>, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let authorization = token
            .map(|token| format!("authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "POST /mcp/{SURFACE} HTTP/1.1\r\nhost: 127.0.0.1:{}\r\n{authorization}\
             content-type: application/json\r\naccept: application/json, text/event-stream\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            self.address.port(),
            body.len(),
        );
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut received = String::new();
        stream.read_to_string(&mut received).unwrap();
        let (head, body) = received.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn it_serves_the_registry_from_files_and_forwards_with_its_own_credential() {
    let mock = mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
        .await
        .unwrap();
    let files = Files::new("binary-serves", &issuer().jwks_document(), &mock.url());
    let mut running = tokio::task::block_in_place(|| Running::start(&files));

    // How it was started, from its boot lines.
    let boot = running.boot_lines();
    let field = |name: &str| -> Vec<Value> {
        boot.iter()
            .filter_map(|line| line["fields"].get(name).cloned())
            .collect()
    };
    assert_eq!(field("identity"), [json!("enforce")], "{boot:#?}");
    assert_eq!(field("issuers"), [json!(1)]);
    assert_eq!(field("subjects"), [json!(2)]);
    assert_eq!(field("audit"), [json!("disabled")]);
    assert_eq!(field("revision"), [json!("demo-1")]);

    let team_a = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);
    let read = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": READ_TOOL, "arguments": {"project": "atlas", "document": "plan"}}});
    let (status, body) = tokio::task::block_in_place(|| running.post(Some(&team_a), &read));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], json!(false), "{body}");
    let ran = tokio::task::block_in_place(|| running.event("ran a tool call"));
    assert_eq!(ran["fields"]["outcome"], json!("ok"));

    let (status, body) = tokio::task::block_in_place(|| running.post(None, &read));
    assert_eq!(status, 401);
    assert_eq!(body["error"]["message"], json!(IDENTITY_FAILURE));
    let refused = tokio::task::block_in_place(|| {
        running.event("refused a caller whose identity was not proved")
    });
    assert_eq!(refused["fields"]["event"], json!("identity_failed"));
    assert_eq!(refused["level"], json!("WARN"));

    // One request reached the server, with the gateway's credential.
    let bearers: Vec<Value> = mock
        .log_lines()
        .iter()
        .filter_map(|line| line.get("bearer_sha256").cloned())
        .collect();
    assert_eq!(bearers.len(), 1, "{bearers:?}");
}
