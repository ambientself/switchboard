//! The `switchboard` binary, run as a process: its arguments, its refusals to start, and a
//! request over loopback with its JSON logs read back.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use gateway::{AUDIT_DISABLED_NOTE, IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE};
use gateway_core::IDENTITY_FAILURE;
use gateway_testkit::{
    AUDIENCE, Fixture, GROUP_G, PROFILE_TEAM_A, PROFILE_USER, READ_TOOL, SCOPED_READ_TOOL,
    SURFACE_READ, TEAM_A, TEAM_A_SUBJECT, USER_ISSUER, WORKLOAD_ISSUER, WRITE_TOOL,
};
use serde_json::{Value, json};

const BINARY: &str = env!("CARGO_BIN_EXE_switchboard");

const PATIENCE: Duration = Duration::from_secs(20);

/// How long a run that should end on its own may take. It is generous because the first run
/// of a freshly built binary can be slow on a loaded machine; it only has to be shorter than
/// forever, so that a refused configuration that starts serving fails the test.
const EXIT_PATIENCE: Duration = Duration::from_secs(120);

/// A configuration this build can start: audit disabled, and no tool on any surface, because
/// the binary registers no connector.
fn startable(identity: Value) -> Value {
    let mut policy = gateway_testkit::policy_data();
    for surface in policy["surfaces"].as_array_mut().unwrap() {
        surface["tools"] = json!([]);
    }
    let definition = |name: &str| json!({"name": name, "description": "A fixture tool.", "input_schema": {"type": "object"}});
    json!({
        "deployment": "binary-test",
        "identity": identity,
        "audit": {"disabled": true},
        "http": {"allowed_hosts": ["127.0.0.1"]},
        "policy": policy,
        "catalog": [definition(READ_TOOL), definition(WRITE_TOOL), definition(SCOPED_READ_TOOL)],
        "profiles": {
            "workloads": [{"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": PROFILE_TEAM_A}],
            "users": [{"issuer": USER_ISSUER, "group": GROUP_G, "profile": PROFILE_USER}],
        },
    })
}

fn enforced(fixture: &Fixture) -> Value {
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
    json!({"enforce": [
        issuer(&fixture.workload_issuer, json!({"workload": {"subjects": {TEAM_A_SUBJECT: TEAM_A}}})),
        issuer(&fixture.user_issuer, json!({"user": {}})),
    ]})
}

/// Writes `config` to a file of its own under the target directory.
fn config_file(name: &str, config: &Value) -> PathBuf {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("switchboard-binary-test");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{name}.json"));
    std::fs::write(&path, config.to_string()).unwrap();
    path
}

/// Runs the binary to its exit. One that is still running after [`EXIT_PATIENCE`] is killed
/// and fails the test, so a configuration that should be refused but starts a server fails the
/// test rather than hanging it.
fn run(arguments: &[&str]) -> Output {
    let mut child = Command::new(BINARY)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn usage_errors_exit_with_two() {
    for arguments in [
        &[][..],
        &["--listen"],
        &["--listen", "not-an-address", "config.json"],
        &["--verbose", "config.json"],
        &["one.json", "two.json"],
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
    assert!(String::from_utf8_lossy(&help.stdout).contains("usage: switchboard"));
}

#[test]
fn it_refuses_to_start_without_the_audit_opt_out() {
    let mut config = startable(json!({"disabled": true}));
    config["audit"] = json!({});
    let path = config_file("audit-not-disabled", &config);
    let output = run(&["--listen", "127.0.0.1:0", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let said = stderr(&output);
    assert!(said.contains("no durable audit store"), "{said}");
    assert!(said.contains("\"audit\": {\"disabled\": true}"), "{said}");
}

#[test]
fn it_refuses_to_start_on_what_the_boot_gates_refuse() {
    let missing = run(&["--listen", "127.0.0.1:0", "/nonexistent/switchboard.json"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        stderr(&missing).contains("cannot read"),
        "{}",
        stderr(&missing)
    );

    let path = config_file("not-json", &json!("not a configuration"));
    let invalid = run(&["--listen", "127.0.0.1:0", path.to_str().unwrap()]);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(stderr(&invalid).contains("is not a valid configuration"));

    // Identity neither enforced nor disabled.
    let path = config_file("identity-unconfigured", &startable(json!({})));
    let unconfigured = run(&["--listen", "127.0.0.1:0", path.to_str().unwrap()]);
    assert_eq!(unconfigured.status.code(), Some(1));
    assert!(stderr(&unconfigured).contains("identity is not configured"));

    // A tool on a surface, whose connector this build cannot register.
    let mut config = startable(json!({"disabled": true}));
    config["policy"]["surfaces"][0]["tools"] = json!([READ_TOOL]);
    let path = config_file("tool-served", &config);
    let served = run(&["--listen", "127.0.0.1:0", path.to_str().unwrap()]);
    assert_eq!(served.status.code(), Some(1));
    assert!(
        stderr(&served).contains("is not registered"),
        "{}",
        stderr(&served)
    );
}

/// The binary running, with each line of its standard output parsed as JSON.
struct Running {
    child: Child,
    lines: mpsc::Receiver<Value>,
    address: SocketAddr,
    /// The event logged once the listener was bound.
    listening: Value,
}

impl Running {
    fn start(name: &str, config: &Value) -> Self {
        let path = config_file(name, config);
        let mut child = Command::new(BINARY)
            .args(["--listen", "127.0.0.1:0", path.to_str().unwrap()])
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
            address: "127.0.0.1:0".parse().unwrap(),
            listening: Value::Null,
        };
        running.listening = running.event("listening");
        running.address = running.listening["fields"]["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        running
    }

    /// The next log event whose message is `message`.
    fn event(&self, message: &str) -> Value {
        loop {
            let line = self
                .lines
                .recv_timeout(PATIENCE)
                .unwrap_or_else(|_| panic!("no `{message}` event was logged"));
            assert!(line["timestamp"].is_string(), "{line}");
            assert!(line["level"].is_string(), "{line}");
            if line["fields"]["message"] == json!(message) {
                return line;
            }
        }
    }

    /// Posts `body` to the fixture's read surface, and returns the status and the body.
    fn post(&self, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let request = format!(
            "POST /mcp/{SURFACE_READ} HTTP/1.1\r\nhost: 127.0.0.1:{}\r\n\
             content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
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
        (status, serde_json::from_str(body).unwrap())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
}

#[test]
fn with_identity_enforced_a_caller_without_a_token_is_refused() {
    let fixture = Fixture::new().unwrap();
    let running = Running::start("enforced", &startable(enforced(&fixture)));
    let started = &running.listening;
    assert_eq!(started["fields"]["identity"], json!("On"));
    assert_eq!(started["fields"]["audit"], json!("Disabled"));

    let (status, body) = running.post(&initialize());
    assert_eq!(status, 401);
    assert_eq!(body["error"]["message"], json!(IDENTITY_FAILURE));
    let refused = running.event("refused a caller whose identity was not proved");
    assert_eq!(refused["level"], json!("WARN"));
    let answered = running.event("answered a request");
    assert_eq!(answered["fields"]["status"], json!(401));
    assert!(answered["fields"]["elapsed_us"].is_u64(), "{answered}");
}

#[test]
fn with_identity_disabled_it_says_so_and_refuses_every_call() {
    let running = Running::start("disabled", &startable(json!({"disabled": true})));

    let (status, body) = running.post(&initialize());
    assert_eq!(status, 200, "{body}");
    let instructions = body["result"]["instructions"].as_str().unwrap();
    assert!(
        instructions.contains(IDENTITY_DISABLED_NOTE),
        "{instructions}"
    );
    assert!(instructions.contains(AUDIT_DISABLED_NOTE), "{instructions}");

    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": READ_TOOL, "arguments": {}}});
    let (status, body) = running.post(&call);
    assert_eq!(status, 200);
    assert_eq!(body["error"]["message"], json!(IDENTITY_DISABLED));
    let answered = running.event("answered a request");
    assert_eq!(answered["fields"]["status"], json!(200));
    assert_eq!(answered["spans"][0]["name"], json!("request"));
}
