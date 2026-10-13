//! `deploy/demo/workload.sh` against a fake gateway. The fake answers as the plans say the
//! gateway does, or misbehaves in exactly one way; every misbehaviour must give a FAIL line
//! naming the check and a non-zero exit, so the demo cannot pass while the gateway is wrong.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::{
    ClosedPort, Run, black_hole, closed_port, dropped, fake_curl, repo, require, scratch, write,
};
use gateway_core::IDENTITY_FAILURE;
use serde_json::{Value, json};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";
const GOOD_TOKEN: &str = "good-team-a-token";
const OWN: &str = "atlas";
const OTHER: &str = "borealis";
const LIST_TOOL: &str = "docs-team-a__list_documents";
const READ_TOOL: &str = "docs-team-a__read_document";

/// How the fake answers.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Fake {
    /// As the gateway should.
    Gateway,
    /// Lets team A read team B's project.
    AllowsOtherProject,
    /// Denies the other project with a sentence that is not the resource-limit one.
    WrongDenialSentence,
    /// Refuses team A's read of its own project.
    DeniesOwnProject,
    /// Wraps each tool result again: the whole result as JSON in one text block.
    WrapsTwice,
    /// Takes any bearer as team A.
    AcceptsAnyToken,
    /// Refuses a bad token with 401 but another sentence.
    WrongIdentitySentence,
    /// The audit database is down: every call gets the audit-failure sentence.
    AuditDown,
    /// Team A's read tool has been withdrawn.
    Withdrawn,
    /// Team A's list tool has been withdrawn.
    WithdrawnList,
    /// Both of team A's tools have been withdrawn, as a reach mismatch withdraws them.
    WithdrawnAll,
    /// Forwards a call with an argument the tool's approval does not declare, and the server
    /// answers it.
    ForwardsUndeclared,
    /// Waits for slow-doc's answer past the deadline, and passes it on.
    SlowDocAnswers,
    /// Holds no cap on the team's calls in flight.
    NoCap,
    /// The mock docs server reached directly: 401 for every request.
    Server401,
}

/// The team's cap on calls in flight to its server, as the fake holds it: decision 0014's.
const TEAM_CAP: usize = 8;

/// Starts the fake on a free loopback port and returns its `/mcp/docs-team-a` URL: team A's
/// surface, whose name the workload's tool names start with.
fn serve(fake: Fake) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let in_flight = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let in_flight = Arc::clone(&in_flight);
            thread::spawn(move || handle(stream, fake, &in_flight));
        }
    });
    format!("http://127.0.0.1:{port}/mcp/docs-team-a")
}

fn handle(mut stream: TcpStream, fake: Fake, in_flight: &AtomicUsize) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let header = |name: &str| {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
    let body: Value =
        serde_json::from_slice(&buffer[header_end..header_end + length]).unwrap_or(Value::Null);
    let bearer = header("authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned));
    let (status, answer) = answer(fake, bearer.as_deref(), &body, in_flight);
    let text = answer.map(|v| v.to_string()).unwrap_or_default();
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        _ => "Unauthorized",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
}

fn error(code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}})
}

fn result(value: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": value})
}

fn read_ok(project: &str) -> Value {
    result(
        json!({"content": [{"type": "text", "text": format!("documents of {project}")}], "isError": false}),
    )
}

/// What the gateway once answered a proxied call with: the server's whole result as the text
/// of one block, and again as structured content.
fn wrapped(answer: Value) -> Value {
    let inner = answer["result"].clone();
    result(json!({
        "content": [{"type": "text", "text": inner.to_string()}],
        "structuredContent": inner,
        "isError": false,
    }))
}

fn outside_limit(project: &str) -> Value {
    error(
        -32001,
        &format!(
            "Tool `{READ_TOOL}` names docs project `{project}`, which is outside what workload \
             `system:serviceaccount:team-a:mock-workload` of team `team-a` from issuer \
             `https://kubernetes.default.svc.cluster.local` may reach. Name only resources within that limit."
        ),
    )
}

/// A tool result with `isError` true: the gateway's answer to a call that ran and failed.
fn tool_error(message: &str) -> Value {
    result(json!({"content": [{"type": "text", "text": message}], "isError": true}))
}

/// A read of slow-doc: held for a second and then answered as late, or, past the team's cap,
/// refused with the team-capacity sentence, as the gateway answers it.
fn slow_read(fake: Fake, in_flight: &AtomicUsize) -> Value {
    if fake == Fake::SlowDocAnswers {
        return read_ok(OWN);
    }
    let held = in_flight.fetch_add(1, Ordering::SeqCst);
    if held >= TEAM_CAP && fake != Fake::NoCap {
        in_flight.fetch_sub(1, Ordering::SeqCst);
        return error(
            -32001,
            &gateway::bulkhead::team_at_capacity("docs-team-a", READ_TOOL),
        );
    }
    thread::sleep(Duration::from_secs(1));
    in_flight.fetch_sub(1, Ordering::SeqCst);
    tool_error(connector_proxy::outcome::TIMED_OUT)
}

fn answer(
    fake: Fake,
    bearer: Option<&str>,
    body: &Value,
    in_flight: &AtomicUsize,
) -> (u16, Option<Value>) {
    if fake == Fake::Server401 {
        return (401, Some(json!({"error": "unauthorized"})));
    }
    let accepted = fake == Fake::AcceptsAnyToken || bearer == Some(GOOD_TOKEN);
    if !accepted {
        let sentence = if fake == Fake::WrongIdentitySentence {
            "Bad token."
        } else {
            IDENTITY_FAILURE
        };
        return (
            401,
            Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32001, "message": sentence}}),
            ),
        );
    }
    let method = body["method"].as_str().unwrap_or_default();
    let tools = |names: &[&str]| {
        let tools: Vec<Value> = names
            .iter()
            .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
            .collect();
        result(json!({"tools": tools}))
    };
    match method {
        "initialize" => (
            200,
            Some(result(
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "0"}}),
            )),
        ),
        "notifications/initialized" => (202, None),
        "ping" => (200, Some(result(json!({})))),
        "tools/list" if fake == Fake::Withdrawn => (200, Some(tools(&[LIST_TOOL]))),
        "tools/list" if fake == Fake::WithdrawnList => (200, Some(tools(&[READ_TOOL]))),
        "tools/list" if fake == Fake::WithdrawnAll => (200, Some(tools(&[]))),
        "tools/list" => (200, Some(tools(&[READ_TOOL, LIST_TOOL]))),
        "tools/call" => {
            let name = body["params"]["name"].as_str().unwrap_or_default();
            let arguments = &body["params"]["arguments"];
            let project = arguments["project"].as_str();
            if fake == Fake::AuditDown {
                return (200, Some(error(-32001, AUDIT_FAILURE)));
            }
            if (fake == Fake::Withdrawn && name == READ_TOOL)
                || (fake == Fake::WithdrawnList && name == LIST_TOOL)
                || fake == Fake::WithdrawnAll
            {
                return (
                    200,
                    Some(error(
                        -32001,
                        &format!(
                            "Tool `{name}` is not available on surface `docs-team-a`. Call `tools/list` to see the tools this surface serves."
                        ),
                    )),
                );
            }
            // Only `project`, and `document` for the read tool, are declared.
            let declared = arguments.as_object().is_none_or(|arguments| {
                arguments
                    .keys()
                    .all(|key| key == "project" || (key == "document" && name == READ_TOOL))
            });
            if !declared && fake != Fake::ForwardsUndeclared {
                return (200, Some(tool_error(&gateway::undeclared_argument(name))));
            }
            if project == Some(OWN) && arguments["document"] == "slow-doc" {
                return (200, Some(slow_read(fake, in_flight)));
            }
            let answer = match project {
                None => error(
                    -32001,
                    &format!(
                        "Tool `{name}` reaches resources the gateway must check, and this call named none of them, so it cannot be allowed. Name the resource the call is for."
                    ),
                ),
                Some(OWN) if fake == Fake::DeniesOwnProject => outside_limit(OWN),
                Some(OWN) if fake == Fake::WrapsTwice => wrapped(read_ok(OWN)),
                Some(OWN) => read_ok(OWN),
                Some(other) if fake == Fake::AllowsOtherProject => read_ok(other),
                Some(_) if fake == Fake::WrongDenialSentence => error(-32001, "Denied."),
                Some(other) => outside_limit(other),
            };
            (200, Some(answer))
        }
        _ => (200, Some(error(-32601, "Method not found"))),
    }
}

/// The workload's environment for team A against `gateway`.
struct Workload {
    gateway: String,
    token: Option<PathBuf>,
    direct: Option<String>,
    own_project: bool,
    dir: PathBuf,
    /// A directory put first on PATH, holding the fake `curl`.
    bin: Option<PathBuf>,
    /// The closed ports its URLs name, held as long as it lives.
    held: Vec<ClosedPort>,
}

impl Workload {
    fn new(name: &str, gateway: String) -> Self {
        require(&["sh", "curl", "jq"]);
        let dir = scratch(name);
        let token = write(&dir, "token", GOOD_TOKEN);
        Workload {
            gateway,
            token: Some(token),
            direct: None,
            own_project: true,
            dir,
            bin: None,
            held: Vec::new(),
        }
    }

    fn token(mut self, token: &str) -> Self {
        self.token = Some(write(&self.dir, "token", token));
        self
    }

    fn missing_token(mut self) -> Self {
        self.token = Some(self.dir.join("no-such-token"));
        self
    }

    fn direct(mut self, url: String) -> Self {
        self.direct = Some(url);
        self
    }

    /// A direct call to a route network policy drops: the fake `curl` times out on it before it
    /// connects, as a dropped route does (exit 28, no connection made). Every other request goes
    /// to the real curl.
    fn direct_dropped(mut self) -> Self {
        let hole = dropped();
        let bin = self.dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        fake_curl(&bin, &[&hole.url]);
        self.bin = Some(bin);
        self.direct = Some(hole.url.clone());
        self.held.push(hole);
        self
    }

    fn without_own_project(mut self) -> Self {
        self.own_project = false;
        self
    }

    fn run(&self, mode: &str) -> Run {
        Run::from(self.command(mode).output().unwrap())
    }

    /// Runs the workload with `args`: the mode and its own arguments.
    fn run_with(&self, args: &[&str]) -> Run {
        let mut command = self.command(args[0]);
        command.args(&args[1..]);
        Run::from(command.output().unwrap())
    }

    fn command(&self, mode: &str) -> Command {
        let bad = write(
            &self.dir,
            "wrong-audience-token",
            "real-token-for-another-audience",
        );
        let mut command = Command::new("sh");
        command
            .arg(repo().join("deploy/demo/workload.sh"))
            .arg(mode)
            .env("GATEWAY_URL", &self.gateway)
            .env("OTHER_PROJECT", OTHER)
            .env("BAD_TOKEN_FILES", &bad)
            .env("DIRECT_TIMEOUT", "1")
            .env_remove("TOKEN_URL")
            .env_remove("BAD_TOKEN_URLS")
            .env_remove("DIRECT_URL")
            .env_remove("IDLE_SECONDS");
        if let Some(bin) = &self.bin {
            command.env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        }
        if let Some(token) = &self.token {
            command.env("TOKEN_FILE", token);
        }
        if let Some(direct) = &self.direct {
            command.env("DIRECT_URL", direct);
        }
        if self.own_project {
            command.env("OWN_PROJECT", OWN);
        } else {
            command.env_remove("OWN_PROJECT");
        }
        command
    }
}

/// The run passed every check: exit 0, no FAIL line, and a RESULT line counting every PASS.
fn assert_passed(run: &Run) {
    let passes = run.lines("PASS ").len();
    assert!(passes > 0, "{}", run.transcript());
    assert!(run.lines("FAIL ").is_empty(), "{}", run.transcript());
    assert_eq!(run.status, Some(0), "{}", run.transcript());
    assert_eq!(
        run.stdout.lines().last(),
        Some(format!("RESULT: PASS ({passes}/{passes})").as_str()),
        "{}",
        run.transcript()
    );
}

/// The run failed the check named `check`, exited non-zero, and said so in its RESULT line.
fn assert_failed(run: &Run, check: &str) {
    assert!(
        run.failed(check),
        "no FAIL line names `{check}`\n{}",
        run.transcript()
    );
    assert_eq!(run.status, Some(1), "{}", run.transcript());
    let last = run.stdout.lines().last().unwrap_or_default();
    assert!(last.starts_with("RESULT: FAIL ("), "{}", run.transcript());
}

#[test]
fn a_gateway_that_behaves_passes_every_check() {
    let run = Workload::new("behaves", serve(Fake::Gateway)).run("full");
    assert_passed(&run);
    for check in [
        "initialize: protocol version",
        "tools/list: names",
        "read own project atlas: isError",
        "read other project borealis: the resource-limit sentence",
        "read naming no project: the none-named sentence",
        "identity failure (no token): sentence",
        "identity failure (not a token): sentence",
    ] {
        assert!(
            run.lines("PASS ").iter().any(|line| line.contains(check)),
            "no PASS for `{check}`\n{}",
            run.transcript()
        );
    }
}

#[test]
fn a_direct_call_dropped_before_it_connects_passes_with_the_gateway_still_reachable() {
    let run = Workload::new("direct-dropped", serve(Fake::Gateway))
        .direct_dropped()
        .run("full");
    assert_passed(&run);
    assert!(
        run.stdout
            .contains("PASS direct call to the server refused before it connected ("),
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains("PASS same pod's read through the gateway: isError"),
        "{}",
        run.transcript()
    );
}

#[test]
fn reading_the_other_teams_project_fails_the_run() {
    let run = Workload::new("other-project", serve(Fake::AllowsOtherProject)).run("full");
    assert_failed(&run, "read other project borealis: error code");
}

#[test]
fn a_denial_without_the_resource_limit_sentence_fails_the_run() {
    let run = Workload::new("wrong-denial", serve(Fake::WrongDenialSentence)).run("full");
    assert_failed(
        &run,
        "read other project borealis: the resource-limit sentence",
    );
}

#[test]
fn an_error_answer_to_the_teams_own_read_fails_the_run() {
    let run = Workload::new("own-denied", serve(Fake::DeniesOwnProject)).run("full");
    assert_failed(&run, "read own project atlas: isError");
}

#[test]
fn a_result_wrapped_twice_fails_the_run() {
    let run = Workload::new("wrapped", serve(Fake::WrapsTwice)).run("full");
    for call in ["list own project atlas", "read own project atlas"] {
        assert_failed(
            &run,
            &format!("{call}: the server's own content, not wrapped again"),
        );
    }
}

#[test]
fn a_gateway_that_accepts_a_bad_token_fails_the_run() {
    let run = Workload::new("any-token", serve(Fake::AcceptsAnyToken)).run("full");
    assert_failed(&run, "identity failure (not a token): HTTP status");
    assert_failed(&run, "identity failure (no token): HTTP status");
    assert_failed(&run, "wrong-audience-token): HTTP status");
}

#[test]
fn an_identity_refusal_with_another_sentence_fails_the_run() {
    let run = Workload::new("identity-sentence", serve(Fake::WrongIdentitySentence)).run("full");
    assert_failed(&run, "identity failure (not a token): sentence");
}

#[test]
fn a_direct_call_that_is_refused_rather_than_dropped_fails_the_run() {
    // A refused connection (curl exit 7) is what a stopped server or a wrong port looks like.
    // It proves nothing about network policy.
    let closed = closed_port();
    let run = Workload::new("direct-refused", serve(Fake::Gateway))
        .direct(closed.url.clone())
        .run("full");
    assert_failed(&run, "direct call to the server refused");
}

#[test]
fn a_direct_call_that_connects_and_gets_no_answer_fails_the_run() {
    // curl exits 28 here too, but it connected: a slow or stalled server, or a tarpit, took the
    // connection (issue #83). That is not a route network policy dropped.
    let run = Workload::new("direct-connected", serve(Fake::Gateway))
        .direct(black_hole())
        .run("full");
    assert_failed(
        &run,
        "direct call to the server refused before it connected (http://127.0.0.1:",
    );
    assert!(
        run.failed("(got 'curl exit 28, 1 connections', want 'curl exit 28, 0 connections')"),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_direct_call_the_server_answers_fails_the_run() {
    let run = Workload::new("direct-answered", serve(Fake::Gateway))
        .direct(serve(Fake::Server401))
        .run("full");
    assert_failed(&run, "direct call to the server refused");
}

/// #168: a closed port refuses connections, to a socket and to curl, and stays reserved while
/// its guard lives: no socket that does not set SO_REUSEADDR can bind it, and on Linux, where CI
/// runs, not even one that does, as std's listener does for the tests' fake servers.
#[test]
fn a_closed_port_refuses_connections_and_stays_reserved_while_held() {
    let closed = closed_port();
    let port: u16 = common::port_of(&closed.url).parse().unwrap();
    let address: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let error = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "{error}"
    );
    let curl = Command::new("curl")
        .args(["-q", "-sS", "-o", "/dev/null", "-m", "5", &closed.url])
        .output()
        .unwrap();
    assert_eq!(curl.status.code(), Some(7), "{curl:?}");

    let plain = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    assert!(
        plain.bind(&address.into()).is_err(),
        "another socket bound the held port {port}"
    );
    if cfg!(target_os = "linux") {
        assert!(
            TcpListener::bind(address).is_err(),
            "a listener bound the held port {port}"
        );
    }
}

#[test]
fn an_unreachable_gateway_fails_every_check_it_makes() {
    let gateway = closed_port();
    let run = Workload::new("no-gateway", gateway.url.clone()).run("full");
    assert_failed(
        &run,
        "initialize: HTTP status (got 'curl exit 7', want '200')",
    );
    assert!(run.lines("PASS ").is_empty(), "{}", run.transcript());
}

#[test]
fn a_missing_token_is_a_failure_not_a_skip() {
    let run = Workload::new("no-token", serve(Fake::Gateway))
        .missing_token()
        .run("full");
    assert_failed(&run, "setup: cannot read TOKEN_FILE");
}

#[test]
fn before_the_policy_the_server_must_answer_401() {
    let passing = Workload::new("before-ok", serve(Fake::Gateway))
        .direct(serve(Fake::Server401))
        .run("before-policy");
    assert_passed(&passing);
    // The positive control, in the same pod: the gateway's own call to the server succeeds.
    assert!(
        passing
            .stdout
            .contains("PASS before policy: read own project through the gateway: isError"),
        "{}",
        passing.transcript()
    );
    let dropped = Workload::new("before-dropped", serve(Fake::Gateway))
        .direct_dropped()
        .run("before-policy");
    assert_failed(&dropped, "before policy: the direct call connects");
    // A server that takes the connection and never answers did not answer 401 either.
    let stalled = Workload::new("before-stalled", serve(Fake::Gateway))
        .direct(black_hole())
        .run("before-policy");
    assert_failed(&stalled, "before policy: the direct call connects");
    // A server that accepts the workload's own token would mean the workload could go around
    // the gateway.
    let accepting = Workload::new("before-accepting", serve(Fake::Gateway))
        .direct(serve(Fake::Gateway))
        .run("before-policy");
    assert_failed(
        &accepting,
        "before policy: the server refuses the workload's own token",
    );
    // A gateway that refuses the read, or cannot be reached, shows nothing about the server.
    let refusing = Workload::new("before-gateway-refuses", serve(Fake::DeniesOwnProject))
        .direct(serve(Fake::Server401))
        .run("before-policy");
    assert_failed(
        &refusing,
        "before policy: read own project through the gateway: isError",
    );
    let gateway = closed_port();
    let unreachable = Workload::new("before-no-gateway", gateway.url.clone())
        .direct(serve(Fake::Server401))
        .run("before-policy");
    assert_failed(
        &unreachable,
        "before policy: read own project through the gateway: HTTP status",
    );
}

#[test]
fn before_the_policy_the_workload_needs_its_own_project() {
    let run = Workload::new("before-no-project", serve(Fake::Gateway))
        .direct(serve(Fake::Server401))
        .without_own_project()
        .run("before-policy");
    assert_ne!(run.status, Some(0), "{}", run.transcript());
    assert!(run.lines("PASS ").is_empty(), "{}", run.transcript());
    assert!(run.stderr.contains("OWN_PROJECT"), "{}", run.transcript());
}

#[test]
fn a_token_outside_the_manifest_must_be_refused() {
    let refused = Workload::new("stranger", serve(Fake::Gateway))
        .token("stranger-token")
        .run("refused");
    assert_passed(&refused);
    let accepted = Workload::new("stranger-accepted", serve(Fake::AcceptsAnyToken))
        .token("stranger-token")
        .run("refused");
    assert_failed(&accepted, "identity failure (own token): HTTP status");
}

#[test]
fn with_the_database_down_the_call_gets_the_audit_sentence() {
    assert_passed(&Workload::new("audit-down", serve(Fake::AuditDown)).run("audit-down"));
    let run = Workload::new("audit-up", serve(Fake::Gateway)).run("audit-down");
    assert_failed(&run, "read while the audit database is down: error code");
}

#[test]
fn a_withdrawn_tool_leaves_the_list_and_is_refused() {
    assert_passed(&Workload::new("withdrawn", serve(Fake::Withdrawn)).run("withdrawn"));
    let run = Workload::new("not-withdrawn", serve(Fake::Gateway)).run("withdrawn");
    assert_failed(&run, "tools/list after withdrawal: names");
    assert_failed(&run, "call to the withdrawn tool: error code");
}

#[test]
fn a_withdrawn_list_tool_leaves_the_list_and_is_refused() {
    assert_passed(
        &Workload::new("withdrawn-list", serve(Fake::WithdrawnList))
            .run_with(&["withdrawn", "list"]),
    );
    let run =
        Workload::new("list-not-withdrawn", serve(Fake::Gateway)).run_with(&["withdrawn", "list"]);
    assert_failed(&run, "tools/list after withdrawal: names");
    assert_failed(&run, "call to the withdrawn tool: error code");
    // The read tool's withdrawal does not pass for the list tool's.
    let run =
        Workload::new("read-withdrawn", serve(Fake::Withdrawn)).run_with(&["withdrawn", "list"]);
    assert_failed(&run, "tools/list after withdrawal: names");
    let run =
        Workload::new("withdrawn-what", serve(Fake::Gateway)).run_with(&["withdrawn", "search"]);
    assert_failed(&run, "setup: withdrawn takes read, list or all");
}

/// After a reach mismatch both of the team's tools are withdrawn: tools/list lists nothing, and
/// a call to the list tool is refused as not available.
#[test]
fn both_withdrawn_tools_leave_the_list_and_are_refused() {
    assert_passed(
        &Workload::new("withdrawn-all", serve(Fake::WithdrawnAll)).run_with(&["withdrawn", "all"]),
    );
    for (case, fake) in [
        ("all-not-withdrawn", Fake::Gateway),
        ("all-but-read", Fake::WithdrawnList),
    ] {
        let run = Workload::new(case, serve(fake)).run_with(&["withdrawn", "all"]);
        assert_failed(&run, "tools/list after withdrawal: names");
    }
    let run = Workload::new("all-but-list", serve(Fake::Withdrawn)).run_with(&["withdrawn", "all"]);
    assert_failed(&run, "tools/list after withdrawal: names");
    assert_failed(&run, "call to the withdrawn tool: error code");
}

#[test]
fn a_served_tool_is_listed_and_answered() {
    assert_passed(&Workload::new("served", serve(Fake::Gateway)).run("served"));
    let run = Workload::new("served-withdrawn", serve(Fake::WithdrawnList)).run("served");
    assert_failed(&run, "tools/list: names");
    assert_failed(&run, "list own project atlas: isError");
}

#[test]
fn an_undeclared_argument_must_be_refused_before_forwarding() {
    let run = Workload::new("undeclared", serve(Fake::Gateway)).run("undeclared");
    assert_passed(&run);
    assert!(
        run.stdout
            .contains("PASS read with an undeclared argument: the undeclared-argument sentence"),
        "{}",
        run.transcript()
    );
    let run = Workload::new("forwarded", serve(Fake::ForwardsUndeclared)).run("undeclared");
    assert_failed(&run, "read with an undeclared argument: isError");
    assert_failed(
        &run,
        "read with an undeclared argument: the undeclared-argument sentence",
    );
}

#[test]
fn a_read_past_its_deadline_must_be_answered_as_late() {
    let run = Workload::new("hang", serve(Fake::Gateway)).run("hang");
    assert_passed(&run);
    // It prints how long its client waited, in the line demo.sh's check_hang reads: the fake
    // holds the read a second.
    let elapsed: Vec<u64> = run
        .stdout
        .lines()
        .filter_map(|line| {
            line.strip_prefix("     read of slow-doc: answered after ")?
                .strip_suffix(" ms by the client's clock")?
                .parse()
                .ok()
        })
        .collect();
    assert_eq!(elapsed.len(), 1, "{}", run.transcript());
    assert!((1000..5000).contains(&elapsed[0]), "{}", run.transcript());
    let run = Workload::new("hang-answered", serve(Fake::SlowDocAnswers)).run("hang");
    assert_failed(&run, "read of slow-doc: isError");
    assert_failed(&run, "read of slow-doc: the late-answer sentence");
}

#[test]
fn one_call_over_the_team_cap_must_be_refused_and_the_rest_held_to_the_deadline() {
    let calls = (TEAM_CAP + 1).to_string();
    let run = Workload::new("overload", serve(Fake::Gateway)).run_with(&["overload", &calls]);
    assert_passed(&run);
    assert!(
        run.stdout
            .contains("PASS overload: one of 9 reads refused with the team-capacity sentence"),
        "{}",
        run.transcript()
    );
    // It prints how long its client waited on each read held to the deadline, in the lines
    // demo.sh's check_overload reads: the fake holds each a second.
    let elapsed: Vec<u64> = run
        .stdout
        .lines()
        .filter_map(|line| {
            let line = line.strip_prefix("     read ")?;
            let (number, rest) = line.split_once(' ')?;
            number.parse::<u32>().ok()?;
            rest.strip_prefix("of slow-doc, held: answered after ")?
                .strip_suffix(" ms by the client's clock")?
                .parse()
                .ok()
        })
        .collect();
    assert_eq!(elapsed.len(), TEAM_CAP, "{}", run.transcript());
    assert!(
        elapsed.iter().all(|ms| (1000..5000).contains(ms)),
        "{}",
        run.transcript()
    );
    let run = Workload::new("no-cap", serve(Fake::NoCap)).run_with(&["overload", &calls]);
    assert_failed(
        &run,
        "overload: one of 9 reads refused with the team-capacity sentence (got '0', want '1')",
    );
    assert_failed(&run, "overload: the other 8 held until the deadline");
    // Two over the cap: two are refused, one more than the step expects.
    let run = Workload::new("two-over", serve(Fake::Gateway)).run_with(&["overload", "10"]);
    assert_failed(
        &run,
        "overload: one of 10 reads refused with the team-capacity sentence (got '2', want '1')",
    );
    let run = Workload::new("overload-answered", serve(Fake::SlowDocAnswers))
        .run_with(&["overload", &calls]);
    assert_failed(&run, "overload: no other answer (got '9', want '0')");
    for count in [None, Some("1"), Some("nine")] {
        let mut args = vec!["overload"];
        args.extend(count);
        let run = Workload::new("overload-count", serve(Fake::Gateway)).run_with(&args);
        assert_failed(&run, "setup: overload takes");
        assert!(run.lines("PASS ").is_empty(), "{}", run.transcript());
    }
}

#[test]
fn every_steady_read_must_be_allowed() {
    assert_passed(&Workload::new("steady", serve(Fake::Gateway)).run_with(&["steady", "2"]));
    let run =
        Workload::new("steady-denied", serve(Fake::DeniesOwnProject)).run_with(&["steady", "2"]);
    assert_failed(
        &run,
        "steady reads of atlas: every one of 2 allowed (got '0', want '2')",
    );
    let run = Workload::new("steady-count", serve(Fake::Gateway)).run_with(&["steady"]);
    assert_failed(&run, "setup: steady takes");
}

#[test]
fn the_workloads_sentences_are_the_gateways() {
    let script = common::read("deploy/demo/workload.sh");
    assert!(
        script.contains(&format!("IDENTITY_FAILURE='{IDENTITY_FAILURE}'")),
        "workload.sh's identity sentence differs from gateway_core::IDENTITY_FAILURE"
    );
    // The core keeps the audit sentence private; this is its text in crates/gateway-core/src/sentences.rs.
    assert!(
        script.contains(&format!("AUDIT_FAILURE='{AUDIT_FAILURE}'")),
        "workload.sh's audit sentence differs"
    );
    assert!(
        script.contains(&format!(
            "LATE_ANSWER=\"{}\"",
            connector_proxy::outcome::TIMED_OUT
        )),
        "workload.sh's late-answer sentence differs from connector_proxy::outcome::TIMED_OUT"
    );
    // Each sentence that names a tool or a server is a printf format, `%s` in each place.
    assert!(
        script.contains(&format!(
            "  printf '{}' \"$1\"\n",
            gateway::undeclared_argument("%s")
        )),
        "workload.sh's undeclared-argument sentence differs from gateway::undeclared_argument"
    );
    assert!(
        script.contains(&format!(
            "  printf '{}' \"$1\" \"$2\"\n",
            gateway::bulkhead::team_at_capacity("%s", "%s")
        )),
        "workload.sh's team-capacity sentence differs from gateway::bulkhead::team_at_capacity"
    );
}

/// Starts `workload.sh idle` and returns it, with its first line, once it says it is waiting.
fn start_idle(name: &str, seconds: Option<&str>) -> (std::process::Child, String) {
    // Idle makes no call, so the closed port need not outlive this.
    let gateway = closed_port();
    let workload = Workload::new(name, gateway.url.clone());
    let mut command = workload.command("idle");
    if let Some(seconds) = seconds {
        command.env("IDLE_SECONDS", seconds);
    }
    // Its own process group, so finish_within can end a sleep it left behind.
    let mut child = command
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    stdout.read_line(&mut first).unwrap();
    child.stdout = Some(stdout.into_inner());
    (child, first)
}

/// Waits for `child` at most `limit`, and returns its run: `first`, then the rest it printed.
fn finish_within(mut child: std::process::Child, first: String, limit: Duration) -> Run {
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > limit {
            let _ = child.kill();
            panic!("workload.sh idle did not end within {limit:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
    // A shell that died by the signal leaves its sleep holding the output open; end it, or
    // reading the output would wait out the sleep. A shell that ended as it should left none.
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{}", child.id())])
        .stderr(Stdio::null())
        .status();
    let mut run = Run::from(child.wait_with_output().unwrap());
    run.stdout = first + &run.stdout;
    run
}

#[test]
fn idle_waits_until_sigterm_and_then_passes() {
    // The route check's pod runs until the driver deletes its Job, and the pod then gets
    // SIGTERM. It must end at once and pass, not wait out its 600 s or die by the signal.
    let (child, first) = start_idle("idle-term", None);
    assert!(
        first.contains("idle: waiting for SIGTERM, at most 600s"),
        "{first:?}"
    );
    let pid = child.id().to_string();
    let killed = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    assert!(killed.success());
    let run = finish_within(child, first, Duration::from_secs(5));
    assert_passed(&run);
    assert_eq!(run.lines("PASS "), ["PASS idle"], "{}", run.transcript());
}

#[test]
fn idle_ends_and_passes_after_its_seconds() {
    let (child, first) = start_idle("idle-timeout", Some("1"));
    let run = finish_within(child, first, Duration::from_secs(5));
    assert_passed(&run);
    assert_eq!(run.lines("PASS "), ["PASS idle"], "{}", run.transcript());
}

#[test]
fn idle_waits_at_most_ten_minutes() {
    for seconds in ["0", "601", "ten"] {
        let gateway = closed_port();
        let mut command = Workload::new("idle-bad", gateway.url.clone()).command("idle");
        let run = Run::from(command.env("IDLE_SECONDS", seconds).output().unwrap());
        assert_failed(&run, "setup: IDLE_SECONDS");
        assert!(run.lines("PASS ").is_empty(), "{}", run.transcript());
    }
}
