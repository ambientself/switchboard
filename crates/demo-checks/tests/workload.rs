//! `deploy/demo/workload.sh` against a fake gateway. The fake answers as the plans say the
//! gateway does, or misbehaves in exactly one way; every misbehaviour must give a FAIL line
//! naming the check and a non-zero exit, so the demo cannot pass while the gateway is wrong.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use common::{Run, repo, require, scratch, write};
use gateway_core::IDENTITY_FAILURE;
use serde_json::{Value, json};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";
const GOOD_TOKEN: &str = "good-team-a-token";
const OWN: &str = "atlas";
const OTHER: &str = "borealis";
const LIST_TOOL: &str = "docs__list_documents";
const READ_TOOL: &str = "docs__read_document";

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
    /// `docs__read_document` has been withdrawn.
    Withdrawn,
    /// The mock docs server reached directly: 401 for every request.
    Server401,
}

/// Starts the fake on a free loopback port and returns its `/mcp/docs` URL.
fn serve(fake: Fake) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || handle(stream, fake));
        }
    });
    format!("http://127.0.0.1:{port}/mcp/docs")
}

/// A port that accepts connections and never answers: what a dropped route looks like to curl,
/// which then times out (exit 28).
fn black_hole() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    format!("http://127.0.0.1:{port}/mcp")
}

/// A port nothing listens on: curl's connection is refused (exit 7).
fn closed_port() -> String {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}/mcp")
}

fn handle(mut stream: TcpStream, fake: Fake) {
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
    let (status, answer) = answer(fake, bearer.as_deref(), &body);
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

fn answer(fake: Fake, bearer: Option<&str>, body: &Value) -> (u16, Option<Value>) {
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
        "tools/list" => (200, Some(tools(&[READ_TOOL, LIST_TOOL]))),
        "tools/call" => {
            let name = body["params"]["name"].as_str().unwrap_or_default();
            let project = body["params"]["arguments"]["project"].as_str();
            if fake == Fake::AuditDown {
                return (200, Some(error(-32001, AUDIT_FAILURE)));
            }
            if fake == Fake::Withdrawn && name == READ_TOOL {
                return (
                    200,
                    Some(error(
                        -32001,
                        &format!(
                            "Tool `{READ_TOOL}` is not available on surface `docs`. Call `tools/list` to see the tools this surface serves."
                        ),
                    )),
                );
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

    fn without_own_project(mut self) -> Self {
        self.own_project = false;
        self
    }

    fn run(&self, mode: &str) -> Run {
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
            .env_remove("DIRECT_URL");
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
        Run::from(command.output().unwrap())
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
fn a_direct_call_that_times_out_passes_with_the_gateway_still_reachable() {
    let run = Workload::new("direct-dropped", serve(Fake::Gateway))
        .direct(black_hole())
        .run("full");
    assert_passed(&run);
    assert!(
        run.stdout
            .contains("PASS direct call to the server refused (curl exit 28"),
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
    let run = Workload::new("direct-refused", serve(Fake::Gateway))
        .direct(closed_port())
        .run("full");
    assert_failed(&run, "direct call to the server refused");
}

#[test]
fn a_direct_call_the_server_answers_fails_the_run() {
    let run = Workload::new("direct-answered", serve(Fake::Gateway))
        .direct(serve(Fake::Server401))
        .run("full");
    assert_failed(&run, "direct call to the server refused");
}

#[test]
fn an_unreachable_gateway_fails_every_check_it_makes() {
    let run = Workload::new("no-gateway", closed_port()).run("full");
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
        .direct(black_hole())
        .run("before-policy");
    assert_failed(&dropped, "before policy: the direct call connects");
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
    let unreachable = Workload::new("before-no-gateway", closed_port())
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
fn the_workloads_sentences_are_the_cores() {
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
}
