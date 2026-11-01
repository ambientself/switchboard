//! What the connector logs when a side effect's outcome becomes `unknown` because its server gave
//! no definite answer: one warning per call, naming the connector, the tool, the kind of answer
//! it got in place of one and its HTTP status, and a JSON-RPC error's code. Never the server's
//! body or the credential. A read's failure is an error, recorded on its row, and logs nothing
//! here.
//!
//! A test binary of its own, because it installs the global log subscriber: tests running
//! alongside without one would have `tracing` remember the log line as unwatched.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    GATEWAY_TOKEN, Harness, Scripted, Step, connector, json_response, response, result_of_size,
    text_result, upstream,
};
use connector_proxy::{SIDE_EFFECT_UNKNOWN_EVENT, Upstream};
use gateway_core::ToolName;
use gateway_core::audit::Answer;
use gateway_testkit::{CONNECTOR, DRAFT_TOOL, READ_TOOL};
use serde_json::{Value, json};

const CAP: usize = 1000;
const DEADLINE: Duration = Duration::from_millis(500);

/// Text the server sends in its bodies. None of it may reach the log.
const CANARIES: [&str; 5] = [
    "status-body-canary",
    "rpc-message-canary",
    "tool-text-canary",
    "html-body-canary",
    "oversized-canary",
];

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
    /// Every line logged so far for a side effect whose outcome became `unknown`.
    fn unknown(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|line| line.contains(SIDE_EFFECT_UNKNOWN_EVENT))
            .map(str::to_owned)
            .collect()
    }
}

/// A connector to `server` with a small cap and a short deadline, serving the draft tool, which
/// is classified `propose`, besides the fixture's read tools.
fn bounded(server: &Scripted) -> connector_proxy::ProxyConnector {
    connector(Upstream {
        deadline: DEADLINE,
        max_response_bytes: CAP,
        ..upstream(server.url()).tool(ToolName::parse(DRAFT_TOOL).unwrap(), "draft_document")
    })
}

/// A script made at run time, for a table of cases.
type BoxedScript = Arc<dyn Fn(&Value) -> Vec<Step> + Send + Sync>;

fn status(status: &'static str) -> BoxedScript {
    Arc::new(move |_: &Value| {
        vec![Step::Write(response(
            status,
            "text/plain",
            b"status-body-canary",
        ))]
    })
}

#[tokio::test]
async fn a_side_effect_that_becomes_unknown_logs_its_status_and_kind_and_never_its_body() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let captured = captured.clone();
            move || captured.clone()
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // Each case: what the server does, the kind logged, its status, and its JSON-RPC code.
    let cases: Vec<(&str, BoxedScript, Option<u16>, Option<i64>)> = vec![
        ("status", status("409 Conflict"), Some(409), None),
        ("status", status("401 Unauthorized"), Some(401), None),
        ("status", status("403 Forbidden"), Some(403), None),
        (
            "status",
            status("500 Internal Server Error"),
            Some(500),
            None,
        ),
        (
            "rpc_error",
            Arc::new(|request: &Value| {
                vec![Step::Write(json_response(&json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {"code": -32602, "message": "rpc-message-canary"},
                })))]
            }),
            Some(200),
            Some(-32602),
        ),
        (
            "tool_failed",
            Arc::new(|request: &Value| {
                vec![Step::Write(json_response(&json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {"content": [{"type": "text", "text": "tool-text-canary"}], "isError": true},
                })))]
            }),
            Some(200),
            None,
        ),
        (
            "not_mcp",
            Arc::new(|_: &Value| {
                vec![Step::Write(response(
                    "200 OK",
                    "text/html",
                    b"<p>html-body-canary</p>",
                ))]
            }),
            Some(200),
            None,
        ),
        (
            "too_large",
            Arc::new(|request: &Value| {
                let mut body = result_of_size(request, CAP + 1);
                body.extend_from_slice(b"oversized-canary");
                vec![Step::Write(response("200 OK", "application/json", &body))]
            }),
            Some(200),
            None,
        ),
        (
            "timed_out",
            Arc::new(|_: &Value| vec![Step::Sleep(DEADLINE * 3)]),
            None,
            None,
        ),
        (
            "exchange_failed",
            Arc::new(|_: &Value| Vec::new()),
            None,
            None,
        ),
    ];
    for (kind, script, status, rpc_code) in cases {
        let case = format!("{kind} {status:?}");
        let before = captured.unknown().len();
        let read_script = script.clone();
        let read_server = Scripted::start(move |request: &Value| read_script(request)).await;
        let harness = Harness::new();
        let answer = harness
            .call(
                &bounded(&read_server),
                READ_TOOL,
                json!({"document": "plan"}),
            )
            .await;
        assert!(matches!(answer, Answer::Error(_)), "{case}: {answer:?}");
        assert_eq!(
            captured.unknown().len(),
            before,
            "{case}: a read's error was logged as unknown"
        );

        let server = Scripted::start(move |request: &Value| script(request)).await;
        let harness = Harness::new();
        let answer = harness
            .call(&bounded(&server), DRAFT_TOOL, json!({"document": "plan"}))
            .await;
        assert!(matches!(answer, Answer::Unknown(_)), "{case}: {answer:?}");
        let lines = captured.unknown();
        assert_eq!(lines.len(), before + 1, "{case}: {lines:#?}");
        let line = lines.last().unwrap();
        assert!(line.contains("WARN"), "{case}: {line}");
        assert!(
            line.contains(&format!("connector={CONNECTOR}")),
            "{case}: {line}"
        );
        assert!(
            line.contains(&format!("tool={DRAFT_TOOL}")),
            "{case}: {line}"
        );
        assert!(line.contains(&format!("kind=\"{kind}\"")), "{case}: {line}");
        match status {
            Some(status) => assert!(line.contains(&format!("status={status}")), "{case}: {line}"),
            None => assert!(!line.contains("status="), "{case}: {line}"),
        }
        match rpc_code {
            Some(code) => assert!(line.contains(&format!("rpc_code={code}")), "{case}: {line}"),
            None => assert!(!line.contains("rpc_code="), "{case}: {line}"),
        }
        for canary in CANARIES {
            assert!(
                !line.contains(canary),
                "{case}: the body was logged: {line}"
            );
        }
        assert!(!line.contains(GATEWAY_TOKEN), "{case}: {line}");
        assert!(!line.contains(harness.caller_token()), "{case}: {line}");
    }

    // A side effect the server answered: nothing is logged.
    let before = captured.unknown().len();
    let server = Scripted::start(|request: &Value| {
        vec![Step::Write(json_response(&text_result(request, "drafted")))]
    })
    .await;
    let answer = Harness::new()
        .call(&bounded(&server), DRAFT_TOOL, json!({"document": "plan"}))
        .await;
    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
    assert_eq!(captured.unknown().len(), before);
}
