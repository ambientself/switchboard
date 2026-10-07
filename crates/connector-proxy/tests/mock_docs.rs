//! The connector against the mock document server, in process on loopback, through the core's
//! audited path: what the server saw, the deadline and the cap, and how each failure maps.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{
    GATEWAY_TOKEN, Harness, LIST_UPSTREAM, READ_UPSTREAM, WRONG_TOKEN, connector, credentials_for,
    prefix, upstream,
};
use connector_proxy::{DEFAULT_DEADLINE, ProxyConnector, Upstream, outcome};
use gateway_core::ToolName;
use gateway_core::audit::{Answer, Outcome};
use gateway_testkit::{CONNECTOR, READ_TOOL, SCOPED_READ_TOOL};
use mock_docs_server::{
    AcceptedCredential, Config, FAIL_CODE, FAIL_DOC, HANG_DOC, HUGE_DOC, PLAN, Running, SLOW_DOC,
    start,
};
use serde_json::{Value, json};

const SLOW: Duration = Duration::from_millis(200);
const SHORT_DEADLINE: Duration = Duration::from_millis(400);

async fn mock() -> Running {
    start(Config {
        slow: SLOW,
        ..Config::new(AcceptedCredential::token(GATEWAY_TOKEN))
    })
    .await
    .unwrap()
}

fn read(project: &str, document: &str) -> Value {
    json!({"project": project, "document": document})
}

/// The log lines for requests that reached `POST /mcp`.
fn requests(server: &Running) -> Vec<Value> {
    server
        .log_lines()
        .into_iter()
        .filter(|line| line["event"] == "request")
        .collect()
}

#[tokio::test]
async fn a_call_reaches_the_server_with_the_gateway_credential_and_never_the_callers() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", PLAN))
        .await;

    let Answer::Ok(result) = answer else {
        panic!("expected a result, got {answer:?}");
    };
    assert_eq!(
        result["content"][0]["text"],
        "The atlas plan. This text belongs to project atlas and to no other."
    );
    let lines = requests(&server);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert_eq!(line["bearer_sha256"], prefix(GATEWAY_TOKEN), "{line}");
    assert_eq!(line["accepted"], true, "{line}");
    assert_eq!(line["rpc_method"], "tools/call", "{line}");
    assert_eq!(line["tool"], READ_UPSTREAM, "{line}");
    assert_eq!(line["project"], "atlas", "{line}");
    assert_eq!(line["document"], PLAN, "{line}");
    let caller = prefix(harness.caller_token());
    assert!(
        server
            .log_lines()
            .iter()
            .all(|line| line["bearer_sha256"] != caller.as_str()),
        "the caller's token reached the server"
    );
    let row = harness.rows().pop().unwrap();
    assert_eq!(row.completion.unwrap().outcome, Outcome::Ok);
}

#[tokio::test]
async fn the_upstream_name_is_sent_and_the_result_comes_back_unchanged() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, SCOPED_READ_TOOL, json!({"project": "borealis"}))
        .await;

    let Answer::Ok(result) = answer else {
        panic!("expected a result, got {answer:?}");
    };
    assert_eq!(result["structuredContent"]["project"], "borealis");
    assert!(
        result["structuredContent"]["documents"]
            .as_array()
            .unwrap()
            .contains(&json!(PLAN))
    );
    assert_eq!(requests(&server)[0]["tool"], LIST_UPSTREAM);
}

#[tokio::test]
async fn a_tool_result_marked_as_an_error_is_an_error_with_its_text() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", "no-such-doc"))
        .await;

    assert_eq!(
        answer,
        Answer::Error("There is no document `no-such-doc` in project `atlas`.".to_owned())
    );
    let row = harness.rows().pop().unwrap();
    assert_eq!(row.completion.unwrap().outcome, Outcome::Error);
}

#[tokio::test]
async fn a_json_rpc_error_is_an_error_with_its_code_and_message() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", FAIL_DOC))
        .await;

    assert_eq!(
        answer,
        Answer::Error(outcome::rpc_error(FAIL_CODE, "fail-doc fails on purpose."))
    );
}

#[tokio::test]
async fn a_call_that_never_answers_is_abandoned_at_the_deadline() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(Upstream {
        deadline: SHORT_DEADLINE,
        ..upstream(&server.url())
    });

    let started = Instant::now();
    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", HANG_DOC))
        .await;
    let took = started.elapsed();

    assert_eq!(answer, Answer::Error(outcome::TIMED_OUT.to_owned()));
    assert!(took >= SHORT_DEADLINE, "abandoned after {took:?}");
    assert!(took < SHORT_DEADLINE * 4, "abandoned after {took:?}");
    // The call was sent: abandoning it is the connector's doing, not a failure to reach.
    assert_eq!(requests(&server)[0]["document"], HANG_DOC);
    let row = harness.rows().pop().unwrap();
    assert_eq!(row.completion.unwrap().outcome, Outcome::Error);
}

#[tokio::test]
async fn a_slow_call_within_the_deadline_is_answered() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, READ_TOOL, read("borealis", SLOW_DOC))
        .await;

    assert!(matches!(answer, Answer::Ok(_)), "{answer:?}");
}

#[tokio::test]
async fn by_default_a_call_is_abandoned_after_five_seconds() {
    assert_eq!(DEFAULT_DEADLINE, Duration::from_secs(5));
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let started = Instant::now();
    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", HANG_DOC))
        .await;
    let took = started.elapsed();

    assert_eq!(answer, Answer::Error(outcome::TIMED_OUT.to_owned()));
    assert!(took >= Duration::from_secs(5), "abandoned after {took:?}");
    assert!(took < Duration::from_secs(7), "abandoned after {took:?}");
}

#[tokio::test]
async fn an_answer_larger_than_the_default_cap_is_discarded() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", HUGE_DOC))
        .await;

    assert_eq!(answer, Answer::Error(outcome::TOO_LARGE.to_owned()));
}

#[tokio::test]
async fn a_credential_the_server_does_not_accept_is_an_error() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = ProxyConnector::new(
        upstream(&server.url()),
        credentials_for(CONNECTOR, WRONG_TOKEN),
    )
    .unwrap();

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", PLAN))
        .await;

    assert_eq!(
        answer,
        Answer::Error(outcome::CREDENTIAL_REJECTED.to_owned())
    );
    let line = &requests(&server)[0];
    assert_eq!(line["bearer_sha256"], prefix(WRONG_TOKEN), "{line}");
    assert_eq!(line["accepted"], false, "{line}");
}

#[tokio::test]
async fn a_tool_with_no_upstream_name_is_refused_and_nothing_is_sent() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(
        Upstream::new(CONNECTOR, server.url())
            .tool(ToolName::parse(READ_TOOL).unwrap(), READ_UPSTREAM),
    );

    let answer = harness
        .call(&connector, SCOPED_READ_TOOL, json!({"project": "atlas"}))
        .await;

    assert_eq!(answer, Answer::Refused(outcome::NOT_SERVED.to_owned()));
    assert!(server.log_lines().is_empty(), "{:?}", server.log_lines());
    let row = harness.rows().pop().unwrap();
    assert_eq!(
        row.completion.unwrap().outcome,
        Outcome::Refused {
            sentence: outcome::NOT_SERVED.to_owned()
        }
    );
}

#[tokio::test]
async fn a_tool_routed_to_another_connector_is_refused_and_nothing_is_sent() {
    let server = mock().await;
    let harness = Harness::new();
    // A connector for another server that happens to map the same exposed name.
    let other = ProxyConnector::new(
        Upstream::new("other-docs", server.url())
            .tool(ToolName::parse(READ_TOOL).unwrap(), READ_UPSTREAM),
        credentials_for("other-docs", GATEWAY_TOKEN),
    )
    .unwrap();

    let answer = harness.call(&other, READ_TOOL, read("atlas", PLAN)).await;

    assert_eq!(answer, Answer::Refused(outcome::NOT_SERVED.to_owned()));
    assert!(server.log_lines().is_empty(), "{:?}", server.log_lines());
}

#[tokio::test]
async fn arguments_that_are_not_an_object_are_refused_and_nothing_is_sent() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(upstream(&server.url()));

    for arguments in [json!(["atlas", PLAN]), json!("atlas"), Value::Null] {
        let answer = harness.call(&connector, READ_TOOL, arguments).await;
        assert_eq!(
            answer,
            Answer::Refused(outcome::ARGUMENTS_NOT_AN_OBJECT.to_owned())
        );
    }
    assert!(server.log_lines().is_empty(), "{:?}", server.log_lines());
}

#[tokio::test]
async fn a_server_that_is_not_there_is_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let harness = Harness::new();
    let connector = connector(upstream(&format!("http://{address}/mcp")));

    let answer = harness
        .call(&connector, READ_TOOL, read("atlas", PLAN))
        .await;

    assert_eq!(answer, Answer::Error(outcome::UNREACHABLE.to_owned()));
}

#[tokio::test]
async fn one_connector_carries_concurrent_calls() {
    let server = mock().await;
    let harness = Harness::new();
    let connector = connector(Upstream {
        deadline: SHORT_DEADLINE * 2,
        ..upstream(&server.url())
    });

    let (hung, slow, plain) = tokio::join!(
        harness.call(&connector, READ_TOOL, read("atlas", HANG_DOC)),
        harness.call(&connector, READ_TOOL, read("atlas", SLOW_DOC)),
        harness.call(&connector, READ_TOOL, read("borealis", PLAN)),
    );

    assert_eq!(hung, Answer::Error(outcome::TIMED_OUT.to_owned()));
    assert!(matches!(slow, Answer::Ok(_)), "{slow:?}");
    let Answer::Ok(plain) = plain else {
        panic!("expected a result, got {plain:?}");
    };
    assert_eq!(
        plain["content"][0]["text"],
        "The borealis plan. This text belongs to project borealis and to no other."
    );
}
