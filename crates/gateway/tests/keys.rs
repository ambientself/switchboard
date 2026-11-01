//! A side effect's key and receipt through the gateway's HTTP endpoint (decision 0009, part 2):
//! the key's three carriers and their order, every answer to a reused key, an `unknown`
//! outcome, a client that leaves just before its side effect would be invoked, and a side
//! effect refused with audit disabled. The fixture's draft tool, classified `propose`, is served
//! in this development build against the testkit's in-memory store, which keeps receipts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use gateway::{Config, Disconnect, DisconnectOnDrop, RequestPath, Source, Wiring, boot};
use gateway_core::audit::{AuditRowId, ErrorKind, Outcome};
use gateway_core::{IdempotencyKey, ReasonKind, ReceiptState, Reuse};
use gateway_identity::Clock;
use gateway_mcp::{
    AUDIT_ROW_DATA, AUDIT_ROW_META, IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_KEY_META, TOOL_USE_ID_META,
};
use gateway_testkit::{
    CONNECTOR, Caller, DRAFT_REFUSAL, DRAFT_TOOL, FOREIGN_DRAFT, Fixture, InMemoryAuditStore,
    PROFILE_TEAM_A, SURFACE_ALL, SteppableClock, TEAM_A_DOCUMENT, block_on,
};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{Value, json};

use support::{Answer, FixtureResources, Http, Server, legacy};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

fn draft(text: &str) -> Value {
    json!({"document": TEAM_A_DOCUMENT, "text": text})
}

/// Team A's 2025-06-18 call to the draft tool with `arguments` and `meta` as its `_meta`.
fn propose(server: &Server, arguments: Value, meta: Value) -> Http {
    server
        .post(
            SURFACE_ALL,
            &legacy(
                "tools/call",
                json!({"name": DRAFT_TOOL, "arguments": arguments, "_meta": meta}),
            ),
        )
        .bearer(&server.token(Caller::TeamA))
}

/// The configuration with team A's profile declaring that its callers set the header.
fn declaring(config: &mut Value) {
    let profiles = config["policy"]["profiles"].as_array_mut().unwrap();
    let team_a = profiles
        .iter_mut()
        .find(|profile| profile["name"] == json!(PROFILE_TEAM_A))
        .unwrap();
    team_a["idempotency_key_header"] = json!(true);
}

fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::parse(value).unwrap()
}

/// The row a result names in its `_meta`.
fn result_row(answer: &Answer) -> AuditRowId {
    AuditRowId::new(answer.result()["_meta"][AUDIT_ROW_META].as_str().unwrap())
}

/// The row a denial names in its `error.data`.
fn denial_row(answer: &Answer) -> AuditRowId {
    AuditRowId::new(
        answer.json()["error"]["data"][AUDIT_ROW_DATA]
            .as_str()
            .unwrap(),
    )
}

/// A tool error's text: a result marked `isError`.
fn tool_error(answer: &Answer) -> String {
    let result = answer.result();
    assert_eq!(result["isError"], json!(true), "{result}");
    result["content"][0]["text"].as_str().unwrap().to_owned()
}

// --- The carriers ----------------------------------------------------------------------------

/// A key in the named `_meta` field keys the call, and the tool-use identifier sent beside it is
/// recorded beside it, on the row and on the receipt. A caller that is not a model sends the
/// field alone.
#[tokio::test]
async fn a_key_in_meta_keys_the_call_with_the_tool_use_identifier_beside_it() {
    let server = Server::start().await;
    let meta = json!({IDEMPOTENCY_KEY_META: "turn-7-draft", TOOL_USE_ID_META: "toolu_one"});
    let ran = propose(&server, draft("One."), meta).send(&server).await;
    assert_eq!(ran.result()["isError"], json!(false), "{ran:?}");
    let alone = propose(
        &server,
        draft("Two."),
        json!({IDEMPOTENCY_KEY_META: "turn-8-draft"}),
    )
    .send(&server)
    .await;
    assert_eq!(alone.result()["isError"], json!(false), "{alone:?}");

    let receipts = server.store.receipts();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].key, key("turn-7-draft"));
    assert_eq!(
        receipts[0].tool_use_id.as_ref().unwrap().as_str(),
        "toolu_one"
    );
    assert_eq!(receipts[0].row, result_row(&ran));
    assert_eq!(receipts[0].state, ReceiptState::Completed);
    assert_eq!(
        server.store.row(0).unwrap().tool_use_id.unwrap().as_str(),
        "toolu_one"
    );
    assert_eq!(receipts[1].key, key("turn-8-draft"));
    assert_eq!(receipts[1].tool_use_id, None);
    assert_eq!(server.connector.writes().len(), 2);
}

/// On a profile that declares its callers set it per request, the `Idempotency-Key` header
/// keys a call that carries no key in `_meta`; one in `_meta` comes first.
#[tokio::test]
async fn the_header_keys_a_call_on_a_profile_that_declares_it() {
    let server = Server::start_configured(declaring).await;
    let from_header = propose(
        &server,
        draft("One."),
        json!({TOOL_USE_ID_META: "toolu_one"}),
    )
    .header(IDEMPOTENCY_KEY_HEADER, "header-key-1")
    .send(&server)
    .await;
    assert_eq!(
        from_header.result()["isError"],
        json!(false),
        "{from_header:?}"
    );
    let both = propose(
        &server,
        draft("Two."),
        json!({IDEMPOTENCY_KEY_META: "meta-key-2", TOOL_USE_ID_META: "toolu_two"}),
    )
    .header(IDEMPOTENCY_KEY_HEADER, "header-key-2")
    .send(&server)
    .await;
    assert_eq!(both.result()["isError"], json!(false), "{both:?}");

    let receipts = server.store.receipts();
    assert_eq!(receipts[0].key, key("header-key-1"));
    assert_eq!(
        receipts[0].tool_use_id.as_ref().unwrap().as_str(),
        "toolu_one"
    );
    assert_eq!(receipts[1].key, key("meta-key-2"));
}

/// On any other profile the header is ignored, and the call is keyed as if it were absent: by
/// its tool-use identifier, or by nothing, and then denied for carrying no key.
#[tokio::test]
async fn the_header_is_ignored_on_a_profile_that_does_not_declare_it() {
    let server = Server::start().await;
    let unkeyed = propose(&server, draft("One."), json!({}))
        .header(IDEMPOTENCY_KEY_HEADER, "header-key-1")
        .send(&server)
        .await;
    assert!(unkeyed.denial().contains("carried none"), "{unkeyed:?}");
    assert_eq!(
        server.store.row(0).unwrap().reason,
        Some(ReasonKind::KeyMissing)
    );
    assert!(
        server.connector.received().is_empty(),
        "the connector was called"
    );

    let keyed = propose(
        &server,
        draft("Two."),
        json!({TOOL_USE_ID_META: "toolu_two"}),
    )
    .header(IDEMPOTENCY_KEY_HEADER, "header-key-2")
    .send(&server)
    .await;
    assert_eq!(keyed.result()["isError"], json!(false), "{keyed:?}");
    assert_eq!(server.store.receipts()[0].key, key("toolu_two"));
}

/// An explicit key that is not a valid key, whether a string or not, is dropped and leaves the
/// call with no key: it is not passed over for the header or the tool-use identifier, so the
/// side effect is denied for want of a key and nothing runs. The denial says the key the call
/// sent is not valid, not that it carried none, and does not repeat it. The tool-use identifier
/// is still recorded. A declared header that is not valid, or is sent twice, does the same.
#[tokio::test]
async fn an_invalid_explicit_key_leaves_the_call_with_no_key() {
    let server = Server::start_configured(declaring).await;
    let too_long = "k".repeat(129);
    let cases: [(&str, Value, Vec<&str>); 8] = [
        (
            "_meta with a space",
            json!({IDEMPOTENCY_KEY_META: "session:turn 7", TOOL_USE_ID_META: "toolu_one"}),
            vec![],
        ),
        (
            "_meta a number",
            json!({IDEMPOTENCY_KEY_META: 7, TOOL_USE_ID_META: "toolu_six"}),
            vec![],
        ),
        (
            "_meta an object, beside a valid header",
            json!({IDEMPOTENCY_KEY_META: {"key": "turn-7"}, TOOL_USE_ID_META: "toolu_seven"}),
            vec!["header-key-7"],
        ),
        (
            "_meta a boolean",
            json!({IDEMPOTENCY_KEY_META: true, TOOL_USE_ID_META: "toolu_eight"}),
            vec![],
        ),
        (
            "_meta empty, beside a valid header",
            json!({IDEMPOTENCY_KEY_META: "", TOOL_USE_ID_META: "toolu_two"}),
            vec!["header-key-2"],
        ),
        (
            "header too long",
            json!({TOOL_USE_ID_META: "toolu_three"}),
            vec![&too_long],
        ),
        (
            "header with a space",
            json!({TOOL_USE_ID_META: "toolu_four"}),
            vec!["two words"],
        ),
        (
            "header sent twice",
            json!({TOOL_USE_ID_META: "toolu_five"}),
            vec!["header-key-5", "header-key-5"],
        ),
    ];
    for (index, (case, meta, headers)) in cases.into_iter().enumerate() {
        let tool_use_id = meta[TOOL_USE_ID_META].as_str().unwrap().to_owned();
        let mut request = propose(&server, draft(case), meta);
        for value in headers {
            request = request.header(IDEMPOTENCY_KEY_HEADER, value);
        }
        let unkeyed = request.send(&server).await;
        let denial = unkeyed.denial();
        assert!(
            denial.contains("The key this call sent is not valid"),
            "{case}: {unkeyed:?}"
        );
        assert!(!denial.contains("carried none"), "{case}: {denial}");
        assert!(!denial.contains("session:turn 7"), "{case}: {denial}");
        assert!(!denial.contains("two words"), "{case}: {denial}");
        let row = server.store.row(index).unwrap();
        assert_eq!(row.reason, Some(ReasonKind::KeyMissing), "{case}");
        assert_eq!(row.tool_use_id.unwrap().as_str(), tool_use_id, "{case}");
    }
    assert!(server.store.receipts().is_empty());
    assert!(
        server.connector.received().is_empty(),
        "the connector was called"
    );
}

// --- The answers to a reused key -------------------------------------------------------------

/// The same call sent again under its key is answered as a duplicate: a success naming the
/// earlier receipt and the vendor's reference, and the draft is made once.
#[tokio::test]
async fn a_resend_is_answered_as_a_duplicate_with_the_reference_and_the_receipt() {
    let server = Server::start().await;
    let meta = json!({IDEMPOTENCY_KEY_META: "turn-7-draft", TOOL_USE_ID_META: "toolu_one"});
    let first = propose(&server, draft("One."), meta.clone())
        .send(&server)
        .await;
    let receipt = result_row(&first);
    let again = propose(&server, draft("One."), meta).send(&server).await;

    let result = again.result();
    assert_eq!(result["isError"], json!(false), "{result}");
    assert_eq!(
        result["structuredContent"]["receipt"],
        json!(receipt.as_str())
    );
    assert_eq!(result["structuredContent"]["reference"], json!("draft-1"));
    let expected = Reuse::Duplicate {
        key: key("turn-7-draft"),
        receipt: receipt.clone(),
        reference: Some(gateway_core::VendorReference::new("draft-1")),
    };
    assert_eq!(
        result["structuredContent"]["duplicate"],
        json!(expected.sentence())
    );
    assert_eq!(
        server.connector.writes().len(),
        1,
        "the draft was made twice"
    );
    let row = server.store.row_with_id(&result_row(&again)).unwrap();
    assert_eq!(
        row.completion.map(|completion| completion.outcome),
        Some(Outcome::Duplicate { receipt })
    );
}

/// The same explicit key sent with another tool-use identifier is refused with a sentence of
/// its own: that is what a key fixed in configuration looks like. Nothing runs.
#[tokio::test]
async fn one_key_with_another_tool_use_identifier_is_refused_as_another_call() {
    let server = Server::start().await;
    let first = propose(
        &server,
        draft("One."),
        json!({IDEMPOTENCY_KEY_META: "fixed-key", TOOL_USE_ID_META: "toolu_one"}),
    )
    .send(&server)
    .await;
    assert_eq!(first.result()["isError"], json!(false), "{first:?}");
    let second = propose(
        &server,
        draft("One."),
        json!({IDEMPOTENCY_KEY_META: "fixed-key", TOOL_USE_ID_META: "toolu_two"}),
    )
    .send(&server)
    .await;
    assert_eq!(
        second.denial(),
        Reuse::DifferentCall {
            key: key("fixed-key")
        }
        .sentence()
    );
    assert_eq!(server.connector.writes().len(), 1);
    assert_eq!(server.connector.received().len(), 1);
}

/// Each of the five answers to a reused key reaches the caller, and none of the calls answered
/// so runs: another call under the key, conflicting reuse, a duplicate, an earlier call that may
/// have happened, and one that did not take effect.
#[tokio::test]
async fn each_answer_to_a_reused_key_reaches_the_caller() {
    let server = Server::start().await;
    let send = |arguments: Value, key: &str, tool_use_id: &str| {
        propose(
            &server,
            arguments,
            json!({IDEMPOTENCY_KEY_META: key, TOOL_USE_ID_META: tool_use_id}),
        )
        .send(&server)
    };

    // Completed: another tool-use identifier, other arguments, and the same call.
    let done = send(draft("One."), "key-done", "toolu_done").await;
    let done_receipt = result_row(&done);
    let other_call = send(draft("One."), "key-done", "toolu_other").await;
    assert_eq!(
        other_call.denial(),
        Reuse::DifferentCall {
            key: key("key-done")
        }
        .sentence()
    );
    let conflicting = send(draft("Other."), "key-done", "toolu_done").await;
    assert_eq!(
        conflicting.denial(),
        Reuse::Conflicting {
            key: key("key-done")
        }
        .sentence()
    );
    let duplicate = send(draft("One."), "key-done", "toolu_done").await;
    assert_eq!(
        duplicate.result()["structuredContent"]["receipt"],
        json!(done_receipt.as_str())
    );

    // Unknown: the draft is made, and no definite answer comes back.
    server.connector.unknown_next();
    let unknown = send(draft("Maybe."), "key-unknown", "toolu_unknown").await;
    let unknown_receipt = result_row(&unknown);
    let may_have_happened = send(draft("Maybe."), "key-unknown", "toolu_unknown").await;
    assert_eq!(
        may_have_happened.denial(),
        Reuse::MayHaveHappened {
            key: key("key-unknown"),
            receipt: unknown_receipt,
        }
        .sentence()
    );

    // Not performed: the draft tool refuses a draft the gateway did not open.
    let foreign = json!({"document": TEAM_A_DOCUMENT, "draft": FOREIGN_DRAFT});
    let refused = send(foreign.clone(), "key-refused", "toolu_refused").await;
    assert_eq!(refused.denial(), DRAFT_REFUSAL);
    let refused_receipt = denial_row(&refused);
    let not_performed = send(foreign, "key-refused", "toolu_refused").await;
    assert_eq!(
        not_performed.denial(),
        Reuse::NotPerformed {
            key: key("key-refused"),
            receipt: refused_receipt,
        }
        .sentence()
    );

    // Three calls reached the connector: one for each key.
    assert_eq!(server.connector.received().len(), 3);
    assert_eq!(server.store.receipts().len(), 3);
}

/// A side effect sent with no definite answer is answered as one that may already have
/// happened and must not be repeated, naming its receipt, which is `unknown`.
#[tokio::test]
async fn an_unknown_outcome_is_answered_as_may_have_happened_with_its_receipt() {
    let server = Server::start().await;
    server.connector.unknown_next();
    let answer = propose(
        &server,
        draft("Maybe."),
        json!({IDEMPOTENCY_KEY_META: "key-unknown", TOOL_USE_ID_META: "toolu_unknown"}),
    )
    .send(&server)
    .await;

    let receipt = result_row(&answer);
    let sentence = tool_error(&answer);
    assert!(sentence.contains("may have taken effect"), "{sentence}");
    assert!(sentence.contains("Do not repeat it"), "{sentence}");
    assert!(sentence.contains(receipt.as_str()), "{sentence}");
    let stored = server.store.receipt(&receipt).unwrap();
    assert_eq!(stored.state, ReceiptState::Unknown);
    assert_eq!(
        server
            .store
            .row_with_id(&receipt)
            .unwrap()
            .completion
            .map(|completion| completion.outcome),
        Some(Outcome::Unknown)
    );
}

// --- A client that leaves, and audit disabled -------------------------------------------------

/// A clock that drops the client's side of a [`Disconnect`] the first time it is read once
/// armed: the gateway reads its clock after it has looked up and wrapped the connector, just
/// before it invokes it, so the client leaves in that window.
struct LeavesWhenRead {
    clock: SteppableClock,
    armed: AtomicBool,
    client: Mutex<Option<DisconnectOnDrop>>,
}

impl Clock for LeavesWhenRead {
    fn now(&self) -> SystemTime {
        if self.armed.load(Ordering::SeqCst) {
            drop(self.client.lock().unwrap().take());
        }
        self.clock.now()
    }
}

/// A side effect whose client leaves after its row is begun and its connector looked up, just
/// before the connector would be invoked, is not invoked: the gateway checks again
/// immediately before, its row is completed as `error` and its receipt is `not_performed`.
#[test]
fn a_side_effect_whose_client_leaves_just_before_invocation_is_not_invoked() {
    let fixture = Fixture::new().unwrap();
    let (client, disconnect) = Disconnect::pair();
    let clock = Arc::new(LeavesWhenRead {
        clock: fixture.clock.clone(),
        armed: AtomicBool::new(false),
        client: Mutex::new(Some(client)),
    });
    let store = Arc::new(InMemoryAuditStore::new());
    let connector = Arc::new(gateway_testkit::FixtureConnector::new(Arc::new(
        gateway_testkit::FakeCredentialSource::new(),
    )));
    let config: Config = serde_json::from_value(support::config(&fixture)).unwrap();
    let wiring = Wiring::new(clock.clone())
        .audit_store(store.clone())
        .connector(CONNECTOR, connector.clone(), Arc::new(FixtureResources));
    let path = RequestPath::new(boot::check(config, wiring).unwrap());

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("accept", HeaderValue::from_static("application/json"));
    let token = format!("Bearer {}", fixture.token(Caller::TeamA));
    headers.insert("authorization", HeaderValue::from_str(&token).unwrap());
    let body = legacy(
        "tools/call",
        json!({"name": DRAFT_TOOL, "arguments": draft("Left."),
               "_meta": {TOOL_USE_ID_META: "toolu_left"}}),
    )
    .to_string();
    let admitted = path
        .admit(&Method::POST, &headers, &Source::default())
        .unwrap();
    // Identity has read the clock; the next reading is the call's own.
    clock.armed.store(true, Ordering::SeqCst);
    let response =
        block_on(path.respond(admitted, SURFACE_ALL, &headers, body.as_bytes(), disconnect));

    assert!(
        clock.client.lock().unwrap().is_none(),
        "the client never left"
    );
    let answer: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(answer["result"]["isError"], json!(true), "{answer}");
    assert_eq!(
        answer["result"]["content"][0]["text"],
        json!(gateway::DISCONNECTED_BEFORE_RUN)
    );
    assert!(
        connector.received().is_empty(),
        "the connector was invoked for a client that had left"
    );
    let row = store.row(0).unwrap();
    assert_eq!(
        row.completion
            .map(|completion| (completion.outcome, completion.latency_ms)),
        Some((
            Outcome::Error {
                error_kind: ErrorKind::Other
            },
            0
        ))
    );
    assert_eq!(store.receipts()[0].state, ReceiptState::NotPerformed);
}

/// A development build with audit disabled keeps no receipts, so it refuses a keyed side effect
/// with the audit-failure sentence, and nothing runs.
#[tokio::test]
async fn with_audit_disabled_a_keyed_side_effect_is_refused_and_nothing_runs() {
    let server =
        Server::start_configured(|config| config["audit"] = json!({"disabled": true})).await;
    let answer = propose(
        &server,
        draft("One."),
        json!({IDEMPOTENCY_KEY_META: "turn-7-draft", TOOL_USE_ID_META: "toolu_one"}),
    )
    .send(&server)
    .await;
    assert_eq!(answer.denial(), AUDIT_FAILURE);
    assert!(
        server.connector.received().is_empty(),
        "the connector was called"
    );
    assert!(server.connector.writes().is_empty(), "a draft was made");
    assert!(
        server.credentials.requests().is_empty(),
        "a credential was requested"
    );
}
