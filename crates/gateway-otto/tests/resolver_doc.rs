//! docs/resolver-interface.md is what Otto's owners implement from, so its constants and its
//! example must be what this crate does: the question the client sends for the example's turn
//! has the example's members, and the example's answer is that question with `answer` added.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_core::{ExecutionId, SessionId, TurnId};
use gateway_otto::fake::{FakeReply, FakeResolver};
use gateway_otto::resolver::{Answer, BUDGET, CURRENCY, MAX_ANSWER_BYTES, VERSION};
use gateway_otto::{CurrencyQuestion, HttpResolver};
use serde_json::{Map, Value};

const DOC: &str = include_str!("../../../docs/resolver-interface.md");

/// The first fenced block after `<!-- example: {name} -->`, as a JSON object.
fn example(name: &str) -> Map<String, Value> {
    let marker = format!("<!-- example: {name} -->");
    let after = &DOC[DOC.find(&marker).unwrap_or_else(|| panic!("no {marker}")) + marker.len()..];
    let opened = &after[after.find("```").unwrap()..];
    let body = &opened[opened.find('\n').unwrap() + 1..];
    serde_json::from_str(&body[..body.find("```").unwrap()]).unwrap()
}

#[test]
fn the_document_states_the_constants() {
    assert!(DOC.starts_with(&format!("# The resolver interface, version `{VERSION}`")));
    assert!(DOC.contains("Status: proposed to Otto's owners, not agreed."));
    assert!(DOC.contains(&format!("POST {{base}}/{VERSION}/{CURRENCY}")));
    assert!(DOC.contains(&format!("more than {MAX_ANSWER_BYTES} bytes")));
    assert_eq!(BUDGET.as_secs(), 1);
    assert_eq!(BUDGET.subsec_nanos(), 0);
    assert!(DOC.contains("## The budget: one second"));
    for answer in Answer::ALL {
        assert!(DOC.contains(&format!("| `{}` |", answer.as_str())));
    }
}

#[tokio::test]
async fn the_example_is_what_the_client_sends_and_reads() {
    let question = example("question");
    let answer = example("answer");

    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let resolver = HttpResolver::new(&fake.config()).unwrap();
    let asked = CurrencyQuestion {
        session: SessionId::new(question["sid"].as_str().unwrap()),
        execution: ExecutionId::new(question["eid"].as_str().unwrap()),
        turn: TurnId::new(question["tid"].as_str().unwrap()),
        epoch: question["epoch"].as_u64().unwrap(),
    };
    assert_eq!(resolver.ask(&asked).await, Ok(Answer::Current));

    // What was sent has the example's members, its request ID aside, which is fresh.
    let mut sent = fake.received()[0].question().unwrap();
    let id = sent.insert("request_id".to_owned(), question["request_id"].clone());
    assert_eq!(id.unwrap().as_str().unwrap().len(), 32);
    assert_eq!(sent, question);
    let id = question["request_id"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    assert!(
        id.bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );

    // The answer is the question with one member added.
    let mut echoed = answer.clone();
    assert_eq!(echoed.remove("answer"), Some(Value::from("current")));
    assert_eq!(echoed, question);
}
