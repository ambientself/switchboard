//! The scripted client against the fixture gateway: every caller in both eras, what it prints,
//! and a script that fails when an answer is not what it expected.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_dev::client::{
    Client, Expect, ScriptError, caller_name, other_document, script, unauthenticated,
};
use gateway_dev::start_fixture_gateway;
use gateway_mcp::{DENIAL_CODE, Era, INVALID_PARAMS, LEGACY, MODERN};
use gateway_testkit::{Caller, SURFACE_READ};
use serde_json::{Value, json};

const CALLERS: [Caller; 3] = [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG];

#[tokio::test]
async fn every_caller_gets_the_answers_its_script_expects_in_both_eras() {
    let gateway = start_fixture_gateway().await.unwrap();
    for caller in CALLERS {
        let token = gateway.token(caller);
        let client = Client::new(gateway.url(SURFACE_READ), caller_name(caller), &token).unwrap();
        for era in [Era::Legacy, Era::Modern] {
            let mut out = Vec::new();
            let exchanges = client
                .run(&script(era, caller), &mut out)
                .await
                .unwrap_or_else(|error| panic!("{error}\n{}", String::from_utf8_lossy(&out)));
            let out = String::from_utf8(out).unwrap();
            assert!(!out.contains(&token), "the token was printed");
            assert!(out.contains("not shown"), "{out}");

            let denied = exchanges.last().unwrap();
            let sentence = denied.body["error"]["message"].as_str().unwrap();
            assert!(sentence.contains(other_document(caller)), "{sentence}");
            match era {
                Era::Legacy => {
                    assert_eq!(
                        exchanges[0].body["result"]["protocolVersion"],
                        json!(LEGACY)
                    );
                    assert!(!out.contains("mcp-method"), "{out}");
                }
                Era::Modern => {
                    for header in [
                        "mcp-protocol-version: 2026-07-28",
                        "mcp-method: tools/call",
                        "mcp-name: fixture__read",
                    ] {
                        assert!(out.contains(header), "{header} was not sent:\n{out}");
                    }
                    assert_eq!(
                        exchanges[0].body["result"]["supportedVersions"],
                        json!([MODERN])
                    );
                }
            }
        }
    }
    // Two calls a caller in each era, one allowed and one denied, each with the tool-use
    // identifier the script sent.
    let rows = gateway.store().rows();
    assert_eq!(rows.len(), CALLERS.len() * 2 * 2);
    assert!(rows.iter().all(|row| row.tool_use_id.is_some()), "{rows:?}");
}

#[tokio::test]
async fn a_request_with_no_token_gets_401() {
    let gateway = start_fixture_gateway().await.unwrap();
    let token = gateway.token(Caller::TeamA);
    let client = Client::new(gateway.url(SURFACE_READ), "team_a", &token).unwrap();
    for era in [Era::Legacy, Era::Modern] {
        let mut out = Vec::new();
        let exchanges = client.run(&[unauthenticated(era)], &mut out).await.unwrap();
        assert_eq!(exchanges[0].status, 401);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("authorization"), "{out}");
    }
}

#[tokio::test]
async fn a_script_fails_when_an_answer_is_not_what_it_expected() {
    let gateway = start_fixture_gateway().await.unwrap();
    gateway.connector().fail_all();
    let caller = Caller::TeamA;
    let client = Client::new(
        gateway.url(SURFACE_READ),
        caller_name(caller),
        gateway.token(caller),
    )
    .unwrap();
    let mut out = Vec::new();
    let failed = client.run(&script(Era::Legacy, caller), &mut out).await;
    let Err(ScriptError::Unexpected(titles)) = failed else {
        panic!("the script passed with a failing tool: {failed:?}");
    };
    assert_eq!(titles.len(), 1, "{titles:?}");
    assert!(titles[0].starts_with("read team-a-notes"), "{titles:?}");
    // Every step was still sent.
    assert_eq!(gateway.store().rows().len(), 2);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("!! expected a tool result")
    );
}

#[test]
fn each_expectation_holds_only_for_its_own_answer() {
    let result = |value: Value| json!({"jsonrpc": "2.0", "id": 1, "result": value});
    let error =
        |code: i64| json!({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "m"}});
    let tool_ok = result(json!({"isError": false}));
    let tool_error = result(json!({"isError": true}));
    let cases = [
        (Expect::Result, 200, result(json!({})), true),
        (Expect::Result, 200, error(DENIAL_CODE), false),
        (Expect::Result, 500, result(json!({})), false),
        (Expect::Accepted, 202, Value::Null, true),
        (Expect::Accepted, 200, Value::Null, false),
        (Expect::Accepted, 202, result(json!({})), false),
        (Expect::ToolOk, 200, tool_ok.clone(), true),
        (Expect::ToolOk, 200, tool_error, false),
        (Expect::ToolOk, 400, tool_ok, false),
        (Expect::Denied, 200, error(DENIAL_CODE), true),
        (Expect::Denied, 200, error(INVALID_PARAMS), false),
        (Expect::Denied, 401, error(DENIAL_CODE), false),
        (Expect::Unauthorized, 401, error(DENIAL_CODE), true),
        (Expect::Unauthorized, 200, error(DENIAL_CODE), false),
    ];
    for (expect, status, body, met) in cases {
        assert_eq!(
            expect.met_by(status, &body),
            met,
            "{expect:?} {status} {body}"
        );
    }
}
