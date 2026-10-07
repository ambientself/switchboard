//! Identity end to end: every caller who cannot be verified gets the same 401, byte for byte,
//! before the body is read; a request from another host or origin is refused before that; and
//! a gateway with identity disabled says so and refuses every call.
//!
//! Plan #26's tests 10, 11 and 16.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::UNIX_EPOCH;

use gateway::{IDENTITY_DISABLED, IDENTITY_DISABLED_NOTE};
use gateway_core::IDENTITY_FAILURE;
use gateway_dev::{FixtureGateway, Options, start_fixture_gateway, start_fixture_gateway_with};
use gateway_identity::{MAX_TOKEN_BYTES, SigningAlgorithm};
use gateway_mcp::{CHALLENGE, DENIAL_CODE, Era, PROTOCOL_VERSION_META};
use gateway_testkit::{
    AUDIENCE, Caller, LocalIssuer, READ_TOOL, SURFACE_READ, TEAM_A_DOCUMENT, USER_SUBJECT,
    WORKLOAD_ISSUER,
};
use serde_json::json;
use support::{Answer, Request, assert_nothing_ran, call_params, document, legacy};

/// The one answer to every caller whose identity was not proved.
fn assert_identity_failure(answer: &Answer, what: &str) {
    assert_eq!(answer.status, 401, "{what}: {answer:?}");
    assert_eq!(answer.header("www-authenticate"), Some(CHALLENGE), "{what}");
    assert_eq!(
        answer.header("content-type"),
        Some("application/json"),
        "{what}"
    );
    assert_eq!(
        answer.json(),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": DENIAL_CODE, "message": IDENTITY_FAILURE}}),
        "{what}"
    );
}

fn now_secs(gateway: &FixtureGateway) -> u64 {
    gateway
        .clock()
        .now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Team A's read of its own document, with whatever `authorization` headers are given.
fn read_with(gateway: &FixtureGateway, era: Era, authorization: &[String]) -> Request {
    let mut request = Request::in_era(
        era,
        &gateway.url(SURFACE_READ),
        "tools/call",
        call_params(READ_TOOL, document(TEAM_A_DOCUMENT)),
    );
    for value in authorization {
        request = request.header("authorization", value);
    }
    request
}

// --- Every identity failure is the same 401 ------------------------------------------------

#[tokio::test]
async fn every_caller_who_cannot_be_verified_gets_the_same_answer() {
    let gateway = start_fixture_gateway().await.unwrap();
    let now = now_secs(&gateway);
    let stranger = LocalIssuer::new(WORKLOAD_ISSUER, SigningAlgorithm::Es256).unwrap();
    let valid = gateway.token(Caller::TeamA);
    let bearer = |token: &str| format!("Bearer {token}");
    let a_team = |caller| gateway.token_builder(caller);

    let causes: Vec<(&str, Vec<String>)> = vec![
        ("no token", vec![]),
        ("an empty bearer", vec!["Bearer ".to_owned()]),
        ("garbage", vec![bearer("not-a-token")]),
        ("another scheme", vec![format!("Basic {valid}")]),
        ("two tokens", vec![bearer(&valid), bearer(&valid)]),
        (
            "expired",
            vec![bearer(
                &a_team(Caller::TeamA)
                    .issued_at(now - 1200)
                    .not_before(now - 1200)
                    .expires_at(now - 600)
                    .build(),
            )],
        ),
        (
            "not yet valid",
            vec![bearer(
                &a_team(Caller::TeamA)
                    .issued_at(now + 600)
                    .not_before(now + 600)
                    .expires_at(now + 1200)
                    .build(),
            )],
        ),
        (
            "living longer than the issuer allows",
            vec![bearer(&a_team(Caller::TeamA).lifetime(24 * 3600).build())],
        ),
        (
            "for another audience",
            vec![bearer(
                &a_team(Caller::TeamA).audience("someone-else").build(),
            )],
        ),
        (
            "for a subject no team holds",
            vec![bearer(
                &gateway
                    .workload_issuer()
                    .workload_token(
                        "system:serviceaccount:team-c:sandbox",
                        AUDIENCE,
                        gateway.clock().now(),
                    )
                    .build(),
            )],
        ),
        (
            "from an issuer nobody trusts",
            vec![bearer(
                &a_team(Caller::TeamA)
                    .issuer("https://issuer.elsewhere.test")
                    .build(),
            )],
        ),
        (
            "signed by a key the issuer does not hold",
            vec![bearer(&a_team(Caller::TeamA).signed_by(&stranger).build())],
        ),
        (
            "with its signature changed",
            vec![bearer(&a_team(Caller::TeamA).corrupt_signature().build())],
        ),
        (
            "unsigned",
            vec![bearer(&a_team(Caller::TeamA).unsigned().build())],
        ),
        (
            "a user's token from the workload issuer",
            vec![bearer(
                &gateway
                    .workload_issuer()
                    .user_token(USER_SUBJECT, AUDIENCE, &["group-g"], gateway.clock().now())
                    .build(),
            )],
        ),
        (
            "over the size limit",
            vec![bearer(
                &a_team(Caller::TeamA)
                    .claim("padding", json!("x".repeat(MAX_TOKEN_BYTES)))
                    .build(),
            )],
        ),
    ];

    let mut first: Option<Vec<u8>> = None;
    for era in [Era::Legacy, Era::Modern] {
        for (what, authorization) in &causes {
            let answer = read_with(&gateway, era, authorization).send().await;
            let what = format!("{what}, {era}");
            assert_identity_failure(&answer, &what);
            match &first {
                None => first = Some(answer.bytes.clone()),
                Some(bytes) => assert_eq!(&answer.bytes, bytes, "{what}"),
            }
        }
    }
    assert_nothing_ran(&gateway);

    // The same gateway serves the valid token.
    let answer = read_with(&gateway, Era::Legacy, &[bearer(&valid)])
        .send()
        .await;
    let (is_error, _) = answer.tool_result();
    assert!(!is_error);
}

#[tokio::test]
async fn identity_is_checked_before_the_body_is_read() {
    let gateway = start_fixture_gateway().await.unwrap();
    let url = gateway.url(SURFACE_READ);
    // Bodies the parser would refuse with 400 get the 401 instead: the parser never ran.
    for body in [
        b"{\"jsonrpc\": \"2.0\",".to_vec(),
        b"[]".to_vec(),
        Vec::new(),
    ] {
        let answer = Request::post(&url, &json!({})).body(body).send().await;
        assert_identity_failure(&answer, "an unparseable body with no token");
    }
    // So does a modern request whose headers disagree with its body.
    let answer = Request::modern(&url, "tools/list", json!({}))
        .json(|body| body["params"]["_meta"][PROTOCOL_VERSION_META] = json!("2099-01-01"))
        .send()
        .await;
    assert_identity_failure(&answer, "a header mismatch with no token");
    assert_nothing_ran(&gateway);
}

#[tokio::test]
async fn the_discovery_methods_need_a_token_too() {
    let gateway = start_fixture_gateway().await.unwrap();
    let url = gateway.url(SURFACE_READ);
    let requests = [
        Request::post(&url, &legacy("initialize", json!({"capabilities": {}}))),
        Request::post(&url, &legacy("ping", json!({}))),
        Request::post(&url, &legacy("tools/list", json!({}))),
        Request::modern(&url, "server/discover", json!({})),
        Request::modern(&url, "tools/list", json!({})),
        Request::post(
            &url,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    ];
    for request in requests {
        let what = String::from_utf8_lossy(&request.body).into_owned();
        assert_identity_failure(&request.send().await, &what);
    }
    assert_nothing_ran(&gateway);
}

// --- Host and Origin -------------------------------------------------------------------------

#[tokio::test]
async fn another_host_or_origin_is_refused_before_identity() {
    let gateway = start_fixture_gateway().await.unwrap();
    let port = gateway.address().port();
    let token = gateway.token(Caller::TeamA);
    let read = || read_with(&gateway, Era::Legacy, &[]);

    for token in [None, Some(token.as_str())] {
        let read = || match token {
            Some(token) => read().bearer(token),
            None => read(),
        };
        // DNS rebinding: a page on another name that resolves to this machine.
        for host in [
            "evil.example".to_owned(),
            format!("evil.example:{port}"),
            format!("localhost.evil.example:{port}"),
        ] {
            let answer = read().header("host", &host).send().await;
            assert_eq!(answer.status, 403, "{host}: {answer:?}");
            assert_eq!(answer.error().1, "Forbidden: host not allowed");
        }
        // A web page, whatever its origin: the fixture gateway allows none.
        for origin in [
            "http://evil.example".to_owned(),
            "null".to_owned(),
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
            "http://localhost:6274".to_owned(),
        ] {
            let answer = read().header("origin", &origin).send().await;
            assert_eq!(answer.status, 403, "{origin}: {answer:?}");
            assert_eq!(answer.error().1, "Forbidden: origin not allowed");
        }
    }
    assert_nothing_ran(&gateway);

    // The hosts it does answer for, with or without the port, and no Origin, as command-line
    // clients send.
    for host in [format!("localhost:{port}"), "127.0.0.1".to_owned()] {
        let answer = read().bearer(&token).header("host", &host).send().await;
        let (is_error, _) = answer.tool_result();
        assert!(!is_error, "{host}");
    }
}

// --- Identity disabled -------------------------------------------------------------------------

#[tokio::test]
async fn with_identity_disabled_every_call_is_refused_and_discovery_says_why() {
    let gateway = start_fixture_gateway_with(Options::new().identity_disabled())
        .await
        .unwrap();
    let url = gateway.url(SURFACE_READ);

    for era in [Era::Legacy, Era::Modern] {
        // With no token, with a valid one and with garbage: nobody is checked, and nothing
        // can be decided for anybody.
        for authorization in [
            vec![],
            vec![format!("Bearer {}", gateway.token(Caller::TeamA))],
            vec!["Bearer not-a-token".to_owned()],
        ] {
            let answer = read_with(&gateway, era, &authorization).send().await;
            assert_eq!(answer.denial(), IDENTITY_DISABLED, "{era}");
        }
    }
    assert_nothing_ran(&gateway);

    let initialized = Request::post(&url, &legacy("initialize", json!({"capabilities": {}})))
        .send()
        .await
        .result();
    let instructions = initialized["instructions"].as_str().unwrap();
    assert!(
        instructions.contains(IDENTITY_DISABLED_NOTE),
        "{instructions}"
    );
    let discovered = Request::modern(&url, "server/discover", json!({}))
        .send()
        .await
        .result();
    let instructions = discovered["instructions"].as_str().unwrap();
    assert!(
        instructions.contains(IDENTITY_DISABLED_NOTE),
        "{instructions}"
    );
    let pong = Request::post(&url, &legacy("ping", json!({})))
        .send()
        .await
        .result();
    assert_eq!(pong, json!({}));

    // A gateway with identity on says nothing of the kind.
    let enforced = start_fixture_gateway().await.unwrap();
    let initialized = Request::post(
        &enforced.url(SURFACE_READ),
        &legacy("initialize", json!({"capabilities": {}})),
    )
    .bearer(&enforced.token(Caller::TeamA))
    .send()
    .await
    .result();
    assert_eq!(initialized.get("instructions"), None, "{initialized}");
}
