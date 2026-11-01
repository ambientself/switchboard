//! What the gateway logs of a turn grant it refuses (decision 0012, design section 11): an
//! audience or pod failure at `ERROR`, to be investigated, with the grant's digest; a lifetime
//! failure not at all, only counted; any other failure at `WARN`, with no digest even when its
//! signature verified; and nothing from any refused grant's claims. The counters export each
//! failure by kind and each accepted grant by key ID.
//!
//! A test binary of its own, because it installs a log subscriber for its thread, as
//! `tests/logs.rs` does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use gateway::{GRANT_HEADER, GRANT_REFUSED_EVENT, Metrics, Telemetry};
use gateway_otto::minter::{TestMinter, with_part};
use gateway_testkit::{AUDIENCE, READ_TOOL, SURFACE_READ, TEAM_A, TEAM_A_SUBJECT};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use support::{Server, legacy};

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

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
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    /// Every grant refusal logged, as JSON.
    fn refusals(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|logged| logged["fields"]["event"] == json!(GRANT_REFUSED_EVENT))
            .collect()
    }
}

const POD: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const OTHER_POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const CANARIES: [&str; 4] = [
    "actor-canary@example.test",
    "session-canary",
    "turn-canary",
    "execution-canary",
];

fn claims(now: u64) -> Value {
    json!({
        "aud": ["server-test"],
        "iat": now,
        "exp": now + 600,
        "team": TEAM_A,
        "tools": ["otto_read"],
        "epoch": 7,
        "sid": "session-canary",
        "tid": "turn-canary",
        "eid": "execution-canary",
        "actor": "actor-canary@example.test",
        "pod": POD,
    })
}

fn digest(grant: &str) -> String {
    Sha256::digest(grant.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn grant_failures_are_logged_by_kind_with_nothing_from_their_claims() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    // This test's runtime runs every task on this thread, the server's included.
    let _logging = tracing::subscriber::set_default(subscriber);

    let minter = TestMinter::generate();
    let stranger = TestMinter::generate();
    let grants = json!({"enforce": {
        "issuers": [{
            "name": "otto-test",
            "current_key": minter.public_key_pem(),
            "require_pod": true,
            "require_egress": false,
        }],
        "tool_mapping": {"otto_read": READ_TOOL},
    }});
    let server = Server::start_configured(move |config| config["grants"] = grants).await;
    let now = server.fixture.clock.unix_millis() / 1000;
    let send = |grant: String, pod: &'static str| {
        let token = server
            .fixture
            .workload_issuer
            .workload_token(
                TEAM_A_SUBJECT,
                AUDIENCE,
                gateway_identity::Clock::now(&server.fixture.clock),
            )
            .claim(
                "kubernetes.io",
                json!({"pod": {"name": "sandbox-1", "uid": pod}}),
            )
            .build();
        let params = json!({"name": READ_TOOL, "arguments": {"document": "team-a-notes"}});
        server
            .post(SURFACE_READ, &legacy("tools/call", params))
            .bearer(&token)
            .header(GRANT_HEADER, &grant)
    };

    let mut elsewhere = claims(now);
    elsewhere["aud"] = json!(["otto-gateway"]);
    let audience = minter.mint(&elsewhere);
    send(audience.clone(), POD).send(&server).await.denial();
    let pod = minter.mint(&claims(now));
    send(pod.clone(), OTHER_POD).send(&server).await.denial();
    let mut late = claims(now);
    late["exp"] = json!(now - 31);
    late["iat"] = json!(now - 600);
    send(minter.mint(&late), POD).send(&server).await.denial();
    let forged = with_part(
        &pod,
        3,
        &gateway_otto::minter::parts(&stranger.mint(&claims(now)))[3],
    );
    send(forged, POD).send(&server).await.denial();
    // Signed, so its signature verifies, and its claims are malformed: not a binding's failure,
    // so it is logged with no digest.
    let mut negative_epoch = claims(now);
    negative_epoch["epoch"] = json!(-7);
    send(minter.mint(&negative_epoch), POD)
        .send(&server)
        .await
        .denial();
    let good = minter.mint(&claims(now));
    let answer = send(good, POD).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false));

    let refusals = captured.refusals();
    let kinds: Vec<(&str, &str)> = refusals
        .iter()
        .map(|logged| {
            (
                logged["fields"]["failure"].as_str().unwrap(),
                logged["level"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("wrong_audience", "ERROR"),
            ("wrong_pod", "ERROR"),
            ("signature", "WARN"),
            ("malformed", "WARN"),
        ],
        "an expired grant is counted, not logged: {refusals:#?}"
    );
    assert_eq!(refusals[0]["fields"]["digest"], json!(digest(&audience)));
    assert_eq!(refusals[1]["fields"]["digest"], json!(digest(&pod)));
    assert_eq!(refusals[1]["fields"]["pod"], json!(OTHER_POD));
    assert!(
        refusals[2]["fields"].get("digest").is_none(),
        "a failure before the signature verified is logged with a digest: {:#}",
        refusals[2]
    );
    assert!(
        refusals[3]["fields"].get("digest").is_none(),
        "a failure after the signature verified that is not a binding's is logged with a \
         digest: {:#}",
        refusals[3]
    );
    let text = captured.text();
    for canary in CANARIES {
        assert!(!text.contains(canary), "{canary} was logged");
    }

    let rendered = Metrics::new(Telemetry::detached(), None)
        .with_grants(server.grant_signals.clone())
        .render();
    for line in [
        "switchboard_grant_failures_total{kind=\"wrong_audience\"} 1",
        "switchboard_grant_failures_total{kind=\"wrong_pod\"} 1",
        "switchboard_grant_failures_total{kind=\"expired\"} 1",
        "switchboard_grant_failures_total{kind=\"signature\"} 1",
        "switchboard_grant_failures_total{kind=\"malformed\"} 1",
        "switchboard_grant_failures_total{kind=\"version\"} 0",
        &format!(
            "switchboard_grants_accepted_total{{key_id=\"{}\"}} 1",
            minter.key_id()
        ),
    ] {
        assert!(
            rendered.lines().any(|each| each == line),
            "{line}\n{rendered}"
        );
    }
}
