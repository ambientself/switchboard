//! Turn grants through the HTTP endpoint (decision 0012, #22), signed by the test minter: what
//! a verified grant puts on the row, replay, use at another deployment and from another pod,
//! format and forgery, clock skew, key rotation across a restart, the boot refusals, failed
//! grants denied at check 3, composition with the tool list, and revocation.
//!
//! Each server is the testkit's world over loopback, as `support` builds it, with a `grants`
//! section naming one issuer whose key the test's minter holds, and a mapping from Otto-style
//! names to the fixture's tools.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use gateway::{BootError, Config, GRANT_HEADER, GrantCounts, Wiring, boot};
use gateway_core::{AuditRecord, Classification, DelegationFailure, PodUid, ReasonKind, WasProved};
use gateway_identity::Clock;
use gateway_otto::minter::{TestMinter, padded, parts, with_part};
use gateway_otto::{FailureKind, KeyConfigError};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, DRAFT_TOOL, FIXTURE_NOW, Fixture, FixtureConnector,
    InMemoryAuditStore, PROFILE_TEAM_A, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ,
    TEAM_A, TEAM_A_SUBJECT, TEAM_B, WRITE_TOOL,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use support::{FixtureResources, Http, Server, config, legacy};

/// The deployment `support`'s configuration names, which a grant's `aud` must include.
const DEPLOYMENT: &str = "server-test";
/// The grant issuer's name.
const ISSUER: &str = "otto-test";
/// The sentence every grant that does not verify is denied with, whatever failed.
const UNVERIFIED: &str =
    "This gateway requires a verifiable turn grant on every call, and this call's did not verify.";
/// The pod the caller's token proves.
const POD: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
/// Another pod of the same team.
const OTHER_POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
/// Values only a grant's claims hold, which nothing from a refused grant may show.
const CANARIES: [&str; 4] = [
    "actor-canary@example.test",
    "session-canary",
    "turn-canary",
    "execution-canary",
];

/// The mapping: Otto's names for the fixture's four tools, and one more that maps to nothing
/// the fixture approves.
fn mapping() -> Value {
    json!({
        "otto_read": READ_TOOL,
        "otto_draft": DRAFT_TOOL,
        "otto_write": WRITE_TOOL,
        "otto_scoped": SCOPED_READ_TOOL,
    })
}

/// The `grants` section: one issuer with `minter`'s key.
fn grants(minter: &TestMinter, require_pod: bool) -> Value {
    json!({"enforce": {
        "issuers": [{
            "name": ISSUER,
            "current_key": minter.public_key_pem(),
            "require_pod": require_pod,
            "require_egress": false,
        }],
        "tool_mapping": mapping(),
    }})
}

/// A grant's claims for team A, issued at `now` for ten minutes.
fn claims(now: u64) -> Value {
    json!({
        "aud": ["otto-gateway", DEPLOYMENT],
        "iat": now,
        "exp": now + 600,
        "team": TEAM_A,
        "tools": ["otto_read", "otto_draft", "otto_write", "otto_unmapped"],
        "epoch": 7,
        "sid": "session-canary",
        "tid": "turn-canary",
        "eid": "execution-canary",
        "actor": "actor-canary@example.test",
        "pod": POD,
        "egress": "sealed",
    })
}

/// `claims` with members replaced, or removed where the value is null.
fn changed(now: u64, changes: Value) -> Value {
    let mut claims = claims(now);
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
    }
    claims
}

fn now(server: &Server) -> u64 {
    server.fixture.clock.unix_millis() / 1000
}

fn digest(grant: &str) -> String {
    Sha256::digest(grant.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A server whose grants verify under `minter`'s key, with `configure` applied after.
async fn server_with(
    minter: &TestMinter,
    require_pod: bool,
    configure: impl FnOnce(&mut Value),
) -> Server {
    let grants = grants(minter, require_pod);
    Server::start_configured(move |config| {
        config["grants"] = grants;
        configure(config);
    })
    .await
}

async fn server(minter: &TestMinter) -> Server {
    server_with(minter, false, |_| {}).await
}

/// Team A's token, naming `pod` when given.
fn token(server: &Server, pod: Option<&str>) -> String {
    let now = server.fixture.clock.now();
    let token = server
        .fixture
        .workload_issuer
        .workload_token(TEAM_A_SUBJECT, AUDIENCE, now);
    match pod {
        Some(uid) => token
            .claim(
                "kubernetes.io",
                json!({"namespace": "team-a", "pod": {"name": "sandbox-1", "uid": uid}}),
            )
            .build(),
        None => token.build(),
    }
}

/// A `tools/call` of `tool` on `surface` from team A's workload in `pod`, carrying `grants`,
/// each as its own header, and a fresh key.
fn call(server: &Server, pod: Option<&str>, surface: &str, tool: &str, grants: &[&str]) -> Http {
    let params = json!({
        "name": tool,
        "arguments": {"document": Caller::TeamA.own_document(), "draft": "draft-1"},
        "_meta": {gateway_mcp::TOOL_USE_ID_META: gateway_testkit::fresh_key().as_str()},
    });
    let mut request = server
        .post(surface, &legacy("tools/call", params))
        .bearer(&token(server, pod));
    for grant in grants {
        request = request.header(GRANT_HEADER, grant);
    }
    request
}

/// A read of team A's own document on the read surface, which the fixture allows team A.
fn read(server: &Server, pod: Option<&str>, grants: &[&str]) -> Http {
    call(server, pod, SURFACE_READ, READ_TOOL, grants)
}

/// A `tools/list` of `surface` from team A, carrying `grant`.
fn list(server: &Server, surface: &str, grant: Option<&str>) -> Http {
    let request = server
        .post(surface, &legacy("tools/list", json!({})))
        .bearer(&token(server, None));
    match grant {
        Some(grant) => request.header(GRANT_HEADER, grant),
        None => request,
    }
}

fn listed(answer: &support::Answer) -> Vec<String> {
    answer.result()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

fn last_row(server: &Server) -> AuditRecord {
    server.store.rows().last().cloned().expect("a row")
}

/// The row of a call denied at check 3 for a grant that failed `failure`, recorded with
/// `digest` and nothing from the grant's claims.
fn assert_unverified_row(row: &AuditRecord, failure: DelegationFailure, digest: Option<&str>) {
    assert_eq!(
        row.reason,
        Some(ReasonKind::DelegationUnverified),
        "{row:?}"
    );
    assert_eq!(row.sentence.as_deref(), Some(UNVERIFIED));
    let recorded = row.delegation_failure.as_ref().expect("a failure");
    assert_eq!(recorded.failure, failure);
    assert_eq!(
        recorded.digest.map(|digest| digest.to_hex()).as_deref(),
        digest
    );
    assert_eq!(row.delegation, None);
    assert_eq!(row.proved_delegation_team, None);
    assert_eq!(row.claimed_acting_person, None);
    let text = serde_json::to_string(row).unwrap();
    for canary in CANARIES {
        assert!(!text.contains(canary), "{canary} in {text}");
    }
}

/// Sends `request`, expects the unverified sentence, and checks the row.
async fn assert_refused(
    server: &Server,
    request: Http,
    failure: DelegationFailure,
    digest: Option<&str>,
) {
    let ran = server.connector.received().len();
    let answer = request.send(server).await;
    assert_eq!(answer.denial(), UNVERIFIED);
    let body = String::from_utf8_lossy(&answer.body).into_owned();
    for canary in CANARIES {
        assert!(!body.contains(canary), "{canary} in {body}");
    }
    assert!(
        !body.contains(failure.as_str()),
        "the failure was named: {body}"
    );
    assert_unverified_row(&last_row(server), failure, digest);
    assert_eq!(server.connector.received().len(), ran, "the connector ran");
}

fn failures(counts: &GrantCounts, kind: FailureKind) -> u64 {
    counts
        .failures
        .iter()
        .find(|(each, _)| *each == kind)
        .map(|(_, count)| *count)
        .unwrap()
}

// --- A verified grant ------------------------------------------------------------------------

/// A verified grant's columns are on the row: its digest, issuer, key ID, session, turn,
/// execution, epoch and egress, the team proved and the person claimed, and the pod the
/// caller's token proves. The list row records the same delegation.
#[tokio::test]
async fn a_verified_grants_columns_and_the_pod_are_on_the_row() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let grant = minter.mint(&claims(now(&server)));

    let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false), "{answer:?}");
    let row = last_row(&server);
    assert_eq!(row.reason, None);
    assert_eq!(row.delegation_failure, None);
    let recorded = row.delegation.clone().expect("the delegation's columns");
    assert_eq!(recorded.digest.to_hex(), digest(&grant));
    assert_eq!(recorded.issuer.as_str(), ISSUER);
    assert_eq!(recorded.key_id.as_str(), minter.key_id().as_str());
    assert_eq!(recorded.session.as_str(), "session-canary");
    assert_eq!(recorded.turn.as_str(), "turn-canary");
    assert_eq!(recorded.execution.as_str(), "execution-canary");
    assert_eq!(recorded.epoch, 7);
    assert_eq!(recorded.egress, Some(gateway_core::Egress::Sealed));
    assert_eq!(
        row.proved_delegation_team
            .as_ref()
            .map(|team| team.get().as_str()),
        Some(TEAM_A)
    );
    assert_eq!(
        row.claimed_acting_person
            .as_ref()
            .map(|person| person.get().as_str()),
        Some("actor-canary@example.test")
    );
    let proved: &WasProved<_> = &row.proved_principal;
    assert_eq!(proved.get().pod(), Some(&PodUid::parse(POD).unwrap()));

    let answer = list(&server, SURFACE_READ, Some(&grant))
        .send(&server)
        .await;
    assert_eq!(listed(&answer), [READ_TOOL]);
    let (_, list_row) = server.store.list_rows().last().cloned().unwrap();
    assert_eq!(list_row.delegation, Some(recorded));

    let counts = server.grant_signals.counts();
    assert_eq!(
        counts.accepted,
        [(minter.key_id().as_str().to_owned(), 2)],
        "{counts:?}"
    );
    assert!(counts.failures.iter().all(|(_, count)| *count == 0));
}

/// A grant is verified whatever the profile requires: the fixture's profiles require no
/// delegation, and a grant for another deployment is still denied at check 3, and a verified
/// one still narrows.
#[tokio::test]
async fn a_grant_is_verified_though_the_profile_requires_no_delegation() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let elsewhere = minter.mint(&changed(now(&server), json!({"aud": ["elsewhere"]})));
    let refused = read(&server, None, &[&elsewhere]);
    assert_refused(
        &server,
        refused,
        DelegationFailure::WrongAudience,
        Some(&digest(&elsewhere)),
    )
    .await;

    // Without the grant the same call is allowed: the profile does not require one.
    let answer = read(&server, None, &[]).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false));
    assert_eq!(last_row(&server).delegation, None);
}

/// A request with no grant has no delegation: under a profile that requires one it is denied
/// as missing, not as unverified.
#[tokio::test]
async fn no_grant_under_a_profile_that_requires_one_is_missing() {
    let minter = TestMinter::generate();
    let server = server_with(&minter, true, |config| {
        config["policy"]["profiles"][0]["requires_delegation"] = json!(true);
    })
    .await;
    let answer = read(&server, Some(POD), &[]).send(&server).await;
    let sentence = answer.denial();
    assert_ne!(sentence, UNVERIFIED);
    let row = last_row(&server);
    assert_eq!(row.reason, Some(ReasonKind::DelegationDisagrees));
    assert_eq!(row.delegation_failure, None);

    let grant = minter.mint(&claims(now(&server)));
    let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false), "{answer:?}");
}

// --- Replay, another deployment, another pod -------------------------------------------------

/// A grant may be presented any number of times within its bounds, and every row records the
/// same digest.
#[tokio::test]
async fn the_same_grant_is_accepted_again_and_again_with_one_digest() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let grant = minter.mint(&claims(now(&server)));
    for _ in 0..3 {
        let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
        assert_eq!(answer.result()["isError"], json!(false));
    }
    let digests: Vec<String> = server
        .store
        .rows()
        .iter()
        .map(|row| row.delegation.as_ref().unwrap().digest.to_hex())
        .collect();
    assert_eq!(digests, vec![digest(&grant); 3]);
}

/// A grant whose audience does not name this deployment is refused, with its digest, since its
/// signature verified.
#[tokio::test]
async fn a_grant_for_another_deployment_is_refused_with_its_digest() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let grant = minter.mint(&changed(now(&server), json!({"aud": ["otto-gateway"]})));
    let request = read(&server, Some(POD), &[&grant]);
    assert_refused(
        &server,
        request,
        DelegationFailure::WrongAudience,
        Some(&digest(&grant)),
    )
    .await;
    assert_eq!(
        failures(&server.grant_signals.counts(), FailureKind::WrongAudience),
        1
    );
}

/// Once the issuer requires `pod`, a grant is accepted only from the pod it names: not from
/// another pod of the team, and not from a caller whose token proves none. The refusal carries
/// the digest and does not name the pod.
#[tokio::test]
async fn once_pod_is_required_a_grant_is_refused_from_another_pod() {
    let minter = TestMinter::generate();
    let server = server_with(&minter, true, |_| {}).await;
    let grant = minter.mint(&claims(now(&server)));
    for pod in [Some(OTHER_POD), None] {
        let request = read(&server, pod, &[&grant]);
        assert_refused(
            &server,
            request,
            DelegationFailure::WrongPod,
            Some(&digest(&grant)),
        )
        .await;
        let row = last_row(&server);
        assert_eq!(row.proved_principal.get().pod().map(PodUid::as_str), pod);
    }
    let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false));

    // A grant without `pod` is malformed for an issuer that requires it.
    let podless = minter.mint(&changed(now(&server), json!({"pod": null})));
    let request = read(&server, Some(POD), &[&podless]);
    assert_refused(&server, request, DelegationFailure::Malformed, None).await;
}

/// Until `pod` is required, a copied grant is accepted from another pod of its team, and the
/// row records the pod that presented it (decision 0012, the gap accepted for stages 1 and 2).
#[tokio::test]
async fn until_pod_is_required_another_pod_is_recorded_not_refused() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let grant = minter.mint(&claims(now(&server)));
    let answer = read(&server, Some(OTHER_POD), &[&grant])
        .send(&server)
        .await;
    assert_eq!(answer.result()["isError"], json!(false));
    let row = last_row(&server);
    assert_eq!(
        row.proved_principal.get().pod().map(PodUid::as_str),
        Some(OTHER_POD)
    );
    assert_eq!(row.delegation.unwrap().digest.to_hex(), digest(&grant));
}

// --- Format and forgery ----------------------------------------------------------------------

/// Each kind of unverifiable grant is denied at check 3 with the one sentence, its row holding
/// which check failed, no digest, since no signature verified, and nothing from its claims.
#[tokio::test]
async fn forged_and_misformatted_grants_are_denied_at_check_3() {
    let minter = TestMinter::generate();
    let stranger = TestMinter::generate();
    let server = server(&minter).await;
    let now = now(&server);
    let good = minter.mint(&claims(now));
    let encoded = parts(&good)[2].clone();
    let cases = [
        (
            "an HMAC grant of Otto's v1",
            minter.sign("v1", minter.key_id().as_str(), &encoded),
            DelegationFailure::Version,
        ),
        (
            "a key no issuer holds",
            stranger.mint(&claims(now)),
            DelegationFailure::UnknownKey,
        ),
        (
            "another key's signature under this key's ID",
            with_part(&good, 3, &parts(&stranger.mint(&claims(now)))[3]),
            DelegationFailure::Signature,
        ),
        (
            "a signature with padding",
            with_part(&good, 3, &padded(&parts(&good)[3]).unwrap()),
            DelegationFailure::Encoding,
        ),
        (
            "five parts",
            format!("{good}.extra"),
            DelegationFailure::Malformed,
        ),
        (
            "over the size limit",
            format!("v3.{}", "a".repeat(9000)),
            DelegationFailure::Malformed,
        ),
    ];
    for (case, grant, failure) in cases {
        let request = read(&server, Some(POD), &[&grant]);
        let answer = request.send(&server).await;
        assert_eq!(answer.denial(), UNVERIFIED, "{case}");
        assert_unverified_row(&last_row(&server), failure, None);
    }
    assert!(server.connector.received().is_empty());
}

/// A grant whose signature verified and whose claims are malformed is refused as malformed,
/// and the row records no digest: only a binding's failure carries one.
#[tokio::test]
async fn a_signed_grant_with_malformed_claims_has_no_digest_on_its_row() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    for change in [
        json!({"team": null}),
        json!({"tools": []}),
        json!({"epoch": 0}),
    ] {
        let grant = minter.mint(&changed(now(&server), change.clone()));
        let request = read(&server, Some(POD), &[&grant]);
        assert_refused(&server, request, DelegationFailure::Malformed, None).await;
    }
}

/// A request with the grant header twice is a malformed grant, even when both are the same
/// good grant.
#[tokio::test]
async fn two_grant_headers_are_a_malformed_grant() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let grant = minter.mint(&claims(now(&server)));
    let request = read(&server, Some(POD), &[&grant, &grant]);
    assert_refused(&server, request, DelegationFailure::Malformed, None).await;
    assert_eq!(
        failures(&server.grant_signals.counts(), FailureKind::Malformed),
        1
    );
    // A list with two is refused the same way: it lists nothing.
    let answer = list(&server, SURFACE_READ, Some(&grant))
        .header(GRANT_HEADER, &grant)
        .send(&server)
        .await;
    assert_eq!(listed(&answer), Vec::<String>::new());
}

// --- Clock skew ------------------------------------------------------------------------------

/// The leeway is 30 seconds either way and the ceiling 15 minutes, read from the gateway's
/// clock. A lifetime failure carries the digest.
#[tokio::test]
async fn clock_skew_is_allowed_to_the_leeway_and_the_lifetime_to_the_ceiling() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let now = now(&server);
    let accepted = [
        json!({"iat": now + 30, "exp": now + 600}),
        json!({"iat": now - 600, "exp": now - 29}),
        json!({"iat": now, "exp": now + 900}),
    ];
    for change in accepted {
        let grant = minter.mint(&changed(now, change.clone()));
        let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
        assert_eq!(answer.result()["isError"], json!(false), "{change}");
    }
    let refused = [
        (
            json!({"iat": now + 31, "exp": now + 600}),
            DelegationFailure::NotYetValid,
        ),
        (
            json!({"iat": now - 600, "exp": now - 30}),
            DelegationFailure::Expired,
        ),
        (
            json!({"iat": now, "exp": now + 901}),
            DelegationFailure::LifetimeOverCeiling,
        ),
    ];
    for (change, failure) in refused {
        let grant = minter.mint(&changed(now, change));
        let request = read(&server, Some(POD), &[&grant]);
        assert_refused(&server, request, failure, Some(&digest(&grant))).await;
    }
    let counts = server.grant_signals.counts();
    for kind in [
        FailureKind::NotYetValid,
        FailureKind::Expired,
        FailureKind::LifetimeOverCeiling,
    ] {
        assert_eq!(failures(&counts, kind), 1, "{kind}");
    }

    // The gateway's clock decides: moved past the grant's expiry and the leeway, the same grant
    // is refused.
    let grant = minter.mint(&claims(now));
    server.fixture.clock.set(now + 630);
    let request = read(&server, Some(POD), &[&grant]);
    assert_refused(
        &server,
        request,
        DelegationFailure::Expired,
        Some(&digest(&grant)),
    )
    .await;
}

// --- Key rotation across a restart -----------------------------------------------------------

/// The `grants` section of an issuer rotating from `previous` to `current`, the previous key
/// retiring at `retires_at`.
fn rotating(current: &TestMinter, previous: &TestMinter, retires_at: u64) -> Value {
    json!({"enforce": {
        "issuers": [{
            "name": ISSUER,
            "current_key": current.public_key_pem(),
            "previous_key": {"key": previous.public_key_pem(), "retires_at": retires_at},
            "require_pod": false,
            "require_egress": false,
        }],
        "tool_mapping": mapping(),
    }})
}

async fn rotating_server(current: &TestMinter, previous: &TestMinter, retires_at: u64) -> Server {
    let grants = rotating(current, previous, retires_at);
    Server::start_configured(move |config| config["grants"] = grants).await
}

/// During a rotation both keys verify, each counted under its own key ID. The previous key's
/// end is an absolute instant: a gateway started again after it refuses that key's grants, and
/// one started again before it still accepts them until it passes.
#[tokio::test]
async fn a_rotation_holds_its_end_instant_across_a_restart() {
    let old = TestMinter::generate();
    let new = TestMinter::generate();
    let retires_at = FIXTURE_NOW + 300;

    let server = rotating_server(&new, &old, retires_at).await;
    for minter in [&old, &new] {
        let grant = minter.mint(&claims(now(&server)));
        let answer = read(&server, Some(POD), &[&grant]).send(&server).await;
        assert_eq!(answer.result()["isError"], json!(false));
        assert_eq!(
            last_row(&server).delegation.unwrap().key_id.as_str(),
            minter.key_id().as_str()
        );
    }
    let mut accepted = server.grant_signals.counts().accepted;
    accepted.sort();
    let mut expected = vec![
        (old.key_id().as_str().to_owned(), 1),
        (new.key_id().as_str().to_owned(), 1),
    ];
    expected.sort();
    assert_eq!(accepted, expected);

    // Started again a minute before the end: the previous key still verifies, until the end.
    let restarted = rotating_server(&new, &old, retires_at).await;
    restarted.fixture.clock.set(retires_at - 60);
    let grant = old.mint(&claims(now(&restarted)));
    let answer = read(&restarted, Some(POD), &[&grant])
        .send(&restarted)
        .await;
    assert_eq!(answer.result()["isError"], json!(false));
    restarted.fixture.clock.set(retires_at);
    let request = read(&restarted, Some(POD), &[&grant]);
    assert_refused(&restarted, request, DelegationFailure::RetiredKey, None).await;

    // Started again after the end: the restart does not extend it.
    let after = rotating_server(&new, &old, retires_at).await;
    after.fixture.clock.set(retires_at + 1);
    let grant = old.mint(&claims(now(&after)));
    let request = read(&after, Some(POD), &[&grant]);
    assert_refused(&after, request, DelegationFailure::RetiredKey, None).await;
    let grant = new.mint(&claims(now(&after)));
    let answer = read(&after, Some(POD), &[&grant]).send(&after).await;
    assert_eq!(answer.result()["isError"], json!(false));
}

// --- Composition with the tool list ----------------------------------------------------------

/// A grant only narrows. On the surface serving all four tools, team A's grant lists Otto's
/// names for the read, draft and write tools, and a name the mapping lacks: the list holds the
/// read and draft tools; the scoped read tool, which the grant does not list, is denied at check
/// 4; the write tool the grant lists is still denied at check 5; and the fixture's own name for
/// a tool, which the mapping lacks, permits nothing.
#[tokio::test]
async fn a_grant_only_narrows_the_tool_list() {
    let minter = TestMinter::generate();
    let server = server(&minter).await;
    let now = now(&server);
    let grant = minter.mint(&claims(now));

    let answer = list(&server, SURFACE_ALL, None).send(&server).await;
    let mut without = listed(&answer);
    without.sort();
    let mut expected = vec![
        READ_TOOL.to_owned(),
        DRAFT_TOOL.to_owned(),
        SCOPED_READ_TOOL.to_owned(),
    ];
    expected.sort();
    assert_eq!(without, expected);
    let answer = list(&server, SURFACE_ALL, Some(&grant)).send(&server).await;
    let mut with = listed(&answer);
    with.sort();
    let mut expected = vec![READ_TOOL.to_owned(), DRAFT_TOOL.to_owned()];
    expected.sort();
    assert_eq!(with, expected);

    let answer = call(&server, Some(POD), SURFACE_ALL, SCOPED_READ_TOOL, &[&grant])
        .send(&server)
        .await;
    answer.denial();
    assert_eq!(
        last_row(&server).reason,
        Some(ReasonKind::ToolNotInDelegation)
    );

    let answer = call(&server, Some(POD), SURFACE_ALL, WRITE_TOOL, &[&grant])
        .send(&server)
        .await;
    answer.denial();
    assert_eq!(
        last_row(&server).reason,
        Some(ReasonKind::ClassificationNotPermitted)
    );

    let unmapped = minter.mint(&changed(
        now,
        json!({"tools": [READ_TOOL, "otto_unmapped"]}),
    ));
    let answer = read(&server, Some(POD), &[&unmapped]).send(&server).await;
    answer.denial();
    assert_eq!(
        last_row(&server).reason,
        Some(ReasonKind::ToolNotInDelegation)
    );
}

// --- Revocation ------------------------------------------------------------------------------

/// The three levers this gateway holds each stop a grant that verifies: the team taken off the
/// surface's allowlist, the key taken out of configuration, and the surface withdrawn. Each is
/// a change of configuration, served here by a restart.
#[tokio::test]
async fn the_team_key_and_surface_levers_stop_a_verified_grant() {
    let minter = TestMinter::generate();

    let team_removed = server_with(&minter, false, |config| {
        for surface in config["policy"]["surfaces"].as_array_mut().unwrap() {
            surface["teams"] = json!([TEAM_B]);
        }
    })
    .await;
    let grant = minter.mint(&claims(now(&team_removed)));
    let answer = read(&team_removed, Some(POD), &[&grant])
        .send(&team_removed)
        .await;
    answer.denial();
    assert_eq!(
        last_row(&team_removed).reason,
        Some(ReasonKind::SurfaceNotPermitted)
    );

    let other = TestMinter::generate();
    let key_removed = server(&other).await;
    let grant = minter.mint(&claims(now(&key_removed)));
    let request = read(&key_removed, Some(POD), &[&grant]);
    assert_refused(&key_removed, request, DelegationFailure::UnknownKey, None).await;

    let surface_withdrawn = server_with(&minter, false, |config| {
        let surfaces = config["policy"]["surfaces"].as_array_mut().unwrap();
        surfaces.retain(|surface| surface["name"] != json!(SURFACE_READ));
    })
    .await;
    let grant = minter.mint(&claims(now(&surface_withdrawn)));
    let answer = read(&surface_withdrawn, Some(POD), &[&grant])
        .send(&surface_withdrawn)
        .await;
    answer.denial();
    assert_eq!(
        last_row(&surface_withdrawn).reason,
        Some(ReasonKind::SurfaceNotPermitted)
    );
}

// --- No issuer, and checking disabled ---------------------------------------------------------

/// With no `grants` section, checking is on with no issuer: a grant is refused as its version
/// or its unknown key, and a request without one is served as before.
#[tokio::test]
async fn with_no_issuer_configured_every_grant_is_refused() {
    let minter = TestMinter::generate();
    let server = Server::start().await;
    let grant = minter.mint(&claims(now(&server)));
    let request = read(&server, Some(POD), &[&grant]);
    assert_refused(&server, request, DelegationFailure::UnknownKey, None).await;
    let request = read(&server, Some(POD), &["v1.key.claims.mac"]);
    assert_refused(&server, request, DelegationFailure::Version, None).await;
    let answer = read(&server, Some(POD), &[]).send(&server).await;
    assert_eq!(answer.result()["isError"], json!(false));
}

/// With checking disabled, which only a development build allows, the header is not read: a
/// grant that would fail is ignored.
#[tokio::test]
async fn with_checking_disabled_the_header_is_not_read() {
    let server = Server::start_configured(|config| {
        config["grants"] = json!({"disabled": true});
    })
    .await;
    let answer = read(&server, Some(POD), &["v1.key.claims.mac", "another"])
        .send(&server)
        .await;
    assert_eq!(answer.result()["isError"], json!(false));
    assert_eq!(last_row(&server).delegation_failure, None);
    assert!(
        server
            .grant_signals
            .counts()
            .failures
            .iter()
            .all(|(_, count)| *count == 0)
    );
}

// --- Boot refusals ---------------------------------------------------------------------------

/// `support`'s configuration with `configure` applied, booted as a development build or as the
/// release build runs the gates.
fn boot_with(configure: impl FnOnce(&mut Value), release: bool) -> Result<(), BootError> {
    let fixture = Fixture::new().unwrap();
    let mut value = config(&fixture);
    configure(&mut value);
    let config: Config = serde_json::from_value(value).unwrap();
    let credentials = Arc::new(gateway_testkit::FakeCredentialSource::new());
    let wiring = Wiring::new(Arc::new(fixture.clock.clone()))
        .connector(
            CONNECTOR,
            Arc::new(FixtureConnector::new(credentials)),
            Arc::new(FixtureResources),
        )
        .audit_store(Arc::new(InMemoryAuditStore::new()));
    let checked = if release {
        boot::as_release::check(config, wiring)
    } else {
        boot::check(config, wiring)
    };
    checked.map(drop)
}

/// The fixture's policy with team A's profile requiring a delegation. Team A's surfaces serve
/// a `propose` and a `write` tool.
fn requiring(config: &mut Value) {
    config["policy"]["profiles"][0]["requires_delegation"] = json!(true);
    assert_eq!(
        config["policy"]["profiles"][0]["name"],
        json!(PROFILE_TEAM_A)
    );
}

/// A profile a rule gives workloads requires a delegation and no grant issuer is configured:
/// refused, naming the profile. With an issuer, it starts.
#[test]
fn a_profile_requiring_a_delegation_needs_a_grant_issuer() {
    let refused = boot_with(requiring, false).unwrap_err();
    assert!(matches!(&refused, BootError::GrantPolicy(_)), "{refused:?}");
    let message = refused.to_string();
    assert!(
        message.contains(&format!("profile `{PROFILE_TEAM_A}`")),
        "{message}"
    );
    assert!(
        message.contains("no turn-grant issuer is configured"),
        "{message}"
    );

    let minter = TestMinter::generate();
    let started = boot_with(
        |config| {
            requiring(config);
            config["grants"] = grants(&minter, true);
        },
        false,
    );
    assert!(started.is_ok(), "{started:?}");
}

/// A tool not classified `read` on a surface admitting a team whose profile requires a
/// delegation, while the issuer does not require `pod`: refused, naming the tool, the surface,
/// the team, the profile and the issuer. Requiring `pod` passes, and so does a profile that
/// requires no delegation.
#[test]
fn a_side_effecting_tool_needs_the_pod_bound() {
    let minter = TestMinter::generate();
    let refused = boot_with(
        |config| {
            requiring(config);
            config["grants"] = grants(&minter, false);
        },
        false,
    )
    .unwrap_err();
    let message = refused.to_string();
    for named in [
        format!(
            "tool `{DRAFT_TOOL}` is classified `{}`",
            Classification::Propose
        ),
        format!("surface `{SURFACE_ALL}`"),
        format!("team `{TEAM_A}`"),
        format!("profile `{PROFILE_TEAM_A}`"),
        format!("issuer `{ISSUER}` does not require `pod`"),
    ] {
        assert!(message.contains(&named), "{named}: {message}");
    }

    let not_requiring = boot_with(|config| config["grants"] = grants(&minter, false), false);
    assert!(not_requiring.is_ok(), "{not_requiring:?}");

    // Any configured issuer's grant verifies for any caller, so every issuer must bind the pod:
    // one that does is not enough beside one that does not.
    let other = TestMinter::generate();
    let mixed = boot_with(
        |config| {
            requiring(config);
            let mut grants = grants(&minter, true);
            grants["enforce"]["issuers"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "name": "otto-unbound",
                    "current_key": other.public_key_pem(),
                    "require_pod": false,
                    "require_egress": false,
                }));
            config["grants"] = grants;
        },
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(
        mixed.contains("issuer `otto-unbound` does not require `pod`"),
        "{mixed}"
    );
}

/// The release build refuses grant checking disabled, before anything else; a development
/// build starts with it.
#[test]
fn grant_checking_off_is_refused_outside_a_development_build() {
    let disabled = |config: &mut Value| config["grants"] = json!({"disabled": true});
    let refused = boot_with(disabled, true).unwrap_err();
    assert!(matches!(refused, BootError::GrantOptOut), "{refused:?}");
    assert!(
        refused
            .to_string()
            .starts_with("turn-grant checking is disabled, which only a development build allows"),
        "{refused}"
    );
    assert!(boot_with(disabled, false).is_ok());
}

/// Each refusal of the key configuration refuses to start, with gateway-otto's own message;
/// and checking both enforced and disabled is a contradiction.
#[test]
fn each_key_configuration_refusal_refuses_to_start() {
    let minter = TestMinter::generate();
    let with_issuer = |change: &dyn Fn(&mut Value)| {
        boot_with(
            |config| {
                let mut grants = grants(&minter, false);
                change(&mut grants["enforce"]["issuers"][0]);
                config["grants"] = grants;
            },
            false,
        )
        .unwrap_err()
    };
    let private = with_issuer(&|issuer| issuer["current_key"] = json!(minter.private_key_pem()));
    assert!(
        matches!(
            &private,
            BootError::GrantKeys(KeyConfigError::PrivateKeyMaterial(name)) if name == ISSUER
        ),
        "{private:?}"
    );
    assert_eq!(
        private.to_string(),
        KeyConfigError::PrivateKeyMaterial(ISSUER.into()).to_string()
    );
    let no_end = with_issuer(&|issuer| {
        issuer["previous_key"] = json!({"key": TestMinter::generate().public_key_pem()});
    });
    assert!(
        matches!(
            &no_end,
            BootError::GrantKeys(KeyConfigError::PreviousKeyWithoutEnd(_))
        ),
        "{no_end:?}"
    );
    let repeated = with_issuer(&|issuer| {
        issuer["previous_key"] = json!({"key": minter.public_key_pem(), "retires_at": FIXTURE_NOW});
    });
    assert!(
        matches!(
            &repeated,
            BootError::GrantKeys(KeyConfigError::KeyRepeated(_))
        ),
        "{repeated:?}"
    );
    let none = boot_with(
        |config| config["grants"] = json!({"enforce": {"issuers": [], "tool_mapping": {}}}),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(none, BootError::GrantKeys(KeyConfigError::NoIssuers)),
        "{none:?}"
    );
    let both = boot_with(
        |config| {
            let mut grants = grants(&minter, false);
            grants["disabled"] = json!(true);
            config["grants"] = grants;
        },
        false,
    )
    .unwrap_err();
    assert!(matches!(both, BootError::GrantContradiction), "{both:?}");

    // A mapping that is not one to one is refused as the configuration is read.
    let fixture = Fixture::new().unwrap();
    let mut value = config(&fixture);
    let mut grants = grants(&minter, false);
    grants["enforce"]["tool_mapping"] = json!({"otto_read": READ_TOOL, "otto_also": READ_TOOL});
    value["grants"] = grants;
    let refused = serde_json::from_value::<Config>(value).unwrap_err();
    assert!(refused.to_string().contains("both map to"), "{refused}");
}
