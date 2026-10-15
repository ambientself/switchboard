//! Decision 0012's currency question through the HTTP endpoint (#22): Otto's two example
//! profiles, turn grants from the test minter, and the fake resolver over loopback, asked about
//! the fixture's `propose` tool.
//!
//! Team A's workloads get the profile for Otto's sandboxes and team B's the profile for Otto's
//! control-plane surface, both read from `docs/examples/otto-profiles.toml`. A read is never
//! asked about and is allowed whatever the resolver says or does; a proposal is asked about
//! once, every time, and allowed only when current. Every failure is unconfirmed and denied,
//! with the row recording the answer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway::{BootError, Config, GRANT_HEADER, Metrics, Wiring, boot};
use gateway_core::audit::DecisionKind;
use gateway_core::{AuditRecord, CurrencyAnswer, Profile, ReasonKind, ReceiptState};
use gateway_identity::Clock;
use gateway_otto::HttpResolver;
use gateway_otto::fake::{FakeReply, FakeResolver, Member};
use gateway_otto::minter::TestMinter;
use gateway_otto::resolver::{Answer, BUDGET};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, DRAFT_TOOL, Fixture, FixtureConnector, InMemoryAuditStore,
    READ_TOOL, SURFACE_ALL, TEAM_A, TEAM_A_SUBJECT, TEAM_B, TEAM_B_SUBJECT, WORKLOAD_ISSUER,
    WRITE_TOOL, fresh_key,
};
use serde::Deserialize;
use serde_json::{Value, json};

use support::{FixtureResources, Http, Server, config, legacy};

/// Otto's example profiles.
const EXAMPLE: &str = include_str!("../../../docs/examples/otto-profiles.toml");
/// The profile for Otto's sandboxes, which requires currency.
const SANDBOX: &str = "otto-sandbox";
/// The profile for Otto's control-plane surface, which does not.
const CONTROL_PLANE: &str = "otto-control-plane";
/// The deployment `support`'s configuration names, which a grant's `aud` must include.
const DEPLOYMENT: &str = "server-test";
/// The grant issuer's name.
const ISSUER: &str = "otto-test";
/// The pod team A's token proves, and its grants name.
const POD: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
/// How long past the budget an answer may take, for a loaded machine.
const SLACK: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Example {
    profiles: Vec<Profile>,
}

/// The example's profiles, as the core reads a profile.
fn example() -> Vec<Profile> {
    toml::from_str::<Example>(EXAMPLE).unwrap().profiles
}

/// The example's profiles beside the fixture's, team A's workloads under the sandbox profile and
/// team B's under the control-plane one, and grants verified under `minter`'s key.
fn otto(config: &mut Value, minter: &TestMinter) {
    let profiles = config["policy"]["profiles"].as_array_mut().unwrap();
    for profile in example() {
        profiles.push(serde_json::to_value(profile).unwrap());
    }
    config["profiles"]["workloads"] = json!([
        {"issuer": WORKLOAD_ISSUER, "team": TEAM_A, "profile": SANDBOX},
        {"issuer": WORKLOAD_ISSUER, "team": TEAM_B, "profile": CONTROL_PLANE},
    ]);
    // The fixture serves its `propose` tool to team A, so the pod gate needs `pod`.
    config["grants"] = json!({"enforce": {
        "issuers": [{
            "name": ISSUER,
            "current_key": minter.public_key_pem(),
            "require_pod": true,
            "require_egress": false,
        }],
        "tool_mapping": {"otto_read": READ_TOOL, "otto_draft": DRAFT_TOOL, "otto_write": WRITE_TOOL},
    }});
}

/// The client for `fake`, over plain HTTP to loopback.
fn client(fake: &FakeResolver) -> Arc<HttpResolver> {
    Arc::new(HttpResolver::new(&fake.config()).unwrap())
}

/// The world under Otto's profiles, asking `resolver`.
async fn server(minter: &TestMinter, resolver: Arc<HttpResolver>) -> Server {
    Server::start_wired(
        |config| otto(config, minter),
        |wiring| wiring.resolver(resolver),
    )
    .await
}

fn now(server: &Server) -> u64 {
    server.fixture.clock.unix_millis() / 1000
}

/// A grant for team A's turn, issued now for ten minutes, with members replaced by `changes`.
fn grant(server: &Server, minter: &TestMinter, changes: Value) -> String {
    let now = now(server);
    let mut claims = json!({
        "aud": [DEPLOYMENT],
        "iat": now,
        "exp": now + 600,
        "team": TEAM_A,
        "tools": ["otto_read", "otto_draft", "otto_write"],
        "epoch": 7,
        "sid": "session-7f3a",
        "tid": "turn-4",
        "eid": "execution-91c2",
        "actor": "actor@example.test",
        "pod": POD,
    });
    for (name, value) in changes.as_object().unwrap() {
        claims[name] = value.clone();
    }
    minter.mint(&claims)
}

/// `caller`'s token: team A's names its pod.
fn token(server: &Server, caller: Caller) -> String {
    let now = server.fixture.clock.now();
    let issuer = &server.fixture.workload_issuer;
    match caller {
        Caller::TeamA => issuer
            .workload_token(TEAM_A_SUBJECT, AUDIENCE, now)
            .claim(
                "kubernetes.io",
                json!({"namespace": "team-a", "pod": {"name": "sandbox-1", "uid": POD}}),
            )
            .build(),
        Caller::TeamB => issuer.workload_token(TEAM_B_SUBJECT, AUDIENCE, now).build(),
        Caller::UserInGroupG => server.token(caller),
    }
}

/// A `tools/call` of `tool` on the surface serving every tool, from `caller`, naming its own
/// document, with a fresh key, carrying `grant` if there is one.
fn call(server: &Server, caller: Caller, tool: &str, grant: Option<&str>) -> Http {
    let arguments = if tool == DRAFT_TOOL {
        json!({"document": caller.own_document(), "text": "A proposal."})
    } else {
        json!({"document": caller.own_document()})
    };
    let params = json!({
        "name": tool,
        "arguments": arguments,
        "_meta": {gateway_mcp::TOOL_USE_ID_META: fresh_key().as_str()},
    });
    let request = server
        .post(SURFACE_ALL, &legacy("tools/call", params))
        .bearer(&token(server, caller));
    match grant {
        Some(grant) => request.header(GRANT_HEADER, grant),
        None => request,
    }
}

/// Team A's read of its own document, under the sandbox profile.
fn read(server: &Server, grant: &str) -> Http {
    call(server, Caller::TeamA, READ_TOOL, Some(grant))
}

/// Team A's proposal on its own document, under the sandbox profile.
fn propose(server: &Server, grant: &str) -> Http {
    call(server, Caller::TeamA, DRAFT_TOOL, Some(grant))
}

fn last_row(server: &Server) -> AuditRecord {
    server.store.rows().last().cloned().expect("a row")
}

/// Sends `request` and expects it allowed and run, with a row that recorded `currency`.
async fn assert_allowed(server: &Server, request: Http, currency: Option<CurrencyAnswer>) {
    let ran = server.connector.received().len();
    let answer = request.send(server).await;
    assert_eq!(answer.result()["isError"], json!(false), "{answer:?}");
    let row = last_row(server);
    assert_eq!(row.decision, DecisionKind::Allow, "{row:?}");
    assert_eq!(row.currency, currency, "{row:?}");
    assert_eq!(
        server.connector.received().len(),
        ran + 1,
        "the connector did not run"
    );
}

/// Sends `request` and expects it denied for `reason`, with a row that recorded `currency`,
/// and nothing run.
async fn assert_denied(
    server: &Server,
    request: Http,
    reason: ReasonKind,
    currency: Option<CurrencyAnswer>,
) {
    let ran = server.connector.received().len();
    let answer = request.send(server).await;
    let sentence = answer.denial();
    let row = last_row(server);
    assert_eq!(row.reason, Some(reason), "{row:?}");
    assert_eq!(row.sentence.as_deref(), Some(sentence.as_str()));
    assert_eq!(row.currency, currency, "{row:?}");
    assert_eq!(server.connector.received().len(), ran, "the connector ran");
}

fn asked(fake: &FakeResolver) -> usize {
    fake.received().len()
}

// --- Each answer ------------------------------------------------------------------------------

/// Whatever the resolver answers, a read is not asked about and is allowed, its row recording
/// no answer. A proposal is asked about once, and allowed only when current; otherwise it is
/// denied as not current. Its row records the answer either way.
#[tokio::test]
async fn a_read_is_never_asked_and_a_proposal_is_allowed_only_when_current() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    for answer in Answer::ALL {
        fake.set(FakeReply::Answer(answer));
        let before = asked(&fake);
        assert_allowed(&server, read(&server, &grant), None).await;
        assert_eq!(asked(&fake), before, "{answer:?}: a read was asked about");

        let request = propose(&server, &grant);
        if answer == Answer::Current {
            assert_allowed(&server, request, Some(CurrencyAnswer::Current)).await;
        } else {
            assert_denied(
                &server,
                request,
                ReasonKind::NotCurrent,
                Some(answer.currency()),
            )
            .await;
        }
        assert_eq!(asked(&fake), before + 1, "{answer:?}");
    }
    // Each question named the grant's turn.
    for received in fake.received() {
        let question = received.question().unwrap();
        assert_eq!(question["sid"], json!("session-7f3a"));
        assert_eq!(question["eid"], json!("execution-91c2"));
        assert_eq!(question["tid"], json!("turn-4"));
        assert_eq!(question["epoch"], json!(7));
    }
}

/// A current proposal carrying a key runs, and reserves its receipt, which is completed.
#[tokio::test]
async fn a_current_proposal_with_a_key_runs_and_reserves_its_receipt() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    assert_allowed(
        &server,
        propose(&server, &grant),
        Some(CurrencyAnswer::Current),
    )
    .await;
    let receipts = server.store.receipts();
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_eq!(receipts[0].tool.as_str(), DRAFT_TOOL);
    assert_eq!(receipts[0].state, ReceiptState::Completed);
}

// --- Unconfirmed --------------------------------------------------------------------------------

/// No answer within the budget, an error, an answer of an unknown version and an answer to
/// another question are each unconfirmed: the proposal is denied, at most the budget after it
/// was asked, and its row records unconfirmed. A read is still allowed.
#[tokio::test]
async fn every_failure_is_unconfirmed_and_denies_a_proposal() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Hang).await.unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    for reply in [
        FakeReply::Hang,
        FakeReply::Status(500),
        FakeReply::UnknownVersion(Answer::Current),
        FakeReply::OtherQuestion(Answer::Current, Member::Turn),
        FakeReply::OtherQuestion(Answer::Current, Member::Epoch),
    ] {
        fake.set(reply);
        let before = asked(&fake);
        let started = Instant::now();
        assert_denied(
            &server,
            propose(&server, &grant),
            ReasonKind::CurrencyUnconfirmed,
            Some(CurrencyAnswer::Unconfirmed),
        )
        .await;
        let took = started.elapsed();
        assert!(took < BUDGET + SLACK, "{reply:?} took {took:?}");
        if matches!(reply, FakeReply::Hang) {
            assert!(took >= BUDGET, "gave up after {took:?}");
        }
        assert_eq!(asked(&fake), before + 1, "{reply:?}");
        assert_allowed(&server, read(&server, &grant), None).await;
    }
}

/// With the resolver down, every proposal is denied as unconfirmed, and reads are served.
#[tokio::test]
async fn with_the_resolver_down_reads_are_still_served() {
    let minter = TestMinter::generate();
    // A loopback port nothing listens on.
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let down = HttpResolver::new(&gateway_otto::ResolverConfig {
        url: format!("http://{address}"),
        ..gateway_otto::ResolverConfig::default()
    })
    .unwrap();
    let down = Arc::new(down);
    let server = server(&minter, down.clone()).await;
    let grant = grant(&server, &minter, json!({}));
    for _ in 0..2 {
        assert_allowed(&server, read(&server, &grant), None).await;
        assert_denied(
            &server,
            propose(&server, &grant),
            ReasonKind::CurrencyUnconfirmed,
            Some(CurrencyAnswer::Unconfirmed),
        )
        .await;
    }
    assert_eq!(down.counts().failed("unreachable"), 2);
}

// --- Revocation and no cache ------------------------------------------------------------------

/// Otto marks the turn revoked: the next side effect is denied, though the one before it was
/// allowed, and reads go on.
#[tokio::test]
async fn once_the_turn_is_revoked_its_next_side_effect_is_denied() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    assert_allowed(
        &server,
        propose(&server, &grant),
        Some(CurrencyAnswer::Current),
    )
    .await;
    fake.set(FakeReply::Answer(Answer::Revoked));
    assert_denied(
        &server,
        propose(&server, &grant),
        ReasonKind::NotCurrent,
        Some(CurrencyAnswer::Revoked),
    )
    .await;
    assert_allowed(&server, read(&server, &grant), None).await;
}

/// Nothing is cached: two proposals of one turn ask twice, each under a request ID of its own.
#[tokio::test]
async fn two_calls_ask_twice() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    for _ in 0..2 {
        assert_allowed(
            &server,
            propose(&server, &grant),
            Some(CurrencyAnswer::Current),
        )
        .await;
    }
    let received = fake.received();
    assert_eq!(received.len(), 2);
    let ids: Vec<Value> = received
        .iter()
        .map(|request| request.question().unwrap()["request_id"].clone())
        .collect();
    assert_ne!(ids[0], ids[1]);
}

// --- What is never asked ----------------------------------------------------------------------

/// A grant that does not verify is denied at check 3, and the resolver is not asked. Nor is it
/// for a call with no grant, which the sandbox profile denies as missing.
#[tokio::test]
async fn a_call_without_a_verified_grant_is_denied_before_asking() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let elsewhere = grant(&server, &minter, json!({"aud": ["elsewhere"]}));
    assert_denied(
        &server,
        propose(&server, &elsewhere),
        ReasonKind::DelegationUnverified,
        None,
    )
    .await;
    let forged = grant(&server, &TestMinter::generate(), json!({}));
    assert_denied(
        &server,
        propose(&server, &forged),
        ReasonKind::DelegationUnverified,
        None,
    )
    .await;
    assert_denied(
        &server,
        call(&server, Caller::TeamA, DRAFT_TOOL, None),
        ReasonKind::DelegationDisagrees,
        None,
    )
    .await;
    assert_eq!(asked(&fake), 0);
}

/// `tools/list` never asks, and lists the proposal tool to a caller who may call it.
#[tokio::test]
async fn a_tool_list_never_asks() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Revoked))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    let grant = grant(&server, &minter, json!({}));
    let answer = server
        .post(SURFACE_ALL, &legacy("tools/list", json!({})))
        .bearer(&token(&server, Caller::TeamA))
        .header(GRANT_HEADER, &grant)
        .send(&server)
        .await;
    let listed: Vec<String> = answer.result()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(listed.contains(&DRAFT_TOOL.to_owned()), "{listed:?}");
    assert_eq!(asked(&fake), 0);
}

/// Under the profile for Otto's control-plane surface, which does not require currency, a
/// proposal is allowed without asking, and its row records no answer.
#[tokio::test]
async fn a_profile_that_does_not_require_currency_never_asks() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Revoked))
        .await
        .unwrap();
    let server = server(&minter, client(&fake)).await;
    assert_allowed(
        &server,
        call(&server, Caller::TeamB, DRAFT_TOOL, None),
        None,
    )
    .await;
    assert_eq!(last_row(&server).profile.as_str(), CONTROL_PLANE);
    assert_eq!(asked(&fake), 0);
}

// --- The example profiles and the boot gate ---------------------------------------------------

/// The example holds the two profiles decision 0012 describes: the sandboxes' reads and
/// proposals with a grant and currency, and the control plane's with neither.
#[test]
fn the_example_profiles_are_the_decisions() {
    let profiles = example();
    let names: Vec<&str> = profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    assert_eq!(names, [SANDBOX, CONTROL_PLANE]);
    let classifications = |profile: &Profile| -> Vec<String> {
        profile
            .classifications
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    for profile in &profiles {
        assert_eq!(
            classifications(profile),
            ["read", "propose"],
            "{}",
            profile.name
        );
        assert!(!profile.idempotency_key_header, "{}", profile.name);
    }
    assert!(profiles[0].requires_delegation && profiles[0].requires_currency);
    assert!(!profiles[1].requires_delegation && !profiles[1].requires_currency);
}

/// The gateway refuses to start with a profile a rule selects that requires currency and no
/// resolver, naming the profile; with one it starts.
#[test]
fn boot_refuses_a_profile_requiring_currency_without_a_resolver() {
    let minter = TestMinter::generate();
    let boot_with = |resolver: Option<Arc<HttpResolver>>| {
        let fixture = Fixture::new().unwrap();
        let mut value = config(&fixture);
        otto(&mut value, &minter);
        let connector = Arc::new(FixtureConnector::new(Arc::new(
            gateway_testkit::FakeCredentialSource::new(),
        )));
        let mut wiring = Wiring::new(Arc::new(fixture.clock.clone()))
            .connector(CONNECTOR, connector, Arc::new(FixtureResources))
            .audit_store(Arc::new(InMemoryAuditStore::new()));
        if let Some(resolver) = resolver {
            wiring = wiring.resolver(resolver);
        }
        let config: Config = serde_json::from_value(value).unwrap();
        boot::check(config, wiring)
    };
    match boot_with(None) {
        Err(BootError::NoResolver(profile)) => assert_eq!(profile.as_str(), SANDBOX),
        other => panic!("expected the currency gate, got {other:?}"),
    }
    let resolver = HttpResolver::new(&gateway_otto::ResolverConfig {
        url: "http://127.0.0.1:9".into(),
        ..gateway_otto::ResolverConfig::default()
    })
    .unwrap();
    assert!(boot_with(Some(Arc::new(resolver))).is_ok());
}

// --- Metrics ----------------------------------------------------------------------------------

/// The metrics listener exports the resolver's counts: each answer, each failure by kind, and
/// how long each question took.
#[tokio::test]
async fn the_resolvers_counts_are_exported() {
    let minter = TestMinter::generate();
    let fake = FakeResolver::start(FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let resolver = client(&fake);
    let server = server(&minter, resolver.clone()).await;
    let grant = grant(&server, &minter, json!({}));
    propose(&server, &grant).send(&server).await;
    fake.set(FakeReply::Answer(Answer::Ended));
    propose(&server, &grant).send(&server).await;
    fake.set(FakeReply::Status(503));
    propose(&server, &grant).send(&server).await;
    read(&server, &grant).send(&server).await;

    let text = Metrics::new(server.telemetry.clone(), None)
        .with_resolver(resolver)
        .render();
    let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
    for expected in [
        "switchboard_resolver_answers_total{answer=\"current\"} 1",
        "switchboard_resolver_answers_total{answer=\"ended\"} 1",
        "switchboard_resolver_answers_total{answer=\"superseded\"} 0",
        "switchboard_resolver_answers_total{answer=\"unconfirmed\"} 1",
        "switchboard_resolver_failures_total{kind=\"status\"} 1",
        "switchboard_resolver_failures_total{kind=\"timeout\"} 0",
        "switchboard_resolver_question_seconds_count 3",
    ] {
        assert!(lines.contains(&expected), "{expected} not in {text}");
    }
}

// --- The token read ---------------------------------------------------------------------------

/// A token file whose read blocks, here a FIFO no writer has opened, does not hold the call
/// past the resolver's budget (#213): the proposal is answered, denied as unconfirmed, within
/// the budget and a margin, and the row records unconfirmed.
#[tokio::test]
async fn a_token_read_that_blocks_still_answers_the_call_within_the_budget() {
    let minter = TestMinter::generate();
    let scratch = Scratch::new("fifo");
    let (tls, ca) = tls_config();
    let fake = FakeResolver::start_tls(tls, FakeReply::Answer(Answer::Current))
        .await
        .unwrap();
    let ca_file = scratch.write("ca.pem", &ca);
    let token = scratch.write("token", "resolver-token\n");
    let resolver = HttpResolver::new(&gateway_otto::ResolverConfig {
        url: fake.url(),
        ca_file: Some(ca_file),
        token_file: Some(token.clone()),
    })
    .unwrap();
    let server = server(&minter, Arc::new(resolver)).await;
    let grant = grant(&server, &minter, json!({}));
    // The client is built: the token is read again only when a question is asked.
    let unblock = stall(&token);
    let started = Instant::now();
    let answer = propose(&server, &grant).send(&server).await;
    let took = started.elapsed();
    unblock.join().unwrap();
    answer.denial();
    let row = last_row(&server);
    assert_eq!(row.reason, Some(ReasonKind::CurrencyUnconfirmed), "{row:?}");
    assert_eq!(row.currency, Some(CurrencyAnswer::Unconfirmed));
    assert!(took >= BUDGET, "answered after {took:?}");
    assert!(took < BUDGET + SLACK, "answered after {took:?}");
    assert!(fake.received().is_empty());
}

/// Replaces the file at `path` with a FIFO no writer has opened, so reading it blocks, and
/// starts a thread that opens it for writing once the call should long have been answered. That
/// lets the stalled read finish, so the runtime can shut down; with the read on a runtime
/// thread, it is also what lets the call be answered, late.
fn stall(path: &Path) -> std::thread::JoinHandle<()> {
    std::fs::remove_file(path).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed: {made}");
    let path = path.to_owned();
    std::thread::spawn(move || {
        std::thread::sleep(BUDGET + SLACK);
        drop(std::fs::OpenOptions::new().write(true).open(&path));
    })
}

/// A TLS server configuration for `127.0.0.1` under a CA made for the test, and the CA in PEM.
fn tls_config() -> (Arc<tokio_rustls::rustls::ServerConfig>, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let signer = rcgen::Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &signer)
        .unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    (Arc::new(config), ca_pem)
}

/// A directory of its own for one test's files, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "gateway-currency-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
