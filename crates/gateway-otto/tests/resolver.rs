//! The resolver client against the fake resolver: each answer, the budget, each failure read
//! as unconfirmed, no cache, the cap on an answer, what a question carries, the configuration's
//! refusals and TLS with a token.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway_core::{
    Claimed, CurrencyAnswer, Delegation, DelegationDigest, DelegationIssuer, ExecutionId, KeyId,
    Person, SessionId, TeamId, TurnId,
};
use gateway_otto::fake::{FakeReply, FakeResolver, Member};
use gateway_otto::resolver::{
    Answer, BUDGET, CaFault, MAX_ANSWER_BYTES, ResolverConfigError, ResolverCounts, TokenFault,
};
use gateway_otto::{CurrencyQuestion, HttpResolver, Resolver, ResolverConfig, ResolverFailure};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Map, Value};

/// How long past the budget a question may take to give up, for a loaded machine.
const SLACK: Duration = Duration::from_millis(500);

/// Longer than any question can take while the budget holds. A test that waits this long has
/// found the budget not applied.
const NEVER: Duration = Duration::from_secs(5);

/// A change to an honest answer's object before the fake sends it.
type Edit = fn(&mut Map<String, Value>);

fn question() -> CurrencyQuestion {
    CurrencyQuestion {
        session: SessionId::new("session-7f3a"),
        execution: ExecutionId::new("execution-91c2"),
        turn: TurnId::new("turn-4"),
        epoch: 12,
    }
}

async fn fake(reply: FakeReply) -> (FakeResolver, HttpResolver) {
    let fake = FakeResolver::start(reply).await.unwrap();
    let resolver = HttpResolver::new(&fake.config()).unwrap();
    (fake, resolver)
}

/// Asks once, failing the test if the question outlives [`NEVER`].
async fn ask(resolver: &HttpResolver) -> Result<Answer, ResolverFailure> {
    tokio::time::timeout(NEVER, resolver.ask(&question()))
        .await
        .expect("the question outlived the budget: the budget is not applied")
}

/// Asks through the trait, as the gateway will.
async fn currency(resolver: &HttpResolver) -> CurrencyAnswer {
    tokio::time::timeout(NEVER, Resolver::currency(resolver, &question()))
        .await
        .expect("the question outlived the budget: the budget is not applied")
}

#[tokio::test]
async fn each_answer_is_read_as_given() {
    for answer in Answer::ALL {
        let (fake, resolver) = fake(FakeReply::Answer(answer)).await;
        assert_eq!(ask(&resolver).await, Ok(answer));
        assert_eq!(currency(&resolver).await, answer.currency());
        assert_eq!(fake.received().len(), 2);
    }
    assert_eq!(
        Answer::ALL.map(Answer::currency),
        [
            CurrencyAnswer::Current,
            CurrencyAnswer::Superseded,
            CurrencyAnswer::Ended,
            CurrencyAnswer::Revoked
        ]
    );
}

#[tokio::test]
async fn a_question_carries_the_turn_and_a_fresh_request_id() {
    let (fake, resolver) = fake(FakeReply::Answer(Answer::Current)).await;
    ask(&resolver).await.unwrap();
    ask(&resolver).await.unwrap();
    let received = fake.received();
    assert_eq!(received.len(), 2);
    let mut ids = Vec::new();
    for request in &received {
        assert_eq!(request.request_line(), "POST /v1/currency HTTP/1.1");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("cache-control"), Some("no-store"));
        assert_eq!(request.header("authorization"), None);
        let mut sent = request.question().unwrap();
        let id = sent.remove("request_id").unwrap();
        let id = id.as_str().unwrap().to_owned();
        assert_eq!(id.len(), 32);
        assert!(
            id.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        ids.push(id);
        let expected: Map<String, Value> = serde_json::from_str(
            r#"{"version":"v1","question":"currency","sid":"session-7f3a",
                "eid":"execution-91c2","tid":"turn-4","epoch":12}"#,
        )
        .unwrap();
        assert_eq!(sent, expected);
    }
    assert_ne!(ids[0], ids[1], "each question has its own request ID");
}

#[test]
fn a_question_built_from_a_delegation_names_its_turn() {
    let delegation = Delegation {
        acting_person: Claimed::new(Person::new("requester@example.test")),
        team: TeamId::new("team-a"),
        tools: BTreeSet::new(),
        issuer: DelegationIssuer::new("otto"),
        digest: DelegationDigest::of(b"grant"),
        key_id: KeyId::new("key"),
        session: SessionId::new("session-7f3a"),
        turn: TurnId::new("turn-4"),
        execution: ExecutionId::new("execution-91c2"),
        epoch: 12,
        egress: None,
    };
    assert_eq!(CurrencyQuestion::of(&delegation), question());
}

#[tokio::test]
async fn no_answer_within_the_budget_is_unconfirmed_at_the_budget() {
    for reply in [FakeReply::Hang, FakeReply::HangInBody] {
        let (fake, resolver) = fake(reply).await;
        let started = Instant::now();
        assert_eq!(
            ask(&resolver).await,
            Err(ResolverFailure::Timeout),
            "{reply:?}"
        );
        let took = started.elapsed();
        assert!(took >= BUDGET, "{reply:?} gave up after {took:?}");
        assert!(took < BUDGET + SLACK, "{reply:?} took {took:?}");

        let started = Instant::now();
        assert_eq!(currency(&resolver).await, CurrencyAnswer::Unconfirmed);
        assert!(started.elapsed() < BUDGET + SLACK);
        assert_eq!(fake.received().len(), 2);
        assert_eq!(resolver.counts().timeouts(), 2);
    }
}

#[test]
fn the_budget_is_one_second() {
    assert_eq!(BUDGET, Duration::from_secs(1));
}

#[tokio::test]
async fn an_error_is_unconfirmed() {
    let cases = [
        (FakeReply::Status(500), ResolverFailure::Status(500)),
        (FakeReply::Status(503), ResolverFailure::Status(503)),
        (FakeReply::Status(404), ResolverFailure::Status(404)),
        // A redirect is not followed, and an honest answer under it is still refused.
        (FakeReply::Status(302), ResolverFailure::Status(302)),
        (FakeReply::Status(201), ResolverFailure::Status(201)),
        (FakeReply::Close, ResolverFailure::Unreachable),
        (FakeReply::NotJson, ResolverFailure::Malformed),
    ];
    for (reply, failure) in cases {
        let (_fake, resolver) = fake(reply).await;
        assert_eq!(ask(&resolver).await, Err(failure), "{reply:?}");
        assert_eq!(
            currency(&resolver).await,
            CurrencyAnswer::Unconfirmed,
            "{reply:?}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_resolver_is_unconfirmed() {
    // A port that was listening and no longer is.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let resolver = HttpResolver::new(&ResolverConfig {
        url: format!("http://127.0.0.1:{port}"),
        ..ResolverConfig::default()
    })
    .unwrap();
    assert_eq!(ask(&resolver).await, Err(ResolverFailure::Unreachable));
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Unconfirmed);
}

#[tokio::test]
async fn an_unknown_version_is_unconfirmed() {
    for answer in Answer::ALL {
        let (_fake, resolver) = fake(FakeReply::UnknownVersion(answer)).await;
        assert_eq!(ask(&resolver).await, Err(ResolverFailure::UnknownVersion));
        assert_eq!(currency(&resolver).await, CurrencyAnswer::Unconfirmed);
    }
}

#[tokio::test]
async fn an_answer_to_another_question_is_unconfirmed() {
    for member in Member::ALL {
        let (_fake, resolver) = fake(FakeReply::OtherQuestion(Answer::Current, member)).await;
        assert_eq!(
            ask(&resolver).await,
            Err(ResolverFailure::OtherQuestion),
            "{member:?}"
        );
        assert_eq!(
            currency(&resolver).await,
            CurrencyAnswer::Unconfirmed,
            "{member:?}"
        );
    }
}

#[tokio::test]
async fn an_answer_out_of_the_format_is_unconfirmed() {
    let edits: [(&str, Edit); 9] = [
        ("an extra member", |object| {
            object.insert("ttl".to_owned(), Value::from(60));
        }),
        ("no answer", |object| {
            object.remove("answer");
        }),
        ("answer unconfirmed", |object| {
            object.insert("answer".to_owned(), Value::from("unconfirmed"));
        }),
        ("answer in capitals", |object| {
            object.insert("answer".to_owned(), Value::from("CURRENT"));
        }),
        ("answer true", |object| {
            object.insert("answer".to_owned(), Value::from(true));
        }),
        ("no version", |object| {
            object.remove("version");
        }),
        ("a numeric version", |object| {
            object.insert("version".to_owned(), Value::from(1));
        }),
        ("no epoch", |object| {
            object.remove("epoch");
        }),
        ("the epoch as a string", |object| {
            object.insert("epoch".to_owned(), Value::from("12"));
        }),
    ];
    for (name, edit) in edits {
        let (_fake, resolver) = fake(FakeReply::Edited(Answer::Current, edit)).await;
        assert_eq!(
            ask(&resolver).await,
            Err(ResolverFailure::Malformed),
            "{name}"
        );
        assert_eq!(
            currency(&resolver).await,
            CurrencyAnswer::Unconfirmed,
            "{name}"
        );
    }
}

#[tokio::test]
async fn every_question_reaches_the_resolver() {
    let (fake, resolver) = fake(FakeReply::Answer(Answer::Current)).await;
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Current);
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Current);
    assert_eq!(
        fake.received().len(),
        2,
        "the same question asked twice is sent twice"
    );

    // A turn revoked between two questions is revoked at the second.
    fake.set(FakeReply::Answer(Answer::Revoked));
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Revoked);
    fake.set(FakeReply::Answer(Answer::Current));
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Current);
    fake.set(FakeReply::Status(500));
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Unconfirmed);
    assert_eq!(fake.received().len(), 5);
}

#[tokio::test]
async fn an_answer_larger_than_the_cap_is_unconfirmed() {
    for declared in [true, false] {
        let (_fake, resolver) = fake(FakeReply::oversized(declared)).await;
        assert_eq!(
            ask(&resolver).await,
            Err(ResolverFailure::TooLarge),
            "declared {declared}"
        );
        assert_eq!(currency(&resolver).await, CurrencyAnswer::Unconfirmed);
    }
}

#[tokio::test]
async fn an_answer_at_the_cap_is_read() {
    for declared in [true, false] {
        let reply = FakeReply::Padded {
            bytes: MAX_ANSWER_BYTES,
            declared,
        };
        let (_fake, resolver) = fake(reply).await;
        assert_eq!(
            ask(&resolver).await,
            Ok(Answer::Current),
            "declared {declared}"
        );
    }
}

#[tokio::test]
async fn each_answer_failure_and_latency_is_counted() {
    let (fake, resolver) = fake(FakeReply::Answer(Answer::Current)).await;
    ask(&resolver).await.unwrap();
    ask(&resolver).await.unwrap();
    fake.set(FakeReply::Answer(Answer::Superseded));
    ask(&resolver).await.unwrap();
    for reply in [
        FakeReply::Status(500),
        FakeReply::UnknownVersion(Answer::Current),
        FakeReply::OtherQuestion(Answer::Current, Member::Epoch),
        FakeReply::NotJson,
        FakeReply::oversized(true),
        FakeReply::Close,
        FakeReply::Hang,
    ] {
        fake.set(reply);
        ask(&resolver).await.unwrap_err();
    }
    let counts: ResolverCounts = resolver.counts();
    assert_eq!(counts.answered(CurrencyAnswer::Current), 2);
    assert_eq!(counts.answered(CurrencyAnswer::Superseded), 1);
    assert_eq!(counts.answered(CurrencyAnswer::Ended), 0);
    assert_eq!(counts.answered(CurrencyAnswer::Unconfirmed), 7);
    for label in [
        "status",
        "unknown_version",
        "other_question",
        "malformed",
        "too_large",
        "unreachable",
        "timeout",
    ] {
        assert_eq!(counts.failed(label), 1, "{label}");
    }
    assert_eq!(counts.failed("token"), 0);
    assert_eq!(counts.timeouts(), 1);
    assert_eq!(counts.latency_count, 10);
    assert_eq!(counts.latency_buckets.iter().sum::<u64>(), 10);
    // The question that timed out took at least the budget, in the 1 s or 2 s bucket.
    assert_eq!(counts.latency_buckets[7] + counts.latency_buckets[8], 1);
    assert!(counts.latency_sum >= BUDGET);
}

#[test]
fn every_failure_has_its_own_label() {
    let failures = [
        ResolverFailure::Token,
        ResolverFailure::NotSent,
        ResolverFailure::Timeout,
        ResolverFailure::Unreachable,
        ResolverFailure::Status(500),
        ResolverFailure::TooLarge,
        ResolverFailure::BrokenOff,
        ResolverFailure::Malformed,
        ResolverFailure::UnknownVersion,
        ResolverFailure::OtherQuestion,
    ];
    let labels: Vec<&str> = failures.iter().map(|failure| failure.label()).collect();
    assert_eq!(labels, ResolverFailure::LABELS);
    for failure in failures {
        assert_eq!(
            gateway_otto::resolver::currency_answer(Err(failure)),
            CurrencyAnswer::Unconfirmed
        );
    }
}

#[test]
fn the_configuration_is_checked() {
    let refused = |url: &str| HttpResolver::new(&config(url)).unwrap_err();
    assert_eq!(refused("not a url"), ResolverConfigError::NotAUrl);
    assert_eq!(refused("/v1"), ResolverConfigError::NotAUrl);
    assert_eq!(refused("ftp://127.0.0.1"), ResolverConfigError::NotAUrl);
    assert_eq!(
        refused("https://user:secret@otto.example.test"),
        ResolverConfigError::UserInfo
    );
    assert_eq!(
        refused("https://otto.example.test/resolver?x=1"),
        ResolverConfigError::Query
    );
    assert_eq!(
        refused("http://otto.example.test"),
        ResolverConfigError::PlainHttp
    );
    assert_eq!(
        refused("http://10.0.0.7:8080"),
        ResolverConfigError::PlainHttp
    );
    assert_eq!(
        refused("http://localhost:8080"),
        ResolverConfigError::PlainHttp
    );
    assert_eq!(
        refused("https://otto.example.test"),
        ResolverConfigError::NoCaFile
    );
    for loopback in ["http://127.0.0.1:8080", "http://[::1]:8080/resolver/"] {
        HttpResolver::new(&config(loopback)).unwrap();
    }

    let scratch = Scratch::new("config");
    let file = scratch.write("file", "token");
    let with = |ca_file: Option<PathBuf>, token_file: Option<PathBuf>| ResolverConfig {
        url: "http://127.0.0.1:8080".to_owned(),
        ca_file,
        token_file,
    };
    assert_eq!(
        HttpResolver::new(&with(Some(file.clone()), None)).unwrap_err(),
        ResolverConfigError::CaFileForHttp
    );
    assert_eq!(
        HttpResolver::new(&with(None, Some(file.clone()))).unwrap_err(),
        ResolverConfigError::TokenForHttp
    );

    let https = |ca_file: PathBuf, token_file: Option<PathBuf>| ResolverConfig {
        url: "https://otto.example.test".to_owned(),
        ca_file: Some(ca_file),
        token_file,
    };
    let ca = TestCa::new().file(&scratch);
    let ca_fault = |path: PathBuf| match HttpResolver::new(&https(path, None)).unwrap_err() {
        ResolverConfigError::CaFile { fault, .. } => fault,
        other => panic!("{other:?}"),
    };
    assert_eq!(ca_fault(scratch.path("absent")), CaFault::Unreadable);
    assert_eq!(ca_fault(file.clone()), CaFault::NotPem);
    let key_only = scratch.write("key.pem", &KeyPair::generate().unwrap().serialize_pem());
    assert_eq!(ca_fault(key_only), CaFault::NoCertificate);

    let token_fault =
        |path: PathBuf| match HttpResolver::new(&https(ca.clone(), Some(path))).unwrap_err() {
            ResolverConfigError::TokenFile { fault, .. } => fault,
            other => panic!("{other:?}"),
        };
    assert_eq!(token_fault(scratch.path("absent")), TokenFault::Unreadable);
    assert_eq!(
        token_fault(scratch.write("empty", " \n")),
        TokenFault::Empty
    );
    assert_eq!(
        token_fault(scratch.write("two", "one two")),
        TokenFault::NotAToken
    );
    assert_eq!(
        token_fault(scratch.write("large", &"t".repeat(8 * 1024 + 1))),
        TokenFault::TooLarge
    );
    HttpResolver::new(&https(ca, Some(file))).unwrap();
}

#[test]
fn a_refusal_does_not_repeat_the_url() {
    let message = HttpResolver::new(&config("https://user:secret@otto.example.test"))
        .unwrap_err()
        .to_string();
    assert!(!message.contains("secret"), "{message}");
}

#[tokio::test]
async fn over_tls_the_token_is_sent_and_read_again_for_each_question() {
    let scratch = Scratch::new("tls");
    let ca = TestCa::new();
    let fake = FakeResolver::start_tls(
        ca.server_config(&["127.0.0.1"]),
        FakeReply::Answer(Answer::Current),
    )
    .await
    .unwrap();
    let token = scratch.write("token", "first-token\n");
    let resolver = HttpResolver::new(&ResolverConfig {
        url: fake.url(),
        ca_file: Some(ca.file(&scratch)),
        token_file: Some(token.clone()),
    })
    .unwrap();
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Current);
    std::fs::write(&token, "second-token").unwrap();
    assert_eq!(currency(&resolver).await, CurrencyAnswer::Current);
    let sent: Vec<_> = fake
        .received()
        .iter()
        .map(|request| request.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(
        sent,
        [
            Some("Bearer first-token".to_owned()),
            Some("Bearer second-token".to_owned())
        ]
    );

    // A token file that cannot be read sends nothing.
    std::fs::write(&token, "").unwrap();
    assert_eq!(ask(&resolver).await, Err(ResolverFailure::Token));
    assert_eq!(fake.received().len(), 2);
}

/// A token file whose read blocks, here a FIFO no writer has opened, does not hold the question
/// past the budget: it is unconfirmed at the budget, as a timeout, and nothing is sent (#213).
/// The read is made on the blocking pool; made on the thread asking, it would hold the budget's
/// own timer, and the question would end only when the stall did.
#[tokio::test]
async fn a_token_read_that_blocks_is_unconfirmed_at_the_budget() {
    let scratch = Scratch::new("fifo");
    let ca = TestCa::new();
    let fake = FakeResolver::start_tls(
        ca.server_config(&["127.0.0.1"]),
        FakeReply::Answer(Answer::Current),
    )
    .await
    .unwrap();
    // A file at first: the client reads it when it is built.
    let token = scratch.write("token", "first-token\n");
    let resolver = HttpResolver::new(&ResolverConfig {
        url: fake.url(),
        ca_file: Some(ca.file(&scratch)),
        token_file: Some(token.clone()),
    })
    .unwrap();
    let unblock = stall(&token);
    let started = Instant::now();
    let asked = ask(&resolver).await;
    let took = started.elapsed();
    unblock.join().unwrap();
    assert_eq!(asked, Err(ResolverFailure::Timeout), "after {took:?}");
    assert!(took >= BUDGET, "gave up after {took:?}");
    assert!(took < BUDGET + SLACK, "took {took:?}");
    assert!(fake.received().is_empty());
    assert_eq!(resolver.counts().timeouts(), 1);
}

/// Replaces the file at `path` with a FIFO no writer has opened, so reading it blocks, and
/// starts a thread that opens it for writing once a question should long have ended. That lets
/// the stalled read finish, so the runtime can shut down; with the read on the thread asking,
/// it is also what ends the question, late.
fn stall(path: &std::path::Path) -> std::thread::JoinHandle<()> {
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

#[tokio::test]
async fn over_tls_only_the_configured_ca_is_trusted() {
    let scratch = Scratch::new("other-ca");
    let fake = FakeResolver::start_tls(
        TestCa::new().server_config(&["127.0.0.1"]),
        FakeReply::Answer(Answer::Current),
    )
    .await
    .unwrap();
    let resolver = HttpResolver::new(&ResolverConfig {
        url: fake.url(),
        ca_file: Some(TestCa::new().file(&scratch)),
        token_file: None,
    })
    .unwrap();
    assert_eq!(ask(&resolver).await, Err(ResolverFailure::Unreachable));
    assert!(fake.received().is_empty());
}

fn config(url: &str) -> ResolverConfig {
    ResolverConfig {
        url: url.to_owned(),
        ..ResolverConfig::default()
    }
}

/// A directory of its own for one test's files, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "gateway-otto-resolver-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A CA made for one test: no key is checked in.
struct TestCa {
    pem: String,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self {
            pem,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A server configuration presenting a leaf for `names`, signed by this CA.
    fn server_config(&self, names: &[&str]) -> Arc<ServerConfig> {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(names)
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Arc::new(config)
    }

    fn file(&self, scratch: &Scratch) -> PathBuf {
        scratch.write("ca.pem", &self.pem)
    }
}
