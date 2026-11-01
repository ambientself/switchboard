//! The GitHub connector's first write tool, `github__create_pr`, end to end over HTTP, against
//! the fake GitHub API and the key custodian on the fake App API (#12): a draft opened with the
//! receipt's marker as its body's last line, on one token narrowed to the call's repository with
//! the tool's own permission set; each refusal and argument error before any request; the
//! comparison's refusal of automation files; the outcome of each kind of answer to the write,
//! `error` only when nothing was sent or GitHub definitely refused it and `unknown` once it may
//! have been sent; reconciliation settling an `unknown` receipt by the lookup by marker, which
//! reads with a token of its own, and not while a late write still runs; a repeated call
//! answered from its receipt; the assurance the gateway holds an approval of the tool to, at the
//! start and on a reload; and the receipt-store gate and the pod gate, which a registry with a
//! built-in `propose` tool now reaches.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use connector_github::fake::{Fault, Recorded};
use connector_github::writes::marker;
use gateway::boot::{self, Settings, Wiring};
use gateway::grants::GrantPolicyError;
use gateway::reload::ReloadError;
use gateway::start::{self, StartError, prepare};
use gateway::{AuditSection, BootError, GrantsSection, ReconcileSettings};
use gateway_core::audit::{AuditRowId, DecisionKind, Outcome};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{
    Classification, ErrorKind, InstanceName, ReasonKind, Receipt, ReceiptState, Resource,
};
use gateway_identity::SystemClock;
use gateway_otto::minter::TestMinter;
use gateway_registry::Registry;
use gateway_testkit::InMemoryAuditStore;
use github_world::{
    ACCOUNT, CREATE_PR, OTHER_ORG, Options, PERMISSIONS, TEAM_A, WRITE_ENTRY, WRITE_SURFACE, World,
    registry,
};
use serde_json::{Value, json};
use support::eventually;

/// A world with the write entry.
fn writing() -> Options {
    Options {
        writes: true,
        ..Options::default()
    }
}

async fn world() -> World {
    World::with(writing()).await
}

/// A pull request from `feature/retry` into `main` of `repo`.
fn arguments(repo: &str) -> Value {
    json!({
        "owner": ACCOUNT,
        "repo": repo,
        "title": "Add a retry to the client",
        "head": "feature/retry",
        "base": "main",
        "body": "Why it helps.",
    })
}

/// `arguments("atlas")` with `changes`; a null removes an argument.
fn changed(changes: Value) -> Value {
    let mut arguments = arguments("atlas");
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            arguments.as_object_mut().unwrap().remove(name);
        } else {
            arguments[name] = value.clone();
        }
    }
    arguments
}

/// The receipt reserved last.
fn last_receipt(world: &World) -> Receipt {
    world.store.receipts().last().cloned().expect("a receipt")
}

/// Every `POST` the fake GitHub API received.
fn posts(world: &World) -> Vec<Recorded> {
    world
        .rest
        .requests()
        .into_iter()
        .filter(|request| request.method == "POST")
        .collect()
}

/// Nothing was asked of the key custodian's App or of GitHub's API.
fn nothing_requested(world: &World) {
    assert_eq!(world.app.token_requests(), 0, "a token was asked for");
    assert!(
        world.rest.requests().is_empty(),
        "GitHub was sent {:?}",
        world.rest.requests()
    );
}

/// The custodian's record, one JSON value a line.
fn record(world: &World) -> Vec<Value> {
    world
        .record
        .text()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// `atlas` on the App's account, as a receipt's target names it.
fn atlas() -> Resource {
    Resource {
        system: "github".into(),
        kind: "repository".into(),
        identifier: format!("{ACCOUNT}/atlas"),
    }
}

/// No token the fake App issued appears in `text`.
fn holds_no_token(world: &World, text: &str) {
    for token in world.tokens() {
        assert!(!text.contains(&token), "a token appears in {text}");
    }
}

#[tokio::test]
async fn a_draft_is_opened_with_the_receipts_marker_on_one_token_for_the_calls_repository() {
    let world = world().await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    let answered = world
        .create_pr(TEAM_A, arguments("atlas"), "toolu_create_1")
        .await;
    let result = answered.ok();
    let row: AuditRowId = AuditRowId::new(
        answered.answer.result()["_meta"]["switchboard/auditRow"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        result["pr"],
        json!({
            "number": 1,
            "url": format!("https://github.example.test/{ACCOUNT}/atlas/pull/1"),
            "draft": true,
            "head": "feature/retry",
            "base": "main",
        })
    );
    assert_eq!(
        result["provenance"],
        json!({
            "tool": CREATE_PR,
            "source": "github",
            "classification": "propose",
            "trust": "untrusted-external",
        })
    );

    // The comparison, then the one write.
    let requests = world.rest.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        (requests[0].method.as_str(), requests[0].path.as_str()),
        (
            "GET",
            "/repos/example-org/atlas/compare/main...feature/retry"
        )
    );
    assert_eq!(
        (requests[1].method.as_str(), requests[1].path.as_str()),
        ("POST", "/repos/example-org/atlas/pulls")
    );
    let sent: Value = serde_json::from_str(requests[1].body.as_deref().unwrap()).unwrap();
    assert_eq!(sent["draft"], json!(true));
    assert_eq!(sent["title"], "Add a retry to the client");
    assert_eq!(
        (sent["head"].clone(), sent["base"].clone()),
        (json!("feature/retry"), json!("main"))
    );
    let body = sent["body"].as_str().unwrap();
    assert_eq!(body, format!("Why it helps.\n\n{}", marker(&row)));
    assert_eq!(body.lines().last().unwrap(), marker(&row));
    assert_eq!(world.rest.opened("atlas")[0]["draft"], json!(true));

    // One token, for the call's one repository and the tool's own set, on both requests.
    let issued = world.app.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].asked_repositories, Some(vec!["atlas".to_owned()]));
    assert_eq!(
        issued[0].asked_permissions,
        Some(BTreeMap::from([
            ("contents".to_owned(), "read".to_owned()),
            ("pull_requests".to_owned(), "write".to_owned()),
        ]))
    );
    assert!(
        requests
            .iter()
            .all(|request| request.token.as_deref() == Some(issued[0].token.as_str()))
    );
    let lines = record(&world);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["team"], "team-a");
    assert_eq!(lines[0]["tool"], CREATE_PR);
    assert_eq!(
        lines[0]["repositories"],
        json!([format!("{ACCOUNT}/atlas")])
    );
    assert_eq!(
        lines[0]["permissions"],
        json!({"contents": "read", "pull_requests": "write"})
    );

    // The row and the receipt.
    world.settle().await;
    assert_eq!(world.last_outcome(CREATE_PR), Outcome::Ok);
    let receipt = last_receipt(&world);
    assert_eq!(receipt.row, row);
    assert_eq!(receipt.state, ReceiptState::Completed);
    assert_eq!(
        receipt
            .reference
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("pull/1")
    );
    assert_eq!(receipt.target, Some(atlas()));
    assert_eq!(receipt.team, Some("team-a".into()));
    holds_no_token(&world, &answered.raw);
    holds_no_token(&world, &format!("{:?}", world.store.rows()));
}

#[tokio::test]
async fn a_call_with_no_key_is_denied_and_the_tool_is_still_listed() {
    let world = world().await;
    let denied = world
        .call_on(WRITE_SURFACE, TEAM_A, CREATE_PR, arguments("atlas"))
        .await
        .refusal();
    assert!(!denied.is_empty());
    let row = world.last_row(CREATE_PR);
    assert_eq!(
        (row.decision, row.reason),
        (DecisionKind::Deny, Some(ReasonKind::KeyMissing))
    );
    nothing_requested(&world);
    assert!(world.store.receipts().is_empty());
    assert!(
        world
            .listed(WRITE_SURFACE, TEAM_A)
            .await
            .contains(&CREATE_PR.to_owned())
    );
}

#[tokio::test]
async fn another_organization_is_refused_with_otto_s_sentence_before_any_request() {
    let world = world().await;
    let mut other = arguments("elsewhere");
    other["owner"] = json!(OTHER_ORG);
    let refusal = world
        .create_pr(TEAM_A, other, "toolu_other")
        .await
        .refusal();
    assert_eq!(
        refusal,
        "owner \"other-org\" is not this gateway's configured org \"example-org\""
    );
    world.settle().await;
    assert_eq!(
        world.last_outcome(CREATE_PR),
        Outcome::Refused { sentence: refusal }
    );
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    nothing_requested(&world);
}

#[tokio::test]
async fn a_repository_outside_the_teams_limit_is_denied_by_check_6() {
    let world = world().await;
    world
        .create_pr(TEAM_A, arguments("cosmos"), "toolu_cosmos")
        .await
        .refusal();
    let row = world.last_row(CREATE_PR);
    assert_eq!(
        (row.decision, row.reason),
        (DecisionKind::Deny, Some(ReasonKind::ResourceOutsideLimit))
    );
    nothing_requested(&world);
}

#[tokio::test]
async fn each_malformed_argument_is_invalid_arguments_and_nothing_is_sent() {
    let world = world().await;
    let long_body = "b".repeat(connector_github::create_pr::MAX_CALLER_BODY_CHARS + 1);
    let long_title = "t".repeat(connector_github::create_pr::MAX_TITLE_CHARS + 1);
    for (at, changes) in [
        json!({"title": ""}),
        json!({"title": long_title}),
        json!({"title": "a\u{1b}[31mred"}),
        json!({"head": "feature..retry"}),
        json!({"head": "-x"}),
        json!({"base": "main:other"}),
        json!({"base": "main.lock"}),
        json!({"body": long_body}),
        json!({"draft": false}),
        json!({"head": null}),
    ]
    .into_iter()
    .enumerate()
    {
        let message = world
            .create_pr(TEAM_A, changed(changes.clone()), &format!("toolu_bad_{at}"))
            .await
            .tool_error();
        assert!(!message.is_empty());
        world.settle().await;
        assert_eq!(
            world.last_outcome(CREATE_PR),
            Outcome::Error {
                error_kind: ErrorKind::InvalidArguments
            },
            "{changes}"
        );
    }
    nothing_requested(&world);
}

#[tokio::test]
async fn command_text_and_the_markers_text_are_refused_before_any_request() {
    let world = world().await;
    for (at, (changes, said)) in [
        (
            json!({"title": "atlantis apply"}),
            "the title begins with \"atlantis\"",
        ),
        (
            json!({"body": "  Atlantis plan -p prod"}),
            "the body begins with \"atlantis\"",
        ),
        (
            json!({"body": "Done.\n<!-- Switchboard-Receipt: 0190f5a2 -->"}),
            "the body holds \"switchboard-receipt\"",
        ),
        (json!({"title": "switchboard-receipt"}), "the title holds"),
    ]
    .into_iter()
    .enumerate()
    {
        let refusal = world
            .create_pr(TEAM_A, changed(changes), &format!("toolu_command_{at}"))
            .await
            .refusal();
        assert!(refusal.starts_with(said), "{refusal}");
        world.settle().await;
        assert_eq!(
            world.last_outcome(CREATE_PR),
            Outcome::Refused { sentence: refusal }
        );
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    }
    nothing_requested(&world);
}

#[tokio::test]
async fn a_comparison_touching_automation_or_cut_short_is_refused_and_nothing_is_written() {
    let world = world().await;
    let many: Vec<String> = (0..connector_github::create_pr::MAX_COMPARED_FILES)
        .map(|at| format!("src/f{at}.rs"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    for (at, (files, said)) in [
        (
            vec!["src/a.rs", ".github/workflows/x.yml"],
            "carry their own token permission",
        ),
        (
            vec!["infra/Atlantis.yml"],
            "atlantis.yaml selects Atlantis project names",
        ),
        (many, "GitHub cuts the list at 300"),
    ]
    .into_iter()
    .enumerate()
    {
        world.rest.compare_files("atlas", &files);
        let refusal = world
            .create_pr(TEAM_A, arguments("atlas"), &format!("toolu_compare_{at}"))
            .await
            .refusal();
        assert!(refusal.contains(said), "{refusal}");
        world.settle().await;
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    }
    assert!(posts(&world).is_empty());
    assert!(world.rest.opened("atlas").is_empty());

    // A comparison GitHub cannot make is an error, not unknown: nothing was written.
    let message = world
        .create_pr(TEAM_A, arguments("borealis"), "toolu_compare_404")
        .await
        .tool_error();
    assert!(message.contains("HTTP 404"), "{message}");
    world.settle().await;
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    assert!(posts(&world).is_empty());
}

#[tokio::test]
async fn a_custodian_that_refuses_or_is_not_there_is_an_error_and_nothing_is_written() {
    for (options, kind) in [
        (
            Options {
                custodian_revision: Some("r0"),
                ..writing()
            },
            ErrorKind::CustodianRefusal,
        ),
        (
            Options {
                custodian: false,
                ..writing()
            },
            ErrorKind::Other,
        ),
    ] {
        let world = World::with(options).await;
        world.rest.compare_files("atlas", &["src/client.rs"]);
        world
            .create_pr(TEAM_A, arguments("atlas"), "toolu_custodian")
            .await
            .tool_error();
        world.settle().await;
        assert_eq!(
            world.last_outcome(CREATE_PR),
            Outcome::Error { error_kind: kind }
        );
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
        assert!(world.rest.requests().is_empty());
    }
}

#[tokio::test]
async fn a_write_github_definitely_refused_is_an_error_and_never_carries_a_credential() {
    let world = world().await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    for (status, kind) in [
        (403, ErrorKind::VendorRefusal),
        (404, ErrorKind::Other),
        (422, ErrorKind::Other),
    ] {
        world.rest.fault_next_write(Fault::Status(status));
        let answered = world
            .create_pr(
                TEAM_A,
                arguments("atlas"),
                &format!("toolu_refused_{status}"),
            )
            .await;
        let message = answered.tool_error();
        assert!(message.contains(&format!("HTTP {status}")), "{message}");
        holds_no_token(&world, &answered.raw);
        world.settle().await;
        assert_eq!(
            world.last_outcome(CREATE_PR),
            Outcome::Error { error_kind: kind }
        );
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    }
    assert_eq!(posts(&world).len(), 3);
    assert!(world.rest.opened("atlas").is_empty());
    holds_no_token(&world, &format!("{:?}", world.store.rows()));
}

/// Each answer that leaves the write's effect unknown is `unknown`, whether or not GitHub
/// applied it: a 502 after applying, a connection closed with no answer, a 201 broken off
/// before its body ends, a 201 whose body is not JSON, and a 502 with nothing applied. One
/// reconciliation pass settles the four GitHub applied, finding each by its marker, and leaves
/// the fifth `unknown`: not found, which is never authoritative, and, with one attempt, handed
/// to a person. The lookups read with tokens of their own, for the
/// receipt's team, its repository and `pull_requests: read`, and only read.
#[tokio::test]
async fn a_write_that_may_have_been_sent_is_unknown_and_reconciliation_settles_what_was_made() {
    let world = World::with(Options {
        reconcile: ReconcileSettings {
            attempts: 1,
            ..ReconcileSettings::default()
        },
        ..writing()
    })
    .await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    let mut receipts = Vec::new();
    for (at, fault) in [
        Fault::AppliedThen(502),
        Fault::AppliedThenClosed,
        Fault::AppliedThenBrokenOff,
        Fault::AppliedThenNotJson,
        Fault::Status(502),
    ]
    .into_iter()
    .enumerate()
    {
        world.rest.fault_next_write(fault);
        let message = world
            .create_pr(TEAM_A, arguments("atlas"), &format!("toolu_unknown_{at}"))
            .await
            .tool_error();
        assert!(!message.is_empty(), "{fault:?}");
        world.settle().await;
        assert_eq!(world.last_outcome(CREATE_PR), Outcome::Unknown, "{fault:?}");
        let receipt = last_receipt(&world);
        assert_eq!(receipt.state, ReceiptState::Unknown, "{fault:?}");
        receipts.push(receipt);
    }
    assert_eq!(world.rest.opened("atlas").len(), 4, "four were applied");

    let requests_before = world.rest.requests().len();
    let tokens_before = world.app.issued().len();
    let record_before = record(&world).len();
    let report = world.reconciler.pass().await;
    assert_eq!(
        (
            report.claimed,
            report.looked_up,
            report.settled,
            report.handed_to_person
        ),
        (5, 5, 4, 1),
        "{report:?}"
    );
    for (receipt, number) in receipts.iter().take(4).zip([1, 2, 3, 4]) {
        let settled = world.store.receipt(&receipt.row).unwrap();
        assert_eq!(
            (
                settled.state,
                &settled.established_by,
                settled
                    .reference
                    .as_ref()
                    .map(|reference| reference.as_str().to_owned())
            ),
            (
                ReceiptState::Completed,
                &EstablishedBy::Reconciliation,
                Some(format!("pull/{number}"))
            )
        );
    }
    let left = world.store.receipt(&receipts[4].row).unwrap();
    assert_eq!(left.state, ReceiptState::Unknown);
    assert!(left.handed_to_person.is_some());
    assert_eq!(
        left.lookups.last().map(|lookup| lookup.answer.clone()),
        Some(gateway_core::LookupAnswer::NotFound {
            authoritative: false
        })
    );

    // The lookups only read, each with a token of its own.
    let looked = &world.rest.requests()[requests_before..];
    assert_eq!(looked.len(), 5, "{looked:?}");
    for request in looked {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/repos/example-org/atlas/pulls");
        assert_eq!(
            request.query,
            "state=all&sort=updated&direction=desc&per_page=100&page=1"
        );
    }
    let issued = &world.app.issued()[tokens_before..];
    assert_eq!(issued.len(), 5);
    for token in issued {
        assert_eq!(token.asked_repositories, Some(vec!["atlas".to_owned()]));
        assert_eq!(
            token.asked_permissions,
            Some(BTreeMap::from([(
                "pull_requests".to_owned(),
                "read".to_owned()
            )]))
        );
    }
    for line in &record(&world)[record_before..] {
        assert_eq!(line["team"], "team-a", "{line}");
        assert_eq!(line["tool"], CREATE_PR, "{line}");
        assert_eq!(line["repositories"], json!([format!("{ACCOUNT}/atlas")]));
        assert_eq!(line["permissions"], json!({"pull_requests": "read"}));
        assert_eq!(line["revision"], "r1");
    }
    assert_eq!(posts(&world).len(), 5, "nothing was sent again");
}

/// A write still on its way at the in-process deadline is answered `unknown`, and runs on: the
/// pull request is still opened. Its receipt is held while it runs and for a full lease after,
/// and only then does a pass look it up and settle it `completed`.
#[tokio::test]
async fn a_late_write_is_unknown_and_settled_only_after_it_ends() {
    let lease = Duration::from_millis(2000);
    let world = World::with(Options {
        bounds: "[connectors.github-write]\ndeadline_seconds = 1\n",
        reconcile: ReconcileSettings {
            interval: Duration::from_secs(60),
            lease,
            attempts: 3,
        },
        ..writing()
    })
    .await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    world
        .rest
        .fault_next_write(Fault::Late(Duration::from_millis(2500)));
    world
        .create_pr(TEAM_A, arguments("atlas"), "toolu_late")
        .await
        .tool_error();
    world.settle().await;
    assert_eq!(world.last_outcome(CREATE_PR), Outcome::Unknown);
    let receipt = last_receipt(&world);
    assert_eq!(receipt.state, ReceiptState::Unknown);
    assert!(world.rest.opened("atlas").is_empty(), "still on its way");
    assert_eq!(
        world.reconciler.pass().await.claimed,
        0,
        "held while it runs"
    );

    eventually("the late write ran to its end", || {
        world.rest.opened("atlas").len() == 1
    })
    .await;
    let ended = std::time::SystemTime::now();
    eventually("the receipt was held once more as the write ended", || {
        world
            .store
            .lease_until(&receipt.row)
            .is_some_and(|until| until + Duration::from_millis(100) >= ended + lease)
    })
    .await;
    assert_eq!(
        world.reconciler.pass().await.claimed,
        0,
        "held a lease after"
    );

    tokio::time::sleep(lease + Duration::from_millis(300)).await;
    let report = world.reconciler.pass().await;
    assert_eq!(
        (report.claimed, report.looked_up, report.settled),
        (1, 1, 1),
        "{report:?}"
    );
    let settled = world.store.receipt(&receipt.row).unwrap();
    assert_eq!(settled.state, ReceiptState::Completed);
    assert_eq!(
        settled
            .reference
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("pull/1")
    );
}

#[tokio::test]
async fn the_same_call_under_the_same_key_is_a_duplicate_and_is_not_sent_again() {
    let world = world().await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    world
        .create_pr(TEAM_A, arguments("atlas"), "toolu_twice")
        .await
        .ok();
    let receipt = last_receipt(&world);
    let again = world
        .create_pr(TEAM_A, arguments("atlas"), "toolu_twice")
        .await;
    assert_eq!(
        again.answer.result()["isError"],
        json!(false),
        "{}",
        again.raw
    );
    world.settle().await;
    assert_eq!(
        world.last_outcome(CREATE_PR),
        Outcome::Duplicate {
            receipt: receipt.row.clone()
        }
    );
    assert_eq!(posts(&world).len(), 1);
    assert_eq!(world.rest.opened("atlas").len(), 1);
}

#[tokio::test]
async fn a_write_that_could_not_connect_is_an_error_and_nothing_was_made() {
    let world = world().await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    world.rest.close_after_next_compare();
    let message = world
        .create_pr(TEAM_A, arguments("atlas"), "toolu_refused_connection")
        .await
        .tool_error();
    assert!(message.contains("could not be reached"), "{message}");
    world.settle().await;
    assert_eq!(
        world.last_outcome(CREATE_PR),
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    assert!(posts(&world).is_empty());
}

/// `text`, a registry file, with the approval of `github__create_pr` changed by `change`.
fn approving(text: &str, change: impl FnOnce(&mut toml::Table)) -> String {
    let mut table: toml::Table = toml::from_str(text).unwrap();
    let approval = table
        .get_mut("built_in_tools")
        .and_then(toml::Value::as_array_mut)
        .unwrap()
        .iter_mut()
        .find(|approval| approval.get("name").and_then(toml::Value::as_str) == Some(CREATE_PR))
        .and_then(toml::Value::as_table_mut)
        .unwrap();
    change(approval);
    toml::to_string(&table).unwrap()
}

/// A change to an approval.
type Change = fn(&mut toml::Table);

/// `github__create_pr` approved as a read, which declares no settlement.
fn as_a_read(approval: &mut toml::Table) {
    approval.insert("classification".into(), "read".into());
    approval.remove("settlement");
}

/// `github__create_pr` approved as reading its repository from `repo` alone, not qualified by
/// `owner`.
fn unqualified(approval: &mut toml::Table) {
    let resources: toml::Table = toml::from_str(
        r#"r = { from_arguments = [{ from_argument = "repo", system = "github", kind = "repository" }] }"#,
    )
    .unwrap();
    approval.insert("resources".into(), resources["r"].clone());
}

/// The connector states `github__create_pr` is `propose`, declared from its `owner` and
/// `repo`: an approval of it as a read, or as reading its repository from `repo` alone,
/// refuses the start, and a reload to either is refused while the policy served keeps serving.
#[tokio::test]
async fn an_approval_of_create_pr_declaring_otherwise_is_refused_at_the_start_and_on_a_reload() {
    let changes: [(Change, &str); 2] = [
        (
            as_a_read,
            "is approved as `read`, and its connector classifies it `propose`",
        ),
        (
            unqualified,
            "is approved as `from_arguments`, reading github repository from `repo`, and its \
             connector states `from_arguments`, reading github repository from `owner`/`repo`",
        ),
    ];
    for (change, said) in changes {
        let world = world().await;
        let path = world.dir.join("registry.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, approving(&text, change)).unwrap();
        let deployment =
            gateway::Deployment::load(&world.dir.join("gateway.toml"), |_| None).unwrap();
        match prepare(
            deployment,
            InstanceName::new("github-test"),
            Arc::new(SystemClock),
        )
        .await
        {
            Err(StartError::Boot(refused @ BootError::BuiltInAssuranceDiffers { .. })) => {
                let sentence = refused.to_string();
                assert!(sentence.contains(CREATE_PR), "{sentence}");
                assert!(sentence.contains(WRITE_ENTRY), "{sentence}");
                assert!(sentence.contains(said), "{sentence}");
            }
            other => panic!("{said}: {other:?}"),
        }

        let reloaded = registry("r2", "limit", PERMISSIONS, true);
        let refused = Registry::from_toml_str(&approving(&reloaded, change)).unwrap();
        match world.reloader.apply(&refused) {
            Err(ReloadError::Boot(BootError::BuiltInAssuranceDiffers {
                tool, connector, ..
            })) => {
                assert_eq!(tool.as_str(), CREATE_PR);
                assert_eq!(connector.as_str(), WRITE_ENTRY);
            }
            other => panic!("{said}: {other:?}"),
        }
        let agreeing = Registry::from_toml_str(&reloaded).unwrap();
        assert_eq!(world.reloader.apply(&agreeing).unwrap().as_str(), "r2");
    }
}

/// The settings and wiring `World::with` checks a registry with, as a release build would be
/// given them.
fn parts(world: &World, registry: &Registry, grants: GrantsSection) -> (Settings, Wiring) {
    let deployment = &world.deployment;
    let settings = Settings {
        deployment: deployment.deployment.clone(),
        identity: deployment.identity.clone(),
        audit: AuditSection {
            disabled: false,
            postgres: false,
        },
        grants,
        http: deployment.http.clone(),
        max_age: None,
        read_at: Instant::now(),
    };
    let wiring = start::wire_github(
        registry,
        deployment.github.as_ref(),
        &deployment.connectors,
        Wiring::new(Arc::new(SystemClock)).audit_store(Arc::new(InMemoryAuditStore::new())),
    )
    .unwrap();
    (settings, wiring)
}

/// A registry with a built-in `propose` tool reaches the receipt-store gate: a release build
/// with no receipt store refuses it, naming the tool. Before `github__create_pr`, only a
/// development build's tests could reach it.
#[tokio::test]
async fn a_built_in_proposal_with_no_receipt_store_is_refused_by_the_receipt_store_gate() {
    let world = world().await;
    let registry = Registry::from_toml_str(&registry("r1", "limit", PERMISSIONS, true)).unwrap();
    let (settings, wiring) = parts(&world, &registry, GrantsSection::default());
    match boot::as_release::check_registry(settings, registry, wiring) {
        Err(BootError::NoReceiptStore {
            tool,
            classification,
        }) => {
            assert_eq!(tool.as_str(), CREATE_PR);
            assert_eq!(classification, Classification::Propose);
        }
        other => panic!("{:?}", other.err()),
    }
}

/// A registry with a built-in `propose` tool, served to a profile that requires a delegation,
/// reaches the pod gate: a grant issuer that does not require `pod` is refused.
#[tokio::test]
async fn a_built_in_proposal_under_a_delegation_profile_is_held_to_the_pod_gate() {
    let world = world().await;
    let text = registry("r1", "limit", PERMISSIONS, true)
        .replace("requires_delegation = false", "requires_delegation = true");
    let registry = Registry::from_toml_str(&text).unwrap();
    let grants: GrantsSection = serde_json::from_value(json!({"enforce": {
        "issuers": [{
            "name": "otto-test",
            "current_key": TestMinter::generate().public_key_pem(),
            "require_pod": false,
            "require_egress": false,
        }],
        "tool_mapping": {"github_create_pr": CREATE_PR},
    }}))
    .unwrap();
    let (settings, wiring) = parts(&world, &registry, grants);
    match boot::check_registry(settings, registry, wiring).err() {
        Some(BootError::GrantPolicy(policy)) => match *policy {
            GrantPolicyError::PodNotRequired {
                tool, grant_issuer, ..
            } => {
                assert_eq!(tool.as_str(), CREATE_PR);
                assert_eq!(grant_issuer, "otto-test");
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}
