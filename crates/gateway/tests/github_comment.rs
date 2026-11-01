//! `github__pr_comment` end to end over HTTP, against the fake GitHub API, the key custodian on
//! the fake App API, a test minter's turn grants and Otto's fake resolver (#12): served only
//! under a profile whose own exception names it, and only while the resolver says the turn is
//! current; each refusal and argument error before any token is asked for; a comment posted
//! once, with the receipt's marker appended, on one token narrowed to the call's repository with
//! `pull_requests: write` alone; the outcome of each kind of answer, `error` only when nothing
//! was sent or GitHub definitely refused it, `unknown` once the comment may have been posted,
//! and never a second post; a repeated key answered from its receipt; and reconciliation
//! settling an `unknown` receipt by the comment carrying the marker, and nothing else.
//!
//! The registry here is a test's: no shipped registry or example lists the exception, which is
//! not in force until its register entry is signed (decision 0011, section 9).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use connector_github::fake::{Fault, Recorded};
use connector_github::writes::marker;
use gateway::ReconcileSettings;
use gateway_core::audit::{AuditRowId, DecisionKind, Outcome};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{
    CurrencyAnswer, ErrorKind, LookupAnswer, ReasonKind, Receipt, ReceiptState, Resource,
};
use gateway_otto::fake::FakeReply;
use gateway_otto::resolver::Answer as Currency;
use gateway_testkit::StoreBudgets;
use github_world::{ACCOUNT, EXCEPTION, OTHER_ORG, Options, PR_COMMENT, TEAM_A, World};
use serde_json::{Value, json};
use support::eventually;

/// A world with the comment entry, under a profile whose exception names the tool.
fn commenting() -> Options {
    Options {
        comments: true,
        exception: true,
        ..Options::default()
    }
}

/// A world with the comment entry and pull request 7 of atlas and borealis.
async fn world_with(options: Options) -> World {
    let world = World::with(options).await;
    for repo in ["atlas", "borealis"] {
        world.rest.pull(
            repo,
            7,
            json!({"number": 7, "title": "Add a retry", "state": "open", "draft": true, "body": "Why."}),
        );
    }
    world
}

async fn world() -> World {
    world_with(commenting()).await
}

/// Budgets that put a call row's deadline a little over a second past its call deadline, so a
/// test in real time sees it pass. No receipt is due before its row's deadline.
const SHORT_BUDGETS: StoreBudgets = StoreBudgets {
    begin: Duration::from_millis(100),
    answer: Duration::from_millis(100),
    finish_deadline: Duration::from_secs(1),
};

/// A comment on pull request 7 of `repo`.
fn arguments(repo: &str) -> Value {
    json!({"owner": ACCOUNT, "repo": repo, "number": 7, "body": "Looks good to me."})
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

/// No token the fake App issued appears in `text`.
fn holds_no_token(world: &World, text: &str) {
    for token in world.tokens() {
        assert!(!text.contains(&token), "a token appears in {text}");
    }
}

/// The audit row an answer names.
fn row_of(answered: &github_world::Answered) -> AuditRowId {
    AuditRowId::new(
        answered.answer.result()["_meta"]["switchboard/auditRow"]
            .as_str()
            .unwrap(),
    )
}

#[tokio::test]
async fn a_current_turn_s_comment_is_posted_once_with_the_marker_on_a_token_for_one_repository() {
    let world = world().await;
    let answered = world
        .comment(TEAM_A, arguments("atlas"), "toolu_comment_1")
        .await;
    let result = answered.ok();
    let row = row_of(&answered);
    let posted = world.rest.posted("atlas");
    assert_eq!(posted.len(), 1);
    let id = posted[0]["id"].as_u64().unwrap();
    assert_eq!(
        result["comment"],
        json!({"id": id, "url": posted[0]["html_url"]})
    );
    assert_eq!(
        result["provenance"],
        json!({
            "tool": PR_COMMENT,
            "source": "github",
            "classification": "write",
            "trust": "untrusted-external",
        })
    );

    // The pull request, then the one write, its body the caller's with the marker after it.
    let requests = world.rest.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(
        (requests[0].method.as_str(), requests[0].path.as_str()),
        ("GET", "/repos/example-org/atlas/pulls/7")
    );
    assert_eq!(
        (requests[1].method.as_str(), requests[1].path.as_str()),
        ("POST", "/repos/example-org/atlas/issues/7/comments")
    );
    let sent: Value = serde_json::from_str(requests[1].body.as_deref().unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({"body": format!("Looks good to me.\n\n{}", marker(&row))})
    );
    assert!(sent["body"].as_str().unwrap().starts_with("Looks good"));

    // One token, for the call's one repository and pull_requests: write alone, on both.
    let issued = world.app.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].asked_repositories, Some(vec!["atlas".to_owned()]));
    assert_eq!(
        issued[0].asked_permissions,
        Some(BTreeMap::from([(
            "pull_requests".to_owned(),
            "write".to_owned()
        )]))
    );
    assert!(
        requests
            .iter()
            .all(|request| request.token.as_deref() == Some(issued[0].token.as_str()))
    );
    let lines = record(&world);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["team"], "team-a");
    assert_eq!(lines[0]["tool"], PR_COMMENT);
    assert_eq!(
        lines[0]["repositories"],
        json!([format!("{ACCOUNT}/atlas")])
    );
    assert_eq!(lines[0]["permissions"], json!({"pull_requests": "write"}));
    assert_eq!(lines[0]["revision"], "r1");

    // The resolver was asked once; the row records the exception and the answer.
    assert_eq!(world.asked(), 1);
    world.settle().await;
    let audit = world.last_row(PR_COMMENT);
    assert_eq!(audit.decision, DecisionKind::Allow);
    assert_eq!(
        audit
            .allowed_by_exception
            .as_ref()
            .map(|name| name.as_str()),
        Some(EXCEPTION)
    );
    assert_eq!(audit.currency, Some(CurrencyAnswer::Current));
    assert_eq!(world.last_outcome(PR_COMMENT), Outcome::Ok);
    let receipt = last_receipt(&world);
    assert_eq!(receipt.row, row);
    assert_eq!(receipt.state, ReceiptState::Completed);
    assert_eq!(
        receipt
            .reference
            .as_ref()
            .map(|reference| reference.as_str().to_owned()),
        Some(format!("comment/{id}"))
    );
    assert_eq!(
        receipt.target,
        Some(Resource {
            system: "github".into(),
            kind: "repository".into(),
            identifier: format!("{ACCOUNT}/atlas"),
        })
    );
    holds_no_token(&world, &answered.raw);
    holds_no_token(&world, &format!("{:?}", world.store.rows()));
}

/// Under a profile whose own list of exceptions does not name the tool, a call is denied at
/// check 5 with a grant and a key, though the turn is current: no token, no request, no
/// receipt. (The currency question is asked before the decision, of any tool that is not a
/// read, so it is asked here too.)
#[tokio::test]
async fn without_the_profile_s_exception_the_tool_is_denied_at_check_5() {
    let world = world_with(Options {
        exception: false,
        ..commenting()
    })
    .await;
    let denied = world
        .comment(TEAM_A, arguments("atlas"), "toolu_unexcepted")
        .await
        .refusal();
    assert!(!denied.is_empty());
    let row = world.last_row(PR_COMMENT);
    assert_eq!(
        (row.decision, row.reason),
        (
            DecisionKind::Deny,
            Some(ReasonKind::ClassificationNotPermitted)
        )
    );
    assert_eq!(row.allowed_by_exception, None);
    nothing_requested(&world);
    assert!(world.store.receipts().is_empty());
}

/// Every answer but `current` denies the call as not current, and a failed answer or none within
/// the budget as unconfirmed: asked once each time, nothing asked of the custodian or GitHub.
#[tokio::test]
async fn a_turn_that_is_not_current_or_unanswered_gets_nothing_posted() {
    let world = world().await;
    let resolver = world.resolver.as_ref().unwrap();
    let replies = [
        (
            FakeReply::Answer(Currency::Superseded),
            ReasonKind::NotCurrent,
        ),
        (FakeReply::Answer(Currency::Ended), ReasonKind::NotCurrent),
        (FakeReply::Answer(Currency::Revoked), ReasonKind::NotCurrent),
        (FakeReply::Status(503), ReasonKind::CurrencyUnconfirmed),
        (FakeReply::Hang, ReasonKind::CurrencyUnconfirmed),
    ];
    for (at, (reply, reason)) in replies.into_iter().enumerate() {
        resolver.set(reply);
        let before = world.asked();
        world
            .comment(TEAM_A, arguments("atlas"), &format!("toolu_stale_{at}"))
            .await
            .refusal();
        let row = world.last_row(PR_COMMENT);
        assert_eq!(
            (row.decision, row.reason),
            (DecisionKind::Deny, Some(reason)),
            "{at}"
        );
        assert_eq!(row.allowed_by_exception, None);
        assert_eq!(world.asked(), before + 1);
    }
    nothing_requested(&world);
}

#[tokio::test]
async fn another_organization_and_each_atlantis_command_are_refused_before_any_token() {
    let world = world().await;
    let mut other = arguments("elsewhere");
    other["owner"] = json!(OTHER_ORG);
    let refusal = world.comment(TEAM_A, other, "toolu_other").await.refusal();
    assert_eq!(
        refusal,
        "owner \"other-org\" is not this gateway's configured org \"example-org\""
    );
    world.settle().await;
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);

    for (at, body) in [
        "atlantis apply",
        "Atlantis apply",
        "ATLANTIS plan",
        "   atlantis plan",
        "\n\n\tatlantis unlock",
        "@atlantis plan",
        "@Atlantis apply -p prod",
        "/atlantis apply",
        "\u{200B}atlantis apply",
        "\u{FEFF}\u{2060} @atlantis plan",
        "atlantis",
    ]
    .into_iter()
    .enumerate()
    {
        let refusal = world
            .comment(
                TEAM_A,
                changed(json!({ "body": body })),
                &format!("toolu_atlantis_{at}"),
            )
            .await
            .refusal();
        assert!(refusal.contains("Atlantis"), "{body:?}: {refusal}");
        world.settle().await;
        assert_eq!(
            world.last_outcome(PR_COMMENT),
            Outcome::Refused { sentence: refusal },
            "{body:?}"
        );
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    }
    let refusal = world
        .comment(
            TEAM_A,
            changed(json!({"body": "Done.\n<!-- switchboard-receipt: 0190f5a2 -->"})),
            "toolu_marker",
        )
        .await
        .refusal();
    assert!(refusal.contains("switchboard-receipt"), "{refusal}");
    nothing_requested(&world);

    // Atlantis named later in the text is not a command.
    world
        .comment(
            TEAM_A,
            changed(json!({"body": "please run atlantis plan later"})),
            "toolu_later",
        )
        .await
        .ok();
    assert_eq!(posts(&world).len(), 1);
}

#[tokio::test]
async fn a_malformed_argument_is_invalid_arguments_and_nothing_is_sent() {
    let world = world().await;
    for (at, changes) in [
        json!({"body": ""}),
        json!({"body": "   "}),
        json!({"number": null}),
        json!({"number": 0}),
        json!({"edit": true}),
    ]
    .into_iter()
    .enumerate()
    {
        world
            .comment(TEAM_A, changed(changes.clone()), &format!("toolu_bad_{at}"))
            .await
            .tool_error();
        world.settle().await;
        assert_eq!(
            world.last_outcome(PR_COMMENT),
            Outcome::Error {
                error_kind: ErrorKind::InvalidArguments
            },
            "{changes}"
        );
        assert_eq!(
            last_receipt(&world).state,
            ReceiptState::NotPerformed,
            "{changes}"
        );
    }
    nothing_requested(&world);
}

#[tokio::test]
async fn a_repository_outside_the_teams_limit_is_denied_at_check_6() {
    let world = world().await;
    world
        .comment(TEAM_A, arguments("cosmos"), "toolu_cosmos")
        .await
        .refusal();
    let row = world.last_row(PR_COMMENT);
    assert_eq!(
        (row.decision, row.reason),
        (DecisionKind::Deny, Some(ReasonKind::ResourceOutsideLimit))
    );
    nothing_requested(&world);
}

/// A number that is no pull request gets nothing posted, and GitHub's definite refusal of the
/// post is `error`: the receipt is `not_performed`, and nothing quotes GitHub or the token.
#[tokio::test]
async fn a_missing_pull_request_or_a_refused_post_is_an_error_and_nothing_was_made() {
    let world = world().await;
    let message = world
        .comment(TEAM_A, changed(json!({"number": 8})), "toolu_no_pull")
        .await
        .tool_error();
    assert!(message.contains("no pull request #8"), "{message}");
    world.settle().await;
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    assert!(posts(&world).is_empty());

    for (status, kind) in [
        (403, ErrorKind::VendorRefusal),
        (404, ErrorKind::Other),
        (422, ErrorKind::Other),
    ] {
        world.rest.fault_next_write(Fault::Status(status));
        let answered = world
            .comment(
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
            world.last_outcome(PR_COMMENT),
            Outcome::Error { error_kind: kind }
        );
        assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    }
    assert_eq!(posts(&world).len(), 3);
    assert!(world.rest.posted("atlas").is_empty());
    holds_no_token(&world, &format!("{:?}", world.store.rows()));
}

#[tokio::test]
async fn a_custodian_that_is_not_there_is_an_error_and_nothing_is_sent() {
    let world = world_with(Options {
        custodian: false,
        ..commenting()
    })
    .await;
    world
        .comment(TEAM_A, arguments("atlas"), "toolu_custodian")
        .await
        .tool_error();
    world.settle().await;
    assert_eq!(
        world.last_outcome(PR_COMMENT),
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(last_receipt(&world).state, ReceiptState::NotPerformed);
    assert!(world.rest.requests().is_empty());
}

/// A 500 with nothing posted, a 500 after posting and a post that breaks off are each
/// `unknown`, posted once and never again. One reconciliation pass once their rows' deadlines
/// have passed settles the two whose comments were made, each by its marker among another
/// person's comment, and leaves the first `unknown`, not found, which is never authoritative,
/// handed to a person. The lookups read the repository's comments with tokens of their own, for
/// the receipt's team, its repository and `pull_requests: read`, and only read.
#[tokio::test]
async fn a_comment_that_may_have_been_posted_is_unknown_and_reconciliation_settles_by_the_marker() {
    let world = world_with(Options {
        reconcile: ReconcileSettings {
            attempts: 1,
            ..ReconcileSettings::default()
        },
        budgets: SHORT_BUDGETS,
        ..commenting()
    })
    .await;
    world
        .rest
        .comment_elsewhere("atlas", 7, "An earlier review, by a person.");
    let mut receipts = Vec::new();
    for (at, fault) in [
        Fault::Status(500),
        Fault::AppliedThen(500),
        Fault::AppliedThenBrokenOff,
    ]
    .into_iter()
    .enumerate()
    {
        world.rest.fault_next_write(fault);
        let posts_before = posts(&world).len();
        world
            .comment(TEAM_A, arguments("atlas"), &format!("toolu_unknown_{at}"))
            .await
            .tool_error();
        assert_eq!(posts(&world).len(), posts_before + 1, "{fault:?}");
        world.settle().await;
        assert_eq!(
            world.last_outcome(PR_COMMENT),
            Outcome::Unknown,
            "{fault:?}"
        );
        let receipt = last_receipt(&world);
        assert_eq!(receipt.state, ReceiptState::Unknown, "{fault:?}");
        receipts.push(receipt);
    }
    // The person's comment and the two the gateway made.
    let made = world.rest.posted("atlas");
    assert_eq!(made.len(), 3);
    for receipt in &receipts {
        world.past_deadline(&receipt.row).await;
    }

    let requests_before = world.rest.requests().len();
    let tokens_before = world.app.issued().len();
    let report = world.reconciler.pass().await;
    assert_eq!(
        (
            report.claimed,
            report.looked_up,
            report.settled,
            report.handed_to_person
        ),
        (3, 3, 2, 1),
        "{report:?}"
    );
    let left = world.store.receipt(&receipts[0].row).unwrap();
    assert_eq!(left.state, ReceiptState::Unknown);
    assert!(left.handed_to_person.is_some());
    assert_eq!(
        left.lookups.last().map(|lookup| lookup.answer.clone()),
        Some(LookupAnswer::NotFound {
            authoritative: false
        })
    );
    for (receipt, comment) in receipts[1..].iter().zip(&made[1..]) {
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
                Some(format!("comment/{}", comment["id"]))
            )
        );
        assert!(
            comment["body"]
                .as_str()
                .unwrap()
                .ends_with(&marker(&receipt.row))
        );
    }

    // The lookups only read, each with a token of its own.
    let looked = &world.rest.requests()[requests_before..];
    assert_eq!(looked.len(), 3, "{looked:?}");
    for request in looked {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/repos/example-org/atlas/issues/comments");
        assert!(request.query.starts_with("since="), "{}", request.query);
        assert!(
            request
                .query
                .ends_with("&sort=created&direction=asc&per_page=100&page=1"),
            "{}",
            request.query
        );
    }
    let issued = &world.app.issued()[tokens_before..];
    assert_eq!(issued.len(), 3);
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
    assert_eq!(posts(&world).len(), 3, "nothing was posted again");
}

/// A post still on its way at the in-process deadline is `unknown`, posted once, and runs on:
/// the comment is still made.
#[tokio::test]
async fn a_late_post_is_unknown_and_is_not_sent_again() {
    let world = world_with(Options {
        bounds: "[connectors.github-comment]\ndeadline_seconds = 1\n",
        ..commenting()
    })
    .await;
    world
        .rest
        .fault_next_write(Fault::Late(Duration::from_millis(2500)));
    world
        .comment(TEAM_A, arguments("atlas"), "toolu_late")
        .await
        .tool_error();
    world.settle().await;
    assert_eq!(world.last_outcome(PR_COMMENT), Outcome::Unknown);
    assert_eq!(last_receipt(&world).state, ReceiptState::Unknown);
    eventually("the late post ran to its end", || {
        world.rest.posted("atlas").len() == 1
    })
    .await;
    assert_eq!(posts(&world).len(), 1);
}

#[tokio::test]
async fn the_same_key_twice_is_a_duplicate_and_is_posted_once() {
    let world = world().await;
    world
        .comment(TEAM_A, arguments("atlas"), "toolu_twice")
        .await
        .ok();
    let receipt = last_receipt(&world);
    let again = world
        .comment(TEAM_A, arguments("atlas"), "toolu_twice")
        .await;
    assert_eq!(
        again.answer.result()["isError"],
        json!(false),
        "{}",
        again.raw
    );
    world.settle().await;
    assert_eq!(
        world.last_outcome(PR_COMMENT),
        Outcome::Duplicate {
            receipt: receipt.row.clone()
        }
    );
    assert_eq!(posts(&world).len(), 1);
    assert_eq!(world.rest.posted("atlas").len(), 1);
}
