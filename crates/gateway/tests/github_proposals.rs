//! The GitHub connector's proposal tools, `github__propose_change` and `github__amend_change`,
//! end to end over HTTP, against the fake GitHub API's git data and the key custodian on the
//! fake App API (#12). Each case of the conformance suite's proposals_test.go and of
//! tools_test.go's proposal refusals has its counterpart here, with a key on every call and a
//! new tool-use identifier on every repeat:
//!
//! - a proposal is a branch `otto/<key>` from the default branch's head, one commit whose
//!   message is the title, and a draft pull request into the default branch with the claims
//!   above the description and the receipt's marker, on two tokens narrowed to the call's
//!   repository, `{contents: write}` for the git writes and `{contents: read, pull_requests:
//!   write}` for the rest;
//! - a repeat answers the existing proposal from reads alone: `already_proposed`, merged or
//!   not, `key_conflict` against the recorded copy, `proposal_declined` once a person closed it;
//!   a proposal that changes nothing is an `error`; a path that is not a regular file, a branch
//!   or pull request the gateway did not open for the caller, are `refused`, all with nothing
//!   written;
//! - an amendment is one commit on the branch, moved forward without force, and the claims
//!   block rewritten above the kept markers and description; refused for a pull request
//!   another principal's proposal opened, one not under `otto/`, one not opened by the App, one
//!   whose branch is elsewhere, one marked ready for review, and one whose marker a person
//!   removed; an error when closed, without `expected_head` on a repeat, with a stale one, and
//!   with no bot login configured;
//! - each refusal and argument error before any request;
//! - after the first write, every failure is `unknown`, and only a definite refusal of the first
//!   write is `error`; reconciliation finds what a proposal and an amendment made by their
//!   markers, and, with a bot login, only in the App's own pull requests;
//! - no test sends a `DELETE`, writes a ref outside `otto/` or forces one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use connector_github::fake::{Fault, Recorded, Special};
use connector_github::writes::marker;
use gateway::ReconcileSettings;
use gateway::boot::Wiring;
use gateway::start::{self, StartError};
use gateway_core::audit::{AuditRowId, DecisionKind, Outcome};
use gateway_core::receipt::EstablishedBy;
use gateway_core::{ErrorKind, LookupAnswer, ReasonKind, Receipt, ReceiptState, Resource};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::StoreBudgets;
use github_world::{
    ACCOUNT, AMEND_CHANGE, Answered, BOT_LOGIN, CREATE_PR, OTHER_ORG, Options, PROPOSE_CHANGE,
    TEAM_A, TEAM_A_OTHER, World,
};
use serde_json::{Value, json};

/// The repository every test proposes in, as the fake API's paths name it.
const REPO: &str = "/repos/example-org/atlas";

/// What the default branch's README holds.
const SEED: &str = "Atlas.\n";

/// Budgets that put a call row's deadline a little over a second past its call deadline, so a
/// test in real time sees it pass. No receipt is due before its row's deadline.
const SHORT_BUDGETS: StoreBudgets = StoreBudgets {
    begin: Duration::from_millis(100),
    answer: Duration::from_millis(100),
    finish_deadline: Duration::from_secs(1),
};

/// A world whose write entry serves the proposal tools, with the App's bot login configured.
fn proposing() -> Options {
    Options {
        writes: true,
        proposals: true,
        bot_login: Some(BOT_LOGIN),
        ..Options::default()
    }
}

/// `options`'s world, with `atlas` given git data: `main`, holding a README, `a.txt` and a
/// file under `docs/`.
async fn world_with(options: Options) -> World {
    let world = World::with(options).await;
    world.rest.git_repository(
        "atlas",
        "main",
        &[("README.md", SEED), ("a.txt", "old"), ("docs/x.md", "doc")],
    );
    world
}

async fn world() -> World {
    world_with(proposing()).await
}

/// `github__propose_change`'s arguments under `key`, with `changes`; a null removes one.
fn proposal(key: &str, changes: Value) -> Value {
    let mut arguments = json!({
        "owner": ACCOUNT,
        "repo": "atlas",
        "title": "Bump the widget",
        "idempotency_key": key,
        "body": "Why this change",
        "files": [{"path": "a.txt", "content": "x"}],
        "unverifiedClaims": ["the latest widget is 1.2"],
    });
    changed(&mut arguments, changes);
    arguments
}

/// `github__amend_change`'s arguments for pull request `number`, with `changes`.
fn amendment(number: u64, changes: Value) -> Value {
    let mut arguments = json!({
        "owner": ACCOUNT,
        "repo": "atlas",
        "pr_number": number,
        "files": [{"path": "a.txt", "content": "y"}],
        "unverifiedClaims": ["the widget's API is unchanged"],
    });
    changed(&mut arguments, changes);
    arguments
}

fn changed(arguments: &mut Value, changes: Value) {
    for (name, value) in changes.as_object().unwrap() {
        if value.is_null() {
            arguments.as_object_mut().unwrap().remove(name);
        } else {
            arguments[name] = value.clone();
        }
    }
}

/// `files` holding one file, `path`, with the content "x".
fn file(path: &str) -> Value {
    json!({"files": [{"path": path, "content": "x"}]})
}

async fn propose(world: &World, arguments: Value, tool_use_id: &str) -> Answered {
    world
        .write(PROPOSE_CHANGE, TEAM_A, arguments, tool_use_id)
        .await
}

async fn amend(world: &World, arguments: Value, tool_use_id: &str) -> Answered {
    world
        .write(AMEND_CHANGE, TEAM_A, arguments, tool_use_id)
        .await
}

/// The audit row an answer names.
fn row_of(answered: &Answered) -> AuditRowId {
    AuditRowId::new(
        answered.answer.result()["_meta"]["switchboard/auditRow"]
            .as_str()
            .unwrap(),
    )
}

/// The writes the fake received from the `from`-th request on, each as `METHOD path` with the
/// repository's prefix taken off.
fn writes_from(world: &World, from: usize) -> Vec<String> {
    writes(world, from)
        .iter()
        .map(|request| {
            format!(
                "{} {}",
                request.method,
                request.path.strip_prefix(REPO).unwrap_or(&request.path)
            )
        })
        .collect()
}

fn writes(world: &World, from: usize) -> Vec<Recorded> {
    world.rest.requests()[from..]
        .iter()
        .filter(|request| request.method != "GET")
        .cloned()
        .collect()
}

/// The JSON body of `request`.
fn body(request: &Recorded) -> Value {
    serde_json::from_str(request.body.as_deref().unwrap()).unwrap()
}

/// The permissions the token `request` carried was asked for, and the repositories.
fn scope(world: &World, request: &Recorded) -> (BTreeMap<String, String>, Vec<String>) {
    let token = request.token.as_deref().unwrap();
    let issued = world
        .app
        .issued()
        .into_iter()
        .find(|issued| issued.token == token)
        .unwrap();
    (
        issued.asked_permissions.unwrap(),
        issued.asked_repositories.unwrap(),
    )
}

fn permissions(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(permission, access)| ((*permission).to_owned(), (*access).to_owned()))
        .collect()
}

/// The receipt reserved under `row`.
fn receipt(world: &World, row: &AuditRowId) -> Receipt {
    world.store.receipt(row).unwrap()
}

/// The last row's outcome of `tool`, once written.
async fn outcome(world: &World, tool: &str) -> Outcome {
    world.settle().await;
    world.last_outcome(tool)
}

/// `atlas`, as a receipt's target names it.
fn atlas() -> Resource {
    Resource {
        system: "github".into(),
        kind: "repository".into(),
        identifier: format!("{ACCOUNT}/atlas"),
    }
}

/// Nothing the fake received deletes, writes a ref outside `otto/`, or forces one.
fn never_unsafe(world: &World) {
    for request in world.rest.requests() {
        assert_ne!(request.method, "DELETE", "{request:?}");
        if request.method == "POST" && request.path.ends_with("/git/refs") {
            let sent = body(&request);
            assert!(
                sent["ref"]
                    .as_str()
                    .unwrap()
                    .starts_with("refs/heads/otto/"),
                "{sent}"
            );
        }
        if request.method == "PATCH" && request.path.contains("/git/refs/") {
            assert!(
                request
                    .path
                    .starts_with(&format!("{REPO}/git/refs/heads/otto/")),
                "{request:?}"
            );
            assert_eq!(body(&request)["force"], json!(false), "{request:?}");
        }
    }
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

#[tokio::test]
async fn a_proposal_is_a_branch_one_commit_and_a_draft_on_two_tokens_for_the_calls_repository() {
    let world = world().await;
    let base = world.rest.git_head("atlas", "main").unwrap();
    let answered = propose(&world, proposal("widget-1.2", json!({})), "toolu_propose").await;
    let result = answered.ok();
    let row = row_of(&answered);
    assert_eq!(result["state"], "proposed");
    assert_eq!(result["branch"], "otto/widget-1.2");
    assert_eq!(result["prNumber"], 1);
    assert_eq!(result["baseSha"], json!(base));
    assert_eq!(
        result["url"],
        format!("https://github.example.test/{ACCOUNT}/atlas/pull/1")
    );
    assert_eq!(
        result["provenance"],
        json!({
            "tool": PROPOSE_CHANGE,
            "source": "github",
            "classification": "propose",
            "trust": "untrusted-external",
        })
    );
    let commit = result["commitSha"].as_str().unwrap().to_owned();

    // A fresh branch from the default branch's head, one commit whose message is the title
    // alone, and a draft pull request into the default branch, in Otto's order.
    let sent = writes(&world, 0);
    assert_eq!(
        writes_from(&world, 0),
        [
            "POST /git/blobs",
            "POST /git/trees",
            "POST /git/commits",
            "POST /git/refs",
            "POST /pulls"
        ]
    );
    let git = permissions(&[("contents", "write")]);
    let pulls = permissions(&[("contents", "read"), ("pull_requests", "write")]);
    for request in &sent[..4] {
        assert_eq!(
            scope(&world, request),
            (git.clone(), vec!["atlas".to_owned()])
        );
    }
    assert_eq!(
        scope(&world, &sent[4]),
        (pulls.clone(), vec!["atlas".to_owned()])
    );
    for request in world.rest.requests().iter().filter(|r| r.method == "GET") {
        assert_eq!(scope(&world, request).0, pulls, "{request:?}");
    }
    assert_eq!(
        body(&sent[0]),
        json!({"content": "eA==", "encoding": "base64"})
    );
    let tree = body(&sent[1]);
    assert_eq!(tree["tree"][0]["path"], "a.txt");
    assert_eq!(tree["tree"][0]["mode"], "100644");
    assert_eq!(
        body(&sent[2]),
        json!({"message": "Bump the widget", "tree": body(&sent[2])["tree"], "parents": [base]})
    );
    assert_eq!(
        body(&sent[3]),
        json!({"ref": "refs/heads/otto/widget-1.2", "sha": commit})
    );
    let pull = body(&sent[4]);
    assert_eq!(pull["draft"], json!(true));
    assert_eq!(
        (&pull["title"], &pull["head"], &pull["base"]),
        (
            &json!("Bump the widget"),
            &json!("otto/widget-1.2"),
            &json!("main")
        )
    );
    // The declared claims sit above the caller's body, quoted, with the receipt's marker.
    let text = pull["body"].as_str().unwrap();
    assert!(text.starts_with("> [!WARNING]"), "{text}");
    assert!(
        text.contains("```\nthe latest widget is 1.2\n```"),
        "{text}"
    );
    assert!(
        text.ends_with(&format!("\n\n{}\n\nWhy this change", marker(&row))),
        "{text}"
    );
    assert_eq!(
        world
            .rest
            .git_file("atlas", "otto/widget-1.2", "a.txt")
            .as_deref(),
        Some("x")
    );
    assert_eq!(
        world.rest.git_head("atlas", "otto/widget-1.2"),
        Some(commit)
    );
    assert_eq!(world.rest.git_head("atlas", "main"), Some(base));
    assert_eq!(world.rest.opened("atlas")[0]["draft"], json!(true));

    // Two tokens, each for the call's repository alone, in the custodian's record.
    let lines: Vec<Value> = world
        .record
        .text()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert_eq!(line["tool"], PROPOSE_CHANGE);
        assert_eq!(line["team"], "team-a");
        assert_eq!(line["repositories"], json!([format!("{ACCOUNT}/atlas")]));
    }
    assert_eq!(
        lines[0]["permissions"],
        json!({"contents": "read", "pull_requests": "write"})
    );
    assert_eq!(lines[1]["permissions"], json!({"contents": "write"}));

    assert_eq!(outcome(&world, PROPOSE_CHANGE).await, Outcome::Ok);
    let receipt = receipt(&world, &row);
    assert_eq!(receipt.state, ReceiptState::Completed);
    assert_eq!(
        receipt
            .reference
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("pull/1")
    );
    assert_eq!(receipt.target, Some(atlas()));
    for token in world.tokens() {
        assert!(!answered.raw.contains(&token));
        assert!(!format!("{:?}", world.store.rows()).contains(&token));
    }
    never_unsafe(&world);
}

#[tokio::test]
async fn a_repeat_answers_the_existing_proposal_from_reads_and_writes_nothing() {
    let world = world().await;
    propose(&world, proposal("widget-1.2", json!({})), "toolu_first")
        .await
        .ok();
    let before = world.rest.requests().len();

    let repeat = propose(&world, proposal("widget-1.2", json!({})), "toolu_repeat").await;
    let result = repeat.ok();
    assert_eq!(
        (&result["state"], &result["prNumber"], &result["merged"]),
        (&json!("already_proposed"), &json!(1), &json!(false))
    );
    assert_eq!(outcome(&world, PROPOSE_CHANGE).await, Outcome::Ok);
    let settled = receipt(&world, &row_of(&repeat));
    assert_eq!(
        (settled.state, settled.reference),
        (ReceiptState::Completed, None)
    );

    // Another file under the same key: a conflict, and the branch is left as it was.
    let other = propose(
        &world,
        proposal("widget-1.2", file("b.txt")),
        "toolu_other_files",
    )
    .await
    .ok();
    assert_eq!(
        (&other["state"], &other["prNumber"]),
        (&json!("key_conflict"), &json!(1))
    );
    assert_eq!(
        world.rest.git_file("atlas", "otto/widget-1.2", "b.txt"),
        None
    );
    // Another body while it is open: a conflict with the recorded copy.
    let body = propose(
        &world,
        proposal("widget-1.2", json!({"body": "Another reason"})),
        "toolu_other_body",
    )
    .await
    .ok();
    assert_eq!(body["state"], "key_conflict");
    assert!(
        body["message"].as_str().unwrap().contains("recorded copy"),
        "{body}"
    );
    assert!(writes_from(&world, before).is_empty());
    assert_eq!(world.rest.opened("atlas").len(), 1);

    // Merged: already proposed, and said to be merged.
    world.rest.set_pull(
        "atlas",
        1,
        json!({"state": "closed", "merged_at": "2026-11-01T00:00:00Z"}),
    );
    let merged = propose(&world, proposal("widget-1.2", json!({})), "toolu_merged")
        .await
        .ok();
    assert_eq!(
        (&merged["state"], &merged["merged"]),
        (&json!("already_proposed"), &json!(true))
    );
    assert!(writes_from(&world, before).is_empty());
    never_unsafe(&world);
}

/// A retry after a person closed the proposal unmerged is declined: the closed pull request is
/// reported and no new one is opened from the branch.
#[tokio::test]
async fn a_proposal_a_person_closed_is_declined_and_never_reopened() {
    let world = world().await;
    propose(&world, proposal("declined", json!({})), "toolu_declined_1")
        .await
        .ok();
    world.rest.set_pull("atlas", 1, json!({"state": "closed"}));
    let before = world.rest.requests().len();
    let declined = propose(&world, proposal("declined", json!({})), "toolu_declined_2")
        .await
        .ok();
    assert_eq!(
        (&declined["state"], &declined["prNumber"]),
        (&json!("proposal_declined"), &json!(1))
    );
    assert!(
        declined["message"]
            .as_str()
            .unwrap()
            .contains("never reopen"),
        "{declined}"
    );
    assert_eq!(outcome(&world, PROPOSE_CHANGE).await, Outcome::Ok);
    assert!(writes_from(&world, before).is_empty());
    let opened = world.rest.opened("atlas");
    assert_eq!(opened.len(), 1);
    assert_eq!(
        (&opened[0]["head"]["ref"], &opened[0]["state"]),
        (&json!("otto/declined"), &json!("closed"))
    );
    never_unsafe(&world);
}

#[tokio::test]
async fn a_proposal_that_changes_nothing_is_an_error_and_makes_no_branch() {
    let world = world().await;
    let message = propose(
        &world,
        proposal(
            "noop",
            json!({"files": [{"path": "README.md", "content": SEED}, {"path": "docs/x.md", "content": "doc"}]}),
        ),
        "toolu_noop",
    )
    .await
    .tool_error();
    assert!(message.contains("no change"), "{message}");
    assert_eq!(
        outcome(&world, PROPOSE_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(
        world.store.receipts().last().unwrap().state,
        ReceiptState::NotPerformed
    );
    assert_eq!(world.rest.git_head("atlas", "otto/noop"), None);
    assert!(writes_from(&world, 0).is_empty());
    // One file that differs is a change.
    propose(
        &world,
        proposal(
            "one-change",
            json!({"files": [{"path": "README.md", "content": SEED}, {"path": "docs/x.md", "content": "doc 2"}]}),
        ),
        "toolu_one_change",
    )
    .await
    .ok();
}

#[tokio::test]
async fn a_path_that_is_not_a_regular_file_is_refused_before_any_write() {
    let world = world().await;
    // GitHub's contents API answers these two with a.txt's contents, type "file": only the
    // tree says they are links.
    world
        .rest
        .git_special("atlas", "link", Special::Symlink("a.txt".into()));
    world
        .rest
        .git_special("atlas", "docs/up", Special::Symlink("../a.txt".into()));
    world
        .rest
        .git_special("atlas", "away", Special::Symlink("../elsewhere".into()));
    world
        .rest
        .git_special("atlas", "vendor/lib", Special::Submodule);
    let cases = [
        ("docs", "x", "is a directory"),
        ("link", "x", "is a symbolic link"),
        // The same text as the file it links to: still not a regular file, not "no change".
        ("link", "old", "is a symbolic link"),
        ("docs/up", "x", "is a symbolic link"),
        ("away", "x", "is a symbolic link"),
        ("vendor/lib", "x", "is a submodule"),
        (
            "a.txt/inner",
            "x",
            "is under \"a.txt\", which is a regular file and not a directory",
        ),
        (
            "link/inner",
            "x",
            "is under \"link\", which is a symbolic link and not a directory",
        ),
        (
            "vendor/lib/inner",
            "x",
            "is under \"vendor/lib\", which is a submodule and not a directory",
        ),
    ];
    for (at, (path, content, is)) in cases.into_iter().enumerate() {
        let refusal = propose(
            &world,
            proposal(
                &format!("special-{at}"),
                json!({"files": [{"path": path, "content": content}]}),
            ),
            &format!("toolu_special_{at}"),
        )
        .await
        .refusal();
        assert!(refusal.contains(is), "{path}: {refusal}");
        assert_eq!(
            outcome(&world, PROPOSE_CHANGE).await,
            Outcome::Refused { sentence: refusal }
        );
    }
    assert!(writes_from(&world, 0).is_empty());
    // A new file under a directory that does not exist yet is a change.
    propose(
        &world,
        proposal("new-directory", file("fresh/dir/new.md")),
        "toolu_new_directory",
    )
    .await
    .ok();
}

#[tokio::test]
async fn a_tree_listing_cut_short_is_an_error_before_any_write() {
    let world = world().await;
    world.rest.git_truncated("atlas");
    let message = propose(&world, proposal("cut-short", json!({})), "toolu_cut_short")
        .await
        .tool_error();
    assert!(message.contains("cut short"), "{message}");
    assert!(message.contains("nothing was written"), "{message}");
    assert_eq!(
        outcome(&world, PROPOSE_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(
        world.store.receipts().last().unwrap().state,
        ReceiptState::NotPerformed
    );
    assert!(writes_from(&world, 0).is_empty());
}

#[tokio::test]
async fn a_branch_or_pull_request_the_gateway_did_not_open_for_the_caller_is_refused() {
    let world = world().await;
    // A branch someone else made under the prefix, with no pull request.
    world.rest.git_branch("atlas", "otto/hand-made");
    let refusal = propose(&world, proposal("hand-made", json!({})), "toolu_branch")
        .await
        .refusal();
    assert!(refusal.contains("already exists"), "{refusal}");
    assert!(writes_from(&world, 0).is_empty());

    // Another principal of the same team, under the same key.
    propose(&world, proposal("shared-key", json!({})), "toolu_mine")
        .await
        .ok();
    let before = world.rest.requests().len();
    let other = world
        .write(
            PROPOSE_CHANGE,
            TEAM_A_OTHER,
            proposal("shared-key", json!({})),
            "toolu_theirs",
        )
        .await
        .refusal();
    assert!(other.contains("did not open for this caller"), "{other}");
    // A pull request github__create_pr opened from a branch under the prefix.
    world.rest.compare_files("atlas", &["a.txt"]);
    world.rest.git_branch("atlas", "otto/by-hand");
    world
        .create_pr(
            TEAM_A,
            json!({"owner": ACCOUNT, "repo": "atlas", "title": "By hand", "head": "otto/by-hand", "base": "main"}),
            "toolu_by_hand",
        )
        .await
        .ok();
    let by_hand = propose(&world, proposal("by-hand", json!({})), "toolu_by_hand_key")
        .await
        .refusal();
    assert!(
        by_hand.contains("did not open for this caller"),
        "{by_hand}"
    );
    assert_eq!(
        writes_from(&world, before),
        ["POST /pulls"],
        "only github__create_pr wrote"
    );
    never_unsafe(&world);
}

/// tools_test.go's proposal cases: each refusal before any request, with Otto's sentences.
#[tokio::test]
async fn each_refusal_before_any_request_is_made_with_otto_s_sentence() {
    let world = world().await;
    let org = "owner \"other-org\" is not this gateway's configured org \"example-org\"";
    // Another organization, in a repository team A's limit holds, so check 6 lets it through.
    let elsewhere = json!({"owner": OTHER_ORG, "repo": "elsewhere"});
    let cases = [
        (PROPOSE_CHANGE, proposal("k", elsewhere.clone()), org),
        (
            PROPOSE_CHANGE,
            proposal("k", file("AGENTS.md")),
            "AGENTS.md is an instruction-authority file",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file("sub/dir/agents.md")),
            "AGENTS.md is an instruction-authority file",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file(".agents/skills/x.md")),
            "paths under .agents/ are instruction-authority files",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file(".github/workflows/ci.yml")),
            "paths under .github/workflows/ carry their own token permission",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file(".GitHub/Workflows/deploy.yaml")),
            "paths under .github/workflows/ carry their own token permission",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file("infra/Atlantis.YAML")),
            "atlantis.yaml selects Atlantis project names",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file("atlantis.yml")),
            "atlantis.yaml selects Atlantis project names",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"title": "atlantis apply"})),
            "the title begins with \"atlantis\"",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"body": "  Atlantis plan -p prod"})),
            "the body begins with \"atlantis\"",
        ),
        (
            PROPOSE_CHANGE,
            proposal(
                "k",
                json!({"unverifiedClaims": ["fine", "atlantis unlock"]}),
            ),
            "the unverifiedClaims[1] begins with \"atlantis\"",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"title": "Switchboard-Receipt"})),
            "the title holds \"switchboard-receipt\"",
        ),
        (
            PROPOSE_CHANGE,
            proposal(
                "k",
                json!({"body": "Done.\n<!-- switchboard-receipt: x -->"}),
            ),
            "the body holds \"switchboard-receipt\"",
        ),
        (
            PROPOSE_CHANGE,
            proposal(
                "k",
                json!({"unverifiedClaims": ["<!-- SWITCHBOARD-RECEIPT: x -->"]}),
            ),
            "the unverifiedClaims[0] holds \"switchboard-receipt\"",
        ),
        (AMEND_CHANGE, amendment(1, elsewhere), org),
        (
            AMEND_CHANGE,
            amendment(1, file(".github/workflows/ci.yml")),
            "paths under .github/workflows/ carry their own token permission",
        ),
        (
            AMEND_CHANGE,
            amendment(1, file("AGENTS.md")),
            "AGENTS.md is an instruction-authority file",
        ),
        (
            AMEND_CHANGE,
            amendment(1, json!({"unverifiedClaims": ["atlantis apply"]})),
            "the unverifiedClaims[0] begins with \"atlantis\"",
        ),
        (
            AMEND_CHANGE,
            amendment(1, json!({"unverifiedClaims": ["switchboard-receipt"]})),
            "the unverifiedClaims[0] holds \"switchboard-receipt\"",
        ),
    ];
    for (at, (tool, arguments, said)) in cases.into_iter().enumerate() {
        let refusal = world
            .write(tool, TEAM_A, arguments, &format!("toolu_refused_{at}"))
            .await
            .refusal();
        assert!(refusal.contains(said), "{tool} {at}: {refusal}");
        assert_eq!(
            outcome(&world, tool).await,
            Outcome::Refused { sentence: refusal },
            "{at}"
        );
        assert_eq!(
            world.store.receipts().last().unwrap().state,
            ReceiptState::NotPerformed
        );
    }
    // A repository outside the team's limit is denied by check 6, before the connector.
    for (at, tool) in [PROPOSE_CHANGE, AMEND_CHANGE].into_iter().enumerate() {
        let mut outside = if tool == PROPOSE_CHANGE {
            proposal("k", json!({}))
        } else {
            amendment(1, json!({}))
        };
        outside["repo"] = json!("cosmos");
        world
            .write(tool, TEAM_A, outside, &format!("toolu_outside_{at}"))
            .await
            .refusal();
        let row = world.last_row(tool);
        assert_eq!(
            (row.decision, row.reason),
            (DecisionKind::Deny, Some(ReasonKind::ResourceOutsideLimit))
        );
    }
    nothing_requested(&world);
}

#[tokio::test]
async fn each_malformed_argument_is_invalid_arguments_and_nothing_is_sent() {
    let world = world().await;
    let many: Vec<Value> = (0..=connector_github::proposals::MAX_FILES)
        .map(|at| json!({"path": format!("f{at}"), "content": "x"}))
        .collect();
    let long_claim = "c".repeat(connector_github::proposals::MAX_CLAIM_BYTES + 1);
    let long_body = "b".repeat(connector_github::propose::MAX_CALLER_BODY_CHARS + 1);
    // The caller's body fits, and with the claims and the marker it does not.
    let full_body = "b".repeat(connector_github::propose::MAX_CALLER_BODY_CHARS);
    let cases = [
        (
            PROPOSE_CHANGE,
            proposal("k", file("../x")),
            "contains a \"..\" segment",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"unverifiedClaims": null})),
            "unverifiedClaims is required",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"title": "two\nlines"})),
            "title contains a control character",
        ),
        (
            PROPOSE_CHANGE,
            proposal("a..b", json!({})),
            "idempotency_key",
        ),
        (
            PROPOSE_CHANGE,
            proposal("x.lock", json!({})),
            "idempotency_key",
        ),
        (
            PROPOSE_CHANGE,
            proposal("widget.", json!({})),
            "idempotency_key",
        ),
        (PROPOSE_CHANGE, proposal(".x", json!({})), "idempotency_key"),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"files": []})),
            "at least one file",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"files": many})),
            "at most 50",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", file(".git/config")),
            "\".git\" segment",
        ),
        (
            PROPOSE_CHANGE,
            proposal(
                "k",
                json!({"files": [{"path": "a", "content": "x"}, {"path": "a", "content": "y"}]}),
            ),
            "given twice",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"files": [{"path": "a", "content": 7}]})),
            "files[0].content must be a string",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"unverifiedClaims": [7]})),
            "unverifiedClaims[0] must be a string",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"unverifiedClaims": [long_claim]})),
            "at most 1000",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"body": long_body})),
            "body is longer than 65536",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"body": full_body})),
            "GitHub takes at most 65536",
        ),
        (
            PROPOSE_CHANGE,
            proposal("k", json!({"draft": false})),
            "is not an argument",
        ),
        (
            AMEND_CHANGE,
            amendment(0, json!({})),
            "pr_number must be a positive number",
        ),
        (
            AMEND_CHANGE,
            amendment(1, json!({"expected_head": "HEAD"})),
            "40 lowercase hex",
        ),
        (AMEND_CHANGE, amendment(1, file("a//b")), "an empty segment"),
    ];
    for (at, (tool, arguments, said)) in cases.into_iter().enumerate() {
        let message = world
            .write(tool, TEAM_A, arguments, &format!("toolu_bad_{at}"))
            .await
            .tool_error();
        // The gateway's own check of the approved schema answers some first, with the same
        // outcome; the connector's sentence answers the rest.
        assert!(
            message.contains(said)
                || message.contains("do not match its approved schema")
                || message.contains("its approved definition does not declare"),
            "{tool} {at}: {message}"
        );
        assert_eq!(
            outcome(&world, tool).await,
            Outcome::Error {
                error_kind: ErrorKind::InvalidArguments
            },
            "{at}"
        );
    }
    nothing_requested(&world);
}

/// A definite refusal of the first write is an error, with nothing made; every failure after
/// a write may have been sent is unknown, a 422 on the branch and a broken pull request write
/// included. One reconciliation pass then finds the pull request that was opened by its marker,
/// and hands the rest to a person.
#[tokio::test]
async fn after_the_first_write_every_failure_is_unknown_and_reconciliation_finds_the_proposal() {
    let world = world_with(Options {
        reconcile: ReconcileSettings {
            attempts: 1,
            ..ReconcileSettings::default()
        },
        budgets: SHORT_BUDGETS,
        ..proposing()
    })
    .await;
    // A fault that changes nothing, for the writes before the one a case breaks.
    let pass = || Fault::Late(Duration::ZERO);

    world.rest.fault_next_write(Fault::Status(422));
    let message = propose(
        &world,
        proposal("refused-blob", json!({})),
        "toolu_refused_blob",
    )
    .await
    .tool_error();
    assert!(message.contains("HTTP 422"), "{message}");
    assert_eq!(
        outcome(&world, PROPOSE_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert_eq!(
        world.store.receipts().last().unwrap().state,
        ReceiptState::NotPerformed
    );
    world.rest.fault_next_write(Fault::Status(403));
    propose(
        &world,
        proposal("forbidden-blob", json!({})),
        "toolu_forbidden_blob",
    )
    .await
    .tool_error();
    assert_eq!(
        outcome(&world, PROPOSE_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::VendorRefusal
        }
    );

    let mut unknown = Vec::new();
    for (at, faults) in [
        // The tree, after the blob was written.
        vec![pass(), Fault::Status(500)],
        // The tree refused outright, after the blob: still unknown.
        vec![pass(), Fault::Status(422)],
        // The branch, refused after the commit.
        vec![pass(), pass(), pass(), Fault::Status(422)],
        // The pull request: a 502 with nothing applied.
        vec![pass(), pass(), pass(), pass(), Fault::Status(502)],
        // The pull request applied, and its answer broken off.
        vec![pass(), pass(), pass(), pass(), Fault::AppliedThenClosed],
    ]
    .into_iter()
    .enumerate()
    {
        for fault in faults {
            world.rest.fault_next_write(fault);
        }
        let answered = propose(
            &world,
            proposal(&format!("unknown-{at}"), json!({})),
            &format!("toolu_unknown_{at}"),
        )
        .await;
        answered.tool_error();
        assert_eq!(
            outcome(&world, PROPOSE_CHANGE).await,
            Outcome::Unknown,
            "{at}"
        );
        let row = row_of(&answered);
        assert_eq!(receipt(&world, &row).state, ReceiptState::Unknown, "{at}");
        unknown.push(row);
    }
    assert_eq!(
        world.rest.opened("atlas").len(),
        1,
        "one pull request was opened"
    );
    for row in &unknown {
        world.past_deadline(row).await;
    }

    let before = world.rest.requests().len();
    let report = world.reconciler.pass().await;
    assert_eq!(
        (
            report.claimed,
            report.looked_up,
            report.settled,
            report.handed_to_person
        ),
        (5, 5, 1, 4),
        "{report:?}"
    );
    let found = receipt(&world, &unknown[4]);
    assert_eq!(
        (
            found.state,
            &found.established_by,
            found.reference.as_ref().map(|reference| reference.as_str())
        ),
        (
            ReceiptState::Completed,
            &EstablishedBy::Reconciliation,
            Some("pull/1")
        )
    );
    for row in &unknown[..4] {
        let left = receipt(&world, row);
        assert_eq!(left.state, ReceiptState::Unknown);
        assert!(left.handed_to_person.is_some());
        assert_eq!(
            left.lookups.last().map(|lookup| lookup.answer.clone()),
            Some(LookupAnswer::NotFound {
                authoritative: false
            })
        );
    }
    assert!(
        writes_from(&world, before).is_empty(),
        "a lookup only reads"
    );
    never_unsafe(&world);
}

#[tokio::test]
async fn an_amendment_is_one_commit_moved_forward_without_force_and_the_claims_rewritten() {
    let world = world().await;
    let proposed = propose(&world, proposal("widget-1.2", json!({})), "toolu_propose").await;
    proposed.ok();
    let opened_by = row_of(&proposed);
    let first = world.rest.git_head("atlas", "otto/widget-1.2").unwrap();
    let before = world.rest.requests().len();
    let tokens_before = world.app.issued().len();

    let answered = amend(&world, amendment(1, json!({})), "toolu_amend").await;
    let result = answered.ok();
    let row = row_of(&answered);
    assert_eq!(
        (&result["state"], &result["branch"], &result["prNumber"]),
        (&json!("amended"), &json!("otto/widget-1.2"), &json!(1))
    );
    assert_eq!(result["provenance"]["tool"], AMEND_CHANGE);
    let head = result["headSha"].as_str().unwrap().to_owned();
    assert_eq!(
        writes_from(&world, before),
        [
            "POST /git/blobs",
            "POST /git/trees",
            "POST /git/commits",
            "PATCH /git/refs/heads/otto/widget-1.2",
            "PATCH /pulls/1"
        ]
    );
    let sent = writes(&world, before);
    // One commit on top of the branch, a fast-forward of it, and the claims block rewritten.
    let commit = body(&sent[2]);
    assert_eq!(
        (&commit["parents"], &commit["message"]),
        (&json!([first]), &json!("Amend pull request #1"))
    );
    assert_eq!(body(&sent[3]), json!({"sha": head, "force": false}));
    let git = permissions(&[("contents", "write")]);
    for request in &sent[..4] {
        assert_eq!(
            scope(&world, request),
            (git.clone(), vec!["atlas".to_owned()])
        );
    }
    assert_eq!(
        scope(&world, &sent[4]),
        (
            permissions(&[("contents", "read"), ("pull_requests", "write")]),
            vec!["atlas".to_owned()]
        )
    );
    assert_eq!(world.app.issued().len() - tokens_before, 2);
    let edited = body(&sent[4]);
    assert_eq!(
        edited.as_object().unwrap().len(),
        1,
        "only the body: {edited}"
    );
    let text = edited["body"].as_str().unwrap();
    assert!(text.contains("the widget's API is unchanged"), "{text}");
    assert!(!text.contains("the latest widget is 1.2"), "{text}");
    assert!(
        text.ends_with(&format!(
            "\n\n{}\n{}\n\nWhy this change",
            marker(&opened_by),
            marker(&row)
        )),
        "{text}"
    );
    assert_eq!(world.rest.opened("atlas")[0]["body"], json!(text));
    assert_eq!(
        world
            .rest
            .git_file("atlas", "otto/widget-1.2", "a.txt")
            .as_deref(),
        Some("y")
    );
    assert_eq!(
        world.rest.git_head("atlas", "otto/widget-1.2"),
        Some(head.clone())
    );
    assert_eq!(outcome(&world, AMEND_CHANGE).await, Outcome::Ok);
    let settled = receipt(&world, &row);
    assert_eq!(
        (
            settled.state,
            settled
                .reference
                .as_ref()
                .map(|reference| reference.as_str())
        ),
        (ReceiptState::Completed, Some("pull/1"))
    );

    // A repeat that would change nothing needs the expected head, and with it is no_change.
    let before = world.rest.requests().len();
    let message = amend(&world, amendment(1, json!({})), "toolu_repeat")
        .await
        .tool_error();
    assert!(message.contains("expected_head is required"), "{message}");
    assert_eq!(
        outcome(&world, AMEND_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    let same = amend(
        &world,
        amendment(1, json!({ "expected_head": head })),
        "toolu_expected",
    )
    .await
    .ok();
    assert_eq!(
        (&same["state"], &same["headSha"]),
        (&json!("no_change"), &json!(head))
    );
    // A stale expected head is an error, whatever the files.
    let stale = amend(
        &world,
        amendment(
            1,
            json!({"expected_head": first, "files": [{"path": "a.txt", "content": "z"}]}),
        ),
        "toolu_stale",
    )
    .await
    .tool_error();
    assert!(stale.contains("not the expected_head"), "{stale}");
    assert!(writes_from(&world, before).is_empty());
    assert_eq!(world.rest.git_head("atlas", "otto/widget-1.2"), Some(head));
    never_unsafe(&world);
}

#[tokio::test]
async fn an_amendment_of_what_the_gateway_did_not_open_for_the_caller_or_a_person_took_over_is_refused()
 {
    let world = world().await;
    propose(&world, proposal("widget-1.2", json!({})), "toolu_propose")
        .await
        .ok();
    // Pull requests github__create_pr opened: one from an ordinary branch, and one from a
    // branch under the reserved prefix with no proposal.
    world.rest.compare_files("atlas", &["a.txt"]);
    for (number, head) in [(2, "feature"), (3, "otto/hand-made")] {
        world.rest.git_branch("atlas", head);
        world
            .create_pr(
                TEAM_A,
                json!({"owner": ACCOUNT, "repo": "atlas", "title": "Hand made", "head": head, "base": "main"}),
                &format!("toolu_create_{number}"),
            )
            .await
            .ok();
    }
    let before = world.rest.requests().len();
    let refused = async |number: u64, subject: &str, id: &str| {
        let refusal = world
            .write(AMEND_CHANGE, subject, amendment(number, json!({})), id)
            .await
            .refusal();
        assert_eq!(
            outcome(&world, AMEND_CHANGE).await,
            Outcome::Refused {
                sentence: refusal.clone()
            }
        );
        refusal
    };
    let feature = refused(2, TEAM_A, "toolu_feature").await;
    assert!(
        feature.contains("which is not under the reserved \"otto/\" prefix"),
        "{feature}"
    );
    let hand_made = refused(3, TEAM_A, "toolu_hand_made").await;
    assert!(
        hand_made.contains("is not one github__propose_change opened"),
        "{hand_made}"
    );
    // Another principal of the same team: the proposal is not theirs.
    let theirs = refused(1, TEAM_A_OTHER, "toolu_other_principal").await;
    assert!(
        theirs.contains("is not one github__propose_change opened"),
        "{theirs}"
    );

    // Marked ready for review.
    world.rest.set_pull("atlas", 1, json!({"draft": false}));
    let ready = refused(1, TEAM_A, "toolu_ready").await;
    assert!(ready.contains("marked ready for review"), "{ready}");
    world.rest.set_pull("atlas", 1, json!({"draft": true}));
    // Opened by someone other than the App.
    world
        .rest
        .set_pull("atlas", 1, json!({"user": {"login": "someone"}}));
    let author = refused(1, TEAM_A, "toolu_author").await;
    assert!(
        author.contains("not opened by this gateway's GitHub App"),
        "{author}"
    );
    world
        .rest
        .set_pull("atlas", 1, json!({"user": {"login": BOT_LOGIN}}));
    // A branch in another repository.
    world.rest.set_pull(
        "atlas",
        1,
        json!({"head": {"repo": {"full_name": "someone/atlas"}}}),
    );
    let fork = refused(1, TEAM_A, "toolu_fork").await;
    assert!(fork.contains("is not in example-org/atlas"), "{fork}");
    world.rest.set_pull(
        "atlas",
        1,
        json!({"head": {"repo": {"full_name": format!("{ACCOUNT}/atlas")}}}),
    );
    // A description whose marker a person removed.
    let body = world.rest.opened("atlas")[0]["body"]
        .as_str()
        .unwrap()
        .to_owned();
    let without: Vec<&str> = body
        .lines()
        .filter(|line| !line.starts_with("<!-- switchboard-receipt"))
        .collect();
    world
        .rest
        .set_pull("atlas", 1, json!({"body": without.join("\n")}));
    let removed = refused(1, TEAM_A, "toolu_removed").await;
    assert!(removed.contains("no longer holds"), "{removed}");
    world.rest.set_pull("atlas", 1, json!({ "body": body }));

    // Closed is an error, not a refusal.
    world.rest.set_pull("atlas", 1, json!({"state": "closed"}));
    let closed = amend(&world, amendment(1, json!({})), "toolu_closed")
        .await
        .tool_error();
    assert!(closed.contains("is closed, not open"), "{closed}");
    assert_eq!(
        outcome(&world, AMEND_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert!(
        writes_from(&world, before).is_empty(),
        "a refused amendment wrote"
    );
    never_unsafe(&world);
}

/// Without the App's own login there is nothing to check authorship against, so every
/// amendment fails before any request.
#[tokio::test]
async fn an_amendment_needs_the_bot_login() {
    let world = world_with(Options {
        bot_login: None,
        ..proposing()
    })
    .await;
    let message = amend(&world, amendment(1, json!({})), "toolu_no_bot")
        .await
        .tool_error();
    assert!(message.contains("no bot login configured"), "{message}");
    assert_eq!(
        outcome(&world, AMEND_CHANGE).await,
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    nothing_requested(&world);
}

/// An amendment whose pull request write may have been applied is unknown, and reconciliation
/// finds it by the marker it added.
#[tokio::test]
async fn reconciliation_finds_an_amendment_by_the_marker_it_added() {
    let world = world_with(Options {
        reconcile: ReconcileSettings {
            attempts: 1,
            ..ReconcileSettings::default()
        },
        budgets: SHORT_BUDGETS,
        ..proposing()
    })
    .await;
    propose(&world, proposal("widget-1.2", json!({})), "toolu_propose")
        .await
        .ok();
    for _ in 0..4 {
        world.rest.fault_next_write(Fault::Late(Duration::ZERO));
    }
    world.rest.fault_next_write(Fault::AppliedThen(502));
    let answered = amend(&world, amendment(1, json!({})), "toolu_amend_unknown").await;
    answered.tool_error();
    assert_eq!(outcome(&world, AMEND_CHANGE).await, Outcome::Unknown);
    let row = row_of(&answered);
    world.past_deadline(&row).await;
    let report = world.reconciler.pass().await;
    assert_eq!((report.claimed, report.settled), (1, 1), "{report:?}");
    let settled = receipt(&world, &row);
    assert_eq!(
        (
            settled.state,
            settled
                .reference
                .as_ref()
                .map(|reference| reference.as_str())
        ),
        (ReceiptState::Completed, Some("pull/1"))
    );
    never_unsafe(&world);
}

/// With a bot login, a lookup looks only at the App's own pull requests: a pull request
/// someone else opened with a copy of a draft's description, marker and all, is passed over,
/// though it was updated since (#242). This is `github__create_pr`'s lookup too.
#[tokio::test]
async fn with_a_bot_login_a_lookup_passes_over_a_copy_someone_else_opened() {
    let world = world_with(Options {
        reconcile: ReconcileSettings {
            attempts: 1,
            ..ReconcileSettings::default()
        },
        budgets: SHORT_BUDGETS,
        ..proposing()
    })
    .await;
    world.rest.compare_files("atlas", &["src/client.rs"]);
    world.rest.fault_next_write(Fault::AppliedThen(502));
    let answered = world
        .create_pr(
            TEAM_A,
            json!({"owner": ACCOUNT, "repo": "atlas", "title": "Retry", "head": "feature/retry", "base": "main"}),
            "toolu_create_unknown",
        )
        .await;
    answered.tool_error();
    assert_eq!(outcome(&world, CREATE_PR).await, Outcome::Unknown);
    let row = row_of(&answered);
    let copied = world.rest.opened("atlas")[0]["body"]
        .as_str()
        .unwrap()
        .to_owned();
    let copy = world.rest.open_elsewhere("atlas", &copied);
    assert_eq!(copy, 2);
    world.past_deadline(&row).await;
    let report = world.reconciler.pass().await;
    assert_eq!(report.settled, 1, "{report:?}");
    assert_eq!(
        receipt(&world, &row)
            .reference
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("pull/1")
    );
}

/// The deployment file's `[github] bot_login` reaches the connector, which refuses one that is
/// not a GitHub login when it is built, before the gateway serves anything.
#[tokio::test]
async fn a_bot_login_that_is_not_a_github_login_refuses_the_start() {
    let world = world().await;
    assert_eq!(
        world
            .deployment
            .github
            .as_ref()
            .and_then(|github| github.bot_login.as_deref()),
        Some(BOT_LOGIN)
    );
    let mut settings = world.deployment.github.clone().unwrap();
    settings.bot_login = Some("not a login[bot]".into());
    let registry = Registry::from_toml_str(&github_world::registry_with(
        "r1",
        "limit",
        github_world::PERMISSIONS,
        true,
        true,
    ))
    .unwrap();
    match start::wire_github(
        &registry,
        Some(&settings),
        &world.deployment.connectors,
        Wiring::new(std::sync::Arc::new(SystemClock)),
    ) {
        Err(StartError::GitHub(connector_github::SettingsError::BotLogin(login))) => {
            assert_eq!(login, "not a login[bot]");
        }
        other => panic!("{:?}", other.err()),
    }
}

/// Without the gateway's receipts to read, no pull request can be told to be the caller's, so
/// each proposal tool sends nothing: it fails closed.
#[tokio::test]
async fn without_the_gateways_receipts_each_proposal_tool_sends_nothing() {
    let world = world_with(Options {
        withhold_receipts: true,
        ..proposing()
    })
    .await;
    for (at, (tool, arguments)) in [
        (PROPOSE_CHANGE, proposal("no-store", json!({}))),
        (AMEND_CHANGE, amendment(1, json!({}))),
    ]
    .into_iter()
    .enumerate()
    {
        let message = world
            .write(tool, TEAM_A, arguments, &format!("toolu_no_store_{at}"))
            .await
            .tool_error();
        assert!(
            message.contains("needs the gateway's receipts"),
            "{message}"
        );
        assert_eq!(
            outcome(&world, tool).await,
            Outcome::Error {
                error_kind: ErrorKind::Other
            }
        );
    }
    nothing_requested(&world);
}
