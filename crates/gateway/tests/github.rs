//! The GitHub connector end to end (#12), through the gateway's HTTP endpoint, wired as `start`
//! wires it: the key custodian on its fake GitHub App API, the fake GitHub REST API, the
//! testkit's issuer and an in-memory audit store (`github_world`). Each tool's success; another
//! organization refused before any request; a repository outside the team's limit denied at
//! check 6 with no request; the token scoped to the team's repositories and the entry's
//! permissions, with the revision; a custodian refusal; vendor errors; no credential in what
//! the caller reads or the row holds; the in-process bound and the rate quota; the row's
//! resources; and a reload that changes an entry.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use connector_github::fake::Mode;
use gateway::path::RequestPath;
use gateway::reload::ReloadError;
use gateway::start::{Prepared, StartError, prepare};
use gateway::{BootError, Rate, RateQuotas, team_over_quota};
use gateway_core::audit::{DecisionKind, Outcome, RecordedResource, RecordedResources};
use gateway_core::{ConnectorName, ErrorKind, InstanceName, ReasonKind};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use github_world::{
    ACCOUNT, ENTRY, GET_FILE, GET_ISSUE, GET_PR, OTHER_ORG, Options, PERMISSIONS, TEAM_A, TEAM_B,
    World, registry_text,
};
use serde_json::{Value, json};

fn file(repo: &str, path: &str) -> Value {
    json!({"owner": ACCOUNT, "repo": repo, "path": path})
}

fn numbered(repo: &str, number: u64) -> Value {
    json!({"owner": ACCOUNT, "repo": repo, "number": number})
}

fn repository(identifier: &str) -> RecordedResources {
    RecordedResources::Named(vec![RecordedResource {
        system: "github".into(),
        kind: "repository".into(),
        identifier: identifier.into(),
    }])
}

fn comments(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| {
            json!({"id": i, "body": format!("comment {i}"), "user": {"login": "someone"},
                   "created_at": "2026-01-01T00:00:00Z"})
        })
        .collect()
}

fn provenance(tool: &str) -> Value {
    json!({"tool": tool, "source": "github", "classification": "read",
           "trust": "untrusted-external"})
}

/// The permissions every token is asked for: exactly the entry's set.
fn entry_permissions() -> BTreeMap<String, String> {
    [
        ("contents", "read"),
        ("issues", "read"),
        ("pull_requests", "read"),
    ]
    .into_iter()
    .map(|(name, level)| (name.to_owned(), level.to_owned()))
    .collect()
}

#[tokio::test]
async fn each_tool_answers_with_a_token_narrowed_to_the_teams_repositories() {
    let world = World::new().await;
    world
        .rest
        .file("atlas", "docs/README.md", "hello from the fake vendor");
    world.rest.pull(
        "atlas",
        42,
        json!({"number": 42, "title": "A change", "state": "open", "draft": true,
               "merged": false, "body": "why", "user": {"login": "someone"},
               "head": {"ref": "otto/x", "sha": "a".repeat(40)}, "base": {"ref": "main"},
               "html_url": "https://example.invalid/pull/42"}),
    );
    world.rest.comments("atlas", 42, comments(21));
    world.rest.issue(
        "atlas",
        7,
        json!({"number": 7, "title": "A bug", "state": "open", "body": "steps",
               "user": {"login": "someone"}, "labels": [{"name": "bug"}], "comments": 25,
               "html_url": "https://example.invalid/issues/7"}),
    );
    world.rest.comments("atlas", 7, comments(25));

    let answered = world
        .team_a(GET_FILE, file("atlas", "docs/README.md"))
        .await;
    let result = answered.ok();
    assert_eq!(result["file"]["text"], "hello from the fake vendor");
    assert_eq!(result["file"]["truncated"], false);
    assert_eq!(result["provenance"], provenance(GET_FILE));

    let result = world.team_a(GET_PR, numbered("atlas", 42)).await.ok();
    assert_eq!(result["pr"]["title"], "A change");
    assert_eq!(result["pr"]["draft"], true);
    assert_eq!(result["comments"].as_array().unwrap().len(), 20);
    assert_eq!(result["comments"][0]["body"], "comment 0");
    assert_eq!(result["commentsTruncated"], true);
    assert_eq!(result["provenance"], provenance(GET_PR));

    let result = world.team_a(GET_ISSUE, numbered("atlas", 7)).await.ok();
    assert_eq!(result["issue"]["title"], "A bug");
    assert_eq!(result["issue"]["labels"], json!(["bug"]));
    assert_eq!(result["issue"]["commentCount"], 25);
    assert_eq!(result["comments"].as_array().unwrap().len(), 20);
    assert!(
        result["commentsTruncationNote"]
            .as_str()
            .unwrap()
            .contains("20 of 25")
    );
    assert_eq!(result["provenance"], provenance(GET_ISSUE));

    // A pull request's number read as an issue says so and reads nothing more.
    let before = world.rest.requests().len();
    let result = world.team_a(GET_ISSUE, numbered("atlas", 42)).await.ok();
    assert_eq!(result["isPullRequest"], true);
    assert!(result["note"].as_str().unwrap().contains(GET_PR));
    assert_eq!(world.rest.requests().len(), before + 1);

    world.settle().await;
    for tool in [GET_FILE, GET_PR, GET_ISSUE] {
        let row = world.last_row(tool);
        assert_eq!(row.decision, DecisionKind::Allow, "{tool}");
        assert_eq!(row.connector.as_ref().unwrap().as_str(), ENTRY);
        assert_eq!(row.resources, repository(&format!("{ACCOUNT}/atlas")));
        assert_eq!(row.policy_revision.as_str(), "r1");
        assert_eq!(world.last_outcome(tool), Outcome::Ok, "{tool}");
    }

    // Each call asked the custodian for its own token, narrowed to team A's repositories on
    // the App's account (not the other organization's) and to the entry's permissions.
    let issued = world.app.issued();
    assert_eq!(issued.len(), 4);
    for token in &issued {
        assert_eq!(
            token.asked_repositories,
            Some(vec!["atlas".to_owned(), "borealis".to_owned()])
        );
        assert_eq!(token.asked_permissions, Some(entry_permissions()));
    }
    // Every request to GitHub carried a token the custodian issued, and nothing else.
    let tokens = world.tokens();
    let requests = world.rest.requests();
    assert_eq!(requests.len(), 1 + 2 + 2 + 1);
    for request in &requests {
        assert!(
            tokens.contains(request.token.as_ref().unwrap()),
            "{request:?}"
        );
        assert_eq!(request.method, "GET");
    }
    assert_eq!(
        requests[0].path,
        "/repos/example-org/atlas/contents/docs/README.md"
    );
    assert_eq!(requests[2].query, "per_page=21");
    // The custodian's record has each request, with the revision it was decided under.
    let record = world.record.text();
    assert_eq!(record.lines().count(), 4, "{record}");
    for line in record.lines() {
        let line: Value = serde_json::from_str(line).unwrap();
        assert_eq!(line["revision"], "r1", "{line}");
        assert_eq!(line["team"], "team-a", "{line}");
    }
}

#[tokio::test]
async fn a_token_narrowed_per_call_names_only_the_calls_repository() {
    let world = World::with(Options {
        narrowing: "call",
        ..Options::default()
    })
    .await;
    world.rest.file("borealis", "x.txt", "x");
    world.team_a(GET_FILE, file("borealis", "x.txt")).await.ok();
    let issued = world.app.issued();
    assert_eq!(
        issued[0].asked_repositories,
        Some(vec!["borealis".to_owned()])
    );
}

#[tokio::test]
async fn another_organization_is_refused_before_any_request() {
    let world = World::new().await;
    // Team A's limit holds a repository of another organization, so check 6 passes and the
    // connector's own check is what refuses.
    let arguments = json!({"owner": OTHER_ORG, "repo": "elsewhere", "number": 1});
    let answered = world.team_a(GET_PR, arguments).await;
    let sentence = answered.refusal();
    assert_eq!(
        sentence,
        format!("owner \"{OTHER_ORG}\" is not this gateway's configured org \"{ACCOUNT}\"")
    );
    world.settle().await;
    let row = world.last_row(GET_PR);
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(row.resources, repository(&format!("{OTHER_ORG}/elsewhere")));
    assert_eq!(world.last_outcome(GET_PR), Outcome::Refused { sentence });
    assert_eq!(world.app.token_requests(), 0, "no token was asked for");
    assert!(
        world.rest.requests().is_empty(),
        "nothing was sent to GitHub"
    );
}

#[tokio::test]
async fn a_repository_outside_the_teams_limit_is_denied_at_check_6() {
    let world = World::new().await;
    for (subject, repo) in [(TEAM_A, "cosmos"), (TEAM_B, "atlas"), (TEAM_A, "secret")] {
        let answered = world.call(subject, GET_FILE, file(repo, "x")).await;
        answered.refusal();
        world.settle().await;
        let row = world.last_row(GET_FILE);
        assert_eq!(row.decision, DecisionKind::Deny, "{repo}");
        assert_eq!(row.reason, Some(ReasonKind::ResourceOutsideLimit), "{repo}");
    }
    assert_eq!(world.app.token_requests(), 0);
    assert!(world.rest.requests().is_empty());
}

#[tokio::test]
async fn malformed_arguments_are_errors_and_send_nothing() {
    let world = World::new().await;
    for (tool, arguments) in [
        (GET_PR, numbered("atlas", 0)),
        (GET_FILE, file("atlas", "../escape")),
        (GET_FILE, file("atlas", "a//b")),
        (GET_ISSUE, json!({"owner": ACCOUNT, "repo": "atlas"})),
    ] {
        let answered = world.team_a(tool, arguments.clone()).await;
        answered.tool_error();
        world.settle().await;
        assert_eq!(
            world.last_outcome(tool),
            Outcome::Error {
                error_kind: ErrorKind::InvalidArguments
            },
            "{tool} {arguments}"
        );
    }
    assert_eq!(world.app.token_requests(), 0);
    assert!(world.rest.requests().is_empty());
}

#[tokio::test]
async fn a_custodian_refusal_is_its_own_kind_and_reaches_nothing() {
    // The custodian holds another revision of the registry, so it refuses every request as
    // decided under a stale one.
    let world = World::with(Options {
        custodian_revision: Some("r0"),
        ..Options::default()
    })
    .await;
    let message = world
        .team_a(GET_FILE, file("atlas", "x"))
        .await
        .tool_error();
    assert!(message.contains("key custodian refused"), "{message}");
    world.settle().await;
    assert_eq!(
        world.last_outcome(GET_FILE),
        Outcome::Error {
            error_kind: ErrorKind::CustodianRefusal
        }
    );
    assert_eq!(world.app.token_requests(), 0);
    assert!(world.rest.requests().is_empty());
    assert!(world.record.text().contains("stale_revision"));
}

#[tokio::test]
async fn a_custodian_that_is_not_there_is_an_error_of_its_own() {
    let world = World::with(Options {
        custodian: false,
        ..Options::default()
    })
    .await;
    let message = world
        .team_a(GET_FILE, file("atlas", "x"))
        .await
        .tool_error();
    assert!(message.contains("no GitHub token"), "{message}");
    world.settle().await;
    assert_eq!(
        world.last_outcome(GET_FILE),
        Outcome::Error {
            error_kind: ErrorKind::Other
        }
    );
    assert!(world.rest.requests().is_empty());
}

#[tokio::test]
async fn vendor_errors_are_told_apart_and_never_carry_a_credential() {
    let world = World::new().await;
    // A file GitHub does not have, or a repository the token cannot see, is a 404.
    let message = world
        .team_a(GET_FILE, file("atlas", "missing.txt"))
        .await
        .tool_error();
    assert!(message.contains("HTTP 404"), "{message}");
    for (mode, kind, said) in [
        (Mode::Status(403), ErrorKind::VendorRefusal, "HTTP 403"),
        (Mode::RateLimited, ErrorKind::Other, "rate limit"),
        (Mode::Status(503), ErrorKind::Other, "HTTP 503"),
        (Mode::Status(401), ErrorKind::Other, "HTTP 401"),
    ] {
        world.rest.set_mode(mode);
        let answered = world.team_a(GET_ISSUE, numbered("atlas", 7)).await;
        let message = answered.tool_error();
        assert!(message.contains(said), "{mode:?}: {message}");
        world.settle().await;
        assert_eq!(
            world.last_outcome(GET_ISSUE),
            Outcome::Error { error_kind: kind },
            "{mode:?}"
        );
        // The fake echoes the token it was sent in every error's body.
        for token in world.tokens() {
            assert!(!answered.raw.contains(&token), "{mode:?}: {}", answered.raw);
        }
    }
    // Nothing a row holds carries a token either.
    let rows = format!("{:?}", world.store.rows());
    for token in world.tokens() {
        assert!(!rows.contains(&token));
    }
    assert!(!world.tokens().is_empty());
}

#[tokio::test]
async fn a_read_past_the_connectors_deadline_is_a_late_read() {
    let world = World::with(Options {
        bounds: "[connectors.github-read]\ndeadline_seconds = 1\n",
        ..Options::default()
    })
    .await;
    world.rest.file("atlas", "x.txt", "x");
    world.rest.set_mode(Mode::Late(Duration::from_secs(3)));
    world
        .team_a(GET_FILE, file("atlas", "x.txt"))
        .await
        .tool_error();
    world.settle().await;
    assert_eq!(
        world.last_outcome(GET_FILE),
        Outcome::Error {
            error_kind: ErrorKind::OversizedOrLateRead
        }
    );
    assert_eq!(world.last_row(GET_FILE).call_deadline_ms, 1000);
}

#[tokio::test]
async fn a_result_past_the_connectors_bound_is_an_oversized_read() {
    let world = World::with(Options {
        bounds: "[connectors.github-read]\nmax_result_bytes = 4096\n",
        ..Options::default()
    })
    .await;
    world.rest.file("atlas", "big.txt", &"z".repeat(8192));
    world.rest.file("atlas", "small.txt", "fits");
    world
        .team_a(GET_FILE, file("atlas", "big.txt"))
        .await
        .tool_error();
    world.settle().await;
    assert_eq!(
        world.last_outcome(GET_FILE),
        Outcome::Error {
            error_kind: ErrorKind::OversizedOrLateRead
        }
    );
    world
        .team_a(GET_FILE, file("atlas", "small.txt"))
        .await
        .ok();
}

#[tokio::test]
async fn a_file_past_256_kib_is_cut_and_said_to_be_cut() {
    let world = World::new().await;
    world
        .rest
        .file("atlas", "large.txt", &"y".repeat(300 * 1024));
    let result = world
        .team_a(GET_FILE, file("atlas", "large.txt"))
        .await
        .ok();
    assert_eq!(result["file"]["truncated"], true);
    assert_eq!(result["file"]["text"].as_str().unwrap().len(), 256 * 1024);
}

#[tokio::test]
async fn the_teams_rate_quota_refuses_before_a_token_is_asked_for() {
    let world = World::with(Options {
        quotas: RateQuotas {
            per_team_per_server: Rate {
                per_minute: 1,
                burst: 2,
            },
            ..RateQuotas::default()
        },
        ..Options::default()
    })
    .await;
    world.rest.file("atlas", "x.txt", "x");
    world.team_a(GET_FILE, file("atlas", "x.txt")).await.ok();
    world.team_a(GET_FILE, file("atlas", "x.txt")).await.ok();
    let sentence = world
        .team_a(GET_FILE, file("atlas", "x.txt"))
        .await
        .refusal();
    assert_eq!(sentence, team_over_quota(ENTRY, GET_FILE));
    world.settle().await;
    assert_eq!(world.last_outcome(GET_FILE), Outcome::Refused { sentence });
    assert_eq!(world.app.token_requests(), 2);
    // Team B's own quota is untouched.
    world.rest.file("cosmos", "x.txt", "x");
    world
        .call(TEAM_B, GET_FILE, file("cosmos", "x.txt"))
        .await
        .ok();
}

#[tokio::test]
async fn a_reload_that_changes_an_entry_is_refused() {
    let world = World::new().await;
    let widened = r#"{ contents = "read", issues = "read", pull_requests = "write" }"#;
    // Under the same revision, as the custodian refuses it too (#219).
    let same = Registry::from_toml_str(&registry_text("r1", "limit", widened)).unwrap();
    match world.reloader.apply(&same) {
        Err(ReloadError::RevisionUnchanged(revision)) => assert_eq!(revision.as_str(), "r1"),
        other => panic!("{other:?}"),
    }
    // Under a new revision: the connector was built with the entry as it was.
    let next = Registry::from_toml_str(&registry_text("r2", "limit", widened)).unwrap();
    assert!(matches!(
        world.reloader.apply(&next),
        Err(ReloadError::ConnectorsChanged)
    ));
    // An unchanged entry under a new revision is served.
    let same_entry = Registry::from_toml_str(&registry_text("r2", "limit", PERMISSIONS)).unwrap();
    assert_eq!(world.reloader.apply(&same_entry).unwrap().as_str(), "r2");
}

/// The deployment `world` wrote, loaded again, after `edit` rewrites its files.
fn reloaded(world: &World, edit: impl FnOnce(&std::path::Path)) -> gateway::Deployment {
    edit(&world.dir);
    gateway::Deployment::load(&world.dir.join("gateway.toml"), |_| None).unwrap()
}

async fn prepared(deployment: gateway::Deployment) -> Result<Prepared, StartError> {
    prepare(
        deployment,
        InstanceName::new("github-test"),
        Arc::new(SystemClock),
    )
    .await
}

/// `start::prepare` wires the GitHub connector from the deployment file's `[github]`, with the
/// bounds `[connectors.github-read]` sets for it.
#[tokio::test]
async fn the_gateway_starts_from_its_files_with_the_github_connector() {
    let world = World::with(Options {
        bounds: "[connectors.github-read]\ndeadline_seconds = 1\n",
        ..Options::default()
    })
    .await;
    world.rest.file("atlas", "x.txt", "from the files");
    let prepared = prepared(reloaded(&world, |_| {})).await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let answered = files::call_on(
        &path,
        github_world::SURFACE,
        &github_world::token(TEAM_A),
        GET_FILE,
        file("atlas", "x.txt"),
    )
    .await;
    assert_eq!(
        answered.body["result"]["structuredContent"]["file"]["text"], "from the files",
        "{}",
        answered.body
    );
    // The deployment file's deadline holds it.
    world.rest.set_mode(Mode::Late(Duration::from_secs(3)));
    let answered = files::call_on(
        &path,
        github_world::SURFACE,
        &github_world::token(TEAM_A),
        GET_FILE,
        file("atlas", "x.txt"),
    )
    .await;
    assert_eq!(
        answered.body["result"]["isError"], true,
        "{}",
        answered.body
    );
    assert_eq!(
        answered.body["result"]["content"][0]["text"],
        gateway::bound::LATE
    );
}

/// `start::prepare` holds the GitHub connector to the deployment file's `[limits]` quotas
/// (#217).
#[tokio::test]
async fn the_deployment_files_quotas_reach_the_github_connector() {
    let world = World::with(Options {
        bounds: "[limits]\nper_team_per_server_calls_per_minute = 1\nper_team_per_server_burst = 1\n",
        ..Options::default()
    })
    .await;
    world.rest.file("atlas", "x.txt", "x");
    let prepared = prepared(reloaded(&world, |_| {})).await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let token = github_world::token(TEAM_A);
    let call = || {
        files::call_on(
            &path,
            github_world::SURFACE,
            &token,
            GET_FILE,
            file("atlas", "x.txt"),
        )
    };
    let first = call().await;
    assert_eq!(first.body["result"]["isError"], false, "{}", first.body);
    let second = call().await;
    assert_eq!(
        second.body["error"]["message"],
        team_over_quota(ENTRY, GET_FILE),
        "{}",
        second.body
    );
    assert_eq!(world.app.token_requests(), 1);
}

#[tokio::test]
async fn a_github_entry_with_no_github_table_refuses_the_start() {
    let world = World::new().await;
    let deployment = reloaded(&world, |dir| {
        let text = std::fs::read_to_string(dir.join("gateway.toml")).unwrap();
        let start = text.find("[github]").unwrap();
        let end = text.find("[credentials]").unwrap();
        let text = format!("{}{}", &text[..start], &text[end..]);
        std::fs::write(dir.join("gateway.toml"), text).unwrap();
    });
    match prepared(deployment).await {
        Err(StartError::NoGitHubSettings(entries)) => {
            assert_eq!(entries, [ConnectorName::new(ENTRY)]);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_github_table_with_no_github_entry_refuses_the_start() {
    let world = World::new().await;
    let deployment = reloaded(&world, |dir| {
        // The entry keeps its permission set for the custodian, and declares no credential.
        let text = std::fs::read_to_string(dir.join("registry.toml")).unwrap();
        let start = text.find("credential = {").unwrap();
        let end = text.find("[[surfaces]]").unwrap();
        let mut text = format!("{}{}", &text[..start], &text[end..]);
        text.truncate(text.find("\n[[built_in_tools]]").unwrap());
        // The surface serves none of the tools, whichever the connector has.
        let surface = text.find("[[surfaces]]").unwrap();
        let from = surface + text[surface..].find("tools = [").unwrap();
        let to = from + text[from..].find(']').unwrap() + 1;
        text.replace_range(from..to, "tools = []");
        std::fs::write(dir.join("registry.toml"), text).unwrap();
    });
    match prepared(deployment).await {
        Err(StartError::GitHubUnused) => {}
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn bounds_for_an_entry_the_connector_does_not_serve_refuse_the_start() {
    let world = World::with(Options {
        bounds: "[connectors.github-other]\ndeadline_seconds = 1\n",
        ..Options::default()
    })
    .await;
    match prepared(reloaded(&world, |_| {})).await {
        Err(StartError::UnknownConnectorLimits(name)) => assert_eq!(name.as_str(), "github-other"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_approval_of_another_definition_than_the_connectors_refuses_the_start() {
    let world = World::new().await;
    let deployment = reloaded(&world, |dir| {
        let definition = connector_github::definitions()
            .into_iter()
            .find(|definition| definition.name == GET_FILE)
            .unwrap();
        let mut changed = definition.clone();
        changed.description = "Reads one file, and anything else it likes.";
        let text = std::fs::read_to_string(dir.join("registry.toml")).unwrap();
        assert_eq!(text.matches(definition.description).count(), 1);
        let text = text
            .replace(definition.description, changed.description)
            .replace(&definition.sha256(), &changed.sha256());
        std::fs::write(dir.join("registry.toml"), text).unwrap();
    });
    match prepared(deployment).await {
        Err(StartError::Boot(BootError::BuiltInDefinitionDiffers(tool))) => {
            assert_eq!(tool.as_str(), GET_FILE);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_unusable_github_table_refuses_the_start() {
    for (from, to, why) in [
        (
            "organization = \"example-org\"",
            "organization = \"example/org\"",
            "organization",
        ),
        (
            "api_url = \"http://127.0.0.1",
            "api_url = \"http://github.example",
            "URL",
        ),
        ("api_url = \"http://", "api_url = \"https://", "CA file"),
    ] {
        let world = World::new().await;
        let deployment = reloaded(&world, |dir| {
            let text = std::fs::read_to_string(dir.join("gateway.toml")).unwrap();
            assert!(text.contains(from), "{from}");
            std::fs::write(dir.join("gateway.toml"), text.replace(from, to)).unwrap();
        });
        match prepared(deployment).await {
            Err(StartError::GitHub(error)) => assert!(error.to_string().contains(why), "{error}"),
            other => panic!("{from}: {other:?}"),
        }
    }
}
