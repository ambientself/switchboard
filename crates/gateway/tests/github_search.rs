//! `github__search` end to end (#12, decision 0011), through the gateway's HTTP endpoint,
//! wired as `start` wires it (`github_world`): the query built as Otto's gateway builds it, the
//! results held to the caller's limit, and the repositories they came from recorded on the
//! call's row as what it reached, in place of the `unknown` a tool that checks its own scope is
//! begun with.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod github_world;
mod support;

use connector_github::fake::Mode;
use gateway_core::ErrorKind;
use gateway_core::audit::{DecisionKind, Outcome, RecordedResource, RecordedResources};
use github_world::{ACCOUNT, OTHER_ORG, SEARCH, TEAM_B, World};
use serde_json::{Value, json};

/// A result as GitHub's issue search gives one, from `repository`, with a body that must never
/// reach the caller.
fn item(repository: &str, number: u64) -> Value {
    json!({
        "number": number,
        "title": format!("Result {number}"),
        "state": "open",
        "body": "a body the search never returns",
        "html_url": format!("https://example.invalid/{repository}/issues/{number}"),
        "repository_url": format!("https://api.github.example/repos/{repository}"),
        "user": {"login": "someone"},
        "updated_at": "2026-10-01T00:00:00Z",
    })
}

fn in_org(repo: &str) -> String {
    format!("{ACCOUNT}/{repo}")
}

fn reached(identifiers: &[String]) -> RecordedResources {
    RecordedResources::Named(
        identifiers
            .iter()
            .map(|identifier| RecordedResource {
                system: "github".into(),
                kind: "repository".into(),
                identifier: identifier.clone(),
            })
            .collect(),
    )
}

fn query(text: &str) -> Value {
    json!({ "query": text })
}

/// What the query sent to GitHub's search asked, as sent.
fn sent(world: &World) -> Vec<String> {
    world
        .rest
        .requests()
        .into_iter()
        .filter(|request| request.path == "/search/issues")
        .map(|request| request.query)
        .collect()
}

#[tokio::test]
async fn a_search_returns_only_the_teams_repositories_and_records_them_as_reached() {
    let world = World::new().await;
    // GitHub's search answers from repositories the token was not narrowed to: another
    // repository of the organization, and another organization's, which team A's limit names
    // but this gateway does not serve.
    world.rest.search(
        12,
        vec![
            item(&in_org("atlas"), 1),
            item(&in_org("secret"), 2),
            item(&format!("{OTHER_ORG}/elsewhere"), 3),
            item(&in_org("borealis"), 4),
            item(&in_org("cosmos"), 5),
            item(&in_org("atlas"), 6),
        ],
    );
    let answered = world.team_a(SEARCH, query("is:open bug")).await;
    let result = answered.ok();
    let results = result["results"].as_array().unwrap();
    let repositories: Vec<&str> = results
        .iter()
        .map(|result| result["repository"].as_str().unwrap())
        .collect();
    assert_eq!(
        repositories,
        [in_org("atlas"), in_org("borealis"), in_org("atlas")]
    );
    assert_eq!(results[0]["number"], 1);
    assert_eq!(results[0]["title"], "Result 1");
    assert!(results.iter().all(|result| result.get("body").is_none()));
    assert_eq!(result["truncated"], true);
    assert_eq!(result["query"], "(is:open bug) org:example-org");
    assert_eq!(
        result["provenance"],
        json!({"tool": SEARCH, "source": "github", "classification": "read",
               "trust": "untrusted-external"})
    );
    assert!(!answered.raw.contains("never returns"), "{}", answered.raw);

    world.settle().await;
    let row = world.last_row(SEARCH);
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.resources,
        reached(&[in_org("atlas"), in_org("borealis")])
    );
    assert_eq!(row.resources_omitted, 0);
    assert_eq!(world.last_outcome(SEARCH), Outcome::Ok);

    // The token was narrowed to team A's repositories on the organization, as every call's is.
    let issued = world.app.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(
        issued[0].asked_repositories,
        Some(vec!["atlas".to_owned(), "borealis".to_owned()])
    );
    assert_eq!(
        world.rest.requests()[0].token.as_deref(),
        Some(issued[0].token.as_str())
    );

    // Team B reads only its own repository's results from the same answer.
    let answered = world.call(TEAM_B, SEARCH, query("bug")).await;
    let repositories: Vec<Value> = answered.ok()["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| result["repository"].clone())
        .collect();
    assert_eq!(repositories, [json!(in_org("cosmos"))]);
    world.settle().await;
    assert_eq!(
        world.last_row(SEARCH).resources,
        reached(&[in_org("cosmos")])
    );
}

#[tokio::test]
async fn a_search_that_returns_nothing_records_an_empty_reach() {
    let world = World::new().await;
    for items in [Vec::new(), vec![item(&in_org("secret"), 1)]] {
        world
            .rest
            .search(u64::try_from(items.len()).unwrap(), items);
        let result = world.team_a(SEARCH, query("nothing here")).await.ok();
        assert_eq!(result["results"], json!([]));
        assert_eq!(result["truncated"], false);
        world.settle().await;
        let row = world.last_row(SEARCH);
        assert_eq!(row.resources, RecordedResources::Named(Vec::new()));
        assert_eq!(row.resources_omitted, 0);
        assert_eq!(world.last_outcome(SEARCH), Outcome::Ok);
    }
}

#[tokio::test]
async fn the_query_is_built_as_otto_builds_it() {
    let world = World::new().await;
    for text in [
        "repo:outside/repo evidence",
        "(a OR b) label:\"needs review\"",
        "\"a ) b\"",
    ] {
        let result = world.team_a(SEARCH, query(text)).await.ok();
        assert_eq!(result["query"], format!("({text}) org:{ACCOUNT}"));
    }
    // Each is sent parenthesised, with the organization qualifier after it, for one page of
    // ten, with the advanced search engine.
    assert_eq!(
        sent(&world),
        [
            "q=%28repo%3Aoutside%2Frepo%20evidence%29%20org%3Aexample-org&per_page=10\
             &advanced_search=true",
            "q=%28%28a%20OR%20b%29%20label%3A%22needs%20review%22%29%20org%3Aexample-org\
             &per_page=10&advanced_search=true",
            "q=%28%22a%20%29%20b%22%29%20org%3Aexample-org&per_page=10&advanced_search=true",
        ]
    );
}

#[tokio::test]
async fn a_malformed_query_is_invalid_arguments_and_sends_nothing() {
    let world = World::new().await;
    for text in [
        "bug) OR (is:open",
        "(bug",
        "\"bug",
        "bug\nmore",
        " ",
        &"a".repeat(257),
    ] {
        let answered = world.team_a(SEARCH, query(text)).await;
        answered.tool_error();
        world.settle().await;
        assert_eq!(
            world.last_outcome(SEARCH),
            Outcome::Error {
                error_kind: ErrorKind::InvalidArguments
            },
            "{text:?}"
        );
        assert_eq!(world.last_row(SEARCH).resources, RecordedResources::Unknown);
    }
    assert_eq!(world.app.token_requests(), 0);
    assert!(world.rest.requests().is_empty());

    // A query GitHub itself cannot run is one too, and its row says nothing was reached.
    world.rest.set_mode(Mode::Status(422));
    let answered = world.team_a(SEARCH, query("is:nonsense")).await;
    let error = answered.tool_error();
    assert!(error.contains("HTTP 422"), "{error}");
    assert!(
        world
            .tokens()
            .iter()
            .all(|token| !answered.raw.contains(token.as_str())),
        "{}",
        answered.raw
    );
    world.settle().await;
    assert_eq!(
        world.last_outcome(SEARCH),
        Outcome::Error {
            error_kind: ErrorKind::InvalidArguments
        }
    );
    assert_eq!(world.last_row(SEARCH).resources, RecordedResources::Unknown);
}

#[tokio::test]
async fn a_qualifier_naming_another_organization_is_refused_before_any_request() {
    let world = World::new().await;
    for text in ["org:outside evidence", "evidence (user:someone)"] {
        let answered = world.team_a(SEARCH, query(text)).await;
        let sentence = answered.refusal();
        assert!(
            sentence.ends_with(&format!(
                "is not this gateway's configured org \"{ACCOUNT}\""
            )),
            "{sentence}"
        );
        world.settle().await;
        assert_eq!(world.last_outcome(SEARCH), Outcome::Refused { sentence });
        assert_eq!(world.last_row(SEARCH).resources, RecordedResources::Unknown);
    }
    assert_eq!(world.app.token_requests(), 0);
    assert!(world.rest.requests().is_empty());
}
