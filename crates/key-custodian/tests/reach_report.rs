//! The one request that may name no repository: a reach report's, for `metadata: read` alone
//! (decision 0011, section 4). It gets an installation-wide token; no other tool or permission
//! does.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{World, scratch, write_file};
use gateway_core::{ErrorKind, PolicyRevision, TeamId, ToolName};
use gateway_registry::Access;
use key_custodian::{ClientError, Refusal, TokenRequest};

const REPORT_TOOL: &str = "github__list_installation_repositories";

/// A registry with a reach-report entry stating more than `metadata: read`, so that only the
/// exception's own rule holds a request to it; a read entry and an entry narrowed `none` but not
/// declared a reach report, each stating `metadata: read` too; and the registry's team.
const REGISTRY: &str = r#"revision = "r1"
servers = []
tools = []
surfaces = []
profiles = []
profile_rules = []

[[connectors]]
name = "github-reach-report"
system = "github"
permissions = { metadata = "read", contents = "read" }
tools = ["github__list_installation_repositories"]
credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "read"
reports_reach = true

[[connectors]]
name = "github-read"
system = "github"
permissions = { metadata = "read", issues = "read" }
tools = ["github__get_issue"]

[[connectors]]
name = "github-unflagged"
system = "github"
permissions = { metadata = "read" }
tools = ["github__list_everything"]
credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "read"

[limits.teams]
registry = []
team-a = [{ system = "github", kind = "repository", identifier = "example-org/atlas" }]
"#;

/// A custodian serving [`REGISTRY`].
async fn world() -> (World, std::path::PathBuf) {
    let dir = scratch();
    let registry = dir.join("reach-registry.toml");
    write_file(&registry, REGISTRY, 0o644);
    let path = registry.clone();
    let world = World::with(move |config| config.registry = path).await;
    (world, dir)
}

/// The registry team's installation-wide request for `tool` with `permissions`.
fn request(tool: &str, permissions: &[(&str, Access)]) -> TokenRequest {
    TokenRequest {
        team: TeamId::new("registry"),
        tool: ToolName::parse(tool).unwrap(),
        repositories: Vec::new(),
        permissions: permissions
            .iter()
            .map(|(name, level)| ((*name).to_owned(), *level))
            .collect(),
        revision: PolicyRevision::new("r1"),
    }
}

#[tokio::test]
async fn a_reach_reports_request_gets_an_installation_wide_metadata_read_token() {
    let (world, dir) = world().await;
    let token = world
        .client
        .token(&request(REPORT_TOOL, &[("metadata", Access::Read)]))
        .await
        .unwrap();
    let issued = world.fake.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(token.expose(), issued[0].token);
    assert_eq!(
        issued[0].asked_repositories, None,
        "GitHub is asked for the installation's whole list"
    );
    assert_eq!(
        issued[0].asked_permissions,
        Some(BTreeMap::from([("metadata".to_owned(), "read".to_owned())])),
        "and for metadata: read alone"
    );
    assert_eq!(issued[0].repositories, world.fake.installed());
    let line = world.record.lines().pop().unwrap();
    assert_eq!(line["outcome"], "issued", "{line}");
    assert_eq!(line["repository_count"], 0, "{line}");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn no_other_tool_or_permission_may_name_no_repository() {
    let (world, dir) = world().await;
    let cases = [
        (
            "another entry's tool, for metadata: read",
            request("github__get_issue", &[("metadata", Access::Read)]),
        ),
        (
            "an entry narrowed none that is not declared a reach report",
            request("github__list_everything", &[("metadata", Access::Read)]),
        ),
        (
            "the reach report's tool, for more than metadata: read",
            request(
                REPORT_TOOL,
                &[("metadata", Access::Read), ("contents", Access::Read)],
            ),
        ),
        (
            "the reach report's tool, for another permission",
            request(REPORT_TOOL, &[("contents", Access::Read)]),
        ),
    ];
    for (case, asked) in &cases {
        let error = world.client.token(asked).await.unwrap_err();
        match &error {
            ClientError::Refused { reason, .. } => {
                assert_eq!(*reason, Refusal::NoRepositories, "{case}: {error}");
            }
            other => panic!("{case}: not a refusal: {other:?}"),
        }
        assert_eq!(error.error_kind(), ErrorKind::CustodianRefusal, "{case}");
    }
    assert_eq!(
        world.fake.token_requests(),
        0,
        "no refused request reached GitHub"
    );
    // The reach report's tool asking for a repository is checked as any request is: against
    // its team's limit, which holds none for the registry.
    let mut named = request(REPORT_TOOL, &[("metadata", Access::Read)]);
    named.repositories = vec!["example-org/atlas".into()];
    let error = world.client.token(&named).await.unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::Refused {
                reason: Refusal::RepositoryOutsideLimit,
                ..
            }
        ),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
