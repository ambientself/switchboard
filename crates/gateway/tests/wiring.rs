//! The gateway built from files, as the `switchboard` binary builds it, forwarding to the mock
//! docs server on loopback: tools listed from the approved definitions, an allowed read
//! forwarded with the gateway's own credential, a read outside the team's limit denied by the
//! gateway, undeclared arguments refused before anything is sent, a registry reload, and every
//! boot refusal of the wiring.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use files::{
    AUDIENCE, Files, LIST_TOOL, READ_TOOL, SURFACE, TEAM_A_SA, TEAM_B_SA, call, cluster_issuer,
    kubernetes_token, listed, registry, rpc,
};
use gateway::path::RequestPath;
use gateway::start::{Prepared, StartError, prepare};
use gateway::{ReloadError, undeclared_argument};
use gateway_core::IDENTITY_FAILURE;
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::LocalIssuer;
use mock_docs_server::{AcceptedCredential, Config};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

fn token(subject: &str) -> String {
    kubernetes_token(issuer(), subject, &[AUDIENCE])
}

/// The first 12 hex digits of a bearer's SHA-256, as the mock server logs them.
fn logged(bearer: &str) -> String {
    let digest = Sha256::digest(bearer.as_bytes());
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct World {
    mock: mock_docs_server::Running,
    files: Files,
}

impl World {
    async fn new(name: &str) -> Self {
        let mock =
            mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
                .await
                .unwrap();
        let files = Files::new(name, &issuer().jwks_document(), &mock.url());
        Self { mock, files }
    }

    async fn prepare(&self) -> Result<Prepared, StartError> {
        prepare(self.files.load(), Arc::new(SystemClock)).await
    }

    /// The bearers the mock server has received, as logged prefixes.
    fn bearers(&self) -> Vec<String> {
        self.mock
            .log_lines()
            .iter()
            .filter_map(|line| line["bearer_sha256"].as_str().map(str::to_owned))
            .collect()
    }

    /// How many `tools/call` requests reached the mock server.
    fn calls(&self) -> usize {
        self.mock
            .log_lines()
            .iter()
            .filter(|line| line["rpc_method"] == json!("tools/call"))
            .count()
    }
}

fn text(answer: &Value) -> String {
    answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{answer}"))
        .to_owned()
}

#[tokio::test]
async fn an_allowed_read_is_forwarded_with_the_gateways_credential_only() {
    let world = World::new("allowed").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    let team_a = token(TEAM_A_SA);

    let initialized = rpc(
        &path,
        Some(&team_a),
        "initialize",
        json!({
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "wiring-test", "version": "0"}}),
    )
    .await;
    assert_eq!(initialized.status, 200, "{}", initialized.body);
    // Listed from the approved definitions, without asking the server.
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL, READ_TOOL]);
    assert!(
        world.mock.log_lines().is_empty(),
        "{:?}",
        world.mock.log_lines()
    );

    let read = call(
        &path,
        &team_a,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    assert_eq!(read.status, 200);
    assert_eq!(
        read.body["result"]["isError"],
        json!(false),
        "{}",
        read.body
    );
    assert!(
        text(&read.body).contains("The atlas plan."),
        "{}",
        read.body
    );
    let listing = call(&path, &team_a, LIST_TOOL, json!({"project": "atlas"})).await;
    assert_eq!(
        listing.body["result"]["isError"],
        json!(false),
        "{}",
        listing.body
    );

    let team_b = token(TEAM_B_SA);
    let read = call(
        &path,
        &team_b,
        READ_TOOL,
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert!(
        text(&read.body).contains("The borealis plan."),
        "{}",
        read.body
    );

    // Every request the server saw carried the gateway's credential, and no caller's token.
    let bearers = world.bearers();
    assert_eq!(bearers.len(), 3, "{bearers:?}");
    assert!(
        bearers
            .iter()
            .all(|bearer| *bearer == logged(files::CREDENTIAL)),
        "{bearers:?}"
    );
    assert!(!bearers.contains(&logged(&team_a)));
    assert!(!bearers.contains(&logged(&team_b)));
}

#[tokio::test]
async fn a_read_outside_the_teams_limit_is_denied_by_the_gateway_and_never_sent() {
    let world = World::new("denied").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    let team_a = token(TEAM_A_SA);

    let other = call(
        &path,
        &team_a,
        READ_TOOL,
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert_eq!(other.status, 200);
    assert_eq!(other.body["error"]["code"], json!(-32001), "{}", other.body);
    let sentence = other.body["error"]["message"].as_str().unwrap();
    assert!(
        sentence.starts_with(
            "Tool `docs__read_document` names docs project `borealis`, which is outside what"
        ),
        "{sentence}"
    );
    assert!(
        sentence.ends_with("Name only resources within that limit."),
        "{sentence}"
    );
    assert!(
        sentence.contains("`borealis`") && sentence.contains(TEAM_A_SA),
        "{sentence}"
    );

    // A call that names no project names no resource, which check 6 denies.
    let none = call(&path, &team_a, READ_TOOL, json!({"document": "plan"})).await;
    assert_eq!(none.body["error"]["code"], json!(-32001), "{}", none.body);
    let none = call(
        &path,
        &team_a,
        READ_TOOL,
        json!({"project": 7, "document": "plan"}),
    )
    .await;
    assert_eq!(none.body["error"]["code"], json!(-32001), "{}", none.body);

    assert_eq!(world.calls(), 0, "{:?}", world.mock.log_lines());
}

#[tokio::test]
async fn an_argument_the_approved_schema_does_not_declare_is_refused_before_it_is_sent() {
    let world = World::new("undeclared").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    let team_a = token(TEAM_A_SA);
    for arguments in [
        json!({"project": "atlas", "document": "plan", "include_drafts": true}),
        json!({"project": "atlas", "limit": 5}),
    ] {
        let tool = if arguments.get("document").is_some() {
            READ_TOOL
        } else {
            LIST_TOOL
        };
        let refused = call(&path, &team_a, tool, arguments.clone()).await;
        assert_eq!(refused.status, 200);
        assert_eq!(
            refused.body["error"]["message"],
            json!(undeclared_argument(tool)),
            "{arguments}: {}",
            refused.body
        );
    }
    assert_eq!(world.calls(), 0, "{:?}", world.mock.log_lines());
}

#[tokio::test]
async fn identity_is_checked_before_anything_else() {
    let world = World::new("identity").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    for bad in [None, Some("not-a-token")] {
        let answered = rpc(&path, bad, "tools/list", json!({})).await;
        assert_eq!(answered.status, 401);
        assert_eq!(answered.body["error"]["message"], json!(IDENTITY_FAILURE));
    }
    let stranger = token(files::STRANGER_SA);
    let answered = call(
        &path,
        &stranger,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    assert_eq!(answered.status, 401);
    assert_eq!(world.calls(), 0);
}

#[tokio::test]
async fn a_new_registry_file_is_served_once_it_passes_and_refused_otherwise() {
    let world = World::new("reload").await;
    let prepared = world.prepare().await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let reloader = prepared.watch.reloader;
    let team_a = token(TEAM_A_SA);
    let original = registry(&world.mock.url());

    // Withdraw the read tool: revision demo-2, the approval and the surface entry removed.
    let withdrawn = withdraw_read_tool(&original);
    let revision = reloader
        .apply(&Registry::from_toml_str(&withdrawn).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), "demo-2");
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL]);
    let gone = call(
        &path,
        &team_a,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    assert_eq!(
        gone.body["error"]["message"],
        json!(format!(
            "Tool `{READ_TOOL}` is not available on surface `{SURFACE}`. Call `tools/list` to see the tools this surface serves."
        ))
    );

    // Back again.
    reloader
        .apply(&Registry::from_toml_str(&original).unwrap())
        .unwrap();
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL, READ_TOOL]);

    // A changed server needs a restart.
    let moved = original.replace(&world.mock.url(), "http://127.0.0.1:9/mcp");
    let refused = reloader
        .apply(&Registry::from_toml_str(&moved).unwrap())
        .unwrap_err();
    assert!(matches!(refused, ReloadError::ServersChanged), "{refused}");
    // So does a tool routed to an upstream tool the connector was not built for.
    let rerouted = original.replace(
        "upstream_name = \"list_documents\"",
        "upstream_name = \"search_documents\"",
    );
    let rerouted = rerouted.replace(
        "453ea692bdf92bc95d262085a1f6b3a54c25ac3d132e844029a49ff5ffaf536d",
        &gateway_registry::definition_sha256(
            "search_documents",
            Some("List documents"),
            "Lists the documents in one project.",
            &json!({"type": "object", "required": ["project"], "additionalProperties": false,
                    "properties": {"project": {"type": "string", "description": "The project, such as `atlas`."}}}),
        ),
    );
    let refused = reloader
        .apply(&Registry::from_toml_str(&rerouted).unwrap())
        .unwrap_err();
    assert!(
        matches!(&refused, ReloadError::RouteChanged(tool) if tool.as_str() == LIST_TOOL),
        "{refused}"
    );
    // And a rule for an issuer the gateway does not trust fails the boot gate.
    let untrusted = original.replace(
        "issuer = \"https://kubernetes.default.svc.cluster.local\"",
        "issuer = \"https://other.example.test\"",
    );
    let refused = reloader
        .apply(&Registry::from_toml_str(&untrusted).unwrap())
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("not a configured workload issuer"),
        "{refused}"
    );
    // Every refusal kept the policy served before.
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL, READ_TOOL]);
}

#[tokio::test]
async fn the_watcher_serves_a_replaced_file_and_keeps_the_old_policy_on_a_broken_one() {
    let world = World::new("watch").await;
    let prepared = world.prepare().await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let watching = tokio::spawn(prepared.watch.run());
    let team_a = token(TEAM_A_SA);
    let original = registry(&world.mock.url());

    // Replaced by a rename, as demo.sh does.
    let swap = |text: &str| {
        world.files.write("registry/.next.toml", text);
        std::fs::rename(
            world.files.path("registry/.next.toml"),
            world.files.path("registry/registry.toml"),
        )
        .unwrap();
    };
    swap(&withdraw_read_tool(&original));
    wait_for(&path, &team_a, &[LIST_TOOL]).await;

    swap("revision = \"broken\"\n");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        listed(&path, &team_a).await,
        [LIST_TOOL],
        "a broken file replaced the policy"
    );

    swap(&original);
    wait_for(&path, &team_a, &[LIST_TOOL, READ_TOOL]).await;
    watching.abort();
}

async fn wait_for(path: &RequestPath, token: &str, tools: &[&str]) {
    for _ in 0..50 {
        if listed(path, token).await == tools {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "tools/list never became {tools:?}: {:?}",
        listed(path, token).await
    );
}

/// The registry without the read tool, at revision demo-2.
fn withdraw_read_tool(registry: &str) -> String {
    let start = registry
        .find("[[tools]]\nname = \"docs__read_document\"")
        .unwrap();
    let end = start + registry[start..].find("# --- Surfaces").unwrap();
    let mut withdrawn = format!("{}{}", &registry[..start], &registry[end..]);
    withdrawn = withdrawn.replace("revision = \"demo-1\"", "revision = \"demo-2\"");
    withdrawn.replace(
        "tools = [\"docs__list_documents\", \"docs__read_document\"]",
        "tools = [\"docs__list_documents\"]",
    )
}

#[tokio::test]
async fn the_wiring_refuses_to_start_on_what_it_cannot_serve() {
    let world = World::new("refusals").await;
    let deployment = files::deployment_file("[audit]\nmode = \"disabled\"\n");

    // A server's credential reference with no file.
    world.files.write(
        "gateway.toml",
        &deployment.replace(
            "docs-credential = \"docs-credential\"",
            "other = \"docs-credential\"",
        ),
    );
    let said = refused(&world).await;
    assert!(said.contains("uses credential `docs-credential`"), "{said}");
    // A credential file no server uses.
    world.files.write(
        "gateway.toml",
        &deployment.replace(
            "docs-credential = \"docs-credential\"",
            "docs-credential = \"docs-credential\"\nspare = \"docs-credential\"",
        ),
    );
    let said = refused(&world).await;
    assert!(said.contains("`spare`"), "{said}");
    world.files.write("gateway.toml", &deployment);
    // An empty credential file.
    world.files.write("docs-credential", "\n");
    let said = refused(&world).await;
    assert!(said.contains("is empty"), "{said}");
    world.files.write("docs-credential", files::CREDENTIAL);
    // A server the proxy cannot reach over plain HTTP.
    world.files.write(
        "registry/registry.toml",
        &registry("https://mock-docs.example.test/mcp"),
    );
    let said = refused(&world).await;
    assert!(said.contains("must be http://"), "{said}");
    // A registry that does not load.
    world
        .files
        .write("registry/registry.toml", "revision = \"demo-1\"\n");
    let said = refused(&world).await;
    assert!(said.contains("does not parse"), "{said}");
    std::fs::remove_file(world.files.path("registry/registry.toml")).unwrap();
    let said = refused(&world).await;
    assert!(said.contains("could not read the registry file"), "{said}");
    // A rule for an issuer the deployment does not trust.
    world.files.write(
        "registry/registry.toml",
        &registry(&world.mock.url()).replace(
            "issuer = \"https://kubernetes.default.svc.cluster.local\"",
            "issuer = \"https://other.example.test\"",
        ),
    );
    let said = refused(&world).await;
    assert!(said.contains("not a configured workload issuer"), "{said}");
    world
        .files
        .write("registry/registry.toml", &registry(&world.mock.url()));
    // An audit database that cannot be reached: refused, not served without audit.
    world.files.write(
        "gateway.toml",
        &files::deployment_file(
            "[audit]\nmode = \"postgres\"\nurl_env = \"WIRING_TEST_DATABASE_URL\"\n",
        ),
    );
    let deployment = world
        .files
        .load_with(&[(
            "WIRING_TEST_DATABASE_URL",
            "postgres://switchboard_gateway:dummy@127.0.0.1:1/switchboard?connect_timeout=2",
        )])
        .unwrap();
    let said = prepare(deployment, Arc::new(SystemClock))
        .await
        .unwrap_err()
        .to_string();
    assert!(said.contains("the audit store will not start"), "{said}");
    let deployment = world
        .files
        .load_with(&[("WIRING_TEST_DATABASE_URL", "not a url at all")])
        .unwrap();
    let said = prepare(deployment, Arc::new(SystemClock))
        .await
        .unwrap_err()
        .to_string();
    assert!(said.contains("does not parse"), "{said}");
}

/// Why the gateway in `world` refuses to start.
async fn refused(world: &World) -> String {
    world.prepare().await.unwrap_err().to_string()
}
