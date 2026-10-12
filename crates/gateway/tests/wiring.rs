//! The gateway built from files, as the `switchboard` binary builds it, forwarding to the mock
//! docs server on loopback: tools listed from the approved definitions, an allowed read
//! forwarded with the gateway's own credential for the team's entry, a team kept to its own
//! surface, a read outside the team's limit denied by the
//! gateway, undeclared arguments and arguments that do not match the approved schema an error
//! with nothing sent, a registry reload, and every boot refusal of the wiring.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use files::{
    AUDIENCE, Files, KIND_REVISION, LIST_TOOL, READ_TOOL, SURFACE, TEAM_A_SA, TEAM_B_LIST_TOOL,
    TEAM_B_READ_TOOL, TEAM_B_SA, TEAM_B_SURFACE, call, call_on, cluster_issuer, kubernetes_token,
    listed, listed_on, registry, rpc,
};
use gateway::path::RequestPath;
use gateway::start::{Prepared, StartError, prepare};
use gateway::{ReloadError, invalid_argument, undeclared_argument};
use gateway_core::IDENTITY_FAILURE;
use gateway_identity::SystemClock;
use gateway_registry::{Registry, RegistryError};
use gateway_testkit::LocalIssuer;
use mock_docs_server::Config;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The list tool's approved `definition_sha256` in the kind registry.
const LIST_TOOL_SHA256: &str = "0ed6da7bfe2db038137f2a650ca17903fcd52f542e4769d37327c21e4beec86a";

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
        let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
            .await
            .unwrap();
        let files = Files::new(name, &issuer().jwks_document(), &mock.url());
        Self { mock, files }
    }

    async fn prepare(&self) -> Result<Prepared, StartError> {
        prepare(
            self.files.load(),
            gateway_core::InstanceName::new("test-instance"),
            Arc::new(SystemClock),
        )
        .await
    }

    /// The bearers the mock server has accepted, as logged prefixes, on every request but the
    /// drift pass's tool lists.
    fn bearers(&self) -> Vec<String> {
        self.mock
            .log_lines()
            .iter()
            .filter(|line| line["accepted"] == json!(true))
            .filter(|line| line["rpc_method"] != json!("tools/list"))
            .filter_map(|line| line["bearer_sha256"].as_str().map(str::to_owned))
            .collect()
    }

    /// The tool lists the mock server has answered: the drift pass's, each with its entry's
    /// credential, as logged prefixes.
    fn lists(&self) -> Vec<String> {
        self.mock
            .log_lines()
            .iter()
            .filter(|line| line["rpc_method"] == json!("tools/list"))
            .filter_map(|line| line["bearer_sha256"].as_str().map(str::to_owned))
            .collect()
    }

    /// The requests the mock server refused: the drift pass's probe calls, each logged with the
    /// prefix of the bearer it carried, if any.
    fn refused(&self) -> Vec<Option<String>> {
        self.mock
            .log_lines()
            .iter()
            .filter(|line| line["event"] == json!("request") && line["accepted"] == json!(false))
            .map(|line| line["bearer_sha256"].as_str().map(str::to_owned))
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
    // Before serving, the first drift pass read each entry's tool list once, with that entry's
    // credential, and probed each entry: three calls the server refused, with no credential, a
    // malformed one and the probe's, never the gateway's. Nothing else.
    let mut lists = world.lists();
    lists.sort();
    let mut entries = vec![logged(files::CREDENTIAL), logged(files::TEAM_B_CREDENTIAL)];
    entries.sort();
    assert_eq!(lists, entries);
    let mut refused = world.refused();
    refused.sort();
    let probe = |bearer: Option<&str>| bearer.map(logged);
    let each = vec![
        probe(None),
        probe(Some(connector_proxy::MALFORMED_CREDENTIAL)),
        probe(Some(files::PROBE_CREDENTIAL)),
    ];
    let mut probes = [each.clone(), each].concat();
    probes.sort();
    assert_eq!(refused, probes);
    assert_eq!(
        world.mock.log_lines().len(),
        2 + 6,
        "{:?}",
        world.mock.log_lines()
    );
    // Listed from the approved definitions, without asking the server.
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL, READ_TOOL]);
    assert_eq!(
        world.mock.log_lines().len(),
        2 + 6,
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
    // The server's own content, as it sent it: one text block, not its whole result wrapped in
    // another as JSON text.
    assert_eq!(
        read.body["result"]["content"],
        json!([{
            "type": "text",
            "text": "The atlas plan. This text belongs to project atlas and to no other."
        }]),
        "{}",
        read.body
    );
    assert!(
        read.body["result"].get("structuredContent").is_none(),
        "the server gave no structured content: {}",
        read.body
    );
    let listing = call(&path, &team_a, LIST_TOOL, json!({"project": "atlas"})).await;
    assert_eq!(
        listing.body["result"]["isError"],
        json!(false),
        "{}",
        listing.body
    );
    let structured = &listing.body["result"]["structuredContent"];
    assert_eq!(structured["project"], json!("atlas"), "{}", listing.body);
    assert_eq!(
        listing.body["result"]["content"],
        json!([{"type": "text", "text": structured.to_string()}]),
        "{}",
        listing.body
    );
    // A tool error is passed on as one: isError, with the server's text.
    let missing = call(
        &path,
        &team_a,
        READ_TOOL,
        json!({"project": "atlas", "document": "no-such-document"}),
    )
    .await;
    assert_eq!(
        missing.body["result"],
        json!({
            "content": [{
                "type": "text",
                "text": "There is no document `no-such-document` in project `atlas`."
            }],
            "isError": true
        }),
        "{}",
        missing.body
    );

    // Team B, on its own surface, through its own entry.
    let team_b = token(TEAM_B_SA);
    assert_eq!(
        listed_on(&path, TEAM_B_SURFACE, &team_b).await,
        [TEAM_B_LIST_TOOL, TEAM_B_READ_TOOL]
    );
    let read = call_on(
        &path,
        TEAM_B_SURFACE,
        &team_b,
        TEAM_B_READ_TOOL,
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert!(
        text(&read.body).contains("The borealis plan."),
        "{}",
        read.body
    );

    // Every request the server saw carried the gateway's credential for the caller's team's
    // entry, and no caller's token: team A's three calls docs-team-a's, team B's docs-team-b's.
    let bearers = world.bearers();
    let (a, b) = (logged(files::CREDENTIAL), logged(files::TEAM_B_CREDENTIAL));
    assert_eq!(bearers, [a.clone(), a.clone(), a, b], "{bearers:?}");
    assert!(!bearers.contains(&logged(&team_a)));
    assert!(!bearers.contains(&logged(&team_b)));
}

#[tokio::test]
async fn each_team_is_kept_to_its_own_surface() {
    let world = World::new("own-surface").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    for (caller, surface, tool) in [
        (TEAM_A_SA, TEAM_B_SURFACE, TEAM_B_READ_TOOL),
        (TEAM_B_SA, SURFACE, READ_TOOL),
    ] {
        let caller = token(caller);
        assert!(listed_on(&path, surface, &caller).await.is_empty());
        let refused = call_on(
            &path,
            surface,
            &caller,
            tool,
            json!({"project": "atlas", "document": "plan"}),
        )
        .await;
        assert_eq!(
            refused.body["error"]["code"],
            json!(-32001),
            "{}",
            refused.body
        );
    }
    assert_eq!(world.calls(), 0, "{:?}", world.mock.log_lines());
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
            "Tool `docs-team-a__read_document` names docs project `borealis`, which is outside what"
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
async fn an_argument_the_approved_schema_does_not_declare_is_an_error_and_is_not_sent() {
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
        let failed = call(&path, &team_a, tool, arguments.clone()).await;
        assert_eq!(failed.status, 200);
        assert_eq!(
            failed.body["result"]["isError"],
            json!(true),
            "{arguments}: {}",
            failed.body
        );
        assert_eq!(
            failed.body["result"]["content"][0]["text"],
            json!(undeclared_argument(tool)),
            "{arguments}: {}",
            failed.body
        );
        assert!(
            failed.body.get("error").is_none(),
            "{arguments}: {}",
            failed.body
        );
    }
    assert_eq!(world.calls(), 0, "{:?}", world.mock.log_lines());
}

#[tokio::test]
async fn arguments_that_do_not_match_the_approved_schema_are_an_error_and_are_not_sent() {
    let world = World::new("invalid").await;
    let path = RequestPath::new(world.prepare().await.unwrap().gates);
    let team_a = token(TEAM_A_SA);
    // Each names `atlas`, within team-a's limit, so each is allowed and reaches the check.
    for arguments in [
        // `document` is typed as a string.
        json!({"project": "atlas", "document": 7}),
        json!({"project": "atlas", "document": ["plan"]}),
        // `document` is required.
        json!({"project": "atlas"}),
    ] {
        let failed = call(&path, &team_a, READ_TOOL, arguments.clone()).await;
        assert_eq!(failed.status, 200);
        assert_eq!(
            failed.body["result"]["isError"],
            json!(true),
            "{arguments}: {}",
            failed.body
        );
        assert_eq!(
            failed.body["result"]["content"][0]["text"],
            json!(invalid_argument(READ_TOOL)),
            "{arguments}: {}",
            failed.body
        );
        assert!(
            failed.body.get("error").is_none(),
            "{arguments}: {}",
            failed.body
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

    // Withdraw team A's read tool: revision demo-2, the approval and the surface entry removed.
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

    // A server entry changed without its tools approved again does not load, so no reload
    // serves it.
    let unapproved = original.replace(&world.mock.url(), "http://127.0.0.1:9/mcp");
    let refused = Registry::from_toml_str(&unapproved).unwrap_err();
    assert!(
        matches!(&refused, RegistryError::BindingChanged { server, .. } if server.as_str() == "docs-team-a"),
        "{refused}"
    );
    // Approved again, a changed server still needs a restart.
    let moved = files::rebind(&original, "http://127.0.0.1:9/mcp");
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
        LIST_TOOL_SHA256,
        &gateway_registry::definition_sha256(
            "search_documents",
            None,
            "List the names of the documents in one project.",
            &json!({"type": "object", "required": ["project"], "additionalProperties": false,
                    "properties": {"project": {"type": "string"}}}),
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
async fn a_new_registry_file_that_changes_the_policy_but_not_its_revision_is_refused() {
    let world = World::new("same-revision").await;
    let prepared = world.prepare().await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let reloader = prepared.watch.reloader;
    let team_a = token(TEAM_A_SA);
    let original = registry(&world.mock.url());

    // The read tool withdrawn and a limit changed, both still under the kind registry's
    // revision. The limit is widened: narrowed below team B's entry's reach, rule 5 would
    // refuse it first.
    let withdrawn = withdraw_read_tool(&original).replace(
        "revision = \"demo-2\"",
        &format!("revision = \"{KIND_REVISION}\""),
    );
    let widened = original.replace(
        "team-b = [{ system = \"docs\", kind = \"project\", identifier = \"borealis\" }]",
        "team-b = [{ system = \"docs\", kind = \"project\", identifier = \"borealis\" }, \
         { system = \"docs\", kind = \"project\", identifier = \"cygnus\" }]",
    );
    assert_ne!(widened, original);
    for changed in [withdrawn, widened] {
        let refused = reloader
            .apply(&Registry::from_toml_str(&changed).unwrap())
            .unwrap_err();
        assert!(
            matches!(&refused, ReloadError::RevisionUnchanged(revision) if revision.as_str() == KIND_REVISION),
            "{refused}"
        );
        assert!(
            refused.to_string().contains(&format!("`{KIND_REVISION}`")),
            "{refused}"
        );
    }
    // The policy served before stays.
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL, READ_TOOL]);
    let team_b = token(TEAM_B_SA);
    let read = call_on(
        &path,
        TEAM_B_SURFACE,
        &team_b,
        TEAM_B_READ_TOOL,
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert!(read.body["result"].is_object(), "{}", read.body);

    // The same policy under the same revision, with only a comment changed, is fine.
    let commented = original.replace(
        "# Recorded with every decision made from this file.",
        "# Recorded with every decision made from this file, as the row's policy_revision.",
    );
    assert_ne!(commented, original);
    let revision = reloader
        .apply(&Registry::from_toml_str(&commented).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), KIND_REVISION);

    // And a changed policy under a new revision is served.
    let revision = reloader
        .apply(&Registry::from_toml_str(&withdraw_read_tool(&original)).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), "demo-2");
    assert_eq!(listed(&path, &team_a).await, [LIST_TOOL]);
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

/// Decision 0013, section 8: removing an approval withdraws the tool on reload. That holds for
/// the tool team A's reach check names, and for the entry's last tool, with the entry and its
/// reach check left as they are.
#[tokio::test]
async fn the_reach_check_tool_and_an_entrys_last_tool_are_withdrawn_by_reload() {
    let world = World::new("reload-last").await;
    let prepared = world.prepare().await.unwrap();
    let path = RequestPath::new(prepared.gates);
    let reloader = prepared.watch.reloader;
    let team_a = token(TEAM_A_SA);
    let original = registry(&world.mock.url());
    let check = format!("[servers.reach_check]\ntool = \"{LIST_TOOL}\"");
    assert_eq!(
        original.matches(&check).count(),
        1,
        "the reach check names the list tool"
    );

    // The list tool, which the reach check names: the approval and the surface entry removed.
    let without_list = without_tool(&original, LIST_TOOL)
        .replace(
            &format!("revision = \"{KIND_REVISION}\""),
            "revision = \"demo-2\"",
        )
        .replace(
            &format!("tools = [\"{LIST_TOOL}\", \"{READ_TOOL}\"]"),
            &format!("tools = [\"{READ_TOOL}\"]"),
        );
    let revision = reloader
        .apply(&Registry::from_toml_str(&without_list).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), "demo-2");
    assert_eq!(listed(&path, &team_a).await, [READ_TOOL]);

    // Then the entry's last tool too, leaving the entry registered with nothing to serve.
    let without_both = without_tool(&without_list, READ_TOOL)
        .replace("revision = \"demo-2\"", "revision = \"demo-3-empty\"")
        .replace(&format!("tools = [\"{READ_TOOL}\"]"), "tools = []");
    let revision = reloader
        .apply(&Registry::from_toml_str(&without_both).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), "demo-3-empty");
    assert_eq!(listed(&path, &team_a).await, Vec::<String>::new());
    assert_eq!(
        listed_on(&path, TEAM_B_SURFACE, &token(TEAM_B_SA)).await,
        [TEAM_B_LIST_TOOL, TEAM_B_READ_TOOL]
    );
    assert_eq!(world.calls(), 0);
}

/// The registry without the approval of `tool`, which is followed by another approval.
fn without_tool(registry: &str, tool: &str) -> String {
    let start = registry
        .find(&format!("[[tools]]\nname = \"{tool}\""))
        .unwrap();
    let end = start + 1 + registry[start + 1..].find("[[tools]]").unwrap();
    format!("{}{}", &registry[..start], &registry[end..])
}

/// The registry without team A's read tool, at revision demo-2.
fn withdraw_read_tool(registry: &str) -> String {
    let start = registry
        .find(&format!("[[tools]]\nname = \"{READ_TOOL}\""))
        .unwrap();
    let end = start + 1 + registry[start + 1..].find("[[tools]]").unwrap();
    let mut withdrawn = format!("{}{}", &registry[..start], &registry[end..]);
    let revision = format!("revision = \"{KIND_REVISION}\"");
    assert_eq!(withdrawn.matches(&revision).count(), 1);
    withdrawn = withdrawn.replace(&revision, "revision = \"demo-2\"");
    let tools = format!("tools = [\"{LIST_TOOL}\", \"{READ_TOOL}\"]");
    assert_eq!(withdrawn.matches(&tools).count(), 1);
    withdrawn.replace(&tools, &format!("tools = [\"{LIST_TOOL}\"]"))
}

#[tokio::test]
async fn the_wiring_refuses_to_start_on_what_it_cannot_serve() {
    let world = World::new("refusals").await;
    let deployment = files::deployment_file("[audit]\nmode = \"disabled\"\n");

    // A server's credential reference with no file.
    world.files.write(
        "gateway.toml",
        &deployment.replace(
            "docs-team-a-credential = \"docs-team-a-credential\"",
            "other = \"docs-team-a-credential\"",
        ),
    );
    let said = refused(&world).await;
    assert!(
        said.contains("uses credential `docs-team-a-credential`"),
        "{said}"
    );
    // A credential file no server uses.
    world.files.write(
        "gateway.toml",
        &deployment.replace(
            "docs-team-a-credential = \"docs-team-a-credential\"",
            "docs-team-a-credential = \"docs-team-a-credential\"\nspare = \"docs-team-a-credential\"",
        ),
    );
    let said = refused(&world).await;
    assert!(said.contains("`spare`"), "{said}");
    world.files.write("gateway.toml", &deployment);
    // An empty credential file.
    world.files.write("docs-team-a-credential", "\n");
    let said = refused(&world).await;
    assert!(said.contains("is empty"), "{said}");
    world
        .files
        .write("docs-team-a-credential", files::CREDENTIAL);
    // A server the proxy cannot reach over plain HTTP.
    world.files.write(
        "registry/registry.toml",
        &registry("https://mock-docs.example.test/mcp"),
    );
    let said = refused(&world).await;
    assert!(said.contains("must be http://"), "{said}");
    // A server entry changed without its tools approved again.
    world.files.write(
        "registry/registry.toml",
        &registry(&world.mock.url()).replace(
            "reference = \"docs-team-a-credential\"",
            "reference = \"other-credential\"",
        ),
    );
    let said = refused(&world).await;
    assert!(
        said.contains("binding to server `docs-team-a`") && said.contains("approve it again"),
        "{said}"
    );
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
    let said = prepare(
        deployment,
        gateway_core::InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(said.contains("the audit store will not start"), "{said}");
    let deployment = world
        .files
        .load_with(&[("WIRING_TEST_DATABASE_URL", "not a url at all")])
        .unwrap();
    let said = prepare(
        deployment,
        gateway_core::InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(said.contains("does not parse"), "{said}");
}

/// Why the gateway in `world` refuses to start.
async fn refused(world: &World) -> String {
    world.prepare().await.unwrap_err().to_string()
}
