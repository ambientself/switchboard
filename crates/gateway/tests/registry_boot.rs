//! The boot gates for a policy from the registry file (`boot::check_registry`), called with
//! wiring the binary would never build, and a reload racing a call: a tool withdrawn between
//! the decision and the run is not sent, and a call is checked against the policy version it
//! was decided under, not one served later. Also the row of a call whose arguments do not match
//! the approved schema.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use connector_proxy::{FileCredentials, ProxyConnector, Upstream};
use files::{
    AUDIENCE, Files, READ_TOOL, TEAM_A_SA, call, cluster_issuer, kubernetes_token, registry,
};
use gateway::boot::{self, BootError, Settings, Wiring};
use gateway::path::RequestPath;
use gateway::{
    AuditSection, NO_PROFILE, ResourceAdapter, invalid_argument, undeclared_argument,
    withdrawn_while_deciding,
};
use gateway_core::audit::{AuditRowId, ErrorKind, ListRecord, Outcome, RowCompletion, StoreError};
use gateway_core::{
    ApprovedTool, AuditRecord, AuditStore, BoxFuture, Principal, PrincipalId, PrincipalKind,
    Resources,
};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::{Gate, InMemoryAuditStore, LocalIssuer};
use mock_docs_server::Config;
use serde_json::{Value, json};

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

/// The settings and registry the deployment in `files` loads, with audit as `disabled` says.
fn parts(files: &Files, disabled: bool) -> (Settings, Registry) {
    let deployment = files.load();
    let settings = Settings {
        deployment: deployment.deployment,
        identity: deployment.identity,
        audit: AuditSection { disabled },
        http: deployment.http,
        max_age: None,
        read_at: Instant::now(),
    };
    (settings, Registry::load(&deployment.registry_file).unwrap())
}

/// The connector for `entry`, one of the mock server's entries, as the binary builds it: its
/// credential is the file `files` writes for it.
fn proxy(entry: &str, url: &str, files: &Files) -> Arc<ProxyConnector> {
    let credential = files.path(&format!("{entry}-credential"));
    let credentials = FileCredentials::load([(entry.into(), credential)]).unwrap();
    let upstream = Upstream::new(entry, url)
        .tool(
            format!("{entry}__read_document").parse().unwrap(),
            "read_document",
        )
        .tool(
            format!("{entry}__list_documents").parse().unwrap(),
            "list_documents",
        );
    Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap())
}

/// `wiring` with a connector for each of the mock server's entries, at `url`.
fn entries(wiring: Wiring, url: &str, files: &Files) -> Wiring {
    wiring
        .proxied("docs-team-a", proxy("docs-team-a", url, files))
        .proxied("docs-team-b", proxy("docs-team-b", url, files))
}

/// Where `name`'s `[[tools]]` entry starts and ends in `registry`: up to the next tool, or the
/// surfaces.
fn tool_block(registry: &str, name: &str) -> (usize, usize) {
    let start = registry
        .find(&format!("[[tools]]\nname = \"{name}\""))
        .unwrap();
    let rest = &registry[start + 1..];
    let end = start
        + 1
        + rest
            .find("[[tools]]")
            .unwrap_or_else(|| rest.find("# --- Surfaces").unwrap());
    (start, end)
}

fn wiring() -> Wiring {
    Wiring::new(Arc::new(SystemClock))
}

struct NoResources;

impl ResourceAdapter for NoResources {
    fn resources(&self, _tool: &ApprovedTool, _arguments: &Value) -> Resources {
        Resources::Named(Vec::new())
    }
}

#[test]
fn every_registry_server_needs_a_connector() {
    let files = Files::new(
        "no-connector",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let refused = boot::check_registry(settings, registry, wiring()).err();
    assert!(
        matches!(&refused, Some(BootError::UnregisteredConnector { connector, .. }) if connector.as_str() == "docs-team-a"),
        "{refused:?}"
    );
    // Each entry of the mock server is a server of its own, and needs its own connector.
    let (settings, registry) = parts(&files, true);
    let only_a = wiring().proxied(
        "docs-team-a",
        proxy("docs-team-a", "http://127.0.0.1:9/mcp", &files),
    );
    let refused = boot::check_registry(settings, registry, only_a).err();
    assert!(
        matches!(&refused, Some(BootError::UnregisteredConnector { connector, .. }) if connector.as_str() == "docs-team-b"),
        "{refused:?}"
    );
}

#[test]
fn a_connector_with_an_adapter_of_its_own_is_refused_beside_the_registry() {
    let files = Files::new(
        "own-adapter",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let url = "http://127.0.0.1:9/mcp";
    let wiring = wiring()
        .connector(
            "docs-team-a",
            proxy("docs-team-a", url, &files),
            Arc::new(NoResources),
        )
        .proxied("docs-team-b", proxy("docs-team-b", url, &files));
    let refused = boot::check_registry(settings, registry, wiring).err();
    assert!(
        matches!(&refused, Some(BootError::AdapterBesideRegistry(name)) if name.as_str() == "docs-team-a"),
        "{refused:?}"
    );
}

#[test]
fn a_proxied_connector_registered_twice_is_refused() {
    let files = Files::new("twice", &issuer().jwks_document(), "http://127.0.0.1:9/mcp");
    let (settings, registry) = parts(&files, true);
    let wiring = entries(wiring(), "http://127.0.0.1:9/mcp", &files).proxied(
        "docs-team-a",
        proxy("docs-team-a", "http://127.0.0.1:9/mcp", &files),
    );
    let refused = boot::check_registry(settings, registry, wiring).err();
    assert!(
        matches!(&refused, Some(BootError::DuplicateConnector(name)) if name.as_str() == "docs-team-a"),
        "{refused:?}"
    );
}

#[test]
fn a_registry_that_defines_the_reserved_profile_is_refused() {
    let files = Files::new(
        "reserved",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    files.write(
        "registry/registry.toml",
        &registry("http://127.0.0.1:9/mcp").replace("workload-read", NO_PROFILE),
    );
    let (settings, registry) = parts(&files, true);
    let refused = boot::check_registry(
        settings,
        registry,
        entries(wiring(), "http://127.0.0.1:9/mcp", &files),
    )
    .err();
    assert!(
        matches!(refused, Some(BootError::ReservedProfile)),
        "{refused:?}"
    );
}

/// The registry's path refuses the identity and audit opt-outs in a release build too
/// (decision 0014, section 4), and a development build starts with them.
#[test]
fn the_registry_path_refuses_the_opt_outs_in_a_release_build() {
    let files = Files::new(
        "opt-outs",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let url = "http://127.0.0.1:9/mcp";
    let identity_off = |settings: &mut Settings| {
        settings.identity = gateway::IdentitySection {
            enforce: None,
            disabled: true,
        };
    };

    let (settings, registry) = parts(&files, true);
    let refused =
        boot::as_release::check_registry(settings, registry, entries(wiring(), url, &files)).err();
    assert!(
        matches!(refused, Some(BootError::AuditOptOut)),
        "{refused:?}"
    );

    let (mut settings, registry) = parts(&files, false);
    identity_off(&mut settings);
    let store = Arc::new(InMemoryAuditStore::new());
    let refused = boot::as_release::check_registry(
        settings,
        registry,
        entries(wiring().audit_store(store), url, &files),
    )
    .err();
    assert!(
        matches!(refused, Some(BootError::IdentityOptOut)),
        "{refused:?}"
    );

    let (mut settings, registry) = parts(&files, true);
    identity_off(&mut settings);
    let (gates, _) =
        boot::check_registry(settings, registry, entries(wiring(), url, &files)).unwrap();
    assert_eq!(gates.identity_state(), gateway::GateState::Disabled);
    assert_eq!(gates.audit_state(), gateway::GateState::Disabled);
}

#[test]
fn a_caller_no_registry_rule_covers_gets_no_profile() {
    let files = Files::new(
        "no-rule",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let (gates, _) = boot::check_registry(
        settings,
        registry,
        entries(wiring(), "http://127.0.0.1:9/mcp", &files),
    )
    .unwrap();
    let workload = |issuer: &str| Principal {
        id: PrincipalId {
            issuer: issuer.into(),
            subject: TEAM_A_SA.into(),
        },
        kind: PrincipalKind::Workload {
            team: "team-a".into(),
        },
    };
    let policy = gates.policy();
    assert_eq!(
        policy.select(&workload(files::CLUSTER_ISSUER)).as_str(),
        "workload-read"
    );
    assert_eq!(
        policy
            .select(&workload("https://other.example.test"))
            .as_str(),
        NO_PROFILE
    );
    let user = Principal {
        id: PrincipalId {
            issuer: files::CLUSTER_ISSUER.into(),
            subject: "someone@example.test".into(),
        },
        kind: PrincipalKind::User {
            groups: ["team-a".into()].into(),
        },
    };
    assert_eq!(policy.select(&user).as_str(), NO_PROFILE);
}

/// An audit store whose `begin` waits at a gate: how a test holds a call between its decision
/// and its run.
struct HeldStore {
    inner: InMemoryAuditStore,
    gate: Gate,
}

impl HeldStore {
    /// Returns once a call waits at the gate. Bounded, so a call that never reaches this store
    /// fails the test instead of hanging it.
    async fn held(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while self.gate.waiting() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the call never reached the audit store it was given");
    }
}

impl AuditStore for HeldStore {
    fn begin<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            self.gate.wait().await;
            self.inner.begin(row, record).await
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.inner.finish(completion)
    }

    fn list<'a>(
        &'a self,
        row: &'a AuditRowId,
        record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.inner.list(row, record)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_withdrawn_while_a_call_waits_is_not_sent() {
    let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap();
    let files = Files::new("race", &issuer().jwks_document(), &mock.url());
    let (settings, registry) = parts(&files, false);
    let store = Arc::new(HeldStore {
        inner: InMemoryAuditStore::new(),
        gate: Gate::closed(),
    });
    let wiring = entries(wiring().audit_store(store.clone()), &mock.url(), &files);
    let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
    let path = RequestPath::new(gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);

    // Decided under the kind registry's revision, then held at begin.
    let calling = tokio::spawn({
        let path = path.clone();
        async move {
            call(
                &path,
                &token,
                READ_TOOL,
                json!({"project": "atlas", "document": "plan"}),
            )
            .await
        }
    });
    store.held().await;
    // Withdrawn meanwhile.
    let original = files::registry(&mock.url());
    let (start, end) = tool_block(&original, READ_TOOL);
    let withdrawn = format!("{}{}", &original[..start], &original[end..])
        .replace(
            &format!("revision = \"{}\"", files::KIND_REVISION),
            "revision = \"demo-2\"",
        )
        .replace(
            &format!("tools = [\"{}\", \"{READ_TOOL}\"]", files::LIST_TOOL),
            &format!("tools = [\"{}\"]", files::LIST_TOOL),
        );
    reloader
        .apply(&Registry::from_toml_str(&withdrawn).unwrap())
        .unwrap();
    store.gate.open();

    let answered = calling.await.unwrap();
    assert_eq!(
        answered.body["error"]["message"],
        json!(withdrawn_while_deciding(READ_TOOL)),
        "{}",
        answered.body
    );
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());
    let rows = store.inner.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].policy_revision.as_str(), files::KIND_REVISION);
    let outcome = rows[0]
        .completion
        .as_ref()
        .map(|completion| completion.outcome.clone());
    assert_eq!(
        outcome,
        Some(Outcome::Refused {
            sentence: withdrawn_while_deciding(READ_TOOL)
        })
    );
}

/// The kind registry under `revision`, with team A's read tool's schema and resources widened
/// to take a second project, `other_project`, and the approved hash to match.
fn widened(original: &str, revision: &str) -> String {
    let (start, end) = tool_block(original, READ_TOOL);
    let project = "{ from_argument = \"project\", system = \"docs\", kind = \"project\" }";
    let schema = json!({
        "type": "object",
        "required": ["project", "document"],
        "additionalProperties": false,
        "properties": {
            "project": {"type": "string"},
            "document": {"type": "string"},
            "other_project": {"type": "string", "description": "Another project."},
        },
    });
    let hash = gateway_registry::definition_sha256(
        "read_document",
        None,
        "Read one document of one project.",
        &schema,
    );
    let tool = original[start..end]
        .replace(
            &format!("resources = {{ from_arguments = [{project}] }}"),
            &format!(
                "resources = {{ from_arguments = [{project}, {}] }}",
                project.replace("\"project\", system", "\"other_project\", system")
            ),
        )
        .replace(
            "88523168357c2c86447effa74bcc7b2224d52b9eef69fc4b4f314e169bf2e28a",
            &hash,
        )
        + "[tools.input_schema.properties.other_project]\ntype = \"string\"\ndescription = \"Another project.\"\n\n";
    assert!(tool.contains("from_argument = \"other_project\""), "{tool}");
    format!("{}{tool}{}", &original[..start], &original[end..]).replace(
        &format!("revision = \"{}\"", files::KIND_REVISION),
        &format!("revision = \"{revision}\""),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_is_checked_against_the_policy_it_was_decided_under_not_a_later_one() {
    let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap();
    let files = Files::new("widened", &issuer().jwks_document(), &mock.url());
    let (settings, registry) = parts(&files, false);
    let store = Arc::new(HeldStore {
        inner: InMemoryAuditStore::new(),
        gate: Gate::closed(),
    });
    let wiring = entries(wiring().audit_store(store.clone()), &mock.url(), &files);
    let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
    let path = RequestPath::new(gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);

    // Decided under the kind registry's revision, whose schema does not declare other_project and whose adapter
    // names only `atlas`; then held at begin.
    let calling = tokio::spawn({
        let path = path.clone();
        let token = token.clone();
        async move {
            call(
                &path,
                &token,
                READ_TOOL,
                json!({"project": "atlas", "document": "plan", "other_project": "borealis"}),
            )
            .await
        }
    });
    store.held().await;
    // Meanwhile demo-2 declares other_project and reads it as a resource.
    let revision = reloader
        .apply(&Registry::from_toml_str(&widened(&files::registry(&mock.url()), "demo-2")).unwrap())
        .unwrap();
    assert_eq!(revision.as_str(), "demo-2");
    store.gate.open();

    let answered = calling.await.unwrap();
    assert_eq!(
        answered.body["result"]["isError"],
        json!(true),
        "{}",
        answered.body
    );
    assert_eq!(
        answered.body["result"]["content"][0]["text"],
        json!(undeclared_argument(READ_TOOL)),
        "{}",
        answered.body
    );
    assert!(answered.body.get("error").is_none(), "{}", answered.body);
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());
    let rows = store.inner.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].policy_revision.as_str(), files::KIND_REVISION);
    let outcome = rows[0]
        .completion
        .as_ref()
        .map(|completion| completion.outcome.clone());
    assert_eq!(
        outcome,
        Some(Outcome::Error {
            error_kind: ErrorKind::InvalidArguments
        })
    );

    // Under demo-2 the same call is decided with other_project read as a resource, and
    // team-a's limit does not hold borealis.
    let denied = call(
        &path,
        &token,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan", "other_project": "borealis"}),
    )
    .await;
    assert_eq!(
        denied.body["error"]["code"],
        json!(-32001),
        "{}",
        denied.body
    );
    assert!(
        denied.body["error"]["message"]
            .as_str()
            .is_some_and(|sentence| sentence.contains("`borealis`")),
        "{}",
        denied.body
    );
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mistyped_argument_completes_its_row_as_invalid_arguments_and_is_not_sent() {
    let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
        .await
        .unwrap();
    let files = Files::new("mistyped", &issuer().jwks_document(), &mock.url());
    let (settings, registry) = parts(&files, false);
    let store = Arc::new(InMemoryAuditStore::new());
    let wiring = entries(wiring().audit_store(store.clone()), &mock.url(), &files);
    let (gates, _) = boot::check_registry(settings, registry, wiring).unwrap();
    let path = RequestPath::new(gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);

    // `atlas` is within team-a's limit, so the call is allowed; `document` is typed as a
    // string, so the argument check fails it.
    let answered = call(
        &path,
        &token,
        READ_TOOL,
        json!({"project": "atlas", "document": 7}),
    )
    .await;
    assert_eq!(
        answered.body["result"]["content"][0]["text"],
        json!(invalid_argument(READ_TOOL)),
        "{}",
        answered.body
    );
    assert_eq!(
        answered.body["result"]["isError"],
        json!(true),
        "{}",
        answered.body
    );
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());
    let rows = store.rows();
    assert_eq!(rows.len(), 1);
    let outcome = rows[0]
        .completion
        .as_ref()
        .map(|completion| completion.outcome.clone());
    assert_eq!(
        outcome,
        Some(Outcome::Error {
            error_kind: ErrorKind::InvalidArguments
        })
    );
}

#[test]
fn a_proxied_connector_is_not_handed_out_to_run_without_the_argument_check() {
    let files = Files::new(
        "unchecked",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let (gates, _) = boot::check_registry(
        settings,
        registry,
        entries(wiring(), "http://127.0.0.1:9/mcp", &files),
    )
    .unwrap();
    let tool = gates
        .snapshot()
        .tool(&READ_TOOL.parse().unwrap())
        .unwrap()
        .clone();
    assert_eq!(tool.connector.as_str(), "docs-team-a");
    assert!(gates.connector(&tool.connector).is_none());
    assert!(gates.resource_adapter(&tool.connector).is_none());
}
