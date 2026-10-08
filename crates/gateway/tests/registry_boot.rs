//! The boot gates for a policy from the registry file (`boot::check_registry`), called with
//! wiring the binary would never build, and a reload racing a call: a tool withdrawn between
//! the decision and the run is not sent, and a call is checked against the policy version it
//! was decided under, not one served later.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::path::Path;
use std::sync::{Arc, OnceLock};

use connector_proxy::{FileCredentials, ProxyConnector, Upstream};
use files::{
    AUDIENCE, Files, READ_TOOL, TEAM_A_SA, call, cluster_issuer, kubernetes_token, registry,
};
use gateway::boot::{self, BootError, Settings, Wiring};
use gateway::path::RequestPath;
use gateway::{
    AuditSection, NO_PROFILE, ResourceAdapter, undeclared_argument, withdrawn_while_deciding,
};
use gateway_core::audit::{AuditRowId, Outcome, RowCompletion, StoreError};
use gateway_core::{
    ApprovedTool, AuditRecord, AuditStore, BoxFuture, Principal, PrincipalId, PrincipalKind,
    Resources,
};
use gateway_identity::SystemClock;
use gateway_registry::Registry;
use gateway_testkit::{Gate, InMemoryAuditStore, LocalIssuer};
use mock_docs_server::{AcceptedCredential, Config};
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
    };
    (settings, Registry::load(&deployment.registry_file).unwrap())
}

/// The mock server's connector, as the binary builds it.
fn proxy(url: &str, credential: &Path) -> Arc<ProxyConnector> {
    let credentials = FileCredentials::load([("mock-docs".into(), credential)]).unwrap();
    let upstream = Upstream::new("mock-docs", url)
        .tool(READ_TOOL.parse().unwrap(), "read_document")
        .tool(files::LIST_TOOL.parse().unwrap(), "list_documents");
    Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap())
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
        matches!(&refused, Some(BootError::UnregisteredConnector { connector, .. }) if connector.as_str() == "mock-docs"),
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
    let connector = proxy("http://127.0.0.1:9/mcp", &files.path("docs-credential"));
    let wiring = wiring().connector("mock-docs", connector, Arc::new(NoResources));
    let refused = boot::check_registry(settings, registry, wiring).err();
    assert!(
        matches!(&refused, Some(BootError::AdapterBesideRegistry(name)) if name.as_str() == "mock-docs"),
        "{refused:?}"
    );
}

#[test]
fn a_proxied_connector_registered_twice_is_refused() {
    let files = Files::new("twice", &issuer().jwks_document(), "http://127.0.0.1:9/mcp");
    let (settings, registry) = parts(&files, true);
    let connector = proxy("http://127.0.0.1:9/mcp", &files.path("docs-credential"));
    let wiring = wiring()
        .proxied("mock-docs", connector.clone())
        .proxied("mock-docs", connector);
    let refused = boot::check_registry(settings, registry, wiring).err();
    assert!(
        matches!(&refused, Some(BootError::DuplicateConnector(name)) if name.as_str() == "mock-docs"),
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
    let connector = proxy("http://127.0.0.1:9/mcp", &files.path("docs-credential"));
    let refused =
        boot::check_registry(settings, registry, wiring().proxied("mock-docs", connector)).err();
    assert!(
        matches!(refused, Some(BootError::ReservedProfile)),
        "{refused:?}"
    );
}

#[test]
fn a_caller_no_registry_rule_covers_gets_no_profile() {
    let files = Files::new(
        "no-rule",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let connector = proxy("http://127.0.0.1:9/mcp", &files.path("docs-credential"));
    let (gates, _) =
        boot::check_registry(settings, registry, wiring().proxied("mock-docs", connector)).unwrap();
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
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        Box::pin(async move {
            self.gate.wait().await;
            self.inner.begin(record).await
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        self.inner.finish(completion)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_withdrawn_while_a_call_waits_is_not_sent() {
    let mock = mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
        .await
        .unwrap();
    let files = Files::new("race", &issuer().jwks_document(), &mock.url());
    let (settings, registry) = parts(&files, false);
    let store = Arc::new(HeldStore {
        inner: InMemoryAuditStore::new(),
        gate: Gate::closed(),
    });
    let wiring = wiring().audit_store(store.clone()).proxied(
        "mock-docs",
        proxy(&mock.url(), &files.path("docs-credential")),
    );
    let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
    let path = RequestPath::new(gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);

    // Decided under demo-1, then held at begin.
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
    let start = original
        .find("[[tools]]\nname = \"docs__read_document\"")
        .unwrap();
    let end = start + original[start..].find("# --- Surfaces").unwrap();
    let withdrawn = format!("{}{}", &original[..start], &original[end..])
        .replace("revision = \"demo-1\"", "revision = \"demo-2\"")
        .replace(
            "tools = [\"docs__list_documents\", \"docs__read_document\"]",
            "tools = [\"docs__list_documents\"]",
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
    assert_eq!(rows[0].policy_revision.as_str(), "demo-1");
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

/// The kind registry under `revision`, with the read tool's schema and resources widened to
/// take a second project, `other_project`, and the approved hash to match.
fn widened(original: &str, revision: &str) -> String {
    let start = original
        .find("[[tools]]\nname = \"docs__read_document\"")
        .unwrap();
    let end = start + original[start..].find("# --- Surfaces").unwrap();
    let project = "{ from_argument = \"project\", system = \"docs\", kind = \"project\" }";
    let schema = json!({
        "type": "object",
        "required": ["project", "document"],
        "additionalProperties": false,
        "properties": {
            "project": {"type": "string", "description": "The project, such as `atlas`."},
            "document": {"type": "string", "description": "The document's name within the project."},
            "other_project": {"type": "string", "description": "Another project."},
        },
    });
    let hash = gateway_registry::definition_sha256(
        "read_document",
        Some("Read a document"),
        "Reads one document from one project.",
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
            "933716f7c43f229c6a246bfa2114812f8c24855b9d38afe28e9c90a04b743cb9",
            &hash,
        )
        + "[tools.input_schema.properties.other_project]\ntype = \"string\"\ndescription = \"Another project.\"\n\n";
    assert!(tool.contains("from_argument = \"other_project\""), "{tool}");
    format!("{}{tool}{}", &original[..start], &original[end..]).replace(
        "revision = \"demo-1\"",
        &format!("revision = \"{revision}\""),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_is_checked_against_the_policy_it_was_decided_under_not_a_later_one() {
    let mock = mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
        .await
        .unwrap();
    let files = Files::new("widened", &issuer().jwks_document(), &mock.url());
    let (settings, registry) = parts(&files, false);
    let store = Arc::new(HeldStore {
        inner: InMemoryAuditStore::new(),
        gate: Gate::closed(),
    });
    let wiring = wiring().audit_store(store.clone()).proxied(
        "mock-docs",
        proxy(&mock.url(), &files.path("docs-credential")),
    );
    let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
    let path = RequestPath::new(gates);
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[AUDIENCE]);

    // Decided under demo-1, whose schema does not declare other_project and whose adapter
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
        answered.body["error"]["message"],
        json!(undeclared_argument(READ_TOOL)),
        "{}",
        answered.body
    );
    assert!(mock.log_lines().is_empty(), "{:?}", mock.log_lines());
    let rows = store.inner.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].policy_revision.as_str(), "demo-1");
    let outcome = rows[0]
        .completion
        .as_ref()
        .map(|completion| completion.outcome.clone());
    assert_eq!(
        outcome,
        Some(Outcome::Refused {
            sentence: undeclared_argument(READ_TOOL)
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

#[test]
fn a_proxied_connector_is_not_handed_out_to_run_without_the_argument_check() {
    let files = Files::new(
        "unchecked",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let (settings, registry) = parts(&files, true);
    let connector = proxy("http://127.0.0.1:9/mcp", &files.path("docs-credential"));
    let (gates, _) =
        boot::check_registry(settings, registry, wiring().proxied("mock-docs", connector)).unwrap();
    let tool = gates
        .snapshot()
        .tool(&READ_TOOL.parse().unwrap())
        .unwrap()
        .clone();
    assert_eq!(tool.connector.as_str(), "mock-docs");
    assert!(gates.connector(&tool.connector).is_none());
    assert!(gates.resource_adapter(&tool.connector).is_none());
}
