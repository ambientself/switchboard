//! Revoking a turn grant the gateway has already accepted, on the running gateway (decision
//! 0012, "Revocation", as decision 0013 amends it): the team taken off the surface's allowlist,
//! and the surface withdrawn, each by a new registry file, stop the same grant within one
//! `registry.poll_seconds` of the file changing. A cluster adds the ConfigMap's delivery bound
//! before the file changes; here the file is replaced in place, so the bound is the poll.
//!
//! The gateway is built from files, as the `switchboard` binary builds it, with a `[grants]`
//! table naming one issuer whose key the test's minter holds, and a mapping from Otto-style
//! names to the kind registry's tools. It serves over loopback, with an in-memory audit store,
//! and its reloader reads the registry file every second. The key, the third lever, is read at
//! boot only, so `tests/grants.rs` tests it across a restart.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use connector_proxy::{Destination, FileCredentials, ProxyConnector, Upstream};
use files::{AUDIENCE, Files, KIND_REVISION, POD_UID, READ_TOOL, SURFACE, TEAM_A_SA};
use gateway::boot::{self, Settings, Wiring};
use gateway::{AuditSection, GRANT_HEADER, TELEMETRY_QUEUE, Telemetry, Timeouts};
use gateway_core::{AuditRecord, ReasonKind};
use gateway_identity::SystemClock;
use gateway_otto::minter::TestMinter;
use gateway_registry::Registry;
use gateway_testkit::InMemoryAuditStore;
use mock_docs_server::Config;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{Answer, Http, exchange, legacy};
use tokio::net::TcpListener;

/// How often the reloader reads the registry file: `registry.poll_seconds = 1`, as
/// [`files::deployment_file`] writes it.
const POLL: Duration = Duration::from_secs(1);

/// How soon after the file changes the grant must be denied: one poll, and two seconds more
/// for a loaded machine. Without the reload the grant would be served for as long as it lives.
const REVOKED_WITHIN: Duration = Duration::from_secs(3);

/// The grant issuer's name.
const ISSUER: &str = "otto-test";

/// The `[grants]` table: one issuer, whose key is in `otto.pem`, and the mapping in
/// `otto-tools.json`.
const GRANTS: &str = r#"[grants]
mode = "enforce"
tool_mapping_file = "otto-tools.json"

[[grants.issuers]]
name = "otto-test"
key_file = "otto.pem"
require_pod = false
require_egress = false
"#;

/// The gateway, served on loopback, and what the test reads back.
struct Revoking {
    address: SocketAddr,
    token: String,
    store: Arc<InMemoryAuditStore>,
    registry_file: PathBuf,
    original: String,
    minter: TestMinter,
    _mock: mock_docs_server::Running,
    _files: Files,
}

impl Revoking {
    async fn start(name: &str) -> Self {
        let mock = mock_docs_server::start(Config::new(files::mock_credentials()))
            .await
            .unwrap();
        let issuer = files::cluster_issuer();
        let files = Files::new(name, &issuer.jwks_document(), &mock.url());
        let minter = TestMinter::generate();
        files.write("otto.pem", &minter.public_key_pem());
        files.write(
            "otto-tools.json",
            &json!({"docs_read": READ_TOOL, "docs_list": files::LIST_TOOL}).to_string(),
        );
        files.write(
            "gateway.toml",
            &files::deployment_file(&format!("[audit]\nmode = \"disabled\"\n\n{GRANTS}\n")),
        );
        let deployment = files.load();
        assert!(
            deployment.grants.enforce.is_some(),
            "the [grants] table was not read"
        );
        let registry_file = deployment.registry_file;
        let loaded = std::fs::read(&registry_file).unwrap();
        let original = String::from_utf8(loaded.clone()).unwrap();
        let settings = Settings {
            deployment: deployment.deployment,
            identity: deployment.identity,
            audit: AuditSection {
                disabled: false,
                postgres: false,
            },
            grants: deployment.grants,
            http: deployment.http,
            max_age: None,
            read_at: Instant::now(),
        };
        let registry = Registry::from_toml_str(&original).unwrap();
        let store = Arc::new(InMemoryAuditStore::new());
        let mut wiring = Wiring::new(Arc::new(SystemClock)).audit_store(store.clone());
        // One connector for each of the mock server's entries, with that entry's credential.
        for entry in ["docs-team-a", "docs-team-b"] {
            let credentials =
                FileCredentials::load([(entry.into(), files.path(&format!("{entry}-credential")))])
                    .unwrap();
            let upstream = Upstream {
                destination: Destination::InCluster,
                ..Upstream::new(entry, mock.url())
            }
            .tool(
                format!("{entry}__read_document").parse().unwrap(),
                "read_document",
            )
            .tool(
                format!("{entry}__list_documents").parse().unwrap(),
                "list_documents",
            );
            let connector = Arc::new(ProxyConnector::new(upstream, Arc::new(credentials)).unwrap());
            wiring = wiring.proxied(entry, connector);
        }
        let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
        tokio::spawn(reloader.watch(registry_file.clone(), POLL, loaded));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        tokio::spawn(gateway::serve_with_telemetry(
            listener,
            gates,
            telemetry,
            drain,
            std::future::pending(),
            Timeouts::default(),
            gateway::DEFAULT_MAX_IN_FLIGHT,
        ));
        Self {
            address,
            token: files::kubernetes_token(&issuer, TEAM_A_SA, &[AUDIENCE]),
            store,
            registry_file,
            original,
            minter,
            _mock: mock,
            _files: files,
        }
    }

    /// A grant for team A at this deployment, naming the caller's pod, issued now for ten
    /// minutes, for the read tool, the list tool and a name the mapping lacks.
    fn grant(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.minter.mint(&json!({
            "aud": ["otto-gateway", "files-test"],
            "iat": now,
            "exp": now + 600,
            "team": "team-a",
            "tools": ["docs_read", "docs_list", "docs_unmapped"],
            "epoch": 1,
            "sid": "session-1",
            "tid": "turn-1",
            "eid": "execution-1",
            "actor": "person@example.test",
            "pod": POD_UID,
        }))
    }

    /// A read of team A's own document on team A's surface, carrying `grant`.
    async fn read(&self, grant: &str) -> Value {
        let params = json!({
            "name": READ_TOOL,
            "arguments": {"project": "atlas", "document": "plan"},
        });
        let request = Http::new("POST", &format!("/mcp/{SURFACE}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .bearer(&self.token)
            .header(GRANT_HEADER, grant)
            .body(legacy("tools/call", params).to_string().into_bytes());
        let answer = send(self.address, request).await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }

    fn last_row(&self) -> AuditRecord {
        self.store.rows().last().cloned().expect("a row")
    }

    /// Replaces the registry file with `text` by a rename, as demo.sh does, and returns when.
    fn replace_registry(&self, text: &str) -> Instant {
        if let Err(error) = Registry::from_toml_str(text) {
            panic!("the new registry file does not load: {error}");
        }
        let next = self.registry_file.with_extension("next");
        std::fs::write(&next, text).unwrap();
        std::fs::rename(&next, &self.registry_file).unwrap();
        Instant::now()
    }

    /// Reads with `grant` until the read is denied, every 50 milliseconds, and returns the
    /// denial once it comes, or fails the test if it has not come within [`REVOKED_WITHIN`] of
    /// `changed`. Every read before it must have been served.
    async fn until_denied(&self, grant: &str, changed: Instant) -> Value {
        loop {
            let answer = self.read(grant).await;
            if answer.get("error").is_some() {
                let after = changed.elapsed();
                assert!(
                    after <= REVOKED_WITHIN,
                    "denied only {after:?} after the file changed"
                );
                return answer;
            }
            assert_eq!(answer["result"]["isError"], json!(false), "{answer}");
            assert!(
                changed.elapsed() <= REVOKED_WITHIN,
                "still served {REVOKED_WITHIN:?} after the file changed: {answer}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Accepts `grant`: the read is served, and its row records the grant verified.
    async fn accept(&self, grant: &str) {
        let answer = self.read(grant).await;
        assert_eq!(answer["result"]["isError"], json!(false), "{answer}");
        let row = self.last_row();
        assert_eq!(row.reason, None, "{row:?}");
        assert_verified(&row, grant);
    }
}

async fn send(address: SocketAddr, request: Http) -> Answer {
    let length = request.body.len().to_string();
    let request = request
        .header("host", &format!("127.0.0.1:{}", address.port()))
        .header("content-length", &length);
    let mut bytes = request.head();
    bytes.extend_from_slice(&request.body);
    exchange(address, &bytes).await
}

/// `row` records `grant` verified, from the issuer, for team A.
fn assert_verified(row: &AuditRecord, grant: &str) {
    assert_eq!(row.delegation_failure, None, "{row:?}");
    let recorded = row.delegation.as_ref().expect("the delegation's columns");
    let digest: String = Sha256::digest(grant.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(recorded.digest.to_hex(), digest);
    assert_eq!(recorded.issuer.as_str(), ISSUER);
    assert_eq!(
        row.proved_delegation_team
            .as_ref()
            .map(|team| team.get().as_str()),
        Some("team-a")
    );
}

/// `text` at revision `revision` instead of the kind registry's.
fn at_revision(text: &str, revision: &str) -> String {
    let line = format!("revision = \"{KIND_REVISION}\"\n");
    assert_eq!(text.matches(&line).count(), 1);
    text.replace(&line, &format!("revision = \"{revision}\"\n"))
}

/// Team A's surface's `[[surfaces]]` table in the kind registry, with its allowlist.
fn team_a_surface(teams: &str) -> String {
    format!(
        "[[surfaces]]\nname = \"{SURFACE}\"\n\
         tools = [\"docs-team-a__list_documents\", \"docs-team-a__read_document\"]\n\
         teams = {teams}\nprincipals = \"any_in_teams_and_groups\"\n\n"
    )
}

/// The team lever: a new registry file taking team A off its surface's allowlist, which leaves
/// it empty, stops a grant the gateway accepted a moment before, within one poll of the file
/// changing. The grant still verifies; the surface's allowlist denies the call. (Team B in its
/// place would not load: the snapshot loader refuses a surface serving a team an entry whose
/// reach its limit does not hold.)
#[tokio::test]
async fn taking_the_team_off_the_allowlist_stops_an_accepted_grant_within_a_poll() {
    let gateway = Revoking::start("revoke-team").await;
    let grant = gateway.grant();
    gateway.accept(&grant).await;

    let surface = team_a_surface("[\"team-a\"]");
    assert_eq!(gateway.original.matches(&surface).count(), 1);
    let removed =
        at_revision(&gateway.original, "demo-revoke-team").replace(&surface, &team_a_surface("[]"));
    let changed = gateway.replace_registry(&removed);
    let denied = gateway.until_denied(&grant, changed).await;
    assert!(denied["error"]["message"].is_string(), "{denied}");
    let row = gateway.last_row();
    assert_eq!(row.reason, Some(ReasonKind::SurfaceNotPermitted), "{row:?}");
    assert_verified(&row, &grant);
    assert_eq!(row.policy_revision.as_str(), "demo-revoke-team");

    // The same grant is denied on every read after.
    let again = gateway.read(&grant).await;
    assert_eq!(
        again["error"]["message"], denied["error"]["message"],
        "{again}"
    );
}

/// The surface lever: a new registry file withdrawing team A's surface stops a grant the
/// gateway accepted a moment before, within one poll of the file changing.
#[tokio::test]
async fn withdrawing_the_surface_stops_an_accepted_grant_within_a_poll() {
    let gateway = Revoking::start("revoke-surface").await;
    let grant = gateway.grant();
    gateway.accept(&grant).await;

    let surface = team_a_surface("[\"team-a\"]");
    assert_eq!(gateway.original.matches(&surface).count(), 1);
    let withdrawn = at_revision(&gateway.original, "demo-revoke-surface").replace(&surface, "");
    let changed = gateway.replace_registry(&withdrawn);
    let denied = gateway.until_denied(&grant, changed).await;
    assert!(denied["error"]["message"].is_string(), "{denied}");
    let row = gateway.last_row();
    assert_eq!(row.reason, Some(ReasonKind::SurfaceNotPermitted), "{row:?}");
    assert_verified(&row, &grant);
    assert_eq!(row.policy_revision.as_str(), "demo-revoke-surface");

    let again = gateway.read(&grant).await;
    assert_eq!(
        again["error"]["message"], denied["error"]["message"],
        "{again}"
    );
}
