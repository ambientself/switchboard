//! The GitHub connector's world for the end-to-end tests: the gateway over HTTP, wired as
//! `start` wires it from a deployment file and a registry file, with the key custodian on a
//! fake GitHub App API, the fake GitHub REST API, the testkit's issuer and an in-memory audit
//! store. No real credential: the App's key is generated per run, and every token is one the
//! fake App API made up. With [`Options::writes`], the registry also has a write entry serving
//! `github__create_pr`, and the world a reconciler that passes only when a test asks; with
//! [`Options::proposals`], the entry serves `github__propose_change` and
//! `github__amend_change` too, and the connector reads the world's store's receipts. With
//! [`Options::comments`], it also has the comment tool's entry and surface, under a profile that
//! requires a turn grant and currency, with turn grants from a test minter and Otto's fake
//! resolver.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};

use connector_github::fake::{FakeLogHost, FakeRest};
use gateway::boot::{self, Settings, Wiring};
use gateway::reload::Reloader;
use gateway::{
    AuditSection, Deployment, RateQuotas, ReconcileSettings, Reconciler, TELEMETRY_QUEUE,
    Telemetry, Timeouts, serve_with_telemetry, start,
};
use gateway_core::audit::{AuditRowId, Completion, Outcome};
use gateway_core::{AuditRecord, Classification, ConnectorName};
use gateway_identity::SystemClock;
use gateway_otto::HttpResolver;
use gateway_otto::fake::{FakeReply, FakeResolver};
use gateway_otto::minter::TestMinter;
use gateway_otto::resolver::Answer as Currency;
use gateway_registry::{Registry, built_in_binding_sha256};
use gateway_testkit::{InMemoryAuditStore, StoreBudgets};
use key_custodian::fake::{FakeApp, FakeGitHub};
use key_custodian::start::{Config, GitHubSection, Limits};
use key_custodian::{Running, start as start_custodian};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::files::{self, AUDIENCE, CLUSTER_ISSUER, TEAM_A_SA, TEAM_B_SA};
use crate::support::{Answer, Http, exchange, legacy};

/// The organization the App is installed on, and the gateway's configured one.
pub const ACCOUNT: &str = "example-org";
/// Another organization, which team A's limit names a repository of.
pub const OTHER_ORG: &str = "other-org";
/// The App.
pub const APP_ID: &str = "4242";
/// The App's installation on [`ACCOUNT`].
pub const INSTALLATION: u64 = 7;
/// The GitHub connector entry.
pub const ENTRY: &str = "github-read";
/// The surface that serves the three tools to both teams.
pub const SURFACE: &str = "github";
/// The three tools.
pub const GET_FILE: &str = "github__get_file";
pub const GET_PR: &str = "github__get_pr";
pub const GET_ISSUE: &str = "github__get_issue";
/// The search, which checks its own scope.
pub const SEARCH: &str = "github__search";
/// The permission set the entry states.
pub const PERMISSIONS: &str = r#"{ contents = "read", issues = "read", pull_requests = "read" }"#;
/// The GitHub connector entry of the newer reads, which ask for their own permission sets
/// within its own.
pub const READS_ENTRY: &str = "github-reads";
/// The surface that serves the newer reads to both teams.
pub const READS_SURFACE: &str = "github-reads";
/// The newer reads.
pub const READS: [&str; 5] = [
    connector_github::reads::GET_CHECKS,
    connector_github::reads::GET_JOB_LOG,
    connector_github::reads::LIST_RELEASES,
    connector_github::reads::PR_TEMPLATE,
    connector_github::reads::REPO_CONVENTIONS,
];
/// The permission set the newer reads' entry states: every permission they ask for.
pub const READS_PERMISSIONS: &str = r#"{ actions = "read", checks = "read", contents = "read", metadata = "read", pull_requests = "read", statuses = "read" }"#;
/// The write entry, narrowed per call, which [`Options::writes`] adds.
pub const WRITE_ENTRY: &str = "github-write";
/// The surface that serves the write tools to team A and team B.
pub const WRITE_SURFACE: &str = "github-write";
/// The permission set the write entry states.
pub const WRITE_PERMISSIONS: &str = r#"{ contents = "write", pull_requests = "write" }"#;
/// The write tool.
pub const CREATE_PR: &str = connector_github::create_pr::CREATE_PR;
/// The proposal tools, which [`Options::proposals`] adds to the write entry.
pub const PROPOSE_CHANGE: &str = connector_github::proposals::PROPOSE_CHANGE;
pub const AMEND_CHANGE: &str = connector_github::proposals::AMEND_CHANGE;
/// The App's own login, as the fake GitHub API names the author of each pull request it opens.
pub const BOT_LOGIN: &str = "switchboard-test-app[bot]";
/// A second workload of team A: another principal of the same team.
pub const TEAM_A_OTHER: &str = "system:serviceaccount:team-a:second-workload";

/// Whether `definition` is a read, which the read entries serve.
fn is_read(definition: &connector_github::Definition) -> bool {
    definition.assurance.classification == Classification::Read
}

/// The App's key, generated by the run that uses it, as PKCS#1 PEM and the public half in DER.
static KEY: LazyLock<(String, Vec<u8>)> = LazyLock::new(|| {
    let key = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    (
        key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string(),
        key.to_public_key()
            .to_pkcs1_der()
            .unwrap()
            .as_bytes()
            .to_vec(),
    )
});

/// The issuer every caller's token comes from.
pub fn issuer() -> &'static gateway_testkit::LocalIssuer {
    static ISSUER: LazyLock<gateway_testkit::LocalIssuer> = LazyLock::new(files::cluster_issuer);
    &ISSUER
}

/// A token for `subject`, a workload of team A or team B.
pub fn token(subject: &str) -> String {
    files::kubernetes_token(issuer(), subject, &[AUDIENCE])
}

/// A directory of its own, short enough for a socket path, open to its owner only.
fn scratch() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sbgh-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir
}

fn write(path: &Path, text: &str, mode: u32) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// What a world is built with, where it differs from the defaults.
#[derive(Clone)]
pub struct Options {
    /// The registry's revision.
    pub revision: &'static str,
    /// The entry's narrowing.
    pub narrowing: &'static str,
    /// The revision of the custodian's own copy of the registry, when it differs.
    pub custodian_revision: Option<&'static str>,
    /// The deployment file's `[connectors.github-read]`, as written.
    pub bounds: &'static str,
    /// The rate quotas the gateway holds the connector to.
    pub quotas: RateQuotas,
    /// Whether the custodian is started at all.
    pub custodian: bool,
    /// Whether the registry has the write entry, serving `github__create_pr` on its own
    /// surface, under a profile that may `propose`.
    pub writes: bool,
    /// How the world's reconciler runs, when a test asks it for a pass.
    pub reconcile: ReconcileSettings,
    /// Whether the write entry also serves `github__propose_change` and
    /// `github__amend_change`. Needs `writes`.
    pub proposals: bool,
    /// The deployment file's `[github] bot_login`, if any.
    pub bot_login: Option<&'static str>,
    /// Whether the connector is left without the store's receipts to read, as before the
    /// gateway's store connects.
    pub withhold_receipts: bool,
    /// The store's budgets, which each call row's deadline includes. No receipt is due before
    /// its row's deadline.
    pub budgets: StoreBudgets,
    /// Whether the registry has the comment entry, serving `github__pr_comment` on its own
    /// surface, with the workloads' profile requiring a turn grant and currency; and whether the
    /// world verifies turn grants and asks a fake resolver ([`with_comments`]).
    pub comments: bool,
    /// Whether that profile's own list of exceptions names `github__pr_comment`.
    pub exception: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            revision: "r1",
            narrowing: "limit",
            custodian_revision: None,
            bounds: "",
            quotas: RateQuotas::default(),
            custodian: true,
            writes: false,
            reconcile: ReconcileSettings::default(),
            proposals: false,
            bot_login: None,
            withhold_receipts: false,
            budgets: StoreBudgets::default(),
            comments: false,
            exception: false,
        }
    }
}

/// The registry file at `revision`: one GitHub entry narrowed `narrowing`, serving the four
/// tools on the surface `github` to team A and team B, each tool approved with its connector's
/// own definition, the search declared `checks_own_scope`. An entry narrowed per call cannot
/// serve a tool that checks its own scope (decision 0011), so it serves the other three. Team
/// A's limit holds atlas and borealis on the App's account and a repository of another
/// organization; team B's holds cosmos. The newer reads are on an entry and a surface of their
/// own ([`reads_text`]).
pub fn registry_text(revision: &str, narrowing: &str, permissions: &str) -> String {
    registry(revision, narrowing, permissions, false)
}

/// The write tools the write entry serves: `github__create_pr`, and the proposal tools when
/// `proposals` is true.
fn write_tools(proposals: bool) -> Vec<&'static str> {
    if proposals {
        vec![CREATE_PR, PROPOSE_CHANGE, AMEND_CHANGE]
    } else {
        vec![CREATE_PR]
    }
}

/// `tools` as a TOML list.
fn listed(tools: &[&str]) -> String {
    let quoted: Vec<String> = tools.iter().map(|tool| format!("\"{tool}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// [`registry_text`], with the write entry when `writes` is true: `github-write`, narrowed
/// `call`, stating [`WRITE_PERMISSIONS`], permitting `propose`, serving `github__create_pr`,
/// approved as its connector states it and settled by a lookup in repositories, on a surface
/// of its own admitting team A and team B; and the workloads' profile may `propose`.
pub fn registry(revision: &str, narrowing: &str, permissions: &str, writes: bool) -> String {
    registry_with(revision, narrowing, permissions, writes, false)
}

/// [`registry`], with the write entry also serving the proposal tools when `proposals` is true.
pub fn registry_with(
    revision: &str,
    narrowing: &str,
    permissions: &str,
    writes: bool,
    proposals: bool,
) -> String {
    let served: Vec<String> = connector_github::definitions()
        .into_iter()
        .filter(is_read)
        .map(|definition| definition.name)
        .filter(|tool| !READS.contains(tool))
        .filter(|tool| narrowing != "call" || *tool != SEARCH)
        .map(|tool| format!("\"{tool}\""))
        .collect();
    let tools = format!("tools = [{}]", served.join(", "));
    let head = format!(
        r#"revision = "{revision}"
servers = []
tools = []

[[connectors]]
name = "{ENTRY}"
system = "github"
permissions = {permissions}
{tools}
credential = {{ mode = "team_service_identity", principal = "switchboard-test-app" }}
narrowing = "{narrowing}"
permits = "read"

[[surfaces]]
name = "{SURFACE}"
{tools}
teams = ["team-a", "team-b"]
principals = "any_in_teams_and_groups"

[[profiles]]
name = "workload-read"
classifications = {classifications}
requires_delegation = false

[[profile_rules]]
issuer = "{CLUSTER_ISSUER}"
principal = "workload"
profile = "workload-read"

[limits.teams]
team-a = [
  {{ system = "github", kind = "repository", identifier = "{ACCOUNT}/atlas" }},
  {{ system = "github", kind = "repository", identifier = "{ACCOUNT}/borealis" }},
  {{ system = "github", kind = "repository", identifier = "{OTHER_ORG}/elsewhere" }},
]
team-b = [{{ system = "github", kind = "repository", identifier = "{ACCOUNT}/cosmos" }}]
"#,
        classifications = if writes {
            r#"["read", "propose"]"#
        } else {
            r#"["read"]"#
        },
    );
    // The surface names the tools before they are approved, so the entry alone is loaded to
    // hash it.
    let entry_only = head.replace(&format!("{tools}\nteams"), "tools = []\nteams");
    // The newer reads on an entry and a surface of their own, after the first entry's
    // approvals.
    let reads = reads_text(narrowing);
    let reads_only = reads.replace(
        &format!("tools = {}\nteams", reads_list()),
        "tools = []\nteams",
    );
    let write_tools = write_tools(proposals);
    let write = if writes {
        write_text(&write_tools)
    } else {
        String::new()
    };
    let write_only = write.replace(
        &format!("tools = {}\nteams", listed(&write_tools)),
        "tools = []\nteams",
    );
    let registry =
        Registry::from_toml_str(&format!("{entry_only}{reads_only}{write_only}")).unwrap();
    let binding = |entry: &str| {
        built_in_binding_sha256(&registry.connectors()[&ConnectorName::new(entry)]).unwrap()
    };
    let (newer, first): (Vec<_>, Vec<_>) = connector_github::definitions()
        .into_iter()
        .filter(is_read)
        .partition(|definition| READS.contains(&definition.name));
    let mut text = head;
    for definition in first
        .into_iter()
        .filter(|definition| served.contains(&format!("\"{}\"", definition.name)))
    {
        text.push_str(&approval(&definition, ENTRY, &binding(ENTRY)));
    }
    text.push_str(&reads);
    for definition in newer {
        text.push_str(&approval(&definition, READS_ENTRY, &binding(READS_ENTRY)));
    }
    if writes {
        text.push_str(&write);
        for tool in &write_tools {
            let definition = connector_github::definitions()
                .into_iter()
                .find(|definition| definition.name == *tool)
                .unwrap();
            text.push_str(&approval(&definition, WRITE_ENTRY, &binding(WRITE_ENTRY)));
        }
    }
    text
}

/// The write entry and its surface, serving `tools` to team A and team B.
fn write_text(tools: &[&str]) -> String {
    let tools = listed(tools);
    format!(
        r#"
[[connectors]]
name = "{WRITE_ENTRY}"
system = "github"
permissions = {WRITE_PERMISSIONS}
tools = {tools}
credential = {{ mode = "team_service_identity", principal = "switchboard-test-app" }}
narrowing = "call"
permits = "propose"

[[surfaces]]
name = "{WRITE_SURFACE}"
tools = {tools}
teams = ["team-a", "team-b"]
principals = "any_in_teams_and_groups"
"#
    )
}

/// The newer reads' entry, narrowed `narrowing`, and their surface, serving them to team A
/// and team B.
fn reads_text(narrowing: &str) -> String {
    let tools = reads_list();
    format!(
        r#"
[[connectors]]
name = "{READS_ENTRY}"
system = "github"
permissions = {READS_PERMISSIONS}
tools = {tools}
credential = {{ mode = "team_service_identity", principal = "switchboard-test-app" }}
narrowing = "{narrowing}"
permits = "read"

[[surfaces]]
name = "{READS_SURFACE}"
tools = {tools}
teams = ["team-a", "team-b"]
principals = "any_in_teams_and_groups"
"#
    )
}

/// The newer reads as a TOML list.
fn reads_list() -> String {
    let quoted: Vec<String> = READS.iter().map(|tool| format!("\"{tool}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// The `[[built_in_tools]]` approval of `definition` on `entry`, whose binding hashes to
/// `binding`, classified as its connector classifies it, declared from its `owner` and `repo`,
/// or, for the search, `checks_own_scope`; and a tool not classified `read` settled by a lookup
/// in repositories.
pub fn approval(definition: &connector_github::Definition, entry: &str, binding: &str) -> String {
    let schema = toml::Value::try_from(&definition.input_schema).unwrap();
    let mut approval = toml::Table::new();
    approval.insert("name".into(), definition.name.into());
    approval.insert("connector".into(), entry.into());
    let classification = definition.assurance.classification;
    approval.insert("classification".into(), classification.as_str().into());
    if classification != Classification::Read {
        approval.insert(
            "settlement".into(),
            toml::from_str::<toml::Table>(
                r#"s = { lookup = { system = "github", kind = "repository" } }"#,
            )
            .unwrap()["s"]
                .clone(),
        );
    }
    approval.insert("description".into(), definition.description.into());
    approval.insert("input_schema".into(), schema);
    approval.insert("approved_by".into(), "reviewer@example.test".into());
    approval.insert(
        "approved_at".into(),
        toml::Value::Datetime("2026-10-15T00:00:00Z".parse().unwrap()),
    );
    approval.insert("definition_sha256".into(), definition.sha256().into());
    approval.insert("binding_sha256".into(), binding.into());
    let resources: toml::Value = if definition.name == SEARCH {
        "checks_own_scope".into()
    } else {
        toml::from_str::<toml::Table>(
            r#"r = { from_arguments = [{ from_argument = "repo", qualified_by = "owner", system = "github", kind = "repository" }] }"#,
        )
        .unwrap()["r"]
            .clone()
    };
    approval.insert("resources".into(), resources);
    let mut wrapper = toml::Table::new();
    wrapper.insert(
        "built_in_tools".into(),
        toml::Value::Array(vec![toml::Value::Table(approval)]),
    );
    format!("\n{}", toml::to_string(&wrapper).unwrap())
}

/// The deployment file: the cluster issuer, audit disabled (the tests read rows from an
/// in-memory store wired in its place), `[github]` pointing at the fake, the custodian and the
/// job log host `log_host`, and `bounds` beside it.
pub fn deployment_text(api_url: &str, socket: &Path, log_host: &str, bounds: &str) -> String {
    deployment_with(api_url, socket, log_host, bounds, None)
}

/// [`deployment_text`], with `[github] bot_login` when `bot_login` is given.
pub fn deployment_with(
    api_url: &str,
    socket: &Path,
    log_host: &str,
    bounds: &str,
    bot_login: Option<&str>,
) -> String {
    let bot_login = bot_login.map_or(String::new(), |login| format!("bot_login = \"{login}\"\n"));
    format!(
        r#"deployment = "github-test"
listen = "127.0.0.1:0"

[http]
allowed_hosts = ["127.0.0.1"]
allowed_origins = []

[registry]
file = "registry.toml"
poll_seconds = 1

[identity]
mode = "enforce"

[[identity.issuers]]
issuer = "{CLUSTER_ISSUER}"
kind = "workload"
audiences = ["{AUDIENCE}"]
algorithm = "RS256"
keys_file = "jwks.json"
subjects_file = "teams.toml"
max_lifetime_seconds = 3600
leeway_seconds = 30

[audit]
mode = "disabled"

[github]
organization = "{ACCOUNT}"
api_url = "{api_url}"
custodian_socket = "{}"
custodian_deadline_seconds = 2
job_log_hosts = ["{log_host}"]
{bot_login}
{bounds}

[credentials]
"#,
        socket.display()
    )
}

/// A buffer the custodian's record is written to.
#[derive(Clone, Default)]
pub struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// What a call answered over HTTP.
pub struct Answered {
    pub answer: Answer,
    pub raw: String,
}

impl Answered {
    /// The tool's structured result, which must be a success.
    pub fn ok(&self) -> Value {
        let result = self.answer.result();
        assert_eq!(result["isError"], json!(false), "{}", self.raw);
        result["structuredContent"].clone()
    }

    /// The text of a tool result that is an error.
    pub fn tool_error(&self) -> String {
        let result = self.answer.result();
        assert_eq!(result["isError"], json!(true), "{}", self.raw);
        result["content"][0]["text"].as_str().unwrap().to_owned()
    }

    /// The sentence of a refusal or denial.
    pub fn refusal(&self) -> String {
        self.answer.denial()
    }
}

/// The gateway, the custodian, both fakes and the store.
pub struct World {
    pub dir: PathBuf,
    pub app: Arc<FakeGitHub>,
    pub rest: FakeRest,
    /// The job log host the deployment pins.
    pub log_host: FakeLogHost,
    /// A job log host it does not.
    pub other_log_host: FakeLogHost,
    pub custodian: Option<Running>,
    pub record: Buffer,
    pub store: Arc<InMemoryAuditStore>,
    pub address: SocketAddr,
    pub reloader: Reloader,
    pub deployment: Deployment,
    /// The instance's reconciler, which passes only when a test calls it.
    pub reconciler: Reconciler,
    /// The turn grants' minter, with [`Options::comments`].
    pub minter: Option<TestMinter>,
    /// Otto's fake resolver, with [`Options::comments`]: it answers `current` until told
    /// otherwise.
    pub resolver: Option<FakeResolver>,
}

impl Drop for World {
    fn drop(&mut self) {
        drop(self.custodian.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The UID this test runs as, which the custodian serves.
fn my_uid() -> u32 {
    std::fs::metadata(env!("CARGO_MANIFEST_DIR")).unwrap().uid()
}

impl World {
    pub async fn new() -> Self {
        Self::with(Options::default()).await
    }

    pub async fn with(options: Options) -> Self {
        let dir = scratch();
        let app = Arc::new(
            FakeGitHub::start(FakeApp {
                public_key_der: KEY.1.clone(),
                app_id: APP_ID.into(),
                installation_id: INSTALLATION,
                account: ACCOUNT.into(),
                repositories: ["atlas", "borealis", "cosmos", "secret"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>(),
            })
            .await
            .unwrap(),
        );
        let rest = FakeRest::start(app.clone(), ACCOUNT).await.unwrap();
        let log_host = FakeLogHost::start().await.unwrap();
        let other_log_host = FakeLogHost::start().await.unwrap();
        let registry = with_comments(
            registry_with(
                options.revision,
                options.narrowing,
                PERMISSIONS,
                options.writes,
                options.proposals,
            ),
            &options,
        );
        write(&dir.join("registry.toml"), &registry, 0o644);
        let custodian_registry = match options.custodian_revision {
            Some(revision) => {
                let path = dir.join("custodian-registry.toml");
                write(
                    &path,
                    &with_comments(
                        registry_with(
                            revision,
                            options.narrowing,
                            PERMISSIONS,
                            options.writes,
                            options.proposals,
                        ),
                        &options,
                    ),
                    0o644,
                );
                path
            }
            None => dir.join("registry.toml"),
        };
        write(&dir.join("app-key.pem"), &KEY.0, 0o600);
        write(&dir.join("jwks.json"), &issuer().jwks_document(), 0o644);
        write(
            &dir.join("teams.toml"),
            &format!(
                "[subjects]\n\"{TEAM_A_SA}\" = \"team-a\"\n\"{TEAM_A_OTHER}\" = \"team-a\"\n\"{TEAM_B_SA}\" = \"team-b\"\n"
            ),
            0o644,
        );
        let socket = dir.join("c.sock");
        write(
            &dir.join("gateway.toml"),
            &deployment_with(
                &rest.url(),
                &socket,
                &log_host.url(),
                options.bounds,
                options.bot_login,
            ),
            0o644,
        );

        let record = Buffer::default();
        let custodian = if options.custodian {
            let config = Config {
                socket: socket.clone(),
                socket_mode: 0o600,
                peer_uid: my_uid(),
                registry: custodian_registry,
                registry_poll_seconds: 1,
                metrics: None,
                github: GitHubSection {
                    api_url: app.url(),
                    ca_file: None,
                    app_id: APP_ID.into(),
                    installation_id: INSTALLATION,
                    account: ACCOUNT.into(),
                    key_file: dir.join("app-key.pem"),
                    deadline_seconds: 2,
                },
                // Enough for every test's calls; the custodian's own rate is its own tests'.
                limits: Limits {
                    requests_per_minute: 3600,
                    burst: 1000,
                    ..Limits::default()
                },
            };
            Some(
                start_custodian(config, Box::new(record.clone()))
                    .await
                    .unwrap(),
            )
        } else {
            None
        };

        let deployment = Deployment::load(&dir.join("gateway.toml"), |_| None).unwrap();
        let registry = Registry::from_toml_str(&registry).unwrap();
        // A world that writes keeps the time as it passes, so a receipt's lease ends.
        let store = if options.writes || options.comments {
            Arc::new(
                InMemoryAuditStore::new()
                    .with_clock(Arc::new(SystemClock))
                    .with_budgets(options.budgets),
            )
        } else {
            Arc::new(InMemoryAuditStore::new().with_budgets(options.budgets))
        };
        let (minter, resolver) = if options.comments {
            (
                Some(TestMinter::generate()),
                Some(
                    FakeResolver::start(FakeReply::Answer(Currency::Current))
                        .await
                        .unwrap(),
                ),
            )
        } else {
            (None, None)
        };
        // The connector reads the receipts of the store the world reads rows from, as the
        // gateway gives it the Postgres store's once it connects.
        let wiring = Wiring::new(Arc::new(SystemClock)).audit_store(store.clone());
        let mut wiring = if options.withhold_receipts {
            start::wire_github(
                &registry,
                deployment.github.as_ref(),
                &deployment.connectors,
                wiring,
            )
        } else {
            start::wire_github_reading(
                &registry,
                deployment.github.as_ref(),
                &deployment.connectors,
                store.clone(),
                wiring,
            )
        }
        .unwrap()
        .quotas(options.quotas);
        if let Some(resolver) = &resolver {
            wiring = wiring.resolver(Arc::new(HttpResolver::new(&resolver.config()).unwrap()));
        }
        let grants = match &minter {
            Some(minter) => serde_json::from_value(json!({"enforce": {
                "issuers": [{
                    "name": GRANT_ISSUER,
                    "current_key": minter.public_key_pem(),
                    "require_pod": true,
                    "require_egress": false,
                }],
                "tool_mapping": {OTTO_PR_COMMENT: PR_COMMENT},
            }}))
            .unwrap(),
            None => Default::default(),
        };
        let settings = Settings {
            deployment: deployment.deployment.clone(),
            identity: deployment.identity.clone(),
            audit: AuditSection {
                disabled: false,
                postgres: false,
            },
            grants,
            http: deployment.http.clone(),
            max_age: None,
            read_at: Instant::now(),
        };
        let (gates, reloader) = boot::check_registry(settings, registry, wiring).unwrap();
        let reconciler = gates.reconciler(store.clone(), options.reconcile);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (telemetry, drain) = Telemetry::bounded(TELEMETRY_QUEUE);
        tokio::spawn(serve_with_telemetry(
            listener,
            gates,
            telemetry,
            drain,
            std::future::pending(),
            Timeouts::default(),
            64,
        ));
        Self {
            dir,
            app,
            rest,
            log_host,
            other_log_host,
            custodian,
            record,
            store,
            address,
            reloader,
            deployment,
            reconciler,
            minter,
            resolver,
        }
    }

    /// Calls `tool` with `arguments` as `subject`, over HTTP.
    pub async fn call(&self, subject: &str, tool: &str, arguments: Value) -> Answered {
        self.call_on(SURFACE, subject, tool, arguments).await
    }

    /// Calls one of the newer reads with `arguments` as `subject`, over HTTP.
    pub async fn read(&self, subject: &str, tool: &str, arguments: Value) -> Answered {
        self.call_on(READS_SURFACE, subject, tool, arguments).await
    }

    /// Calls `tool` on `surface` with `arguments` as `subject`, over HTTP.
    pub async fn call_on(
        &self,
        surface: &str,
        subject: &str,
        tool: &str,
        arguments: Value,
    ) -> Answered {
        let params = json!({"name": tool, "arguments": arguments});
        self.send(surface, subject, legacy("tools/call", params))
            .await
    }

    /// The names of the tools `surface` lists to `subject`.
    pub async fn listed(&self, surface: &str, subject: &str) -> Vec<String> {
        let answered = self
            .send(surface, subject, legacy("tools/list", json!({})))
            .await;
        answered.answer.result()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Calls `github__create_pr` with `arguments` as `subject`, over HTTP, with the tool-use
    /// identifier `tool_use_id`, which is the call's key.
    pub async fn create_pr(&self, subject: &str, arguments: Value, tool_use_id: &str) -> Answered {
        self.write(CREATE_PR, subject, arguments, tool_use_id).await
    }

    /// Calls the write tool `tool` with `arguments` as `subject`, over HTTP, with the tool-use
    /// identifier `tool_use_id`, which is the call's key.
    pub async fn write(
        &self,
        tool: &str,
        subject: &str,
        arguments: Value,
        tool_use_id: &str,
    ) -> Answered {
        let params = json!({
            "name": tool,
            "arguments": arguments,
            "_meta": {"claudecode/toolUseId": tool_use_id},
        });
        self.send(WRITE_SURFACE, subject, legacy("tools/call", params))
            .await
    }

    /// Calls `github__pr_comment` with `arguments` as `subject`, over HTTP, with the tool-use
    /// identifier `tool_use_id`, which is the call's key, and a turn grant for the subject's team
    /// naming Otto's `github_pr_comment`.
    pub async fn comment(&self, subject: &str, arguments: Value, tool_use_id: &str) -> Answered {
        let params = json!({
            "name": PR_COMMENT,
            "arguments": arguments,
            "_meta": {"claudecode/toolUseId": tool_use_id},
        });
        let grant = self.grant(subject);
        self.send_with(
            COMMENT_SURFACE,
            subject,
            legacy("tools/call", params),
            Some(&grant),
        )
        .await
    }

    /// A turn grant for `subject`'s team, issued now for ten minutes, naming Otto's
    /// `github_pr_comment` and the pod every test token proves.
    pub fn grant(&self, subject: &str) -> String {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let team = if subject == TEAM_B {
            "team-b"
        } else {
            "team-a"
        };
        self.minter
            .as_ref()
            .expect("a world with comments")
            .mint(&json!({
                "aud": [self.deployment.deployment.as_str()],
                "iat": now,
                "exp": now + 600,
                "team": team,
                "tools": [OTTO_PR_COMMENT],
                "epoch": 7,
                "sid": "session-7f3a",
                "tid": "turn-4",
                "eid": "execution-91c2",
                "actor": "actor@example.test",
                "pod": files::POD_UID,
            }))
    }

    /// How many questions Otto's fake resolver has been asked.
    pub fn asked(&self) -> usize {
        self.resolver
            .as_ref()
            .expect("a world with comments")
            .received()
            .len()
    }

    /// Sends the JSON-RPC request `request` on `surface` as `subject`, over HTTP.
    async fn send(&self, surface: &str, subject: &str, request: Value) -> Answered {
        self.send_with(surface, subject, request, None).await
    }

    /// Sends the JSON-RPC request `request` on `surface` as `subject`, over HTTP, with the turn
    /// grant `grant` if there is one.
    async fn send_with(
        &self,
        surface: &str,
        subject: &str,
        request: Value,
        grant: Option<&str>,
    ) -> Answered {
        let body = request.to_string().into_bytes();
        let mut http = Http::new("POST", &format!("/mcp/{surface}"))
            .header("host", "127.0.0.1")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .bearer(&token(subject));
        if let Some(grant) = grant {
            http = http.header(gateway::GRANT_HEADER, grant);
        }
        let http = http
            .header("content-length", &body.len().to_string())
            .body(body);
        let mut bytes = http.head();
        bytes.extend_from_slice(&http.body);
        let answer = exchange(self.address, &bytes).await;
        let raw = String::from_utf8_lossy(&answer.body).into_owned();
        Answered { answer, raw }
    }

    /// Calls `tool` as team A.
    pub async fn team_a(&self, tool: &str, arguments: Value) -> Answered {
        self.call(TEAM_A_SA, tool, arguments).await
    }

    /// Every row of a call of `tool`, in the order begun.
    pub fn rows(&self, tool: &str) -> Vec<AuditRecord> {
        self.store
            .rows()
            .into_iter()
            .filter(|row| row.tool == tool)
            .collect()
    }

    /// The last row of a call of `tool`.
    pub fn last_row(&self, tool: &str) -> AuditRecord {
        self.rows(tool).pop().unwrap()
    }

    /// The outcome the last row of `tool` was completed with.
    pub fn last_outcome(&self, tool: &str) -> Outcome {
        let row = self.last_row(tool);
        let completion: Completion = row.completion.unwrap();
        completion.outcome
    }

    /// Every token the fake App issued.
    pub fn tokens(&self) -> Vec<String> {
        self.app
            .issued()
            .into_iter()
            .map(|issued| issued.token)
            .collect()
    }

    /// Waits a moment for a row's completion to be written after its answer.
    pub async fn settle(&self) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    /// Waits, in real time, until the row `row` is past its deadline, before which its receipt
    /// is not due.
    pub async fn past_deadline(&self, row: &AuditRowId) {
        let deadline = self.store.deadline(row).expect("the row has a deadline");
        while SystemTime::now() <= deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Team A's ServiceAccount.
pub const TEAM_A: &str = TEAM_A_SA;
/// Team B's ServiceAccount.
pub const TEAM_B: &str = TEAM_B_SA;

/// The comment entry, narrowed per call, which [`Options::comments`] adds.
pub const COMMENT_ENTRY: &str = "github-comment";
/// The surface that serves the comment tool to team A and team B.
pub const COMMENT_SURFACE: &str = "github-comment";
/// The permission set the comment entry states: the tool's own.
pub const COMMENT_PERMISSIONS: &str = r#"{ pull_requests = "write" }"#;
/// The comment tool.
pub const PR_COMMENT: &str = connector_github::pr_comment::PR_COMMENT;
/// Otto's name for it, which a turn grant lists.
pub const OTTO_PR_COMMENT: &str = "github_pr_comment";
/// The exception the workloads' profile names it in, as decision 0011, section 9, names it.
pub const EXCEPTION: &str = "otto-comment-tools";
/// The turn grants' issuer.
pub const GRANT_ISSUER: &str = "otto-test";

/// The comment entry and its surface, serving `github__pr_comment` to team A and team B, the
/// surface's list as `surface_tools` gives it.
fn comment_entry(surface_tools: &str) -> String {
    format!(
        r#"
[[connectors]]
name = "{COMMENT_ENTRY}"
system = "github"
permissions = {COMMENT_PERMISSIONS}
tools = ["{PR_COMMENT}"]
credential = {{ mode = "team_service_identity", principal = "switchboard-test-app" }}
narrowing = "call"
permits = "write"

[[surfaces]]
name = "{COMMENT_SURFACE}"
tools = {surface_tools}
teams = ["team-a", "team-b"]
principals = "any_in_teams_and_groups"
"#
    )
}

/// `text`, a registry file [`registry`] wrote, as [`Options::comments`] has it: with the comment
/// entry and its surface, the tool approved as its connector states it and settled by a lookup
/// in repositories; and the workloads' profile requiring a turn grant and currency, as the
/// profile for Otto's sandboxes does, its own list of exceptions naming the tool when
/// [`Options::exception`] says so. A test registry only: no shipped registry or example lists
/// the exception, which is not in force until its register entry is signed.
pub fn with_comments(text: String, options: &Options) -> String {
    if !options.comments {
        return text;
    }
    // The surface names the tool before it is approved, and the exception names an approved
    // tool, so the entry alone is loaded to hash it.
    let entry_only = Registry::from_toml_str(&format!("{text}{}", comment_entry("[]"))).unwrap();
    let binding =
        built_in_binding_sha256(&entry_only.connectors()[&ConnectorName::new(COMMENT_ENTRY)])
            .unwrap();
    let exceptions = if options.exception {
        format!("exceptions = [{{ name = \"{EXCEPTION}\", tools = [\"{PR_COMMENT}\"] }}]\n")
    } else {
        String::new()
    };
    let mut text = text.replacen(
        "requires_delegation = false\n",
        &format!("requires_delegation = true\nrequires_currency = true\n{exceptions}"),
        1,
    );
    text.push_str(&comment_entry(&format!("[\"{PR_COMMENT}\"]")));
    let definition = connector_github::definitions()
        .into_iter()
        .find(|definition| definition.name == PR_COMMENT)
        .unwrap();
    text.push_str(&approval(&definition, COMMENT_ENTRY, &binding));
    text
}
