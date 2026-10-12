//! The deployment file: what the `switchboard` binary is started with.
//!
//! One TOML file names everything else the gateway reads at boot: the registry file, each
//! trusted issuer with the file or URL holding its keys and, for a workload issuer, the team
//! manifest, the audit store, and the file holding each proxied server's credential. Relative
//! paths are read from the deployment file's own directory.
//!
//! ```toml
//! deployment = "compose-demo"
//! listen = "0.0.0.0:8080"     # 127.0.0.1:8080 if left out
//!
//! [http]
//! allowed_hosts = ["gateway", "127.0.0.1", "localhost"]
//! allowed_origins = []
//!
//! [registry]
//! file = "/etc/switchboard/registry/registry.toml"
//! poll_seconds = 2
//! max_age_seconds = 60        # 60 if left out; at least twice poll_seconds
//!
//! [identity]
//! mode = "enforce"            # or "disabled" (test-support builds only), alone in the table
//!
//! [[identity.issuers]]
//! issuer = "https://dev-issuer.switchboard.test"
//! kind = "workload"           # or "user", with an optional groups_claim
//! audiences = ["switchboard"]
//! algorithm = "RS256"         # or "ES256"
//! keys_file = "/shared/issuer/jwks.json"
//! subjects_file = "teams.toml"
//! max_lifetime_seconds = 3600
//! leeway_seconds = 30
//!
//! [[identity.issuers]]
//! issuer = "https://issuer.internal:8443"
//! kind = "user"
//! audiences = ["switchboard"]
//! algorithm = "ES256"
//! keys_url = "https://issuer.internal:8443/jwks"  # instead of keys_file
//! keys_ca_file = "issuer-ca.pem"                  # needed for https; the only CAs trusted
//! keys_token_file = "/run/secrets/issuer-token"   # optional; read again on every fetch
//! keys_refresh_seconds = 300                      # 300 if left out; at least 30
//! max_lifetime_seconds = 3600
//! leeway_seconds = 30
//!
//! [audit]
//! mode = "postgres"           # or "disabled" (test-support builds only), alone in the table
//! url_env = "SWITCHBOARD_DATABASE_URL"
//!
//! [metrics]                   # optional; left out, nothing serves metrics
//! listen = "0.0.0.0:9090"
//!
//! [limits]                    # optional; these are the defaults
//! max_in_flight = 256         # requests in flight in this instance
//! per_server_in_flight = 32   # calls in flight to each proxied server
//! per_team_per_server_in_flight = 8  # from each team to each proxied server
//!
//! [servers.mock-docs]         # optional, for a server the registry names
//! deadline_seconds = 5        # 5 if left out; 1 to 60
//! max_result_bytes = 65536    # 64 KiB if left out; 1 to 1 MiB
//!
//! [drift]                     # optional
//! interval_seconds = 300      # 300 if left out; 5 to 900
//!
//! [credentials]
//! docs-credential = "/run/secrets/docs-credential"
//! ```
//!
//! - **Keys** are a JWK set, `{"keys": [...]}`, as an issuer publishes it (a cluster's
//!   `/openid/v1/jwks`). Each issuer takes exactly one of `keys_file` and `keys_url`; both, or
//!   neither, is refused.
//!   - `keys_file` is read once, at boot. Nothing is fetched, and rotating a key means writing
//!     the file and restarting the gateway.
//!   - `keys_url` is fetched from the issuer's own origin (the same scheme, host and port) at
//!     boot, and again every `keys_refresh_seconds`: 300 unless given, and at least 30 (see
//!     [`crate::keys`]). Loading the file checks only these fields. The URL's origin is checked,
//!     and the first fetch made, when the gateway starts
//!     ([`start::prepare`](crate::start::prepare)).
//!   - An `https` keys URL needs `keys_ca_file`, a PEM bundle of the only CAs its certificate
//!     may chain to, read when the gateway starts. `keys_token_file`, if given, holds a bearer
//!     token sent with each fetch to the keys URL only, and is read again on every fetch, so a
//!     token rotated in place is the one sent. The gateway refuses to start with either beside
//!     an `http` keys URL.
//!   - `keys_refresh_seconds`, `keys_ca_file` and `keys_token_file` belong to `keys_url` and are
//!     refused beside `keys_file`.
//! - **The team manifest** is a TOML table of subject to team:
//!
//!   ```toml
//!   [subjects]
//!   "system:serviceaccount:team-a:mock-workload" = "team-a"
//!   ```
//!
//! - **The maximum age** of the policy is `registry.max_age_seconds` since the registry file
//!   was last read successfully, whether or not that version loaded (decision 0013, section 8):
//!   [`DEFAULT_MAX_AGE`] if it is not given, and refused below twice `poll_seconds`, so one
//!   slow or failed read never makes the policy stale. Past it, `/readyz` fails and
//!   `tools/call` and `tools/list` are refused until a read succeeds.
//! - **The database URL** is read from the environment variable `url_env` names, so no password
//!   is written in the file.
//! - **Credentials** map each registry server's credential reference to the file holding it.
//!   Every server's reference must be here, and nothing else may be.
//! - **Metrics** are served in Prometheus text at `GET /metrics` on a listener of their own
//!   (see [`crate::metrics`]), and only when `[metrics]` is given. Its `listen` may not take
//!   the MCP listener's port on the same or an overlapping address: the two are never one
//!   listener.
//! - **Limits** are decision 0014's caps, each at least 1, and hold in each instance, not across
//!   replicas. `max_in_flight` bounds the requests to `POST /mcp/{surface}` in flight: one over
//!   it is answered 503 before its body is read, with no row. `per_server_in_flight` bounds the
//!   calls in flight to each proxied server, and `per_team_per_server_in_flight` those from
//!   each team to each server, by the caller's proved team; a caller with no team is held by
//!   the server's cap alone. A call over either is completed as `refused`, with a capacity
//!   sentence, and nothing is sent (see [`crate::bulkhead`]).
//! - **Each server's bounds** are set under `[servers.<name>]`, for a server the registry names;
//!   the gateway refuses to start with any other (see [`crate::start`]). `deadline_seconds`
//!   bounds a call from sending it to the last byte of its answer, and `max_result_bytes` the
//!   answer's HTTP body. Zero, or a value past [`MAX_SERVER_DEADLINE`] or
//!   [`MAX_SERVER_RESULT_BYTES`], is refused. The deployment's termination grace must cover
//!   the longest deadline set (decision 0014, section 1).
//! - **The drift pass** reads each proxied server's tool list every `drift.interval_seconds`,
//!   and withdraws a tool whose served definition no longer matches its approval (see
//!   [`crate::drift`]): [`DEFAULT_DRIFT_INTERVAL`](crate::drift::DEFAULT_DRIFT_INTERVAL) if it
//!   is not given, and refused below 5 or above 900 (decision 0013, section 5).
//!
//! Every table refuses fields it does not know. Only `listen`, `registry.max_age_seconds`, the
//! limits, each server's bounds and the drift interval have defaults, so a gateway not told where to listen is
//! reachable from its own machine only. Any other missing field is an error, and so is a field that does not belong to the chosen mode or kind,
//! such as `subjects_file` on a user issuer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use connector_proxy::{DEFAULT_DEADLINE, DEFAULT_MAX_RESPONSE_BYTES};
use gateway_core::{ConnectorName, DeploymentName, Issuer, Subject, TeamId};
use serde::Deserialize;
use thiserror::Error;

use crate::config::{
    Algorithm, AuditSection, HttpSection, IdentitySection, IssuerEntry, IssuerKindEntry,
};
use crate::drift::{DriftError, DriftSection};
use crate::keys::{DEFAULT_KEYS_REFRESH, MIN_KEYS_REFRESH};

/// Where the gateway listens when the deployment file does not say: loopback only, never every
/// interface.
pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

/// How long after the registry file was last read the policy is stale, when the deployment file
/// does not say (decision 0013, section 8).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60);

/// How many requests to `POST /mcp/{surface}` may be in flight in one instance, unless
/// `[limits]` says otherwise (decision 0014, section 2).
pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;

/// How many calls may be in flight to one proxied server in one instance, unless `[limits]`
/// says otherwise.
pub const DEFAULT_PER_SERVER_IN_FLIGHT: usize = 32;

/// How many calls may be in flight from one team to one proxied server in one instance, unless
/// `[limits]` says otherwise.
pub const DEFAULT_PER_TEAM_PER_SERVER_IN_FLIGHT: usize = 8;

/// The longest deadline a server's entry may set (decision 0014, section 1).
pub const MAX_SERVER_DEADLINE: Duration = Duration::from_secs(60);

/// The largest answer a server's entry may allow, in bytes: 1 MiB.
pub const MAX_SERVER_RESULT_BYTES: usize = 1024 * 1024;

/// The deployment file as written.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentFile {
    /// The deployment's name, recorded on every audit row.
    pub deployment: DeploymentName,
    /// The address the gateway listens on, [`DEFAULT_LISTEN`] if it is not given.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// What the HTTP endpoint accepts.
    pub http: HttpSection,
    /// Where the policy comes from.
    pub registry: RegistrySection,
    /// Whether and how callers are verified.
    pub identity: IdentityFile,
    /// Where audit rows go.
    pub audit: AuditFile,
    /// Where metrics are served, if anywhere.
    #[serde(default)]
    pub metrics: Option<MetricsSection>,
    /// The caps on calls in flight, where they differ from the defaults.
    #[serde(default)]
    pub limits: Option<LimitsSection>,
    /// Each proxied server's bounds, where they differ from the defaults.
    #[serde(default)]
    pub servers: BTreeMap<ConnectorName, ServerSection>,
    /// How often the drift pass runs, where it differs from the default.
    #[serde(default)]
    pub drift: Option<DriftSection>,
    /// Each credential reference the registry's servers name, and the file holding it.
    pub credentials: BTreeMap<String, PathBuf>,
}

impl DeploymentFile {
    /// The longest call deadline the file sets for any server, or [`DEFAULT_DEADLINE`] if it
    /// sets none longer. The deployment's termination grace must cover it.
    pub fn longest_deadline(&self) -> Duration {
        self.servers
            .values()
            .filter_map(|server| server.deadline_seconds)
            .map(Duration::from_secs)
            .fold(DEFAULT_DEADLINE, Duration::max)
    }
}

/// The caps on calls in flight, as written. Each field left out has its default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    /// Requests in flight in the instance; [`DEFAULT_MAX_IN_FLIGHT`] if left out.
    #[serde(default)]
    pub max_in_flight: Option<usize>,
    /// Calls in flight to each proxied server; [`DEFAULT_PER_SERVER_IN_FLIGHT`] if left out.
    #[serde(default)]
    pub per_server_in_flight: Option<usize>,
    /// Calls in flight from each team to each proxied server;
    /// [`DEFAULT_PER_TEAM_PER_SERVER_IN_FLIGHT`] if left out.
    #[serde(default)]
    pub per_team_per_server_in_flight: Option<usize>,
}

/// One proxied server's bounds, as written. Each field left out has its default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// How long a call may take, in seconds: 1 to 60, and [`DEFAULT_DEADLINE`] if left out.
    #[serde(default)]
    pub deadline_seconds: Option<u64>,
    /// The largest answer accepted, in bytes: 1 to [`MAX_SERVER_RESULT_BYTES`], and
    /// [`DEFAULT_MAX_RESPONSE_BYTES`] if left out.
    #[serde(default)]
    pub max_result_bytes: Option<usize>,
}

/// The caps on calls in flight in one instance (decision 0014, section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Requests to `POST /mcp/{surface}` in flight.
    pub max_in_flight: usize,
    /// Calls in flight to each proxied server.
    pub per_server_in_flight: usize,
    /// Calls in flight from each team to each proxied server.
    pub per_team_per_server_in_flight: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            per_server_in_flight: DEFAULT_PER_SERVER_IN_FLIGHT,
            per_team_per_server_in_flight: DEFAULT_PER_TEAM_PER_SERVER_IN_FLIGHT,
        }
    }
}

/// One proxied server's bounds on each call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    /// How long a call may take, from sending it to the last byte of its answer.
    pub deadline: Duration,
    /// The largest answer accepted, in bytes of HTTP body.
    pub max_result_bytes: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_DEADLINE,
            max_result_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// The metrics listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSection {
    /// The address `GET /metrics` is served on. Never the MCP listener's.
    pub listen: SocketAddr,
}

fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN
}

/// The registry file, and how often it is read again.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySection {
    /// The registry file. Mount the directory holding it, so a replaced file is seen.
    pub file: PathBuf,
    /// How often, in seconds, the file is read again for a new version. At least 1.
    pub poll_seconds: u64,
    /// How long, in seconds, after the last successful read the policy is stale.
    /// [`DEFAULT_MAX_AGE`] if it is not given, and at least twice `poll_seconds`.
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

/// The identity gate.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityFile {
    /// Verify every caller against these issuers.
    Enforce {
        /// The trusted issuers.
        issuers: Vec<IssuerFile>,
    },
    /// Verify nobody. The gateway lists no tools and refuses every call.
    ///
    /// An empty struct, not a unit variant: serde ignores the other fields of a table whose tag
    /// names a unit variant, so `mode = "disabled"` with issuers still listed would load.
    Disabled {},
}

/// One trusted issuer, as the deployment file writes it.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerFile {
    /// The issuer, matched exactly against a token's `iss`.
    pub issuer: Issuer,
    /// `workload` or `user`.
    pub kind: IssuerKindName,
    /// The audiences accepted for this issuer.
    pub audiences: BTreeSet<String>,
    /// The one algorithm this issuer signs with.
    pub algorithm: Algorithm,
    /// The file holding the issuer's JWK set, read once at boot. Exactly one of this and
    /// `keys_url`.
    #[serde(default)]
    pub keys_file: Option<PathBuf>,
    /// The URL of the issuer's JWK set, on the issuer's own origin, fetched at boot and on a
    /// timer. Exactly one of this and `keys_file`.
    #[serde(default)]
    pub keys_url: Option<String>,
    /// With `keys_url`, and only with it: how often, in seconds, the keys are fetched again.
    /// [`DEFAULT_KEYS_REFRESH`] if it is not given, and at least [`MIN_KEYS_REFRESH`].
    #[serde(default)]
    pub keys_refresh_seconds: Option<u64>,
    /// With an `https` `keys_url`, and only with one: the PEM bundle of the CAs its certificate
    /// is verified against, and the only ones trusted.
    #[serde(default)]
    pub keys_ca_file: Option<PathBuf>,
    /// With an `https` `keys_url`, and only with one: a file holding a bearer token sent with
    /// each fetch, read again on every fetch.
    #[serde(default)]
    pub keys_token_file: Option<PathBuf>,
    /// For a workload issuer, and only for one: the team manifest.
    #[serde(default)]
    pub subjects_file: Option<PathBuf>,
    /// For a user issuer, and only for one: the claim holding the user's groups, `groups` if
    /// it is not given.
    #[serde(default)]
    pub groups_claim: Option<String>,
    /// The longest a token may live, in seconds.
    pub max_lifetime_seconds: u64,
    /// Clock skew tolerated, in seconds.
    pub leeway_seconds: u64,
}

/// What an issuer's tokens are about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerKindName {
    /// Workloads, mapped to teams by the team manifest.
    Workload,
    /// Users, with groups from a claim.
    User,
}

/// The team manifest: which team each workload subject belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamManifest {
    /// Subject to team.
    pub subjects: BTreeMap<Subject, TeamId>,
}

/// The audit gate.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditFile {
    /// Write every call's row to Postgres.
    Postgres {
        /// The environment variable holding the database URL.
        url_env: String,
    },
    /// Record nothing. An empty struct for the same reason as [`IdentityFile::Disabled`].
    Disabled {},
}

/// Why the deployment file, or a file it names, was refused.
#[derive(Debug, Error)]
pub enum DeploymentError {
    /// A file could not be read.
    #[error("cannot read `{path}`: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The deployment file is not valid TOML of the right shape.
    #[error("`{path}` is not a valid deployment file: {message}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        message: String,
    },
    /// The registry is polled less than once a second, or never.
    #[error("`registry.poll_seconds` must be at least 1")]
    PollTooFast,
    /// The maximum age is under two polls, so one late read would make the policy stale.
    #[error(
        "`registry.max_age_seconds` is {max_age}, and must be at least twice \
         `registry.poll_seconds`, {least}"
    )]
    MaxAgeTooShort {
        /// The maximum age, given or the default, in seconds.
        max_age: u64,
        /// Twice the poll interval, in seconds.
        least: u64,
    },
    /// A workload issuer has no team manifest.
    #[error("workload issuer `{0}` needs `subjects_file`, its team manifest")]
    NoManifest(Issuer),
    /// A user issuer was given a team manifest.
    #[error("user issuer `{0}` has `subjects_file`, which only a workload issuer takes")]
    ManifestForUser(Issuer),
    /// A workload issuer was given a groups claim.
    #[error("workload issuer `{0}` has `groups_claim`, which only a user issuer takes")]
    GroupsForWorkload(Issuer),
    /// An issuer was given neither a keys file nor a keys URL.
    #[error("issuer `{0}` needs `keys_file` or `keys_url`, where its keys are")]
    NoKeys(Issuer),
    /// An issuer was given both a keys file and a keys URL.
    #[error("issuer `{0}` has both `keys_file` and `keys_url`; give one")]
    KeysTwice(Issuer),
    /// An issuer whose keys are in a file was given a refresh interval.
    #[error("issuer `{0}` has `keys_refresh_seconds`, which only an issuer with `keys_url` takes")]
    RefreshForKeysFile(Issuer),
    /// An issuer whose keys are in a file was given a CA file or a token file for fetching them.
    #[error("issuer `{issuer}` has `{field}`, which only an issuer with `keys_url` takes")]
    FetchFileForKeysFile {
        /// The issuer.
        issuer: Issuer,
        /// `keys_ca_file` or `keys_token_file`.
        field: &'static str,
    },
    /// An issuer's keys would be fetched more often than the minimum allows.
    #[error(
        "issuer `{issuer}` has `keys_refresh_seconds = {seconds}`; it must be at least {}",
        MIN_KEYS_REFRESH.as_secs()
    )]
    RefreshTooFast {
        /// The issuer.
        issuer: Issuer,
        /// The interval given, in seconds.
        seconds: u64,
    },
    /// An issuer's keys file is not a JSON object.
    #[error("the keys file `{path}` is not JSON: {message}")]
    Keys {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        message: String,
    },
    /// A team manifest is not valid TOML of the right shape.
    #[error("the team manifest `{path}` is not valid: {message}")]
    Manifest {
        /// The file.
        path: PathBuf,
        /// What the parser said.
        message: String,
    },
    /// The database URL's environment variable is not set.
    #[error("the environment variable `{0}`, which `audit.url_env` names, is not set")]
    NoDatabaseUrl(String),
    /// A cap in `[limits]` is zero.
    #[error("`limits.{0}` must be at least 1")]
    LimitZero(&'static str),
    /// A server's deadline is zero or past [`MAX_SERVER_DEADLINE`].
    #[error(
        "`servers.{server}.deadline_seconds` is {seconds}; it must be from 1 to {}",
        MAX_SERVER_DEADLINE.as_secs()
    )]
    DeadlineOutOfRange {
        /// The server.
        server: ConnectorName,
        /// The deadline given, in seconds.
        seconds: u64,
    },
    /// A server's answer cap is zero or past [`MAX_SERVER_RESULT_BYTES`].
    #[error(
        "`servers.{server}.max_result_bytes` is {bytes}; it must be from 1 to \
         {MAX_SERVER_RESULT_BYTES}"
    )]
    ResultBytesOutOfRange {
        /// The server.
        server: ConnectorName,
        /// The cap given, in bytes.
        bytes: usize,
    },
    /// The drift interval is out of range.
    #[error(transparent)]
    Drift(#[from] DriftError),
    /// The metrics listener would take the MCP listener's port.
    #[error(
        "`metrics.listen` ({metrics}) takes the port the gateway listens on for MCP ({listen}); \
         metrics are served on a listener of their own"
    )]
    MetricsOnMcpListener {
        /// The metrics address.
        metrics: SocketAddr,
        /// The MCP address.
        listen: SocketAddr,
    },
}

/// A deployment file with the files it names read: what [`start`](crate::start) builds the
/// gateway from.
#[derive(Clone, PartialEq)]
pub struct Deployment {
    /// The deployment's name.
    pub deployment: DeploymentName,
    /// The address to listen on.
    pub listen: SocketAddr,
    /// What the HTTP endpoint accepts.
    pub http: HttpSection,
    /// The registry file.
    pub registry_file: PathBuf,
    /// How often the registry file is read again.
    pub poll: Duration,
    /// How long after the registry file was last read successfully the policy is stale.
    pub max_age: Duration,
    /// The identity gate, with every team manifest read and the keys of every issuer with a
    /// keys file. An issuer with a keys URL has `null` keys here until
    /// [`start::prepare`](crate::start::prepare) fetches them; it is listed in `keys_urls`.
    pub identity: IdentitySection,
    /// Each issuer whose keys are fetched from a URL, in the order the file lists them.
    pub keys_urls: Vec<KeysUrl>,
    /// The audit store.
    pub audit: AuditChoice,
    /// Where metrics are served, or `None` for nowhere.
    pub metrics: Option<SocketAddr>,
    /// The caps on calls in flight.
    pub limits: Limits,
    /// The bounds of each server the file gives an entry, within their ceilings. Every other
    /// server has [`ServerLimits::default`].
    pub servers: BTreeMap<ConnectorName, ServerLimits>,
    /// How often the drift pass runs.
    pub drift_interval: Duration,
    /// Each credential reference, and the file holding it.
    pub credentials: BTreeMap<String, PathBuf>,
}

impl std::fmt::Debug for Deployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deployment")
            .field("deployment", &self.deployment)
            .field("listen", &self.listen)
            .field("registry_file", &self.registry_file)
            .field("audit", &self.audit)
            .field("metrics", &self.metrics)
            .field("limits", &self.limits)
            .field("servers", &self.servers)
            .field("drift_interval", &self.drift_interval)
            .finish_non_exhaustive()
    }
}

/// An issuer whose keys are fetched from a URL, and how often.
#[derive(Clone, PartialEq, Eq)]
pub struct KeysUrl {
    /// The issuer.
    pub issuer: Issuer,
    /// The URL of its JWK set. Not printed: a URL can carry a password, which the gateway
    /// refuses when it starts.
    pub url: String,
    /// How often the keys are fetched again. Loading the deployment file holds it to at least
    /// [`MIN_KEYS_REFRESH`].
    pub refresh: Duration,
    /// The CA bundle an `https` URL is verified against, from the deployment file's directory.
    pub ca_file: Option<PathBuf>,
    /// The file holding a bearer token for each fetch, from the deployment file's directory.
    /// Only its path is kept; the token is read when a fetch is made.
    pub token_file: Option<PathBuf>,
}

impl std::fmt::Debug for KeysUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysUrl")
            .field("issuer", &self.issuer)
            .field("refresh", &self.refresh)
            .field("ca_file", &self.ca_file)
            .field("token_file", &self.token_file)
            .finish_non_exhaustive()
    }
}

/// Where audit rows go.
#[derive(Clone, PartialEq, Eq)]
pub enum AuditChoice {
    /// Postgres, at this URL. The URL may hold a password, so it is never printed.
    Postgres {
        /// The connection URL.
        url: String,
    },
    /// Nowhere: audit is explicitly disabled.
    Disabled,
}

impl std::fmt::Debug for AuditChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres { .. } => f.write_str("Postgres { url: <hidden> }"),
            Self::Disabled => f.write_str("Disabled"),
        }
    }
}

impl AuditChoice {
    /// The audit section the boot gates read: disabled, or not.
    pub fn section(&self) -> AuditSection {
        AuditSection {
            disabled: matches!(self, Self::Disabled),
        }
    }
}

impl Deployment {
    /// Reads the deployment file at `path` and every file it names, reading environment
    /// variables through `var`.
    pub fn load(
        path: &Path,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, DeploymentError> {
        let text = read_text(path)?;
        let file: DeploymentFile =
            toml::from_str(&text).map_err(|error| DeploymentError::Parse {
                path: path.to_owned(),
                message: error.to_string(),
            })?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_file(file, base, var)
    }

    /// Reads every file `file` names, relative to `base`.
    pub fn from_file(
        file: DeploymentFile,
        base: &Path,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, DeploymentError> {
        if file.registry.poll_seconds == 0 {
            return Err(DeploymentError::PollTooFast);
        }
        let max_age = file
            .registry
            .max_age_seconds
            .unwrap_or(DEFAULT_MAX_AGE.as_secs());
        let least = file.registry.poll_seconds.saturating_mul(2);
        if max_age < least {
            return Err(DeploymentError::MaxAgeTooShort { max_age, least });
        }
        if let Some(metrics) = &file.metrics
            && takes_port(metrics.listen, file.listen)
        {
            return Err(DeploymentError::MetricsOnMcpListener {
                metrics: metrics.listen,
                listen: file.listen,
            });
        }
        let limits = limits(file.limits.unwrap_or_default())?;
        let drift_interval = DriftSection::interval(file.drift.as_ref())?;
        let servers = file
            .servers
            .into_iter()
            .map(|(server, section)| {
                let bounds = server_limits(&server, section)?;
                Ok((server, bounds))
            })
            .collect::<Result<_, DeploymentError>>()?;
        let mut keys_urls = Vec::new();
        let identity = match file.identity {
            IdentityFile::Disabled {} => IdentitySection {
                enforce: None,
                disabled: true,
            },
            IdentityFile::Enforce { issuers } => IdentitySection {
                enforce: Some(
                    issuers
                        .into_iter()
                        .map(|issuer| issuer_entry(issuer, base, &mut keys_urls))
                        .collect::<Result<_, _>>()?,
                ),
                disabled: false,
            },
        };
        let audit = match file.audit {
            AuditFile::Disabled {} => AuditChoice::Disabled,
            AuditFile::Postgres { url_env } => match var(&url_env) {
                Some(url) if !url.is_empty() => AuditChoice::Postgres { url },
                _ => return Err(DeploymentError::NoDatabaseUrl(url_env)),
            },
        };
        Ok(Self {
            deployment: file.deployment,
            listen: file.listen,
            http: file.http,
            registry_file: base.join(file.registry.file),
            poll: Duration::from_secs(file.registry.poll_seconds),
            max_age: Duration::from_secs(max_age),
            identity,
            keys_urls,
            audit,
            metrics: file.metrics.map(|metrics| metrics.listen),
            limits,
            servers,
            drift_interval,
            credentials: file
                .credentials
                .into_iter()
                .map(|(reference, path)| (reference, base.join(path)))
                .collect(),
        })
    }
}

/// The caps `section` sets, each defaulted, and refused if zero.
fn limits(section: LimitsSection) -> Result<Limits, DeploymentError> {
    let defaults = Limits::default();
    let cap = |given: Option<usize>, default: usize, field: &'static str| match given {
        Some(0) => Err(DeploymentError::LimitZero(field)),
        given => Ok(given.unwrap_or(default)),
    };
    Ok(Limits {
        max_in_flight: cap(
            section.max_in_flight,
            defaults.max_in_flight,
            "max_in_flight",
        )?,
        per_server_in_flight: cap(
            section.per_server_in_flight,
            defaults.per_server_in_flight,
            "per_server_in_flight",
        )?,
        per_team_per_server_in_flight: cap(
            section.per_team_per_server_in_flight,
            defaults.per_team_per_server_in_flight,
            "per_team_per_server_in_flight",
        )?,
    })
}

/// The bounds `section` sets for `server`, each defaulted, and refused if zero or past its
/// ceiling.
fn server_limits(
    server: &ConnectorName,
    section: ServerSection,
) -> Result<ServerLimits, DeploymentError> {
    let defaults = ServerLimits::default();
    let deadline = match section.deadline_seconds {
        None => defaults.deadline,
        Some(seconds) if seconds == 0 || seconds > MAX_SERVER_DEADLINE.as_secs() => {
            return Err(DeploymentError::DeadlineOutOfRange {
                server: server.clone(),
                seconds,
            });
        }
        Some(seconds) => Duration::from_secs(seconds),
    };
    let max_result_bytes = match section.max_result_bytes {
        None => defaults.max_result_bytes,
        Some(bytes) if bytes == 0 || bytes > MAX_SERVER_RESULT_BYTES => {
            return Err(DeploymentError::ResultBytesOutOfRange {
                server: server.clone(),
                bytes,
            });
        }
        Some(bytes) => bytes,
    };
    Ok(ServerLimits {
        deadline,
        max_result_bytes,
    })
}

/// Whether a listener on `metrics` would take the MCP listener's port: the same port, other than
/// 0 (any free port), on the same address, or where either is every address.
fn takes_port(metrics: SocketAddr, listen: SocketAddr) -> bool {
    metrics.port() == listen.port()
        && metrics.port() != 0
        && (metrics.ip() == listen.ip()
            || metrics.ip().is_unspecified()
            || listen.ip().is_unspecified())
}

/// One issuer, with its team manifest read, and its keys read from their file or its keys URL
/// added to `keys_urls`. The identity crate's own checks (an audience, a lifetime, a leeway
/// within bounds, keys that fit the algorithm, a manifest that is not empty) run when the boot
/// gates build the identity gate.
fn issuer_entry(
    issuer: IssuerFile,
    base: &Path,
    keys_urls: &mut Vec<KeysUrl>,
) -> Result<IssuerEntry, DeploymentError> {
    let kind = match (issuer.kind, issuer.subjects_file, issuer.groups_claim) {
        (IssuerKindName::Workload, Some(manifest), None) => IssuerKindEntry::Workload {
            subjects: read_manifest(&base.join(manifest))?,
        },
        (IssuerKindName::Workload, None, _) => {
            return Err(DeploymentError::NoManifest(issuer.issuer));
        }
        (IssuerKindName::Workload, Some(_), Some(_)) => {
            return Err(DeploymentError::GroupsForWorkload(issuer.issuer));
        }
        (IssuerKindName::User, None, groups_claim) => IssuerKindEntry::User {
            groups_claim: groups_claim
                .unwrap_or_else(|| gateway_identity::DEFAULT_GROUPS_CLAIM.to_owned()),
        },
        (IssuerKindName::User, Some(_), _) => {
            return Err(DeploymentError::ManifestForUser(issuer.issuer));
        }
    };
    let keys = match (issuer.keys_file, issuer.keys_url) {
        (Some(_), Some(_)) => return Err(DeploymentError::KeysTwice(issuer.issuer)),
        (None, None) => return Err(DeploymentError::NoKeys(issuer.issuer)),
        (Some(file), None) => {
            if issuer.keys_refresh_seconds.is_some() {
                return Err(DeploymentError::RefreshForKeysFile(issuer.issuer));
            }
            if issuer.keys_ca_file.is_some() {
                return Err(DeploymentError::FetchFileForKeysFile {
                    issuer: issuer.issuer,
                    field: "keys_ca_file",
                });
            }
            if issuer.keys_token_file.is_some() {
                return Err(DeploymentError::FetchFileForKeysFile {
                    issuer: issuer.issuer,
                    field: "keys_token_file",
                });
            }
            let keys_path = base.join(file);
            serde_json::from_str(&read_text(&keys_path)?).map_err(|error| {
                DeploymentError::Keys {
                    path: keys_path.clone(),
                    message: error.to_string(),
                }
            })?
        }
        (None, Some(url)) => {
            let refresh = issuer
                .keys_refresh_seconds
                .map_or(DEFAULT_KEYS_REFRESH, Duration::from_secs);
            if refresh < MIN_KEYS_REFRESH {
                return Err(DeploymentError::RefreshTooFast {
                    issuer: issuer.issuer,
                    seconds: refresh.as_secs(),
                });
            }
            keys_urls.push(KeysUrl {
                issuer: issuer.issuer.clone(),
                url,
                refresh,
                ca_file: issuer.keys_ca_file.map(|path| base.join(path)),
                token_file: issuer.keys_token_file.map(|path| base.join(path)),
            });
            // Fetched when the gateway starts. Left unfilled it is not a JWK set, and the
            // identity gate would refuse to build.
            serde_json::Value::Null
        }
    };
    Ok(IssuerEntry {
        issuer: issuer.issuer,
        audiences: issuer.audiences,
        kind,
        algorithm: issuer.algorithm,
        keys,
        max_lifetime_secs: issuer.max_lifetime_seconds,
        leeway_secs: issuer.leeway_seconds,
    })
}

fn read_manifest(path: &Path) -> Result<BTreeMap<Subject, TeamId>, DeploymentError> {
    let manifest: TeamManifest =
        toml::from_str(&read_text(path)?).map_err(|error| DeploymentError::Manifest {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    Ok(manifest.subjects)
}

fn read_text(path: &Path) -> Result<String, DeploymentError> {
    std::fs::read_to_string(path).map_err(|source| DeploymentError::Read {
        path: path.to_owned(),
        source,
    })
}
