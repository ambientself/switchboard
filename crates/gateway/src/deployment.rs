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
//!
//! [identity]
//! mode = "enforce"            # or "disabled", with nothing else in the table
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
//! issuer = "http://issuer.internal:8081"
//! kind = "user"
//! audiences = ["switchboard"]
//! algorithm = "ES256"
//! keys_url = "http://issuer.internal:8081/jwks"   # instead of keys_file
//! keys_refresh_seconds = 300                      # 300 if left out; at least 30
//! max_lifetime_seconds = 3600
//! leeway_seconds = 30
//!
//! [audit]
//! mode = "postgres"           # or "disabled", with nothing else in the table
//! url_env = "SWITCHBOARD_DATABASE_URL"
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
//!     ([`start::prepare`](crate::start::prepare)). This build has no TLS client, so an `https`
//!     URL, which an `https` issuer needs, is refused when the gateway starts (issue #88).
//!     `keys_refresh_seconds` belongs to `keys_url` and is refused beside `keys_file`.
//! - **The team manifest** is a TOML table of subject to team:
//!
//!   ```toml
//!   [subjects]
//!   "system:serviceaccount:team-a:mock-workload" = "team-a"
//!   ```
//!
//! - **The database URL** is read from the environment variable `url_env` names, so no password
//!   is written in the file.
//! - **Credentials** map each registry server's credential reference to the file holding it.
//!   Every server's reference must be here, and nothing else may be.
//!
//! Every table refuses fields it does not know. Only `listen` has a default, [`DEFAULT_LISTEN`],
//! so a gateway not told where to listen is reachable from its own machine only. Any other
//! missing field is an error, and so is a field that does not belong to the chosen mode or kind,
//! such as `subjects_file` on a user issuer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use gateway_core::{DeploymentName, Issuer, Subject, TeamId};
use serde::Deserialize;
use thiserror::Error;

use crate::config::{
    Algorithm, AuditSection, HttpSection, IdentitySection, IssuerEntry, IssuerKindEntry,
};
use crate::keys::{DEFAULT_KEYS_REFRESH, MIN_KEYS_REFRESH};

/// Where the gateway listens when the deployment file does not say: loopback only, never every
/// interface.
pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

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
    /// Each credential reference the registry's servers name, and the file holding it.
    pub credentials: BTreeMap<String, PathBuf>,
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
    /// The identity gate, with every team manifest read and the keys of every issuer with a
    /// keys file. An issuer with a keys URL has `null` keys here until
    /// [`start::prepare`](crate::start::prepare) fetches them; it is listed in `keys_urls`.
    pub identity: IdentitySection,
    /// Each issuer whose keys are fetched from a URL, in the order the file lists them.
    pub keys_urls: Vec<KeysUrl>,
    /// The audit store.
    pub audit: AuditChoice,
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
}

impl std::fmt::Debug for KeysUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysUrl")
            .field("issuer", &self.issuer)
            .field("refresh", &self.refresh)
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
            identity,
            keys_urls,
            audit,
            credentials: file
                .credentials
                .into_iter()
                .map(|(reference, path)| (reference, base.join(path)))
                .collect(),
        })
    }
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
