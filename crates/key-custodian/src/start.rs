//! The custodian's configuration file, and starting it.
//!
//! ```toml
//! # The socket the gateway connects to, and the one UID it is served to.
//! socket = "/run/switchboard-custodian/custodian.sock"
//! socket_mode = 0o660          # the default; a mode giving others any access is refused
//! peer_uid = 10001
//!
//! # The registry file the gateway loads its snapshot from, read again every few seconds.
//! registry = "/etc/switchboard/registry/registry.toml"
//! registry_poll_seconds = 5    # the default
//!
//! # Optional: GET /metrics on an address of its own.
//! metrics = "0.0.0.0:9465"
//!
//! [github]
//! api_url = "https://api.github.com"
//! ca_file = "/etc/ssl/certs/ca-certificates.crt"   # required for https
//! app_id = "123456"
//! installation_id = 7890
//! account = "example-org"      # the account the App is installed on
//! key_file = "/run/secrets/github-app/private-key.pem"
//! deadline_seconds = 10        # the default
//!
//! [limits]                     # the defaults
//! requests_per_minute = 30
//! burst = 10
//! token_lifetime_seconds = 300
//! ```
//!
//! [`start`] refuses to start, with a [`StartError`], when:
//!
//! - the key file is missing, cannot be read, gives its group or others any access, or does
//!   not hold an RSA private key in PEM;
//! - `socket_mode` gives others any access, or something other than a socket is at `socket`;
//! - the registry file does not load;
//! - `api_url` is not https with a CA file, or plain http to a loopback address;
//! - a limit is out of its range.
//!
//! A socket left at `socket` by an earlier run is removed. The new one is set to `socket_mode`
//! explicitly once bound, whatever the umask.

use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::github::{ApiConfigError, AppKey, GitHubApp, GitHubConfig};
use crate::metrics::{Counters, serve_metrics};
use crate::policy::{PolicyCell, PolicyError};
use crate::rate::{DEFAULT_BURST, DEFAULT_PER_MINUTE, RateLimiter};
use crate::record::Recorder;
use crate::server::Custodian;

/// The default lifetime of a token handed out: five minutes. A token is asked for per call,
/// and the gateway's longest call deadline is a minute.
pub const DEFAULT_LIFETIME_SECONDS: u64 = 300;

/// The longest lifetime: GitHub's own, an hour.
pub const MAX_LIFETIME_SECONDS: u64 = 3600;

fn default_socket_mode() -> u32 {
    0o660
}

fn default_poll() -> u64 {
    5
}

fn default_deadline() -> u64 {
    10
}

/// The configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The socket's path.
    pub socket: PathBuf,
    /// The socket's mode once bound.
    #[serde(default = "default_socket_mode")]
    pub socket_mode: u32,
    /// The UID of the one process served: the gateway's.
    pub peer_uid: u32,
    /// The registry file.
    pub registry: PathBuf,
    /// How often the registry file is read again.
    #[serde(default = "default_poll")]
    pub registry_poll_seconds: u64,
    /// Where `GET /metrics` is served, if anywhere.
    #[serde(default)]
    pub metrics: Option<SocketAddr>,
    /// GitHub.
    pub github: GitHubSection,
    /// The rate and lifetime limits.
    #[serde(default)]
    pub limits: Limits,
}

/// The `[github]` table.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSection {
    /// The API's base URL.
    pub api_url: String,
    /// The CAs trusted for an https URL.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// The App's ID or client ID.
    pub app_id: String,
    /// The installation tokens are issued for.
    pub installation_id: u64,
    /// The account the App is installed on: every repository asked for must be on it.
    pub account: String,
    /// The App's private key, in PEM.
    pub key_file: PathBuf,
    /// How long a call to GitHub may take, in seconds.
    #[serde(default = "default_deadline")]
    pub deadline_seconds: u64,
}

/// The `[limits]` table.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Token requests per minute per team, sustained.
    pub requests_per_minute: u32,
    /// Token requests at once per team.
    pub burst: u32,
    /// How long a token handed out lives, in seconds.
    pub token_lifetime_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: DEFAULT_PER_MINUTE,
            burst: DEFAULT_BURST,
            token_lifetime_seconds: DEFAULT_LIFETIME_SECONDS,
        }
    }
}

impl Config {
    /// The configuration in `text`.
    pub fn from_toml_str(text: &str) -> Result<Self, StartError> {
        toml::from_str(text).map_err(|error| StartError::Config(error.to_string()))
    }

    /// The configuration in the file at `path`.
    pub fn load(path: &Path) -> Result<Self, StartError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            StartError::Config(format!("could not read `{}`: {error}", path.display()))
        })?;
        Self::from_toml_str(&text)
    }

    fn check(&self) -> Result<(), StartError> {
        let range = |name: &'static str, value: u64, low: u64, high: u64| {
            if (low..=high).contains(&value) {
                Ok(())
            } else {
                Err(StartError::Limit {
                    name,
                    low,
                    high,
                    value,
                })
            }
        };
        range(
            "limits.requests_per_minute",
            self.limits.requests_per_minute.into(),
            1,
            3600,
        )?;
        range("limits.burst", self.limits.burst.into(), 1, 1000)?;
        range(
            "limits.token_lifetime_seconds",
            self.limits.token_lifetime_seconds,
            1,
            MAX_LIFETIME_SECONDS,
        )?;
        range(
            "github.deadline_seconds",
            self.github.deadline_seconds,
            1,
            60,
        )?;
        range("registry_poll_seconds", self.registry_poll_seconds, 1, 300)?;
        if self.github.account.is_empty() || self.github.app_id.is_empty() {
            return Err(StartError::Config(
                "`github.account` and `github.app_id` must not be empty".into(),
            ));
        }
        if self.socket_mode & 0o007 != 0 || self.socket_mode > 0o777 {
            return Err(StartError::SocketMode(self.socket_mode));
        }
        Ok(())
    }
}

/// Why the custodian refused to start.
#[derive(Debug, Error)]
pub enum StartError {
    /// The configuration file could not be read or does not parse.
    #[error("the configuration is not valid: {0}")]
    Config(String),
    /// A limit is out of its range.
    #[error("`{name}` is {value}; it must be from {low} to {high}")]
    Limit {
        /// The setting.
        name: &'static str,
        /// Its lowest value.
        low: u64,
        /// Its highest value.
        high: u64,
        /// The value given.
        value: u64,
    },
    /// There is no key file.
    #[error("there is no key file at `{0}`")]
    NoKey(PathBuf),
    /// The key file gives its group or others some access.
    #[error("the key file `{path}` has mode {mode:o}; it must give its group and others no access")]
    KeyOpen {
        /// The file.
        path: PathBuf,
        /// Its mode.
        mode: u32,
    },
    /// The key file could not be read.
    #[error("the key file `{0}` could not be read")]
    KeyUnreadable(PathBuf),
    /// The key file does not hold a key that signs.
    #[error("the key file `{0}` does not hold an RSA private key in PEM")]
    KeyInvalid(PathBuf),
    /// `socket_mode` gives others some access.
    #[error("`socket_mode` is {0:o}; the socket must give others no access")]
    SocketMode(u32),
    /// Something other than a socket is at the socket's path.
    #[error("`{0}` exists and is not a socket")]
    SocketPathTaken(PathBuf),
    /// The socket could not be bound or its mode set.
    #[error("could not serve on `{path}`: {message}")]
    Socket {
        /// The path.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },
    /// The registry file does not give a copy of policy.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The GitHub client could not be built.
    #[error(transparent)]
    Api(#[from] ApiConfigError),
    /// The metrics address could not be bound.
    #[error("could not serve metrics on {address}: {message}")]
    Metrics {
        /// The address.
        address: SocketAddr,
        /// What went wrong.
        message: String,
    },
}

/// The App key in the file at `path`, if the file is the owner's alone and holds one.
fn read_key(path: &Path) -> Result<AppKey, StartError> {
    let metadata = std::fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => StartError::NoKey(path.to_owned()),
        _ => StartError::KeyUnreadable(path.to_owned()),
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StartError::KeyOpen {
            path: path.to_owned(),
            mode,
        });
    }
    let pem = std::fs::read(path).map_err(|_| StartError::KeyUnreadable(path.to_owned()))?;
    AppKey::from_pem(&pem).map_err(|_| StartError::KeyInvalid(path.to_owned()))
}

/// The socket at `path`, bound and set to `mode`. A socket an earlier run left is removed.
fn bind(path: &Path, mode: u32) -> Result<UnixListener, StartError> {
    let failed = |error: std::io::Error| StartError::Socket {
        path: path.to_owned(),
        message: error.to_string(),
    };
    match std::fs::symlink_metadata(path) {
        Ok(existing) if existing.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(failed)?;
        }
        Ok(_) => return Err(StartError::SocketPathTaken(path.to_owned())),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path).map_err(failed)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(failed)?;
    Ok(listener)
}

/// A running custodian.
pub struct Running {
    stop: Option<oneshot::Sender<()>>,
    server: JoinHandle<()>,
    tasks: Vec<JoinHandle<()>>,
    socket: PathBuf,
    metrics: Option<SocketAddr>,
    counters: Arc<Counters>,
}

impl Running {
    /// The socket's path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Where metrics are served, if anywhere.
    pub fn metrics(&self) -> Option<SocketAddr> {
        self.metrics
    }

    /// The counters, as the metrics listener renders them.
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Stops accepting, stops the policy watch and the metrics listener, and removes the
    /// socket. Connections already accepted finish on their own.
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.server).await;
        for task in &self.tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.server.abort();
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Starts the custodian `config` describes, writing its record to `record`.
pub async fn start(config: Config, record: Box<dyn Write + Send>) -> Result<Running, StartError> {
    config.check()?;
    let key = read_key(&config.github.key_file)?;
    let (policy, loaded) = PolicyCell::load(&config.registry)?;
    let github = GitHubApp::new(
        &GitHubConfig {
            api_url: &config.github.api_url,
            ca_file: config.github.ca_file.as_deref(),
            app_id: &config.github.app_id,
            installation_id: config.github.installation_id,
            deadline: Duration::from_secs(config.github.deadline_seconds),
        },
        key,
    )?;
    let metrics = match config.metrics {
        Some(address) => {
            Some(
                TcpListener::bind(address)
                    .await
                    .map_err(|error| StartError::Metrics {
                        address,
                        message: error.to_string(),
                    })?,
            )
        }
        None => None,
    };
    let listener = bind(&config.socket, config.socket_mode)?;

    let counters = Arc::new(Counters::default());
    let custodian = Arc::new(Custodian {
        policy: policy.clone(),
        github,
        rate: RateLimiter::new(config.limits.requests_per_minute, config.limits.burst),
        lifetime: Duration::from_secs(config.limits.token_lifetime_seconds),
        peer_uid: config.peer_uid,
        account: config.github.account.clone(),
        record: Recorder::new(record),
        counters: counters.clone(),
    });
    let mut tasks = vec![tokio::spawn(policy.watch(
        config.registry.clone(),
        Duration::from_secs(config.registry_poll_seconds),
        loaded,
        counters.clone(),
    ))];
    let mut metrics_address = None;
    if let Some(listener) = metrics {
        metrics_address = listener.local_addr().ok();
        let counters = counters.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(error) =
                serve_metrics(listener, counters, std::future::pending::<()>()).await
            {
                tracing::error!(%error, "the metrics listener failed");
            }
        }));
    }
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(custodian.serve(listener, async {
        let _ = stopped.await;
    }));
    tracing::info!(socket = %config.socket.display(), "serving token requests");
    Ok(Running {
        stop: Some(stop),
        server,
        tasks,
        socket: config.socket,
        metrics: metrics_address,
        counters,
    })
}
