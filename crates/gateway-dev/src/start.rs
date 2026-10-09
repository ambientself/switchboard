//! Starting the gateway on the fixture world.

use std::fmt;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use gateway::{BootError, Config, Wiring, boot, serve_with_shutdown};
use gateway_core::{AuditStore, InstanceName};
use gateway_identity::{Clock, SigningAlgorithm, SystemClock};
use gateway_testkit::{
    AUDIENCE, CONNECTOR, Caller, FakeCredentialSource, FixtureConnector, GROUP_G,
    InMemoryAuditStore, IssuerError, LocalIssuer, TEAM_A_SUBJECT, TEAM_B_SUBJECT, TokenBuilder,
    USER_ISSUER, USER_SUBJECT, WORKLOAD_ISSUER,
};
use serde_json::json;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::printer::AuditPrinter;
use crate::world::{FixtureResources, fixture_config};

/// The address the fixture gateway listens on: loopback, always.
pub const LISTEN_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The instance the fixture gateway's audit rows record, unless [`Options::instance`] says
/// otherwise.
pub const DEV_INSTANCE: &str = "switchboard-dev";

/// Why the fixture gateway did not start.
#[derive(Debug, Error)]
pub enum DevError {
    /// An issuer's key could not be generated.
    #[error(transparent)]
    Issuer(#[from] IssuerError),
    /// The fixture configuration did not read as a gateway configuration.
    #[error("the fixture configuration is not valid: {0}")]
    Config(#[from] serde_json::Error),
    /// The boot gates refused the fixture configuration.
    #[error("the gateway refused to start: {0}")]
    Boot(#[from] BootError),
    /// The listener could not be bound, or the server failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// How to start the fixture gateway. [`Options::default`] is what
/// [`start_fixture_gateway`] uses: an ephemeral port on loopback, identity enforced, audit in
/// memory, the system clock, the instance [`DEV_INSTANCE`], and no audit printing.
pub struct Options {
    port: u16,
    instance: InstanceName,
    identity_disabled: bool,
    audit_disabled: bool,
    clock: Arc<dyn Clock>,
    audit_printer: Option<Box<dyn Write + Send>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            port: 0,
            instance: InstanceName::new(DEV_INSTANCE),
            identity_disabled: false,
            audit_disabled: false,
            clock: Arc::new(SystemClock),
            audit_printer: None,
        }
    }
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("port", &self.port)
            .field("instance", &self.instance)
            .field("identity_disabled", &self.identity_disabled)
            .field("audit_disabled", &self.audit_disabled)
            .field("audit_printer", &self.audit_printer.is_some())
            .finish_non_exhaustive()
    }
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Listens on `port` on [`LISTEN_HOST`]. Zero, the default, picks a free port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Names the instance every audit row records as the one that began it.
    pub fn instance(mut self, instance: InstanceName) -> Self {
        self.instance = instance;
        self
    }

    /// Starts with `"identity": {"disabled": true}`: no caller is checked, no tool is listed
    /// and every call is refused.
    pub fn identity_disabled(mut self) -> Self {
        self.identity_disabled = true;
        self
    }

    /// Starts with `"audit": {"disabled": true}` and no store: calls run with no row. The
    /// in-memory store is still made, and stays empty.
    pub fn audit_disabled(mut self) -> Self {
        self.audit_disabled = true;
        self
    }

    /// The clock the gateway verifies tokens and times calls with, and that tokens are issued
    /// at. The system clock unless set.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Writes each audit row to `out` as a JSON line as it is written; see [`AuditPrinter`].
    pub fn print_audit_to(mut self, out: Box<dyn Write + Send>) -> Self {
        self.audit_printer = Some(out);
        self
    }
}

/// The gateway serving the fixture world on loopback, with handles to every fake behind it.
///
/// Dropping it stops the server; [`shutdown`](Self::shutdown) stops it and waits.
pub struct FixtureGateway {
    address: SocketAddr,
    clock: Arc<dyn Clock>,
    workload_issuer: LocalIssuer,
    user_issuer: LocalIssuer,
    store: Arc<InMemoryAuditStore>,
    connector: Arc<FixtureConnector>,
    credentials: Arc<FakeCredentialSource>,
    stop: Option<oneshot::Sender<()>>,
    serving: JoinHandle<io::Result<()>>,
}

impl fmt::Debug for FixtureGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixtureGateway")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// Starts the gateway on the fixture world with [`Options::default`]: a free port on
/// `127.0.0.1`, identity enforced against two local issuers on the system clock, every call
/// recorded in an [`InMemoryAuditStore`], and the [`FixtureConnector`] behind every tool.
///
/// Call it inside a Tokio runtime: the server runs on a task of its own.
pub async fn start_fixture_gateway() -> Result<FixtureGateway, DevError> {
    start_fixture_gateway_with(Options::default()).await
}

/// Starts the gateway on the fixture world as `options` say.
pub async fn start_fixture_gateway_with(options: Options) -> Result<FixtureGateway, DevError> {
    let Options {
        port,
        instance,
        identity_disabled,
        audit_disabled,
        clock,
        audit_printer,
    } = options;
    let workload_issuer = LocalIssuer::new(WORKLOAD_ISSUER, SigningAlgorithm::Es256)?;
    let user_issuer = LocalIssuer::new(USER_ISSUER, SigningAlgorithm::Es256)?;
    let credentials = Arc::new(FakeCredentialSource::new());
    let connector = Arc::new(FixtureConnector::new(credentials.clone()));
    let store = Arc::new(InMemoryAuditStore::new());

    let mut config = fixture_config(&workload_issuer, &user_issuer);
    if identity_disabled {
        config["identity"] = json!({"disabled": true});
    }
    let mut wiring = Wiring::new(clock.clone()).instance(instance).connector(
        CONNECTOR,
        connector.clone(),
        Arc::new(FixtureResources),
    );
    if audit_disabled {
        config["audit"] = json!({"disabled": true});
    } else {
        let audit: Arc<dyn AuditStore> = match audit_printer {
            Some(out) => Arc::new(AuditPrinter::new(store.clone(), out)),
            None => store.clone(),
        };
        wiring = wiring.audit_store(audit);
    }
    let config: Config = serde_json::from_value(config)?;
    let gates = boot::check(config, wiring)?;

    let listener = TcpListener::bind(SocketAddr::from((LISTEN_HOST, port))).await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let serving = tokio::spawn(serve_with_shutdown(listener, gates, async {
        // A dropped sender stops the server too.
        let _ = stopped.await;
    }));
    Ok(FixtureGateway {
        address,
        clock,
        workload_issuer,
        user_issuer,
        store,
        connector,
        credentials,
        stop: Some(stop),
        serving,
    })
}

impl FixtureGateway {
    /// Where the gateway listens.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The endpoint for `surface`: `http://127.0.0.1:<port>/mcp/<surface>`.
    pub fn url(&self, surface: &str) -> String {
        format!("{}/mcp/{surface}", self.base_url())
    }

    /// A valid token for `caller`, issued now by the gateway's clock and living
    /// [`DEFAULT_TOKEN_LIFETIME`](gateway_testkit::DEFAULT_TOKEN_LIFETIME) seconds.
    pub fn token(&self, caller: Caller) -> String {
        self.token_builder(caller).build()
    }

    /// The token [`token`](Self::token) builds, before it is signed, so a test can change or
    /// break one part of it.
    pub fn token_builder(&self, caller: Caller) -> TokenBuilder<'_> {
        let now = self.clock.now();
        match caller {
            Caller::TeamA => self
                .workload_issuer
                .workload_token(TEAM_A_SUBJECT, AUDIENCE, now),
            Caller::TeamB => self
                .workload_issuer
                .workload_token(TEAM_B_SUBJECT, AUDIENCE, now),
            Caller::UserInGroupG => {
                self.user_issuer
                    .user_token(USER_SUBJECT, AUDIENCE, &[GROUP_G], now)
            }
        }
    }

    /// The workload issuer the gateway trusts: team A's and team B's tokens.
    pub fn workload_issuer(&self) -> &LocalIssuer {
        &self.workload_issuer
    }

    /// The user issuer the gateway trusts.
    pub fn user_issuer(&self) -> &LocalIssuer {
        &self.user_issuer
    }

    /// The gateway's clock.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The audit store every row is written to.
    pub fn store(&self) -> &Arc<InMemoryAuditStore> {
        &self.store
    }

    /// The connector behind every tool.
    pub fn connector(&self) -> &Arc<FixtureConnector> {
        &self.connector
    }

    /// The credential source the connector asks.
    pub fn credentials(&self) -> &Arc<FakeCredentialSource> {
        &self.credentials
    }

    /// Stops taking connections, and returns once every tool call started has completed its
    /// row. A connection still open after the shutdown grace is closed, and a request on it
    /// that had not started its answer is not answered.
    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match (&mut self.serving).await {
            Ok(served) => served,
            Err(error) => Err(io::Error::other(error)),
        }
    }
}
