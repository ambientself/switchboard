//! Tests against a real Postgres server.
//!
//! Each runs only when `SWITCHBOARD_TEST_DATABASE_URL` names a superuser on a throwaway
//! server, and otherwise passes without doing anything, so CI without Postgres skips them.
//! They live inside the crate so they can reach the store's pools and its completion step,
//! which the crate does not export.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod budgets;
mod schema;
mod store;

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;
use tokio_postgres::{Client, Config, NoTls};

use crate::{GATEWAY_ROLE, OWNER_ROLE, PgAuditStore, PoolSizes, ROLES, migrate};

/// The variable naming the server the tests may use.
const URL_VARIABLE: &str = "SWITCHBOARD_TEST_DATABASE_URL";

/// Given to both roles on the throwaway test server, so the tests can log in as them. A dummy
/// value for tests only, never a credential.
const DUMMY_PASSWORD: &str = "dummy-password-for-tests-only";

/// Tests run in parallel. Creating databases and changing the cluster-wide roles is done one
/// test at a time, because two sessions updating one role at once fail.
static SETUP: Mutex<()> = Mutex::const_new(());

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A database of its own for one test, with the roles, the dummy passwords and the schema in
/// place. Dropped, with every connection to it, when the test ends, whether or not it passed.
pub(crate) struct TestDatabase {
    server: Config,
    name: String,
}

impl TestDatabase {
    /// `None`, after saying so, when no test server is configured.
    pub(crate) async fn create() -> Option<Self> {
        let Ok(url) = std::env::var(URL_VARIABLE) else {
            eprintln!("skipped: {URL_VARIABLE} is not set");
            return None;
        };
        let server: Config = url
            .parse()
            .expect("SWITCHBOARD_TEST_DATABASE_URL is not a Postgres URL");
        let name = format!(
            "switchboard_audit_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let database = Self { server, name };
        {
            let _one_at_a_time = SETUP.lock().await;
            let server = connect(&database.server).await;
            server
                .batch_execute(&format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    database.name
                ))
                .await
                .unwrap();
            server
                .batch_execute(&format!("CREATE DATABASE {}", database.name))
                .await
                .unwrap();
            let admin = database.admin().await;
            admin.batch_execute(ROLES).await.unwrap();
            for role in [OWNER_ROLE, GATEWAY_ROLE] {
                admin
                    .batch_execute(&format!("ALTER ROLE {role} PASSWORD '{DUMMY_PASSWORD}'"))
                    .await
                    .unwrap();
            }
        }
        let mut owner = database.connect_as(OWNER_ROLE).await;
        assert_eq!(migrate(&mut owner).await.unwrap(), vec![1]);
        Some(database)
    }

    /// The database's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// How to connect to this database as the server's superuser.
    pub(crate) fn admin_config(&self) -> Config {
        let mut config = self.server.clone();
        config.dbname(&self.name);
        config
    }

    /// How to connect to this database as `role`.
    pub(crate) fn config_as(&self, role: &str) -> Config {
        let mut config = self.admin_config();
        config.user(role).password(DUMMY_PASSWORD);
        config
    }

    /// A session as the server's superuser.
    pub(crate) async fn admin(&self) -> Client {
        connect(&self.admin_config()).await
    }

    /// A session as `role`.
    pub(crate) async fn connect_as(&self, role: &str) -> Client {
        connect(&self.config_as(role)).await
    }

    /// A store connected as the gateway's role.
    pub(crate) fn store(&self, sizes: PoolSizes) -> PgAuditStore {
        PgAuditStore::connect(self.config_as(GATEWAY_ROLE), NoTls, sizes).unwrap()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // Drop runs inside the test's runtime, which cannot be blocked on, so the database is
        // dropped from a thread with a runtime of its own.
        let server = self.server.clone();
        let name = self.name.clone();
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server = connect(&server).await;
                server
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("the test database {} was not dropped", self.name);
        }
    }
}

/// Connects, and drives the connection on the current runtime.
pub(crate) async fn connect(config: &Config) -> Client {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

/// The SQLSTATE of a failed statement.
pub(crate) fn code(error: &tokio_postgres::Error) -> Option<&str> {
    error.code().map(|code| code.code())
}

/// The message of a failed statement, as the server wrote it.
pub(crate) fn message(error: &tokio_postgres::Error) -> String {
    error
        .as_db_error()
        .map_or_else(|| error.to_string(), |db| db.message().to_owned())
}

/// The SQLSTATE for a missing privilege.
pub(crate) const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The SQLSTATE for a failed check constraint.
pub(crate) const CHECK_VIOLATION: &str = "23514";
