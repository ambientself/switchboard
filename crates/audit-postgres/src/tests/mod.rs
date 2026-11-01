//! Tests against a real Postgres server.
//!
//! Each runs only when `SWITCHBOARD_TEST_DATABASE_URL` names a superuser on a throwaway
//! server, and otherwise passes without doing anything, so CI without Postgres skips them.
//! They live inside the crate so they can reach the store's pools and its completion step,
//! which the crate does not export.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod budgets;
mod check;
mod contract;
mod latency;
mod open_rows;
mod receipts;
mod reconcile;
mod recovery;
mod schema;
mod stats;
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

/// Tests run in parallel. Creating databases, and changing the roles, memberships and grants on
/// settings that the whole server shares, is done one test at a time, because two sessions
/// updating one row of a shared catalog at once fail ("tuple concurrently updated").
static SETUP: Mutex<()> = Mutex::const_new(());

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A database of its own for one test, with the roles, the dummy passwords and the schema in
/// place. Dropped, with every connection to it, when the test ends, whether or not it passed.
pub(crate) struct TestDatabase {
    server: Config,
    name: String,
    /// Roles made for this test alone, dropped with the database.
    roles: std::sync::Mutex<Vec<String>>,
}

impl TestDatabase {
    /// `None`, after saying so, when no test server is configured.
    pub(crate) async fn create() -> Option<Self> {
        Self::create_with("").await
    }

    /// The same, with `options` after `CREATE DATABASE` and its name, such as an encoding.
    pub(crate) async fn create_with(options: &str) -> Option<Self> {
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
        let database = Self {
            server,
            name,
            roles: std::sync::Mutex::default(),
        };
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
                .batch_execute(&format!("CREATE DATABASE {} {options}", database.name))
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
        assert_eq!(
            migrate(&mut owner).await.unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
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

    /// Runs `sql` in this database as the server's superuser, one test at a time. For
    /// statements that change what the whole server shares: roles, memberships, role defaults
    /// and grants on settings. Two sessions changing one row of a shared catalog at once fail,
    /// as two tests granting on one setting do, or one granting while another's teardown
    /// revokes.
    pub(crate) async fn cluster_wide(&self, sql: &str) {
        let _one_at_a_time = SETUP.lock().await;
        self.admin().await.batch_execute(sql).await.unwrap();
    }

    /// A store connected as the gateway's role.
    pub(crate) fn store(&self, sizes: PoolSizes) -> PgAuditStore {
        PgAuditStore::connect(self.config_as(GATEWAY_ROLE), NoTls, sizes).unwrap()
    }

    /// Makes a role of this test's own, with `attributes` as `CREATE ROLE` spells them, a
    /// member of each of `member_of` (inheriting what they hold), and the dummy password.
    /// Roles belong to the whole server, so a test that needs a role unlike the gateway's
    /// makes one rather than changing the gateway's role under other tests. Dropped with the
    /// database.
    pub(crate) async fn new_role(&self, attributes: &str, member_of: &[&str]) -> String {
        let role = {
            let mut roles = self.roles.lock().unwrap();
            let role = format!("{}_role_{}", self.name, roles.len());
            roles.push(role.clone());
            role
        };
        let _one_at_a_time = SETUP.lock().await;
        let admin = self.admin().await;
        admin
            .batch_execute(&format!(
                "CREATE ROLE {role} PASSWORD '{DUMMY_PASSWORD}' {attributes}"
            ))
            .await
            .unwrap();
        for group in member_of {
            admin
                .batch_execute(&format!("GRANT {group} TO {role}"))
                .await
                .unwrap();
        }
        role
    }

    /// A store connected as a new role with `attributes` that holds whatever the gateway's
    /// role holds, through membership, and is a member of `also` besides.
    pub(crate) async fn store_like_gateway(&self, attributes: &str, also: &[&str]) -> PgAuditStore {
        let mut member_of = vec![GATEWAY_ROLE];
        member_of.extend_from_slice(also);
        let role = self
            .new_role(&format!("LOGIN {attributes}"), &member_of)
            .await;
        self.store_as(&role)
    }

    /// A store connected as `role`.
    pub(crate) fn store_as(&self, role: &str) -> PgAuditStore {
        PgAuditStore::connect(self.config_as(role), NoTls, PoolSizes::default()).unwrap()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // Drop runs inside the test's runtime, which cannot be blocked on, so the database is
        // dropped from a thread with a runtime of its own.
        let server = self.server.clone();
        let name = self.name.clone();
        let roles = std::mem::take(&mut *self.roles.lock().unwrap_or_else(|e| e.into_inner()));
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let server = connect(&server).await;
                server
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await?;
                // The database is gone, and with it everything granted in it. DROP OWNED
                // revokes what a role holds on things the whole server shares, such as a
                // setting, so the role can then be dropped.
                let _one_at_a_time = SETUP.lock().await;
                for role in roles {
                    server
                        .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
                        .await?;
                }
                Ok::<(), tokio_postgres::Error>(())
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!(
                "the test database {} or one of its roles was not dropped",
                self.name
            );
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

/// The columns migration 0010 adds (decision 0012), for a read-back's `SELECT`.
pub(crate) const DELEGATION_COLUMNS: &str = "proved_pod, delegation_digest, delegation_issuer,
    delegation_key_id, delegation_session, delegation_turn, delegation_execution,
    delegation_epoch, delegation_egress, delegation_failure, currency";

/// The columns migration 0010 adds, as an SQL array of their names: a test that a migration
/// before it keeps the rows already written takes them out of what it compares.
pub(crate) const ADDED_BY_0010: &str = "ARRAY['proved_pod', 'delegation_digest',
    'delegation_issuer', 'delegation_key_id', 'delegation_session', 'delegation_turn',
    'delegation_execution', 'delegation_epoch', 'delegation_egress', 'delegation_failure',
    'currency']";

/// The column migration 0012 adds (decision 0011, section 9): a read-back reads it, and a
/// test that a migration before it keeps the rows already written takes it out of what it
/// compares.
pub(crate) const EXCEPTION_COLUMN: &str = "allowed_by_exception";

/// What a row read with [`DELEGATION_COLUMNS`] records of decision 0012, as the core's record
/// writes it in JSON: the pod, the verified delegation, the failure and the currency answer.
/// The pod goes in the principal.
pub(crate) struct DelegationRead {
    pub pod: Option<String>,
    pub delegation: serde_json::Value,
    pub failure: serde_json::Value,
    pub currency: serde_json::Value,
}

impl DelegationRead {
    pub(crate) fn of(row: &tokio_postgres::Row) -> Self {
        use serde_json::json;
        let text = |column: &str| row.get::<_, Option<String>>(column);
        let delegation = match text("delegation_issuer") {
            None => serde_json::Value::Null,
            Some(issuer) => json!({
                "digest": text("delegation_digest"),
                "issuer": issuer,
                "key_id": text("delegation_key_id"),
                "session": text("delegation_session"),
                "turn": text("delegation_turn"),
                "execution": text("delegation_execution"),
                "epoch": row.get::<_, Option<i64>>("delegation_epoch"),
                "egress": text("delegation_egress"),
            }),
        };
        let failure = match text("delegation_failure") {
            None => serde_json::Value::Null,
            Some(failure) => json!({
                "failure": failure,
                "digest": text("delegation_digest"),
            }),
        };
        Self {
            pod: text("proved_pod"),
            delegation,
            failure,
            currency: json!(text("currency")),
        }
    }
}

/// The SQLSTATE for a missing privilege.
pub(crate) const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The SQLSTATE for a failed check constraint.
pub(crate) const CHECK_VIOLATION: &str = "23514";

/// The SQLSTATE for a missing value in a `NOT NULL` column.
pub(crate) const NOT_NULL_VIOLATION: &str = "23502";
