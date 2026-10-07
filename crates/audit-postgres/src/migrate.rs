//! The roles and the schema: the SQL that sets up the audit database, and the function that
//! applies it.

use thiserror::Error;
use tokio_postgres::Client;

/// The role that owns the audit schema and runs the migrations.
pub const OWNER_ROLE: &str = "switchboard_owner";

/// The role the gateway connects as.
pub const GATEWAY_ROLE: &str = "switchboard_gateway";

/// The schema that holds the audit tables.
pub const SCHEMA: &str = "switchboard_audit";

/// Creates [`OWNER_ROLE`] and [`GATEWAY_ROLE`] if they do not exist, and lets them connect to
/// the current database, the owner also to create a schema in it. Run by an administrator,
/// connected to the audit database, before [`migrate`]. Safe to run again. Sets no password.
pub const ROLES: &str = include_str!("../sql/roles.sql");

/// One schema change, applied once, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    /// Its position in the order. Recorded once applied.
    pub version: i32,
    /// A short name, recorded with the version.
    pub name: &'static str,
    /// The SQL, run in one transaction with the record that it ran.
    pub sql: &'static str,
}

/// Every migration, in the order they are applied.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "call_rows",
    sql: include_str!("../sql/migrations/0001_call_rows.sql"),
}];

/// Any number, the same in every gateway: two migrators on one database take turns.
const MIGRATION_LOCK: i64 = 0x5357_4244_4155_4401;

/// Why the schema could not be brought up to date.
#[derive(Debug, Error)]
pub enum MigrateError {
    /// The session is not [`OWNER_ROLE`], so what it created would belong to someone else: a
    /// superuser, or the gateway's own role, which must never own the table it writes to.
    #[error("migrations run as {OWNER_ROLE}, and this session is {current_user}")]
    NotOwner {
        /// The session's current role.
        current_user: String,
    },
    /// The database refused a statement. Nothing from the failed migration is kept.
    #[error("the audit schema could not be migrated: {}", crate::store::describe(.0))]
    Database(#[from] tokio_postgres::Error),
}

/// Applies each migration in [`MIGRATIONS`] the database has not recorded, in order, each in
/// one transaction with the record of it. Returns the versions applied.
///
/// The session must be [`OWNER_ROLE`], so the owner owns the schema and everything in it. An
/// administrator may log in as itself and `SET ROLE switchboard_owner` first. Creates the
/// schema and its `migrations` table if they are missing.
pub async fn migrate(client: &mut Client) -> Result<Vec<i32>, MigrateError> {
    let current_user: String = client
        .query_one("SELECT current_user::text", &[])
        .await?
        .get(0);
    if current_user != OWNER_ROLE {
        return Err(MigrateError::NotOwner { current_user });
    }
    let mut applied = Vec::new();
    for migration in MIGRATIONS {
        let transaction = client.transaction().await?;
        transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
            .await?;
        transaction
            .batch_execute(
                "CREATE SCHEMA IF NOT EXISTS switchboard_audit;
                 CREATE TABLE IF NOT EXISTS switchboard_audit.migrations (
                     version    integer     PRIMARY KEY,
                     name       text        NOT NULL,
                     applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
                 );",
            )
            .await?;
        let done = transaction
            .query_opt(
                "SELECT 1 FROM switchboard_audit.migrations WHERE version = $1",
                &[&migration.version],
            )
            .await?
            .is_some();
        if done {
            transaction.commit().await?;
            continue;
        }
        transaction.batch_execute(migration.sql).await?;
        transaction
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await?;
        transaction.commit().await?;
        applied.push(migration.version);
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_in_order_and_numbered_from_one() {
        let versions: Vec<i32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let expected: Vec<i32> = (1..).take(MIGRATIONS.len()).collect();
        assert_eq!(versions, expected);
    }

    #[test]
    fn the_sql_names_the_roles_and_schema_these_constants_name() {
        for name in [OWNER_ROLE, GATEWAY_ROLE] {
            assert!(ROLES.contains(&format!("CREATE ROLE {name}")), "{name}");
        }
        assert!(MIGRATIONS[0].sql.contains(&format!("{SCHEMA}.call_rows")));
        assert!(MIGRATIONS[0].sql.contains(&format!("TO {GATEWAY_ROLE}")));
    }
}
