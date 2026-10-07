//! The checks a gateway runs before it serves: the table it writes to is the one it expects,
//! and the role it connects as can do what the store needs and nothing more.

use std::collections::BTreeSet;
use std::fmt;

use deadpool_postgres::ClientWrapper;
use thiserror::Error;

use crate::store::{PgAuditStore, describe};

/// Every column of `call_rows` the store writes or reads, with its type as Postgres's
/// `format_type` names it.
pub(crate) const COLUMNS: &[(&str, &str)] = &[
    ("id", "uuid"),
    ("begun_at", "timestamp with time zone"),
    ("finished_at", "timestamp with time zone"),
    ("tool_use_id", "text"),
    ("deployment", "text"),
    ("surface", "text"),
    ("profile", "text"),
    ("tool", "text"),
    ("connector", "text"),
    ("classification", "text"),
    ("resources", "jsonb"),
    ("resources_omitted", "bigint"),
    ("decision", "text"),
    ("reason", "text"),
    ("sentence", "text"),
    ("policy_revision", "text"),
    ("proved_issuer", "text"),
    ("proved_subject", "text"),
    ("proved_kind", "text"),
    ("proved_team", "text"),
    ("proved_groups", "text[]"),
    ("proved_delegation_team", "text"),
    ("claimed_acting_person", "text"),
    ("claimed_team", "text"),
    ("outcome", "text"),
    ("outcome_sentence", "text"),
    ("latency_ms", "bigint"),
];

/// The columns the gateway's role inserts: the first half of a row, without the identifier,
/// the times or the completion.
pub(crate) const INSERTED: &[&str] = &[
    "tool_use_id",
    "deployment",
    "surface",
    "profile",
    "tool",
    "connector",
    "classification",
    "resources",
    "resources_omitted",
    "decision",
    "reason",
    "sentence",
    "policy_revision",
    "proved_issuer",
    "proved_subject",
    "proved_kind",
    "proved_team",
    "proved_groups",
    "proved_delegation_team",
    "claimed_acting_person",
    "claimed_team",
];

/// The columns the gateway's role updates: the completion.
pub(crate) const UPDATED: &[&str] = &["outcome", "outcome_sentence", "latency_ms"];

/// The columns the gateway's role reads: which row, whether it was allowed, its completion.
pub(crate) const SELECTED: &[&str] = &[
    "id",
    "decision",
    "outcome",
    "outcome_sentence",
    "latency_ms",
];

/// Settings that must hold for a committed row to be durable.
const DURABILITY: &[(&str, &str)] = &[("fsync", "on"), ("full_page_writes", "on")];

/// One reason the store will not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// The server does not keep committed rows safe.
    Setting {
        /// The setting.
        name: &'static str,
        /// What it is.
        found: String,
        /// What it must be.
        expected: &'static str,
    },
    /// `switchboard_audit.call_rows` is not there.
    TableMissing,
    /// A column the store writes or reads is not there.
    ColumnMissing {
        /// The column.
        column: &'static str,
    },
    /// A column has another type than the store writes.
    ColumnType {
        /// The column.
        column: &'static str,
        /// The type it has.
        found: String,
        /// The type it must have.
        expected: &'static str,
    },
    /// The trigger that completes a row at most once is not on the table.
    TriggerMissing,
    /// The trigger is on the table but does not fire.
    TriggerDisabled,
    /// The session's role, or a role it can become, has an attribute that lets it around the
    /// grants or the trigger.
    RoleAttribute {
        /// The role with the attribute.
        role: String,
        /// The attribute, as `CREATE ROLE` spells it.
        attribute: &'static str,
    },
    /// The session's role owns, or is a member of the role that owns, an audit object, so it
    /// could change or drop it.
    Owns {
        /// The object.
        object: String,
    },
    /// The session's role holds a privilege the store does not need.
    Extra {
        /// The privilege.
        privilege: String,
        /// What it is held on.
        object: String,
    },
    /// The session's role lacks a privilege the store needs.
    Missing {
        /// The privilege.
        privilege: String,
        /// What it is needed on.
        object: String,
    },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setting {
                name,
                found,
                expected,
            } => write!(
                f,
                "the server has {name} = {found}, and committed rows are durable only with {expected}"
            ),
            Self::TableMissing => write!(f, "the table switchboard_audit.call_rows does not exist"),
            Self::ColumnMissing { column } => {
                write!(f, "the column call_rows.{column} does not exist")
            }
            Self::ColumnType {
                column,
                found,
                expected,
            } => write!(
                f,
                "the column call_rows.{column} is {found}, not {expected}"
            ),
            Self::TriggerMissing => write!(
                f,
                "the trigger complete_once, which completes a row at most once, is not on call_rows"
            ),
            Self::TriggerDisabled => {
                write!(f, "the trigger complete_once on call_rows is disabled")
            }
            Self::RoleAttribute { role, attribute } => write!(
                f,
                "the role {role}, which this session is or can become, has {attribute}"
            ),
            Self::Owns { object } => write!(
                f,
                "this session's role owns {object}, or is a member of the role that does"
            ),
            Self::Extra { privilege, object } => write!(
                f,
                "this session's role holds {privilege} on {object}, which the gateway must not have"
            ),
            Self::Missing { privilege, object } => write!(
                f,
                "this session's role lacks {privilege} on {object}, which the store needs"
            ),
        }
    }
}

/// Why [`PgAuditStore::check_at_boot`] refused.
#[derive(Debug, Error)]
pub enum BootCheckError {
    /// The database or the role is not fit to hold the audit log. Every problem found is
    /// listed.
    #[error("the audit store will not start: as role {role}, {}", list(.problems))]
    Unfit {
        /// The session's role.
        role: String,
        /// Every problem found.
        problems: Vec<Problem>,
    },
    /// No connection could be had.
    #[error("the audit store will not start: no connection to the audit database: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
    /// A check's query failed.
    #[error("the audit store will not start: a check failed: {}", describe(.0))]
    Database(#[from] tokio_postgres::Error),
}

fn list(problems: &[Problem]) -> String {
    let all: Vec<String> = problems.iter().map(ToString::to_string).collect();
    all.join("; ")
}

const CALL_ROWS: &str = "switchboard_audit.call_rows";

impl PgAuditStore {
    /// Checks, as the role the store connects as, that the store can be trusted to write the
    /// audit log, and refuses otherwise, naming every reason. Run it at boot, before serving,
    /// and do not serve if it fails.
    ///
    /// - The server syncs commits to disk: `fsync` and `full_page_writes` are on.
    /// - `switchboard_audit.call_rows` has every column the store uses, with its type, and its
    ///   write-once trigger, enabled.
    /// - The role is not a superuser, and cannot create roles or databases, replicate, or
    ///   bypass row security; nor can any role it is a member of.
    /// - The role does not own the schema, the table, the trigger function or anything else in
    ///   the schema, and is not a member of a role that does.
    /// - The role holds exactly its own privileges: inserting the first half of a row,
    ///   updating the completion, selecting the identifier, decision and completion, and using
    ///   the schema. Nothing on the table as a whole, so it cannot DELETE or TRUNCATE; no
    ///   CREATE on the schema or the database; nothing on any other table or sequence in the
    ///   schema; and it cannot set `session_replication_role`, which would silence the
    ///   trigger.
    ///
    /// Has no time limit: wrap it in one if boot must not wait on the database.
    pub async fn check_at_boot(&self) -> Result<(), BootCheckError> {
        let client = self.begin.get().await?;
        check(&client).await
    }
}

async fn check(client: &ClientWrapper) -> Result<(), BootCheckError> {
    let mut problems = Vec::new();
    let session = client
        .query_one(
            "SELECT current_user::text, current_setting('server_version_num')::int",
            &[],
        )
        .await?;
    let role: String = session.get(0);
    let version: i32 = session.get(1);

    for (name, expected) in DURABILITY {
        let found: String = client
            .query_one("SELECT current_setting($1)", &[name])
            .await?
            .get(0);
        problems.extend(setting_problem(name, found, expected));
    }

    role_attributes(client, &mut problems).await?;
    ownership(client, &mut problems).await?;

    // The catalog is read directly, by name, so a missing schema or table is a problem found
    // rather than an error.
    let table = client
        .query_opt(
            "SELECT c.oid FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'switchboard_audit' AND c.relname = 'call_rows'
                 AND c.relkind IN ('r', 'p')",
            &[],
        )
        .await?
        .map(|row| row.get::<_, tokio_postgres::types::Oid>(0));
    match table {
        None => problems.push(Problem::TableMissing),
        Some(table) => {
            columns(client, table, &mut problems).await?;
            trigger(client, table, &mut problems).await?;
            column_privileges(client, table, &mut problems).await?;
        }
    }
    other_privileges(client, version, &mut problems).await?;

    if problems.is_empty() {
        Ok(())
    } else {
        Err(BootCheckError::Unfit { role, problems })
    }
}

/// A problem if the setting `name` is `found` rather than `expected`.
fn setting_problem(name: &'static str, found: String, expected: &'static str) -> Option<Problem> {
    (found != expected).then_some(Problem::Setting {
        name,
        found,
        expected,
    })
}

async fn role_attributes(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    // Attributes are not inherited, but a member can SET ROLE to any role it belongs to.
    let roles = client
        .query(
            "SELECT rolname::text, rolsuper, rolcreaterole, rolcreatedb, rolreplication,
                    rolbypassrls
             FROM pg_catalog.pg_roles
             WHERE pg_has_role(current_user, oid, 'MEMBER')
             ORDER BY rolname",
            &[],
        )
        .await?;
    for row in roles {
        let name: String = row.get(0);
        for (index, attribute) in [
            (1, "SUPERUSER"),
            (2, "CREATEROLE"),
            (3, "CREATEDB"),
            (4, "REPLICATION"),
            (5, "BYPASSRLS"),
        ] {
            if row.get::<_, bool>(index) {
                problems.push(Problem::RoleAttribute {
                    role: name.clone(),
                    attribute,
                });
            }
        }
    }
    Ok(())
}

async fn ownership(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let owned = client
        .query(
            "SELECT 'the schema ' || n.nspname
             FROM pg_catalog.pg_namespace n
             WHERE n.nspname = 'switchboard_audit'
                 AND pg_has_role(current_user, n.nspowner, 'MEMBER')
             UNION ALL
             SELECT 'the relation ' || n.nspname || '.' || c.relname
             FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'switchboard_audit'
                 AND pg_has_role(current_user, c.relowner, 'MEMBER')
             UNION ALL
             SELECT 'the function ' || n.nspname || '.' || p.proname
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'switchboard_audit'
                 AND pg_has_role(current_user, p.proowner, 'MEMBER')
             ORDER BY 1",
            &[],
        )
        .await?;
    problems.extend(
        owned
            .into_iter()
            .map(|row| Problem::Owns { object: row.get(0) }),
    );
    Ok(())
}

async fn columns(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let found = client
        .query(
            "SELECT attname::text, format_type(atttypid, atttypmod)
             FROM pg_catalog.pg_attribute
             WHERE attrelid = $1::oid AND attnum > 0 AND NOT attisdropped",
            &[&table],
        )
        .await?;
    for (column, expected) in COLUMNS {
        match found.iter().find(|row| row.get::<_, &str>(0) == *column) {
            None => problems.push(Problem::ColumnMissing { column }),
            Some(row) => {
                let found: String = row.get(1);
                if found != *expected {
                    problems.push(Problem::ColumnType {
                        column,
                        found,
                        expected,
                    });
                }
            }
        }
    }
    Ok(())
}

async fn trigger(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    // The trigger must call the schema's own function. 'O' fires in a normal session and 'A'
    // always; 'D' never and 'R' only for replication.
    let found = client
        .query_opt(
            "SELECT t.tgenabled::text
             FROM pg_catalog.pg_trigger t
                 JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
                 JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE t.tgrelid = $1::oid AND t.tgname = 'complete_once' AND NOT t.tgisinternal
                 AND n.nspname = 'switchboard_audit' AND p.proname = 'complete_once'",
            &[&table],
        )
        .await?;
    match found.map(|row| row.get::<_, String>(0)) {
        None => problems.push(Problem::TriggerMissing),
        Some(enabled) if enabled != "O" && enabled != "A" => {
            problems.push(Problem::TriggerDisabled);
        }
        Some(_) => {}
    }
    Ok(())
}

/// The table-level privileges a role may hold, by server version.
fn table_privileges(version: i32) -> Vec<&'static str> {
    let mut privileges = vec![
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ];
    if version >= 170_000 {
        privileges.push("MAINTAIN");
    }
    privileges
}

async fn column_privileges(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let held = client
        .query(
            "SELECT a.attname::text, p
             FROM pg_catalog.pg_attribute a,
                 unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p
             WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped
                 AND has_column_privilege(current_user, $1::oid, a.attnum, p)",
            &[&table],
        )
        .await?;
    let held: BTreeSet<(String, String)> = held
        .into_iter()
        .map(|row| (row.get(1), row.get(0)))
        .collect();
    let mut expected = BTreeSet::new();
    for (privilege, columns) in [
        ("INSERT", INSERTED),
        ("UPDATE", UPDATED),
        ("SELECT", SELECTED),
    ] {
        for column in columns {
            expected.insert((privilege.to_owned(), (*column).to_owned()));
        }
    }
    // A privilege on the whole table shows on every column; it is reported once, for the
    // table, by `other_privileges`.
    let whole: BTreeSet<String> = client
        .query(
            "SELECT p FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p
             WHERE has_table_privilege(current_user, $1::oid, p)",
            &[&table],
        )
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    for (privilege, column) in held.difference(&expected) {
        if !whole.contains(privilege) {
            problems.push(Problem::Extra {
                privilege: privilege.clone(),
                object: format!("{CALL_ROWS}.{column}"),
            });
        }
    }
    for (privilege, column) in expected.difference(&held) {
        problems.push(Problem::Missing {
            privilege: privilege.clone(),
            object: format!("{CALL_ROWS}.{column}"),
        });
    }
    Ok(())
}

async fn other_privileges(
    client: &ClientWrapper,
    version: i32,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    // Nothing on any table, view or foreign table in the schema as a whole, and nothing at all
    // on any but call_rows.
    let privileges = table_privileges(version);
    let held = client
        .query(
            "SELECT n.nspname || '.' || c.relname, p
             FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                 unnest($1::text[]) AS p
             WHERE n.nspname = 'switchboard_audit' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                 AND (has_table_privilege(current_user, c.oid, p)
                     OR (c.relname <> 'call_rows'
                         AND p IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
                         AND has_any_column_privilege(current_user, c.oid, p)))
             UNION ALL
             SELECT n.nspname || '.' || c.relname, p
             FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                 unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p
             WHERE n.nspname = 'switchboard_audit' AND c.relkind = 'S'
                 AND has_sequence_privilege(current_user, c.oid, p)
             ORDER BY 1, 2",
            &[&privileges],
        )
        .await?;
    for row in held {
        problems.push(Problem::Extra {
            privilege: row.get(1),
            object: row.get(0),
        });
    }

    let schema = client
        .query_opt(
            "SELECT has_schema_privilege(current_user, oid, 'USAGE'),
                    has_schema_privilege(current_user, oid, 'CREATE')
             FROM pg_catalog.pg_namespace WHERE nspname = 'switchboard_audit'",
            &[],
        )
        .await?;
    if let Some(schema) = schema {
        if !schema.get::<_, bool>(0) {
            problems.push(Problem::Missing {
                privilege: "USAGE".into(),
                object: "the schema switchboard_audit".into(),
            });
        }
        if schema.get::<_, bool>(1) {
            problems.push(Problem::Extra {
                privilege: "CREATE".into(),
                object: "the schema switchboard_audit".into(),
            });
        }
    }

    let database = client
        .query_one(
            "SELECT current_database()::text,
                    has_database_privilege(current_user, current_database(), 'CREATE')",
            &[],
        )
        .await?;
    if database.get::<_, bool>(1) {
        problems.push(Problem::Extra {
            privilege: "CREATE".into(),
            object: format!("the database {}", database.get::<_, String>(0)),
        });
    }

    // From version 15 a role can be granted the right to set a superuser setting.
    if version >= 150_000 {
        let can_set: bool = client
            .query_one(
                "SELECT has_parameter_privilege(current_user, 'session_replication_role', 'SET')",
                &[],
            )
            .await?
            .get(0);
        if can_set {
            problems.push(Problem::Extra {
                privilege: "SET".into(),
                object: "the setting session_replication_role".into(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MIGRATIONS;
    use crate::columns::BeginRow;

    #[test]
    fn the_checked_columns_are_the_ones_the_store_writes() {
        // Every inserted column is in the INSERT, in its order.
        let insert = BeginRow::INSERT;
        let listed = &insert[insert.find('(').unwrap() + 1..insert.find(')').unwrap()];
        let listed: Vec<&str> = listed.split(',').map(str::trim).collect();
        assert_eq!(listed, INSERTED);
        for column in INSERTED.iter().chain(UPDATED).chain(SELECTED) {
            assert!(
                COLUMNS.iter().any(|(name, _)| name == column),
                "{column} is not checked"
            );
        }
    }

    #[test]
    fn the_checked_privileges_are_the_ones_the_migration_grants() {
        let sql = MIGRATIONS[0].sql;
        let granted = |privilege: &str| -> Vec<String> {
            let start = sql.find(&format!("GRANT {privilege} (")).unwrap();
            let rest = &sql[start..];
            let inner = &rest[rest.find('(').unwrap() + 1..rest.find(')').unwrap()];
            inner.split(',').map(|c| c.trim().to_owned()).collect()
        };
        assert_eq!(granted("INSERT"), INSERTED);
        assert_eq!(granted("UPDATE"), UPDATED);
        assert_eq!(granted("SELECT"), SELECTED);
    }

    #[test]
    fn a_setting_that_loses_committed_rows_is_a_problem() {
        assert_eq!(setting_problem("fsync", "on".into(), "on"), None);
        let problem = setting_problem("fsync", "off".into(), "on").unwrap();
        assert_eq!(
            problem.to_string(),
            "the server has fsync = off, and committed rows are durable only with on"
        );
        assert_eq!(DURABILITY, &[("fsync", "on"), ("full_page_writes", "on")]);
    }

    #[test]
    fn maintain_is_checked_only_where_it_exists() {
        assert!(!table_privileges(160_004).contains(&"MAINTAIN"));
        assert!(table_privileges(170_000).contains(&"MAINTAIN"));
        assert!(table_privileges(160_004).contains(&"DELETE"));
        assert!(table_privileges(160_004).contains(&"TRUNCATE"));
    }
}
