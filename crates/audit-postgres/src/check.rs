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

/// The triggers on `call_rows`, each calling the schema's function of the same name, and when
/// each must fire, as `pg_trigger.tgtype` encodes it: for each row (1), before (2), on insert
/// (4) or on update (16).
pub(crate) const TRIGGERS: &[Trigger] = &[
    Trigger {
        name: "set_times",
        purpose: "sets both times from the database's clock",
        fires: "before each insert",
        tgtype: 1 | 2 | 4,
    },
    Trigger {
        name: "complete_once",
        purpose: "completes a row at most once",
        fires: "before each update",
        tgtype: 1 | 2 | 16,
    },
];

/// A trigger the table must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Trigger {
    name: &'static str,
    purpose: &'static str,
    fires: &'static str,
    tgtype: i16,
}

/// Settings that must hold for a committed row to be durable.
const DURABILITY: &[(&str, &str)] = &[("fsync", "on"), ("full_page_writes", "on")];

/// The predefined roles that reach the server's own files or programs, and so get around every
/// grant and trigger. PostgreSQL documents each as a way to gain a superuser's powers.
const SERVER_ROLES: &[(&str, &str)] = &[
    (
        "pg_execute_server_program",
        "runs programs on the database server",
    ),
    (
        "pg_read_server_files",
        "reads any file on the database server",
    ),
    (
        "pg_write_server_files",
        "writes any file on the database server",
    ),
];

/// The privileges a role may hold on a column. One held with grant option can be passed on to
/// any other role, so it is checked as a privilege of its own.
const COLUMN_PRIVILEGES: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "REFERENCES",
    "SELECT WITH GRANT OPTION",
    "INSERT WITH GRANT OPTION",
    "UPDATE WITH GRANT OPTION",
];

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
    /// A trigger the table needs is not on it, or does not fire on every row it must: it
    /// calls another function, fires at another time, or has a condition or a column list.
    TriggerMissing {
        /// The trigger.
        trigger: &'static str,
        /// What it does.
        purpose: &'static str,
        /// When it must fire.
        fires: &'static str,
    },
    /// A trigger is on the table but does not fire in an ordinary session.
    TriggerDisabled {
        /// The trigger.
        trigger: &'static str,
    },
    /// The session runs with `session_replication_role` set to `replica`, as a role or
    /// database default can set it, so a trigger enabled for ordinary sessions, as both of the
    /// table's are, does not fire.
    ReplicaSession,
    /// The session's role, or a role it can become, has an attribute that lets it around the
    /// grants or the trigger.
    RoleAttribute {
        /// The role with the attribute.
        role: String,
        /// The attribute, as `CREATE ROLE` spells it.
        attribute: &'static str,
    },
    /// The session's role owns, or is a member of the role that owns, the database or an
    /// audit object, so it could change or drop it.
    Owns {
        /// The object.
        object: String,
    },
    /// The session's role is, or can become, a predefined role that reaches the server's files
    /// or programs.
    ServerAccess {
        /// The predefined role.
        role: &'static str,
        /// What it lets a member do.
        reach: &'static str,
    },
    /// The session's role, or a role it can become with `SET ROLE`, holds a privilege the store
    /// does not need. A membership the session does not inherit counts, since `SET ROLE`
    /// reaches it all the same.
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
    /// The session logged in as another role than the one it runs as, for example through a
    /// `role` setting in its options or a role default. `SET ROLE NONE` returns it to the role
    /// it logged in as, which the other checks do not look at.
    LoggedInAs {
        /// The role the session logged in as.
        role: String,
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
            Self::TriggerMissing {
                trigger,
                purpose,
                fires,
            } => write!(
                f,
                "the trigger {trigger}, which {purpose}, is not on call_rows to fire {fires} on every row"
            ),
            Self::TriggerDisabled { trigger } => {
                write!(f, "the trigger {trigger} on call_rows is disabled")
            }
            Self::ReplicaSession => write!(
                f,
                "this session has session_replication_role = replica, under which a trigger \
                 enabled as the migration enables both does not fire; a role or database \
                 default may set it"
            ),
            Self::RoleAttribute { role, attribute } => write!(
                f,
                "the role {role}, which this session is or can become, has {attribute}"
            ),
            Self::Owns { object } => write!(
                f,
                "this session's role owns {object}, or is a member of the role that does"
            ),
            Self::ServerAccess { role, reach } => write!(
                f,
                "this session's role is or can become {role}, which {reach}"
            ),
            Self::Extra { privilege, object } => write!(
                f,
                "this session's role, or a role it can become, holds {privilege} on {object}, \
                 which the gateway must not have"
            ),
            Self::Missing { privilege, object } => write!(
                f,
                "this session's role lacks {privilege} on {object}, which the store needs"
            ),
            Self::LoggedInAs { role } => write!(
                f,
                "this session logged in as {role}, and SET ROLE NONE would return it to {role}; \
                 the store must log in as the role it runs as"
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
    ///   two triggers, enabled: the one that sets both times at insert, and the one that
    ///   completes a row at most once.
    /// - The session's `session_replication_role` is not `replica`, which a role or database
    ///   default can set, and under which neither trigger fires.
    /// - The session logged in as the role it runs as, so `SET ROLE NONE` cannot take it
    ///   to another role.
    /// - The role is not a superuser, and cannot create roles or databases, replicate, or
    ///   bypass row security; nor can any role it is a member of.
    /// - The role is not a member of `pg_execute_server_program`, `pg_read_server_files` or
    ///   `pg_write_server_files`, which reach the server's programs and files.
    /// - The role does not own the database, the schema, the table, the trigger function or
    ///   anything else in the schema, and is not a member of a role that does. The database's
    ///   owner can drop it, and every row with it, without CREATE on it.
    /// - The role holds its own privileges: inserting the first half of a row, updating the
    ///   completion, selecting the identifier, decision and completion, and using the schema.
    /// - Neither the role nor any role it is a member of holds more. A membership counts
    ///   whether or not it is inherited, since `SET ROLE` reaches a role that is not. So none
    ///   holds the store's privileges with grant option; none holds anything on the table as a
    ///   whole, so none can DELETE, TRUNCATE or add a trigger; none can CREATE in the schema or
    ///   the database; none holds anything on any other table or sequence in the schema; and
    ///   none can set `session_replication_role`, which would silence the trigger.
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
            "SELECT current_user::text, session_user::text,
                    current_setting('server_version_num')::int,
                    current_setting('session_replication_role')",
            &[],
        )
        .await?;
    let role: String = session.get(0);
    let logged_in: String = session.get(1);
    let version: i32 = session.get(2);
    let replication_role: String = session.get(3);

    // Every check below asks about the current role. A session can return to the role it
    // logged in as, so the two must be the same.
    if logged_in != role {
        problems.push(Problem::LoggedInAs { role: logged_in });
    }

    for (name, expected) in DURABILITY {
        let found: String = client
            .query_one("SELECT current_setting($1)", &[name])
            .await?
            .get(0);
        problems.extend(setting_problem(name, found, expected));
    }

    // The value in effect, after any role or database default. The role cannot change it
    // itself: being able to set it is refused below.
    if replication_role == "replica" {
        problems.push(Problem::ReplicaSession);
    }

    role_attributes(client, &mut problems).await?;
    server_roles(client, &mut problems).await?;
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
            triggers(client, table, &mut problems).await?;
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

async fn server_roles(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    for (role, reach) in SERVER_ROLES {
        let member: bool = client
            .query_one(
                "SELECT EXISTS (SELECT FROM pg_catalog.pg_roles
                                WHERE rolname = $1 AND pg_has_role(current_user, oid, 'MEMBER'))",
                &[role],
            )
            .await?
            .get(0);
        if member {
            problems.push(Problem::ServerAccess { role, reach });
        }
    }
    Ok(())
}

/// A condition that holds when `test`, a privilege check on the role `r.oid`, holds for the
/// session's role or for any role it can become. A privilege function asked about
/// `current_user` counts only what that role inherits, and `SET ROLE` also reaches a role it
/// does not inherit.
fn by_any_role(test: &str) -> String {
    format!(
        "EXISTS (SELECT FROM pg_catalog.pg_roles r
                 WHERE pg_has_role(current_user, r.oid, 'MEMBER') AND {test})"
    )
}

async fn ownership(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let owned = client
        .query(
            "SELECT 'the database ' || d.datname
             FROM pg_catalog.pg_database d
             WHERE d.datname = current_database()
                 AND pg_has_role(current_user, d.datdba, 'MEMBER')
             UNION ALL
             SELECT 'the schema ' || n.nspname
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

async fn triggers(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    for trigger in TRIGGERS {
        // Each trigger must call the schema's own function, at its time, on every row: no
        // condition and no column list.
        let found = client
            .query_opt(
                "SELECT t.tgenabled::text
                 FROM pg_catalog.pg_trigger t
                     JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
                     JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                 WHERE t.tgrelid = $1::oid AND t.tgname = $2 AND NOT t.tgisinternal
                     AND n.nspname = 'switchboard_audit' AND p.proname = $2
                     AND t.tgtype = $3 AND t.tgqual IS NULL
                     AND cardinality(t.tgattr::int2[]) = 0",
                &[&table, &trigger.name, &trigger.tgtype],
            )
            .await?;
        problems.extend(trigger_problem(
            trigger,
            found.map(|row| row.get::<_, String>(0)).as_deref(),
        ));
    }
    Ok(())
}

/// The problem with `trigger`, given how it is enabled, or that it was not found. 'O' fires in
/// a session whose `session_replication_role` is not `replica`, which [`check`] requires, and
/// 'A' always; 'D' never and 'R' only for replication.
fn trigger_problem(trigger: &Trigger, enabled: Option<&str>) -> Option<Problem> {
    match enabled {
        None => Some(Problem::TriggerMissing {
            trigger: trigger.name,
            purpose: trigger.purpose,
            fires: trigger.fires,
        }),
        Some("O" | "A") => None,
        Some(_) => Some(Problem::TriggerDisabled {
            trigger: trigger.name,
        }),
    }
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
    // What the session's role holds itself, which must include the store's own privileges, and
    // what it or any role it can become holds, which must include nothing else.
    let rows = client
        .query(
            &format!(
                "SELECT a.attname::text, p,
                        has_column_privilege(current_user, $1::oid, a.attnum, p),
                        {}
                 FROM pg_catalog.pg_attribute a, unnest($2::text[]) AS p
                 WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped",
                by_any_role("has_column_privilege(r.oid, $1::oid, a.attnum, p)")
            ),
            &[&table, &COLUMN_PRIVILEGES],
        )
        .await?;
    let mut held = BTreeSet::new();
    let mut reachable = BTreeSet::new();
    for row in rows {
        let pair: (String, String) = (row.get(1), row.get(0));
        if row.get::<_, bool>(2) {
            held.insert(pair.clone());
        }
        if row.get::<_, bool>(3) {
            reachable.insert(pair);
        }
    }
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
            &format!(
                "SELECT p FROM unnest($2::text[]) AS p WHERE {}",
                by_any_role("has_table_privilege(r.oid, $1::oid, p)")
            ),
            &[&table, &COLUMN_PRIVILEGES],
        )
        .await?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    for (privilege, column) in reachable.difference(&expected) {
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
    // on any but call_rows, for the session's role or any role it can become.
    let privileges = table_privileges(version);
    let held = client
        .query(
            &format!(
                "SELECT n.nspname || '.' || c.relname, p
                 FROM pg_catalog.pg_class c
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                     unnest($1::text[]) AS p
                 WHERE n.nspname = 'switchboard_audit' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND ({}
                         OR (c.relname <> 'call_rows'
                             AND p IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
                             AND {}))
                 UNION ALL
                 SELECT n.nspname || '.' || c.relname, p
                 FROM pg_catalog.pg_class c
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                     unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p
                 WHERE n.nspname = 'switchboard_audit' AND c.relkind = 'S'
                     AND {}
                 ORDER BY 1, 2",
                by_any_role("has_table_privilege(r.oid, c.oid, p)"),
                by_any_role("has_any_column_privilege(r.oid, c.oid, p)"),
                by_any_role("has_sequence_privilege(r.oid, c.oid, p)"),
            ),
            &[&privileges],
        )
        .await?;
    for row in held {
        problems.push(Problem::Extra {
            privilege: row.get(1),
            object: row.get(0),
        });
    }

    // The session's role must use the schema itself. Neither it nor any role it can become may
    // create in it, or pass on using it.
    let schema = client
        .query_opt(
            &format!(
                "SELECT has_schema_privilege(current_user, n.oid, 'USAGE'), {}, {}
                 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'switchboard_audit'",
                by_any_role("has_schema_privilege(r.oid, n.oid, 'CREATE')"),
                by_any_role("has_schema_privilege(r.oid, n.oid, 'USAGE WITH GRANT OPTION')"),
            ),
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
        if schema.get::<_, bool>(2) {
            problems.push(Problem::Extra {
                privilege: "USAGE WITH GRANT OPTION".into(),
                object: "the schema switchboard_audit".into(),
            });
        }
    }

    let database = client
        .query_one(
            &format!(
                "SELECT current_database()::text, {}",
                by_any_role("has_database_privilege(r.oid, current_database(), 'CREATE')")
            ),
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
                &format!(
                    "SELECT {}",
                    by_any_role(
                        "has_parameter_privilege(r.oid, 'session_replication_role', 'SET')"
                    )
                ),
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
    fn a_trigger_must_be_found_and_fire_in_an_ordinary_session() {
        let trigger = &TRIGGERS[0];
        assert_eq!(trigger_problem(trigger, Some("O")), None);
        assert_eq!(trigger_problem(trigger, Some("A")), None);
        for never_here in ["D", "R"] {
            assert_eq!(
                trigger_problem(trigger, Some(never_here)),
                Some(Problem::TriggerDisabled {
                    trigger: "set_times"
                })
            );
        }
        let missing = trigger_problem(trigger, None).unwrap();
        assert_eq!(
            missing.to_string(),
            "the trigger set_times, which sets both times from the database's clock, is not on \
             call_rows to fire before each insert on every row"
        );
    }

    #[test]
    fn each_trigger_is_checked_for_the_time_the_migration_gives_it() {
        let sql = MIGRATIONS[0].sql;
        for trigger in TRIGGERS {
            let event = match trigger.tgtype {
                7 => "INSERT",
                19 => "UPDATE",
                other => panic!("{}: tgtype {other}", trigger.name),
            };
            let created = format!(
                "CREATE TRIGGER {name}\n    BEFORE {event} ON switchboard_audit.call_rows\n    \
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.{name}();",
                name = trigger.name
            );
            assert!(sql.contains(&created), "{created}");
        }
        assert_eq!(sql.matches("CREATE TRIGGER").count(), TRIGGERS.len());
    }

    #[test]
    fn maintain_is_checked_only_where_it_exists() {
        assert!(!table_privileges(160_004).contains(&"MAINTAIN"));
        assert!(table_privileges(170_000).contains(&"MAINTAIN"));
        assert!(table_privileges(160_004).contains(&"DELETE"));
        assert!(table_privileges(160_004).contains(&"TRUNCATE"));
    }
}
