//! The checks a gateway runs before it serves: the table it writes to is the one it expects,
//! and the role it connects as can do what the store needs and nothing more.

use std::collections::BTreeSet;
use std::fmt;

use deadpool_postgres::ClientWrapper;
use thiserror::Error;

use crate::OWNER_ROLE;
use crate::store::{PgAuditStore, SESSION_SETTINGS, describe};

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
    ("instance", "text"),
    ("kind", "text"),
    ("allowance_ms", "bigint"),
    ("deadline", "timestamp with time zone"),
    ("listed_tools", "jsonb"),
    ("listed_omitted", "bigint"),
];

/// The columns the gateway's role inserts: the identifier it chose and the first half of a row,
/// with the instance, the kind and the allowance, and without the times, the deadline or the
/// completion; and for a list row, the tools listed and their count.
pub(crate) const INSERTED: &[&str] = &[
    "id",
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
    "instance",
    "kind",
    "allowance_ms",
    "listed_tools",
    "listed_omitted",
];

/// The columns the gateway's role updates: the completion.
pub(crate) const UPDATED: &[&str] = &["outcome", "outcome_sentence", "latency_ms"];

/// The columns the gateway's role reads: which row, whether it was allowed, its completion,
/// and its kind and deadline, which say whether an empty completion is open.
pub(crate) const SELECTED: &[&str] = &[
    "id",
    "decision",
    "outcome",
    "outcome_sentence",
    "latency_ms",
    "kind",
    "deadline",
];

/// The triggers on `call_rows`, each calling the schema's function of the same name, and when
/// each must fire, as `pg_trigger.tgtype` encodes it: for each row (1), before (2), on insert
/// (4) or on update (16).
pub(crate) const TRIGGERS: &[Trigger] = &[
    Trigger {
        name: "set_times",
        purpose: "sets both times and the deadline from the database's clock",
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

/// The view the open-row query reads (decision 0009, "Open rows"): allowed rows of kind `call`
/// with no completion past their deadline, by the database's clock. Migration 0005 creates it.
pub(crate) const OPEN_ROWS: &str = "open_call_rows";

/// The view's definition as PostgreSQL gives it back (`pg_get_viewdef`) to a session whose
/// search path is the store's, with its whitespace collapsed to single spaces.
pub(crate) const OPEN_ROWS_DEFINITION: &str = "SELECT id, deadline, begun_at \
    FROM switchboard_audit.call_rows \
    WHERE ((kind = 'call'::text) AND (decision = 'allow'::text) AND (outcome IS NULL) \
    AND (deadline < clock_timestamp()));";

/// `definition` with every run of whitespace made one space, and none at either end.
fn collapse(definition: &str) -> String {
    definition.split_whitespace().collect::<Vec<_>>().join(" ")
}

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

/// The catalog's functions that read or write the server's own files, as the roles in
/// [`SERVER_ROLES`] do. Each is revoked from PUBLIC when the server is created, and an
/// administrator can grant it. `lo_export` writes any file the server's operating-system user
/// can write, `postgresql.auto.conf` among them, which reaches every session at the next
/// reload. The `pg_file_*` functions are adminpack's, which PostgreSQL 17 no longer has.
const SERVER_FUNCTIONS: &[&str] = &[
    "lo_export",
    "lo_import",
    "pg_ls_dir",
    "pg_read_binary_file",
    "pg_read_file",
    "pg_stat_file",
    "pg_file_rename",
    "pg_file_sync",
    "pg_file_unlink",
    "pg_file_write",
];

/// Every relation whose rules read or write `call_rows`, given as `$1`, directly or through
/// another such relation, in any schema, `call_rows` included: a view or materialized view
/// over it, and a table or view with a rule whose action reaches it. A view's query is a rule,
/// so one walk over the rules' dependencies finds them all. A view runs with its owner's
/// privileges, and a rule with those of its table's owner, so a grant on any of them can give
/// what the grants on `call_rows` withhold.
const REACHING: &str = "reaching(oid) AS (
        SELECT $1::oid
        UNION
        SELECT rw.ev_class
        FROM reaching x
            JOIN pg_catalog.pg_depend d ON d.refobjid = x.oid
                AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
                AND d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass
            JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid
    )";

/// A function's name as reports give it: schema, name and argument types.
const FUNCTION_NAME: &str =
    "fn.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'";

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
    /// The session does not have a setting the store gives each of its sessions at connection,
    /// as when a pooler drops the startup options that carry it.
    SessionSetting {
        /// The setting.
        name: &'static str,
        /// What it is.
        found: String,
        /// What the store sets it to.
        expected: &'static str,
    },
    /// `switchboard_audit.call_rows` is not there.
    TableMissing,
    /// `switchboard_audit.call_rows` is partitioned. Each partition has its own triggers,
    /// each enabled or disabled on its own, its own owner and its own grants, and may be in
    /// another schema, so the store refuses a partitioned table rather than trust what the
    /// partitioned table alone shows.
    Partitioned,
    /// A table inherits from `switchboard_audit.call_rows` or is a partition of it, or
    /// `call_rows` inherits from a table or is a partition of one. An update or delete through
    /// the parent reaches the child's rows, under the child's own triggers and the parent's
    /// grants, so the store requires `call_rows` to stand alone.
    Inheritance {
        /// The table that inherits.
        child: String,
        /// The table it inherits from.
        parent: String,
    },
    /// `switchboard_audit.call_rows`, or a partition of it, is unlogged. Crash recovery empties
    /// an unlogged table, committed rows included, and a standby never receives its rows.
    Unlogged {
        /// The table or partition.
        table: String,
    },
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
    /// The database's encoding is not UTF8, so a row carrying a character the encoding cannot
    /// hold, such as the `…` the core ends a shortened value with, would not be written.
    Encoding {
        /// The encoding the database has.
        found: String,
    },
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
    /// `switchboard_audit.call_rows` has a rule. A rule's statements run, as the table's owner,
    /// in place of or beside a write the gateway makes, so one could delete a row whenever the
    /// gateway completes one. The migration makes none.
    Rule {
        /// The rule.
        rule: String,
    },
    /// A `SECURITY DEFINER` function runs as a role that can read or change `call_rows`, itself
    /// or through another such function, and the session's role, or a role it can become, can
    /// run it: with EXECUTE, or by writing to a table whose trigger runs it.
    Definer {
        /// The function, with its schema and argument types.
        function: String,
        /// The role it runs as.
        owner: String,
        /// How the session can run it.
        by: String,
    },
    /// The session's role, or a role it can become, can run a catalog function that reads or
    /// writes the server's own files, such as `lo_export`, which writes any file the server's
    /// operating-system user can write.
    ServerFunction {
        /// The function, with its schema and argument types.
        function: String,
    },
    /// The session's role lacks a privilege the store needs.
    Missing {
        /// The privilege.
        privilege: String,
        /// What it is needed on.
        object: String,
    },
    /// The view `switchboard_audit.open_call_rows`, which the open-row query reads, is not there.
    OpenRowsMissing,
    /// The open-row view is owned by another role than `switchboard_owner`. A view reads its
    /// table with its owner's privileges, so its owner decides what it can show.
    OpenRowsOwner {
        /// The role that owns it.
        owner: String,
    },
    /// The open-row view has another definition than the migration gives it, so it may count
    /// rows that are not open, miss rows that are, or show who called.
    OpenRowsDefinition {
        /// Its definition, with its whitespace collapsed.
        found: String,
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
            Self::SessionSetting {
                name,
                found,
                expected,
            } => write!(
                f,
                "this session has {name} = {found}, not the {expected} the store sets in its \
                 startup options; something between the store and the server, such as a \
                 pooler, may have dropped them"
            ),
            Self::TableMissing => write!(f, "the table switchboard_audit.call_rows does not exist"),
            Self::Partitioned => write!(
                f,
                "the table switchboard_audit.call_rows is partitioned, and each partition has \
                 triggers, an owner and grants of its own, which the store does not check"
            ),
            Self::Inheritance { child, parent } => write!(
                f,
                "the table {child} inherits from {parent} or is a partition of it, and the \
                 store requires switchboard_audit.call_rows to stand alone"
            ),
            Self::Unlogged { table } => write!(
                f,
                "the table {table} is unlogged, so a crash empties it, committed rows and all, \
                 and a standby never receives its rows"
            ),
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
            Self::Encoding { found } => write!(
                f,
                "the database's encoding is {found}, not UTF8, so a row with a character \
                 {found} cannot hold would not be written"
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
            Self::Rule { rule } => write!(
                f,
                "the table switchboard_audit.call_rows has the rule {rule}, whose statements run \
                 as the table's owner when the gateway writes"
            ),
            Self::Definer {
                function,
                owner,
                by,
            } => write!(
                f,
                "the SECURITY DEFINER function {function} runs as {owner}, which can read or \
                 change switchboard_audit.call_rows, and this session's role, or a role it can \
                 become, holds {by}"
            ),
            Self::ServerFunction { function } => write!(
                f,
                "this session's role, or a role it can become, can run {function}, which \
                 reaches the database server's own files"
            ),
            Self::Missing { privilege, object } => write!(
                f,
                "this session's role lacks {privilege} on {object}, which the store needs"
            ),
            Self::OpenRowsMissing => write!(
                f,
                "the view switchboard_audit.{OPEN_ROWS}, which the open-row query reads, does \
                 not exist"
            ),
            Self::OpenRowsOwner { owner } => write!(
                f,
                "the view switchboard_audit.{OPEN_ROWS} is owned by {owner}, not {OWNER_ROLE}"
            ),
            Self::OpenRowsDefinition { found } => write!(
                f,
                "the view switchboard_audit.{OPEN_ROWS} is defined as {found:?}, not as the \
                 migration defines it"
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
    /// - The session has the settings the store sets in its startup options:
    ///   `synchronous_commit` is `on` and `search_path` is `pg_catalog,pg_temp`. A pooler that
    ///   drops the options would leave the database's or the role's defaults in force.
    /// - The database's encoding is UTF8, so it holds every character a row may carry.
    /// - `switchboard_audit.call_rows` has every column the store uses, with its type, and its
    ///   two triggers, enabled: the one that sets both times at insert, and the one that
    ///   completes a row at most once. It is not unlogged. It stands alone: it is not
    ///   partitioned, no table inherits from it or is a partition of it, and it inherits from
    ///   none. A partition or child has triggers, an owner and grants of its own, which this
    ///   check does not read.
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
    ///   the database; none holds anything on any other table, view or sequence in the schema
    ///   but SELECT on the open-row view;
    ///   none can set a setting only a superuser may set, such as `session_replication_role`,
    ///   which would silence both triggers; and none can change any setting with
    ///   `ALTER SYSTEM`, which reaches every session at the next reload.
    /// - The view `switchboard_audit.open_call_rows`, which the open-row query reads, is there,
    ///   owned by `switchboard_owner`, with the definition migration 0005 gives it, whitespace
    ///   aside. The role may select from it, and may do nothing else with it.
    /// - `call_rows` is a table, not a view or foreign table of that name, and has no rule. A
    ///   rule's statements run as the table's owner whenever the gateway writes.
    /// - Neither the role nor any role it can become, PUBLIC included, holds anything on a
    ///   view, materialized view or table with a rule, in any schema, that reaches `call_rows`
    ///   directly or through other views and rules. A view runs with its owner's privileges,
    ///   and a rule with its table's owner's.
    /// - Neither can run a `SECURITY DEFINER` function, in any schema, whose owner can read or
    ///   change `call_rows`: one that holds a privilege on it, or on a view or rule that
    ///   reaches it, or can act as the schema's owner, or can run another such function. Running
    ///   it means EXECUTE, which PUBLIC holds on every new function unless it is revoked, or a
    ///   write to a table whose trigger runs it, since a trigger does not ask for EXECUTE.
    /// - Neither can run the catalog's functions that read or write the server's own files:
    ///   `lo_export`, `lo_import`, `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`,
    ///   `pg_stat_file`, and adminpack's `pg_file_*` where the server has them.
    ///
    /// # What it does not look for
    ///
    /// The check reads the catalog of one database, once. It does not see:
    ///
    /// - anything changed after it passes, until the next boot;
    /// - an event trigger, which fires on statements the role may be able to run, such as
    ///   `CREATE TEMP TABLE`, and whose function may be `SECURITY DEFINER`;
    /// - functions that reach outside the database other than the catalog's file functions
    ///   named above: one in an untrusted language such as `plpython3u`, or in C from an
    ///   extension, runs with the server's operating-system user's access to its files;
    /// - a way back in through another connection: `postgres_fdw` or `dblink`, through a user
    ///   mapping or a function that holds another role's password, can reach `call_rows` as
    ///   that role. A foreign table in `switchboard_audit` is refused; one elsewhere is not
    ///   followed to where it connects.
    ///
    /// Has no time limit: wrap it in one if boot must not wait on the database.
    pub async fn check_at_boot(&self) -> Result<(), BootCheckError> {
        let client = self.begin.get().await?;
        check(&client).await
    }
}

async fn check(client: &ClientWrapper) -> Result<(), BootCheckError> {
    let mut problems = Vec::new();
    // The search path is not yet known to be the store's, so this names the catalog's own.
    let session = client
        .query_one(
            "SELECT current_user::pg_catalog.text, session_user::pg_catalog.text,
                    pg_catalog.current_setting('server_version_num')::pg_catalog.int4,
                    pg_catalog.current_setting('session_replication_role'),
                    pg_catalog.current_setting('server_encoding')",
            &[],
        )
        .await?;
    let role: String = session.get(0);
    let logged_in: String = session.get(1);
    let version: i32 = session.get(2);
    let replication_role: String = session.get(3);
    let encoding: String = session.get(4);

    // Every check below asks about the current role. A session can return to the role it
    // logged in as, so the two must be the same.
    if logged_in != role {
        problems.push(Problem::LoggedInAs { role: logged_in });
    }

    for (name, expected) in DURABILITY {
        let found: String = client
            .query_one("SELECT pg_catalog.current_setting($1)", &[name])
            .await?
            .get(0);
        problems.extend(setting_problem(name, found, expected));
    }
    for (name, expected) in SESSION_SETTINGS {
        let found: String = client
            .query_one("SELECT pg_catalog.current_setting($1)", &[name])
            .await?
            .get(0);
        if found != *expected {
            problems.push(Problem::SessionSetting {
                name,
                found,
                expected,
            });
        }
    }

    // The value in effect, after any role or database default. The role cannot change it
    // itself: being able to set it is refused below.
    if replication_role == "replica" {
        problems.push(Problem::ReplicaSession);
    }
    if encoding != "UTF8" {
        problems.push(Problem::Encoding { found: encoding });
    }

    role_attributes(client, &mut problems).await?;
    server_roles(client, &mut problems).await?;
    ownership(client, &mut problems).await?;

    // The catalog is read directly, by name, so a missing schema or table is a problem found
    // rather than an error.
    let table = client
        .query_opt(
            "SELECT c.oid, c.relkind = 'p' FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'switchboard_audit' AND c.relname = 'call_rows'
                 AND c.relkind IN ('r', 'p')",
            &[],
        )
        .await?
        .map(|row| {
            (
                row.get::<_, tokio_postgres::types::Oid>(0),
                row.get::<_, bool>(1),
            )
        });
    match table {
        None => problems.push(Problem::TableMissing),
        Some((table, partitioned)) => {
            if partitioned {
                problems.push(Problem::Partitioned);
            }
            inheritance(client, table, &mut problems).await?;
            unlogged(client, table, &mut problems).await?;
            columns(client, table, &mut problems).await?;
            triggers(client, table, &mut problems).await?;
            rules(client, table, &mut problems).await?;
            column_privileges(client, table, &mut problems).await?;
        }
    }
    other_privileges(client, version, &mut problems).await?;
    open_rows(client, &mut problems).await?;
    if let Some((table, _)) = table {
        reaching_privileges(client, table, version, &mut problems).await?;
        definers(client, table, version, &mut problems).await?;
    }
    server_functions(client, &mut problems).await?;

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

/// Every table that inherits from `table` or is a partition of it, and every table `table`
/// inherits from or is a partition of, in any schema. Only direct links are listed: one is
/// enough to refuse.
async fn inheritance(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let found = client
        .query(
            "SELECT cn.nspname || '.' || c.relname, pn.nspname || '.' || p.relname
             FROM pg_catalog.pg_inherits i
                 JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
                 JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace
                 JOIN pg_catalog.pg_class p ON p.oid = i.inhparent
                 JOIN pg_catalog.pg_namespace pn ON pn.oid = p.relnamespace
             WHERE i.inhparent = $1::oid OR i.inhrelid = $1::oid
             ORDER BY 1, 2",
            &[&table],
        )
        .await?;
    problems.extend(found.into_iter().map(|row| Problem::Inheritance {
        child: row.get(0),
        parent: row.get(1),
    }));
    Ok(())
}

async fn unlogged(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    // A partitioned table is refused on its own, and an unlogged partition is named as well,
    // so one refusal lists everything wrong. A partition can be unlogged when the partitioned
    // table is not, and the rows are in the partitions. The tree of a table that is not
    // partitioned is empty.
    let found = client
        .query(
            "SELECT n.nspname || '.' || c.relname
             FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE (c.oid = $1::oid
                    OR c.oid IN (SELECT relid
                                 FROM pg_catalog.pg_partition_tree(($1::oid)::pg_catalog.regclass)))
                 AND c.relpersistence <> 'p'
             ORDER BY 1",
            &[&table],
        )
        .await?;
    problems.extend(
        found
            .into_iter()
            .map(|row| Problem::Unlogged { table: row.get(0) }),
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

async fn rules(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let found = client
        .query(
            "SELECT rulename::text FROM pg_catalog.pg_rewrite WHERE ev_class = $1::oid
             ORDER BY 1",
            &[&table],
        )
        .await?;
    problems.extend(
        found
            .into_iter()
            .map(|row| Problem::Rule { rule: row.get(0) }),
    );
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
    // on any but call_rows, for the session's role or any role it can become. SELECT on the
    // open-row view is the exception, which `open_rows` checks.
    let privileges = table_privileges(version);
    let held = client
        .query(
            &format!(
                "SELECT n.nspname || '.' || c.relname, p
                 FROM pg_catalog.pg_class c
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                     unnest($1::text[]) AS p
                 WHERE n.nspname = 'switchboard_audit' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                     AND NOT (c.relname = $2 AND c.relkind = 'v' AND p = 'SELECT')
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
            &[&privileges, &OPEN_ROWS],
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

    // From version 15 a role can be granted the right to set a setting only a superuser may
    // set, such as session_replication_role, which silences both triggers, and the right to
    // change any setting with ALTER SYSTEM. A setting changed that way reaches every session,
    // the store's own already checked among them, at the next reload: fsync off, or
    // session_replication_role = replica, or archive_command, which runs a program on the
    // server. Every such grant is in pg_parameter_acl. SET on a setting any role may set adds
    // nothing.
    if version >= 150_000 {
        let held = client
            .query(
                &format!(
                    "SELECT a.parname, p
                     FROM pg_catalog.pg_parameter_acl a,
                         unnest(ARRAY['ALTER SYSTEM', 'SET']) AS p
                     WHERE (p = 'ALTER SYSTEM'
                            OR NOT EXISTS (SELECT FROM pg_catalog.pg_settings s
                                           WHERE s.name = a.parname AND s.context = 'user'))
                         AND {}
                     ORDER BY 1, 2",
                    by_any_role("has_parameter_privilege(r.oid, a.parname, p)")
                ),
                &[],
            )
            .await?;
        for row in held {
            problems.push(Problem::Extra {
                privilege: row.get(1),
                object: format!("the setting {}", row.get::<_, String>(0)),
            });
        }
    }
    Ok(())
}

/// The open-row view is there, as a view, owned by [`OWNER_ROLE`], with the migration's
/// definition. The session's role may select from it, and neither it nor any role it can become
/// may pass that on, for the whole view or for any column of it. Anything else on it is refused
/// with the rest of the schema.
async fn open_rows(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let found = client
        .query_opt(
            &format!(
                "SELECT pg_get_userbyid(c.relowner)::text, pg_get_viewdef(c.oid),
                        has_table_privilege(current_user, c.oid, 'SELECT'), {}
                 FROM pg_catalog.pg_class c
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'switchboard_audit' AND c.relname = $1 AND c.relkind = 'v'",
                by_any_role("has_any_column_privilege(r.oid, c.oid, 'SELECT WITH GRANT OPTION')"),
            ),
            &[&OPEN_ROWS],
        )
        .await?;
    let Some(view) = found else {
        problems.push(Problem::OpenRowsMissing);
        return Ok(());
    };
    let owner: String = view.get(0);
    if owner != OWNER_ROLE {
        problems.push(Problem::OpenRowsOwner { owner });
    }
    let definition = collapse(view.get(1));
    if definition != OPEN_ROWS_DEFINITION {
        problems.push(Problem::OpenRowsDefinition { found: definition });
    }
    let object = format!("switchboard_audit.{OPEN_ROWS}");
    if !view.get::<_, bool>(2) {
        problems.push(Problem::Missing {
            privilege: "SELECT".into(),
            object: object.clone(),
        });
    }
    if view.get::<_, bool>(3) {
        problems.push(Problem::Extra {
            privilege: "SELECT WITH GRANT OPTION".into(),
            object,
        });
    }
    Ok(())
}

/// Nothing, for the session's role or any role it can become, PUBLIC included, on any view,
/// materialized view or table with a rule, in another schema, that reaches `call_rows`
/// ([`REACHING`]). Those in the schema are refused with everything else there.
async fn reaching_privileges(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    version: i32,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let privileges = table_privileges(version);
    let held = client
        .query(
            &format!(
                "WITH RECURSIVE {REACHING}
                 SELECT n.nspname || '.' || v.relname, p
                 FROM reaching x
                     JOIN pg_catalog.pg_class v ON v.oid = x.oid
                     JOIN pg_catalog.pg_namespace n ON n.oid = v.relnamespace,
                     unnest($2::text[]) AS p
                 WHERE n.nspname <> 'switchboard_audit'
                     AND ({}
                         OR (p IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') AND {}))
                 ORDER BY 1, 2",
                by_any_role("has_table_privilege(r.oid, v.oid, p)"),
                by_any_role("has_any_column_privilege(r.oid, v.oid, p)"),
            ),
            &[&table, &privileges],
        )
        .await?;
    for row in held {
        problems.push(Problem::Extra {
            privilege: row.get(1),
            object: row.get(0),
        });
    }
    Ok(())
}

/// No `SECURITY DEFINER` function, in any schema, that runs as a role able to read or change
/// `call_rows` may be run by the session's role or a role it can become, PUBLIC included,
/// which holds EXECUTE on every new function unless it is revoked. A function's owner is able
/// when it holds a privilege on `call_rows` or on anything [`REACHING`] finds, superusers among
/// them since they hold every privilege; when it can act as the owner of the schema, which may
/// drop the table; or when it can run another such function, itself or through a trigger on a
/// table it can write. A trigger runs its function without asking for EXECUTE, so a write to a
/// table with such a trigger counts as running it. A function owned by a role the session can
/// become is left out: what that role holds is checked as the session's own.
async fn definers(
    client: &ClientWrapper,
    table: tokio_postgres::types::Oid,
    version: i32,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let privileges = table_privileges(version).join(", ");
    let found = client
        .query(
            &format!(
                "WITH RECURSIVE {REACHING},
                 definers(oid) AS (
                     SELECT p.oid FROM pg_catalog.pg_proc p
                     WHERE p.prosecdef
                         AND (EXISTS (SELECT FROM reaching x
                                      WHERE has_table_privilege(p.proowner, x.oid, $2)
                                          OR has_any_column_privilege(p.proowner, x.oid,
                                                                      'SELECT, INSERT, UPDATE'))
                              OR EXISTS (SELECT FROM pg_catalog.pg_namespace s
                                         WHERE s.nspname = 'switchboard_audit'
                                             AND pg_has_role(p.proowner, s.nspowner, 'USAGE')))
                     UNION
                     SELECT p.oid
                     FROM definers d
                         JOIN pg_catalog.pg_proc p ON p.prosecdef
                             AND (has_function_privilege(p.proowner, d.oid, 'EXECUTE')
                                  OR EXISTS (SELECT FROM pg_catalog.pg_trigger t
                                             WHERE t.tgfoid = d.oid
                                                 AND (has_any_column_privilege(
                                                          p.proowner, t.tgrelid,
                                                          'INSERT, UPDATE')
                                                      OR has_table_privilege(
                                                          p.proowner, t.tgrelid,
                                                          'DELETE, TRUNCATE'))))
                 )
                 SELECT {FUNCTION_NAME}, o.rolname::text, 'EXECUTE on it'
                 FROM definers d
                     JOIN pg_catalog.pg_proc p ON p.oid = d.oid
                     JOIN pg_catalog.pg_namespace fn ON fn.oid = p.pronamespace
                     JOIN pg_catalog.pg_roles o ON o.oid = p.proowner
                 WHERE NOT pg_has_role(current_user, p.proowner, 'MEMBER')
                     AND {}
                 UNION ALL
                 SELECT {FUNCTION_NAME}, o.rolname::text,
                        w || ' on ' || n.nspname || '.' || c.relname || ', whose trigger '
                            || t.tgname || ' runs it'
                 FROM definers d
                     JOIN pg_catalog.pg_proc p ON p.oid = d.oid
                     JOIN pg_catalog.pg_namespace fn ON fn.oid = p.pronamespace
                     JOIN pg_catalog.pg_roles o ON o.oid = p.proowner
                     JOIN pg_catalog.pg_trigger t ON t.tgfoid = p.oid
                     JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
                     unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS w
                 WHERE NOT pg_has_role(current_user, p.proowner, 'MEMBER')
                     AND {}
                 ORDER BY 1, 3",
                by_any_role("has_function_privilege(r.oid, d.oid, 'EXECUTE')"),
                by_any_role(
                    "(has_table_privilege(r.oid, c.oid, w)
                      OR w IN ('INSERT', 'UPDATE') AND has_any_column_privilege(r.oid, c.oid, w))"
                ),
            ),
            &[&table, &privileges],
        )
        .await?;
    problems.extend(found.into_iter().map(|row| Problem::Definer {
        function: row.get(0),
        owner: row.get(1),
        by: row.get(2),
    }));
    Ok(())
}

/// None of [`SERVER_FUNCTIONS`] may be run by the session's role or a role it can become.
async fn server_functions(
    client: &ClientWrapper,
    problems: &mut Vec<Problem>,
) -> Result<(), tokio_postgres::Error> {
    let found = client
        .query(
            &format!(
                "SELECT {FUNCTION_NAME}
                 FROM pg_catalog.pg_proc p
                     JOIN pg_catalog.pg_namespace fn ON fn.oid = p.pronamespace
                 WHERE fn.nspname = 'pg_catalog' AND p.proname::text = ANY($1::text[])
                     AND {}
                 ORDER BY 1",
                by_any_role("has_function_privilege(r.oid, p.oid, 'EXECUTE')"),
            ),
            &[&SERVER_FUNCTIONS],
        )
        .await?;
    problems.extend(found.into_iter().map(|row| Problem::ServerFunction {
        function: row.get(0),
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MIGRATIONS;
    use crate::columns::{BeginRow, ListRow};

    #[test]
    fn the_checked_columns_are_the_ones_the_store_writes() {
        // Every inserted column is in begin's INSERT or list's, and every column either names.
        let columns = |insert: &'static str| -> BTreeSet<&'static str> {
            insert[insert.find('(').unwrap() + 1..insert.find(')').unwrap()]
                .split(',')
                .map(str::trim)
                .collect()
        };
        let begin = columns(BeginRow::INSERT);
        let list = columns(ListRow::INSERT);
        let inserted: BTreeSet<&str> = INSERTED.iter().copied().collect();
        assert_eq!(&begin | &list, inserted);
        assert_eq!(
            &list - &begin,
            ["listed_tools", "listed_omitted"].into(),
            "a list row writes a column begin does not, besides its tools"
        );
        for column in INSERTED.iter().chain(UPDATED).chain(SELECTED) {
            assert!(
                COLUMNS.iter().any(|(name, _)| name == column),
                "{column} is not checked"
            );
        }
    }

    #[test]
    fn the_checked_privileges_are_the_ones_the_migrations_grant() {
        // Every column the migrations grant `privilege` on, each granted once.
        let granted = |privilege: &str| -> BTreeSet<String> {
            let mut columns = BTreeSet::new();
            for migration in MIGRATIONS {
                let grant = format!("GRANT {privilege} (");
                let mut sql = migration.sql;
                while let Some(start) = sql.find(&grant) {
                    let rest = &sql[start..];
                    let inner = &rest[rest.find('(').unwrap() + 1..rest.find(')').unwrap()];
                    for column in inner.split(',').map(|c| c.trim().to_owned()) {
                        assert!(columns.insert(column), "granted twice");
                    }
                    sql = &rest[grant.len()..];
                }
            }
            columns
        };
        let set = |columns: &[&str]| columns.iter().map(|c| (*c).to_owned()).collect();
        assert_eq!(granted("INSERT"), set(INSERTED));
        assert_eq!(granted("UPDATE"), set(UPDATED));
        assert_eq!(granted("SELECT"), set(SELECTED));
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
            "the trigger set_times, which sets both times and the deadline from the database's \
             clock, is not on call_rows to fire before each insert on every row"
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
