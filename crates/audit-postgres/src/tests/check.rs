//! The boot checks, against databases and roles set up right and wrong.

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use std::collections::BTreeSet;

use super::{DUMMY_PASSWORD, GATEWAY_ROLE, OWNER_ROLE, TestDatabase, connect};
use crate::check::{INSERTED, SELECTED, UPDATED};
use crate::{BootCheckError, PgAuditStore, PoolSizes, Problem};

/// The problems the check found, which must be some.
async fn problems(store: &PgAuditStore) -> Vec<Problem> {
    match store.check_at_boot().await {
        Err(BootCheckError::Unfit { problems, .. }) => problems,
        other => panic!("expected the check to refuse, got {other:?}"),
    }
}

fn extra(privilege: &str, object: &str) -> Problem {
    Problem::Extra {
        privilege: privilege.into(),
        object: object.into(),
    }
}

fn attribute(role: &str, attribute: &'static str) -> Problem {
    Problem::RoleAttribute {
        role: role.into(),
        attribute,
    }
}

#[tokio::test]
async fn the_gateway_set_up_as_the_migration_says_passes() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.store(PoolSizes::default())
        .check_at_boot()
        .await
        .unwrap();
    // So does a role that holds the gateway's privileges through membership, which is how the
    // tests below get a role unlike the gateway's.
    db.store_like_gateway("", &[])
        .await
        .check_at_boot()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_superuser_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = PgAuditStore::connect(db.admin_config(), NoTls, PoolSizes::default()).unwrap();
    let error = store.check_at_boot().await.unwrap_err();
    let BootCheckError::Unfit { role, problems } = &error else {
        panic!("{error}");
    };
    assert!(problems.contains(&attribute(role, "SUPERUSER")), "{error}");
    assert!(error.to_string().contains("has SUPERUSER"), "{error}");
}

#[tokio::test]
async fn the_owner_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store =
        PgAuditStore::connect(db.config_as(OWNER_ROLE), NoTls, PoolSizes::default()).unwrap();
    let found = problems(&store).await;
    for object in [
        "the schema switchboard_audit",
        "the relation switchboard_audit.call_rows",
        "the relation switchboard_audit.migrations",
        "the function switchboard_audit.complete_once",
    ] {
        assert!(
            found.contains(&Problem::Owns {
                object: object.into()
            }),
            "{object}: {found:?}"
        );
    }
}

#[tokio::test]
async fn a_role_that_can_become_the_owner_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    // NOINHERIT membership still lets the role SET ROLE to the owner.
    let role = db.new_role("NOLOGIN", &[]).await;
    db.admin()
        .await
        .batch_execute(&format!("GRANT {OWNER_ROLE} TO {role} WITH INHERIT FALSE"))
        .await
        .unwrap();
    let store = db.store_like_gateway("", &[&role]).await;
    let found = problems(&store).await;
    for object in [
        "the schema switchboard_audit",
        "the relation switchboard_audit.call_rows",
        "the function switchboard_audit.complete_once",
        "the function switchboard_audit.set_times",
    ] {
        assert!(
            found.contains(&Problem::Owns {
                object: object.into()
            }),
            "{object}: {found:?}"
        );
    }
}

/// The database's owner can drop the database, and every row with it, even once CREATE on it
/// has been taken away.
#[tokio::test]
async fn a_role_that_owns_the_database_or_can_become_its_owner_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let give_the_database_to = |role: String| {
        format!(
            "ALTER DATABASE {name} OWNER TO {role}; REVOKE CREATE ON DATABASE {name} FROM {role};",
            name = db.name()
        )
    };
    let owns = vec![Problem::Owns {
        object: format!("the database {}", db.name()),
    }];

    // NOINHERIT membership still lets the role SET ROLE to the owner.
    let owner = db.new_role("NOLOGIN", &[]).await;
    let member = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    admin
        .batch_execute(&format!(
            "{} GRANT {owner} TO {member} WITH INHERIT FALSE;",
            give_the_database_to(owner.clone())
        ))
        .await
        .unwrap();
    assert_eq!(problems(&db.store_as(&member)).await, owns);

    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    admin
        .batch_execute(&give_the_database_to(role.clone()))
        .await
        .unwrap();
    assert_eq!(problems(&db.store_as(&role)).await, owns);

    // What the check refuses is real: from another database, the role drops this one. It can
    // end its own sessions in it, but not the superuser's or another role's, so those go first.
    drop(admin);
    let server = connect(&db.server).await;
    for _ in 0..1500 {
        let others: i64 = server
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND usename <> $2",
                &[&db.name(), &role],
            )
            .await
            .unwrap()
            .get(0);
        if others == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut elsewhere = db.server.clone();
    elsewhere.user(&role).password(DUMMY_PASSWORD);
    connect(&elsewhere)
        .await
        .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", db.name()))
        .await
        .unwrap();
}

/// A session that logged in as one role and took the gateway's at startup can go back to the
/// first with SET ROLE NONE, so it is refused, however little the gateway's role can do.
#[tokio::test]
async fn a_session_that_logged_in_as_another_role_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let as_gateway = |role: &str| {
        let mut config = db.config_as(role);
        config.options(format!("-c role={GATEWAY_ROLE}"));
        PgAuditStore::connect(config, NoTls, PoolSizes::default()).unwrap()
    };
    let refused = |logged_in: &str| BootCheckError::Unfit {
        role: GATEWAY_ROLE.into(),
        problems: vec![Problem::LoggedInAs {
            role: logged_in.into(),
        }],
    };

    // A role that can become the schema's owner.
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE, OWNER_ROLE]).await;
    let store = as_gateway(&role);
    let error = store.check_at_boot().await.unwrap_err();
    assert_eq!(error.to_string(), refused(&role).to_string());
    // What the check refuses is real: the session goes back to the role it logged in as and
    // removes the trigger that completes a row once. (RESET ROLE would not: it returns to the
    // role the startup options set.)
    let session = store.begin.get().await.unwrap();
    let current: String = session
        .query_one("SELECT current_user::text", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(current, GATEWAY_ROLE);
    session
        .batch_execute("SET ROLE NONE; DROP TRIGGER complete_once ON switchboard_audit.call_rows")
        .await
        .unwrap();

    // The server's superuser.
    let mut config = db.admin_config();
    config.options(format!("-c role={GATEWAY_ROLE}"));
    let superuser = config.get_user().unwrap().to_owned();
    let store = PgAuditStore::connect(config, NoTls, PoolSizes::default()).unwrap();
    let BootCheckError::Unfit { role, problems } = store.check_at_boot().await.unwrap_err() else {
        panic!("the check failed to run");
    };
    assert_eq!(role, GATEWAY_ROLE);
    assert!(
        problems.contains(&Problem::LoggedInAs { role: superuser }),
        "{problems:?}"
    );
}

#[tokio::test]
async fn a_role_with_a_wide_attribute_is_refused_for_each() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let store = db
        .store_like_gateway("CREATEROLE CREATEDB REPLICATION BYPASSRLS", &[])
        .await;
    let error = store.check_at_boot().await.unwrap_err();
    let BootCheckError::Unfit { role, problems } = &error else {
        panic!("{error}");
    };
    for name in ["CREATEROLE", "CREATEDB", "REPLICATION", "BYPASSRLS"] {
        assert!(problems.contains(&attribute(role, name)), "{name}: {error}");
    }
    assert_eq!(problems.len(), 4, "{error}");
}

#[tokio::test]
async fn a_role_that_can_become_a_wide_role_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let wide = db.new_role("NOLOGIN CREATEDB", &[]).await;
    let store = db.store_like_gateway("", &[&wide]).await;
    assert_eq!(problems(&store).await, vec![attribute(&wide, "CREATEDB")]);
}

/// The server's version, as `server_version_num` gives it.
async fn version(db: &TestDatabase) -> i32 {
    db.admin()
        .await
        .query_one("SELECT current_setting('server_version_num')::int", &[])
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn each_privilege_on_the_whole_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    // INSERT on the whole table would let the role write a row's identifier and completion
    // itself, a row complete from the start. TRIGGER would let it add a trigger of its own
    // that rewrites a row after complete_once has passed it. A privilege on the whole table
    // shows on every column, so the column check does not report these.
    let mut granted = vec![
        "DELETE",
        "INSERT",
        "REFERENCES",
        "SELECT",
        "TRIGGER",
        "TRUNCATE",
        "UPDATE",
    ];
    if version(&db).await >= 170_000 {
        granted.push("MAINTAIN");
    }
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT {} ON switchboard_audit.call_rows TO {GATEWAY_ROLE}",
            granted.join(", ")
        ))
        .await
        .unwrap();
    let store = db.store(PoolSizes::default());
    let error = store.check_at_boot().await.unwrap_err();
    let BootCheckError::Unfit { problems, .. } = &error else {
        panic!("{error}");
    };
    granted.sort_unstable();
    let expected: Vec<Problem> = granted
        .iter()
        .map(|privilege| extra(privilege, "switchboard_audit.call_rows"))
        .collect();
    assert_eq!(problems, &expected);
    assert!(
        error
            .to_string()
            .contains("holds DELETE on switchboard_audit.call_rows"),
        "{error}"
    );
}

#[tokio::test]
async fn a_privilege_on_the_whole_table_is_refused_once() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT SELECT ON switchboard_audit.call_rows TO {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![extra("SELECT", "switchboard_audit.call_rows")]
    );
}

#[tokio::test]
async fn create_on_the_schema_or_the_database_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT CREATE ON SCHEMA switchboard_audit TO {GATEWAY_ROLE};
             GRANT CREATE ON DATABASE {} TO {GATEWAY_ROLE};",
            db.name()
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![
            extra("CREATE", "the schema switchboard_audit"),
            extra("CREATE", &format!("the database {}", db.name())),
        ]
    );
}

#[tokio::test]
async fn a_column_grant_beyond_its_own_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT SELECT (proved_subject), UPDATE (tool)
                 ON switchboard_audit.call_rows TO {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![
            extra("SELECT", "switchboard_audit.call_rows.proved_subject"),
            extra("UPDATE", "switchboard_audit.call_rows.tool"),
        ]
    );
}

#[tokio::test]
async fn a_grant_the_store_needs_and_lacks_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "REVOKE UPDATE (latency_ms) ON switchboard_audit.call_rows FROM {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![Problem::Missing {
            privilege: "UPDATE".into(),
            object: "switchboard_audit.call_rows.latency_ms".into()
        }]
    );
}

#[tokio::test]
async fn a_role_that_cannot_use_the_schema_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "REVOKE USAGE ON SCHEMA switchboard_audit FROM {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![Problem::Missing {
            privilege: "USAGE".into(),
            object: "the schema switchboard_audit".into()
        }]
    );
}

/// A view over call_rows would show the gateway the columns its own grants withhold, such as
/// who called; so would a materialized view; and a foreign table may reach anywhere.
#[tokio::test]
async fn any_privilege_on_another_table_in_the_schema_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT SELECT (version) ON switchboard_audit.migrations TO {GATEWAY_ROLE};
             CREATE SEQUENCE switchboard_audit.extra;
             GRANT USAGE ON SEQUENCE switchboard_audit.extra TO {GATEWAY_ROLE};
             SET ROLE {OWNER_ROLE};
             CREATE VIEW switchboard_audit.who AS
                 SELECT id, proved_subject FROM switchboard_audit.call_rows;
             CREATE MATERIALIZED VIEW switchboard_audit.who_then AS
                 SELECT id, proved_subject FROM switchboard_audit.call_rows;
             GRANT SELECT ON switchboard_audit.who, switchboard_audit.who_then
                 TO {GATEWAY_ROLE};
             RESET ROLE;
             CREATE FOREIGN DATA WRAPPER switchboard_test_wrapper;
             CREATE SERVER switchboard_test_server FOREIGN DATA WRAPPER switchboard_test_wrapper;
             CREATE FOREIGN TABLE switchboard_audit.elsewhere (id uuid)
                 SERVER switchboard_test_server;
             GRANT SELECT (id) ON switchboard_audit.elsewhere TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![
            extra("SELECT", "switchboard_audit.elsewhere"),
            extra("USAGE", "switchboard_audit.extra"),
            extra("SELECT", "switchboard_audit.migrations"),
            extra("SELECT", "switchboard_audit.who"),
            extra("SELECT", "switchboard_audit.who_then"),
        ]
    );
}

/// SET on `session_replication_role` silences both triggers, and SET on any other setting only
/// a superuser may set is as far from what the gateway needs. SET on a setting any role may set
/// adds nothing.
#[tokio::test]
async fn a_role_that_can_set_a_setting_only_a_superuser_may_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT SET ON PARAMETER session_replication_role, log_statement, work_mem TO {role}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        vec![
            extra("SET", "the setting log_statement"),
            extra("SET", "the setting session_replication_role"),
        ]
    );
    // What the check refuses is real: the role turns both triggers off for its session.
    db.connect_as(&role)
        .await
        .batch_execute("SET session_replication_role = replica")
        .await
        .unwrap();
}

/// A setting changed with ALTER SYSTEM reaches every session at the next reload, whoever
/// reloads, including the store's own sessions that already passed the check:
/// `session_replication_role = replica` silences both triggers, `fsync = off` loses committed
/// rows, and `archive_command` runs a program on the server.
#[tokio::test]
async fn a_role_that_can_change_a_setting_with_alter_system_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    // NOINHERIT membership still lets the role SET ROLE to the other.
    let other = db.new_role("NOLOGIN", &[]).await;
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT ALTER SYSTEM ON PARAMETER session_replication_role, fsync TO {role};
             GRANT ALTER SYSTEM ON PARAMETER archive_command TO {other};
             GRANT {other} TO {role} WITH INHERIT FALSE;"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        vec![
            extra("ALTER SYSTEM", "the setting archive_command"),
            extra("ALTER SYSTEM", "the setting fsync"),
            extra("ALTER SYSTEM", "the setting session_replication_role"),
        ]
    );
    // What the check refuses is real: the role writes the server's configuration. It writes the
    // value fsync already has, and takes it out again, so the server is as it was.
    let session = db.connect_as(&role).await;
    session
        .batch_execute("ALTER SYSTEM SET fsync = on")
        .await
        .unwrap();
    session
        .batch_execute("ALTER SYSTEM RESET fsync")
        .await
        .unwrap();
}

/// Grants `role` the gateway's own privileges directly, as the migration grants them to the
/// gateway's role, each followed by `option`.
async fn grant_the_gateways_own(db: &TestDatabase, role: &str, option: &str) {
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA switchboard_audit TO {role}{option};
             GRANT INSERT ({}) ON switchboard_audit.call_rows TO {role}{option};
             GRANT UPDATE ({}) ON switchboard_audit.call_rows TO {role}{option};
             GRANT SELECT ({}) ON switchboard_audit.call_rows TO {role}{option};",
            INSERTED.join(", "),
            UPDATED.join(", "),
            SELECTED.join(", "),
        ))
        .await
        .unwrap();
}

/// A role holding far more than the gateway may: rows it can delete, columns it can read,
/// things it can create, and a setting that silences the trigger.
async fn wide_role(db: &TestDatabase) -> String {
    let wide = db.new_role("NOLOGIN", &[]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT USAGE, CREATE ON SCHEMA switchboard_audit TO {wide} WITH GRANT OPTION;
             GRANT DELETE, TRUNCATE, UPDATE ON switchboard_audit.call_rows TO {wide};
             GRANT SELECT (proved_subject) ON switchboard_audit.call_rows TO {wide};
             GRANT SELECT (version) ON switchboard_audit.migrations TO {wide};
             CREATE SEQUENCE switchboard_audit.extra;
             GRANT USAGE ON SEQUENCE switchboard_audit.extra TO {wide};
             GRANT CREATE ON DATABASE {} TO {wide};
             GRANT SET ON PARAMETER session_replication_role TO {wide};",
            db.name()
        ))
        .await
        .unwrap();
    wide
}

/// The problems a role that can become [`wide_role`] has.
fn what_the_wide_role_holds(db: &TestDatabase) -> Vec<Problem> {
    vec![
        extra("SELECT", "switchboard_audit.call_rows.proved_subject"),
        extra("DELETE", "switchboard_audit.call_rows"),
        extra("TRUNCATE", "switchboard_audit.call_rows"),
        extra("UPDATE", "switchboard_audit.call_rows"),
        extra("USAGE", "switchboard_audit.extra"),
        extra("SELECT", "switchboard_audit.migrations"),
        extra("CREATE", "the schema switchboard_audit"),
        extra("USAGE WITH GRANT OPTION", "the schema switchboard_audit"),
        extra("CREATE", &format!("the database {}", db.name())),
        extra("SET", "the setting session_replication_role"),
    ]
}

/// A membership granted without inheritance still lets the role SET ROLE, and then do all the
/// other role can.
#[tokio::test]
async fn a_role_that_can_set_role_to_a_wide_role_without_inheriting_it_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let wide = wide_role(&db).await;
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT {wide} TO {role} WITH INHERIT FALSE, SET TRUE"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        what_the_wide_role_holds(&db)
    );
    // What the check refuses is real: the role can delete rows.
    db.connect_as(&role)
        .await
        .batch_execute(&format!(
            "SET ROLE {wide}; DELETE FROM switchboard_audit.call_rows"
        ))
        .await
        .unwrap();
}

/// A role created NOINHERIT inherits nothing from any role it is a member of, and can SET ROLE
/// to each of them.
#[tokio::test]
async fn a_noinherit_role_that_can_become_a_wide_role_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let wide = wide_role(&db).await;
    let role = db.new_role("LOGIN NOINHERIT", &[]).await;
    grant_the_gateways_own(&db, &role, "").await;
    // With its own privileges given to it directly, it passes.
    db.store_as(&role).check_at_boot().await.unwrap();
    db.admin()
        .await
        .batch_execute(&format!("GRANT {wide} TO {role}"))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        what_the_wide_role_holds(&db)
    );
}

/// The store's own privileges must be the session's without SET ROLE, since the store never
/// sets a role.
#[tokio::test]
async fn a_role_that_does_not_inherit_the_gateways_privileges_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let role = db.new_role("LOGIN NOINHERIT", &[GATEWAY_ROLE]).await;
    let found = problems(&db.store_as(&role)).await;
    assert!(
        found
            .iter()
            .all(|problem| matches!(problem, Problem::Missing { .. })),
        "{found:?}"
    );
    assert_eq!(
        found.len(),
        INSERTED.len() + UPDATED.len() + SELECTED.len() + 1,
        "{found:?}"
    );
}

/// A role that holds its own privileges with grant option can give them to any other role.
#[tokio::test]
async fn the_gateways_own_privileges_with_grant_option_are_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let role = db.new_role("LOGIN", &[]).await;
    grant_the_gateways_own(&db, &role, " WITH GRANT OPTION").await;
    let mut expected = BTreeSet::new();
    for (privilege, columns) in [
        ("INSERT", INSERTED),
        ("UPDATE", UPDATED),
        ("SELECT", SELECTED),
    ] {
        for column in columns {
            expected.insert((format!("{privilege} WITH GRANT OPTION"), *column));
        }
    }
    let mut expected: Vec<Problem> = expected
        .into_iter()
        .map(|(privilege, column)| {
            extra(&privilege, &format!("switchboard_audit.call_rows.{column}"))
        })
        .collect();
    expected.push(extra(
        "USAGE WITH GRANT OPTION",
        "the schema switchboard_audit",
    ));
    assert_eq!(problems(&db.store_as(&role)).await, expected);
}

#[tokio::test]
async fn a_role_that_can_reach_the_servers_files_or_programs_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let writer = db.new_role("NOLOGIN", &["pg_write_server_files"]).await;
    let role = db
        .new_role(
            "LOGIN",
            &[
                GATEWAY_ROLE,
                "pg_execute_server_program",
                "pg_read_server_files",
            ],
        )
        .await;
    db.admin()
        .await
        .batch_execute(&format!("GRANT {writer} TO {role} WITH INHERIT FALSE"))
        .await
        .unwrap();
    let found = problems(&db.store_as(&role)).await;
    let roles: Vec<&str> = found
        .iter()
        .map(|problem| match problem {
            Problem::ServerAccess { role, .. } => *role,
            other => panic!("{other}"),
        })
        .collect();
    assert_eq!(
        roles,
        [
            "pg_execute_server_program",
            "pg_read_server_files",
            "pg_write_server_files"
        ]
    );
    assert!(
        found[0]
            .to_string()
            .contains("can become pg_execute_server_program, which runs programs"),
        "{}",
        found[0]
    );
}

#[tokio::test]
async fn a_missing_column_or_one_of_another_type_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(
            "ALTER TABLE switchboard_audit.call_rows DROP COLUMN claimed_team;
             ALTER TABLE switchboard_audit.call_rows ALTER COLUMN latency_ms TYPE integer;",
        )
        .await
        .unwrap();
    let found = problems(&db.store(PoolSizes::default())).await;
    assert!(
        found.contains(&Problem::ColumnMissing {
            column: "claimed_team"
        }),
        "{found:?}"
    );
    assert!(
        found.contains(&Problem::ColumnType {
            column: "latency_ms",
            found: "integer".into(),
            expected: "bigint",
        }),
        "{found:?}"
    );
}

#[tokio::test]
async fn a_missing_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute("DROP TABLE switchboard_audit.call_rows")
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![Problem::TableMissing]
    );
}

/// Crash recovery empties an unlogged table, and a standby never receives its rows, so rows
/// begin reported as committed would be lost.
#[tokio::test]
async fn an_unlogged_table_or_partition_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    let unlogged = |table: &str| Problem::Unlogged {
        table: table.into(),
    };
    admin
        .batch_execute("ALTER TABLE switchboard_audit.call_rows SET UNLOGGED")
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![unlogged("switchboard_audit.call_rows")]
    );
    admin
        .batch_execute("ALTER TABLE switchboard_audit.call_rows SET LOGGED")
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();

    // A partitioned table holds no rows itself: they are in its partitions, which may be
    // unlogged when it is not.
    admin
        .batch_execute(
            "ALTER TABLE switchboard_audit.call_rows RENAME TO old_rows;
             CREATE TABLE switchboard_audit.call_rows (LIKE switchboard_audit.old_rows)
                 PARTITION BY RANGE (begun_at);
             CREATE TABLE switchboard_audit.logged_rows PARTITION OF switchboard_audit.call_rows
                 FOR VALUES FROM (MINVALUE) TO ('2000-01-01');
             CREATE UNLOGGED TABLE switchboard_audit.unlogged_rows
                 PARTITION OF switchboard_audit.call_rows DEFAULT;",
        )
        .await
        .unwrap();
    let found: Vec<Problem> = problems(&store)
        .await
        .into_iter()
        .filter(|problem| matches!(problem, Problem::Unlogged { .. }))
        .collect();
    assert_eq!(found, vec![unlogged("switchboard_audit.unlogged_rows")]);
}

fn inheritance(child: &str, parent: &str) -> Problem {
    Problem::Inheritance {
        child: child.into(),
        parent: parent.into(),
    }
}

/// Each partition has its own triggers, each enabled or not on its own, its own owner and its
/// own grants, and may be in another schema. An update through the partitioned table fires the
/// partition's copy of complete_once, so one disabled there lets a completed row be completed
/// again, and a grant on a partition reaches its rows directly. So a partitioned table is
/// refused, whatever its partitions hold, even when the table itself has the migration's
/// triggers and grants.
#[tokio::test]
async fn a_partitioned_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    admin
        .batch_execute(&format!(
            "ALTER TABLE switchboard_audit.call_rows RENAME TO old_rows;
             CREATE TABLE switchboard_audit.call_rows
                 (LIKE switchboard_audit.old_rows INCLUDING DEFAULTS INCLUDING CONSTRAINTS)
                 PARTITION BY LIST (decision);
             DROP TABLE switchboard_audit.old_rows;
             ALTER TABLE switchboard_audit.call_rows OWNER TO {OWNER_ROLE};
             CREATE TRIGGER complete_once BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();
             CREATE TRIGGER set_times BEFORE INSERT ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();
             GRANT INSERT ({inserted}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT UPDATE ({updated}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT SELECT ({selected}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};",
            inserted = INSERTED.join(", "),
            updated = UPDATED.join(", "),
            selected = SELECTED.join(", "),
        ))
        .await
        .unwrap();
    let store = db.store(PoolSizes::default());
    // With no partition yet, the table can hold no row, and is refused all the same.
    assert_eq!(problems(&store).await, vec![Problem::Partitioned]);

    // A partition in the schema with complete_once disabled on it alone, and one in another
    // schema that the gateway may delete from.
    admin
        .batch_execute(&format!(
            "CREATE TABLE switchboard_audit.allow_rows PARTITION OF switchboard_audit.call_rows
                 FOR VALUES IN ('allow');
             ALTER TABLE switchboard_audit.allow_rows DISABLE TRIGGER complete_once;
             CREATE SCHEMA elsewhere;
             CREATE TABLE elsewhere.deny_rows PARTITION OF switchboard_audit.call_rows
                 FOR VALUES IN ('deny');
             GRANT USAGE ON SCHEMA elsewhere TO {GATEWAY_ROLE};
             GRANT DELETE ON elsewhere.deny_rows TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![
            Problem::Partitioned,
            inheritance("elsewhere.deny_rows", "switchboard_audit.call_rows"),
            inheritance(
                "switchboard_audit.allow_rows",
                "switchboard_audit.call_rows"
            ),
        ]
    );
}

/// An update or delete through a parent reaches its children's rows, under each child's own
/// triggers and the parent's grants. So `call_rows` may have no child, in any schema, and may
/// be the child of no table.
#[tokio::test]
async fn a_table_that_inherits_or_is_inherited_from_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());

    admin
        .batch_execute("CREATE TABLE public.more_rows () INHERITS (switchboard_audit.call_rows)")
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![inheritance(
            "public.more_rows",
            "switchboard_audit.call_rows"
        )]
    );
    admin
        .batch_execute("DROP TABLE public.more_rows")
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();

    admin
        .batch_execute(
            "CREATE TABLE public.base_rows (id uuid);
             ALTER TABLE switchboard_audit.call_rows INHERIT public.base_rows",
        )
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![inheritance(
            "switchboard_audit.call_rows",
            "public.base_rows"
        )]
    );
}

#[tokio::test]
async fn a_disabled_or_missing_trigger_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    let alter = |change: &str| format!("ALTER TABLE switchboard_audit.call_rows {change}");

    for trigger in ["set_times", "complete_once"] {
        let disabled = vec![Problem::TriggerDisabled { trigger }];
        admin
            .batch_execute(&alter(&format!("DISABLE TRIGGER {trigger}")))
            .await
            .unwrap();
        assert_eq!(problems(&store).await, disabled);
        // A replica trigger does not fire in an ordinary session.
        admin
            .batch_execute(&alter(&format!("ENABLE REPLICA TRIGGER {trigger}")))
            .await
            .unwrap();
        assert_eq!(problems(&store).await, disabled);
        // One that fires always is fine.
        admin
            .batch_execute(&alter(&format!("ENABLE ALWAYS TRIGGER {trigger}")))
            .await
            .unwrap();
        store.check_at_boot().await.unwrap();
    }

    admin
        .batch_execute("DROP TRIGGER complete_once ON switchboard_audit.call_rows")
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![missing("complete_once")]);
    admin
        .batch_execute("DROP TRIGGER set_times ON switchboard_audit.call_rows")
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![missing("set_times"), missing("complete_once")]
    );
}

fn missing(trigger: &'static str) -> Problem {
    let (purpose, fires) = match trigger {
        "set_times" => (
            "sets both times from the database's clock",
            "before each insert",
        ),
        _ => ("completes a row at most once", "before each update"),
    };
    Problem::TriggerMissing {
        trigger,
        purpose,
        fires,
    }
}

/// A trigger of the right name and function that would not fire on every row it must is no
/// trigger at all.
#[tokio::test]
async fn a_trigger_that_fires_at_another_time_or_on_some_rows_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    for (trigger, replacement) in [
        ("set_times", "AFTER INSERT"),
        ("set_times", "BEFORE INSERT OR UPDATE"),
        ("complete_once", "BEFORE UPDATE OF outcome"),
        ("complete_once", "BEFORE DELETE"),
    ] {
        admin
            .batch_execute(&format!(
                "DROP TRIGGER {trigger} ON switchboard_audit.call_rows;
                 CREATE TRIGGER {trigger} {replacement} ON switchboard_audit.call_rows
                     FOR EACH ROW EXECUTE FUNCTION switchboard_audit.{trigger}();"
            ))
            .await
            .unwrap();
        assert_eq!(
            problems(&store).await,
            vec![missing(trigger)],
            "{trigger} {replacement}"
        );
        let restored = if trigger == "set_times" {
            "BEFORE INSERT"
        } else {
            "BEFORE UPDATE"
        };
        admin
            .batch_execute(&format!(
                "DROP TRIGGER {trigger} ON switchboard_audit.call_rows;
                 CREATE TRIGGER {trigger} {restored} ON switchboard_audit.call_rows
                     FOR EACH ROW EXECUTE FUNCTION switchboard_audit.{trigger}();"
            ))
            .await
            .unwrap();
        store.check_at_boot().await.unwrap();
    }
    // A trigger of the right name, at the right time, that calls a function of the same name in
    // another schema, which need not do anything.
    for (trigger, time) in [
        ("set_times", "BEFORE INSERT"),
        ("complete_once", "BEFORE UPDATE"),
    ] {
        let create = |schema: &str| {
            format!(
                "DROP TRIGGER {trigger} ON switchboard_audit.call_rows;
                 CREATE TRIGGER {trigger} {time} ON switchboard_audit.call_rows
                     FOR EACH ROW EXECUTE FUNCTION {schema}.{trigger}();"
            )
        };
        admin
            .batch_execute(&format!(
                "CREATE FUNCTION public.{trigger}() RETURNS trigger LANGUAGE plpgsql
                     AS $$ BEGIN RETURN NEW; END $$;
                 {}",
                create("public")
            ))
            .await
            .unwrap();
        assert_eq!(problems(&store).await, vec![missing(trigger)], "{trigger}");
        admin
            .batch_execute(&create("switchboard_audit"))
            .await
            .unwrap();
        store.check_at_boot().await.unwrap();
    }
    // A condition makes a trigger fire on some rows only.
    admin
        .batch_execute(
            "DROP TRIGGER complete_once ON switchboard_audit.call_rows;
             CREATE TRIGGER complete_once BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW WHEN (OLD.decision = 'deny')
                 EXECUTE FUNCTION switchboard_audit.complete_once();",
        )
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![missing("complete_once")]);
}

/// A function another role made, in a schema that a database or role default puts before
/// `pg_catalog`, cannot stand in for the catalog's own: the store's sessions look names up in
/// `pg_catalog` alone.
#[tokio::test]
async fn a_function_put_before_the_catalogs_own_does_not_change_what_the_check_finds() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    // The stand-in says no role is a member of any other, so every check that asks about the
    // roles the session can become would find nothing.
    db.admin()
        .await
        .batch_execute(&format!(
            "CREATE FUNCTION public.pg_has_role(name, oid, text) RETURNS boolean
                 LANGUAGE sql AS 'SELECT false';
             ALTER DATABASE {} SET search_path = public, pg_catalog;
             GRANT DELETE ON switchboard_audit.call_rows TO {GATEWAY_ROLE};",
            db.name()
        ))
        .await
        .unwrap();
    // A plain session finds the stand-in.
    let member: bool = db
        .connect_as(GATEWAY_ROLE)
        .await
        .query_one(
            "SELECT pg_has_role(current_user, oid, 'MEMBER')
             FROM pg_catalog.pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!member);

    let store = db.store(PoolSizes::default());
    assert_eq!(
        problems(&store).await,
        vec![extra("DELETE", "switchboard_audit.call_rows")]
    );
    let path: String = store
        .begin
        .get()
        .await
        .unwrap()
        .query_one("SHOW search_path", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(path, "pg_catalog,pg_temp");
}

/// What a session of `store` has `session_replication_role` set to.
async fn replication_role(store: &PgAuditStore) -> String {
    store
        .begin
        .get()
        .await
        .unwrap()
        .query_one("SHOW session_replication_role", &[])
        .await
        .unwrap()
        .get(0)
}

/// A role or database default can set `session_replication_role` to `replica` for a role that
/// cannot set it itself. Neither trigger fires then.
#[tokio::test]
async fn a_session_a_default_puts_in_replica_mode_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;

    // A default for the role in this database.
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    admin
        .batch_execute(&format!(
            "ALTER ROLE {role} IN DATABASE {} SET session_replication_role = replica",
            db.name()
        ))
        .await
        .unwrap();
    let store = db.store_as(&role);
    assert_eq!(replication_role(&store).await, "replica");
    assert_eq!(problems(&store).await, vec![Problem::ReplicaSession]);

    // A default for every session in the database.
    let other = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.store_as(&other).check_at_boot().await.unwrap();
    admin
        .batch_execute(&format!(
            "ALTER DATABASE {} SET session_replication_role = replica",
            db.name()
        ))
        .await
        .unwrap();
    let store = db.store_as(&other);
    assert_eq!(replication_role(&store).await, "replica");
    assert_eq!(problems(&store).await, vec![Problem::ReplicaSession]);
    assert!(
        Problem::ReplicaSession
            .to_string()
            .contains("session_replication_role = replica")
    );
}

/// In a database that is not UTF8, a character the encoding cannot hold fails the whole
/// insert, and the core ends every shortened value with one.
#[tokio::test]
async fn a_database_that_is_not_utf8_is_refused() {
    let Some(db) = TestDatabase::create_with(
        "ENCODING 'LATIN1' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0",
    )
    .await
    else {
        return;
    };
    let store = db.store(PoolSizes::default());
    assert_eq!(
        problems(&store).await,
        vec![Problem::Encoding {
            found: "LATIN1".into()
        }]
    );
    // What the check refuses is real.
    let error = store
        .begin
        .get()
        .await
        .unwrap()
        .query_one("SELECT $1::text", &[&"shortened\u{2026}"])
        .await
        .unwrap_err();
    assert_eq!(super::code(&error), Some("22P05"), "{error}");
}

/// The store gives each session its settings in the startup options. A session without them,
/// as a pooler that drops the options would hand the store, keeps the database's and the role's
/// defaults, so it is refused.
#[tokio::test]
async fn a_session_without_the_stores_settings_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.admin()
        .await
        .batch_execute(&format!("ALTER ROLE {role} SET synchronous_commit = off"))
        .await
        .unwrap();
    // The store's own sessions override the role's default.
    let mut store = db.store_as(&role);
    store.check_at_boot().await.unwrap();

    let manager = Manager::from_config(
        db.config_as(&role),
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    store.begin = Pool::builder(manager).max_size(1).build().unwrap();
    assert_eq!(
        problems(&store).await,
        vec![
            Problem::SessionSetting {
                name: "synchronous_commit",
                found: "off".into(),
                expected: "on",
            },
            Problem::SessionSetting {
                name: "search_path",
                found: "\"$user\", public".into(),
                expected: "pg_catalog,pg_temp",
            },
        ]
    );
}
