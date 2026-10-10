//! The boot checks, against databases and roles set up right and wrong.

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

use std::collections::BTreeSet;

use super::{DUMMY_PASSWORD, GATEWAY_ROLE, OWNER_ROLE, TestDatabase, connect};
use crate::check::{INSERTED, OPEN_ROWS_DEFINITION, SELECTED, UPDATED};
use crate::{BootCheckError, MIGRATIONS, PgAuditStore, PoolSizes, Problem};

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

/// Makes the open-row view again, as migration 0005 does, as the owner: for a test that put
/// another table in place of `call_rows`, which took the view with the old one.
fn open_rows_again() -> String {
    let migration = MIGRATIONS.iter().find(|m| m.name == "open_rows").unwrap();
    format!("SET ROLE {OWNER_ROLE}; {} RESET ROLE;", migration.sql)
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
    db.cluster_wide(&format!("GRANT {OWNER_ROLE} TO {role} WITH INHERIT FALSE"))
        .await;
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
    db.cluster_wide(&format!(
        "{} GRANT {owner} TO {member} WITH INHERIT FALSE;",
        give_the_database_to(owner.clone())
    ))
    .await;
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
            "GRANT SELECT (proved_subject), UPDATE (tool), REFERENCES (id)
                 ON switchboard_audit.call_rows TO {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![
            extra("REFERENCES", "switchboard_audit.call_rows.id"),
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
/// who called; so would a materialized view; and a foreign table may reach anywhere. On a
/// sequence, SELECT reads it and UPDATE sets it with setval.
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
             CREATE SEQUENCE switchboard_audit.extra_read;
             GRANT SELECT ON SEQUENCE switchboard_audit.extra_read TO {GATEWAY_ROLE};
             CREATE SEQUENCE switchboard_audit.extra_set;
             GRANT UPDATE ON SEQUENCE switchboard_audit.extra_set TO {GATEWAY_ROLE};
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
            extra("SELECT", "switchboard_audit.extra_read"),
            extra("UPDATE", "switchboard_audit.extra_set"),
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
    db.cluster_wide(&format!(
        "GRANT SET ON PARAMETER session_replication_role, log_statement, work_mem TO {role}"
    ))
    .await;
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
    db.cluster_wide(&format!(
        "GRANT ALTER SYSTEM ON PARAMETER session_replication_role, fsync TO {role};
         GRANT ALTER SYSTEM ON PARAMETER archive_command TO {other};
         GRANT {other} TO {role} WITH INHERIT FALSE;"
    ))
    .await;
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
             GRANT SELECT ({}) ON switchboard_audit.call_rows TO {role}{option};
             GRANT SELECT ON switchboard_audit.open_call_rows TO {role}{option};",
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
             GRANT CREATE ON DATABASE {} TO {wide};",
            db.name()
        ))
        .await
        .unwrap();
    db.cluster_wide(&format!(
        "GRANT SET ON PARAMETER session_replication_role TO {wide}"
    ))
    .await;
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
    db.cluster_wide(&format!(
        "GRANT {wide} TO {role} WITH INHERIT FALSE, SET TRUE"
    ))
    .await;
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
    db.cluster_wide(&format!("GRANT {wide} TO {role}")).await;
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
    // Each column privilege, USAGE on the schema, and SELECT on the open-row view.
    assert_eq!(
        found.len(),
        INSERTED.len() + UPDATED.len() + SELECTED.len() + 2,
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
    expected.push(extra(
        "SELECT WITH GRANT OPTION",
        "switchboard_audit.open_call_rows",
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
    db.cluster_wide(&format!("GRANT {writer} TO {role} WITH INHERIT FALSE"))
        .await;
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
             ALTER TABLE switchboard_audit.call_rows DROP COLUMN deadline CASCADE;
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
    // The column the open-row query reads, and the trigger writes.
    assert!(
        found.contains(&Problem::ColumnMissing { column: "deadline" }),
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
        .batch_execute("DROP TABLE switchboard_audit.call_rows CASCADE")
        .await
        .unwrap();
    // The open-row view goes with the table it reads.
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![Problem::TableMissing, Problem::OpenRowsMissing]
    );
}

/// Only a table is the table. A foreign table named `call_rows`, with the columns, the grants
/// and the triggers the store expects, may send its rows anywhere, so it is refused as missing.
#[tokio::test]
async fn a_relation_named_call_rows_that_is_not_a_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let columns: Vec<String> = crate::check::COLUMNS
        .iter()
        .map(|(name, kind)| format!("{name} {kind}"))
        .collect();
    db.admin()
        .await
        .batch_execute(&format!(
            "DROP TABLE switchboard_audit.call_rows CASCADE;
             CREATE FOREIGN DATA WRAPPER switchboard_test_wrapper;
             CREATE SERVER switchboard_test_server FOREIGN DATA WRAPPER switchboard_test_wrapper;
             CREATE FOREIGN TABLE switchboard_audit.call_rows ({columns})
                 SERVER switchboard_test_server;
             ALTER FOREIGN TABLE switchboard_audit.call_rows OWNER TO {OWNER_ROLE};
             CREATE TRIGGER set_times BEFORE INSERT ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();
             CREATE TRIGGER complete_once BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();
             GRANT INSERT ({inserted}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT UPDATE ({updated}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT SELECT ({selected}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             {open_rows}",
            columns = columns.join(", "),
            inserted = INSERTED.join(", "),
            updated = UPDATED.join(", "),
            selected = SELECTED.join(", "),
            open_rows = open_rows_again(),
        ))
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
             DROP TABLE switchboard_audit.old_rows CASCADE;
             ALTER TABLE switchboard_audit.call_rows OWNER TO {OWNER_ROLE};
             CREATE TRIGGER complete_once BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.complete_once();
             CREATE TRIGGER set_times BEFORE INSERT ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();
             GRANT INSERT ({inserted}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT UPDATE ({updated}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             GRANT SELECT ({selected}) ON switchboard_audit.call_rows TO {GATEWAY_ROLE};
             {open_rows}",
            inserted = INSERTED.join(", "),
            updated = UPDATED.join(", "),
            selected = SELECTED.join(", "),
            open_rows = open_rows_again(),
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
            "sets both times and the deadline from the database's clock",
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
    // A trigger of the right name, at the right time, that calls the schema's other function:
    // complete_once running set_times would fire before every update and hold nothing to
    // being written once.
    admin
        .batch_execute(
            "DROP TRIGGER complete_once ON switchboard_audit.call_rows;
             CREATE TRIGGER complete_once BEFORE UPDATE ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION switchboard_audit.set_times();",
        )
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![missing("complete_once")]);
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
    db.cluster_wide(&format!(
        "ALTER ROLE {role} IN DATABASE {} SET session_replication_role = replica",
        db.name()
    ))
    .await;
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
    db.cluster_wide(&format!("ALTER ROLE {role} SET synchronous_commit = off"))
        .await;
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

/// Begins an allowed row as the owner, and returns its identifier.
async fn a_row(db: &TestDatabase) -> String {
    db.connect_as(OWNER_ROLE)
        .await
        .query_one(
            "INSERT INTO switchboard_audit.call_rows (
                 id, deployment, surface, profile, tool, connector, classification, resources,
                 resources_omitted, decision, policy_revision, proved_issuer, proved_subject,
                 proved_kind, proved_team, instance, kind, allowance_ms)
             VALUES (gen_random_uuid(), 'fixture', 'fixture-all', 'workload-rw', 'fixture__read',
                     'fixture', 'read', '[]', 0, 'allow', 'fixture-1',
                     'https://issuer.fixture.test', 'secret-subject', 'workload', 'team-a',
                     'fixture-instance', 'call', 37000)
             RETURNING id::text",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// How many rows `call_rows` has, as the superuser counts them.
async fn rows(db: &TestDatabase) -> i64 {
    db.admin()
        .await
        .query_one("SELECT count(*) FROM switchboard_audit.call_rows", &[])
        .await
        .unwrap()
        .get(0)
}

/// A view runs with its owner's privileges, and a rule's statements with those of its table's
/// owner. So a grant on a view over `call_rows`, on a view over that view, on a materialized
/// view, or on a table with a rule that writes `call_rows`, gives what the grants on
/// `call_rows` withhold, in whatever schema it is, to PUBLIC or to a role the gateway's can
/// SET ROLE to without inheriting it. A grant on a table that does not reach `call_rows` is no
/// concern here.
#[tokio::test]
async fn a_grant_on_a_view_or_rule_in_another_schema_that_reaches_the_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let reader = db.new_role("NOLOGIN", &[]).await;
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.cluster_wide(&format!("GRANT {reader} TO {role} WITH INHERIT FALSE"))
        .await;
    db.admin()
        .await
        .batch_execute(&format!(
            "SET ROLE {OWNER_ROLE};
             CREATE SCHEMA reports;
             CREATE VIEW reports.calls AS SELECT * FROM switchboard_audit.call_rows;
             CREATE VIEW reports.subjects AS SELECT id, proved_subject FROM reports.calls;
             CREATE MATERIALIZED VIEW reports.calls_then AS
                 SELECT id, proved_subject FROM switchboard_audit.call_rows;
             CREATE TABLE reports.inbox (id uuid);
             CREATE RULE purge AS ON INSERT TO reports.inbox
                 DO ALSO DELETE FROM switchboard_audit.call_rows WHERE id = NEW.id;
             CREATE TABLE reports.unrelated (id uuid);
             GRANT USAGE ON SCHEMA reports TO PUBLIC;
             GRANT SELECT ON reports.calls TO PUBLIC;
             GRANT DELETE ON reports.calls TO {reader};
             GRANT SELECT (id, proved_subject) ON reports.subjects TO {reader};
             GRANT SELECT ON reports.calls_then TO {reader};
             GRANT INSERT (id) ON reports.inbox TO {GATEWAY_ROLE};
             GRANT SELECT, INSERT ON reports.unrelated TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        vec![
            extra("DELETE", "reports.calls"),
            extra("SELECT", "reports.calls"),
            extra("SELECT", "reports.calls_then"),
            extra("INSERT", "reports.inbox"),
            extra("SELECT", "reports.subjects"),
        ]
    );

    // What the check refuses is real: the role reads who called, through a view over a view,
    // and deletes rows, through a view as the role it can become and through a rule as
    // itself.
    let first = a_row(&db).await;
    let second = a_row(&db).await;
    let session = db.connect_as(&role).await;
    session
        .batch_execute(&format!("SET ROLE {reader}"))
        .await
        .unwrap();
    let subject: String = session
        .query_one(
            &format!("SELECT proved_subject FROM reports.subjects WHERE id = '{first}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(subject, "secret-subject");
    session
        .batch_execute(&format!(
            "DELETE FROM reports.calls WHERE id = '{first}';
             RESET ROLE;
             INSERT INTO reports.inbox (id) VALUES ('{second}');"
        ))
        .await
        .unwrap();
    assert_eq!(rows(&db).await, 0);
}

/// A rule on `call_rows` itself runs its statements as the table's owner whenever the gateway
/// writes: here completing a row deletes it.
#[tokio::test]
async fn a_rule_on_the_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "SET ROLE {OWNER_ROLE};
             CREATE RULE also_purge AS ON UPDATE TO switchboard_audit.call_rows
                 DO ALSO DELETE FROM switchboard_audit.call_rows WHERE id = OLD.id;"
        ))
        .await
        .unwrap();
    let error = db
        .store(PoolSizes::default())
        .check_at_boot()
        .await
        .unwrap_err();
    let BootCheckError::Unfit { problems, .. } = &error else {
        panic!("{error}");
    };
    assert_eq!(
        problems,
        &vec![Problem::Rule {
            rule: "also_purge".into()
        }]
    );
    assert!(
        error.to_string().contains("has the rule also_purge"),
        "{error}"
    );

    // What the check refuses is real.
    let row = a_row(&db).await;
    db.connect_as(GATEWAY_ROLE)
        .await
        .batch_execute(&format!(
            "UPDATE switchboard_audit.call_rows SET outcome = 'ok', latency_ms = 1
             WHERE id = '{row}'"
        ))
        .await
        .unwrap();
    assert_eq!(rows(&db).await, 0);
}

fn definer(function: &str, owner: &str, by: &str) -> Problem {
    Problem::Definer {
        function: function.into(),
        owner: owner.into(),
        by: by.into(),
    }
}

/// The problems the check finds for the gateway's own role.
async fn problems_of(db: &TestDatabase) -> Vec<Problem> {
    problems(&db.store(PoolSizes::default())).await
}

/// A `SECURITY DEFINER` function runs as its owner, and a trigger runs its function without
/// asking for EXECUTE. So the gateway's role, or a role it can become, must not be able to run
/// one whose owner can read or change `call_rows`, by EXECUTE or by writing to a table whose
/// trigger runs it. The owner can when it holds a privilege on the table, or only on some of
/// its columns, or only on a view over it, or can act as the schema's owner, which may drop
/// it. A function whose owner can reach nothing, or that the gateway cannot run, is no
/// concern.
#[tokio::test]
async fn a_definer_function_that_can_reach_the_table_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let column_reader = db.new_role("NOLOGIN", &[]).await;
    let view_reader = db.new_role("NOLOGIN", &[]).await;
    let harmless = db.new_role("NOLOGIN", &[]).await;
    let reader = db.new_role("NOLOGIN", &[]).await;
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.cluster_wide(&format!("GRANT {reader} TO {role} WITH INHERIT FALSE"))
        .await;
    db.admin()
        .await
        .batch_execute(&format!(
            "CREATE SCHEMA reports AUTHORIZATION {OWNER_ROLE};
             GRANT USAGE ON SCHEMA reports TO PUBLIC;
             GRANT CREATE ON SCHEMA reports TO {column_reader}, {view_reader}, {harmless};
             SET ROLE {OWNER_ROLE};
             GRANT USAGE ON SCHEMA switchboard_audit TO {column_reader};
             GRANT SELECT (proved_subject) ON switchboard_audit.call_rows TO {column_reader};
             CREATE VIEW reports.calls AS SELECT * FROM switchboard_audit.call_rows;
             GRANT SELECT ON reports.calls TO {view_reader};
             CREATE FUNCTION reports.purge() RETURNS bigint
                 LANGUAGE sql SECURITY DEFINER
                 AS 'WITH gone AS (DELETE FROM switchboard_audit.call_rows RETURNING 1)
                     SELECT count(*) FROM gone';
             REVOKE EXECUTE ON FUNCTION reports.purge() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.purge() TO {reader};
             CREATE FUNCTION reports.purge_on_write() RETURNS trigger
                 LANGUAGE plpgsql SECURITY DEFINER
                 AS $$BEGIN DELETE FROM switchboard_audit.call_rows; RETURN NULL; END$$;
             REVOKE EXECUTE ON FUNCTION reports.purge_on_write() FROM PUBLIC;
             CREATE TABLE reports.inbox (id uuid);
             CREATE TRIGGER purge_on_write BEFORE INSERT OR DELETE ON reports.inbox
                 FOR EACH ROW EXECUTE FUNCTION reports.purge_on_write();
             GRANT INSERT (id), DELETE ON reports.inbox TO {reader};
             SET ROLE {column_reader};
             CREATE FUNCTION reports.subjects() RETURNS SETOF text
                 LANGUAGE sql SECURITY DEFINER
                 AS 'SELECT proved_subject FROM switchboard_audit.call_rows';
             SET ROLE {view_reader};
             CREATE FUNCTION reports.peek() RETURNS SETOF text
                 LANGUAGE sql SECURITY DEFINER AS 'SELECT proved_subject FROM reports.calls';
             SET ROLE {harmless};
             CREATE FUNCTION reports.harmless() RETURNS int
                 LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
             RESET ROLE;
             REVOKE EXECUTE ON FUNCTION reports.subjects(), reports.peek() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.subjects(), reports.peek() TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    // harmless, which PUBLIC may run, runs as a role that can run none of the others. If it
    // could, it would be refused too.
    let by_trigger = |privilege: &str| {
        format!("{privilege} on reports.inbox, whose trigger purge_on_write runs it")
    };
    let error = db.store_as(&role).check_at_boot().await.unwrap_err();
    let BootCheckError::Unfit { problems, .. } = &error else {
        panic!("{error}");
    };
    assert_eq!(
        problems,
        &vec![
            definer("reports.peek()", &view_reader, "EXECUTE on it"),
            definer("reports.purge()", OWNER_ROLE, "EXECUTE on it"),
            definer(
                "reports.purge_on_write()",
                OWNER_ROLE,
                &by_trigger("DELETE")
            ),
            definer(
                "reports.purge_on_write()",
                OWNER_ROLE,
                &by_trigger("INSERT")
            ),
            definer("reports.subjects()", &column_reader, "EXECUTE on it"),
        ]
    );
    assert!(
        error.to_string().contains(
            "the SECURITY DEFINER function reports.purge() runs as switchboard_owner, which can \
             read or change switchboard_audit.call_rows"
        ),
        "{error}"
    );

    // What the check refuses is real: the role reads who called, and deletes rows by EXECUTE
    // and through the trigger.
    let session = db.connect_as(&role).await;
    a_row(&db).await;
    for read in ["SELECT reports.subjects()", "SELECT reports.peek()"] {
        let subject: String = session.query_one(read, &[]).await.unwrap().get(0);
        assert_eq!(subject, "secret-subject", "{read}");
    }
    session
        .batch_execute(&format!("SET ROLE {reader}"))
        .await
        .unwrap();
    for purge in [
        "SELECT reports.purge()",
        "INSERT INTO reports.inbox VALUES (NULL)",
    ] {
        a_row(&db).await;
        session.batch_execute(purge).await.unwrap();
        assert_eq!(rows(&db).await, 0, "{purge}");
    }

    // With nothing left that the role can run, it passes.
    db.admin()
        .await
        .batch_execute(&format!(
            "REVOKE ALL ON FUNCTION reports.subjects(), reports.peek() FROM {GATEWAY_ROLE};
             REVOKE ALL ON FUNCTION reports.purge() FROM {reader};
             REVOKE ALL ON reports.inbox FROM {reader};"
        ))
        .await
        .unwrap();
    db.store_as(&role).check_at_boot().await.unwrap();

    // The schema's owner may drop the table, so a function of a role that can act as the
    // schema's owner is refused, though that role holds nothing on the table itself.
    let schema_owner = db.new_role("NOLOGIN", &[]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "ALTER SCHEMA switchboard_audit OWNER TO {schema_owner};
             GRANT CREATE ON SCHEMA reports TO {schema_owner};
             SET ROLE {schema_owner};
             CREATE FUNCTION reports.drop_it() RETURNS void
                 LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
             REVOKE EXECUTE ON FUNCTION reports.drop_it() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.drop_it() TO {GATEWAY_ROLE};
             RESET ROLE;"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems_of(&db).await,
        vec![definer("reports.drop_it()", &schema_owner, "EXECUTE on it")]
    );
}

/// A `SECURITY DEFINER` function whose owner can reach `call_rows` only by running another
/// such function, or by writing to a table whose trigger runs one, reaches it all the same.
#[tokio::test]
async fn a_definer_function_that_reaches_the_table_through_another_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let middle = db.new_role("NOLOGIN", &[]).await;
    let writer = db.new_role("NOLOGIN", &[]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "CREATE SCHEMA reports AUTHORIZATION {OWNER_ROLE};
             GRANT USAGE ON SCHEMA reports TO PUBLIC;
             GRANT CREATE ON SCHEMA reports TO {middle}, {writer};
             SET ROLE {OWNER_ROLE};
             CREATE FUNCTION reports.purge() RETURNS bigint
                 LANGUAGE sql SECURITY DEFINER
                 AS 'WITH gone AS (DELETE FROM switchboard_audit.call_rows RETURNING 1)
                     SELECT count(*) FROM gone';
             REVOKE EXECUTE ON FUNCTION reports.purge() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.purge() TO {middle};
             CREATE FUNCTION reports.purge_on_insert() RETURNS trigger
                 LANGUAGE plpgsql SECURITY DEFINER
                 AS $$BEGIN DELETE FROM switchboard_audit.call_rows; RETURN NEW; END$$;
             REVOKE EXECUTE ON FUNCTION reports.purge_on_insert() FROM PUBLIC;
             CREATE TABLE reports.inbox (id uuid);
             CREATE TRIGGER purge_on_insert BEFORE INSERT ON reports.inbox
                 FOR EACH ROW EXECUTE FUNCTION reports.purge_on_insert();
             GRANT INSERT ON reports.inbox TO {writer};
             SET ROLE {middle};
             CREATE FUNCTION reports.tidy() RETURNS bigint
                 LANGUAGE sql SECURITY DEFINER AS 'SELECT reports.purge()';
             REVOKE EXECUTE ON FUNCTION reports.tidy() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.tidy() TO {GATEWAY_ROLE};
             SET ROLE {writer};
             CREATE FUNCTION reports.fill_inbox() RETURNS void
                 LANGUAGE sql SECURITY DEFINER AS 'INSERT INTO reports.inbox VALUES (NULL)';
             REVOKE EXECUTE ON FUNCTION reports.fill_inbox() FROM PUBLIC;
             GRANT EXECUTE ON FUNCTION reports.fill_inbox() TO {GATEWAY_ROLE};
             RESET ROLE;"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems_of(&db).await,
        vec![
            definer("reports.fill_inbox()", &writer, "EXECUTE on it"),
            definer("reports.tidy()", &middle, "EXECUTE on it"),
        ]
    );

    // What the check refuses is real.
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    for purge in ["SELECT reports.tidy()", "SELECT reports.fill_inbox()"] {
        a_row(&db).await;
        gateway.batch_execute(purge).await.unwrap();
        assert_eq!(rows(&db).await, 0, "{purge}");
    }
}

/// EXECUTE on `lo_export` writes any file the server's operating-system user can write, and
/// `pg_read_file` and the others read or list them, as membership in `pg_write_server_files`
/// or `pg_read_server_files` would. Each is refused, for every argument list, whether the role
/// holds it or can SET ROLE to one that does.
#[tokio::test]
async fn a_role_that_can_run_a_function_that_reaches_the_servers_files_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let other = db.new_role("NOLOGIN", &[]).await;
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.cluster_wide(&format!("GRANT {other} TO {role} WITH INHERIT FALSE"))
        .await;
    let admin = db.admin().await;
    admin
        .batch_execute(&format!(
            "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid, text) TO {role};
             GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_file(text) TO {other};"
        ))
        .await
        .unwrap();
    let store = db.store_as(&role);
    assert_eq!(
        problems(&store).await,
        vec![
            Problem::ServerFunction {
                function: "pg_catalog.lo_export(oid, text)".into()
            },
            Problem::ServerFunction {
                function: "pg_catalog.pg_read_file(text)".into()
            },
        ]
    );
    // What the check refuses is real: the role reads a file of the server's own.
    let session = db.connect_as(&role).await;
    session
        .batch_execute(&format!("SET ROLE {other}"))
        .await
        .unwrap();
    let version: String = session
        .query_one("SELECT pg_read_file('PG_VERSION')", &[])
        .await
        .unwrap()
        .get(0);
    assert!(version.trim().parse::<u32>().is_ok(), "{version}");

    // Every function the check names that this server has, with each of its argument lists.
    let names = [
        "lo_export",
        "lo_import",
        "pg_ls_dir",
        "pg_read_binary_file",
        "pg_read_file",
        "pg_stat_file",
    ];
    let all: Vec<String> = admin
        .query(
            "SELECT 'pg_catalog.' || proname || '(' || pg_get_function_identity_arguments(oid)
                    || ')'
             FROM pg_catalog.pg_proc
             WHERE pronamespace = 'pg_catalog'::regnamespace AND proname::text = ANY($1)
             ORDER BY 1",
            &[&names.as_slice()],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert!(all.len() > names.len(), "{all:?}");
    for function in &all {
        admin
            .batch_execute(&format!("GRANT EXECUTE ON FUNCTION {function} TO {other}"))
            .await
            .unwrap();
    }
    let expected: Vec<Problem> = all
        .iter()
        .map(|function| Problem::ServerFunction {
            function: function.clone(),
        })
        .collect();
    assert_eq!(problems(&store).await, expected);
}

/// The open-row view must be there, as migration 0005 makes it: a view, owned by the owner,
/// with that definition, which the gateway's role may select from and do nothing else with.
/// A view runs with its owner's privileges, so one with another definition could count rows
/// that are not open, miss rows that are, or show the gateway who called.
#[tokio::test]
async fn the_open_row_view_must_be_as_the_migration_makes_it() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let store = db.store(PoolSizes::default());
    let view = "switchboard_audit.open_call_rows";
    let replace = |definition: &str| {
        format!(
            "DROP VIEW {view};
             SET ROLE {OWNER_ROLE};
             CREATE VIEW {view} AS {definition};
             GRANT SELECT ON {view} TO {GATEWAY_ROLE};
             RESET ROLE;"
        )
    };

    admin
        .batch_execute(&format!("DROP VIEW {view}"))
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![Problem::OpenRowsMissing]);
    assert_eq!(
        Problem::OpenRowsMissing.to_string(),
        "the view switchboard_audit.open_call_rows, which the open-row query reads, does not exist"
    );
    // Nor is a table of that name the view.
    admin
        .batch_execute(&format!(
            "SET ROLE {OWNER_ROLE};
             CREATE TABLE {view} (id uuid, deadline timestamptz, begun_at timestamptz);
             GRANT SELECT ON {view} TO {GATEWAY_ROLE};
             RESET ROLE;"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![extra("SELECT", view), Problem::OpenRowsMissing]
    );
    admin
        .batch_execute(&format!("DROP TABLE {view}; {}", open_rows_again()))
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();

    // Another definition: one that counts list rows, or deny rows, or rows whose deadline has
    // not passed, or shows who called.
    let open = "kind = 'call' AND decision = 'allow' AND outcome IS NULL \
                AND deadline < clock_timestamp()";
    for (definition, shows) in [
        (
            "SELECT id, deadline, begun_at FROM switchboard_audit.call_rows \
             WHERE decision = 'allow' AND outcome IS NULL AND deadline < clock_timestamp()"
                .to_owned(),
            "WHERE ((decision = 'allow'::text) AND",
        ),
        (
            "SELECT id, deadline, begun_at FROM switchboard_audit.call_rows \
             WHERE kind = 'call' AND outcome IS NULL AND deadline < clock_timestamp()"
                .to_owned(),
            "WHERE ((kind = 'call'::text) AND (outcome IS NULL)",
        ),
        (
            "SELECT id, deadline, begun_at FROM switchboard_audit.call_rows \
             WHERE kind = 'call' AND decision = 'allow' AND outcome IS NULL \
             AND begun_at < clock_timestamp()"
                .to_owned(),
            "(begun_at < clock_timestamp())",
        ),
        (
            format!(
                "SELECT id, deadline, begun_at, proved_subject \
                 FROM switchboard_audit.call_rows WHERE {open}"
            ),
            "begun_at, proved_subject FROM",
        ),
    ] {
        admin.batch_execute(&replace(&definition)).await.unwrap();
        let found = problems(&store).await;
        let [Problem::OpenRowsDefinition { found: rendered }] = found.as_slice() else {
            panic!("{definition}: {found:?}");
        };
        assert!(rendered.contains(shows), "{rendered}");
        assert_ne!(rendered, OPEN_ROWS_DEFINITION);
    }

    // The definition the migration gives, written another way, is the same view.
    admin
        .batch_execute(&replace(&format!(
            "SELECT id,\n\tdeadline,  begun_at\n FROM switchboard_audit.call_rows\n WHERE {open}"
        )))
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();

    // Owned by another role, here the server's superuser, which can read anything.
    let superuser = db.admin_config().get_user().unwrap().to_owned();
    admin
        .batch_execute(&format!("ALTER VIEW {view} OWNER TO {superuser}"))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![Problem::OpenRowsOwner { owner: superuser }]
    );
    admin
        .batch_execute(&format!("ALTER VIEW {view} OWNER TO {OWNER_ROLE}"))
        .await
        .unwrap();

    // The gateway's role must select from it, and may not pass that on or write through it.
    admin
        .batch_execute(&format!("REVOKE SELECT ON {view} FROM {GATEWAY_ROLE}"))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![Problem::Missing {
            privilege: "SELECT".into(),
            object: view.into(),
        }]
    );
    admin
        .batch_execute(&format!(
            "GRANT SELECT ON {view} TO {GATEWAY_ROLE} WITH GRANT OPTION;
             GRANT DELETE, UPDATE (deadline) ON {view} TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![
            extra("DELETE", view),
            extra("UPDATE", view),
            extra("SELECT WITH GRANT OPTION", view),
        ]
    );

    // A grant option on one column of it can be passed on too.
    admin
        .batch_execute(&format!(
            "REVOKE GRANT OPTION FOR SELECT ON {view} FROM {GATEWAY_ROLE};
             REVOKE DELETE, UPDATE ON {view} FROM {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();
    admin
        .batch_execute(&format!(
            "GRANT SELECT (begun_at) ON {view} TO {GATEWAY_ROLE} WITH GRANT OPTION"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&store).await,
        vec![extra("SELECT WITH GRANT OPTION", view)]
    );
}
