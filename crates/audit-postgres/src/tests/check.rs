//! The boot checks, against databases and roles set up right and wrong.

use tokio_postgres::NoTls;

use std::collections::BTreeSet;

use super::{GATEWAY_ROLE, OWNER_ROLE, TestDatabase};
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
    assert!(
        found.contains(&Problem::Owns {
            object: "the relation switchboard_audit.call_rows".into()
        }),
        "{found:?}"
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

#[tokio::test]
async fn delete_and_truncate_are_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT DELETE, TRUNCATE ON switchboard_audit.call_rows TO {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    let store = db.store(PoolSizes::default());
    let error = store.check_at_boot().await.unwrap_err();
    let BootCheckError::Unfit { problems, .. } = &error else {
        panic!("{error}");
    };
    assert_eq!(
        problems,
        &vec![
            extra("DELETE", "switchboard_audit.call_rows"),
            extra("TRUNCATE", "switchboard_audit.call_rows"),
        ]
    );
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
             GRANT USAGE ON SEQUENCE switchboard_audit.extra TO {GATEWAY_ROLE};"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store(PoolSizes::default())).await,
        vec![
            extra("USAGE", "switchboard_audit.extra"),
            extra("SELECT", "switchboard_audit.migrations"),
        ]
    );
}

#[tokio::test]
async fn a_role_that_can_silence_the_trigger_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let role = db.new_role("LOGIN", &[GATEWAY_ROLE]).await;
    db.admin()
        .await
        .batch_execute(&format!(
            "GRANT SET ON PARAMETER session_replication_role TO {role}"
        ))
        .await
        .unwrap();
    assert_eq!(
        problems(&db.store_as(&role)).await,
        vec![extra("SET", "the setting session_replication_role")]
    );
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
