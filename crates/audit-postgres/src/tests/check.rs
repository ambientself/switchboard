//! The boot checks, against databases and roles set up right and wrong.

use tokio_postgres::NoTls;

use super::{GATEWAY_ROLE, OWNER_ROLE, TestDatabase};
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

    admin
        .batch_execute(&alter("DISABLE TRIGGER complete_once"))
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![Problem::TriggerDisabled]);
    // A replica trigger does not fire in an ordinary session.
    admin
        .batch_execute(&alter("ENABLE REPLICA TRIGGER complete_once"))
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![Problem::TriggerDisabled]);
    // One that fires always is fine.
    admin
        .batch_execute(&alter("ENABLE ALWAYS TRIGGER complete_once"))
        .await
        .unwrap();
    store.check_at_boot().await.unwrap();

    admin
        .batch_execute("DROP TRIGGER complete_once ON switchboard_audit.call_rows")
        .await
        .unwrap();
    assert_eq!(problems(&store).await, vec![Problem::TriggerMissing]);
}
