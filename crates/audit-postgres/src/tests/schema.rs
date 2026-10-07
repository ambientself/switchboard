//! The roles, grants, trigger and constraints, exercised with plain SQL.

use std::time::Duration;

use tokio::time::{Instant, sleep};
use tokio_postgres::Client;

use super::{
    CHECK_VIOLATION, INSUFFICIENT_PRIVILEGE, NOT_NULL_VIOLATION, SETUP, TestDatabase, code, message,
};
use crate::{GATEWAY_ROLE, MigrateError, OWNER_ROLE, ROLES, migrate};

/// The begin columns of an allowed call by a workload, as `(column, value)` in SQL.
const ALLOWED: &[(&str, &str)] = &[
    ("deployment", "'fixture'"),
    ("surface", "'fixture-all'"),
    ("profile", "'workload-rw'"),
    ("tool", "'fixture__read'"),
    ("connector", "'fixture'"),
    ("classification", "'read'"),
    (
        "resources",
        "'[{\"system\": \"fixture\", \"kind\": \"document\", \"identifier\": \"team-a/notes\"}]'::jsonb",
    ),
    ("resources_omitted", "0"),
    ("decision", "'allow'"),
    ("policy_revision", "'fixture-1'"),
    ("proved_issuer", "'https://workload-issuer.fixture.test'"),
    ("proved_subject", "'system:serviceaccount:team-a:sandbox'"),
    ("proved_kind", "'workload'"),
    ("proved_team", "'team-a'"),
];

/// `ALLOWED`, with each of `changes` replacing or adding a column.
fn insert(changes: &[(&str, &str)]) -> String {
    let mut columns: Vec<(&str, &str)> = ALLOWED
        .iter()
        .filter(|(column, _)| !changes.iter().any(|(changed, _)| changed == column))
        .copied()
        .collect();
    columns.extend(changes.iter().filter(|(_, value)| !value.is_empty()));
    let (names, values): (Vec<&str>, Vec<&str>) = columns.into_iter().unzip();
    format!(
        "INSERT INTO switchboard_audit.call_rows ({}) VALUES ({}) RETURNING id::text",
        names.join(", "),
        values.join(", ")
    )
}

/// The begin columns of a denial.
fn denied() -> String {
    insert(&[
        ("decision", "'deny'"),
        ("reason", "'unknown_tool'"),
        ("sentence", "'Denied.'"),
    ])
}

async fn insert_row(client: &Client, sql: &str) -> String {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

async fn complete(client: &Client, id: &str, outcome: &str) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET outcome = '{outcome}', latency_ms = 1
                 WHERE id = '{id}'"
            ),
            &[],
        )
        .await
}

#[tokio::test]
async fn migrating_again_applies_nothing() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    assert_eq!(migrate(&mut owner).await.unwrap(), Vec::<i32>::new());
    let recorded: Vec<i32> = owner
        .query(
            "SELECT version FROM switchboard_audit.migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(recorded, vec![1]);
}

#[tokio::test]
async fn only_the_owner_may_migrate() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut gateway = db.connect_as(GATEWAY_ROLE).await;
    assert!(matches!(
        migrate(&mut gateway).await,
        Err(MigrateError::NotOwner { current_user }) if current_user == GATEWAY_ROLE
    ));
    let mut admin = db.admin().await;
    assert!(matches!(
        migrate(&mut admin).await,
        Err(MigrateError::NotOwner { .. })
    ));
}

/// Two migrators on one database take turns: one applies the migration, and the other then
/// finds it applied. Without the lock, both create the schema at once and one fails.
#[tokio::test]
async fn two_migrators_at_once_take_turns() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    for _ in 0..5 {
        admin
            .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
            .await
            .unwrap();
        let mut first = db.connect_as(OWNER_ROLE).await;
        let mut second = db.connect_as(OWNER_ROLE).await;
        let (first, second) = tokio::join!(migrate(&mut first), migrate(&mut second));
        let mut applied = vec![first.unwrap(), second.unwrap()];
        applied.sort_unstable();
        assert_eq!(applied, vec![vec![], vec![1]]);
    }
}

/// Several administrators running the roles script on one database at once take turns.
/// Without the lock, their grants update the database's catalog row at once and all but one
/// fail.
#[tokio::test]
async fn the_roles_script_runs_in_several_sessions_at_once() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    // The runs are held at their first CREATE ROLE until all four are waiting, so they then go
    // on together rather than one after another as they arrive.
    let _one_at_a_time = SETUP.lock().await;
    let gate = db.admin().await;
    let waiting = format!(
        "SELECT count(*) FROM pg_stat_activity
         WHERE datname = '{}' AND wait_event_type = 'Lock'",
        db.name()
    );
    for _ in 0..5 {
        gate.batch_execute("BEGIN; LOCK TABLE pg_catalog.pg_authid IN SHARE MODE")
            .await
            .unwrap();
        let mut runs = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let admin = db.admin().await;
            runs.spawn(async move { admin.batch_execute(ROLES).await });
        }
        let give_up = Instant::now() + Duration::from_secs(5);
        while gate
            .query_one(&waiting, &[])
            .await
            .unwrap()
            .get::<_, i64>(0)
            < 4
        {
            assert!(Instant::now() < give_up, "the runs did not all wait");
            sleep(Duration::from_millis(10)).await;
        }
        gate.batch_execute("COMMIT").await.unwrap();
        while let Some(run) = runs.join_next().await {
            run.unwrap().unwrap();
        }
    }
}

#[tokio::test]
async fn the_owner_owns_the_schema_the_table_and_the_triggers() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    for function in ["set_times", "complete_once"] {
        let owners = admin
            .query_one(
                "SELECT n.nspowner::regrole::text, c.relowner::regrole::text,
                        p.proowner::regrole::text
                 FROM pg_namespace n
                 JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = 'call_rows'
                 JOIN pg_proc p ON p.pronamespace = n.oid AND p.proname = $1
                 WHERE n.nspname = 'switchboard_audit'",
                &[&function],
            )
            .await
            .unwrap();
        for column in 0..3 {
            assert_eq!(owners.get::<_, String>(column), OWNER_ROLE, "{function}");
        }
        let enabled: String = admin
            .query_one(
                "SELECT tgenabled::text FROM pg_trigger
                 WHERE tgrelid = 'switchboard_audit.call_rows'::regclass AND tgname = $1",
                &[&function],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(enabled, "O", "the trigger {function} is not enabled");
    }
}

#[tokio::test]
async fn the_roles_can_do_no_more_than_their_own() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    for role in [OWNER_ROLE, GATEWAY_ROLE] {
        let row = admin
            .query_one(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
                 FROM pg_roles WHERE rolname = $1",
                &[&role],
            )
            .await
            .unwrap();
        for column in 0..5 {
            assert!(!row.get::<_, bool>(column), "{role}: attribute {column}");
        }
    }
    let gateway_may_create: bool = admin
        .query_one(
            "SELECT has_database_privilege('switchboard_gateway', current_database(), 'CREATE')
                 OR has_schema_privilege('switchboard_gateway', 'switchboard_audit', 'CREATE')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!gateway_may_create, "the gateway may create objects");
}

#[tokio::test]
async fn the_gateway_holds_exactly_its_column_grants() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let admin = db.admin().await;
    let granted: Vec<(String, String)> = admin
        .query(
            "SELECT privilege_type::text, column_name::text
             FROM information_schema.column_privileges
             WHERE grantee = 'switchboard_gateway' AND table_schema = 'switchboard_audit'
             ORDER BY 1, 2",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let mut expected: Vec<(String, String)> = [
        ("INSERT", "classification"),
        ("INSERT", "claimed_acting_person"),
        ("INSERT", "claimed_team"),
        ("INSERT", "connector"),
        ("INSERT", "decision"),
        ("INSERT", "deployment"),
        ("INSERT", "policy_revision"),
        ("INSERT", "profile"),
        ("INSERT", "proved_delegation_team"),
        ("INSERT", "proved_groups"),
        ("INSERT", "proved_issuer"),
        ("INSERT", "proved_kind"),
        ("INSERT", "proved_subject"),
        ("INSERT", "proved_team"),
        ("INSERT", "reason"),
        ("INSERT", "resources"),
        ("INSERT", "resources_omitted"),
        ("INSERT", "sentence"),
        ("INSERT", "surface"),
        ("INSERT", "tool"),
        ("INSERT", "tool_use_id"),
        ("SELECT", "decision"),
        ("SELECT", "id"),
        ("SELECT", "latency_ms"),
        ("SELECT", "outcome"),
        ("SELECT", "outcome_sentence"),
        ("UPDATE", "latency_ms"),
        ("UPDATE", "outcome"),
        ("UPDATE", "outcome_sentence"),
    ]
    .iter()
    .map(|(privilege, column)| ((*privilege).to_owned(), (*column).to_owned()))
    .collect();
    expected.sort();
    assert_eq!(granted, expected);

    let table_wide: Vec<String> = admin
        .query(
            "SELECT p FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                         'REFERENCES', 'TRIGGER']) AS p
             WHERE has_table_privilege('switchboard_gateway', 'switchboard_audit.call_rows', p)
                OR has_table_privilege('switchboard_gateway', 'switchboard_audit.migrations', p)",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(table_wide, Vec::<String>::new());
}

#[tokio::test]
async fn the_gateway_cannot_write_the_identifier_the_times_or_a_completion_at_insert() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    insert_row(&gateway, &insert(&[])).await;
    for column in [
        ("id", "gen_random_uuid()"),
        ("begun_at", "now() - interval '1 day'"),
        ("finished_at", "now()"),
        ("outcome", "'ok'"),
        ("latency_ms", "1"),
    ] {
        let error = gateway
            .query_one(&insert(&[column]), &[])
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{}", column.0);
    }
}

#[tokio::test]
async fn the_gateway_updates_only_the_completion() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &insert(&[])).await;
    for assignment in [
        "tool = 'fixture__other'",
        "proved_subject = 'someone-else'",
        "decision = 'deny'",
        "begun_at = now()",
        "finished_at = now()",
    ] {
        let error = gateway
            .execute(
                &format!("UPDATE switchboard_audit.call_rows SET {assignment} WHERE id = '{id}'"),
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{assignment}");
    }
    assert_eq!(complete(&gateway, &id, "ok").await.unwrap(), 1);
}

#[tokio::test]
async fn the_gateway_cannot_read_who_called_or_delete() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &insert(&[])).await;
    gateway
        .query_one(
            &format!(
                "SELECT id, decision, outcome, outcome_sentence, latency_ms
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    for column in ["proved_subject", "claimed_team", "tool", "begun_at", "*"] {
        let error = gateway
            .query(
                &format!("SELECT {column} FROM switchboard_audit.call_rows"),
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{column}");
    }
    for statement in [
        "DELETE FROM switchboard_audit.call_rows".to_owned(),
        "TRUNCATE switchboard_audit.call_rows".to_owned(),
        "SELECT * FROM switchboard_audit.migrations".to_owned(),
        "CREATE TABLE switchboard_audit.other (id int)".to_owned(),
    ] {
        let error = gateway.batch_execute(&statement).await.unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{statement}");
    }
}

#[tokio::test]
async fn a_row_is_completed_at_most_once_whoever_writes() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &insert(&[])).await;
    assert_eq!(complete(&gateway, &id, "ok").await.unwrap(), 1);
    for client in [&gateway, &owner] {
        let error = complete(client, &id, "error").await.unwrap_err();
        assert!(message(&error).contains("is already complete"), "{error}");
        let error = complete(client, &id, "ok").await.unwrap_err();
        assert!(message(&error).contains("is already complete"), "{error}");
    }
    let outcome: String = owner
        .query_one(
            &format!("SELECT outcome FROM switchboard_audit.call_rows WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(outcome, "ok");
}

#[tokio::test]
async fn a_denial_is_never_completed() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let id = insert_row(&owner, &denied()).await;
    let error = complete(&owner, &id, "ok").await.unwrap_err();
    assert!(message(&error).contains("records a denial"), "{error}");
}

#[tokio::test]
async fn a_completion_writes_nothing_else_even_for_the_owner() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let id = insert_row(&owner, &insert(&[])).await;
    for assignment in [
        "tool = 'fixture__other'",
        "proved_subject = 'someone-else'",
        "begun_at = now() - interval '1 day'",
    ] {
        let error = owner
            .execute(
                &format!(
                    "UPDATE switchboard_audit.call_rows SET outcome = 'ok', latency_ms = 1,
                     {assignment} WHERE id = '{id}'"
                ),
                &[],
            )
            .await
            .unwrap_err();
        assert!(
            message(&error).contains("only the completion"),
            "{assignment}: {error}"
        );
    }
    let error = owner
        .execute(
            &format!("UPDATE switchboard_audit.call_rows SET tool = 'x' WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap_err();
    assert!(message(&error).contains("has no outcome"), "{error}");
}

/// Whether a row's begin time is the last minute's, and whether its completion time is its
/// begin time, or `None` when it has no completion time.
async fn times(client: &Client, id: &str) -> (bool, Option<bool>) {
    let row = client
        .query_one(
            &format!(
                "SELECT begun_at > now() - interval '1 minute', finished_at = begun_at
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

#[tokio::test]
async fn an_insert_cannot_choose_its_times_whoever_writes() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    // A row begun with times of its own choosing is begun now, and not complete.
    let id = insert_row(
        &owner,
        &insert(&[
            ("begun_at", "'2000-01-01T00:00:00Z'"),
            ("finished_at", "'2000-01-01T00:00:01Z'"),
        ]),
    )
    .await;
    assert_eq!(times(&owner, &id).await, (true, None));
    // A row written complete is complete at the moment it was begun.
    let id = insert_row(
        &owner,
        &insert(&[
            ("begun_at", "'2000-01-01T00:00:00Z'"),
            ("outcome", "'ok'"),
            ("latency_ms", "1"),
        ]),
    )
    .await;
    assert_eq!(times(&owner, &id).await, (true, Some(true)));
    // Without the trigger nothing sets the begin time, so no row can be stored.
    db.admin()
        .await
        .batch_execute("ALTER TABLE switchboard_audit.call_rows DISABLE TRIGGER set_times")
        .await
        .unwrap();
    let error = owner.query_one(&insert(&[]), &[]).await.unwrap_err();
    assert_eq!(code(&error), Some(NOT_NULL_VIOLATION), "{error}");
}

#[tokio::test]
async fn the_database_sets_both_times() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &insert(&[])).await;
    // The owner tries to backdate the completion; the trigger sets the time regardless.
    let owner = db.connect_as(OWNER_ROLE).await;
    owner
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows
                 SET outcome = 'ok', latency_ms = 1, finished_at = '2000-01-01T00:00:00Z'
                 WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    let in_order: bool = owner
        .query_one(
            &format!(
                "SELECT begun_at > now() - interval '1 minute' AND finished_at >= begun_at
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(in_order);
}

#[tokio::test]
async fn a_row_the_core_could_not_make_is_refused() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let deny = [
        ("decision", "'deny'"),
        ("reason", "'unknown_tool'"),
        ("sentence", "'Denied.'"),
    ];
    let with = |changes: &[(&'static str, &'static str)]| -> Vec<(&'static str, &'static str)> {
        changes.to_vec()
    };
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "a decision that is neither",
            with(&[("decision", "'maybe'")]),
        ),
        (
            "an unknown classification",
            with(&[("classification", "'other'")]),
        ),
        (
            "an allowed call with a reason",
            with(&[("reason", "'unknown_tool'")]),
        ),
        (
            "an allowed call with a sentence",
            with(&[("sentence", "'Denied.'")]),
        ),
        (
            "a principal of neither kind",
            with(&[("proved_kind", "'service'"), ("proved_team", "")]),
        ),
        (
            "an allowed call with no connector",
            with(&[("connector", "")]),
        ),
        (
            "an allowed call with no classification",
            with(&[("classification", "")]),
        ),
        ("a denial without its sentence", with(&deny[..2])),
        ("a denial without its reason", with(&[deny[0], deny[2]])),
        (
            "a denial with an outcome",
            with(&[
                deny[0],
                deny[1],
                deny[2],
                ("outcome", "'ok'"),
                ("latency_ms", "1"),
                ("finished_at", "now()"),
            ]),
        ),
        ("a workload without a team", with(&[("proved_team", "")])),
        (
            "a workload with groups",
            with(&[("proved_groups", "ARRAY['g']")]),
        ),
        (
            "a user without groups",
            with(&[("proved_kind", "'user'"), ("proved_team", "")]),
        ),
        (
            "an outcome without a latency",
            with(&[("outcome", "'ok'"), ("finished_at", "now()")]),
        ),
        (
            "a refusal without its sentence",
            with(&[
                ("outcome", "'refused'"),
                ("latency_ms", "1"),
                ("finished_at", "now()"),
            ]),
        ),
        (
            "a sentence on an outcome that is not a refusal",
            with(&[
                ("outcome", "'ok'"),
                ("outcome_sentence", "'No.'"),
                ("latency_ms", "1"),
                ("finished_at", "now()"),
            ]),
        ),
        (
            "an unknown outcome",
            with(&[
                ("outcome", "'maybe'"),
                ("latency_ms", "1"),
                ("finished_at", "now()"),
            ]),
        ),
        (
            "a negative latency",
            with(&[
                ("outcome", "'ok'"),
                ("latency_ms", "-1"),
                ("finished_at", "now()"),
            ]),
        ),
        (
            "resources that are an object",
            with(&[("resources", "'{}'::jsonb")]),
        ),
        (
            "a negative count of resources left out",
            with(&[("resources_omitted", "-1")]),
        ),
        (
            "resources left out of resources nobody could name",
            with(&[
                ("resources", "'\"unknown\"'::jsonb"),
                ("resources_omitted", "1"),
            ]),
        ),
    ];
    for (case, changes) in cases {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
    }
    for (case, changes) in [
        ("no resources", with(&[("resources", "")])),
        (
            "no count of resources left out",
            with(&[("resources_omitted", "")]),
        ),
    ] {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(NOT_NULL_VIOLATION), "{case}: {error}");
    }
    // And the shapes the core does make are accepted.
    for changes in [
        with(&[]),
        with(&deny),
        with(&[
            ("proved_kind", "'user'"),
            ("proved_team", ""),
            ("proved_groups", "ARRAY[]::text[]"),
        ]),
        with(&[("resources", "'[]'::jsonb")]),
        with(&[("resources", "'\"unknown\"'::jsonb")]),
        with(&[("resources_omitted", "3")]),
        with(&[
            ("outcome", "'refused'"),
            ("outcome_sentence", "'No.'"),
            ("latency_ms", "1"),
            ("finished_at", "now()"),
        ]),
    ] {
        insert_row(&owner, &insert(&changes)).await;
    }

    // The trigger sets the completion time together with the outcome. With it disabled, which
    // only the owner can do, the constraint still keeps the two together.
    let set_times = |change: &str| {
        format!("ALTER TABLE switchboard_audit.call_rows {change} TRIGGER set_times")
    };
    owner.batch_execute(&set_times("DISABLE")).await.unwrap();
    for (case, changes) in [
        (
            "an outcome without its time",
            with(&[
                ("begun_at", "now()"),
                ("outcome", "'ok'"),
                ("latency_ms", "1"),
            ]),
        ),
        (
            "a time without an outcome",
            with(&[("begun_at", "now()"), ("finished_at", "now()")]),
        ),
    ] {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
    }
    owner.batch_execute(&set_times("ENABLE")).await.unwrap();
}
