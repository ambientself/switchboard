//! The roles, grants, trigger and constraints, exercised with plain SQL.

use std::time::Duration;

use tokio::time::{Instant, sleep};
use tokio_postgres::Client;

use super::{
    ADDED_BY_0010, CHECK_VIOLATION, EXCEPTION_COLUMN, INSUFFICIENT_PRIVILEGE, NOT_NULL_VIOLATION,
    SETUP, TestDatabase, code, message,
};
use crate::{GATEWAY_ROLE, MIGRATIONS, MigrateError, OWNER_ROLE, ROLES, migrate};

/// The begin columns of an allowed call by a workload, as `(column, value)` in SQL. The
/// identifier is a fresh UUID, as the gateway supplies one. The allowance is a fixed 37 s,
/// written as SQL; these tests do not derive it from the budgets.
const ALLOWED: &[(&str, &str)] = &[
    ("id", "gen_random_uuid()"),
    ("instance", "'fixture-instance'"),
    ("kind", "'call'"),
    ("allowance_ms", "37000"),
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

/// The columns of a list row by a workload, as `(column, value)` in SQL.
const LISTED: &[(&str, &str)] = &[
    ("id", "gen_random_uuid()"),
    ("instance", "'fixture-instance'"),
    ("kind", "'list'"),
    ("deployment", "'fixture'"),
    ("surface", "'fixture-all'"),
    ("profile", "'workload-rw'"),
    ("policy_revision", "'fixture-1'"),
    ("proved_issuer", "'https://workload-issuer.fixture.test'"),
    ("proved_subject", "'system:serviceaccount:team-a:sandbox'"),
    ("proved_kind", "'workload'"),
    ("proved_team", "'team-a'"),
    (
        "listed_tools",
        "'[\"fixture__read\", \"fixture__write\"]'::jsonb",
    ),
    ("listed_omitted", "0"),
];

/// `ALLOWED`, with each of `changes` replacing or adding a column.
pub(super) fn insert(changes: &[(&str, &str)]) -> String {
    insert_from(ALLOWED, changes)
}

/// `LISTED`, with each of `changes` replacing or adding a column.
pub(super) fn list(changes: &[(&str, &str)]) -> String {
    insert_from(LISTED, changes)
}

/// `base`, with each of `changes` replacing or adding a column. An empty value leaves the
/// column out.
fn insert_from(base: &[(&str, &str)], changes: &[(&str, &str)]) -> String {
    let mut columns: Vec<(&str, &str)> = base
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
pub(super) fn denied() -> String {
    insert(&[
        ("decision", "'deny'"),
        ("reason", "'unknown_tool'"),
        ("sentence", "'Denied.'"),
    ])
}

pub(super) async fn insert_row(client: &Client, sql: &str) -> String {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

/// Completes `id` with `outcome` and a latency of 1, and an `error` with the kind `other`, as
/// an error must have since 0006. Any other outcome is given no kind, so a row can be completed
/// this way before 0006 too.
pub(super) async fn complete(
    client: &Client,
    id: &str,
    outcome: &str,
) -> Result<u64, tokio_postgres::Error> {
    let kind = if outcome == "error" {
        ", error_kind = 'other'"
    } else {
        ""
    };
    complete_with(client, id, &format!("outcome = '{outcome}'{kind}")).await
}

/// Completes `id` with the assignments in `set` and a latency of 1.
async fn complete_with(client: &Client, id: &str, set: &str) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET {set}, latency_ms = 1 WHERE id = '{id}'"
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
    assert_eq!(recorded, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
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

/// Two migrators on one database take turns: each migration is applied by one of them, and the
/// other then finds it applied. Without the lock, both create the schema at once and one fails.
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
        let mut applied = first.unwrap();
        applied.extend(second.unwrap());
        applied.sort_unstable();
        assert_eq!(
            applied,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            "each migration is applied once"
        );
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
        let give_up = Instant::now() + Duration::from_secs(30);
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
                 AND table_name = 'call_rows'
             ORDER BY 1, 2",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let mut expected: Vec<(String, String)> = [
        ("INSERT", "allowance_ms"),
        ("INSERT", "allowed_by_exception"),
        ("INSERT", "classification"),
        ("INSERT", "claimed_acting_person"),
        ("INSERT", "claimed_team"),
        ("INSERT", "connector"),
        ("INSERT", "credential_mode"),
        ("INSERT", "credential_principal"),
        ("INSERT", "currency"),
        ("INSERT", "decision"),
        ("INSERT", "delegation_digest"),
        ("INSERT", "delegation_egress"),
        ("INSERT", "delegation_epoch"),
        ("INSERT", "delegation_execution"),
        ("INSERT", "delegation_failure"),
        ("INSERT", "delegation_issuer"),
        ("INSERT", "delegation_key_id"),
        ("INSERT", "delegation_session"),
        ("INSERT", "delegation_turn"),
        ("INSERT", "deployment"),
        ("INSERT", "duplicate_of"),
        ("INSERT", "id"),
        ("INSERT", "instance"),
        ("INSERT", "kind"),
        ("INSERT", "latency_ms"),
        ("INSERT", "listed_omitted"),
        ("INSERT", "listed_tools"),
        ("INSERT", "outcome"),
        ("INSERT", "outcome_sentence"),
        ("INSERT", "policy_revision"),
        ("INSERT", "profile"),
        ("INSERT", "proved_delegation_team"),
        ("INSERT", "proved_groups"),
        ("INSERT", "proved_issuer"),
        ("INSERT", "proved_kind"),
        ("INSERT", "proved_pod"),
        ("INSERT", "proved_subject"),
        ("INSERT", "proved_team"),
        ("INSERT", "reason"),
        ("INSERT", "resources"),
        ("INSERT", "resources_omitted"),
        ("INSERT", "sentence"),
        ("INSERT", "surface"),
        ("INSERT", "tool"),
        ("INSERT", "tool_use_id"),
        ("SELECT", "deadline"),
        ("SELECT", "decision"),
        ("SELECT", "duplicate_of"),
        ("SELECT", "error_kind"),
        ("SELECT", "id"),
        ("SELECT", "kind"),
        ("SELECT", "latency_ms"),
        ("SELECT", "outcome"),
        ("SELECT", "outcome_sentence"),
        ("UPDATE", "error_kind"),
        ("UPDATE", "latency_ms"),
        ("UPDATE", "outcome"),
        ("UPDATE", "outcome_sentence"),
        ("UPDATE", "resources"),
        ("UPDATE", "resources_omitted"),
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

    // On anything else in the schema as a whole, the gateway's role holds SELECT on the
    // open-row view, and nothing more. What it holds on the receipts' columns is
    // the_gateway_holds_exactly_its_receipt_grants'.
    let elsewhere: Vec<(String, String)> = admin
        .query(
            "SELECT table_name::text, privilege_type::text
             FROM information_schema.table_privileges
             WHERE grantee = 'switchboard_gateway' AND table_schema = 'switchboard_audit'
             ORDER BY 1, 2",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        elsewhere,
        vec![("open_call_rows".to_owned(), "SELECT".to_owned())]
    );
}

#[tokio::test]
async fn the_gateway_writes_the_identifier_but_not_the_times_or_a_completion_at_insert() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let chosen = "0199c3a2-7b1e-7c3d-9f00-0123456789ab";
    let written = insert_row(&gateway, &insert(&[("id", &format!("'{chosen}'"))])).await;
    assert_eq!(
        written, chosen,
        "the row is stored under the identifier given"
    );
    // The database assigns none: a row without one is not written.
    let error = gateway
        .query_one(&insert(&[("id", "")]), &[])
        .await
        .unwrap_err();
    assert_eq!(
        code(&error),
        Some(NOT_NULL_VIOLATION),
        "{}",
        message(&error)
    );
    for column in [
        ("begun_at", "now() - interval '1 day'"),
        ("finished_at", "now()"),
        ("deadline", "now() + interval '1 day'"),
        ("error_kind", "'other'"),
    ] {
        let error = gateway
            .query_one(&insert(&[column]), &[])
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{}", column.0);
    }
    // It writes the answer to a reused key complete at insert (migration 0008), and the
    // database gives it its completion time, the time at begin. The completion's columns are
    // written together or not at all.
    let answered = insert_row(
        &gateway,
        &insert(&[
            ("outcome", "'refused'"),
            ("outcome_sentence", "'Reused.'"),
            ("latency_ms", "0"),
        ]),
    )
    .await;
    let owner = db.connect_as(OWNER_ROLE).await;
    let same: bool = owner
        .query_one(
            &format!(
                "SELECT finished_at = begun_at FROM switchboard_audit.call_rows
                 WHERE id = '{answered}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(same, "an answered row is complete at its time at begin");
    for partial in [&[("outcome", "'ok'")][..], &[("latency_ms", "1")]] {
        let error = gateway.query_one(&insert(partial), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{partial:?}");
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
        "deadline = now()",
        "instance = 'another'",
        "kind = 'list'",
        "allowance_ms = 0",
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
                "SELECT id, decision, outcome, outcome_sentence, error_kind, latency_ms, kind,
                        deadline
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    for column in [
        "proved_subject",
        "claimed_team",
        "tool",
        "resources",
        "begun_at",
        "instance",
        "allowance_ms",
        "*",
    ] {
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
        "deadline = now() + interval '1 day'",
        "instance = 'another'",
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

/// Migration 0011: a completion may write what a tool that checks its own scope reached in
/// place of the `unknown` its row was begun with, as a list, and nothing else of the resources,
/// whoever writes. Not without a completion, not after one, not on a row begun with named
/// resources or a reach, and not as anything but a list. The gateway's role writes them but
/// cannot read them back.
#[tokio::test]
async fn a_completion_replaces_only_unknown_resources_with_what_was_reached() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let reached = r#"'[{"system": "github", "kind": "repository", "identifier": "o/r"}]'::jsonb"#;
    let unknown = insert(&[("resources", r#"'"unknown"'::jsonb"#)]);

    let id = insert_row(&gateway, &unknown).await;
    let error = gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET resources = {reached}
                 WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap_err();
    assert!(message(&error).contains("has no outcome"), "{error}");
    for not_a_list in [r#"'{"reach": "github-read"}'::jsonb"#, "'[]'::jsonb"] {
        let other = insert_row(&gateway, &unknown).await;
        let set = format!("outcome = 'ok', resources = {not_a_list}, resources_omitted = 0");
        let written = complete_with(&gateway, &other, &set).await;
        // An empty list is what a tool that reached nothing reports; a reach is refused.
        assert_eq!(
            written.is_ok(),
            not_a_list == "'[]'::jsonb",
            "{not_a_list}: {written:?}"
        );
    }
    let set = format!("outcome = 'ok', resources = {reached}, resources_omitted = 2");
    assert_eq!(complete_with(&gateway, &id, &set).await.unwrap(), 1);
    let (resources, omitted): (serde_json::Value, i64) = owner
        .query_one(
            &format!(
                "SELECT resources, resources_omitted FROM switchboard_audit.call_rows
                 WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    assert_eq!(
        resources,
        serde_json::json!([{"system": "github", "kind": "repository", "identifier": "o/r"}])
    );
    assert_eq!(omitted, 2);
    let error = complete_with(&gateway, &id, "outcome = 'ok', resources = '[]'::jsonb")
        .await
        .unwrap_err();
    assert!(message(&error).contains("is already complete"), "{error}");
    let error = gateway
        .query(
            &format!("SELECT resources FROM switchboard_audit.call_rows WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE));

    let reach = insert(&[("resources", r#"'{"reach": "github-read"}'::jsonb"#)]);
    for (client, begun) in [
        (&gateway, insert(&[])),
        (&owner, insert(&[])),
        (&gateway, reach),
    ] {
        let named = insert_row(client, &begun).await;
        for set in [
            format!("outcome = 'ok', resources = {reached}"),
            "outcome = 'ok', resources_omitted = 1".to_owned(),
        ] {
            let error = complete_with(client, &named, &set).await.unwrap_err();
            assert!(
                message(&error).contains("was not begun with unknown resources"),
                "{set}: {error}"
            );
        }
    }
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

/// The row's deadline, less its time at begin, in milliseconds; `None` when it has none.
async fn deadline_after_begin(client: &Client, id: &str) -> Option<f64> {
    client
        .query_one(
            &format!(
                "SELECT (extract(epoch FROM deadline - begun_at) * 1000)::float8
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn the_deadline_is_the_database_time_plus_the_allowance() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let owner = db.connect_as(OWNER_ROLE).await;
    for (allowance, expected) in [("37000", 37_000.0), ("1", 1.0), ("0", 0.0)] {
        let id = insert_row(&gateway, &insert(&[("allowance_ms", allowance)])).await;
        assert_eq!(times(&owner, &id).await, (true, None));
        assert_eq!(
            deadline_after_begin(&owner, &id).await,
            Some(expected),
            "{allowance}"
        );
    }
    // A listing has no deadline, and carries no allowance.
    let id = insert_row(&gateway, &list(&[])).await;
    assert_eq!(deadline_after_begin(&owner, &id).await, None);
    let error = owner
        .query_one(&list(&[("allowance_ms", "37000")]), &[])
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(CHECK_VIOLATION), "{error}");
    // A negative allowance would put the deadline before the row began.
    let error = owner
        .query_one(&insert(&[("allowance_ms", "-1")]), &[])
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(CHECK_VIOLATION), "{error}");
}

#[tokio::test]
async fn an_insert_cannot_choose_its_begin_time_or_deadline_whoever_writes() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    // A row begun with times of its own choosing is begun now, and not complete, and its
    // deadline is its allowance from now.
    let id = insert_row(
        &owner,
        &insert(&[
            ("begun_at", "'2000-01-01T00:00:00Z'"),
            ("finished_at", "'2000-01-01T00:00:01Z'"),
            ("deadline", "'2100-01-01T00:00:00Z'"),
        ]),
    )
    .await;
    assert_eq!(times(&owner, &id).await, (true, None));
    assert_eq!(deadline_after_begin(&owner, &id).await, Some(37_000.0));
    // A listing that names a deadline has none.
    let id = insert_row(&owner, &list(&[("deadline", "'2100-01-01T00:00:00Z'")])).await;
    assert_eq!(deadline_after_begin(&owner, &id).await, None);
    // The gateway's role may not even try.
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    for column in [
        ("begun_at", "'2000-01-01T00:00:00Z'"),
        ("deadline", "'2100-01-01T00:00:00Z'"),
    ] {
        let error = gateway
            .query_one(&insert(&[column]), &[])
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{}", column.0);
    }
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
async fn a_call_row_without_a_deadline_cannot_be_stored() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    // A call with no allowance gets no deadline from the trigger, so it is refused.
    for client in [&gateway, &owner] {
        let error = client
            .query_one(&insert(&[("allowance_ms", "")]), &[])
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{error}");
        assert!(message(&error).contains("deadline_shape"), "{error}");
    }
    // Neither a kind nor an instance may be left out, and the kind is one of two.
    for (case, changes, expected) in [
        ("no kind", [("kind", "")], NOT_NULL_VIOLATION),
        ("no instance", [("instance", "")], NOT_NULL_VIOLATION),
        ("another kind", [("kind", "'other'")], CHECK_VIOLATION),
    ] {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(expected), "{case}: {error}");
    }
    // With the trigger off, which only the owner can do, the constraint alone still refuses
    // a call without a deadline, and a listing with one.
    owner
        .batch_execute("ALTER TABLE switchboard_audit.call_rows DISABLE TRIGGER set_times")
        .await
        .unwrap();
    for (case, sql) in [
        (
            "a call without a deadline",
            insert(&[("begun_at", "now()")]),
        ),
        (
            "a listing with a deadline",
            list(&[("begun_at", "now()"), ("deadline", "now()")]),
        ),
    ] {
        let error = owner.query_one(&sql, &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
        assert!(
            message(&error).contains("deadline_shape"),
            "{case}: {error}"
        );
    }
    insert_row(
        &owner,
        &insert(&[("begun_at", "now()"), ("deadline", "now()")]),
    )
    .await;
    insert_row(&owner, &list(&[("begun_at", "now()")])).await;
}

#[tokio::test]
async fn a_completion_cannot_change_the_deadline_or_instance() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let id = insert_row(&owner, &insert(&[])).await;
    let before: (String, String) = {
        let row = owner
            .query_one(
                &format!(
                    "SELECT instance, deadline::text FROM switchboard_audit.call_rows
                     WHERE id = '{id}'"
                ),
                &[],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    for assignment in [
        "deadline = deadline + interval '1 day'",
        "instance = 'another'",
        "kind = 'list'",
        "allowance_ms = 1",
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
    assert_eq!(complete(&owner, &id, "ok").await.unwrap(), 1);
    let after = owner
        .query_one(
            &format!(
                "SELECT instance, deadline::text FROM switchboard_audit.call_rows
                 WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!((after.get(0), after.get(1)), before);
}

/// The migration that adds the deadline applies to a table that already has rows: each becomes
/// a call by an unrecorded instance, due when it was completed, or begun if it never was.
#[tokio::test]
async fn the_deadline_migration_keeps_the_rows_already_written() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
        .await
        .unwrap();
    owner
        .batch_execute(
            "CREATE SCHEMA switchboard_audit;
             CREATE TABLE switchboard_audit.migrations (
                 version    integer     PRIMARY KEY,
                 name       text        NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await
        .unwrap();
    for migration in &MIGRATIONS[..2] {
        owner.batch_execute(migration.sql).await.unwrap();
        owner
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await
            .unwrap();
    }
    let before_0003 = |sql: String| {
        sql.replace(", instance, kind, allowance_ms", "")
            .replace(", 'fixture-instance', 'call', 37000", "")
    };
    let open = insert_row(&owner, &before_0003(insert(&[]))).await;
    let completed = insert_row(&owner, &before_0003(insert(&[]))).await;
    assert_eq!(complete(&owner, &completed, "ok").await.unwrap(), 1);
    let refused = insert_row(&owner, &before_0003(denied())).await;

    assert_eq!(
        migrate(&mut owner).await.unwrap(),
        vec![3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
    for (id, due) in [
        (&open, "begun_at"),
        (&completed, "finished_at"),
        (&refused, "begun_at"),
    ] {
        let row = owner
            .query_one(
                &format!(
                    "SELECT instance, kind, allowance_ms, deadline = {due}
                     FROM switchboard_audit.call_rows WHERE id = '{id}'"
                ),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "before-0003");
        assert_eq!(row.get::<_, String>(1), "call");
        assert_eq!(row.get::<_, Option<i64>>(2), Some(0));
        assert!(row.get::<_, bool>(3), "{id} is not due at its {due}");
    }
    // The trigger that completes a row once is back on.
    let error = complete(&owner, &completed, "error").await.unwrap_err();
    assert!(message(&error).contains("is already complete"), "{error}");
    assert_eq!(complete(&owner, &open, "ok").await.unwrap(), 1);
}

/// Both trigger functions look names up in `pg_catalog` alone. Otherwise a role that can write
/// the table, and puts a schema holding functions of its own before `pg_catalog`, would change
/// what the triggers do: here a `-` that makes every two rows look alike, so a completion may
/// write any column, and a clock that says it is 2000.
#[tokio::test]
async fn the_triggers_use_the_catalogs_own_functions_whatever_the_search_path() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    db.admin()
        .await
        .batch_execute(
            "CREATE FUNCTION public.all_alike(jsonb, text[]) RETURNS jsonb
                 LANGUAGE sql AS $$SELECT '{}'::jsonb$$;
             CREATE OPERATOR public.- (
                 LEFTARG = jsonb, RIGHTARG = text[], FUNCTION = public.all_alike);
             CREATE FUNCTION public.clock_timestamp() RETURNS timestamptz
                 LANGUAGE sql AS $$SELECT '2000-01-01T00:00:00Z'::timestamptz$$;",
        )
        .await
        .unwrap();
    let owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("SET search_path = public, pg_catalog")
        .await
        .unwrap();
    // A plain statement in this session finds the stand-ins.
    let shadowed: bool = owner
        .query_one(
            "SELECT '{\"a\": 1}'::jsonb - ARRAY['b'] = '{}'::jsonb
                 AND clock_timestamp() < '2001-01-01T00:00:00Z'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(shadowed);

    // The triggers do not.
    let id = insert_row(&owner, &insert(&[])).await;
    assert_eq!(times(&owner, &id).await, (true, None));
    let error = owner
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET outcome = 'ok', latency_ms = 1,
                 tool = 'fixture__other' WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap_err();
    assert!(message(&error).contains("only the completion"), "{error}");
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
    // Since 0004, decision_shape refuses a decision that is neither allow nor deny as well. The
    // column's own check still refuses it first: a table's checks run in order of name, and its
    // name comes first.
    let error = owner
        .query_one(&insert(&[("decision", "'maybe'")]), &[])
        .await
        .unwrap_err();
    let refused = message(&error);
    assert!(refused.contains("call_rows_decision_check"), "{refused}");
    // A call has its tool, decision and resources, and lists no tools.
    for (case, changes) in [
        ("no tool", with(&[("tool", "")])),
        ("no decision", with(&[("decision", "")])),
        ("no resources", with(&[("resources", "")])),
        (
            "no count of resources left out",
            with(&[("resources_omitted", "")]),
        ),
        ("tools listed", with(&[("listed_tools", "'[]'::jsonb")])),
        (
            "a count of tools left out",
            with(&[("listed_omitted", "0")]),
        ),
    ] {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
        assert!(message(&error).contains("kind_shape"), "{case}: {error}");
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
                ("deadline", "now()"),
                ("outcome", "'ok'"),
                ("latency_ms", "1"),
            ]),
        ),
        (
            "a time without an outcome",
            with(&[
                ("begun_at", "now()"),
                ("deadline", "now()"),
                ("finished_at", "now()"),
            ]),
        ),
    ] {
        let error = owner.query_one(&insert(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
        assert!(
            message(&error).contains("completion_shape"),
            "{case}: {error}"
        );
    }
    owner.batch_execute(&set_times("ENABLE")).await.unwrap();
}

/// A list row has its tools and their count, and none of a call's columns. Each is refused,
/// for every role, by the constraint `kind_shape`.
#[tokio::test]
async fn a_list_row_with_a_deadline_outcome_or_decision_cannot_be_stored() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &list(&[])).await;
    let stored = owner
        .query_one(
            &format!(
                "SELECT kind, listed_tools, listed_omitted, deadline IS NULL,
                        outcome IS NULL AND finished_at IS NULL AND latency_ms IS NULL
                 FROM switchboard_audit.call_rows WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(stored.get::<_, String>(0), "list");
    assert_eq!(
        stored.get::<_, serde_json::Value>(1),
        serde_json::json!(["fixture__read", "fixture__write"])
    );
    assert_eq!(stored.get::<_, i64>(2), 0);
    assert!(stored.get::<_, bool>(3), "a list row has a deadline");
    assert!(stored.get::<_, bool>(4), "a list row has a completion");

    for (case, changes) in [
        ("a tool-use identifier", vec![("tool_use_id", "'toolu_01'")]),
        ("a tool", vec![("tool", "'fixture__read'")]),
        ("a connector", vec![("connector", "'fixture'")]),
        ("a classification", vec![("classification", "'read'")]),
        ("resources", vec![("resources", "'[]'::jsonb")]),
        (
            "a count of resources left out",
            vec![("resources_omitted", "0")],
        ),
        ("an allowed decision", vec![("decision", "'allow'")]),
        (
            "a denial",
            vec![
                ("decision", "'deny'"),
                ("reason", "'unknown_tool'"),
                ("sentence", "'Denied.'"),
            ],
        ),
        ("a reason", vec![("reason", "'unknown_tool'")]),
        ("a sentence", vec![("sentence", "'Denied.'")]),
        ("an outcome", vec![("outcome", "'ok'"), ("latency_ms", "1")]),
        ("an allowance", vec![("allowance_ms", "37000")]),
        ("no tools", vec![("listed_tools", "")]),
        (
            "tools that are not a list",
            vec![("listed_tools", "'{}'::jsonb")],
        ),
        ("no count of tools left out", vec![("listed_omitted", "")]),
        (
            "a negative count of tools left out",
            vec![("listed_omitted", "-1")],
        ),
    ] {
        let error = owner.query_one(&list(&changes), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{case}: {error}");
    }
    // The trigger gives a list row no deadline, whatever it carries. With it off, which only
    // the owner can do, the constraints still refuse one.
    owner
        .batch_execute("ALTER TABLE switchboard_audit.call_rows DISABLE TRIGGER set_times")
        .await
        .unwrap();
    let error = owner
        .query_one(&list(&[("begun_at", "now()"), ("deadline", "now()")]), &[])
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(CHECK_VIOLATION), "{error}");
    insert_row(&owner, &list(&[("begun_at", "now()")])).await;
}

/// A list row is written complete and never completed, by any role. Before 0004 the trigger
/// tested only the decision, and that test was NULL for a row with none, so it let the update
/// through.
#[tokio::test]
async fn a_list_row_is_never_completed_whoever_writes() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &list(&[])).await;
    for client in [&gateway, &owner] {
        for outcome in ["ok", "error"] {
            let error = complete(client, &id, outcome).await.unwrap_err();
            assert!(message(&error).contains("records a listing"), "{error}");
        }
    }
    let error = owner
        .execute(
            &format!("UPDATE switchboard_audit.call_rows SET tool = 'x' WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap_err();
    assert!(message(&error).contains("records a listing"), "{error}");
    let outcome: Option<String> = owner
        .query_one(
            &format!("SELECT outcome FROM switchboard_audit.call_rows WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(outcome, None);
}

/// The gateway's role writes a list row's tools and the caller's columns, and cannot write a
/// completion, a deadline or a time on one.
#[tokio::test]
async fn the_gateway_cannot_insert_a_list_row_with_a_completion() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    insert_row(&gateway, &list(&[])).await;
    for column in [
        ("finished_at", "now()"),
        ("begun_at", "now()"),
        ("deadline", "now()"),
    ] {
        let error = gateway.query_one(&list(&[column]), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{}", column.0);
    }
    // It may insert a completion, for the answer to a reused key, but not on a list row.
    for column in [
        ("outcome", "'ok'"),
        ("outcome_sentence", "'No.'"),
        ("latency_ms", "1"),
    ] {
        let error = gateway.query_one(&list(&[column]), &[]).await.unwrap_err();
        assert_eq!(code(&error), Some(CHECK_VIOLATION), "{}", column.0);
    }
    // Nor can the owner, which may insert a completion, write one on a list row.
    let owner = db.connect_as(OWNER_ROLE).await;
    let error = owner
        .query_one(&list(&[("outcome", "'ok'"), ("latency_ms", "1")]), &[])
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(CHECK_VIOLATION), "{error}");
    assert!(message(&error).contains("kind_shape"), "{error}");
}

/// Whether `error` is the check `constraint` refusing a row.
fn refused_by(error: &tokio_postgres::Error, constraint: &str) -> bool {
    code(error) == Some(CHECK_VIOLATION) && message(error).contains(&format!("\"{constraint}\""))
}

/// An error's kind is one of the five the core names, or `before-0006` for an error completed
/// before the column was added, and nothing else, whoever writes it.
#[tokio::test]
async fn an_error_kind_is_one_the_core_names_or_before_0006() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    for kind in [
        "invalid_arguments",
        "oversized_or_late_read",
        "custodian_refusal",
        "vendor_refusal",
        "other",
        "before-0006",
    ] {
        let id = insert_row(&gateway, &insert(&[])).await;
        let set = format!("outcome = 'error', error_kind = '{kind}'");
        assert_eq!(complete_with(&owner, &id, &set).await.unwrap(), 1, "{kind}");
    }
    for kind in ["unknown", "Other", "vendor-refusal", ""] {
        let id = insert_row(&gateway, &insert(&[])).await;
        let set = format!("outcome = 'error', error_kind = '{kind}'");
        for client in [&gateway, &owner] {
            let error = complete_with(client, &id, &set).await.unwrap_err();
            assert!(refused_by(&error, "error_kind_known"), "{kind}: {error}");
        }
    }
}

/// A row has an error kind exactly when its outcome is `error`: an error without one is
/// refused, and so is another outcome with one, or a row with no outcome yet.
#[tokio::test]
async fn only_an_error_has_a_kind() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    for set in [
        "outcome = 'error'",
        "outcome = 'ok', error_kind = 'other'",
        "outcome = 'refused', outcome_sentence = 'No.', error_kind = 'vendor_refusal'",
    ] {
        let id = insert_row(&gateway, &insert(&[])).await;
        for client in [&gateway, &owner] {
            let error = complete_with(client, &id, set).await.unwrap_err();
            assert!(refused_by(&error, "error_kind_shape"), "{set}: {error}");
        }
    }
    // Only the owner can insert a kind at all, and even it cannot give one to a row with no
    // outcome.
    let error = owner
        .query_one(&insert(&[("error_kind", "'other'")]), &[])
        .await
        .unwrap_err();
    assert!(refused_by(&error, "error_kind_shape"), "{error}");
}

/// The error kind is written with the rest of the completion, by the gateway's role too, and
/// never after it or without it, by any role.
#[tokio::test]
async fn the_error_kind_is_written_with_the_completion_and_never_after() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let id = insert_row(&gateway, &insert(&[])).await;
    let set = "outcome = 'error', error_kind = 'vendor_refusal'";
    assert_eq!(complete_with(&gateway, &id, set).await.unwrap(), 1);
    let open = insert_row(&gateway, &insert(&[])).await;
    for client in [&gateway, &owner] {
        for (row, refusal) in [(&id, "is already complete"), (&open, "has no outcome")] {
            let error = client
                .execute(
                    &format!(
                        "UPDATE switchboard_audit.call_rows SET error_kind = 'other'
                         WHERE id = '{row}'"
                    ),
                    &[],
                )
                .await
                .unwrap_err();
            assert!(message(&error).contains(refusal), "{error}");
        }
    }
    let kind: String = owner
        .query_one(
            &format!("SELECT error_kind FROM switchboard_audit.call_rows WHERE id = '{id}'"),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kind, "vendor_refusal");
}

/// Every row as JSON, without its error kind or the credential columns 0007 adds after it, by
/// identifier.
async fn rows_without_error_kind(client: &Client) -> Vec<(String, serde_json::Value)> {
    client
        .query(
            &format!(
                "SELECT id::text,
                    to_jsonb(r) - 'error_kind' - 'credential_mode' - 'credential_principal'
                        - 'duplicate_of' - {ADDED_BY_0010} - '{EXCEPTION_COLUMN}'
                 FROM switchboard_audit.call_rows AS r ORDER BY id"
            ),
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

/// The migration that adds the error kind applies to a table that already has rows: each
/// error is given the kind `before-0006`, every other row none, and nothing else changes, not
/// even a completion's time.
#[tokio::test]
async fn the_error_kind_migration_marks_the_errors_already_written() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
        .await
        .unwrap();
    owner
        .batch_execute(
            "CREATE SCHEMA switchboard_audit;
             CREATE TABLE switchboard_audit.migrations (
                 version    integer     PRIMARY KEY,
                 name       text        NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await
        .unwrap();
    for migration in &MIGRATIONS[..5] {
        owner.batch_execute(migration.sql).await.unwrap();
        owner
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await
            .unwrap();
    }
    let failed = insert_row(&owner, &insert(&[])).await;
    let set = "outcome = 'error'";
    assert_eq!(complete_with(&owner, &failed, set).await.unwrap(), 1);
    let succeeded = insert_row(&owner, &insert(&[])).await;
    assert_eq!(complete(&owner, &succeeded, "ok").await.unwrap(), 1);
    let refused = insert_row(&owner, &insert(&[])).await;
    let set = "outcome = 'refused', outcome_sentence = 'No.'";
    assert_eq!(complete_with(&owner, &refused, set).await.unwrap(), 1);
    let open = insert_row(&owner, &insert(&[])).await;
    let denial = insert_row(&owner, &denied()).await;
    let before = rows_without_error_kind(&owner).await;

    assert_eq!(
        migrate(&mut owner).await.unwrap(),
        vec![6, 7, 8, 9, 10, 11, 12, 13]
    );
    assert_eq!(rows_without_error_kind(&owner).await, before);
    for (id, kind) in [
        (&failed, Some("before-0006")),
        (&succeeded, None),
        (&refused, None),
        (&open, None),
        (&denial, None),
    ] {
        let stored: Option<String> = owner
            .query_one(
                &format!("SELECT error_kind FROM switchboard_audit.call_rows WHERE id = '{id}'"),
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored.as_deref(), kind, "{id}");
    }
    // The trigger that completes a row once is back on.
    let error = complete(&owner, &failed, "error").await.unwrap_err();
    assert!(message(&error).contains("is already complete"), "{error}");
    assert_eq!(complete(&owner, &open, "error").await.unwrap(), 1);
}

/// A reach is recorded as `{"reach": entry}`: an object with that one key, naming an entry, with
/// nothing left out. Any other object is refused, whoever writes it, and the gateway's role
/// writes one.
#[tokio::test]
async fn a_reach_is_an_object_naming_one_entry_with_nothing_left_out() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let reach = ("resources", "'{\"reach\": \"docs-team-a\"}'::jsonb");
    insert_row(&gateway, &insert(&[reach])).await;
    insert_row(
        &gateway,
        &insert(&[
            reach,
            ("decision", "'deny'"),
            ("reason", "'resource_outside_limit'"),
            ("sentence", "'Denied.'"),
        ]),
    )
    .await;
    for (case, resources) in [
        ("an empty object", "'{}'::jsonb"),
        ("an empty entry", "'{\"reach\": \"\"}'::jsonb"),
        (
            "an entry that is not a string",
            "'{\"reach\": [\"docs-team-a\"]}'::jsonb",
        ),
        ("an entry that is null", "'{\"reach\": null}'::jsonb"),
        (
            "another key beside the entry",
            "'{\"reach\": \"docs-team-a\", \"named\": []}'::jsonb",
        ),
        ("another key alone", "'{\"named\": []}'::jsonb"),
        ("a number", "'7'::jsonb"),
        ("another string", "'\"docs-team-a\"'::jsonb"),
    ] {
        for client in [&gateway, &owner] {
            let error = client
                .query_one(&insert(&[("resources", resources)]), &[])
                .await
                .unwrap_err();
            assert!(refused_by(&error, "resources_known"), "{case}: {error}");
        }
    }
    for client in [&gateway, &owner] {
        let error = client
            .query_one(&insert(&[reach, ("resources_omitted", "3")]), &[])
            .await
            .unwrap_err();
        assert!(refused_by(&error, "reach_shape"), "{error}");
    }
}

/// The credential identity is a mode the core names and its principal, written together at
/// insert by the gateway's role, or neither. A row with neither is accepted: a call naming no
/// tool with an entry, or a row written before 0007.
#[tokio::test]
async fn a_credential_identity_is_a_known_mode_with_its_principal_or_neither() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    for mode in ["team_service_identity", "gateway_token", "per_user_grant"] {
        let mode = format!("'{mode}'");
        let id = insert_row(
            &gateway,
            &insert(&[
                ("credential_mode", &mode),
                ("credential_principal", "'docs-team-a'"),
            ]),
        )
        .await;
        let stored: (String, String) = owner
            .query_one(
                &format!(
                    "SELECT credential_mode, credential_principal
                       FROM switchboard_audit.call_rows WHERE id = '{id}'"
                ),
                &[],
            )
            .await
            .map(|row| (row.get(0), row.get(1)))
            .unwrap();
        assert_eq!(
            stored,
            (mode.trim_matches('\'').to_owned(), "docs-team-a".to_owned())
        );
    }
    insert_row(&gateway, &insert(&[])).await;
    for (constraint, changes) in [
        (
            "credential_mode_known",
            vec![
                ("credential_mode", "'service_account'"),
                ("credential_principal", "'docs-team-a'"),
            ],
        ),
        (
            "credential_mode_known",
            vec![
                ("credential_mode", "'Gateway_Token'"),
                ("credential_principal", "'docs-team-a'"),
            ],
        ),
        (
            "credential_shape",
            vec![("credential_mode", "'team_service_identity'")],
        ),
        (
            "credential_shape",
            vec![("credential_principal", "'docs-team-a'")],
        ),
    ] {
        for client in [&gateway, &owner] {
            let error = client.query_one(&insert(&changes), &[]).await.unwrap_err();
            assert!(refused_by(&error, constraint), "{changes:?}: {error}");
        }
    }
    // The gateway's role writes them at begin and never again, and cannot read them back.
    let id = insert_row(&gateway, &insert(&[])).await;
    let error = gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows
                    SET credential_mode = 'gateway_token', credential_principal = 'x'
                  WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
    let error = gateway
        .query(
            "SELECT credential_mode, credential_principal FROM switchboard_audit.call_rows",
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
}

/// Rows written before 0007 keep their resources, and record no credential identity: NULL,
/// not recorded. The migration accepts every shape of resources they could hold.
#[tokio::test]
async fn the_reach_and_credential_migration_keeps_the_rows_already_written() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
        .await
        .unwrap();
    owner
        .batch_execute(
            "CREATE SCHEMA switchboard_audit;
             CREATE TABLE switchboard_audit.migrations (
                 version    integer     PRIMARY KEY,
                 name       text        NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await
        .unwrap();
    for migration in &MIGRATIONS[..6] {
        owner.batch_execute(migration.sql).await.unwrap();
        owner
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await
            .unwrap();
    }
    let named = insert_row(&owner, &insert(&[])).await;
    let unknown = insert_row(&owner, &insert(&[("resources", "'\"unknown\"'::jsonb")])).await;
    let listed = insert_row(&owner, &list(&[])).await;
    let read = |id: &str| {
        format!(
            "SELECT resources, credential_mode IS NULL AND credential_principal IS NULL
               FROM switchboard_audit.call_rows WHERE id = '{id}'"
        )
    };
    let resources =
        |id: &str| format!("SELECT resources FROM switchboard_audit.call_rows WHERE id = '{id}'");
    let mut before = Vec::new();
    for id in [&named, &unknown, &listed] {
        let row = owner.query_one(&resources(id), &[]).await.unwrap();
        before.push(row.get::<_, Option<serde_json::Value>>(0));
    }

    assert_eq!(
        migrate(&mut owner).await.unwrap(),
        vec![7, 8, 9, 10, 11, 12, 13]
    );
    for (id, resources) in [&named, &unknown, &listed].into_iter().zip(before) {
        let row = owner.query_one(&read(id), &[]).await.unwrap();
        assert_eq!(
            row.get::<_, Option<serde_json::Value>>(0),
            resources,
            "{id}"
        );
        assert!(row.get::<_, bool>(1), "{id} records a credential identity");
    }
}

/// A digest, as migration 0010's `delegation_digest` holds one: 64 lowercase hex digits.
const DIGEST: &str = "'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'";

/// The columns of a verified delegation, with its team and person, as `(column, value)` in SQL.
const VERIFIED: &[(&str, &str)] = &[
    ("proved_delegation_team", "'team-a'"),
    ("claimed_acting_person", "'person@fixture.test'"),
    ("delegation_digest", DIGEST),
    ("delegation_issuer", "'otto-test'"),
    ("delegation_key_id", "'key-1'"),
    ("delegation_session", "'session-1'"),
    ("delegation_turn", "'turn-1'"),
    ("delegation_execution", "'execution-1'"),
    ("delegation_epoch", "7"),
];

/// A row check 3 denied for a delegation whose signature did not verify.
const AT_CHECK_3: &[(&str, &str)] = &[
    ("decision", "'deny'"),
    ("reason", "'delegation_unverified'"),
    ("sentence", "'Denied.'"),
    ("delegation_failure", "'signature'"),
];

/// Decision 0012's columns (migration 0010) hold the shapes the core writes and no others,
/// whoever writes them: a verified delegation's columns together, with its team and person; a
/// failure only on a row check 3 denied for it, beside nothing from the delegation's claims,
/// and with a digest only after a verified signature; a currency answer only on a call row; and
/// a pod UID only for a workload.
#[tokio::test]
async fn the_delegation_columns_hold_decision_0012s_shapes_and_no_others() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    fn with<'a>(
        base: &[(&'a str, &'a str)],
        more: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let kept = base
            .iter()
            .filter(|(column, _)| !more.iter().any(|(added, _)| added == column));
        kept.chain(more).copied().collect()
    }
    let pod = ("proved_pod", "'0f8fad5b-d9cb-469f-a165-70867728950e'");
    for accepted in [
        insert(VERIFIED),
        insert(&with(
            VERIFIED,
            &[
                ("delegation_egress", "'sealed'"),
                ("currency", "'current'"),
                pod,
            ],
        )),
        insert(&with(VERIFIED, &[("delegation_egress", "'open'")])),
        insert(AT_CHECK_3),
        insert(&with(
            AT_CHECK_3,
            &[
                ("delegation_failure", "'wrong_pod'"),
                ("delegation_digest", DIGEST),
                ("currency", "'revoked'"),
            ],
        )),
        insert(&[("currency", "'unconfirmed'")]),
        list(&with(VERIFIED, &[pod])),
    ] {
        insert_row(&gateway, &accepted).await;
    }
    for failure in [
        "version",
        "unknown_key",
        "retired_key",
        "encoding",
        "signature",
        "malformed",
    ] {
        let failure = format!("'{failure}'");
        insert_row(
            &gateway,
            &insert(&with(AT_CHECK_3, &[("delegation_failure", &failure)])),
        )
        .await;
    }
    for failure in [
        "expired",
        "not_yet_valid",
        "lifetime_over_ceiling",
        "wrong_audience",
        "wrong_pod",
    ] {
        let failure = format!("'{failure}'");
        insert_row(
            &gateway,
            &insert(&with(
                AT_CHECK_3,
                &[
                    ("delegation_failure", &failure),
                    ("delegation_digest", DIGEST),
                ],
            )),
        )
        .await;
    }

    let user = [
        ("proved_kind", "'user'"),
        ("proved_team", ""),
        ("proved_groups", "ARRAY['group-g']"),
    ];
    for (constraint, sql) in [
        ("proved_pod_shape", insert(&[("proved_pod", "'pod-name'")])),
        ("proved_pod_shape", insert(&with(&user, &[pod]))),
        (
            "delegation_digest_known",
            insert(&with(VERIFIED, &[("delegation_digest", "'9F86'")])),
        ),
        (
            "delegation_epoch_known",
            insert(&with(VERIFIED, &[("delegation_epoch", "-1")])),
        ),
        (
            "delegation_egress_known",
            insert(&with(VERIFIED, &[("delegation_egress", "'closed'")])),
        ),
        (
            "delegation_failure_known",
            insert(&with(AT_CHECK_3, &[("delegation_failure", "'forged'")])),
        ),
        ("currency_known", insert(&[("currency", "'stale'")])),
        (
            "delegation_shape",
            insert(&with(VERIFIED, &[("delegation_key_id", "")])),
        ),
        (
            "delegation_shape",
            insert(&with(VERIFIED, &[("proved_delegation_team", "")])),
        ),
        (
            "delegation_shape",
            insert(&with(VERIFIED, &[("claimed_acting_person", "")])),
        ),
        (
            "delegation_shape",
            insert(&with(VERIFIED, &[("delegation_digest", "")])),
        ),
        (
            "delegation_shape",
            insert(&[("delegation_egress", "'sealed'")]),
        ),
        (
            "delegation_failure_shape",
            insert(&[("delegation_failure", "'signature'")]),
        ),
        (
            "delegation_failure_shape",
            insert(&with(
                AT_CHECK_3,
                &[("reason", "'classification_not_permitted'")],
            )),
        ),
        (
            "delegation_failure_shape",
            insert(&with(AT_CHECK_3, &[("delegation_failure", "")])),
        ),
        (
            "delegation_failure_shape",
            list(&[("delegation_failure", "'signature'")]),
        ),
        (
            "delegation_failure_unclaimed",
            insert(&with(
                AT_CHECK_3,
                &[("claimed_acting_person", "'person@fixture.test'")],
            )),
        ),
        (
            "delegation_failure_unclaimed",
            insert(&with(AT_CHECK_3, &[("proved_delegation_team", "'team-a'")])),
        ),
        (
            "delegation_failure_unclaimed",
            insert(&with(AT_CHECK_3, VERIFIED)),
        ),
        (
            "delegation_digest_shape",
            insert(&with(AT_CHECK_3, &[("delegation_digest", DIGEST)])),
        ),
        (
            "delegation_digest_shape",
            insert(&with(
                AT_CHECK_3,
                &[
                    ("delegation_failure", "'malformed'"),
                    ("delegation_digest", DIGEST),
                ],
            )),
        ),
        (
            "delegation_digest_shape",
            insert(&[("delegation_digest", DIGEST)]),
        ),
        ("currency_shape", list(&[("currency", "'current'")])),
    ] {
        for client in [&gateway, &owner] {
            let error = client.query_one(&sql, &[]).await.unwrap_err();
            assert!(refused_by(&error, constraint), "{sql}: {error}");
        }
    }

    // The gateway's role writes them at begin and never again, and cannot read them back.
    let id = insert_row(&gateway, &insert(VERIFIED)).await;
    let error = gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET currency = 'current' WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
    let error = gateway
        .query(
            "SELECT delegation_digest, delegation_failure, currency, proved_pod
               FROM switchboard_audit.call_rows",
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
}

/// The exception that allowed a call (decision 0011, section 9; migration 0012) holds the
/// shape the core writes and no other, whoever writes it: a name of lowercase letters, digits
/// and `-`, of at most 64 characters, on an allowed call row of a `write` or `destructive` tool
/// only. Never on a denial, a read, a proposal or a list row. The gateway's role writes it at
/// begin and never again, and cannot read it back.
#[tokio::test]
async fn the_exception_column_holds_an_allowed_writes_exception_and_nothing_else() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let owner = db.connect_as(OWNER_ROLE).await;
    let gateway = db.connect_as(GATEWAY_ROLE).await;
    let longest = format!("'{}'", "a".repeat(64));
    let too_long = format!("'{}'", "a".repeat(65));
    let write = ("classification", "'write'");
    for accepted in [
        insert(&[write, ("allowed_by_exception", "'otto-comment-tools'")]),
        insert(&[write, ("allowed_by_exception", longest.as_str())]),
        insert(&[write, ("allowed_by_exception", "'7'")]),
        insert(&[
            ("classification", "'destructive'"),
            ("allowed_by_exception", "'otto-comment-tools'"),
        ]),
        insert(&[write]),
    ] {
        insert_row(&gateway, &accepted).await;
    }
    for (constraint, sql) in [
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", "'Otto'")]),
        ),
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", "'-otto'")]),
        ),
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", "'otto-'")]),
        ),
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", "'otto comment'")]),
        ),
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", "''")]),
        ),
        (
            "allowed_by_exception_known",
            insert(&[write, ("allowed_by_exception", too_long.as_str())]),
        ),
        (
            "allowed_by_exception_shape",
            insert(&[("allowed_by_exception", "'otto-comment-tools'")]),
        ),
        (
            "allowed_by_exception_shape",
            insert(&[
                ("classification", "'propose'"),
                ("allowed_by_exception", "'otto-comment-tools'"),
            ]),
        ),
        (
            "allowed_by_exception_shape",
            insert(&[
                write,
                ("decision", "'deny'"),
                ("reason", "'not_current'"),
                ("sentence", "'Denied.'"),
                ("allowed_by_exception", "'otto-comment-tools'"),
            ]),
        ),
        (
            "allowed_by_exception_shape",
            list(&[("allowed_by_exception", "'otto-comment-tools'")]),
        ),
    ] {
        for client in [&gateway, &owner] {
            let error = client.query_one(&sql, &[]).await.unwrap_err();
            assert!(refused_by(&error, constraint), "{sql}: {error}");
        }
    }

    let id = insert_row(
        &gateway,
        &insert(&[write, ("allowed_by_exception", "'otto-comment-tools'")]),
    )
    .await;
    let error = gateway
        .execute(
            &format!(
                "UPDATE switchboard_audit.call_rows SET allowed_by_exception = 'other'
                  WHERE id = '{id}'"
            ),
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
    let error = gateway
        .query(
            "SELECT allowed_by_exception FROM switchboard_audit.call_rows",
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(code(&error), Some(INSUFFICIENT_PRIVILEGE), "{error}");
}

/// Rows written before 0010 keep every value they had, and record none of decision 0012's
/// columns: NULL, not recorded. The migration's checks hold for each, a row with a delegation's
/// team and person among them.
#[tokio::test]
async fn the_delegation_migration_keeps_the_rows_already_written() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let mut owner = db.connect_as(OWNER_ROLE).await;
    owner
        .batch_execute("DROP SCHEMA switchboard_audit CASCADE")
        .await
        .unwrap();
    owner
        .batch_execute(
            "CREATE SCHEMA switchboard_audit;
             CREATE TABLE switchboard_audit.migrations (
                 version    integer     PRIMARY KEY,
                 name       text        NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await
        .unwrap();
    for migration in &MIGRATIONS[..9] {
        owner.batch_execute(migration.sql).await.unwrap();
        owner
            .execute(
                "INSERT INTO switchboard_audit.migrations (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )
            .await
            .unwrap();
    }
    let delegated = [
        ("proved_delegation_team", "'team-a'"),
        ("claimed_acting_person", "'person@fixture.test'"),
    ];
    let rows = [
        insert_row(&owner, &insert(&delegated)).await,
        insert_row(&owner, &denied()).await,
        insert_row(&owner, &list(&delegated)).await,
    ];
    let compared = format!(
        "SELECT to_jsonb(r) - {ADDED_BY_0010} - '{EXCEPTION_COLUMN}'
           FROM switchboard_audit.call_rows r WHERE id::text = $1"
    );
    let mut before = Vec::new();
    for id in &rows {
        let row = owner.query_one(&compared, &[id]).await.unwrap();
        before.push(row.get::<_, serde_json::Value>(0));
    }

    assert_eq!(migrate(&mut owner).await.unwrap(), vec![10, 11, 12, 13]);
    for (id, before) in rows.iter().zip(before) {
        let row = owner.query_one(&compared, &[id]).await.unwrap();
        assert_eq!(row.get::<_, serde_json::Value>(0), before, "{id}");
        let added = owner
            .query_one(
                &format!(
                    "SELECT to_jsonb(r) - (SELECT array_agg(k) FROM jsonb_object_keys(to_jsonb(r)) k
                                            WHERE NOT k = ANY({ADDED_BY_0010}))
                       FROM switchboard_audit.call_rows r WHERE id::text = $1"
                ),
                &[id],
            )
            .await
            .unwrap()
            .get::<_, serde_json::Value>(0);
        let recorded: Vec<&str> = added
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(column, _)| column.as_str())
            .collect();
        assert_eq!(added.as_object().unwrap().len(), 11, "{added}");
        assert!(recorded.is_empty(), "{id} records {recorded:?}");
    }
}
