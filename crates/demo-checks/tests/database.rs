//! The demo's database, set up as Compose and kind set it up, passes the audit store's boot
//! checks as the gateway's role. Both run `deploy/demo/migrate.sh`: `deploy/demo/roles.sql` as
//! the superuser, the audit migrations as the owner, then the reader's grants. This test runs
//! the same SQL, from the same files, against a throwaway server.
//!
//! Runs only when `SWITCHBOARD_TEST_DATABASE_URL` names a superuser on a throwaway server, as
//! the audit store's own database tests do; otherwise it says it was skipped and passes. It
//! drops and makes the database `switchboard`, the name the demo uses, and drops it afterwards.
//! It gives the demo's three roles a dummy password.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use audit_postgres::{GATEWAY_ROLE, OWNER_ROLE, PgAuditStore, PoolSizes, SCHEMA, migrate};
use common::read;
use tokio_postgres::{Client, Config, NoTls, SimpleQueryMessage};

const URL_VARIABLE: &str = "SWITCHBOARD_TEST_DATABASE_URL";

/// The database `deploy/demo/roles.sql` creates.
const DATABASE: &str = "switchboard";

/// Given to the demo's roles on the throwaway test server. A dummy value for tests only.
const DUMMY_PASSWORD: &str = "dummy-password-for-tests-only";

async fn connect(config: &Config) -> Client {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

/// Each value of each row `query` returns.
async fn values(client: &Client, query: &str) -> Vec<String> {
    client
        .simple_query(query)
        .await
        .unwrap_or_else(|error| panic!("{query}: {error}"))
        .iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(row),
            _ => None,
        })
        .flat_map(|row| (0..row.len()).filter_map(|column| row.get(column).map(str::to_owned)))
        .collect()
}

/// Runs a psql script as psql would for the parts the demo's scripts use: `:'name'` is
/// replaced by `variables`' value as a literal and `:"name"` as an identifier, `\set` lines are
/// skipped (they only set psql's own options), and a query ended by `\gexec` has each value it
/// returns run as a statement. Every other statement ends with `;` at the end of a line.
async fn run_psql(client: &Client, script: &str, variables: &[(&str, &str)]) {
    let mut script = script.to_owned();
    for (name, value) in variables {
        script = script
            .replace(
                &format!(":'{name}'"),
                &format!("'{}'", value.replace('\'', "''")),
            )
            .replace(
                &format!(":\"{name}\""),
                &format!("\"{}\"", value.replace('"', "\"\"")),
            );
    }
    assert!(
        !script.contains(":'") && !script.contains(":\""),
        "a psql variable was not given:\n{script}"
    );
    let mut statement = String::new();
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("\\set ") {
            continue;
        }
        if trimmed == "\\gexec" {
            for generated in values(client, &statement).await {
                values(client, &generated).await;
            }
            statement.clear();
            continue;
        }
        assert!(
            !trimmed.starts_with('\\'),
            "a psql command this test does not run: {trimmed}"
        );
        if trimmed.starts_with("--") || (trimmed.is_empty() && statement.is_empty()) {
            continue;
        }
        statement.push_str(line);
        statement.push('\n');
        if trimmed.ends_with(';') {
            values(client, &statement).await;
            statement.clear();
        }
    }
    assert!(
        statement.trim().is_empty(),
        "the script ends inside a statement:\n{statement}"
    );
}

/// The SQL `deploy/demo/migrate.sh` runs as the owner after the migrations: its one here-doc.
fn reader_grants() -> String {
    let script = read("deploy/demo/migrate.sh");
    let (_, after) = script
        .split_once("<<'SQL'\n")
        .expect("migrate.sh has no SQL here-doc");
    let (sql, _) = after
        .split_once("\nSQL\n")
        .expect("migrate.sh's here-doc does not end");
    sql.to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_demo_database_passes_the_audit_stores_boot_checks() {
    let Ok(server_url) = std::env::var(URL_VARIABLE) else {
        eprintln!("skipped: {URL_VARIABLE} is not set");
        return;
    };
    let server: Config = server_url.parse().unwrap();
    // migrate.sh runs roles.sql connected to the database `postgres`.
    let mut on_postgres = server.clone();
    on_postgres.dbname("postgres");
    let admin = connect(&on_postgres).await;
    let drop_database = format!("DROP DATABASE IF EXISTS {DATABASE} WITH (FORCE)");
    values(&admin, &drop_database).await;

    let outcome = set_up_and_check(&server, &admin).await;
    values(&admin, &drop_database).await;
    outcome.unwrap();
}

async fn set_up_and_check(server: &Config, admin: &Client) -> Result<(), String> {
    run_psql(
        admin,
        &read("deploy/demo/roles.sql"),
        &[
            ("owner_password", DUMMY_PASSWORD),
            ("gateway_password", DUMMY_PASSWORD),
            ("reader_password", DUMMY_PASSWORD),
        ],
    )
    .await;

    let mut as_owner = server.clone();
    as_owner
        .dbname(DATABASE)
        .user(OWNER_ROLE)
        .password(DUMMY_PASSWORD);
    let mut owner = connect(&as_owner).await;
    migrate(&mut owner)
        .await
        .map_err(|error| error.to_string())?;
    run_psql(&owner, &reader_grants(), &[("schema", SCHEMA)]).await;

    let mut as_gateway = as_owner.clone();
    as_gateway.user(GATEWAY_ROLE);
    let store = PgAuditStore::connect(as_gateway, NoTls, PoolSizes::default())
        .map_err(|error| error.to_string())?;
    store
        .check_at_boot()
        .await
        .map_err(|error| error.to_string())?;

    // The demo's closing query reads every column as the reader.
    let mut as_reader = as_owner.clone();
    as_reader.user("switchboard_reader");
    let reader = connect(&as_reader).await;
    values(&reader, &format!("SELECT count(*) FROM {SCHEMA}.call_rows")).await;
    Ok(())
}
