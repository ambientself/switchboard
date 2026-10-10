//! The gateway built from files with its audit rows in Postgres, as the demo runs it: the store
//! passes its boot checks as the gateway's role, an allowed call, a denial and a refusal each
//! leave their row, a `tools/list` leaves a row of kind `list`, a completion the database refuses is logged as given up, naming its row,
//! and a connection as a superuser refuses to start.
//!
//! Runs only when `SWITCHBOARD_TEST_DATABASE_URL` names a superuser on a throwaway server, as
//! the audit store's own database tests do; otherwise it says it was skipped and passes. It
//! makes a database of its own and drops it afterwards, creates the two audit roles if they
//! are missing, and gives them a dummy password.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::Arc;
use std::time::Duration;

use audit_postgres::{GATEWAY_ROLE, OWNER_ROLE, ROLES, migrate};
use files::{
    AUDIENCE, Files, LIST_TOOL, READ_TOOL, TEAM_A_SA, call, cluster_issuer, kubernetes_token, rpc,
};
use gateway::path::RequestPath;
use gateway::start::prepare;
use gateway::undeclared_argument;
use gateway_identity::SystemClock;
use mock_docs_server::{AcceptedCredential, Config};
use serde_json::{Value, json};
use tokio_postgres::{Client, NoTls};

const URL_VARIABLE: &str = "SWITCHBOARD_TEST_DATABASE_URL";

/// Given to both audit roles on the throwaway test server. A dummy value for tests only.
const DUMMY_PASSWORD: &str = "dummy-password-for-tests-only";

/// A log writer the test reads back.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Every event logged with `event` as its `event` field, as JSON.
    fn events(&self, event: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|logged| logged["fields"]["event"] == json!(event))
            .collect()
    }
}

async fn connect(config: &tokio_postgres::Config) -> Client {
    let (client, connection) = config.connect(NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

fn url(config: &tokio_postgres::Config, user: &str, password: &str, database: &str) -> String {
    let host = match &config.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(host) => host.clone(),
        #[cfg(unix)]
        tokio_postgres::config::Host::Unix(path) => path.display().to_string(),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    format!("postgres://{user}:{password}@{host}:{port}/{database}")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateway_writes_its_rows_to_postgres_as_its_own_role_and_no_other() {
    let Ok(server_url) = std::env::var(URL_VARIABLE) else {
        eprintln!("skipped: {URL_VARIABLE} is not set");
        return;
    };
    // The store reports a finish it gives up on that finish's own task, on any of the
    // runtime's threads, so the subscriber is global. This binary has no other test.
    let captured = Captured::default();
    let writer = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();
    let server: tokio_postgres::Config = server_url.parse().unwrap();
    let database = format!("switchboard_gateway_test_{}", std::process::id());
    let admin = connect(&server).await;
    // Two statements, not one batch: a batch runs as one transaction, which DROP DATABASE and
    // CREATE DATABASE refuse.
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut in_database = server.clone();
    in_database.dbname(&database);
    let setup = connect(&in_database).await;
    setup.batch_execute(ROLES).await.unwrap();
    for role in [OWNER_ROLE, GATEWAY_ROLE] {
        setup
            .batch_execute(&format!("ALTER ROLE {role} PASSWORD '{DUMMY_PASSWORD}'"))
            .await
            .unwrap();
    }
    let mut owner = in_database.clone();
    owner.user(OWNER_ROLE).password(DUMMY_PASSWORD);
    migrate(&mut connect(&owner).await).await.unwrap();

    let outcome = run(&server, &database, &setup, &captured).await;
    drop(setup);
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .await
        .unwrap();
    outcome.unwrap();
}

async fn run(
    server: &tokio_postgres::Config,
    database: &str,
    setup: &Client,
    captured: &Captured,
) -> Result<(), String> {
    let mock = mock_docs_server::start(Config::new(AcceptedCredential::token(files::CREDENTIAL)))
        .await
        .unwrap();
    let issuer = cluster_issuer();
    let files = Files::new("postgres", &issuer.jwks_document(), &mock.url());
    files.write(
        "gateway.toml",
        &files::deployment_file("[audit]\nmode = \"postgres\"\nurl_env = \"AUDIT_URL\"\n"),
    );

    // As a superuser the store's boot checks refuse, and the gateway does not start.
    let superuser = server.get_user().unwrap().to_owned();
    let superuser_password = String::from_utf8(server.get_password().unwrap().to_vec()).unwrap();
    let as_superuser = url(server, &superuser, &superuser_password, database);
    let deployment = files.load_with(&[("AUDIT_URL", &as_superuser)]).unwrap();
    let refused = prepare(
        deployment,
        gateway_core::InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .err()
    .ok_or("a superuser was accepted")?;
    let said = refused.to_string();
    if !said.contains("the audit store will not start") || !said.contains("has SUPERUSER") {
        return Err(format!("refused for the wrong reason: {said}"));
    }

    // As the gateway's role it starts.
    let as_gateway = url(server, GATEWAY_ROLE, DUMMY_PASSWORD, database);
    let deployment = files.load_with(&[("AUDIT_URL", &as_gateway)]).unwrap();
    let prepared = prepare(
        deployment,
        gateway_core::InstanceName::new("test-instance"),
        Arc::new(SystemClock),
    )
    .await
    .map_err(|error| error.to_string())?;
    assert!(prepared.store.is_some());
    let path = RequestPath::new(prepared.gates);
    let token = kubernetes_token(&issuer, TEAM_A_SA, &[AUDIENCE]);

    let allowed = call(
        &path,
        &token,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    assert_eq!(
        allowed.body["result"]["isError"],
        json!(false),
        "{}",
        allowed.body
    );
    let denied = call(
        &path,
        &token,
        READ_TOOL,
        json!({"project": "borealis", "document": "plan"}),
    )
    .await;
    assert_eq!(
        denied.body["error"]["code"],
        json!(-32001),
        "{}",
        denied.body
    );
    // An undeclared argument is a tool error, recorded as outcome `error`, with nothing sent.
    let failed = call(
        &path,
        &token,
        LIST_TOOL,
        json!({"project": "atlas", "extra": 1}),
    )
    .await;
    assert_eq!(
        failed.body["result"]["isError"],
        json!(true),
        "{}",
        failed.body
    );
    assert_eq!(
        failed.body["result"]["content"][0]["text"],
        json!(undeclared_argument(LIST_TOOL)),
        "{}",
        failed.body
    );
    assert!(failed.body.get("error").is_none(), "{}", failed.body);

    // Each row is a call begun by this instance, due when the database's time at begin plus
    // the store's 2 s and 30 s and the proxied server's 5 s call deadline have passed.
    let deadlines: Vec<(String, String, i64, f64)> = setup
        .query(
            "SELECT instance, kind, allowance_ms,
                    (extract(epoch FROM deadline - begun_at) * 1000)::float8
               FROM switchboard_audit.call_rows ORDER BY begun_at",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    let due = (
        "test-instance".to_owned(),
        "call".to_owned(),
        37_000,
        37_000.0,
    );
    assert_eq!(deadlines, vec![due.clone(), due.clone(), due]);

    // Each row names the project its call named, as `system/kind/identifier`, so an allowed
    // read shows which project it read and a denial which one it refused.
    let rows = setup
        .query(
            "SELECT tool, decision, coalesce(reason, ''), coalesce(outcome, ''), proved_subject,
                    proved_team, coalesce(sentence, ''), coalesce(outcome_sentence, ''),
                    policy_revision,
                    CASE WHEN jsonb_typeof(resources) = 'array' THEN
                        (SELECT coalesce(string_agg(concat_ws('/', r->>'system', r->>'kind',
                                                              r->>'identifier'), ','), '')
                           FROM jsonb_array_elements(resources) AS r)
                    ELSE coalesce(resources #>> '{}', 'NULL') END,
                    resources_omitted::text
               FROM switchboard_audit.call_rows ORDER BY begun_at",
            &[],
        )
        .await
        .unwrap();
    let rows: Vec<[String; 11]> = rows
        .iter()
        .map(|row| std::array::from_fn(|column| row.get(column)))
        .collect();
    assert_eq!(rows.len(), 3, "{rows:#?}");
    let expected = [
        [READ_TOOL, "allow", "", "ok", "", "", "docs/project/atlas"],
        [
            READ_TOOL,
            "deny",
            "resource_outside_limit",
            "",
            "`borealis`",
            "",
            "docs/project/borealis",
        ],
        [
            LIST_TOOL,
            "allow",
            "",
            "error",
            "",
            "",
            "docs/project/atlas",
        ],
    ];
    for (
        row,
        [
            tool,
            decision,
            reason,
            outcome,
            sentence,
            outcome_sentence,
            resources,
        ],
    ) in rows.iter().zip(expected)
    {
        assert_eq!(
            [&row[0], &row[1], &row[2], &row[3]].map(String::as_str),
            [tool, decision, reason, outcome],
            "{row:?}"
        );
        assert_eq!(row[4], TEAM_A_SA);
        assert_eq!(row[5], "team-a");
        assert!(row[6].contains(sentence), "{row:?}");
        assert!(row[7].contains(outcome_sentence), "{row:?}");
        assert_eq!(row[8], "demo-1");
        assert_eq!([&row[9], &row[10]], [resources, "0"], "{row:?}");
    }

    // A tools/list writes its row, of kind list, naming what it listed, and the answer names
    // that row.
    let listed = rpc(&path, Some(&token), "tools/list", json!({})).await;
    let names: Vec<&str> = listed.body["result"]["tools"]
        .as_array()
        .ok_or_else(|| format!("not a list: {}", listed.body))?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names, [LIST_TOOL, READ_TOOL], "{}", listed.body);
    let list_rows = setup
        .query(
            "SELECT id::text, listed_tools::text, listed_omitted, policy_revision, proved_team,
                    tool IS NULL AND decision IS NULL AND deadline IS NULL
               FROM switchboard_audit.call_rows WHERE kind = 'list'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(list_rows.len(), 1, "one list, one row");
    let list_row = &list_rows[0];
    assert_eq!(
        listed.body["result"]["_meta"][gateway_mcp::AUDIT_ROW_META],
        json!(list_row.get::<_, String>(0)),
        "{}",
        listed.body
    );
    assert_eq!(
        serde_json::from_str::<Value>(list_row.get(1)).unwrap(),
        json!(names)
    );
    assert_eq!(list_row.get::<_, i64>(2), 0);
    assert_eq!(list_row.get::<_, String>(3), "demo-1");
    assert_eq!(list_row.get::<_, String>(4), "team-a");
    assert!(list_row.get::<_, bool>(5), "a list row has no call columns");

    // A completion the database refuses is given up at once, and logged naming its row and
    // the outcome that was not written.
    setup
        .batch_execute(&format!(
            "REVOKE UPDATE (outcome, outcome_sentence, latency_ms) \
               ON switchboard_audit.call_rows FROM {GATEWAY_ROLE}"
        ))
        .await
        .unwrap();
    call(
        &path,
        &token,
        READ_TOOL,
        json!({"project": "atlas", "document": "plan"}),
    )
    .await;
    let open: String = setup
        .query_one(
            "SELECT id::text FROM switchboard_audit.call_rows
              WHERE outcome IS NULL AND decision = 'allow'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let mut waited = Duration::ZERO;
    let logged = loop {
        // The name operators and deploy/README.md know it by.
        let logged = captured.events("audit_row_given_up");
        if !logged.is_empty() || waited >= Duration::from_secs(10) {
            break logged;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    };
    assert_eq!(logged.len(), 1, "{logged:#?}");
    let fields = &logged[0]["fields"];
    assert_eq!(logged[0]["level"], json!("ERROR"), "{logged:#?}");
    assert_eq!(fields["row"], json!(open), "{logged:#?}");
    assert_eq!(fields["outcome"], json!("ok"), "{logged:#?}");
    assert!(
        fields["cause"]
            .as_str()
            .is_some_and(|cause| cause.contains("permission denied")),
        "{logged:#?}"
    );
    Ok(())
}
