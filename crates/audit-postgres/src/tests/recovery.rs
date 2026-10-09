//! A begin whose confirmation was lost: begin tries again under the same identifier within its
//! budget, and a row that a failed begin may have written is completed as `error` on the
//! finish pool.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway_core::audit::{self, AuditFailure, AuditRowId, Begun};
use gateway_testkit::{
    Caller, Fixture, READ_TOOL, SURFACE_ALL, TEAM_A_DOCUMENT, TEAM_B_DOCUMENT, WRITE_TOOL,
    row_start,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::config::Host;
use tokio_postgres::{Client, Config, NoTls};

use super::budgets::{
    SLACK, cause, count, decide_read, lock_table, release, reporting, reports_of, until, within,
};
use super::store::Call;
use super::{DUMMY_PASSWORD, GATEWAY_ROLE, TestDatabase};
use crate::{Budgets, FinishCounts, PgAuditError, PgAuditStore, PoolSizes};

/// What [`Cutter`] does with what the server sends.
const PASS: u8 = 0;
const CUT_ONCE: u8 = 1;
const CUT_EVERY: u8 = 2;

/// A proxy in front of the test server. It passes everything through until it is told to cut.
/// Then it throws away the next bytes the server sends, on whichever connection, and closes
/// that connection, so the client never reads them: once, or on every connection until it is
/// told to pass again. The server has done the work it answers by then: it answers an insert
/// after committing it.
struct Cutter {
    port: u16,
    mode: Arc<AtomicU8>,
    cuts: Arc<AtomicUsize>,
}

impl Cutter {
    async fn start(db: &TestDatabase) -> Self {
        let Some(Host::Tcp(host)) = db.server.get_hosts().first().cloned() else {
            panic!("the test server is not reached over TCP");
        };
        let upstream = (host, db.server.get_ports().first().copied().unwrap_or(5432));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = Arc::new(AtomicU8::new(PASS));
        let cuts = Arc::new(AtomicUsize::new(0));
        let (kept_mode, kept_cuts) = (Arc::clone(&mode), Arc::clone(&cuts));
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(upstream.clone()).await else {
                    continue;
                };
                tokio::spawn(relay(
                    client,
                    server,
                    Arc::clone(&kept_mode),
                    Arc::clone(&kept_cuts),
                ));
            }
        });
        Self { port, mode, cuts }
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn mode(&self) -> u8 {
        self.mode.load(Ordering::SeqCst)
    }

    fn cuts(&self) -> usize {
        self.cuts.load(Ordering::SeqCst)
    }

    /// A store connected as the gateway's role through this proxy, with one connection in
    /// each pool, so a test knows which connection a begin uses.
    fn store(&self, db: &TestDatabase, budgets: Budgets) -> PgAuditStore {
        let mut config = Config::new();
        config
            .host("127.0.0.1")
            .port(self.port)
            .user(GATEWAY_ROLE)
            .password(DUMMY_PASSWORD)
            .dbname(db.name());
        PgAuditStore::connect(
            config,
            NoTls,
            PoolSizes {
                begin: 1,
                finish: 1,
            },
        )
        .unwrap()
        .with_budgets(budgets)
    }
}

/// Copies one connection both ways, until the server's bytes are to be cut.
async fn relay(client: TcpStream, server: TcpStream, mode: Arc<AtomicU8>, cuts: Arc<AtomicUsize>) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let upstream = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
    });
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = match server_read.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        let cut = match mode.load(Ordering::SeqCst) {
            PASS => false,
            CUT_ONCE => mode
                .compare_exchange(CUT_ONCE, PASS, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            _ => true,
        };
        if cut {
            cuts.fetch_add(1, Ordering::SeqCst);
            break;
        }
        if client_write.write_all(&buffer[..read]).await.is_err() {
            break;
        }
    }
    // Both halves of both sockets are dropped, so the client and the server see the
    // connection close.
    upstream.abort();
}

fn allowed() -> Call {
    Call::new(Caller::TeamA, SURFACE_ALL, READ_TOOL, TEAM_A_DOCUMENT)
}

fn denied() -> Call {
    Call::new(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, TEAM_B_DOCUMENT)
}

/// Begins `call` through the core under `row`.
async fn begin_as(
    store: &PgAuditStore,
    fixture: &Fixture,
    row: &AuditRowId,
    call: Call,
) -> Result<Begun, AuditFailure> {
    let decision = decide_read(fixture, &call);
    let mut start = row_start();
    start.row = row.clone();
    audit::begin(store, start, decision, call.arguments, call.metadata).await
}

/// Begins `call` under a new row, and checks that begin wrote it. The begin connection is
/// then open, and has prepared the insert, so a later begin on it sends only the insert,
/// whose answer comes after its commit.
async fn warm_up(store: &PgAuditStore, fixture: &Fixture, call: Call) {
    let _ = begin_as(store, fixture, &row_start().row, call)
        .await
        .unwrap();
}

/// How many rows the table holds under `row`.
async fn rows_under(admin: &Client, row: &AuditRowId) -> i64 {
    count(
        admin,
        &format!(
            "SELECT count(*) FROM switchboard_audit.call_rows WHERE id = '{}'::uuid",
            row.as_str()
        ),
    )
    .await
}

/// The decision, outcome and latency of `row`, which must be stored.
async fn row_of(admin: &Client, row: &AuditRowId) -> (String, Option<String>, Option<i64>) {
    let stored = admin
        .query_one(
            "SELECT decision, outcome, latency_ms FROM switchboard_audit.call_rows
             WHERE id = ($1::text)::uuid",
            &[&row.as_str()],
        )
        .await
        .unwrap();
    (stored.get(0), stored.get(1), stored.get(2))
}

/// A begin whose failure leaves it unknown whether the insert committed.
fn unanswered(failure: &AuditFailure) -> bool {
    let error = cause(failure);
    error.is_transient() || matches!(error, PgAuditError::BeginBudget { .. })
}

/// The first attempt's insert commits and its answer is lost with its connection. The retry,
/// on a new connection, finds the row under the same identifier, and begin succeeds with one
/// row, not two, and nothing left to complete.
#[tokio::test]
async fn a_begin_retried_after_its_connection_was_killed_writes_one_row() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_secs(5),
        ..Budgets::default()
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;
    warm_up(&store, &fixture, allowed()).await;

    cutter.set(CUT_ONCE);
    let row = row_start().row;
    let begun = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap();
    assert!(matches!(begun, Begun::Allowed(_)));
    // The cut happened: the first attempt lost its answer.
    assert_eq!((cutter.mode(), cutter.cuts()), (PASS, 1));
    assert_eq!(rows_under(&admin, &row).await, 1);
    assert_eq!(
        count(&admin, "SELECT count(*) FROM switchboard_audit.call_rows").await,
        2
    );
    assert_eq!(row_of(&admin, &row).await, ("allow".to_owned(), None, None));
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}

/// Begin starts a lost confirmation's completion, which is counted in flight, and keeps
/// failing while every answer is lost. Returns the row.
async fn begin_losing_every_answer(
    store: &PgAuditStore,
    fixture: &Fixture,
    cutter: &Cutter,
) -> AuditRowId {
    warm_up(store, fixture, allowed()).await;
    cutter.set(CUT_EVERY);
    let row = row_start().row;
    let failure = within(
        store.budgets().begin + SLACK,
        begin_as(store, fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    assert!(unanswered(&failure), "{failure}");
    row
}

/// The first attempt's insert commits and its answer is lost, and so is every answer after,
/// until the begin budget runs out. Begin fails, so the call is refused and nothing runs. Once
/// the database answers again, the store completes the row it wrote as `error`.
#[tokio::test]
async fn a_begin_whose_confirmation_is_lost_on_every_attempt_leaves_its_row_completed_as_error() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_secs(1),
        ..Budgets::default()
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;

    let row = begin_losing_every_answer(&store, &fixture, &cutter).await;
    // The first attempt wrote the row, open.
    assert_eq!(row_of(&admin, &row).await, ("allow".to_owned(), None, None));
    cutter.set(PASS);
    until(budgets.finish_deadline, "the row's completion", || async {
        store.finishes().in_flight == 0
    })
    .await;
    assert_eq!(
        row_of(&admin, &row).await,
        ("allow".to_owned(), Some("error".to_owned()), Some(0))
    );
    assert_eq!(rows_under(&admin, &row).await, 1);
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}

/// A denial is a complete record: when its confirmation is lost, the store starts nothing to
/// complete it, and the row stays a denial with no outcome.
#[tokio::test]
async fn a_lost_confirmation_for_a_denial_leaves_the_denial_as_it_is() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_secs(1),
        ..Budgets::default()
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;
    warm_up(&store, &fixture, denied()).await;

    cutter.set(CUT_EVERY);
    let row = row_start().row;
    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, denied()),
    )
    .await
    .unwrap_err();
    assert!(unanswered(&failure), "{failure}");
    assert!(cutter.cuts() >= 1);
    // Nothing was started for the row: there is nothing in flight to wait for.
    assert_eq!(store.finishes(), FinishCounts::default());
    cutter.set(PASS);
    assert_eq!(row_of(&admin, &row).await, ("deny".to_owned(), None, None));
    assert!(reports_of(&reports).is_empty());
}

/// Waits until no insert of the gateway's role is running in `db`: the store's cancel of the
/// begin that ran out of time has arrived.
async fn until_no_insert_runs(db: &TestDatabase, admin: &Client) {
    until(
        Duration::from_secs(5),
        "the insert's cancellation",
        || async {
            count(
                admin,
                &format!(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
                         AND query LIKE '%INSERT INTO switchboard_audit.call_rows%'",
                    db.name()
                ),
            )
            .await
                == 0
        },
    )
    .await;
}

/// A begin on a new connection prepares its insert first, and the prepare waits on the lock
/// too. When the begin budget runs out there, no insert was executed, so none can commit, and
/// the store starts nothing to complete the row.
#[tokio::test]
async fn a_begin_whose_insert_was_never_executed_starts_no_completion() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        ..Budgets::default()
    };
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
    let admin = db.admin().await;
    let lock = lock_table(&db).await;

    let row = row_start().row;
    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    assert_eq!(store.finishes(), FinishCounts::default());
    until_no_insert_runs(&db, &admin).await;
    release(&lock).await;
    assert_eq!(rows_under(&admin, &row).await, 0);
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}

/// An insert executed and still waiting on a lock when the begin budget runs out is
/// cancelled, so it never commits. The store cannot know that, so it starts a completion,
/// which finds no row. That is counted as never written, not given up, and nothing is
/// reported. The completion starts no attempt that its deadline could cut short, so it stops
/// one answer budget before the deadline, with its last attempt's answer.
#[tokio::test]
async fn a_begin_that_never_committed_leaves_nothing_and_reports_nothing() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    // The completion's first attempt waits on the lock until it is released, well within the
    // answer budget, so it keeps its connection, and every later attempt is quick.
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_secs(2),
        finish_deadline: Duration::from_secs(5),
    };
    // One begin connection, which the warm-up leaves with the insert prepared, so the begin
    // under test executes its insert, which then waits on the lock.
    let sizes = PoolSizes {
        begin: 1,
        ..PoolSizes::default()
    };
    let (store, reports) = reporting(db.store(sizes).with_budgets(budgets));
    let admin = db.admin().await;
    warm_up(&store, &fixture, allowed()).await;
    let lock = lock_table(&db).await;

    let row = row_start().row;
    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    let failed_at = Instant::now();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    assert_eq!(store.finishes().in_flight, 1);
    until_no_insert_runs(&db, &admin).await;
    release(&lock).await;

    // It stops by the deadline less one answer budget, not at the deadline: a second
    // between the two either way.
    let stops_by = failed_at + budgets.finish_deadline - budgets.answer + Duration::from_secs(1);
    until(
        stops_by.saturating_duration_since(Instant::now()),
        "the completion to stop before its last answer budget",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 0,
            never_written: 1
        },
        "{:?}",
        reports_of(&reports)
    );
    assert!(reports_of(&reports).is_empty());
    assert_eq!(rows_under(&admin, &row).await, 0);
}

/// The completion of a lost begin's row is counted in flight for as long as it keeps trying, so
/// a gateway shutting down, which waits for nothing in flight, waits for it.
#[tokio::test]
async fn shutdown_waits_for_a_lost_begins_completion() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_secs(1),
        ..Budgets::default()
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;

    let row = begin_losing_every_answer(&store, &fixture, &cutter).await;
    // The completion's own attempts lose their answers too, and it is in flight all along.
    let cut_by_begin = cutter.cuts();
    until(
        Duration::from_secs(10),
        "three failed attempts to complete the row",
        || async {
            assert_eq!(store.finishes().in_flight, 1);
            cutter.cuts() >= cut_by_begin + 3
        },
    )
    .await;
    assert_eq!(store.finishes().in_flight, 1);
    assert_eq!(row_of(&admin, &row).await, ("allow".to_owned(), None, None));

    cutter.set(PASS);
    until(budgets.finish_deadline, "the row's completion", || async {
        store.finishes().in_flight == 0
    })
    .await;
    assert_eq!(
        row_of(&admin, &row).await,
        ("allow".to_owned(), Some("error".to_owned()), Some(0))
    );
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}
