//! A begin whose confirmation was lost: begin tries again under the same identifier within its
//! budget, and a row that a failed begin may have written is completed as `error` on the
//! finish pool.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
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
    SLACK, cause, count, decide_read, lock_table, release, reporting, reports_of,
    set_for_new_sessions, until, within,
};
use super::store::Call;
use super::{DUMMY_PASSWORD, GATEWAY_ROLE, TestDatabase, code};
use crate::{Budgets, FinishCounts, PgAuditError, PgAuditStore, PoolSizes};

/// What [`Cutter`] does with what the server sends.
const PASS: u8 = 0;
const CUT_ONCE: u8 = 1;
const CUT_EVERY: u8 = 2;
const HOLD_EMPTY: u8 = 3;
/// What [`Cutter`] is in once it holds an answer back.
const HOLDING: u8 = 4;

/// The code a request to cancel a statement carries where a startup has its protocol version.
const CANCEL_REQUEST_CODE: u32 = 80_877_102;

/// A proxy in front of the test server. It passes everything through until it is told to cut.
/// Then it throws away the next bytes the server sends, on whichever connection, and closes
/// that connection, so the client never reads them: once, or on every connection until it is
/// told to pass again. The server has done the work it answers by then: it answers an insert
/// after committing it.
///
/// Told to hold, it keeps back the next answer from the server that says a `SELECT` found no
/// rows, on whichever connection, until it is told to pass again, and then sends it on. It
/// passes everything else meanwhile, on that connection and the others.
///
/// Told to, it also throws away every request to cancel a statement, so the statement runs on
/// as if the request had failed.
struct Cutter {
    port: u16,
    mode: Arc<AtomicU8>,
    cuts: Arc<AtomicUsize>,
    drop_cancels: Arc<AtomicBool>,
    dropped_cancels: Arc<AtomicUsize>,
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
        let drop_cancels = Arc::new(AtomicBool::new(false));
        let dropped_cancels = Arc::new(AtomicUsize::new(0));
        let (kept_mode, kept_cuts) = (Arc::clone(&mode), Arc::clone(&cuts));
        let (kept_drop, kept_dropped) = (Arc::clone(&drop_cancels), Arc::clone(&dropped_cancels));
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let upstream = upstream.clone();
                let (mode, cuts) = (Arc::clone(&kept_mode), Arc::clone(&kept_cuts));
                let (drop_cancels, dropped) = (Arc::clone(&kept_drop), Arc::clone(&kept_dropped));
                tokio::spawn(async move {
                    // A startup or a cancel request: its length, then its code.
                    let mut first = [0; 8];
                    if client.read_exact(&mut first).await.is_err() {
                        return;
                    }
                    if first[4..] == CANCEL_REQUEST_CODE.to_be_bytes()
                        && drop_cancels.load(Ordering::SeqCst)
                    {
                        dropped.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                    let Ok(mut server) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    if server.write_all(&first).await.is_err() {
                        return;
                    }
                    relay(client, server, mode, cuts).await;
                });
            }
        });
        Self {
            port,
            mode,
            cuts,
            drop_cancels,
            dropped_cancels,
        }
    }

    /// Throws away every request to cancel a statement from now on.
    fn drop_cancels(&self) {
        self.drop_cancels.store(true, Ordering::SeqCst);
    }

    fn dropped_cancels(&self) -> usize {
        self.dropped_cancels.load(Ordering::SeqCst)
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
            PASS | HOLDING => false,
            CUT_ONCE => mode
                .compare_exchange(CUT_ONCE, PASS, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            HOLD_EMPTY => {
                if finds_no_rows(&buffer[..read])
                    && mode
                        .compare_exchange(HOLD_EMPTY, HOLDING, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    while mode.load(Ordering::SeqCst) == HOLDING {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                false
            }
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

/// Whether `answer`, bytes from the server, holds the end of a `SELECT` that found no rows: its
/// command tag, as a `CommandComplete` message carries it.
fn finds_no_rows(answer: &[u8]) -> bool {
    let tag = b"SELECT 0\0";
    answer.windows(tag.len()).any(|window| window == tag)
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
/// reported. The completion keeps trying until its deadline, and its last attempt, made at the
/// deadline, is not cut short by it, so it ends with that attempt's answer.
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

    // It stops at the deadline, after its last attempt there, which is quick.
    until(
        budgets.finish_deadline + SLACK,
        "the completion to stop at its deadline",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    let stopped = failed_at.elapsed();
    assert!(
        stopped >= budgets.finish_deadline - Duration::from_millis(100),
        "stopped {stopped:?} after the begin failed"
    );
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

/// Makes an insert into `call_rows` fail with SQLSTATE `code` whenever `condition`, SQL over
/// the row being inserted, `NEW`, holds. A trigger that fires before the table's own does it,
/// so an insert of a row already stored is refused too, before its conflict is found.
async fn refuse_inserts_when(db: &TestDatabase, condition: &str, code: &str) {
    db.admin()
        .await
        .batch_execute(&format!(
            "CREATE FUNCTION public.refuse_an_insert() RETURNS trigger
                 LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
             AS $$
             BEGIN
                 IF {condition} THEN
                     RAISE EXCEPTION 'the test refuses this insert' USING ERRCODE = '{code}';
                 END IF;
                 RETURN NEW;
             END
             $$;
             CREATE TRIGGER a_refuse_an_insert
                 BEFORE INSERT ON switchboard_audit.call_rows
                 FOR EACH ROW EXECUTE FUNCTION public.refuse_an_insert();"
        ))
        .await
        .unwrap();
}

/// SQLSTATE `P0001`, what `RAISE EXCEPTION` gives by default: not a failure trying again
/// could fix.
const RAISE_EXCEPTION: &str = "P0001";

/// The first attempt's insert commits and its answer is lost. The retry finds the row stored,
/// and its insert is refused before it gets there, with an error trying again cannot fix, so
/// begin fails with that error at once. The first attempt may have written the row, and did:
/// a later attempt's error does not undo that, and the store completes the row as `error`.
#[tokio::test]
async fn a_lost_confirmation_is_completed_whatever_a_later_attempt_finds() {
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
    refuse_inserts_when(
        &db,
        "EXISTS (SELECT FROM switchboard_audit.call_rows WHERE id = NEW.id)",
        RAISE_EXCEPTION,
    )
    .await;

    cutter.set(CUT_ONCE);
    let row = row_start().row;
    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    match cause(&failure) {
        PgAuditError::Database(error) => assert_eq!(code(error), Some(RAISE_EXCEPTION)),
        other => panic!("{other}"),
    }
    assert!(!cause(&failure).is_transient());
    // The first attempt lost its answer, after its insert committed.
    assert_eq!((cutter.mode(), cutter.cuts()), (PASS, 1));
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

/// The key of the advisory lock that [`hold_inserts`] takes.
const INSERT_LOCK: i64 = 4_201_009;

/// Makes every insert into `call_rows` wait, before it writes anything, until
/// [`let_inserts_through`]: a trigger that fires before the table's own waits for an advisory
/// lock, which the session returned holds. An update does not wait, so an attempt to complete
/// a row that is not there yet finds it missing at once.
async fn hold_inserts(db: &TestDatabase) -> Client {
    let lock = db.admin().await;
    lock.batch_execute(&format!(
        "CREATE FUNCTION public.wait_for_the_test() RETURNS trigger
             LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
         AS $$
         BEGIN
             PERFORM pg_advisory_xact_lock({INSERT_LOCK});
             RETURN NEW;
         END
         $$;
         CREATE TRIGGER a_wait_for_the_test
             BEFORE INSERT ON switchboard_audit.call_rows
             FOR EACH ROW EXECUTE FUNCTION public.wait_for_the_test();
         SELECT pg_advisory_lock({INSERT_LOCK});"
    ))
    .await
    .unwrap();
    lock
}

async fn let_inserts_through(lock: &Client) {
    lock.batch_execute(&format!("SELECT pg_advisory_unlock({INSERT_LOCK})"))
        .await
        .unwrap();
}

/// An executed insert waits past the begin budget, and the store's request to cancel it is
/// lost, so it runs on. It commits after the answer budget and before the finish deadline,
/// while every attempt to complete the row until then has found it missing at once. The
/// completion is still trying at the deadline, and completes the row as `error`.
#[tokio::test]
async fn an_insert_whose_cancel_failed_and_that_commits_late_is_completed_as_error() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_secs(2),
        finish_deadline: Duration::from_millis(4500),
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;
    // The begin connection has its insert prepared, so the begin under test executes it, and
    // the finish connection is open, so the completion's first attempt is quick too.
    warm_up(&store, &fixture, allowed()).await;
    drop(store.finish.get().await.unwrap());
    let lock = hold_inserts(&db).await;
    cutter.drop_cancels();

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
    // The store asked to cancel the insert, the request was lost, and the insert still waits.
    until(SLACK, "the request to cancel the insert", || async {
        cutter.dropped_cancels() >= 1
    })
    .await;
    assert_eq!(
        count(
            &admin,
            &format!(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE usename = '{GATEWAY_ROLE}' AND datname = '{}' AND state = 'active'
                     AND query LIKE '%INSERT INTO switchboard_audit.call_rows%'",
                db.name()
            ),
        )
        .await,
        1
    );

    // The insert commits 4 s after the begin failed: past the answer budget; past 2.5 s, where
    // a completion that stopped one answer budget before its deadline would have stopped; and
    // past the completion's last attempt before its deadline, about 3.55 s in, whose next
    // pause reaches the deadline at 4.5 s. Only an attempt at the deadline finds the row.
    let commit_at = failed_at + Duration::from_secs(4);
    tokio::time::sleep(commit_at.saturating_duration_since(Instant::now())).await;
    assert_eq!(store.finishes().in_flight, 1);
    assert_eq!(rows_under(&admin, &row).await, 0);
    let_inserts_through(&lock).await;
    until(
        budgets.finish_deadline + budgets.answer + SLACK,
        "the row's completion",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert_eq!(
        row_of(&admin, &row).await,
        ("allow".to_owned(), Some("error".to_owned()), Some(0)),
        "{:?} {:?}",
        store.finishes(),
        reports_of(&reports)
    );
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}

/// An executed insert waits past the begin budget, and the store's request to cancel it is
/// lost. Less than one answer budget before the finish deadline, an attempt to complete the
/// row finds it missing, and the answer saying so is held back until after the deadline. The
/// insert commits in between. That answer is stale, and does not end the completion: the
/// attempt is cut short at the deadline, and the attempt at the deadline completes the row as
/// `error`.
#[tokio::test]
async fn a_missing_row_answer_held_past_the_deadline_leaves_the_attempt_at_the_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let cutter = Cutter::start(&db).await;
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_secs(2),
        finish_deadline: Duration::from_millis(4500),
    };
    let (store, reports) = reporting(cutter.store(&db, budgets));
    let admin = db.admin().await;
    warm_up(&store, &fixture, allowed()).await;
    drop(store.finish.get().await.unwrap());
    let lock = hold_inserts(&db).await;
    cutter.drop_cancels();

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

    // The completion's attempts come about 2.55 s and 3.55 s in. From 3 s, less than one answer
    // budget before the deadline, the next answer that the row is missing is held back.
    tokio::time::sleep(
        (failed_at + Duration::from_secs(3)).saturating_duration_since(Instant::now()),
    )
    .await;
    assert_eq!(rows_under(&admin, &row).await, 0);
    cutter.set(HOLD_EMPTY);
    until(
        Duration::from_millis(1400),
        "an attempt to find the row missing",
        || async { cutter.mode() == HOLDING },
    )
    .await;
    // That attempt has looked. The insert commits before the deadline.
    let_inserts_through(&lock).await;
    until(SLACK, "the insert to commit", || async {
        rows_under(&admin, &row).await == 1
    })
    .await;
    let committed_by = failed_at.elapsed();
    assert!(
        committed_by < budgets.finish_deadline,
        "the insert committed {committed_by:?} after the begin failed"
    );
    // The held answer goes on after the deadline, within the answer budget of the attempt.
    let answer_at = failed_at + budgets.finish_deadline + Duration::from_millis(200);
    tokio::time::sleep(answer_at.saturating_duration_since(Instant::now())).await;
    cutter.set(PASS);
    until(budgets.answer + SLACK, "the row's completion", || async {
        store.finishes().in_flight == 0
    })
    .await;
    assert_eq!(
        row_of(&admin, &row).await,
        ("allow".to_owned(), Some("error".to_owned()), Some(0)),
        "{:?} {:?}",
        store.finishes(),
        reports_of(&reports)
    );
    assert_eq!(store.finishes(), FinishCounts::default());
    assert!(reports_of(&reports).is_empty());
}

/// Begins an allowed call that executes its insert while `call_rows` is locked, so the insert
/// waits past the begin budget and is cancelled, and the store starts a completion of the row,
/// whose attempts wait on the lock too. Returns the lock, still held, and when the begin failed.
async fn begin_waiting_on_a_lock(
    db: &TestDatabase,
    admin: &Client,
    store: &PgAuditStore,
    fixture: &Fixture,
    row: &AuditRowId,
) -> (Client, Instant) {
    warm_up(store, fixture, allowed()).await;
    let lock = lock_table(db).await;
    let failure = within(
        store.budgets().begin + SLACK,
        begin_as(store, fixture, row, allowed()),
    )
    .await
    .unwrap_err();
    let failed_at = Instant::now();
    assert!(
        matches!(cause(&failure), PgAuditError::BeginBudget { .. }),
        "{failure}"
    );
    assert_eq!(store.finishes().in_flight, 1);
    until_no_insert_runs(db, admin).await;
    (lock, failed_at)
}

/// Every attempt to complete a failed begin's row waits on a lock held past the finish
/// deadline. The attempt at the deadline is still waiting when the deadline passes, and finds
/// the row missing once the lock is released, half an answer budget later. A gateway shutting
/// down waits [`Budgets::shutdown_wait`] for nothing to be in flight, and is still waiting
/// then.
#[tokio::test]
async fn shutdown_waits_for_the_attempt_at_the_finish_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_secs(2),
        finish_deadline: Duration::from_secs(3),
    };
    // One begin connection, which the warm-up leaves with the insert prepared, so the begin
    // under test executes its insert, which then waits on the lock.
    let sizes = PoolSizes {
        begin: 1,
        ..PoolSizes::default()
    };
    let (store, reports) = reporting(db.store(sizes).with_budgets(budgets));
    let admin = db.admin().await;
    let row = row_start().row;
    let (lock, failed_at) = begin_waiting_on_a_lock(&db, &admin, &store, &fixture, &row).await;
    let shutdown_stops_waiting = failed_at + budgets.shutdown_wait();

    let released_at = failed_at + budgets.finish_deadline + budgets.answer / 2;
    tokio::time::sleep(released_at.saturating_duration_since(Instant::now())).await;
    assert_eq!(store.finishes().in_flight, 1);
    assert!(
        Instant::now() < shutdown_stops_waiting,
        "a gateway shutting down has stopped waiting for the row's completion"
    );
    release(&lock).await;
    until(
        shutdown_stops_waiting.saturating_duration_since(Instant::now()),
        "the completion to end before shutdown stops waiting",
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

/// Every attempt to complete a failed begin's row waits on a lock held until the test ends, and
/// is cut short. The attempts before the deadline are cut short by it, however close to it they
/// start, and the one at the deadline runs its full answer budget: the completion gives up one
/// answer budget after the deadline, within [`Budgets::shutdown_wait`].
#[tokio::test]
async fn a_completion_that_gets_no_answer_gives_up_one_answer_budget_after_its_deadline() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    // The first attempt is cut short 3 s in, and the second starts 50 ms later. Were it not cut
    // short at the deadline, 3.5 s in, it would run to 6.05 s, and the attempt after it to 9.05 s.
    let budgets = Budgets {
        begin: Duration::from_millis(300),
        answer: Duration::from_secs(3),
        finish_deadline: Duration::from_millis(3500),
    };
    let sizes = PoolSizes {
        begin: 1,
        ..PoolSizes::default()
    };
    let (store, reports) = reporting(db.store(sizes).with_budgets(budgets));
    let admin = db.admin().await;
    let row = row_start().row;
    let (lock, failed_at) = begin_waiting_on_a_lock(&db, &admin, &store, &fixture, &row).await;

    until(
        budgets.shutdown_wait() + Duration::from_secs(1),
        "the completion to give up",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    let stopped = failed_at.elapsed();
    assert!(
        stopped >= budgets.shutdown_wait() - Duration::from_millis(200),
        "gave up {stopped:?} after the begin failed"
    );
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 1,
            never_written: 0
        }
    );
    assert_eq!(
        reports_of(&reports),
        vec![(row.as_str().to_owned(), "error", "deadline".to_owned())]
    );
    release(&lock).await;
    assert_eq!(rows_under(&admin, &row).await, 0);
}

/// Every insert of the row is refused with SQLSTATE `code`, an explicit refusal that trying
/// again could fix, until the begin budget runs out. The row may exist, as far as the store
/// can tell, so it starts a completion. Here it does not, and the refusals do not touch the
/// completion's updates: it finds no row through its deadline, and ends counted as never
/// written, with nothing reported.
async fn a_begin_refused_with(code: &str) {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_secs(1),
        answer: Duration::from_secs(1),
        finish_deadline: Duration::from_secs(2),
    };
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
    let admin = db.admin().await;
    let row = row_start().row;
    refuse_inserts_when(&db, &format!("NEW.id = '{}'::uuid", row.as_str()), code).await;

    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    let failed_at = Instant::now();
    match cause(&failure) {
        PgAuditError::Database(error) => assert_eq!(super::code(error), Some(code)),
        // On a loaded machine the last retry's new connection can outlast the budget.
        PgAuditError::BeginBudget { .. } => {}
        other => panic!("{code}: {other}"),
    }
    assert_eq!(store.finishes().in_flight, 1, "{code}");
    until(
        budgets.finish_deadline + budgets.answer + SLACK,
        "the completion",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert!(failed_at.elapsed() >= budgets.finish_deadline - Duration::from_millis(100));
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 0,
            never_written: 1
        },
        "{code}: {:?}",
        reports_of(&reports)
    );
    assert!(reports_of(&reports).is_empty(), "{code}");
    assert_eq!(rows_under(&admin, &row).await, 0, "{code}");
}

/// Class 40, a serialization failure.
#[tokio::test]
async fn a_begin_refused_as_a_serialization_failure_starts_a_completion_that_finds_no_row() {
    a_begin_refused_with("40001").await;
}

/// Class 57, a statement cancelled, as by a `statement_timeout` a database or role sets.
#[tokio::test]
async fn a_begin_refused_as_cancelled_starts_a_completion_that_finds_no_row() {
    a_begin_refused_with("57014").await;
}

/// A server that stays read-only past the finish deadline refuses the begin and every attempt
/// to complete the row. The store cannot tell whether an earlier insert committed, so it gives
/// the row up and reports it, with the outcome `error`, though none was written.
#[tokio::test]
async fn a_refusal_that_outlasts_the_finish_deadline_is_reported() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let fixture = Fixture::new().unwrap();
    let budgets = Budgets {
        begin: Duration::from_secs(1),
        answer: Duration::from_secs(1),
        finish_deadline: Duration::from_secs(2),
    };
    let (store, reports) = reporting(db.store(PoolSizes::default()).with_budgets(budgets));
    let admin = db.admin().await;
    let read_only = "default_transaction_read_only";
    set_for_new_sessions(&db.server, db.name(), read_only, Some("on")).await;

    let row = row_start().row;
    let failure = within(
        budgets.begin + SLACK,
        begin_as(&store, &fixture, &row, allowed()),
    )
    .await
    .unwrap_err();
    match cause(&failure) {
        PgAuditError::Database(error) => assert_eq!(code(error), Some("25006")),
        // On a loaded machine the last retry's new connection can outlast the budget.
        PgAuditError::BeginBudget { .. } => {}
        other => panic!("{other}"),
    }
    assert_eq!(store.finishes().in_flight, 1);
    until(
        budgets.finish_deadline + budgets.answer + SLACK,
        "the completion",
        || async { store.finishes().in_flight == 0 },
    )
    .await;
    assert_eq!(
        store.finishes(),
        FinishCounts {
            in_flight: 0,
            given_up: 1,
            never_written: 0
        }
    );
    assert_eq!(
        reports_of(&reports),
        vec![(row.as_str().to_owned(), "error", "deadline".to_owned())]
    );
    set_for_new_sessions(&db.server, db.name(), read_only, None).await;
    assert_eq!(rows_under(&admin, &row).await, 0);
}
