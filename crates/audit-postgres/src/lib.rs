//! The gateway's audit store on Postgres.
//!
//! - [`ROLES`] creates two roles: [`OWNER_ROLE`], which owns the schema and runs the
//!   migrations, and [`GATEWAY_ROLE`], which the gateway connects as. An administrator runs it.
//! - [`migrate`] creates the schema `switchboard_audit` and applies [`MIGRATIONS`], as the
//!   owner. The table `call_rows` follows the core's [`AuditRecord`](gateway_core::AuditRecord),
//!   with proved and claimed values in separate columns.
//! - [`PgAuditStore`] is the core's [`AuditStore`](gateway_core::AuditStore) on that table.
//!   Begin and finish each keep a time budget ([`Budgets`]). Finish keeps trying, on a task of
//!   its own, after its answer budget has passed, until a deadline.
//! - [`PgAuditStore::check_at_boot`] refuses to start, naming every reason, unless the table
//!   is as the store expects and the role it connects as can do no more than the store needs.
//!
//! What the database itself enforces, for the gateway's role:
//!
//! - It inserts the first half of a row, but not the identifier or the two times, which the
//!   database sets.
//! - It updates only the completion columns: outcome, its sentence, and latency.
//! - It selects only the identifier, the decision and the completion. It cannot read who
//!   called what, and it cannot delete.
//!
//! And for every role, through two triggers: both times come from the database's clock,
//! whatever an insert or a completion carries; a row is completed at most once, a denial is
//! never completed, and a completion writes nothing else.
//!
//! # Tests against a database
//!
//! The tests that need Postgres run only when `SWITCHBOARD_TEST_DATABASE_URL` is set, to the
//! URL of a superuser on a throwaway server; otherwise they pass without doing anything. They
//! create a database per test and drop it afterwards, create the two roles if they are
//! missing, and give the roles a dummy password. For example:
//!
//! ```text
//! docker run -d --rm --name sb-pg -p 127.0.0.1:25432:5432 -e POSTGRES_PASSWORD=dev postgres:17-alpine
//! SWITCHBOARD_TEST_DATABASE_URL=postgres://postgres:dev@127.0.0.1:25432/postgres cargo test -p audit-postgres
//! ```

#![forbid(unsafe_code)]

mod check;
mod columns;
mod migrate;
mod store;

#[cfg(test)]
mod tests;

pub use check::{BootCheckError, Problem};
pub use migrate::{
    GATEWAY_ROLE, MIGRATIONS, MigrateError, Migration, OWNER_ROLE, ROLES, SCHEMA, migrate,
};
pub use store::{Budgets, FinishCounts, PgAuditError, PgAuditStore, PoolSizes};
