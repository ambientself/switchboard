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
//! - It inserts the identifier the gateway chose and the first half of a row, with the
//!   instance that began it, its kind and its allowance, but not the two times or the
//!   deadline, which the database sets.
//! - It updates only the completion columns: outcome, its sentence, and latency.
//! - It selects only the identifier, the decision, the completion, the kind and the deadline.
//!   It cannot read who called what, and it cannot delete.
//!
//! Those are the migration's grants on the table. Other objects can give a role more: a grant
//! on a view over the table, a rule, a `SECURITY DEFINER` function, or a function that reaches
//! the server's files. [`PgAuditStore::check_at_boot`] refuses the ones it knows of, and its
//! documentation lists those it does not look for.
//!
//! And for every role, through two triggers: both times and the deadline come from the
//! database's clock, whatever an insert or a completion carries; a row is completed at most
//! once, a denial is never completed, and a completion writes nothing else. A call's deadline
//! is its time at begin plus the allowance the store gives it: the begin budget, the call's
//! deadline and the finish deadline ([`Budgets`]). A call row cannot be stored without one.
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
pub use store::{Budgets, FinishCounts, GivenUp, PgAuditError, PgAuditStore, PoolSizes};
