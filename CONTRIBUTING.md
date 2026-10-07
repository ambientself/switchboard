# Developing

The Rust workspace lives at the repository root. `rust-toolchain.toml` pins the exact
toolchain, and rustup installs it on first use. These are the checks CI runs on every pull
request, and each must pass before merging:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

The compile-fail tests in `crates/gateway-core/tests/compile-fail` compare compiler output
with checked-in `.stderr` files, which is why the toolchain is pinned to an exact version.
Bumping the pin is a deliberate change that regenerates those files in the same pull request,
with `TRYBUILD=overwrite cargo test -p gateway-core --test compile_fail`, after checking that
each error is still the intended one.

## The mutation check

```sh
python3 scripts/mutation_check.py
```

It breaks each guard in the gateway crates (the core, the identity verifier and the test fakes), one at a time, in a temporary copy of the workspace, and
requires the test suite to fail. It needs Python 3.12 or later and nothing else (if your
`python3` is older, `uv run --python 3.13 scripts/mutation_check.py`), never touches
the working tree, and prints one line per mutation. It takes a long while (a full test run per
mutation), so CI does not run it; run it after changing a guard or the tests that watch one,
and add a mutation for every guard you add.

## Tests against Postgres

The audit store's tests in `crates/audit-postgres` that need a database run only when
`SWITCHBOARD_TEST_DATABASE_URL` is set; otherwise they pass without doing anything. Point it
at a superuser on a throwaway server only. The tests create and drop a database each, create
the two audit roles if they are missing, and give those roles a dummy password. Some also make
roles of their own, named after their database, and drop them at the end, and some refuse
connections to their own database for a moment.

```sh
docker run -d --rm --name sb-pg -p 127.0.0.1:25432:5432 -e POSTGRES_PASSWORD=dev postgres:17-alpine
export SWITCHBOARD_TEST_DATABASE_URL=postgres://postgres:dev@127.0.0.1:25432/postgres
cargo test -p audit-postgres
```

Add `-- --nocapture` to see the latency test's p50 and p95 for begin and finish. They measure
your machine, not production.

CI runs these tests in the job "Audit store against Postgres", against a `postgres:17` service
container, and fails the job if any of them says it was skipped.

Set it for the mutation check too. Without it, the `pg-` mutations other than `pg-columns-*`
and the few caught by unit tests survive. When running mutation checks side by side, give each
run a server of its own: the tests change the two cluster-wide roles, one test at a time
within a run but not across runs.
