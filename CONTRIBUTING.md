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

## Running the gateway on fixtures

`switchboard-dev` runs the gateway on the test fakes in `crates/gateway-testkit`: two
in-process token issuers, the fixture policy, a fixture connector serving a few documents and an
in-memory audit store. Nothing else is needed: no database, no Docker, no network beyond
loopback.

```sh
cargo run -p gateway-dev --bin switchboard-dev -- --once
```

This starts the gateway on `127.0.0.1:8471`, writes a token for team A, team B and the user to
`target/switchboard-dev/tokens.json`, and runs a scripted client against it as team A, once in
each MCP revision (`2025-06-18` and `2026-07-28`), then once with no token. Each request,
each answer and each audit row is printed as it happens. Team A reads `team-a-notes` and is
denied `team-b-notes` with a sentence naming it. `--once` exits afterwards, with status 0 only
if every answer was as expected.

Without `--once` it keeps serving until interrupted, and rewrites the tokens file every half
hour. Each token lasts an hour. `--port 0` picks a free port, and `--tokens PATH` writes the
tokens elsewhere. Logs go to standard error at `warn`; set `RUST_LOG=info` for more.

While it serves, run the scripted client from another terminal as any caller:

```sh
cargo run -p gateway-dev --bin switchboard-client -- --caller team-b --era modern
```

`--caller` is `team-a`, `team-b` or `user`, and `--era` is `legacy`, `modern` or `both` (the
default). It reads the token and the URL from the tokens file, and never prints the token. If
`switchboard-dev` was given `--tokens`, pass the same path here.

To point an MCP client such as Claude Code at it, use one surface's URL and a token from the
file:

```sh
claude mcp add --transport http switchboard-a http://127.0.0.1:8471/mcp/fixture-read \
  --header "Authorization: Bearer $(jq -r .team_a target/switchboard-dev/tokens.json)"
```

The header is read once, when the server is added, so it stops working when that token
expires an hour later. Add it again with a fresh token.

The endpoints are `/mcp/fixture-read` and `/mcp/fixture-all`. Requests must come to
`127.0.0.1` or `localhost`, and a request carrying an `Origin` header is refused, so
browser-based clients such as the MCP Inspector get 403 by design.

The end-to-end tests in `crates/gateway-dev/tests` start the same gateway inside the test
process. Run one file of them with `cargo test -p gateway-dev --test <name>`, for example
`--test calls` or `--test rmcp`.

## The mutation check

```sh
python3 scripts/mutation_check.py
```

It breaks each guard in the workspace's crates, one at a time, in a temporary copy of the
workspace, and requires the test suite to fail. It needs Python 3.12 or later and nothing else (if your
`python3` is older, `uv run --python 3.13 scripts/mutation_check.py`), never touches
the working tree, and prints one line per mutation. It takes a long while (a full test run per
mutation), so CI does not run it; run it after changing a guard or the tests that watch one,
and add a mutation for every guard you add.

## Tests against Postgres

The audit store's tests in `crates/audit-postgres` that need a database, and the gateway's
`tests/postgres.rs`, run only when `SWITCHBOARD_TEST_DATABASE_URL` is set; otherwise they pass
without doing anything. Point it
at a superuser on a throwaway server only. The tests create and drop a database each, create
the two audit roles if they are missing, and give those roles a dummy password. Some also make
roles of their own, named after their database, and drop them at the end, and some refuse
connections to their own database for a moment.

```sh
docker run -d --rm --name sb-pg -p 127.0.0.1:25432:5432 -e POSTGRES_PASSWORD=dev postgres:17-alpine
export SWITCHBOARD_TEST_DATABASE_URL=postgres://postgres:dev@127.0.0.1:25432/postgres
cargo test -p audit-postgres
cargo test -p gateway --test postgres
```

Add `-- --nocapture` to see the latency test's p50 and p95 for begin and finish. They measure
your machine, not production.

Set it for the mutation check too. Without it, the `pg-` mutations other than `pg-columns-*`
and the few caught by unit tests survive. CI's `postgres` job sets it and runs both; see
`docs/ci-postgres-job.md`.
