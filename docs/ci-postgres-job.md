# Draft: a CI job for the audit store against Postgres

Status: a draft for the owner to approve. Nothing here is applied. `.github/workflows/ci.yml` is
unchanged.

## Why

The tests in `crates/audit-postgres` that need a database run only when
`SWITCHBOARD_TEST_DATABASE_URL` is set. CI does not set it, so today CI skips every one of
them. That covers the schema, the grants, the write-once trigger, the time budgets, the boot
checks and the latency measurement. Without this job, a change that breaks any of them passes
CI. Only the column-mapping tests, which need no server, run.

## The job

Add this job to `.github/workflows/ci.yml`, beside the existing `rust` job:

```yaml
  postgres:
    name: Audit store against Postgres
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          # A dummy password for this throwaway service container only. Not a credential.
          POSTGRES_PASSWORD: dummy-ci-password
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U postgres"
          --health-interval 2s
          --health-timeout 5s
          --health-retries 30
    env:
      SWITCHBOARD_TEST_DATABASE_URL: postgres://postgres:dummy-ci-password@localhost:5432/postgres
    steps:
      - uses: actions/checkout@v4
      - name: Install the pinned toolchain
        run: |
          rustup toolchain install
          rustc --version
      - uses: Swatinem/rust-cache@v2
      # A test with no server says "skipped" and passes. Here that would mean the job checked
      # nothing, so the job fails if any test says it.
      - name: Test the audit store against Postgres
        run: |
          set -o pipefail
          cargo test -p audit-postgres --locked -- --nocapture 2>&1 | tee test-output.txt
          if grep -q 'skipped: SWITCHBOARD_TEST_DATABASE_URL is not set' test-output.txt; then
            echo "a Postgres test was skipped, so SWITCHBOARD_TEST_DATABASE_URL did not reach it"
            exit 1
          fi
```

## What it does

- The service is a throwaway `postgres:17` container that lives only for the job. The tests
  connect as its superuser. Each test creates its own database, creates the two audit roles if
  they are missing, makes any roles of its own that it needs, and drops them all at the end.
- `--nocapture` puts the latency test's p50 and p95 for begin and finish in the job log. They
  measure a CI runner, not production.
- The job adds about one build of the workspace and a few seconds of tests.

## What it does not do

- It does not run `scripts/mutation_check.py`. That is one full test run per mutation, and CI
  does not run it for any crate.
- It does not test TLS to Postgres. The tests connect without TLS, as Compose and kind do.
- It does not pin a minor version. `postgres:17` follows the latest 17.x. Pin a digest if the
  job must not change under you.

## To approve

1. Paste the job into `.github/workflows/ci.yml`.
2. Make it a required check on `main`, beside "Format, lint and test", if the audit store's tests
   should block a merge.
