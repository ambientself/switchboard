# Otto conformance baseline

This is issue [#1](https://github.com/ambientself/switchboard/issues/1): a black-box suite
against the unmodified Go gateway. It imports no Otto packages. Requests travel over HTTP;
assertions inspect responses, requests received by the fake vendor, and real Postgres rows.

## Run

Requirements: Python 3.12 or newer, Git, Docker with a running daemon, and Go capable of
selecting the pinned toolchain. Go modules and the database image may need downloading on
the first run. A local clone of `https://github.com/ambientself/otto.git` must contain the
commit in [baseline.json](baseline.json). The local directory is historically called
`agentrunner`; it is not the GitHub repository name.

From the Switchboard repository root:

```sh
python3 conformance/run.py --otto-source /path/to/agentrunner
```

To run a focused scenario:

```sh
python3 conformance/run.py --otto-source /path/to/agentrunner \
  --test TestAuditBeginFailureBlocksExecutionAndDenial
```

The runner exports the exact committed tree into a temporary directory, builds
`cmd/otto-gateway`, starts a disposable Postgres container, and runs the tests with the race
detector. Uncommitted changes in the source clone are not included or modified. The runner
does not reset or check out that clone, run its migrations against an existing database, or
use its deployment configuration.

Each test gets an isolated schema loaded from the pinned `0013_gateway_audit.sql`, a fresh
RSA key and team manifest, a loopback issuer and fake GitHub server, and its own gateway
process. The fake vendor validates App JWT signatures, issues only a dummy installation
token, and observes that an unfinished allowed audit row exists before downstream work.
No vendor or cluster credentials are needed. Inherited gateway configuration and proxy
settings are not passed to the gateway.

Postgres is bound only to an ephemeral loopback port with a test-only password and no volume.
The container is removed on normal completion, test failure or keyboard interrupt. If the
runner is forcibly killed, its container has the label `switchboard.conformance=true` for
identification and manual cleanup. Go build cache is the only retained local artifact, under
the ignored `conformance/.cache/` directory; Go's ordinary module cache is also used.

Calling `go test` directly without the runner's binary, schema and database environment
fails with setup instructions instead of silently skipping the suite.

## What the baseline covers

| Area | Executable checks |
| --- | --- |
| Boot | Missing, partial and contradictory gates; malformed manifest; partial connector configuration; explicit local opt-outs. |
| Protocol | Fixed negotiated revision, request IDs, initialization, ping, tool listing, notifications, malformed requests and unsupported methods; no client session ID. |
| Identity | Signed local tokens; expiry, not-before, audience, issuer, subject, lifetime, algorithm, key ID and signature failures; opaque 401 with an audit row. |
| Attribution | Required acting headers; proved/claimed team mismatch; proved, failed and disabled verification states. |
| Tools | Exactly five real tools with classifications and required argument schemas; unconfigured connector serves one marked fixture. |
| GitHub | Real broker code against a fake API; App JWT validation, installation discovery/token reuse, all five tool results, proposal write routes, organization and argument restrictions, result bounds and credential redaction. |
| Audit | Allowed and denied records, audit before vendor requests, begin failure, finish failure and completion after client disconnect. |
| Known gaps | Repeated writes are not deduplicated; fencing-epoch headers are recorded without enforcement. |

The negative scenarios are part of the baseline, not desired Switchboard behavior. See
[observed behavior](../docs/otto-baseline.md) before using these tests as a migration gate.

## Migration mappings and limits

`baseline.json` is the explicit mapping from Otto's `/mcp` and `github_*` tool names to the
proposed Switchboard `github__*` names. Switchboard's endpoint will be `/mcp/{surface}`;
the actual surface is a deployment choice. There is no Rust target adapter yet. Adding it
must translate only the agreed endpoint/name differences, and keep identity, authorization,
credential and audit assertions intact unless a separately recorded decision changes them.

The suite does not prove complete MCP specification compliance, constant-time verification,
key rotation over the one-hour cache interval, every Postgres constraint, or production
network behavior. A destructive or unclassified tool cannot be injected into the shipped Go
binary over HTTP: these tests establish its exposed tool set and unknown-tool refusal, not
its internal constructor's behavior. Otto's own unit tests cover that internal boundary.

New company-wide requirements belong in a separate future suite. They must not be smuggled
into this baseline as failures against behavior the pinned Go gateway never implemented.

## Updating the pin

Change the commit/toolchain/image in `baseline.json` deliberately, run the entire suite, and
review each behavior change in `docs/otto-baseline.md`. Never refresh expected responses
merely to make a failing test pass. The database migration is read from the same source
commit as the gateway so schema and binary stay aligned.
