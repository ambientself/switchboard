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
python3 conformance/run.py --otto-source /path/to/otto
```

To run a focused scenario:

```sh
python3 conformance/run.py --otto-source /path/to/otto \
  --test TestAuditBeginFailureBlocksExecutionAndDenial
```

`python3` must resolve to 3.12 or newer in the directory you run from; the runner says so and
stops if it does not.

The runner exports the exact committed tree into a temporary directory and builds three of
Otto's binaries from it: the gateway, the key custodian the gateway asks for GitHub tokens,
and the session service, which is the only binary that migrates the schema. It starts a
disposable Postgres container, creates Otto's component roles with Otto's own bootstrap
script, applies the schema with the pinned migrator, and runs the tests with the race
detector. Uncommitted changes in the source clone are not included or modified. The runner
does not reset or check out that clone, run its migrations against an existing database, or
use its deployment configuration.

Each test gets its own copy of the migrated database, a fresh RSA key, turn-grant signing
key and team manifest, a loopback issuer, fake GitHub and Jira servers, and its own gateway
and custodian processes. The gateway connects as Otto's narrow `otto_gateway` role; the
suite inspects rows as the owner. Turn grants are minted by the suite from Otto's wire
format, without importing Otto's code. The fake vendor validates App JWT signatures, issues
dummy installation tokens scoped exactly as asked, and observes that an unfinished allowed
audit row exists before downstream work.
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
| Boot | Missing, partial and contradictory gates for identity, turn grants and audit; malformed manifest; a database login wider than the gateway's role; partial connector configuration; the retired App-key variable; explicit local opt-outs. |
| Protocol | Fixed negotiated revision, request IDs, initialization, ping, tool listing, notifications, malformed requests and unsupported methods; no client session ID. |
| Identity | Signed local tokens; expiry, not-before, audience, issuer, subject, lifetime, algorithm, key ID and signature failures; opaque 401 with an audit row. |
| Turn grants | Missing grant; sixteen kinds of unverifiable grant, including forged claims under a genuine signature; grant and pod team mismatch; a tool outside the grant; legacy headers accepted only with grant checking off. |
| Attribution | Proved, failed and disabled verification states; nothing from an unverified grant recorded; the caller's tool-use identifier recorded. |
| Tools | Exactly eighteen tools with classifications and required arguments, none destructive; unconfigured connector serves a marked fixture. |
| GitHub | Real custodian and connector code against a fake API; App JWT validation; tokens scoped by repository and permission; results of the five original tools; draft pull requests; scope refusals and argument errors told apart; result bounds and credential redaction. |
| Audit | Allowed, denied and refused records; audit before vendor requests; begin failure; finish failure; the answer waiting for finish; completion after client disconnect. |
| Known gaps in Otto | Repeated comments are not deduplicated. |
| Not covered | The behavior of thirteen newer tools, the three control-plane endpoints, grant key rotation and the custodian's peer check. See [observed behavior](../docs/otto-baseline.md). |

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

## Checking that the tests can fail

```sh
python3 conformance/mutation_check.py --otto-source /path/to/otto
```

This breaks one guard in the pinned gateway at a time, builds it, and requires the test named
for that guard to fail. A guard whose text no longer matches the pinned source is reported as
not caught, so the list has to be kept current when the pin moves. `run.py --gateway-binary`
is the same mechanism for a one-off check.

## Updating the pin

Change the commit/toolchain/image in `baseline.json` deliberately, run the entire suite, and
review each behavior change in `docs/otto-baseline.md`. Never refresh expected responses
merely to make a failing test pass. The schema is applied by the migrator built from the same
source commit as the gateway, so schema and binary stay aligned. Then run
`mutation_check.py`; its guard patterns are tied to the pinned source.
