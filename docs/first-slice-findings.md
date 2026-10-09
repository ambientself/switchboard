# First slice: findings

Issue #14, criterion "Findings" (planDemo step 14k). Measured on 2026-10-07 from
`agent/first-slice` at `d7fd716`, with the Compose stack and the kind cluster
`switchboard-demo` that `deploy/demo/demo.sh` starts. Every number below was measured. None is
estimated.

**These are laptop numbers.** They describe one gateway, one Postgres and one mock server on one
laptop. They are not the production cost of the audit write. Decision 0008 says the mock slice
cannot show that, and these numbers do not change it.

## Summary

- **Audit latency.** Begin and finish each take about half a millisecond at p50 and under one
  millisecond at p95, one call at a time. With 8 calls at a time, p95 rises to 2 to 3.3 ms. The
  provisional 2 s budgets of decision 0009 are at least 600 times the highest p95 measured.
- **Database paused.** Every tool call is refused after exactly the 2 s begin budget, with the
  audit-failure sentence. Nothing reaches the server. `tools/list` keeps answering.
- **Database stopped.** Every tool call is refused within 30 ms. The first call after Postgres
  starts again succeeds.
- **Database lost between begin and finish.** The caller gets the call's result after the call
  plus the 2 s answer budget. The row is completed if Postgres comes back within the 30 s
  finish deadline. If it does not, the row stays open. In these runs nothing was logged when the
  store gave up; that was fixed after them, and the gateway now logs each one as
  `audit_row_given_up` at `ERROR` (section 7, gap 1).
- **Time to see a policy change.** Compose: 0.15 s to 2.03 s (30 changes). kind: 33 s to 88 s
  (6 changes), because kubelet takes that long to update a mounted ConfigMap.
- **Run time.** `demo.sh compose` took 21 s and `demo.sh kind` took 44 s, both warm. A cold
  run was not measured.
- **After the review's fixes** (section 8). Both runs pass again from `a509ec9`: Compose
  89/89 and kind 139/139. Nothing needed fixing.
- **With PR #39's stricter boot check** (section 9). Both runs pass from `ef621ef`: Compose
  90/90 and kind 140/140. The boot check accepted the demo's database in both. Nothing needed
  fixing.
- **After the review's triage** (section 10). Both runs pass from `eaccbab`: Compose 90/90
  and kind 156/156. mock-docs accepted exactly the calls the gateway allowed, and the operator
  checks are now 58, 29 per team.
- **Run twice in a row** (section 11). From `eb58476`, each demo ran twice without `down` in
  between, and all four runs passed: Compose 90/90 both times and kind 156/156 both times.

## Where and how

| | |
| --- | --- |
| Machine | Apple M5, 10 cores, 32 GB, macOS 26.6.2 |
| Docker | Colima VM, 4 CPUs, 8 GiB, Docker 29.5.2, linux/arm64 |
| kind | v0.32.0, kubectl v1.36.1, one node, kindnet |
| Postgres | 17.11 (`postgres:17-alpine`), default settings (`synchronous_commit` and `fsync` on) |
| Gateway | the release build in the demo image, one replica, Postgres pools of 16 (begin) and 4 (finish), no TLS to Postgres |
| Load | Other work ran on the laptop throughout. The load average was between 3.6 and 8.3. |

Two sources of timing were used:

- **The store test.** `crates/audit-postgres/src/tests/latency.rs` times `audit::begin` and
  `audit::finish` through the core against a real server, 200 calls one at a time and then 200
  calls 8 at a time. It ran three times against a throwaway `postgres:17-alpine` container
  published on 127.0.0.1, so each write crosses from macOS into the VM:

  ```sh
  SWITCHBOARD_TEST_DATABASE_URL=postgres://postgres:<password>@127.0.0.1:<port>/postgres \
    cargo test --release --locked -p audit-postgres --lib latency_of_begin -- --nocapture
  ```

- **The running gateway.** For each tool call the gateway logs a `"ran a tool call"` line
  with `begin_us`, `run_us` and `finish_us`, and for each denial a `"denied a tool call"` line
  with `begin_us`. For each request it logs `"answered a request"` with `elapsed_us`. Calls
  were made with curl from the host: through the published port in Compose, and through
  `kubectl port-forward` in kind. The port-forward affects only the client's own timing, not
  the gateway's. In kind the token came from `kubectl create token` for
  `team-a/mock-workload` with audience `switchboard`, so the cluster signed it, as it signs
  the projected tokens.

Percentiles are nearest-rank, as in the store test.

## 1. Audit begin and finish latency

### The store alone (host to the VM)

Three runs of 200 calls each way:

| | begin p50 | begin p95 | finish p50 | finish p95 |
| --- | --- | --- | --- | --- |
| One at a time | 0.39 to 0.41 ms | 0.53 to 0.69 ms | 0.40 to 0.42 ms | 0.50 to 0.69 ms |
| 8 at a time | 0.88 to 0.99 ms | 1.51 to 1.76 ms | 0.90 to 1.04 ms | 1.45 to 2.02 ms |

### Inside the running gateway

Three rounds of 200 allowed reads (`docs__read_document`, team-a, `atlas/plan`) and 200 denied
reads (`borealis/plan`), one at a time. A denial writes a begin row and no finish.

| | allowed begin p50 / p95 | allowed finish p50 / p95 | upstream run p50 / p95 | denied begin p50 / p95 |
| --- | --- | --- | --- | --- |
| Compose | 449 to 588 / 591 to 873 µs | 400 to 523 / 551 to 823 µs | 166 to 224 / 225 to 309 µs | 515 to 553 / 714 to 980 µs |
| kind | 503 to 508 / 635 to 689 µs | 410 to 445 / 540 to 696 µs | 177 to 191 / 235 to 281 µs | 535 to 592 / 620 to 971 µs |

Compose, three rounds of 200 allowed reads, 8 at a time. All 600 calls answered with
`isError: false`.

| | begin p50 | begin p95 | finish p50 | finish p95 |
| --- | --- | --- | --- | --- |
| Compose, 8 at a time | 891 to 1273 µs | 2319 to 2993 µs | 953 to 1339 µs | 2335 to 3328 µs |

### The whole request (Compose, one at a time)

The gateway's `elapsed_us` per request, from the request arriving to the answer, three rounds
of 200 each. `tools/list` writes no audit row, so it shows the rest of the path: the host
check, the token's verification and the reply.

| | gateway p50 | gateway p95 | curl p50 | curl p95 |
| --- | --- | --- | --- | --- |
| `tools/list` (no row) | 306 to 325 µs | 350 to 405 µs | 1.08 to 1.48 ms | 1.34 to 1.99 ms |
| denied read (begin) | 818 to 949 µs | 959 to 1329 µs | 1.62 to 2.04 ms | 2.00 to 5.29 ms |
| allowed read (begin, run, finish) | 1378 to 1450 µs | 1688 to 1897 µs | 2.18 to 2.27 ms | 2.74 to 2.96 ms |

### What this says, and what it does not

- On this laptop, begin and finish are each a single round trip to Postgres plus a commit.
  Together they are most of an allowed call's time inside the gateway. The mock server's own
  answer took less time than either.
- Concurrency moves the tail. With 8 calls at a time, p95 is roughly three to six times the
  one-at-a-time p95. Nothing here measured the store under sustained load, or with its begin
  pool of 16 exhausted.
- None of this measures a networked Postgres, TLS, a replicated commit, larger rows, or a busy
  database. The rows here name at most one resource each. Q12 owns the budgets and their final values,
  and these numbers can only bound them from below.

## 2. A paused or stopped audit database

Measured through the Compose gateway, with team-a's token. `docker compose pause postgres`
freezes the server with its connections open. `docker compose stop postgres` stops it, so new
connections are refused.

| | allowed read | denied read | `tools/list` | reached mock-docs |
| --- | --- | --- | --- | --- |
| Paused | refused after 2.002 s | refused after 2.003 s | answered in 1.5 ms | 0 requests |
| Stopped | refused after 29 ms, then 2 ms | refused after 2 ms | answered in 0.9 ms | 0 requests |

Each refused call answered with JSON-RPC -32001 and this sentence: "The gateway could not
record this call in its audit log, so it was refused and nothing ran. Try again later." The
gateway logged each one at `ERROR`, with `begin_us` of about 2,000,000 when paused and the
connection error when stopped.

**Recovery.** After `docker compose unpause postgres`, the first allowed read succeeded. After
`docker compose start postgres` returned (0.1 s), the first allowed read 0.03 s later also
succeeded. The pool replaced its broken connections on its own and logged `deadpool`
warnings. No restart of the gateway was needed in either case.

**Rows.**

- **Paused, allowed read.** The insert committed after Postgres was unpaused, after the call
  had been refused. The store completed the row as `allow | error | 0 ms`, as decision 0009
  requires: a row may overstate what ran, never understate it. *Changed after these runs:* the
  branch now carries the Postgres store as PR #39 has it, which does not complete such a row.
  It stays open, with no outcome, until that recovery is built (design section 17).
- **Paused, denied read.** No row appeared. The call was refused, so nothing ran, but the
  denial itself is recorded only in the gateway's log. This was seen once.
- **Stopped.** No row for any refused call. Nothing was sent, so nothing was written.
- **`tools/list`.** It writes no row in either state, and is answered from the approved
  definitions. That is by design for now: decision 0009 defers `tools/list` rows.

### Lost between begin and finish

A read of `slow-doc` (the mock server answers after 10 s, the proxy's deadline is 5 s), with
Postgres paused 1 s after the call began, so begin committed and finish could not:

| Postgres unpaused after | caller's answer | row |
| --- | --- | --- |
| 12 s | after 7.0 s: the tool's result (`isError: true`, the deadline sentence) | completed 18.2 s after begin, `allow | error | 5001 ms` |
| 40 s | after 7.0 s: the same | **left open: no outcome, no latency** |

- The answer went out after the 5 s call deadline plus the 2 s answer budget, as decision 0009
  says. It is never held for the row. The gateway logged at `ERROR` that the call ran and its
  row could not be completed.
- Past the 30 s finish deadline the store gave up, and the row stays an allowed row without an
  outcome. **Nothing was logged when it gave up.** The store only counts it. The binary reports
  the count at shutdown. Decision 0009 asks for a telemetry event naming the row at that point.
  See gaps 1 and 2.

### The upstream side, for comparison

Through the same gateway, with Postgres up:

- A 1 MiB answer (`huge-doc`) was discarded in 6 ms with "This tool's answer was larger than
  the gateway accepts, so it was discarded."
- `hang-doc` and `slow-doc` were abandoned at 5.00 s with the deadline sentence.
- With mock-docs stopped, `tools/list` still answered in 1 ms, from the approved definitions.
  A read failed in 69 ms with "The gateway could not reach this tool's server." The read
  after mock-docs started again succeeded.

Each of these is an `allow` row with outcome `error` and the time the call took.

## 3. Time to see a policy change

The change withdraws `docs__read_document`: revision `demo-1` becomes `demo-2`, and back. It
is timed from replacing the registry to the first `tools/list` that shows it, with one clock,
the host's. After every withdrawal, a call to the withdrawn tool was refused with "Tool
`docs__read_document` is not available on surface `docs`."

| | how the change is made | changes | min | p50 | max |
| --- | --- | --- | --- | --- | --- |
| Compose | rename a new file into the mounted directory; poll every 0.1 s | 30 | 0.15 s | 0.78 s | 2.03 s |
| kind | `kubectl apply` of ConfigMap `switchboard/registry`; poll every 0.5 s | 6 | 32.7 s | 65.8 s | 87.5 s |

- **Compose** follows the gateway's 2 s poll. A random wait before each rename kept the changes
  from falling into step with the poll. Without it, the first ten changes all took about 1 s.
- **kind** waits for kubelet to update the mounted ConfigMap. The six times were 32.7, 60.1,
  65.8, 68.1, 70.2 and 87.5 s. Each change logged one `policy_reloaded` line with the new
  revision.
- During those 33 to 88 s, a tool withdrawn in kind is still served. A withdrawal that must
  take effect faster needs another path, such as restarting the gateway or having it read the
  ConfigMap from the API. Neither is built.

## 4. The runs

| | result | wall clock | notes |
| --- | --- | --- | --- |
| `demo.sh compose` | PASS (83/83), exit 0 | 21 s | warm: the image was fully cached |
| `demo.sh kind` | PASS (93/93), exit 0 | 44 s | warm: existing cluster, cached image; includes the 10 s wait after the network policy |

A cold run was not measured. That means a new cluster, the node image and Postgres pulls, and
a first build of the workspace's dependencies. An earlier Compose run, with the dependencies
already cached, spent 38.9 s compiling the workspace's own crates inside the image.

## 5. What the kind run proved

From the run of 2026-10-07 (93/93):

- **Real workload identity.** The gateway trusted the cluster's own issuer,
  `https://kubernetes.default.svc.cluster.local`. Its key set was read with
  `kubectl get --raw /openid/v1/jwks` at deploy time. Each workload's token was a projected
  ServiceAccount token with audience `switchboard`. No token was made by hand.
- **Two teams, one resource limit.** Each team read its own project. The other team's project
  was denied by the gateway's check 6, with the named sentence and a `deny` row naming that
  project. The denied call never reached the server. No allowed row names the other team's
  project.
- **Identity failures are refused, with one opaque sentence.** No token, a string that is not
  a token, the pod's real default API token (cluster-signed, wrong audience), and a real token
  for a ServiceAccount outside the team manifest. Each was logged as `identity_failed` with
  its cause, and none left an audit row.
- **No route around the gateway, with its controls in the same run.** Before the policy, a new
  pod's direct call to mock-docs connected and got 401. After the policy, new pods' direct
  calls timed out (curl exit 28). The same pods still reached the gateway, and an allowed read
  through it succeeded. kindnet enforced the policy.
- **The server saw only the gateway's credential.** mock-docs accepted 6 requests, all with
  the gateway credential's hash. The only other request was the refused pre-policy probe.
- **The workload holds nothing that reaches the server.** Six `kubectl auth can-i` checks
  answered `no`.
- **Durable audit.** The rows were in Postgres, read back as `switchboard_reader`, from a
  gateway that reported `role_check: passed` at boot.
- **The run deployed its own build.** The gateway and mock-docs ran the image tag taken from
  this run's image ID.

## 6. What the kind run did not prove

- **Key rotation or fetching.** The keys are copied once at deploy time. Tokens signed with a
  new cluster key would be refused until the next deploy.
- **A real client or a real workload.** The workload is a shell script using the 2025-06-18
  era. Claude Code as a client, and the 2026-07-28 era over HTTP in a cluster, were not run.
  Whether the policy model fits a real team's needs is still open (decision 0008).
- **Egress control.** The policies are ingress only: mock-docs admits only the gateway,
  Postgres admits only the gateway and the migration, and the gateway admits only the two
  teams. Nothing limits where a workload or the gateway itself can connect.
- **A production network plugin.** kindnet enforced the policy here. A production cluster's
  plugin must be checked the same way.
- **Audit under failure in a cluster.** The database outage was measured only in Compose.
  Postgres in kind is a single pod on an `emptyDir`, so stopping it would lose the schema.
- **Durability.** The same `emptyDir` means the kind rows do not survive the Postgres pod.
- **More than one gateway, restarts with calls in flight, or load.** One replica. Nothing was
  killed mid-call.
- **Proposals, writes, and `tools/list` rows.** Only read tools were served, and `tools/list`
  writes no row.

## 7. Gaps

1. **A row given up at the finish deadline is silent.** The store counts it, and the binary
   reports the count only at shutdown. Decision 0009 asks for a telemetry event naming the
   row when it happens. Without one, the open row is found only by querying for it. That query
   is not built either (decision 0009's open-row work). *Fixed after these runs:* the store
   reports each finish it gives up, and the gateway logs each report as `audit_row_given_up` at
   `ERROR`, naming the row, the outcome it could not write, and why. An insert that commits
   after its begin failed is not a finish, so its row stays open with no event. The open-row
   query is still not built.
2. **The gateway's termination grace period is the default.** In kind it is 30 s, and Compose
   uses its default of 10 s. Decision 0009 says it must be longer than the readiness-removal
   delay plus the begin budget, the call deadline and the finish deadline: 2 s + 5 s + 30 s
   here, plus the delay. Until it is set, every deploy can leave open rows. *Fixed after these
   runs:* both manifests now give the gateway 50 s (see `deploy/README.md`).
3. **Proxied results reach the caller wrapped twice.** The proxy hands the upstream's whole
   `result` object to the core. The reply then puts that object, serialized, into a single
   text block, and also into `structuredContent`. A read of `atlas/plan` answers with a text
   block whose text is `{"content":[{"text":"The atlas plan. …","type":"text"}],"isError":false}`,
   not the server's own text block. The demo checks only that some content is present, so it
   passes. A real client would show the JSON. This was found while measuring. *Fixed after
   these runs:* the gateway passes on the server's `content` and `structuredContent` as the
   server sent them, and the workload fails a result whose text holds a whole tool result.
4. **Withdrawal in kind takes up to 88 s** (section 3). Any "refused within the stated time"
   claim for kind must use that number, not Compose's 2 s.
5. **Some refusals leave no row.** Identity failures go to the log only, by design (decision
   0009). A denial refused because the database was down left no row. `tools/list` writes no
   row and keeps answering while the database is down.
6. **The numbers are noisy and local.** Other work kept the laptop's load average between 3.6
   and 8.3. Each number is reported as the range over three rounds, not one figure.
7. **Not measured.** A cold run. A database outage in kind. Sustained load and an exhausted
   begin pool. A gateway restart with calls in flight. Rows that name many resources.
8. **Run before the work merged.** These runs were made from `agent/first-slice`, which then
   stacked unmerged work (#25's harness, #26, #10, #14 and #9). That work has since merged
   (#35, #38, #39 and #42), and the later runs in section 11 are from #42's tree. Milestone 2
   is not done until decisions 0009 and 0010's remaining criteria for the slice land (#47).
9. **The runs claimed more than some checks tested.** A review of the demo after these runs
   found four. A call to a tool the gateway does not know, such as the withdrawn one, recorded
   `resources` as `[]`, which reads as a call that named nothing, though it named a project.
   The check "every row records the resources its call named" only checked that the column
   was not null. The operator checks were six, for team-a's workload only, and did not ask
   about exec, port-forward or the proxy routes, which reach a pod through the API server and
   not through network policy. Only team-a's direct call had a pre-policy control. *Fixed
   after these runs:* such a row records `"unknown"`; the driver matches every row to the call
   that made it and checks its resources; the operator checks cover both teams and those
   routes, in `mock-docs` and `switchboard`; and each team makes its own pre-policy call.
   Sections 1 to 6 describe the runs as they were, before these fixes. Section 8 has the runs
   after them.

## 8. The runs after the fixes

Both demos ran again on 2026-10-07 from `a509ec9`, which carries the fixes of gaps 1, 2, 3 and
9, on the same laptop. Compose ran first and was taken down. kind then ran on the existing
cluster `switchboard-demo` and was left deployed. Both passed on the first attempt. Nothing in
the repository had to change.

| | result | wall clock | notes |
| --- | --- | --- | --- |
| `demo.sh compose` | PASS (89/89), exit 0 | 85 s | 47 s of it compiled the workspace's own crates in the image; dependencies were cached |
| `demo.sh kind` | PASS (139/139), exit 0 | 81 s | the image was fully cached from the Compose run; existing cluster |

The counts rose from 83 and 93 because the checks of gap 9 now run. What they showed:

- **Each row records what its call named.** Every row of each run was matched to the call
  that made it: 10 rows in Compose and 10 in kind, none wrong. Each team's call that named no
  project recorded `[]`. In Compose, the call to the withdrawn tool recorded `"unknown"` under
  revision `demo-2`, not `[]`.
- **The operator checks cover both teams and the API server's routes.** 42 `kubectl auth
  can-i` checks answered `no`, 21 per team. Besides secrets, ConfigMaps, pods and gateway
  tokens, they cover exec, port-forward and the pod proxy, each with `create` and `get`, and the
  Service proxy, in both `mock-docs` and `switchboard`.
- **Each team has its own control for the network policy.** Before the policy, each team's new
  pod reached mock-docs directly and got 401. After it, each team's new pod timed out (curl
  exit 28) and still read through the gateway.
- **The server saw only the gateway's credential through the gateway.** mock-docs accepted 6
  requests, all with the gateway credential's hash, and refused the two pre-policy probes,
  each with that team's own token.
- **Results are not wrapped twice** (gap 3). Each list and read through the gateway, in both
  runs, returned the server's own content, and the workload checks that the text is not a whole
  tool result.
- **The gateway's grace period is 50 s** in the deployed kind manifest (gap 2).

The rest matched sections 4 and 5: the cluster's own issuer, 7 `identity_failed` lines and no
row for the stranger, and in Compose the paused database refused the call with nothing reaching
mock-docs.

**One thing on the host, not in the repository.** The Colima VM's SSH control connection had
been restarted earlier that evening, which dropped its forwards of the Docker socket and of the
cluster's API port. `docker` and `kubectl` on the host were refused. The runs reached them
through a separate SSH tunnel into the VM for each: the Docker socket at `.demo/d.sock`, with
`DOCKER_HOST` pointing at it, and the cluster's API port at its usual address. Restarting Colima
would restore its own forwards.

## 9. The runs with PR #39's audit store

Both demos ran again on 2026-10-08 from `ef621ef`, on the same laptop. That commit carries the
Postgres audit store as PR #39 has it at `9ac12c8`. Its boot check refuses more than before:
views and rules that reach the table, `SECURITY DEFINER` functions, functions that read or
write server files, partitions, replica sessions and databases not in UTF8. Compose ran first,
on a new database, and was taken down. kind then ran on the existing cluster
`switchboard-demo`, against the database the earlier runs left, and was left deployed. Both
passed on the first attempt. Nothing in the repository had to change.

| | result | wall clock | notes |
| --- | --- | --- | --- |
| `demo.sh compose` | PASS (90/90), exit 0 | 34 s | 14 s of it compiled the workspace's own crates in the image; dependencies were cached |
| `demo.sh kind` | PASS (140/140), exit 0 | 48 s | the image was fully cached from the Compose run; existing cluster |

What changed from section 8:

- **The boot check accepted the demo's setup.** The gateway logged `"role_check":"passed"` in
  both runs, so `deploy/demo/roles.sql`, the migrations and `migrate.sh`'s reader grants give
  the gateway's role nothing the stricter check refuses.
- **One check became two,** so each count rose by one. "No allowed row is left without an
  outcome" is now "no allowed row outside the database outage is left without an outcome" and
  "the database outage left at most its refused call's row without an outcome". In Compose the
  outage left that one row open, as an `allow` row with no outcome; this store does not
  complete it (design section 17). kind has no outage step and left none.

The rest matched section 8: 10 rows in each run, each matched to the call that made it and
none wrong; 42 `kubectl auth can-i` checks answered `no`; mock-docs accepted 4 requests in
Compose and 6 in kind, all with the gateway credential's hash, and refused only the two
pre-policy probes in kind; 7 `identity_failed` lines and no row for the stranger. Docker and the
cluster's API were reached through Colima's own forwards; no tunnel was needed.

## 10. The runs after the review's triage

Both demos ran again on 2026-10-08 from `eaccbab`, on the same laptop. That commit carries PR
#42 with main merged in (PR #39's audit store and the pinned CI actions) and the fixes from the
review's triage. Compose ran first, on a new database, and was taken down. kind then ran on the
existing cluster `switchboard-demo` and was left deployed. Both passed on the first attempt.

| | result | wall clock | notes |
| --- | --- | --- | --- |
| `demo.sh compose` | PASS (90/90), exit 0 | 36 s | the image's build context was 24 kB; dependencies were cached |
| `demo.sh kind` | PASS (156/156), exit 0 | 53 s | the image was cached from the Compose run; existing cluster |

What changed from section 9:

- **The server check counts exactly.** It used to ask for at least 4 requests accepted with
  the gateway's credential, so a denied call that reached mock-docs would still have passed.
  It now asks for exactly the calls the gateway allowed: 4 in Compose, each team's list and
  read, and 6 in kind, which adds each pod's read after its direct call timed out. Both runs
  got exactly that. These are the same numbers section 9 saw; only the check is stricter.
- **The operator checks ask more.** 58 `kubectl auth can-i` checks answered `no`, 29 per team,
  up from 42. Secrets in `switchboard` and `mock-docs` and ConfigMaps in `switchboard` are now
  asked about with `get`, `list` and `watch`, since `list` and `watch` return a Secret's data
  too. The node proxy is asked about with `create` and `get`. That is why kind's count rose
  by 16. Decision 0010's other controls (attach, ephemeral containers, impersonation, bind
  and escalate, and controllers that create pods) are still not checked.
- **The driver touches only `switchboard-demo`.** `SWITCHBOARD_DEMO_CLUSTER` set to any other
  name now stops the script before any `kind` or `kubectl` call.

Two gateway changes from the same triage are not exercised by these runs, and are covered by
tests in `crates/gateway`. A proxied call's arguments are checked against the policy version
its decision was made from, not one loaded while its audit row was being begun. A registry
reload that changes the policy but keeps its `revision` is refused. The demo's withdrawal step
changes the revision to `demo-2`, so it still loads.

The rest matched section 9: 10 rows in each run, each matched to the call that made it and
none wrong; the boot check passed for the demo's database in both runs; mock-docs refused only
the two pre-policy probes in kind; 7 `identity_failed` lines and no row for the stranger.

## 11. Each demo run twice in a row

Both demos ran on 2026-10-08 from `eb58476`, on the same laptop. That commit carries PR #42 with
main merged in (PRs #44, #45 and #46 as well as #39) and the second round of review fixes. Each
demo ran twice in a row without `demo.sh down` in between: Compose twice, then kind twice on the
existing cluster `switchboard-demo`. All four passed on the first attempt. Compose was then taken
down, and kind was left deployed.

| | result | wall clock | notes |
| --- | --- | --- | --- |
| `demo.sh compose` | PASS (90/90), exit 0 | 44 s | new containers and database |
| `demo.sh compose`, again | PASS (90/90), exit 0 | 16 s | the gateway, mock-docs, the dev issuer and Postgres kept running from the first run |
| `demo.sh kind` | PASS (156/156), exit 0 | 55 s | existing cluster |
| `demo.sh kind`, again | PASS (156/156), exit 0 | 57 s | existing cluster |

What changed from section 10:

- **A rerun counts only its own requests.** The server check asks for exactly the calls the
  gateway allowed, but it read mock-docs' whole log, so a second run against the same mock-docs
  saw the first run's requests too and failed. It now reads the log from the run's start mark,
  taken from Postgres' clock with the audit rows' mark. The second Compose run reused the
  first run's mock-docs and saw exactly its own 4 accepted requests.
- **A rerun keeps the registry directory.** The Compose run used to delete its copy of the
  registry and copy it again, but a gateway container kept from the first run still had the
  deleted directory mounted, so the withdrawal step's change never reached it. The run now
  keeps the directory and replaces only `registry.toml`. The second Compose run reused the
  gateway, and its withdrawal step passed.
- **kind did not exercise the reused server.** Each kind run built an image with a new ID, so
  mock-docs and the gateway got new pods both times. The image's layers were all cached; the ID
  still changes because the build exports a new attestation manifest each time. The second kind
  run read mock-docs' log from its start mark all the same.

The rest matched section 10: 10 rows in each run, each matched to the call that made it and
none wrong; mock-docs accepted 4 requests in Compose and 6 in kind, all with the gateway
credential's hash, and refused only the two pre-policy probes in kind; 58 `kubectl auth can-i`
checks answered `no`; 7 `identity_failed` lines and no row for the stranger.

## 12. The kind dummy credential is gone

On 2026-10-09 the kind deployment lost its dummy credential (#47). The gateway now presents a
projected token of its own ServiceAccount to mock-docs, for audience `mock-docs` and valid
600 s, and reads it again on every call. mock-docs runs in its JWT mode and accepts only
`system:serviceaccount:switchboard:gateway`, signed by the cluster's keys. Compose keeps its
own dummy credential, since it has no cluster issuer. The kind run passed (360/360): mock-docs
accepted 8 requests, every one from the gateway's ServiceAccount, and refused only the two
direct calls before the policy, as `wrong_audience`. No run waited for the token to rotate.
