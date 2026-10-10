# 0014: Rollout safeguards and audit operations

Date: 2026-10-10. Status: proposed, awaiting the owner. Would settle Q12 (#5), except the
per-user rate limit, which stays the owner's, and the parts under Still open, which wait on
other people. Written against [decision 0009](0009-audit-completion-receipts-and-recovery.md)
as amended on 2026-10-10, [decision 0011](0011-resource-authorization-and-tool-assurance.md),
and the code on main at the end of milestone 2, including the metrics export of #47. Decision
0013, proposed beside this one, settles Q11. Neither depends on the other. The alert conditions
below on drift, probes, reach checks and the policy's age apply to the signals decision 0013
defines.

## Context

Milestone 3 hardens the proxy before Otto's callers and employees use it. Decision 0009 left
its provisional values, pool sizes, alert thresholds and retention to Q12. Decision 0011 left
the size and duration bounds, and whether a server may have a longer deadline than the
default, to the same place. Q12 also asks how the identity and audit opt-outs are kept out of
production, what an overloaded audit store does, and who owns it.

What is built today:

- A request body is read up to 1 MiB. A proxied server's result is bounded at 64 KiB and its
  call at 5 s, for every server, with no way to set another value. A connector in the gateway's
  own process has a 5 s deadline that only feeds each row's deadline; nothing stops it.
- Nothing bounds how many calls run at once.
- The audit store has a begin pool of 16 connections and a finish pool of 4, fixed in code.
  The budgets are decision 0009's provisional 2 s for begin, 2 s for the answer and 30 s for
  finish. The deployments give the gateway a termination grace of 50 s, against the 47 s that
  readiness removal (8 s), begin, a 5 s call deadline, finish and one answer budget need.
- The counters decision 0009 asked for are exported at `GET /metrics` (#47). Nothing alerts.
- Every build accepts `[identity] mode = "disabled"` and `[audit] mode = "disabled"`, with a
  loud warning. With identity disabled, nothing is listed and every `tools/call` is refused,
  with no row ([decision 0007](0007-serve-two-mcp-revisions-from-a-hand-written-endpoint.md),
  item 5 of its amendment). #69 holds the work decision 0009 describes instead: reads served,
  each with a row whose identity is `disabled`.

What the first slice measured ([first-slice-findings.md](../first-slice-findings.md), #14),
against Postgres in the same kind cluster:

- Begin and finish each take under 1 ms at p95 one call at a time, and 2 to 3.3 ms with 8 calls
  at a time.
- An allowed read through the gateway takes 1.7 to 1.9 ms at p95 inside the gateway.
- With Postgres stopped, every call is refused within 30 ms. With Postgres paused, every call
  is refused at the 2 s begin budget.
- None of it measured a networked Postgres, TLS, a replicated commit, larger rows or sustained
  load.

A row's recorded resources alone can reach 298,059 bytes as JSON (design.md, section 11).
Q12 asked for size limits in the units the store counts.

## Decision

### 1. Size limits and deadlines

- **Requests:** the 1 MiB body cap stays.
- **Proxied results:** 64 KiB by default.
- **Proxied calls:** a 5 s deadline by default.
- **Per-server overrides** are set in the deployment file, beside the server's entry, up to
  1 MiB for a result and 60 s for a deadline. A larger value is refused at boot. The deployment
  file is operational configuration, and it sits beside the termination grace that must cover
  the longest deadline. Policy files do not set limits.
- **Limits are per server, not per tool,** in milestone 3. No tool needs its own yet.
- **The 60 s ceiling** is raised to 120 s only when Sumo Logic is onboarded, since a search
  there may take two minutes. A higher ceiling lengthens every deploy's grace.
- **The termination grace** must exceed 8 + 2 + D + 30 + 2 seconds, where D is the largest
  call deadline configured. At the 60 s ceiling that is 102 s. demo-checks holds the manifests
  to it, as it holds them to 47 s today.
- **A connector in the gateway's own process** gets no gateway-level bound in milestone 3.
  The first such connectors that reach a real system are milestone 4's built-in ones (#12). A
  late result from one not classified `read` must be recorded as `unknown`, which arrives with
  receipts (#55). The bound is built with them.

A result over its bound, or a call past its deadline, is handled as decision 0011 says: `error`
for a `read` tool, `unknown` for any other, never cut short silently.

### 2. Concurrency caps and isolation

There is no queue and no circuit breaker. Three caps hold in each gateway instance:

- **256 requests in flight.** A request over it is refused at admission, before its body is
  read: HTTP 503 with a fixed sentence, a telemetry event and no audit row. This is a transport
  refusal, which decision 0009 makes telemetry, and it keeps overload away from Postgres.
- **32 calls in flight to each proxied server.**
- **8 calls in flight from each team to each proxied server,** by the caller's proved team.

The last two are taken inside the audited run, after begin, so every allowed decision keeps
its row. A call over either is completed as `refused` with a fixed capacity sentence that names
the scope, server or team, and the server. Nothing was sent, so a side effect's receipt is
`not_performed`. It is not `error`: an `error` row stores no sentence (the `completion_shape`
constraint), so a capacity refusal would look like any other failure in the store. The capacity
sentence tells the caller the call may be tried again.

The per-server and per-team caps, with the call deadline, isolate a hanging server. Its calls
hold at most 32 slots in each instance until their deadline, and one team holds at most 8 of
them. Calls to other servers are not held up.

Per-team and per-server rate quotas wait for milestone 4's built-in connectors and the vendor
quotas they meet (#12). Until then the caps are the only limit. A caller with no team, such as
an employee from milestone 5, is held by the per-server cap alone until the per-user rate
limit is answered (Still open).

### 3. Audit overload

- **Admission is the caps.** No other admission control sits in front of the store. An
  authentication flood already writes nothing to it (decision 0009).
- **Pools:** 16 begin and 4 finish connections in each instance, as built. A begin that cannot
  get a connection within its 2 s budget refuses the call with the audit-failure sentence.
- **The database's `max_connections`** must be at least the number of gateway replicas times
  20, plus the connections the migrate job and readers use.
- **The pool sizes become configurable** in the deployment file before the first deployment
  against a real database. The defaults stay 16 and 4.

### 4. The identity and audit opt-outs

The release binary refuses `[identity] mode = "disabled"` and `[audit] mode = "disabled"` at
boot, before it makes any connection. Only a development build, with the `test-support`
feature, accepts them, as it alone may serve a tool not classified `read` without a receipt
store (pull request #72). The receipt gate moves to run right after the registry loads, so that CI's
receipt-gate configuration can enforce identity from a checked-in public key file and name a
database it never reaches. CI's release-artifact job gains a refusal step for each opt-out.
The harness and the conformance suite's Rust target stay development builds on fakes.

With identity disabled, the stricter behaviour stays: nothing is listed and every `tools/call`
is refused, with no row. #69, serving reads with rows whose identity is `disabled`, is not
built, and closes as not planned. It would take three full-tier changes, a migration and
changes to core types, for a mode no release build can run.

### 5. Targets

All provisional, awaiting measurement against a networked Postgres before the first production
deployment:

- **Gateway overhead,** the time a call spends in the gateway apart from the upstream call:
  p95 at most 25 ms, in-cluster.
- **Audit begin:** p95 at most 10 ms, in-cluster, with rows at the size bound in section 7 as
  well as typical rows.
- **Availability:** the audit database's. Every call waits for begin, so the gateway cannot be
  more available than the database, and is not asked to be.

When the audit store fails, every call is refused with the audit-failure sentence, as decision
0009 says. The first slice measured that at 30 ms with Postgres stopped and at the 2 s budget
with it paused.

### 6. Audit budgets

The 2 s begin budget, the 2 s answer budget and the 30 s finish deadline are final for
milestone 3. The first slice's p95 of at most 3.3 ms leaves the 2 s budgets about 600 times
the highest it measured. They are revisited with the networked measurement in section 5.

### 7. What a row holds, and how large it may be

**A row is at most 512 KiB,** counted as the bytes of the values the Postgres store sends:
UTF-8 text, with each JSON value counted as its JSON text. The resources' 298,059 bytes fit,
with room for the rest of the row. The caps on every value a caller chooses must keep the
largest possible row inside it, and a test shows the largest row fits. The store refuses a
record over the bound as it refuses one it cannot hold exactly, naming the column, so the call
is refused.

**The credential identity on a row is the configured entry identity, recorded at begin:** the
connector entry's stated credential mode and principal, never the secret. An entry has exactly
one credential and no fallback, so that is the identity the call runs under, and no completion
column is needed. It is named as configured, not as used, because the gateway records what the
entry says rather than what the credential layer reports. This is revisited when per-user
grants arrive in milestone 5, since a grant can then be missing at run time.

**Redaction is as built.** A row holds no tool arguments and no results: the argument digest
of decision 0009 is not storing them. It holds no token or secret. Claimed values are escaped
and capped, and so are recorded resources. Storing arguments or results still needs a decision
of its own.

### 8. Ownership, retention and access

- **Ownership.** The audit and receipt schema, its grants, triggers and migrations stay in
  this repository, under its code owners (#48). The Postgres instance belongs to whoever runs
  Postgres, named with IT: its backups, failover, `max_connections`, and the superuser login.
- **Retention.** Rows, receipts, resolution records and the policy snapshots rows cite are
  kept for 400 days, provisional until compliance answers Q10. A receipt is never deleted
  before its row. Decision 0009 says a key is honored only while its receipt is kept.
- **Access.** A separate retention role, the only role that may delete, and a read-only
  reviewer role are created before the first production deployment, not in milestone 3. Until
  the retention role exists nothing is deleted. The gateway's role stays as decision 0009 sets
  it.

### 9. Metrics and alert conditions

Exported beside the counters of decision 0009:

- Per proxied server, labelled only by the server names in the registry: calls by outcome,
  latency, deadline and size failures, drift polls and withdrawals, probe results and reach
  check results.
- Calls shed, labelled by scope: instance, server or team.
- The policy's age, and each issuer's key-refresh age, labelled by the issuer as configured.

No label carries a value a caller chooses, a credential or a payload.

The alert conditions:

- any begin failure, any finish given up, or any open row past its deadline;
- any telemetry dropped, or the begin pool at its limit for 60 s;
- any call shed, any withdrawal, any probe answered as open, or any reach mismatch;
- three consecutive failed polls of one server;
- issuer keys older than four refresh intervals, or a stale policy.

There is no rules file and no paging until a metrics sink and an on-call rotation exist
(decision 0009, Still open 3 and 9). Until then the conditions are written here and the
signals are exported.

### 10. Otto's audit table

Whether Otto's `gateway_audit` table gains columns for the resources a call names, the
credential identity and the error kind moves to the one list of Otto requests (Q18, #21). It
is no longer a question in Q12.

## Alternatives rejected

- **Every cap before begin, with no row,** as #5's draft had it. An allowed decision would
  then have no record, and a capacity refusal would be invisible in the store.
- **A capacity refusal recorded as `error`.** An `error` row keeps no sentence, so it could be
  told apart only by the metrics.
- **A queue in front of the caps.** It turns overload into latency past the budgets, and the
  caller cannot tell a queued call from a slow one.
- **A circuit breaker.** It trips on errors one caller's arguments cause and cuts off every
  caller. Its state differs between replicas. The caps and the deadline bound a failing
  server's cost without judging its health.
- **Limits per tool, or in the policy files.** No tool needs its own limit yet. A deadline must
  fit the termination grace, which is set where the deployment is set, not where tools are
  approved.
- **A 120 s ceiling now.** It lengthens every deploy's grace to 162 s for a server not yet
  onboarded.
- **Rate quotas now.** They depend on vendor quotas that only built-in connectors meet, in
  milestone 4.
- **Building #69.** The cost is above. The mode it serves is development-only.
- **Allowing the opt-outs in release builds with a warning.** The warning is then the only
  control, and a misconfigured production deployment runs unaudited or unauthenticated.
- **Counting the row bound in characters.** Postgres counts bytes, and escaping and multi-byte
  text make the two differ.
- **Recording the credential identity at completion.** It needs a completion column, an
  interim row shape and a second migration, for an identity that cannot differ from the
  configured one until per-user grants exist.

## Consequences

- #11 builds sections 1 to 4 and 9: per-server limits in the deployment file and their
  ceilings, the three caps with the capacity sentence, the opt-out refusals and CI's checks of
  the release artifact, configurable pools, the row bound and its test, the new signals, and a
  demo of overload and a hanging server. The grace check moves to the largest configured
  deadline.
- Decision 0009's `refused` covers a call refused by the per-server or per-team cap, and its
  call deadlines are set per server. Its provisional values become final for milestone 3. Each
  is a dated note on that record. Its Still open 6 is answered in part: the schema stays here,
  and who runs the instance stays open.
- Decision 0011's list of parts that may refuse outside the decision function gains the
  capacity caps. None of them can allow. A dated note on its section 5 says so, and names the
  credential identity as the configured entry identity, recorded at begin.
- Decision 0007's item 5 holds, in development builds only. A dated note says so.
- #69 closes as not planned.
- The audit store gains no admission control of its own. Overload shows as begin failures and
  the begin pool at its limit, both alerted.
- Q12 is narrowed to what others decide and the per-user rate limit.

## Decided by the owner

On 2026-10-10 the owner asked for the work to keep going on the recommendations made for it.
This record adopts the recommendation on each question above. It is proposed on that basis and
is accepted when the owner merges it, or changed if the owner asks in its review. The one
question it leaves to the owner, with no answer adopted, is the per-user rate limit, under
Still open.

## Still open

Each needs someone other than the owner, except the first. The record holds while they are
open; each says what holds until it is answered.

- **Whether a per-user rate limit must be in place before the first employee proposal tool,**
  and if so what limit. For the owner; decision 0011 reserved it. The recommendation is to
  leave it open until milestone 5, since no employee is served a proposal tool before then,
  and to track it in #15. Until it is answered no employee proposal tool is approved.
- **How long rows, receipts and resolution records are kept.** Compliance decides, with Q10.
  Until then 400 days, and nothing is deleted before the retention role exists.
- **Who runs the audit database:** its backups, failover, `max_connections` and superuser
  login. Whoever runs Postgres, named with IT. Until then the demos' databases are the only
  ones, and no production deployment is made.
- **What "committed" means** (decision 0009, Still open 5). IT, or whoever runs Postgres.
  Until then a begin is committed on the primary.
- **Who is paged, on whose rotation,** for the alert conditions in section 9. Whoever runs the
  on-call rotation (decision 0009, Still open 9). Until then nothing pages.
- **Who may read the audit store through the reviewer role.** The security team. Until the
  role exists, no one reads it but its operators.
- **Whether Otto's `gateway_audit` table gains columns.** Otto's owners, through the one list
  of Otto requests (Q18, #21). Until then those columns stay in this gateway's own record.
