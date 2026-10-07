# 0009: What an audit row guarantees, recovery, and receipts for side effects

Date: 2026-10-06, accepted 2026-10-07. Status: accepted. The owner accepted both parts on
2026-10-07, taking the recommendation on every question that was the owner's to answer (see The
owner's answers). Settles Q10, except what compliance requires of read auditing, which stays
open (Still open 1); Q10 is narrowed to it. Other details need someone other than the owner,
alone or with the owner. They are listed under Still open, with who decides and what holds
until then. Fencing is not decided here; it moved to Q18. Written against [decision
0006](0006-what-the-decision-function-sees.md) as amended on 2026-10-04 (`propose`, and `write`
and `destructive` denied in every profile), and against the resources column on the audit
record proposed in #30, which is not yet merged.

Part 1 covers every audit row and is needed before milestone 2. Part 2 covers receipts and is
needed before the first tool not classified `read` reaches a real system. Both are accepted.

## Context

Section 11 of the design begins the audit row before the tool runs and finishes it before the
answer, waiting a short budget. Four things are not yet said:

- What a successful begin promises, and what a failed or timed-out begin leaves behind.
- What happens to a row whose finish is never written: a crash, a killed pod, a database that
  comes back too late. Today such a row stays open and nobody is told.
- Which requests are audit rows at all. The design review asked for three records to be told
  apart: telemetry for malformed and unauthenticated traffic, the authorization audit, and
  receipts for side effects.
- What stops a side effect happening twice. An audit row records one attempt. Otto's gateway
  makes the same comment twice when asked twice, even with the same `Idempotency-Key` header.

What is already true:

- Q4 accepted a synchronous begin, and Postgres on the path of every call, company-wide.
- Otto's gateway waits for finish before answering, for at most two seconds. If finish fails,
  the answer still goes out and the row keeps an empty outcome. A client that disconnects
  during a blocked read still gets an `error` row. Otto writes rows for identity failures,
  unverifiable turn grants, `initialize`, `ping` and `tools/list`, and none for an accepted
  notification or a malformed authenticated request ([otto-baseline.md](../otto-baseline.md)).
- In the core, `begin` hands out a guard only once the store says the row is durable, and
  `finish` gives out the answer only after the store's `finish` returns. The store assigns the
  row identifier. The core reads no clock and has no timer.
- `axum` drops a request's future when the client disconnects. A call run on that future is
  cancelled wherever it happens to be, including between a vendor write and the finish.
- Under the amendment to decision 0006, only `read` and `propose` tools can be allowed, and
  `write` tools under a recorded exception: [decision
  0011](0011-resource-authorization-and-tool-assurance.md) allows Otto's `github_pr_comment`
  and `jira_comment` to Otto's callers once its exception mechanism is built (#12). Below,
  "side effect" means a call to any tool not classified `read`. An excepted `write` tool is a
  side effect like any other. That stays true if more is permitted later.
- Tool arguments and results are not stored without a separate decision (Q12).

## Decision, part 1: every audit row

### Three records

| Record | Covers | Written | If it cannot be written |
| --- | --- | --- | --- |
| Telemetry | Requests that reach no decision: a token that does not prove a principal, a body that cannot be parsed, an accepted notification, a transport refusal (method, protocol headers, size, host or origin), `initialize`, `ping` and `server/discover`. Also every audit or receipt write that failed. | Structured events and counters, off the request path, through a bounded queue. Drops are counted. | Lost. Nothing waits for it. |
| Audit row | Every request that reaches a decision, from a proved principal or with identity checking explicitly disabled: each `tools/call`, allowed or denied, including one denied because its delegation could not be verified; and each `tools/list`. | Postgres, before the tool runs and before any answer. | The call is refused with the audit-failure sentence. |
| Receipt | Each allowed side effect (part 2). | Postgres, in the same transaction as the call's begin. | The same: the call is refused. |

**Identity failures are telemetry.** If an unauthenticated request caused a synchronous
database write, anyone who can reach the gateway could load the store that every call in the
company depends on. During a database outage every 401 would also become the audit-failure
sentence, which tells an unauthenticated caller how healthy the store is. The event records
the time, the deployment, the surface, the source address and which check failed, for
operators only, as section 10 already requires. It records the issuer and subject the token
claimed, as claims, escaped and capped, and never the token. "We were not checking" is still a
row with identity `disabled`; "someone tried and was refused" is a telemetry event. The cost is
that failed authentication is kept less durably than the audit, can be dropped under load, and
an incident review joins two sources. Whether that loss is acceptable is the security team's
call (Still open 4), and where telemetry goes is for whoever runs logging (Still open 3).

**A delegation that cannot be verified is an audit row.** A forged or expired turn grant
presented under a proved workload identity is one of the most security-relevant events the
gateway sees, and the principal is proved, so there is someone to record. One place decides.
The delegation's verifier runs before the decision function, as
[decision 0012](0012-what-a-turn-grant-binds.md) describes for turn grants, but it does not
deny. It passes the delegation on as unverified, carrying only the kind of failure, and the
decision function denies it at check 3 with a single reason kind of its own. The verifier's
failure kinds are recorded on the row and are not reason kinds. The row holds the proved
columns and nothing from the grant's claims. Where the signature verified and only a binding
failed (audience, lifetime or pod), decision 0012 also records the grant's digest and which
binding failed. The caller reads one fixed sentence whatever was wrong with the grant, as in
Otto.

**`tools/list` is an audit row of its own kind.** It reaches decisions: it tells a caller what
it may call. A list row has kind `list` where a call's row has kind `call`. It holds the policy
revision and the names of the tools returned, each made safe, at most 64 with the rest
counted, as the resources column proposed in #30 is bounded. It is written complete before the
answer, has no deadline and no finish, and is never open.

### Row identifiers

The gateway assigns each row its identifier before begin, a UUIDv7. The store no longer does.
Begin and finish are then idempotent on that identifier: either can be retried without making
a second row or a second completion, and an event about a failed write can name the row it was
for. The time inside a UUIDv7 comes from the gateway's clock. It is part of an identifier and
is never used for ordering or deadlines. The identifier is returned to the caller in the
result's `_meta`, or in `error.data` for a JSON-RPC error, so a person reporting a problem can
quote it.

### What begin guarantees

- When begin returns success, the row is committed. It survives a crash of the gateway and a
  restart of the database server. It survives a failover only with a synchronous standby,
  which is still open (Still open 5); until then, committed means committed on the primary.
  The Postgres store uses synchronous commit for its own sessions and refuses to start against
  a server with `fsync` or `full_page_writes` off. These are configuration gates, not tests of
  durability.
- Besides what it holds today, the row records the instance that began it, the database's time
  at begin, and the row's deadline: that time plus the begin budget, the call deadline and the
  finish deadline. The gateway supplies the allowance. A `BEFORE INSERT` trigger sets both
  times from the database's clock and the supplied allowance, overwriting anything the insert
  carried, and the gateway's role cannot write them. A generated column cannot do this, because
  Postgres requires its expression to be immutable, and a default cannot read the allowance.
  The deadline is `NOT NULL`, so a row without one cannot be stored and drop out of the
  open-row query.
- No tool runs, and no decision is returned, before begin succeeds. This is unchanged.
- Begin has a budget, which includes waiting for a connection. Within it, begin is retried by
  identifier. A retry that finds its own row returns what the first attempt decided, receipt
  included. If begin fails or the budget runs out, nothing runs and the caller reads the
  audit-failure sentence.
- A begin reported as failed may still have committed, if the confirmation was lost. The
  instance knows nothing ran, so it completes that row as `error`, as it does when a guard is
  given up without running, and settles a side effect's receipt as `not_performed` in the same
  transaction. It keeps trying on the finish pool until the finish deadline; if the row never
  committed, there is nothing to complete. Only a row it could not complete by then reads as
  open once its deadline passes. A row can overstate what ran. It never understates it.

### Where a call runs

Begin, run and finish happen on a task of their own, started before begin and not on the
request's future, so a client that disconnects cannot cancel a write to the store. What a
disconnect does to the call itself depends on when it comes:

- Before the connector is called: the connector is not called. The row is completed as
  `error`, and a side effect's receipt as `not_performed`.
- During a read: the tool call is cancelled and recorded as `error`, as Otto records it.
- During a side effect: nothing is cancelled. It runs to its call deadline, so its outcome is
  learned rather than made unknown by the cancellation.

The MCP transport says a disconnect should not be read as a cancellation. Cancelling reads is
deliberate, for parity with Otto. A `notifications/cancelled` is accepted and ignored: on a
gateway without sessions it can reach an instance that is not running the call.

### What finish guarantees

- Finish writes only the completion columns, and completes a row at most once. The first
  completion stands. The same completion written again is success. A different one is an
  error, and is logged and counted.
- The answer waits for finish for at most the answer budget and then goes out regardless,
  because withholding the result of a call that already happened invites a retry. Finish keeps
  retrying by identifier until the finish deadline. A finish not written by then is a telemetry
  event naming the row, the outcome's kind and, for a side effect, the vendor's reference. It
  never holds the result. The row stays open.
- A connector's refusal is the exception. Nothing ran, and a refusal is not handed out
  unrecorded. If its completion is not confirmed within the answer budget, the caller reads the
  audit-failure sentence, which is still true: nothing ran. The row may be completed as
  `refused` afterwards.
- Finish, receipt settlement and reconciliation's short writes use a small connection pool of
  their own, so a surge of begins cannot starve the writes that close rows.

The core has no timer, so the store keeps the answer budget. Its `finish` waits for the write
for at most the budget and then returns, with an error if the row is not yet complete, while
the write goes on retrying on a task of its own until the finish deadline. The Postgres store
built for #10 must do this. The in-memory store must do the same, so the contract suite can
test it on both.

### Outcomes

`ok`, `error` and `refused` keep their meanings. Two are new. `unknown` applies to side effects
only. It means the connector sent the request and got no definite answer: a timeout, a dropped
connection, or a server error after the request was sent. A side-effecting connector reports
`error` only when it knows the vendor did nothing, because the request failed before it was
sent or the vendor definitely rejected it. A proxied tool's error is `unknown` unless its
approval says its errors are safe. A read never reports `unknown`. `duplicate` belongs to
part 2: nothing ran, because the same request was already completed.

### Open rows

Nothing writes to an audit row except begin and finish, and nothing marks it afterwards. What
a row of kind `call` means follows from its columns and the database's clock:

| Decision | Outcome | Deadline | Meaning |
| --- | --- | --- | --- |
| deny | empty | — | The complete record of a denial. Nothing ran. |
| allow | set | — | What the gateway learned. |
| allow | empty | not passed | In flight, or its finish is still being retried. |
| allow | empty | passed | Open. The gateway never learned what happened: the call may have completed, partly run or not run. For a side effect, the receipt settles which. |

An empty outcome means no outcome was durably recorded. It is never evidence that a call is
safe to repeat. Open rows are found by a query, counted and exported; alerting waits for Still
open 9. A finish that arrives after the deadline is still written, and the row then shows what
the gateway learned late.

Rows are never edited by hand. A person's finding about a row or a receipt is a resolution
record: what it concerns, what the person concluded and from what evidence, who they are as
proved by the path they used, and the database's time. Resolution records are appended and
never changed. Which path that is, and who may use it, is still open (Still open 10). Until it
is settled no resolution is recorded, and an open row stays in the open-row query.

### The database role

On the audit table, the gateway's role may insert every column except the times, which the
database sets. It may select the identifier, kind, decision, deadline and completion columns,
which finish, a retried begin and the open-row query need. It may update the completion
columns. It cannot delete, and it cannot read who called what on the audit table. Receipts,
which the reuse check must read, do expose the principal, tool and resources of each side
effect to the same role (part 2). A trigger refuses any update to a completion that is already
set, so "at most once" holds in the database and not only in code. The receipt table has
grants and a trigger of its own (part 2). The boot check on the role in section 12 also checks
both tables' grants, and that all three triggers exist and are enabled: the one that sets the
times, and the two that refuse updates. Deletion for retention uses a separate role (Q12).

### Shutdown

On termination, an instance first fails its readiness check, then stops accepting calls, and
lets running calls and their finishes complete. Its termination grace period must be longer
than the readiness-removal delay plus the begin budget, the call deadline and the finish
deadline, or every deploy leaves open rows. Kubernetes' default of thirty seconds is shorter
than that, so it is set explicitly.

### Provisional values

Two seconds for the begin budget. Two seconds for the answer budget, as in Otto. Thirty
seconds for the finish deadline, counted from when the tool returns. Call deadlines are set per
tool. The owner accepted these as defaults on 2026-10-07. Q12 owns all of them, and sets the
final values from the first slice's measurements.

### Signals

Counted and exported from milestone 2: begin failures and the audit-failure answers they
cause; answers released before finish; finishes not written by their deadline; open rows;
receipts in `unknown` and the age of the oldest; begin and finish latency; connections in use
per pool; telemetry dropped. Alert thresholds, paging and who is paged are set before the first
production deployment, not for the mock slice (Still open 9).

## Decision, part 2: receipts for side effects

### What a receipt is

A receipt is the gateway's durable record of one side effect it was asked to cause. It holds
the proved principal, the delegation fields that scope its key, the tool, the key, the caller's
tool-use identifier if it sent one, a digest of the arguments, the audit row, the resources the
call named and the vendor target a marker lookup needs (a repository, a Jira project), a state,
how that state was established, the lookups made, and, once known, the vendor's reference for
what was made: a pull request number, a comment identifier. It is not a copy of the result.
Reads have no receipt. Receipts are a table of their own, because a receipt can change after
its row is final, and an audit row must not. They are unrelated to Otto's `/pr-receipt`
endpoint.

A receipt is reserved as `pending` in the same transaction as the begin of an allowed call. A
denied call reserves none, so a denial does not use up a key. Where finish settles a receipt,
it moves in the same transaction as the finish.

| State | Meaning |
| --- | --- |
| `pending` | Reserved; no outcome yet. A receipt still `pending` after its row's deadline is treated as `unknown` wherever it is read. |
| `completed` | The vendor confirmed the effect. Its reference is recorded. |
| `not_performed` | Established, not assumed, that nothing took effect: the connector refused, the request was never sent, the vendor definitely rejected it, or an authoritative lookup found nothing. |
| `unknown` | The request may have reached the vendor and the result is not known. |

A receipt leaves `pending` once, for any of the other three. It leaves `unknown`, or a
`pending` past its deadline, only by reconciliation or a person, for `completed` or
`not_performed`. Every move records how it was established: by the call that reserved it, by
reconciliation, or by a named person in a resolution record. Nothing returns to `pending`, and
the gateway never deletes a receipt. The gateway's role may insert and select receipts,
including their resources and vendor target, which reconciliation needs, and may update only
their state, reference and lookup columns. A trigger refuses every move the states above do
not allow. So the role that cannot read who called what on the audit table can read who caused
each side effect, on which tool and where. The reuse check needs the principal, the delegation
fields and the tool, and reconciliation needs the resources. Whether receipts need more
protection than this is part of Still open 7.

When the instance making a call knows nothing was sent, it settles the receipt as
`not_performed` itself and completes the row as `error`. That happens when the caller
disconnected before the connector was called, and when begin was never confirmed; in the
second case it keeps trying on the finish pool until the finish deadline. A late finish that
disagrees with a receipt reconciliation has already settled is written to the row. The
receipt is left as it is, and the disagreement is logged and counted; alerting waits for Still
open 9.

### The key

The key is chosen per request, never per connection. MCP clients set headers once per server,
so a client configured with a fixed `Idempotency-Key` would have every later side effect
answered as reuse. The carriers are the caller's tool-use identifier, a named `_meta` field
for callers that are not models, such as Otto's control plane, and a header only from a
profile that declares its callers set it per request. The owner accepted these carriers, in
this order, on 2026-10-07. What Otto's control plane sends is agreed with Otto's owners (Still
open 8).

The MCP specification defines no tool-use identifier. Claude Code sends one as
`claudecode/toolUseId` in the request's `_meta`, and Otto's gateway stores it; other clients
may send none. A client that sends no tool-use identifier and cannot set the named `_meta`
field carries no key, so it cannot make side effects through this gateway. Q13 checks this
for each target client.

A call that carries both a key and a tool-use identifier records both. The same key arriving
with a different tool-use identifier is refused with a sentence of its own, because that is
what a key fixed in configuration looks like.

A key is scoped to the proved principal and, when a delegation is present, to the delegation's
identifying fields: for Otto, the session and the turn, to be confirmed with Otto's owners
(Still open 8). They are also asked whether a turn is unique only within an execution, which
decision 0012 adds to a grant's verified fields, so the scope needs the execution too. Many
sandboxes share one workload subject, and one person uses several clients, so a principal alone
is too wide. Within its scope a key is unique across all tools. Without a delegation, two
clients of one principal can still choose the same key. With tool-use identifiers that is
unlikely, and a collision is answered by the reuse table below, never across principals.

A side-effecting call that carries no key is denied by the decision function, with a reason
kind and a sentence of its own asking for one, since that is knowable before anything runs. It
is the last check, after check 6 and after decision 0012's currency check, so a caller is asked
for a key only when the call would otherwise be allowed, and every permission denial keeps its
own reason. It is skipped for `tools/list`, as the currency check is, because a list request
carries no key: a `propose` tool is listed to a caller who may call it, and denied on
`tools/call` without a key. With identity disabled there is no principal to scope a key to, so
no side effect is served at all (see "Until receipts exist").

### The argument digest

SHA-256 over the arguments as canonical JSON (RFC 8785), except that integers are written
exactly rather than as doubles, so two different large integers never share a digest. The core
hashes the value the guard carries; it still does not parse a tool's arguments. The cost is
that anyone who can read receipts can test a guess at arguments that have few possible values.
The owner decided on 2026-10-07 that this digest is not storing the arguments under Q12's rule,
and accepted that cost.

### Reuse

A call whose key already has a receipt in its scope does not run. The check happens at begin,
in the same transaction as the reservation. It ignores a receipt reserved under this call's
own row, so a retried begin never refuses itself. The first line that matches decides:

| Earlier receipt | Outcome | What the caller reads |
| --- | --- | --- |
| Recorded a different tool-use identifier | `refused` | The key was reused for a different call. |
| A different tool or digest | `refused` | Conflicting reuse, naming the key. |
| Same tool and digest, `completed` | `duplicate` | A successful result: it was already done, with the reference and the receipt identifier. |
| Same tool and digest, `pending` or `unknown` | `refused` | It may already have happened, must not be repeated, and will be checked as that receipt. |
| Same tool and digest, `not_performed` | `refused` | Nothing was done. A new attempt needs a new key. |

Each is an allowed row written already complete, so every attempt is on record. A completed
duplicate is answered as a success because an error invites the model to try again by another
route, under a new key, which is the duplicate receipts exist to prevent. Like a connector's
refusal, this check cannot make anything run. It decides about delivery, not permission. A key
is used once, which keeps the states simple and the answers unambiguous.

### Reconciliation

A side-effecting tool's approval declares how an `unknown` receipt is settled: by a lookup, or
by a person.

- **A lookup** finds the effect by a marker the gateway attached to the request, carrying the
  receipt identifier: in a draft pull request's body, in a comment. A lookup matches the
  marker, never a field the caller chose alone. A branch name can match a pull request made by
  an earlier call or by a person.
- **A vendor's idempotency key** is not a way to settle anything. Where the vendor honors one,
  the connector sends the receipt identifier as that key on the request. That makes a resend
  the gateway did not intend, such as an HTTP client's automatic retry, harmless. Using it to
  settle an `unknown` would mean sending the request again.

Reconciliation only looks. It never sends anything again. It concludes `not_performed` only
from an authoritative lookup, one the vendor documents as complete and current, because a
search that finds nothing proves nothing. A lookup is not a tool call and has no audit row. It
uses a read credential narrowed, through the custodian, to the team of the receipt's principal
and the vendor target and resources the receipt records, and the custodian keeps its own
record. Each lookup is recorded on the receipt.

Every instance works the queue of unknown receipts, so no separate deployment is needed. An
instance claims a receipt by setting a short lease in a transaction that commits before the
vendor call, so no lock or connection is held across it. Each receipt is looked up a bounded
number of times and then handed to a person, who records a resolution. With no declared lookup
it goes straight to a person. A `propose` tool may be approved with no lookup: a duplicate
proposal is a second draft or comment, which a person sees before acting on it. A `write` tool
allowed under a recorded exception (decision 0011) is treated like any side effect: it needs a
key, a receipt and the gate in "Until receipts exist". It must declare a lookup by marker,
which a comment can carry, unless its exception says otherwise, because a lookup is the
default and the allowance for no lookup is for `propose` only. Whether a `write` tool could
otherwise be approved without a lookup, and who could grant that, is for the decision that
permits direct writes.

### What may be retried

| Who | May retry | Must not |
| --- | --- | --- |
| A connector | A read, within the call deadline. A side effect only if it failed before any byte was sent. | Resend a side effect once any byte was sent, with or without a vendor key. Retry anything across a restart or after rebuilding an upstream session. |
| The gateway | Its own audit and receipt writes, by identifier. Reconciliation lookups. | Repeat any tool call. |
| The caller | Any read. Any call answered with a denial. Any call answered with the audit-failure sentence at begin, using a new key for a side effect. A side effect with the same key and tool-use identifier, which the receipt answers without running it. A `not_performed` call with a new key. | Repeat a call it was told is `pending` or `unknown`. The gateway cannot stop a caller that uses a new key; it can only give the sentence and the receipt identifier. |

A receipt does not make a side effect happen exactly once. A new key, a vendor's own retries,
and a turn that Otto's control plane replays each produce a new call. Receipts cover a resend
of the same call. They cover a replayed turn, including one replayed after a control-plane
failover, only if Otto's control plane sends a key that stays the same across replays, which
is part of Still open 8. A replayed turn's model makes new tool-use identifiers, so a key taken
from them does not. Until Otto's owners agree such a key, two control planes driving one
session can propose twice, and decision 0012's currency check makes that unlikely, not
impossible. This record is where that window is stated. A vendor effect that reconciliation
cannot see stays `unknown` until a person settles it.

### Until receipts exist

The gateway binary refuses a snapshot that serves any tool not classified `read` unless a
receipt store is configured, audit is on and identity is on. It checks at boot and at every
snapshot swap, whatever the snapshot's source. The check is in the binary, not in policy data,
so no profile setting can change it. Only the harness's test builds are exempt, so proposals
can still be tested against fixture connectors. `#[cfg(test)]` cannot provide that exemption,
because the harness runs the gateway end to end from integration tests and other crates,
which do not see it. The exemption is a test-support cargo feature that the release build
never enables. Since a feature can be turned on in any build, CI checks the release artifact
itself: started with a snapshot holding a `propose` tool and no receipt store, it must refuse.
The rule holds whatever Q12 decides about opt-outs, which it recommends allowing only in
development builds.

Decision 0011 says that until receipts exist, only proposals that create something are served
to employees and services. This record supersedes that sentence: until receipts exist no
proposal is served at all. Once they exist, a proposal that changes something existing also
needs the connector's creation check that decision 0011 describes.

## How it is tested

The in-memory store and the Postgres store pass one contract suite: the same test functions,
run against each. The fake runs it in the per-change loop and Postgres in the slow loop. A fake
that can do what Postgres cannot tests nothing.

1. `begin` returns `Ok` only once the row is stored, and is idempotent by identifier.
2. The stored row is exactly the record given, including the resources.
3. `finish` completes a row once, accepts an identical repeat, refuses a different one, and
   touches only the completion columns. A refusal is a returned error, not a panic.
4. Times and deadlines come from the store's clock: database time for Postgres, the
   deterministic clock for the fake. The deadline includes the begin budget. Times the insert
   carries are overwritten, and a row of kind `call` cannot be stored with no deadline.
5. The open-row query returns exactly the allowed rows of kind `call` with no completion past
   their deadline. A `tools/list` row is never open.
6. Once receipts are built: a receipt is reserved with its row or not at all, and moves with
   its finish. A key stays unique in its scope under concurrent calls, and two delegations
   under one principal can use the same key. A begin retried after a lost confirmation finds
   its own receipt, runs once, and is not refused as reuse. A begin whose confirmation was lost
   on every attempt leaves its row completed as `error` and its receipt `not_performed`.

The fake can be told to fail before writing; to write and then report failure, which is a lost
confirmation; to hang until released, to test the budgets; and to lose the process between run
and finish, where the test builds a new gateway over the same store. The core's test store
panics on a second finish today. It changes to accept an identical one and return an error for
a different one. The Postgres store refuses to start with `fsync` or `full_page_writes` off,
with any of the three triggers missing or disabled, or on a role wider than its own.

| Rule | Per change, on fakes | Slow loop | Mutation that must be caught |
| --- | --- | --- | --- |
| Nothing runs before begin commits. | Begin hangs; the connector is never called. | Postgres made unavailable. | Run before begin. Already a compile-fail test. |
| A begin not confirmed within its budget runs nothing. | The fake writes, then reports failure on every attempt; the row is completed as `error`. | The connection is killed after commit. | Retry begin under a new identifier. A lost confirmation left open. |
| Identity failures write no row; unverifiable delegations do. | A bad token makes a telemetry event and no store call. A forged grant under a good token makes a deny row at check 3 with nothing from the grant. | — | Identity failure routed through begin. Bad grant sent to telemetry. Bad grant denied before the function. |
| A `tools/list` row is never open. | List rows past any deadline; the open-row query returns none. | The same. | The query without its kind filter. |
| The answer waits for finish at most the budget. | Finish hangs. The answer arrives at the budget, and the row completes once released. | A trigger slows finish on Postgres. | Answer before finish. Wait without a budget. |
| A disconnect cancels no store write, and no side effect once sent. | An in-process HTTP client dropped during begin, during a read and during a side effect. | Otto's `TestDisconnectStillFinishesAudit`, from milestone 4. | Begin, run or finish on the request's future. A side effect cancelled on disconnect. |
| A row is completed at most once. | Identical repeat accepted; different completion refused. | The same, and a direct update refused by the trigger. | Finish overwrites a completion. |
| Nothing writes an outcome the gateway did not learn. | The process is lost between run and finish; the row reads as open after its deadline. | The gateway is killed after a vendor write and restarted. | A restart completes open rows as `error`. A deadline without the begin budget, or shorter than the call deadline. |
| The role cannot change a decision, read who called what on the audit table, set a time, or delete a row. | — | Boot refuses wider grants, or a missing or disabled trigger; an insert carrying its own times has them overwritten. | The role check removed. The trigger that sets the times removed. |
| A side effect without a key is denied, and only on `tools/call`. | A `propose` tool appears in `tools/list` without a key, and is denied on `tools/call` without one, with the sentence asking for a key. A call that also fails an earlier check gets that check's reason. | — | The key check applied to `tools/list`. The key check placed before a permission check. |
| A side effect is not run again under the same key. | A fake vendor with side effects, called twice with one key. | The crash run, then a retry with the same key. | Argument digest ignored. `pending` treated as `not_performed`. A reuse check that does not ignore its own row. |
| A key fixed in configuration is caught. | One key with two tool-use identifiers is refused with its own sentence, not answered as a duplicate. | — | The tool-use identifier ignored by the reuse check. |
| `unknown` is never offered as safe to repeat. | Each receipt state against each reuse. | Reconciliation against the fake vendor. | `unknown` mapped to `not_performed`. An empty search concluded `not_performed`. A lookup by branch alone. |
| No side effect reaches a real system without receipts. | A snapshot with a `propose` tool refused at boot and at swap without a receipt store. | CI starts the release artifact with such a snapshot, and it refuses. | The check removed, or keyed on where the snapshot came from. The test-support feature enabled in the release build. |

Milestone 2 needs part 1 without the two new outcomes: identifiers, budgets, the detached
task, the grants and trigger, the open-row query and the signals. Part 2 is needed before the
first side effect reaches a real system, which is milestone 4 at the latest. The suite and
this table are also in section 18 of the design.

## Alternatives rejected

- **Finishing after the answer,** as Otto's gateway document describes and its control-plane
  document proposes for reads. Otto's gateway in fact waits, and Otto's control plane reads the
  row back by tool-use identifier after the answer, so the row should be complete by then
  whenever the store is healthy.
- **Recording reads asynchronously.** That is two paths to build and test, a queue whose loss
  rules must be stated, and a read record that is lost when the database is struggling, which
  is when an incident review most needs it. Q4 already accepted the cost of the synchronous
  write. The mock slice cannot measure that cost under real traffic (decision 0008). If the
  real workload in milestone 2 shows it is too high, this is the first thing to reconsider.
- **Withholding a read's result when its finish fails.** A read changes nothing, so this is
  safe, and an empty outcome on a read would then mean nothing was delivered. It is rejected
  because the row begun before the read already records who read which resources; because it
  turns a database fault after the vendor call into a failed call and a second vendor read; and
  because the audit-failure sentence says nothing ran, which would be false, so it would need a
  sentence of its own. The owner kept this rejection on 2026-10-07.
- **Other placements of the three records:** a synchronous row for every failed
  authentication, as Otto writes; telemetry for a delegation that cannot be verified; no row
  for `tools/list`. The reasons are given above. Leaving out `tools/list` would also narrow
  invariant 5.
- **Marking open rows abandoned, or writing `error` or `unknown` into their outcome.** Recovery
  learns nothing about what a tool did, and the outcome column is the one a review trusts most.
  A marker needs the role to write rows after finish. The deadline column answers the same
  question with a query.
- **Refusing a finish after the row's deadline,** so a row is final at its deadline. That
  removes a race with recovery, but recovery here writes nothing to rows, and it would discard
  what the gateway learned late.
- **Detecting dead instances by heartbeat.** The deadline makes it unnecessary, and a heartbeat
  could treat as lost a row that a slow but live instance is about to finish.
- **Letting the store assign row identifiers.** A lost confirmation then makes begin impossible
  to retry safely, and an event cannot name the row it failed to write.
- **Attempting finish once.** It has fewer moving parts, but one transient fault leaves an
  empty outcome on a call whose result the gateway knew.
- **Begin on the request's future, with only run and finish detached.** A disconnect during a
  slow begin would leave a committed row that nobody finishes, and a receipt handed to a person
  although nothing ran.
- **Using the audit row as the idempotency record,** or putting the key on the row. A row
  records one attempt, denials included, and merging attempts would hide retries from auditors.
  Reconciling would also change an audit row after its finish.
- **Deriving the key from the principal, tool and arguments.** It needs nothing from the
  caller, but it treats two deliberate identical comments as one, and gives a retry no way to
  say that it is a retry.
- **Other choices about keys argued above:** the `Idempotency-Key` header as the first choice
  of key, a key scoped to the principal alone, and a completed duplicate answered as a
  refusal, which would also widen `refused` beyond a decision not to act.
- **Running a `not_performed` call again under the same key.** It suits a transport that
  resends, but it sends a receipt back to `pending` and makes the answers ambiguous.
- **Other choices about reconciliation argued above:** a vendor's idempotency key as a way to
  settle `unknown`, a lookup by a field the caller chose, and a row lock held across a lookup,
  which would hold a connection from the small finish pool for a network call.
- **Running reconciliation as a separate scheduled job.** It is another deployment holding
  database credentials. A lease lets every instance share the work.
- **Gating side effects on where a snapshot came from.** A registry served by an API, from
  milestone 6, would pass the gate, and the core cannot tell sources apart.
- **Replaying a side effect whose outcome is unknown,** after a restart, a reconnect or under
  any other condition. Q5 and Q10 both rule it out. A replay is a second write.
- **Promising exactly-once execution.** No local record can.

## Consequences

- Invariant 5 becomes: "No tool runs, and no authorization decision is returned, without an
  audit row." Its exceptions are the telemetry list in section 11 and the fixed audit-failure
  answer. Two invariants are added: "The gateway never repeats a tool call on its own" and "A
  side effect that may have happened is never presented as safe to repeat."
- The core's interface changes. `begin` takes the identifier the gateway chose. `finish`
  gives out the answer once the store's finish returns, which is within the answer budget.
  `ToolOutcome` gains `unknown` and a vendor
  reference, and the record's outcome gains `unknown` and `duplicate`. `Begun` gains a call
  answered at receipt reservation. A guard can be given up without running, which completes
  the row as `error`. The record gains its kind, the instance, the database's time, the
  deadline, and a list form that names the tools returned. `RequestMetadata` gains the key.
  Connectors for side-effecting tools must tell "not sent" apart from "sent, with no answer".
- Decision 0006 gets a dated amendment. The delegation in the call context can be present and
  unverified. The verifier passes it on with only the kind of failure, and check 3 denies it
  with a single reason kind of its own; the verifier never denies on its own. Decision 0012's
  amendment to 0006, accepted the same day, says the verifier's checks run before the function
  and none of their failures is a reason kind. Both hold under this model, and 0012's paragraph
  is to say that the function then denies at check 3. The context says whether the request
  carries a key, and a tool not classified `read` without one is denied with a reason kind of
  its own, by a last check after check 6 that is skipped for `tools/list`. The receipt check is
  a second decision made outside the function. Like a connector's refusal it cannot make
  anything run, and it decides about delivery, not permission. The outcome set gains `unknown`
  and `duplicate`.
- Otto parity changes, to be agreed with Otto when its adapter is built. This gateway writes no
  row for identity failures, `initialize` or `ping`, and a 401 during an audit outage carries
  the opaque identity sentence, not the audit-failure one. Otto's `gateway_audit` table has no
  `unknown`, no `duplicate` and no deadline. The adapter leaves the outcome empty for
  `unknown`, never `error`, and writes `ok` for `duplicate`, since the effect exists. Open rows
  are found from this gateway's own record. A side effect is no longer cancelled when the
  client disconnects. `TestRepeatedCommentIsWrittenTwice` fails on purpose once receipts are on
  for Otto's profile, and moves to the existing-behavior group with the divergence recorded.
  Otto's control plane reads rows back by tool-use identifier. A `duplicate` row, and a row
  refused as reuse, carry the same tool-use identifier as the original call, so that read can
  return more than one row; how it picks one is agreed with Otto's owners (Still open 8).
  Unchanged: the answer budget, a failed finish, a read cancelled by a disconnect, and rows for
  unverifiable grants.
- Otto's control plane must send a stable key for the actions it asks for, in the agreed
  carrier. It must treat both "may already have happened" and an empty outcome on a row it
  reads back as an instruction not to repeat. How it learns that a receipt was settled later is
  agreed when the adapter is built.
- Only clients that send a tool-use identifier, or can set the named `_meta` field, can make
  side effects. Claude Code can. Q13 checks each employee client it accepts, before milestone 5
  serves employees any `propose` tool.
- Every read waits for begin, and for finish up to the answer budget. The mock slice measures
  both writes and what a slow database does to them. Their cost under real traffic waits for
  the real workload.
- An authentication flood no longer writes to the audit store. Q12's overload question is
  reduced to begins from proved callers.
- Q12 owns the provisional values, pool sizes, alert thresholds, and how long rows, receipts
  and resolution records are kept. How long telemetry is kept is Still open 3. A key is honored
  only while its receipt is kept.
- Deployments set their termination grace period and readiness delay explicitly.
- The resources a self-scoping tool actually reached belong in finish when they are added.
- The grants and triggers do not protect rows against a database superuser who rewrites them.
- Fencing is decided under Q18 (decision 0012). Nothing here depends on it. The window it
  leaves for a replayed turn is stated once, under "What may be retried".

## The owner's answers

The owner accepted the record on 2026-10-07, taking the recommendation on every question that
was the owner's to answer. Each answer carries the proposal's number.

- **2. A read's result goes out when its finish fails,** as in Otto. Withholding it stays
  rejected (see Alternatives rejected).
- **3. Identity failures, `initialize` and `ping` are telemetry,** as the table of three records
  says. Unverifiable grants stay audit rows. Whether Otto's adapter still writes them into
  `gateway_audit` is for Otto's owners (Still open 2).
- **9. The provisional values are the defaults:** two seconds for begin, two seconds for the
  answer to wait, and thirty seconds for finish. Q12 sets the final values from the
  measurements.
- **12. The key's carriers** are the tool-use identifier, a named `_meta` field, and a header only
  from a profile that declares its callers set it per request, in that order. A side effect
  that carries no key is denied. What Otto's control plane sends, and which grant fields
  scope a key, need Otto's owners (Still open 8).
- **13. A `propose` tool may be approved with no lookup.** A duplicate proposal reaches a
  person before it acts. A `write` tool allowed under a recorded exception (decision 0011)
  declares a lookup by marker unless its exception says otherwise. Whether any other `write`
  tool could be approved without one is left to the decision that permits direct writes.
- **14. The argument digest does not count as storing the arguments** under Q12's rule.
- **15. Receipts come before the first `propose` tool** reaches a real system, not only before the
  first `write` tool. The risk of a duplicate draft pull request or comment is not accepted.
- **16. Both parts are accepted now.** Q10 is narrowed to what compliance requires of read
  auditing.

## Still open

Each of these needs someone other than the owner, alone or with the owner. The record holds
while they are open; what applies until each is answered is stated with it. The first side
effect to reach a real system waits for 9 and 10, so that a receipt reconciliation gives up on
has someone to settle it and a way to record the result. Otto's cutover of writes also waits
for 8.

1. **What compliance requires of read auditing,** if anything: coverage, immutability and
   retention. Compliance decides. Until it answers, reads are written synchronously, on Q4's
   acceptance. A stricter or looser requirement would change part 1. Issue #3 stays open until
   it answers. (Proposal 1.)
2. **Whether Otto's adapter still writes identity failures, `initialize` and `ping` into
   `gateway_audit`.** Otto's owners decide, when the adapter is built (#22, #23). Until then
   this gateway writes no row for them, and that is a recorded parity difference.
   (Proposal 3.)
3. **Where telemetry goes, how long it is kept, and who can read it,** and whether the audit
   table is the compliance system of record or is exported to one, such as Sumo Logic.
   Whoever runs logging decides, with compliance for the system of record. Until then
   telemetry is the gateway's structured events and counters, and the audit table is the only
   audit record. (Proposal 4.)
4. **Whether evidence of failed authentication may be dropped** by the bounded telemetry queue
   under load, or needs a durable sink. The security team decides. Until then it goes through
   the bounded queue, and drops are counted. (Proposal 5.)
5. **What "committed" means:** the primary only, or also a synchronous standby and
   point-in-time recovery. A standby costs latency and joins the gateway's availability, and
   it is the only way a begin survives a failover. Whoever runs Postgres decides, probably IT.
   Until then a begin is committed on the primary, with synchronous commit, and does not
   survive a failover. (Proposal 6.)
6. **Who owns the audit and receipt schema,** its grants, its triggers and its migrations. The
   proposal made no recommendation. The owner decides with whoever will own the audit
   database, under Q12. Until then the schema and its migrations live in this repository.
   (Proposal 7.)
7. **Tamper evidence beyond grants and triggers,** such as an append-only copy or a hash chain,
   and who holds the database superuser login. This covers receipts as well as rows, including
   whether the gateway's role should see less of a receipt than the principal, tool and
   resources, for example by finding a key through a keyed hash. The security team and the
   storage owners decide. Until then the grants and triggers are the only protection, they do
   not stop a superuser, and the gateway's role can read receipts. (Proposal 8.)
8. **Otto's key:** the carrier Otto's control plane uses, Otto's tool-use identifier as its
   key, and which grant fields scope a key. The session and the turn are recommended. Otto's
   owners are also asked whether the scope needs the execution; whether the control plane can
   send a key that stays the same when it replays a turn, without which receipts do not cover a
   replay; and how its read-back by tool-use identifier treats the `duplicate` and reuse rows
   that share one with the original call. Otto's owners decide (#21, #22). Until then Otto's
   callers make every side effect through Otto's Go gateway: the cutover of writes waits for
   this answer. (Proposal 12.)
9. **Who is paged, and on whose rotation,** for begin failures, open rows and unknown receipts,
   and who settles a receipt by hand once reconciliation gives up, including whether the
   owning team in the registry is accountable for it. Whoever runs the on-call rotation
   decides, with the owning teams, before the first production deployment. Until then the
   signals are counted and exported and nobody is paged. The mock slice needs no paging.
   (Proposal 10.)
10. **How a person records a resolution:** through which authenticated path, and who may. The
    proposal made no recommendation, and the path is partly a design choice. The owner decides
    with the security team, before part 2 reaches a real system. Until then no resolution is
    recorded, open rows stay in the open-row query, and part 2 does not reach a real system,
    so no receipt there can be `unknown`. (Proposal 11.)
