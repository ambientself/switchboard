# Feedback loops for the build

Date: 2026-10-01. Status: proposal, revised after the design review. How to find out quickly whether a change to the gateway is
right, once building starts. Nothing here is built yet.

## The three loops

| Loop | Target time | Answers | Runs on |
| --- | --- | --- | --- |
| Inner | Seconds | Is this decision, sentence or type right? | Every save |
| Per-change | Under two minutes | Does the gateway still behave, end to end, over HTTP? | Before every commit |
| Slow | Minutes | Does it hold against real Postgres, Otto's real gateway and Otto's latest code? | CI and a schedule |

A check belongs in the fastest loop that can run it honestly. The slow loop exists for what
the faster ones cannot see, not as the place tests go by default.

## Inner loop: the core with no I/O

`gateway-core` holds principals, classification, the decision function and the denial
sentences, and performs no I/O. That is what makes this loop possible: it compiles in a second
or two and its tests need nothing running.

- **A decision table as data.** One file of cases: principal, profile, surface, tool,
  delegation, expected decision and expected sentence. The tests iterate it. Adding a policy
  rule means adding rows first and watching them fail. The same file is readable by someone
  reviewing policy who does not read Rust.
- **Compile-fail tests** for the guarantees the design puts in types: a claimed value where a
  proved one is required, a tool run without an audit guard, an unrecognized classification
  registered.
- **Property tests** for rules that must hold for every input: a tool with no classification
  never runs; principals from different issuers never compare equal; for any snapshot that
  loads, every admitted team's and group's limit holds the whole reach of every tool on its
  surfaces whose resources are its reach, or that is proxied with narrowing `none`
  ([decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md)).
- **Loader table cases,** one for each of the snapshot loader's nine rules in decision 0011,
  each with a mutation in `scripts/mutation_check.py`.
- **Golden files** for JSON-RPC envelopes and denial sentences, so a changed sentence shows up
  as a diff to review.
- **A watcher** that re-runs the core's tests on save.

## Per-change loop: the whole gateway in one process, on fakes

Every dependency the gateway has sits behind a trait in the design: the audit store, the
credential custodian, connectors, identity verifiers. Each gets an in-memory fake that tests
can script, including to fail.

- **In-process end-to-end tests.** Start the real HTTP server on a loopback port inside the
  test process with fakes behind it, and drive it over HTTP. No Docker, no database, no
  second binary. This is where "audit begin fails, so the call is refused" is tested in
  milliseconds, by telling the fake store to fail.
- **A fake MCP server and a fake vendor API** as a crate, scriptable to list tools, change its
  tool list, stream slowly, hang and return errors. Proxied-server work is tested against it.
- **Decision 0011's checks on fakes:** an undeclared argument never reaches the fake MCP
  server; a `call`-narrowed token request names exactly the call's resources; a fake vendor
  whose reach is widened between runs causes withdrawal, and later rows carry the
  withdrawal's own snapshot revision; the AWS account filter holds against
  hostile parameters; and each built-in `propose` tool changes only refs, pull requests and
  comments it created or that its receipts or resolver attribute to it, with the fake vendor
  recording every write's target.
- **A local issuer** that signs user and workload tokens, so nothing waits on Okta.
- **One command to run it by hand.** The gateway on fixtures, plus a scripted client that
  runs initialize, list and one call and prints what came back.
- **A real client from the first day.** Point a real MCP client at the local gateway. The
  protocol questions in Q13 get answered by trying it, weeks before employees' agents are a
  milestone.

## Slow loop: the real things

- **Real Postgres** for the audit store: begin, finish, failure, and the latency the
  synchronous write adds. A local Postgres left running with a fresh database per run can
  bring the audit store's own tests into the per-change loop.
- **Fuzzing** of JSON-RPC bodies, grants and tool arguments, and of the resource adapters
  that read them.
- **A vendor reach test** for each proxied connector entry, before exposure and after any
  vendor-side change to its credential (decision 0011).
- **Failure runs:** a slow or unavailable database, a hanging upstream, a crash after a vendor
  write and before the audit row is finished.
- **Otto's conformance suite against both gateways, from milestone 4.** Today the suite is
  tied to the Go binary's flags. Give it a target adapter (start this gateway in this mode,
  map these tool names) so the same scenarios run against Otto's Go gateway and the Rust one.
  The count of scenarios passing against Rust is then the progress measure for Otto's
  cutover.
- **The mutation check,** after any change to the suite or the pin.
- **A scheduled re-pin trial.** Run the suite against Otto's latest `main` on a schedule,
  without moving the pin. Failures are the list of what Otto changed. This turns drift from a
  surprise 269 commits later into a weekly report.
- **Shadow comparison, later.** Before Otto's cutover, send copies of Otto's real read calls
  to the Rust gateway and compare answers and audit rows with the Go gateway's. Reads only; a
  copied write would act twice.

## What to build first so the loops exist

1. The policy core and the decision table, with the watcher.
2. The traits and their in-memory fakes, before any real implementation of them.
3. A walking skeleton: the endpoint, the fixture tool and the fakes, reachable with one
   command and one HTTP request.

These three are milestone 1 of the design. The conformance target adapter waits for
milestone 4, when Otto's adapter is built.

## What in the current plan would make feedback slow

| Risk | Why it is slow | What avoids it |
| --- | --- | --- |
| Audit before answer on Postgres | Every end-to-end test would need a database. | The store is a trait; Postgres only in the slow loop. |
| The conformance suite as the only end-to-end test | It builds three Go binaries and starts a container. | In-process tests for the core; the suite for Otto parity only. |
| Okta | IT owns it and access is slow. | The local issuer; Okta only at milestone 5. |
| Real vendor MCP servers | Accounts, rate limits and the network. | The fake server crate; one real server late. |
| Otto-owned state in tools | Tests would need Otto's schema and control plane. | Decision 0003 keeps that state in Otto, behind a resolver interface the gateway fakes. |
| Otto's conformance suite early | A moving pin turns ordinary core changes into compatibility investigations. | The suite is not run against the Rust gateway until milestone 4. |
| Many crates before the interfaces settle | Every interface change touches several crates. | Start with few crates and split along the trait lines later. |
| Compile time | A large crate graph rebuilds slowly. | Keep `gateway-core` free of heavy dependencies; split crates along the trait lines. |
