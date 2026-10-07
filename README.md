# MCP gateway

The one MCP path for Org, planned in Rust. Every agent in the company reaches tools through
this gateway: it proves who is calling, decides whether the call is allowed, shows each caller
only the tools it may use, attaches the credential on the server side and writes an audit row
before answering.

Otto, Org's platform for running agents in Kubernetes sandboxes, is one caller. It has a
working gateway of its own, written in Go at `cmd/otto-gateway` in the `otto`
repository, and a written contract for gateway behavior. This design applies that contract's
mechanisms company-wide and adds what a company-wide gateway needs beyond it: several kinds of
caller, proxied MCP servers and a registry. The model for those additions is DoorDash's Agent
Gateway
([write-up, 2026-07-30](https://careersatdoordash.com/blog/how-doordash-built-a-centralized-gateway-for-ai-agent-tool-access/)).

**Status: conformance baseline.** The suite passes against the Otto Go gateway pinned at
`752395a` (re-pinned 2026-10-01). It covers Otto's contract only, and not all of it; the
gaps are listed in [docs/otto-baseline.md](docs/otto-baseline.md). The Rust gateway's policy
core exists (`crates/gateway-core`: the decision function, its table of cases and the audit
record type). The gateway serves MCP over HTTP in both revisions (`crates/gateway`), but only
on test fakes: it has no durable audit store and no real connectors yet. The Postgres audit
store (`crates/audit-postgres`), the registry (`crates/gateway-registry`), the proxy
connector (`crates/connector-proxy`) and a mock document server exist as crates, and the
demo's deployment is in [deploy/](deploy/README.md), but the `switchboard` binary does not
use them yet.

Run the baseline with `python3 conformance/run.py --otto-source /path/to/otto`.
See [conformance setup and coverage](conformance/README.md).

## Running the gateway on fixtures

```sh
cargo run -p gateway-dev --bin switchboard-dev -- --once
```

This serves the gateway on `127.0.0.1:8471` over the test fakes, with real signed tokens from
in-process issuers, and runs a scripted client against it in both MCP revisions. It prints
every request, answer and audit row: team A reads its own document and is denied the other
team's with a sentence naming it. Leave out `--once` to keep it serving, then use
`switchboard-client` or point an MCP client at it. See
[CONTRIBUTING.md](CONTRIBUTING.md#running-the-gateway-on-fixtures).

## Documents

| Document | What it is |
| --- | --- |
| [docs/design.md](docs/design.md) | The design: scope, architecture, data model, invariants and delivery milestones. Authoritative once the open questions are settled. |
| [docs/systems.md](docs/systems.md) | The systems the gateway must reach, how each is likely to be connected, and what is still unverified. |
| [docs/otto-baseline.md](docs/otto-baseline.md) | Behavior verified against the pinned Go gateway, including gaps and differences from the draft. |
| [docs/feedback-loops.md](docs/feedback-loops.md) | Proposal for fast feedback once building starts: what runs in seconds, before a commit, and in CI. |
| [docs/open-questions.md](docs/open-questions.md) | Settled questions and proposed refinements, each open item with a recommendation and what it blocks. |
| [docs/decisions/](docs/decisions/) | Decision records, one per file, for choices that are settled. |

## How the documents relate

The design incorporates accepted decisions and links to proposed refinements by question
number. Proposals are not accepted requirements. When a question is answered, the answer
moves into the design, a decision record is written if the choice was contested, and the
open question is replaced by a short settled entry.
