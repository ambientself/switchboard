# MCP gateway

The one MCP path for Org, planned in Rust. Every agent in the company reaches tools through
this gateway: it proves who is calling, decides whether the call is allowed, shows each caller
only the tools it may use, attaches the credential on the server side and writes an audit row
before answering.

Otto, Org's platform for running agents in Kubernetes sandboxes, is one caller. It has a
working gateway of its own, written in Go at `cmd/otto-gateway` in the `agentrunner`
repository, and a written contract for gateway behavior. This design applies that contract's
mechanisms company-wide and adds what a company-wide gateway needs beyond it: several kinds of
caller, proxied MCP servers and a registry. The model for those additions is DoorDash's Agent
Gateway
([write-up, 2026-07-30](https://careersatdoordash.com/blog/how-doordash-built-a-centralized-gateway-for-ai-agent-tool-access/)).

**Status: planning.** There is no code yet.

## Documents

| Document | What it is |
| --- | --- |
| [docs/design.md](docs/design.md) | The design: scope, architecture, data model, invariants and delivery milestones. Authoritative once the open questions are settled. |
| [docs/systems.md](docs/systems.md) | The systems the gateway must reach, how each is likely to be connected, and what is still unverified. |
| [docs/open-questions.md](docs/open-questions.md) | Settled questions and proposed refinements, each open item with a recommendation and what it blocks. |
| [docs/decisions/](docs/decisions/) | Decision records, one per file, for choices that are settled. |

## How the documents relate

The design incorporates accepted decisions and links to proposed refinements by question
number. Proposals are not accepted requirements. When a question is answered, the answer
moves into the design, a decision record is written if the choice was contested, and the
open question is replaced by a short settled entry.
