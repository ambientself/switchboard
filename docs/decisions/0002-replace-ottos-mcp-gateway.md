# 0002: Replace Otto's MCP gateway

Date: 2026-09-30. Status: accepted.

## Context

The company-wide gateway must become Otto's MCP path as well as serve other callers.
Otto already has a working Go gateway and a security and behavioral contract to preserve.

## Decision

The Rust gateway replaces Otto's Go MCP gateway. Otto will be reconfigured to call it
directly after the conformance suite passes. The Go gateway remains Otto's MCP path until
that cutover, after which it no longer serves Otto's MCP calls.

Otto retains responsibility for `/repo-config` and model brokering. Their separation from
the existing gateway is a migration requirement, outside this project's MCP implementation.

## Consequences

- The conformance suite is the first deliverable and establishes the existing Go behavior.
- Otto's headers, team manifest, audit-table contract, denial behavior and tool protections
  remain compatibility requirements.
- Endpoint and tool-name changes are handled explicitly by reconfiguring Otto and mapping
  the corresponding conformance requests, without weakening their assertions.
- The new gateway does not forward Otto's MCP calls through the old gateway, and Otto does
  not keep an independent MCP authorization path after cutover.

## Reaffirmed 2026-10-01

The decision was made against Otto commit `4ad4f69`. It was reviewed against Otto `main` at
`752395a`, 269 commits later, and stands: Otto switches from its built-in gateway to this one.

What the review changed is the size and shape of the work, not the decision:

- **The compatibility contract is different.** The `X-Otto-*` headers named above are gone from
  the wire. Otto's control plane now mints a signed grant for each turn, carrying session,
  turn, team, acting human, fencing epoch, expiry and the tools that turn may call. The grant
  replaces "Otto's headers" in the list of compatibility requirements.
- **The tool surface is larger.** Five GitHub tools became fourteen, plus three Jira tools and
  a claim-declaring tool. Several depend on state Otto owns: the pull-request proposal table,
  per-turn skill pins, the repo-config cache and the team manifest's member table.
- **Model brokering has already separated.** It is its own binary in Otto and needs nothing
  from this project.
- **`/repo-config` does not separate as cleanly as assumed,** and it now has siblings,
  `/pr-receipt` and `/pr-outcome`. All three need the GitHub credential, and Otto's own rule
  is that a second holder of that credential is a second path. They move to this gateway;
  see [decision 0003](0003-serve-ottos-control-plane-endpoints.md), which supersedes the
  sentence above that leaves `/repo-config` with Otto.
- **Parity is a moving target.** Fifty-five commits touched Otto's gateway between the two
  commits above. The baseline is re-pinned now and then on a schedule, with a freeze before
  cutover; see [design.md](../design.md), section 18.
