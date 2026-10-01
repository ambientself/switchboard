# 0003: Serve Otto's control-plane endpoints from this gateway

Date: 2026-10-01. Status: accepted.

## Context

Otto's Go gateway serves three endpoints that are not MCP and that sandboxes cannot reach:
`/repo-config`, `/pr-receipt` and `/pr-outcome`. Jira inbox and answer endpoints are proposed
in Otto. Each uses the gateway's GitHub or Atlassian credential, and `/pr-receipt` writes to
GitHub. Several of Otto's tools also read state Otto owns: the pull-request proposal table,
per-turn skill pins, the repo-config cache and the team manifest's member table.

[Decision 0002](0002-replace-ottos-mcp-gateway.md) first assumed these endpoints would stay
with Otto. Otto's own rule is that a second holder of a vendor credential is a second path
around the gateway.

## Decision

This gateway serves Otto's control-plane endpoints, on a surface that only named Otto
control-plane workloads may use. It is the only holder of the vendor credentials.

State follows whoever writes it:

- State the gateway writes, such as the proposal table, moves with the tools into this
  gateway's store.
- State Otto's control plane writes, such as skill pins, reaches the gateway either inside
  the turn grant or through a narrow read interface Otto exposes. This is chosen per item
  when the tool that needs it is built.

## Alternatives rejected

- **Otto keeps a small service with its own vendor credential.** Two holders of the
  credential, and a GitHub write path this gateway neither decides nor audits.
- **Otto keeps a small service that asks this gateway's custodian for tokens.** One key
  holder, but the writes made with those tokens still bypass the gateway's decision and audit.

## Consequences

- The gateway needs surfaces restricted to named workload subjects. Internal services need
  the same mechanism, so it is built once.
- Callers of these endpoints and sandboxes stay disjoint: a sandbox's subject is never
  admitted to the control-plane surface, so a model cannot ask for instruction-position text
  or edit its own receipt.
- Each endpoint keeps its own set of permitted subjects. Otto found that one shared set let
  the repo-config caller reach the receipt endpoint.
- The gateway carries Otto-specific code. It lives in its own crate so the company-wide core
  does not depend on it.
- The endpoints that change something, such as `/pr-receipt`, get a durable record like a
  tool call does. Otto records those in a separate delivery table; whether this gateway keeps
  that table or uses the main audit table is decided when the endpoint is built.
- These endpoints are part of Otto's cutover, so they are part of the conformance suite.
