# 0003: Otto keeps its control-plane endpoints; the gateway performs their vendor actions

Date: 2026-10-01. Status: accepted. Replaces the first version of this decision, made the same
day, which moved the endpoints into the gateway.

## Context

Otto's Go gateway serves three endpoints that are not MCP and that sandboxes cannot reach:
`/repo-config`, `/pr-receipt` and `/pr-outcome`. Jira inbox and answer endpoints are proposed
in Otto. Each uses the gateway's GitHub or Atlassian credential, and `/pr-receipt` writes to
GitHub. Several of Otto's tools also depend on state Otto owns: the pull-request proposal
table, per-turn skill pins, the repo-config cache and the team manifest's member table.

Otto's own rule is that a second holder of a vendor credential is a second path around the
gateway. The first version of this decision satisfied that rule by having the gateway host
the endpoints and read or take over Otto's state.

A design review argued that this erodes the boundary the design claims. Hosting Otto's
endpoints would bring Otto's schema migrations, retention rules, proposal and receipt
transactions, skill-pin consistency and release cadence into a company-wide service. A
separate crate prevents a compile-time dependency; it does not prevent that operational
coupling.

## Decision

Otto keeps its control-plane endpoints, their orchestration and the state behind them. This
gateway does not host them and does not read Otto's tables.

Whenever one of those endpoints needs something done in a vendor system, Otto's control plane
asks this gateway to do it, as a narrowly defined action on a surface that only named Otto
control-plane workloads may use. The gateway decides, attaches the credential, performs the
action and audits it, as for any other call. Otto's control plane never holds a vendor
credential.

Where a tool's decision depends on a fact only Otto knows, the fact reaches the gateway in one
of two ways, chosen per fact when the tool is built:

- **Signed in the turn grant,** for facts that are fixed for the turn, such as which skills
  the turn pinned and at which commit.
- **Through a versioned resolver interface Otto exposes,** for facts that can change during a
  turn, such as whether a pull request was opened by Otto's own proposal. The interface states
  what the gateway does when Otto does not answer: it refuses the call.

## Alternatives rejected

- **The gateway hosts Otto's endpoints and state** (the first version). One credential
  holder, but Otto's domain logic and schema inside the company-wide gateway.
- **Otto keeps a service with its own vendor credential.** Two holders of the credential, and
  a GitHub write path the gateway neither decides nor audits.
- **Otto keeps a service that asks the custodian for tokens.** One key holder, but the
  writes made with those tokens bypass the gateway's decision and audit.

## Consequences

- The gateway needs surfaces restricted to named workload subjects, each with its own set of
  subjects. Internal services need the same mechanism, so it is built once and is not
  specific to Otto.
- The actions Otto's control plane needs are ordinary tools with classifications: read a file
  at a commit, read a pull request's state, post or edit a comment on a pull request. They are
  designed when Otto's adapter is built, not copied from the three endpoints' current shapes.
- A sandbox's subject is never admitted to the control-plane surface, so a model cannot ask
  for instruction-position text or edit its own receipt.
- There is no Otto extension crate holding endpoints or Otto's tables. What is specific to
  Otto in the gateway is a policy profile, the turn-grant verifier and a client for Otto's
  resolver interface.
- Otto has work to do for cutover that the first version put on this project: keeping the
  three endpoints running outside its Go gateway, and exposing the resolver interface.
- The conformance suite does not need to cover the three endpoints. It needs to cover the
  vendor actions they will call, once those are defined.
- The resolver makes Otto's control plane a dependency of some Otto tool calls. That is a
  dependency Otto's callers already have, and it does not affect other callers.
