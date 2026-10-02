# 0008: Mock the first slice, in kind and Docker Compose

Date: 2026-10-01. Status: accepted. Settles Q19.

## Context

Milestone 2 called for one internal workload that is not Otto, calling one self-built
read-only MCP server through the gateway. Naming a real workload and a real server needs a
team to volunteer both, and would put the project's first production exposure ahead of
knowing whether the gateway works at all.

## Decision

The first slice uses a mock workload and a mock MCP server that this repository owns. It runs
in two places, for two different purposes.

**In kind, to prove the security properties.** A local Kubernetes cluster gives the slice
what a mock in plain processes cannot:

- Real workload identity. The mock workload runs under a ServiceAccount, and the gateway
  verifies its projected token against the cluster's own issuer. No token is hand-made.
- A real answer to "what stops the workload going around the gateway". Network policy lets
  only the gateway reach the mock server, and the test shows a direct call from the workload
  fails.
- Two teams. Two ServiceAccounts map to two teams, so a resource limit can be shown both
  allowing and refusing.

**In Docker Compose, to run it by hand.** The gateway, the mock server and Postgres start with
one command for local development. Identity there comes from the local token issuer, not
from a cluster.

### What is mocked

- **The server:** a small read-only MCP server holding documents grouped by project, with
  tools to list a project's documents and read one. The project is the resource a call names.
- **The workload:** a scripted client, not a model. It lists tools, makes calls it is
  entitled to and calls it is not, and reports what came back.
- **The policy:** each team may read its own project. One team is refused the other's.

## What this does and does not show

It shows the mechanics hold end to end: identity from a real issuer, the decision, a resource
limit, approval from files, durable audit in Postgres, bounded output, withdrawal, and no
route around the gateway.

It does not show that the policy model survives a real team's needs, or what the synchronous
audit write costs under real traffic. Those need a real workload, which becomes a later step
of milestone 2 once the mock slice passes and a team is willing.

## Consequences

- Milestone 2 no longer waits on anyone outside the project.
- The mock server doubles as the "fake MCP server" the test harness needs, built to be
  scripted: it can change its tool list, answer slowly, hang and fail.
- The kind run belongs to the slow loop: it needs Docker and takes minutes. Everything it
  checks is also checked on fakes in the per-change loop, except the two things only a
  cluster can show: the real issuer and the network policy.
- Whether kind's default network plugin enforces network policy must be checked when the
  slice is built; if it does not, the cluster is created with one that does.
- [Decision 0005](0005-build-without-a-comparison-first.md) named milestone 2 as the test of
  whether to continue. The mock slice answers "does it work"; "is it worth adopting" still
  needs the real workload.
