# 0006: What the decision function sees and returns

Date: 2026-10-01. Status: accepted. Settles the part of Q9 that milestone 1 needs. The rest of
Q9 (tool assurance for proxied servers, employee writes, breadth of reads) stays open.

## Context

The policy core performs no I/O and must be written before any connector exists. Its
interface is the hardest thing to change later, because every caller profile, connector and
test goes through it. Q9 asked what a call's context contains.

## Decision

The decision function takes one value, the call context, and returns one value, the decision.
It reads nothing else: no clock, no network, no global state.

### The call context

| Field | Meaning | Who fills it |
| --- | --- | --- |
| Principal | The proved caller: issuer, subject, and either a workload's team or a user's groups. | The identity verifier. |
| Delegation | Optional. A verified statement that the principal is acting for someone: the acting person (recorded as a claim), the team it was issued for, and optionally the set of tools it permits. | A delegation verifier, such as Otto's turn-grant verifier. |
| Profile | The policy set for this kind of caller. | Chosen from the issuer, the deployment and the principal. |
| Surface | The named tool surface the request arrived on. | The HTTP layer. |
| Tool | The approved tool: name, classification, the connector that runs it, and whether it declares resources. | The registry snapshot. Absent if the name is not approved on this surface. |
| Resources | The resources this call names, as system, kind and identifier, or "unknown" when the tool cannot say before it runs. | The tool's resource adapter, from the arguments. |
| Deployment | Which gateway deployment received the call. | Configuration. |
| Policy revision | The revision of the snapshot the decision was made from. | The registry snapshot. |

The arguments themselves are not in the context. Policy reasons about the resources a call
names, not about raw arguments, so the core never parses a tool's argument format.

### The decision

Either **allow**, or **deny** with a reason. A reason is one of a fixed set of kinds, each with
its sentence: unknown tool, tool not on this surface, surface not permitted to this principal,
tool not permitted by the delegation, delegation and principal disagree, classification not
permitted by the profile, resource outside the caller's limit. The sentence returned to the
caller and the one written to the audit record are the same text.

### The order of checks

1. The surface is permitted to the principal.
2. The tool is approved on the surface.
3. The delegation, if the profile requires one, is present and agrees with the principal.
4. The delegation, if it lists tools, lists this one.
5. The profile permits the tool's classification. A destructive tool is denied in every
   profile.
6. Each named resource is within the caller's limit. A tool whose resources are "unknown" is
   allowed here only if it is marked as checking its own scope when it runs.

The first failing check decides the reason. `tools/list` runs the same function once per tool
with no resources and returns the tools that pass.

### What a connector may still do

A tool marked as checking its own scope may refuse when it runs, because of what the call
names. That is recorded as the outcome `refused` on the same audit record, with its sentence.
It is the only decision made outside this function, and only a refusal is possible there: a
connector can never allow what the function denied.

## Consequences

- Profiles, surfaces and limits are data, loaded into a snapshot. Adding a rule is adding data
  and table cases, not changing the function's signature.
- The core depends on no HTTP, MCP or database types.
- "One function decides" is true for everything knowable before the tool runs. The design's
  section 8 already says scope known only at run time is refused by the connector.
- Resource limits are simple matches on system, kind and identifier in milestone 1: an
  allowlist per team or group. Anything richer waits for a caller that needs it.
- Open in Q9 and unaffected by this: when a proxied tool is eligible for exposure, employee
  write permissions, and opt-in for broad reads.
