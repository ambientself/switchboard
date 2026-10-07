# 0006: What the decision function sees and returns

Date: 2026-10-01, amended the same day after the first implementation was reviewed, and again
on 2026-10-04 (classifications, direct writes and delegation tool lists; see the end), with
the rule for comments added on 2026-10-06. Status: accepted. Settles the part of Q9 that
milestone 1 needs, and with the amendment, what the core needs for employee proposals and
broad reads. The rest of Q9 stays open: when a proxied tool is eligible for exposure, any write
policy beyond proposals, whether Otto's comment tools get an exception to the comment rule, and
whether a proposal stays `propose` where the CI it starts can deploy or holds a production
credential.

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
| Delegation | Optional. A verified statement that the principal is acting for someone: the acting person (recorded as a claim), the team it was issued for, and the set of tools it permits. | A delegation verifier, such as Otto's turn-grant verifier. |
| Profile | The name of the policy set for this kind of caller. The function looks the profile up in the snapshot it decides from, so a profile and a snapshot can never be mismatched. | Chosen from the issuer, the deployment and the principal. |
| Surface | The named tool surface the request arrived on. | The HTTP layer. |
| Tool | The approved tool: name, classification, the connector that runs it, and whether it declares resources. | The registry snapshot. Absent if the name is not approved on this surface. |
| Resources | The resources this call names, as system, kind and identifier, or "unknown" when the tool cannot say before it runs. | The tool's resource adapter, from the arguments. |
| Deployment | Which gateway deployment received the call. | Configuration. |
| Policy revision | The revision of the snapshot the decision was made from. | The registry snapshot. |

The arguments themselves are not in the context. Policy reasons about the resources a call
names, not about raw arguments, so the core never parses a tool's argument format.

### The decision

Either **allow**, or **deny** with a reason. A reason is one of a fixed set of kinds, each with
its sentence: unknown profile, unknown tool, tool not on this surface, surface not permitted to
this principal, tool not permitted by the delegation, delegation missing or disagreeing with
the principal, classification not permitted by the profile, resource outside the caller's
limit. An unknown tool and a tool that exists on another surface are different kinds in the
audit record and the same sentence to the caller, so the answer does not reveal which tool
names exist. The sentence returned to the
caller and the one written to the audit record are the same text.

### The order of checks

0. The profile named in the context exists in the snapshot.
1. The surface is permitted to the principal.
2. The tool is approved on the surface.
3. A delegation is present if the profile requires one. A delegation that is present agrees
   with the principal, whether or not the profile requires it: one that contradicts the
   proved team is a sign of something wrong. A user, who has no team, cannot present one.
4. The delegation, if present, lists this tool. A delegation always carries a tool list; an
   empty list permits nothing.
5. The profile permits the tool's classification. A `write` or `destructive` tool is denied
   before the profile is consulted, so no profile data can permit either.
6. Each named resource is within the caller's limit, by exact match. A tool that declares
   resources and is given none is denied, so a failure to find the argument fails closed. A
   tool whose resources are "unknown" is allowed here only if it is marked as checking its
   own scope when it runs.

The first failing check decides the reason. `tools/list` runs the same function once per tool
with no resources and returns the tools that pass.

### What a connector may still do

A tool marked as checking its own scope may refuse when it runs, because of what the call
names. That is recorded as the outcome `refused` on the same audit record, with its sentence.
Since the 2026-10-04 amendment, a `propose` tool also refuses in the same way a call on
something the gateway did not create, or one that would take effect on its own, or forces a
value such as a draft. These are the only decisions made outside this function, and they can
only restrict: a connector can never allow what the function denied.

## Consequences

- Profiles, surfaces and limits are data, loaded into a snapshot. Adding a rule is adding data
  and table cases, not changing the function's signature.
- The core depends on no HTTP, MCP or database types.
- "One function decides" is true for everything knowable before the tool runs. The design's
  section 8 already says scope known only at run time is refused by the connector.
- Resource limits are simple matches on system, kind and identifier in milestone 1: an
  allowlist per team or group. Anything richer waits for a caller that needs it.
- A tool must either declare its resources or be marked as checking its own scope. A snapshot
  containing a tool that does neither is refused when loaded, because such a tool could be
  listed and never called.
- The arguments are not policy input, but the audit guard carries them from the decision to
  the connector, so what runs is what was decided.
- Group names are not yet qualified by issuer. Two identity providers that use the same group
  name would collide; this must be settled before a second user issuer is added.
- Open in Q9 and unaffected by this: when a proxied tool is eligible for exposure, and any
  write policy beyond proposals. Employee proposals and opt-in for broad reads were open here
  too; the amendment below settles what the core needs of each.

## Amended 2026-10-04: classifications, direct writes and delegation tool lists

A review on 2026-10-04 found that the policy model could not state three rules the design's
profile table states, and that the code and this record disagreed about delegations.

### A fourth classification, `propose`

The design allows Otto's callers and services only "proposal-shaped" writes, and Q9 recommends
the same for employees at first. A profile was a set of classifications, so it could permit
every `write` tool or none. "Proposal-shaped" had nowhere to live.

There are now four classifications:

| Classification | Meaning |
| --- | --- |
| `read` | Reads and changes nothing. |
| `propose` | Creates something for a person to review, or changes only what the gateway itself created for review: a draft pull request, an issue it opens, a commit to its own proposal branch, a comment on something it created for review. It never changes, transitions, merges or deploys anything else, so nothing it does takes effect until a person acts on it. |
| `write` | Changes something directly: a merge, a push to a branch the gateway did not create for a proposal, a status transition, a configuration change, a comment on anything the gateway did not create for review. |
| `destructive` | Destroys something. |

`propose` follows Otto's definition, "open a PR, don't push; comment, don't transition", with
one difference: Otto allows a comment on any pull request or issue a team may reach, and this
definition does not (see Comments, below).

The person approving a tool assigns its classification. The decision function sees only the
classification; it cannot tell what the gateway created. So a tool is `propose` only if it
refuses, when it runs, to act on anything the gateway did not create, by a check such as the
author being the gateway's own identity, a reserved branch prefix, or a fact from Otto's
resolver ([decision 0003](0003-otto-keeps-its-control-plane-endpoints.md)). Otto's
`github_amend_change` makes this check: it commits only to an open pull request its own App
opened, on a branch under its reserved prefix. A tool that cannot make the check is `write`,
whatever its name.

Acting only on what the gateway created is not enough, because a comment on the gateway's own
pull request can still be a command. A `propose` tool must also guard, when it runs, against
anything that would take effect without a person acting. A guard is either a refusal or a value
the tool forces. Otto's tools show the cases. `github_pr_comment` refuses a comment whose first
word Atlantis would read as a command, on any pull request. `github_create_pr` forces a draft,
because the org's Atlantis plans every pull request that is not a draft. `github_amend_change`
refuses to commit to a pull request a person has marked ready for review, because Atlantis
would plan the new commit.

A refusal is recorded as the outcome `refused`, like a connector's scope refusal (see What a
connector may still do, above). A forced value is not a refusal: the call completes with the
outcome `ok`, and what it created is a draft. Every guard, the forced draft included, gets a
connector test and a mutation (see Consequences, below).

A `propose` tool has no setting that turns a guard off. Otto's `github_create_pr` has one: the
operator flag `CreateReadyPRs` makes it open pull requests that are ready for review. That flag
is not carried over, and a create-PR tool with such a setting is `write`.

The bots whose commands a comment tool refuses are named when the tool is approved: those
configured for the repositories or projects it can reach, which today is Atlantis. CI cannot
be refused by what starts it: a draft pull request, a push to the gateway's proposal branch and
a comment each start the workflows configured for them. That is acceptable where those workflows
only build and test. Whether a proposal stays `propose` in a repository where a workflow that a
pull request, a push or a comment starts can deploy or holds a production credential is open in
Q9.

### Comments

Decided by the owner on 2026-10-06. A comment is `propose` only when it is on something the
gateway itself created for review, such as its own draft pull request or an issue it opened.
A comment anywhere else is `write`. A comment can take effect on its own: a bot reads
`/deploy` or `atlantis apply` as a command, and a comment can start CI.

The rule is about what the comment is on, not that thing's state. A comment on the gateway's
own pull request is still `propose` after a person marks it ready for review, if its tool makes
the guards above.

Of the five write tools Otto serves at `752395a`, three are `propose` under this rule:
`github_create_pr`, `github_propose_change` and `github_amend_change`. Two are `write`:
`github_pr_comment` posts on any pull request in the team's repositories, and `jira_comment`
on any issue in the configured projects. So is `addOrEditJiraIssueComment` on Atlassian's
hosted server, the comment write in the Jira surface [systems.md](../systems.md) lists to
match Otto's.

Otto's callers are therefore denied both comment tools, and the gateway does not reach parity
with Otto's gateway for them (#12). No exception is made here. Whether to allow them by a narrow,
recorded exception is open in Q9 for the owner.

### Direct writes are denied in every profile

Check 5 now denies a `write` tool before the profile is consulted, as it already did a
`destructive` one. What a profile can permit is `read` and `propose`.

This is how "production mutation is denied for every profile initially" is enforced. Under
the definitions above, anything that changes production without a person acting is `write` or
`destructive`, so no profile can permit it. The policy model needs no notion of environment
for this.

The denial is in code, not left out of each profile's data, for the reason Otto's ADR-0003
gives for its own hard denial: a per-profile opt-in makes the company's posture the union of
every profile's weakest setting. Permitting direct writes takes a decision record that
replaces this section, and a change to check 5. That decision must first settle how the
gateway tells production from everything else.

This replaces what the design said before: that a destructive tool could be held only in a
type the Otto profile's run path does not accept. That type was never built. Every profile
shares one run path, so a type per profile would need a run path per profile, and the rule is
about every profile, not only Otto's. The type system still makes sure a tool runs only on an
allow from this function (the compile-fail tests `decision_without_decide`,
`guard_without_begin` and `run_without_guard`). That an allow is never given for a `write` or
`destructive` tool is a runtime check. The property that such a tool is never allowed or
listed watches it, as do decision-table cases for each profile and the mutations
`write-permitted-by-profile`, `destructive-permitted-by-profile` and `check-5-removed`.

### A delegation's tool list is required

Check 4 already said that a delegation always carries a tool list. The first implementation
allowed `null`, meaning "narrows nothing", and the decision table relied on it. The code now
matches this record: the list is required, `null` is refused when a delegation is read, and
an empty list permits nothing. Otto already refuses a grant without one, so nothing Otto sends
is affected.

### Broad reads need no field of their own yet

The design's opt-in for reads that show more than a caller could otherwise see, such as AWS
inventory across accounts, can be expressed with what exists. Such a tool is served only on
surfaces whose allowlist is the opted-in teams and groups, and the resources it names are
checked against their limits. A dedicated field waits for the first such tool.

### Alternatives rejected

- **A separate write-shape attribute on each tool, and a setting on each profile for which
  shapes it permits.** This keeps the classification column Otto-compatible without a
  mapping. But it adds a field to every tool that means something only for writes, and a
  setting to every profile that means something only if the profile lists `write`. Both are
  states that should not be representable.
- **An environment on each resource, so check 6 could refuse production.** It is needed only
  once a profile may write directly. Until then it adds a way to get production wrong: a
  resource adapter that mislabels a production resource would permit the write.

### Consequences

- Otto's `gateway_audit` table allows only `read`, `write` and `destructive` in its
  classification column, and Otto's tool listing reports classifications the same way. The
  Otto adapter records and reports `propose` as `write`. This is an explicit mapping in the
  adapter, like the tool-name and endpoint mappings. The company-wide audit record keeps
  `propose`.
- Approving a tool now includes judging whether it proposes or writes directly. That judgment
  is what keeps production mutation out, so it is part of what the reviewer of an approval
  checks.
- A `propose` tool's run-time guards, its refusals and any value it forces such as a draft,
  are guards like any other, and this function's tests cannot see them. A built-in tool is
  approved as `propose` only with a connector test against the fake vendor that fails without
  each guard, and a mutation that removes it. Whether a refusal inside a proxied server can
  make its tool `propose` is part of what stays open in Q9.
- The rule binds the vendor actions Otto's control plane asks for under
  [decision 0003](0003-otto-keeps-its-control-plane-endpoints.md), since they are ordinary
  tools under a profile. Each must be `read` or `propose`. The receipt comment is posted or
  edited on a pull request the gateway created for Otto's proposal, so it is `propose` if its
  tool refuses any other pull request and the commands of the bots named when it is approved.
  That holds after a person marks the pull request ready for review. If Otto's proposed Jira answer endpoint answers by
  commenting on an issue the gateway did not create, that is `write`. An action that needs a
  direct write takes the decision that replaces the section above.
- Otto's two comment tools are denied to Otto's callers until Q9 settles an exception (see
  Comments, above). The conformance suite requires both in its tool inventory. It calls
  `github_pr_comment` as an allowed call in `TestOriginalToolsAndBrokeredCredentials` and
  counts its write there, uses it in three of its scope and argument cases, and makes it the
  only write in its tests of audit-finish failure and repeated writes. Against the Rust
  gateway those cases are an expected difference until then (design section 18). Their
  coverage is kept: the brokered-credentials test's `github_create_pr` case, with its
  token-scope and draft checks, still runs against the Rust gateway, and the two audit tests
  are also run with a `propose` tool. That test calls a comment a proposal write; that is
  Otto's definition, not this record's.
- The suite also compares classifications, and pins `write` for the three tools that are
  `propose` here. Those checks pass through the adapter's mapping of `propose` to `write`, the
  first item in this list. They are not expected differences.
- "Write" in plain text, in the design and the open questions, still means any call that
  changes something, `propose` or `write`. Receipts before writes (Q10) cover proposals.
- The decision table's write tools are reclassified: proposals are `propose`, and the comment
  and the transition that remain are `write`, to show the denial. A comment tool that comments
  only on what the gateway created for review is `propose` and allowed, to show the other side
  of the comment rule.
