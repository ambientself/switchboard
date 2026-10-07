# 0006: What the decision function sees and returns

Date: 2026-10-01, amended the same day after the first implementation was reviewed. Amended
on 2026-10-04 (classifications, direct writes and delegation tool lists), with the rule for
comments added on 2026-10-06. Amended three times on 2026-10-07, when the owner accepted
[decision 0011](0011-resource-authorization-and-tool-assurance.md) (what may refuse outside
this function, and the exception for Otto's comment tools),
[decision 0009](0009-audit-completion-receipts-and-recovery.md) (unverified delegations, keys
and receipts) and [decision 0012](0012-what-a-turn-grant-binds.md) (currency for Otto's
side-effecting calls). The amendments are at the end, in that order, followed by the order of
checks they leave. Status: accepted. Settles the part of Q9 that milestone 1 needs, and with
the amendment, what the core needs for employee proposals and broad reads. The rest of Q9 is
settled by decision 0011, including a narrow, recorded exception for Otto's two comment tools,
except what that record lists as still open. Among those is whether a proposal stays `propose`
where the CI it starts can deploy or holds a production credential.

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
with no resources and returns the tools that pass. The 2026-10-07 amendments add to this list;
the order they leave is at the end of this record.

### What a connector may still do

A tool marked as checking its own scope may refuse when it runs, because of what the call
names. That is recorded as the outcome `refused` on the same audit record, with its sentence.
Since the 2026-10-04 amendment, a `propose` tool also refuses in the same way a call on
something the gateway did not create, or one that would take effect on its own, or forces a
value such as a draft. The gateway's argument check, the connector, the credential layer and
the custodian may each refuse outside this function, and none may allow
([decision 0011](0011-resource-authorization-and-tool-assurance.md)). A connector can never
allow what the function denied.

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
- When a proxied tool may be exposed, and what employees may do besides read, are settled by
  [decision 0011](0011-resource-authorization-and-tool-assurance.md), without changing this
  function. `checks_own_scope` is available only to built-in connectors. A `declared` tool's
  adapter may name its connector entry's whole recorded reach in place of resources read from
  the arguments. Direct writes stay denied (see the amendment below).

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
with Otto's gateway for them (#12). No exception is made here. On 2026-10-07 the owner allowed
them to Otto's callers by a narrow, recorded exception, set out in
[decision 0011](0011-resource-authorization-and-tool-assurance.md), section 9. The core needs
a mechanism for it, built under #12. Until then they stay denied.

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
gateway tells production from everything else. Decision 0011 does not replace this section. It
records one narrow exception, for Otto's two comment tools in Otto's profile, checked within
check 5: once #12 builds it, check 5 denies `write` and `destructive` unless the tool is named
in the calling profile's list of excepted tools. A list checked after this rule could never
allow, since the checks stop at the first denial. The list names tools, never a
classification, so it does not reopen the objection above. A setting that permits a
classification permits every tool of that kind, including tools approved later. A name
permits one tool, and adding one takes a decision record and an entry in the register of
exceptions, so every exception to the company's posture is in that register, read in one
place.

This replaces what the design said before: that a destructive tool could be held only in a
type the Otto profile's run path does not accept. That type was never built. Every profile
shares one run path, so a type per profile would need a run path per profile, and the rule is
about every profile, not only Otto's. The type system still makes sure a tool runs only on an
allow from this function (the compile-fail tests `decision_without_decide`,
`guard_without_begin` and `run_without_guard`). That an allow is never given for a `write` or
`destructive` tool is a runtime check. The property that such a tool is never allowed or
listed watches it, as do decision-table cases for each profile and the mutations
`write-permitted-by-profile`, `destructive-permitted-by-profile` and `check-5-removed`. When
#12 builds decision 0011's exception, the property becomes "never allowed or listed, except a
tool named in its profile's exception list".

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

Decision 0011 settles this with no field: the breadth is a resource, such as
`aws / organization / o-example`, in the limits of the teams and groups that opt in. Check 6
enforces it on any surface, so a surface of its own is not required.

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
  each guard, and a mutation that removes it. A refusal inside a proxied server cannot make
  its tool `propose`: decision 0011 exposes a proxied tool only as `read`.
- The rule binds the vendor actions Otto's control plane asks for under
  [decision 0003](0003-otto-keeps-its-control-plane-endpoints.md), since they are ordinary
  tools under a profile. Each must be `read` or `propose`. The receipt comment is posted or
  edited on a pull request the gateway created for Otto's proposal, so it is `propose` if its
  tool refuses any other pull request and the commands of the bots named when it is approved.
  That holds after a person marks the pull request ready for review. If Otto's proposed Jira answer endpoint answers by
  commenting on an issue the gateway did not create, that is `write`. An action that needs a
  direct write takes the decision that replaces the section above.
- Otto's two comment tools are denied to Otto's callers until the mechanism for the exception
  in decision 0011 is built (#12; see Comments, above). The conformance suite requires both in
  its tool inventory. It calls `github_pr_comment` as an allowed call in `TestOriginalToolsAndBrokeredCredentials` and
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

## Amended 2026-10-07: what may refuse outside this function, and Otto's comment tools

[Decision 0011](0011-resource-authorization-and-tool-assurance.md), accepted on 2026-10-07,
changed the sections above in place. In summary:

- **More may refuse outside this function, and still none may allow.** The gateway's argument
  check, the connector, the credential layer and the custodian may each refuse after the
  decision (What a connector may still do). The credential layer's refusal, such as an
  employee with no grant, is recorded as `refused`, like a connector's.
- **Check 5 gains an exception step,** once #12 builds it. Check 5 denies `write` and
  `destructive` unless the tool is named in the calling profile's list of excepted tools. The
  first entries are Otto's `github_pr_comment` and `jira_comment`, in Otto's profile only. An
  allow under the exception gives the exception as its reason. Until #12 builds it, both tools
  stay denied. See the sections on comments and on direct writes, above.
- **Resources.** `checks_own_scope` is available only to built-in connectors, and a `declared`
  tool's adapter may name its connector entry's whole recorded reach (Consequences). Broad
  reads use a breadth resource in a limit, with no field of their own (Broad reads).
- **A proxied tool is only ever `read`,** so a refusal inside a proxied server cannot make its
  tool `propose` (the consequences of the 2026-10-04 amendment).

## Amended 2026-10-07: unverified delegations, keys and receipts

[Decision 0009](0009-audit-completion-receipts-and-recovery.md), accepted on 2026-10-07,
changes four things here.

- **A delegation can be present and unverified.** The delegation's verifier runs before this
  function, but does not deny. It passes on a delegation that could not be verified, carrying
  nothing from it but the kind of failure. Check 3 denies it with a single reason kind of its
  own, so one place decides, and the caller reads one fixed sentence whatever was wrong with
  it. The row records the failure kind, which is also logged and counted. Failure kinds are
  not reason kinds. The audit row holds the proved columns and nothing from the delegation's
  claims. Where a turn grant's signature verified and only a binding failed (audience,
  lifetime or pod), the row also records the grant's digest (decision 0012).
- **The context says whether the request carries a key.** A tool not classified `read` whose
  call carries no key is denied with a reason kind of its own, and a sentence asking for one.
  That is knowable before anything runs, so it belongs in this function. It is a new last
  check, after check 5, decision 0012's currency check and check 6, so a caller is asked for a
  key only when the call would otherwise be allowed. It is skipped for `tools/list`, like
  check 6 and the currency check, because a list request carries no key: a `propose` tool
  appears in the list and is denied on `tools/call` without a key. The decision table gains
  that case, and a mutation that applies the check to `tools/list`, and one that moves it
  before a permission check, must be caught.
- **The receipt check is a second decision outside this function.** It is made at begin, when
  a key already has a receipt in its scope. Like a connector's refusal, it cannot make
  anything run. It decides about delivery, not permission.
- **The outcomes gain `unknown` and `duplicate`.** `unknown` is for side effects only: the
  request was sent and no definite answer came back. `duplicate` means nothing ran because the
  same request was already completed.

"Receipts before writes (Q10)" in the consequences above is now decision 0009. Receipts come
before the first `propose` tool reaches a real system.

## Amended 2026-10-07: currency for Otto's side-effecting calls

[Decision 0012](0012-what-a-turn-grant-binds.md) allows a call of any tool not classified
`read` under the profile for Otto's sandboxes only while Otto says the turn is current. That
is, its control plane still holds the lease at the grant's epoch, and the turn has not ended or
been revoked. This amendment puts that rule in the decision function. It covers Otto's
`propose` tools, and its two `write` comment tools once the exception that decision 0011
records for them, above, is built.

### What changes

- **The call context** gains the call's currency: current, not current (superseded, ended or
  revoked), unconfirmed, or not asked. The Otto adapter fills it, for `tools/call` only. It
  asks Otto's resolver only when the snapshot's tool is not classified `read` and the profile
  requires currency. An adapter that fails to ask leaves "not asked".
- **The principal** gains, for a Kubernetes workload, the pod UID its token proves. **The
  delegation** gains its issuer, digest, key ID and egress setting. The function reads none of
  these. The audit record keeps them.
- **A profile** gains a setting: a call of a tool not classified `read` requires a current
  control plane. The profile for Otto's sandboxes sets it. The profile for Otto's
  control-plane surface does not, because Otto's receipts are posted after the turn has ended.
- **A new check after check 5,** and after the exception step that decision 0011 adds to
  check 5, before check 6. Under such a profile a call of a tool not classified `read` is
  allowed only if its currency is current. Not current, unconfirmed and not asked are each
  denied. A `write` tool that no exception names is denied at check 5 first. The check is
  skipped for `tools/list`, like check 6, and does not apply to `read`.
- **Two new reason kinds,** each with its sentence: the control plane is not current, and
  currency is unconfirmed. "Not asked" is denied as unconfirmed. The row records which answer
  Otto gave.

### Why currency is in the function

The 2026-10-04 amendment kept profiles to a set of classifications, and rejected fields that
mean something only for some tools and profiles. Currency is such a field. It goes in the
function anyway, so that the decision table and its properties cover it. The alternative is
for the adapter to deny before the function runs. That is a second place that decides, which
this record allows only for refusals that can never allow: a connector's, and those decisions
0009 and 0011 add.

### What runs before the function

The turn-grant verifier's own checks run before the function: version, key, encoding,
signature, audience, lifetime and, once required, pod. The verifier does not deny. A grant
that fails any of them reaches the function as a delegation that is present and unverified,
carrying only which check failed, and check 3 denies it under the single reason kind the
amendment for decision 0009, above, gives an unverified delegation. The caller reads the fixed
sentence for a bad grant. Which check failed is recorded on the row, logged and counted, and is
not a reason kind. The row holds the proved columns and nothing from the grant's claims. When
the signature verified and a binding failed (audience, lifetime or pod), the row also records
the grant's digest. That is the one exception to 0009's rule that such a row holds nothing
from the grant: a digest is not a claim. Check 3 still names a team mismatch. Such a grant
verified, and the mismatch is usually a rollout fault.

### Consequences

- The Otto adapter asks Otto's resolver before deciding each call of a tool not classified
  `read` under the profile for Otto's sandboxes, from stage 3. No answer within one second
  denies the call.
- The decision table gains a case for each currency value against a `read` tool, a `propose`
  tool and, once decision 0011's exception exists, an excepted `write` tool, under a profile
  that requires currency and one that does not.
- A new property: under a profile that requires currency, a call of a tool not classified
  `read` is never allowed unless its currency is current.
- New mutations: the currency check skipped, "not asked" treated as current, "unconfirmed"
  treated as current, the check applied to `read`, and the check applied to `propose` alone.
- The core changes these need (the currency type in the call context, the profile setting,
  the check, the reason kinds and the recorded fields) are follow-on code for milestone 4.
  They are not built yet.

## The order of checks after the 2026-10-07 amendments

In this order, the first check that fails giving the reason:

- **Check 0.** The profile exists.
- **Check 1.** The surface is permitted to the principal.
- **Check 2.** The tool is approved on the surface.
- **Check 3.** A delegation is present if the profile requires one, and one that is present is
  verified and agrees with the principal. An unverified delegation is denied here under its
  own reason kind (decision 0009).
- **Check 4.** The delegation, if present, lists the tool.
- **Check 5.** The profile permits the classification. `write` and `destructive` are denied
  before the profile is read, unless the tool is named in the profile's list of excepted
  tools, once #12 builds that list (decision 0011).
- **The currency check.** Under a profile that requires it, a tool not classified `read` needs
  a current control plane (decision 0012).
- **Check 6.** Each named resource is within the caller's limit.
- **The key check,** last. A tool not classified `read` whose call carries no key is denied
  (decision 0009).

`tools/list` decides with no resources and no key, and skips the currency check, check 6 and
the key check. The checks added on 2026-10-07 are named, not numbered, so that "check 6" still
means the resource check wherever it is cited. The reason kinds added on 2026-10-07 are an
unverified delegation, a control plane that is not current, unconfirmed currency, and a
missing key, each with its sentence. Outside this function, the receipt check at begin, the
argument check, the connector, the credential layer and the custodian may each refuse, and
none may allow.
