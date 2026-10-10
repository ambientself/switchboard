# 0011: Resource authorization and tool assurance

Date: 2026-10-06. Status: accepted on 2026-10-07, when the owner accepted the recommendations
(see Decided by the owner). Settles the rest of Q9 after
[decision 0006](0006-what-the-decision-function-sees.md) and the 2026-10-04 amendment to it,
except the parts under Still open, which wait on other people. Written against that amendment
and the audit row's resources column (pull request #30, merged on 2026-10-07; design.md
section 11). Its 64-resource bound, and its question about Otto's `gateway_audit` table in
Q12, are used below.

## Context

Decision 0006 fixed what the decision function sees: the resources a call names, found in the
arguments by the tool's resource adapter. Its amendment added the `propose` classification,
denied `write` and `destructive` in every profile, and deferred a field for broad reads until
the first such tool. Four things stayed open: what a tool must declare about where its checks
happen, when a proxied tool may be exposed, what employees may do besides read, and how a read
that shows more than its caller could otherwise see is opted into.

This record assumes two failures at once. An agent may be compromised or confused, and will
call any tool it can see with any arguments, including arguments chosen to get past a check.
A person approving tools or editing limits may be careless, and will pick the weakest
declaration that loads. Against the agent, a guarantee must hold for every argument. Against
the careless person, a wrong declaration should fail when the snapshot loads. But the loader
can only compare what approvals state. It cannot tell whether a tool proposes or writes,
whether a structured argument carries every resource a tool reaches, or whether a recorded
reach is true. Those rest on the approval's reviewer, and this record says where.

Five facts shape the answer.

- A built-in connector is gateway code and understands its arguments. A proxied server is
  someone else's code. The gateway can read what it sends the server, but not what the server
  does with it, and the server can make any call its credential allows, whichever tool was
  called.
- Some arguments are free text: JQL, CQL, log queries, SQL against AWS Config. The gateway
  cannot reliably find the resources they name by reading them ([systems.md](../systems.md)).
- Under check 6, a tool whose resources are `unknown` passes if it is marked
  `checks_own_scope`. Nothing stops that mark being put on a proxied tool, where no code in
  the gateway does the check, and the call's audit row then records `unknown`.
- `tools/list` decides with no resources, so it skips check 6. A tool whose every call check 6
  would deny is still listed.
- The amendment defines `propose` as changing only what the gateway created. Nothing yet
  checks that.

## Decision

### 1. What a tool's approval says

Issue 2 asks where four things happen for each tool: the resource check, argument
validation, credential narrowing and output limits. Two vary from tool to tool and are
declared in the approval. Two follow from the kind of connector and are not.

**The resource check is declared per tool.** The declaration keeps decision 0006's three
values. A `declared` tool also says where its adapter finds the resources.

| Declaration | Resources on the call | Where scope is checked | Allowed for |
| --- | --- | --- | --- |
| `declared`, from the arguments | The adapter reads them from structured arguments. | Check 6, before the tool runs. | Built-in and proxied tools. |
| `declared`, as the reach | The adapter names its connector entry's whole recorded reach on every call, whatever the arguments. | Check 6, before the tool runs. | Built-in and proxied tools. |
| `checks_own_scope` | `unknown`. | The built-in connector, while it runs. It can only refuse. | Built-in tools only. |
| `no_resources` | None. | Nowhere. The tool reaches nothing a limit applies to. | Built-in tools; proxied tools only when their entry's reach is empty. |

The decision function does not change. The reach comes from the same snapshot as the
decision, so it always matches the policy revision on the row. The row records a reach by
reference, as the connector entry marked as a reach, not as a list: a reach can hold more
than the 64 resources a row keeps, and the revision says exactly what it was. A tool whose
arguments name its resources in structured fields uses `declared` from the arguments, not
`checks_own_scope`, so that its row says what the call named. `checks_own_scope` is for what
cannot be known before the tool runs, such as which repositories a code search returns.

**The credential is declared per connector entry.** Each entry has exactly one credential, in
one of the modes in design.md section 9: team service identity, gateway-held token or
per-user grant. A system reached in two modes, with a service account per team, or with
several permission sets is registered as several entries. Otto's GitHub tokens, requested per
permission set, are one entry per set. The entry records:

- **Narrowing:** `call`, a token narrowed to the resources the call names; `limit`, narrowed
  to the caller's limit as the snapshot holds it; or `none`. Otto's GitHub tokens are `limit`
  today, narrowed to the team's repositories, and its accepted direction for writes is `call`.
  `call` requires a tool `declared` from the arguments, because a token can be narrowed only
  to resources the call names. A vendor may cap what one token can name. GitHub names at most
  500 repositories, so `limit` there serves only limits of that size or smaller, and a request
  for more is refused, not cut short.
- **Reach:** every resource the credential and route can reach, as system, kind and
  identifier. If it cannot be listed resource by resource, it is one resource naming the
  whole site or account, such as `jira / site / example.atlassian.net`. For a per-user grant,
  the reach is the site or workspace, and the vendor's permissions for each person narrow it
  further. Required for proxied entries, and for any entry serving a tool `declared` as the
  reach.
- **What the credential permits:** the highest classification any call made with it could
  have. For a proxied entry it must not exceed the classification of any tool the entry
  serves. For a built-in entry it is recorded, not compared. Vendor permissions cannot express
  `propose`: the GitHub permission that commits to a proposal branch also pushes to any other
  branch. A built-in `propose` tool rests on its connector's code and tests.

For a self-built server the gateway presents its own identity, not a vendor credential. The
reach and what the credential permits are then the server owner's statement about its
backend, and rest on the reviewer.

**Argument validation follows from the kind of connector.** A built-in connector parses the
arguments into its own types and returns `error` for malformed input; an argument it does not
read cannot change what it does. For a proxied tool, the gateway validates the arguments
against the approved input schema, read as JSON Schema 2020-12. Revision `2025-06-18`, which
this gateway serves ([decision
0007](0007-serve-two-mcp-revisions-from-a-hand-written-endpoint.md)), names no default dialect,
and servers of that era often publish draft-07 schemas. Read as 2020-12, a draft-07 schema can
mean something else: the array form of `items` is invalid, `definitions` is not `$defs`, and
`dependencies` was split in two. So at approval a schema whose `$schema` names another dialect,
or that uses a form valid only in an earlier draft, is refused or converted to 2020-12, and the
converted schema is the one approved. The dialect is part of the approval's hash. Where an
object in the schema lists its properties, any other property is refused, at any depth,
whatever the schema says about additional properties. An object the schema leaves open, such as
a map or a MongoDB filter, is accepted as one value, and the reviewer treats it as free text.
The gateway forwards its own serialization of the arguments the audit guard carries, never the
caller's bytes. A call that fails validation is completed with outcome `error` and is never
forwarded.

Without this, an adapter could check `project` while the server acted on a second argument
the adapter never read. It covers undeclared arguments only. That no declared free-text
argument or open object can name a resource is the reviewer's check; where one can, the tool
is `declared` as the reach or is not exposed. The exact rules for composed schemas and
references are fixed with their test cases when the proxy path is built.

**Output limits are the gateway's, as a backstop for every tool.** The gateway bounds the size
and duration of every result. A connector may bound further in its own code, and may return a
result cut short with an explicit flag, as Otto's GitHub tools do: ten search results, twenty
comments, files up to 256 KiB, each marked as truncated. The gateway's bounds are set above
every connector's, so the caller sees the connector's flagged truncation and Otto's behavior
holds. A result that exceeds the gateway's bound is never cut short silently. For a `read`
tool it is outcome `error`. For any other tool the vendor may already have acted, so an
oversized or late result is recorded as `unknown`
([decision 0009](0009-audit-completion-receipts-and-recovery.md)) and is never presented as
safe to retry. The values, and whether a server may have a longer deadline than the default
(a Sumo Logic search may take two minutes), are set with the other limits in milestone 3
(Q12).

### 2. When a proxied tool may be exposed

A proxied tool is exposed only when all of these hold.

- **It is `declared` or `no_resources`, never `checks_own_scope`.** The proxy connector
  forwards calls and cannot check scope. A server's claim to check its own scope is not
  assurance, for the same reason a server is never trusted to classify its own tools.
- **From the arguments:** each resource is named by a structured argument, never inside free
  text or an open object. A tool whose resources sit in a query string cannot use this. The
  adapter is gateway code, with cases built from the tool's real argument shapes.
- **As the reach:** the reach has been shown to hold. The approval records a dated test
  showing that a call outside the reach fails: for a vendor server, the test its section of
  systems.md names under "To confirm"; for a self-built server, one its owner runs. For a
  per-user entry, whose reach is the whole site or workspace, the test shows that a call to
  another site or workspace fails. The loader can check that a test is recorded. It cannot
  check that the test was right; the reviewer does.
- **Its credential reaches nothing outside its callers' limits.** The entry narrows per `call`
  or to the caller's `limit`, or its whole reach lies within the limit of every team and group
  admitted to every surface that serves the tool. A server that ignores its arguments then
  still reaches nothing its caller may not. For `no_resources`, the reach is empty.
- **It is `read`.** A proxied tool is not `propose` until a later decision allows it. The
  gateway cannot check that a proxied tool changes only what the gateway created, or refuse
  content that downstream automation would act on. Proposals go through built-in connectors.
- **Its credential cannot write.** Where a vendor's scopes cannot exclude writes, the tool is
  not exposed. A read-only credential is necessary, not sufficient: it does not make a tool
  `read`, and it says nothing about which data the tool may show.
- **Milestone 3 is in place,** outside development and test deployments: approval bound to
  the server's identity, route and credential configuration, destination limits and drift
  detection. A self-built server accepts only the gateway's own identities
  ([decision 0010](0010-what-stops-an-agent-going-around-the-gateway.md)).

Some arguments name a resource only through something the vendor resolves. An issue key names
its project, and Jira keeps an issue's old key after the issue moves, so `OLD-123` may now be
in project `NEW`. A repository name may be redirected after a rename. For a proxied tool this
cannot take a call outside its caller's limit, since its credential reaches nothing outside
it, but the row may name the old resource. A built-in connector that accepts such names checks
the resource it gets back against the limit before returning it.

### 3. What the snapshot loader refuses

These sit beside the existing rule that every tool says how its resources are known. A
snapshot that breaks one is not loaded and the previous snapshot keeps serving. The error
names the tool, team or group, and resource, and the policy owners are alerted.

1. A proxied tool declared `checks_own_scope`.
2. A proxied tool classified anything but `read`.
3. A proxied connector entry with no recorded reach, or with a non-empty reach and no
   recorded test.
4. A proxied connector entry whose credential permits more than the classification of a tool
   it serves.
5. A tool on a surface that admits a team or group whose limit does not hold the whole reach
   of the tool's connector entry, where the tool is `declared` as the reach, or is proxied and
   its entry narrows `none`.
6. A proxied `no_resources` tool whose connector entry's reach is not empty.
7. A connector entry narrowing per `call` that serves a tool not `declared` from the
   arguments.
8. A per-user connector entry's tool on a surface that admits any team. Otto's callers and
   services never act as a named user (design.md, section 8).
9. A `propose` tool on a surface that admits any group, unless its connector entry is
   per-user.

Rule 5 means `tools/list` never shows a tool `declared` as the reach to a caller whose every
call check 6 would deny. A tool `declared` from its arguments can still be listed to a team
whose limit holds none of its resources, and a per-user tool to an employee with no grant.
Both fail when called. That is accepted.

### 4. Keeping a reach true

A reach rests on facts outside this repository. An administrator can widen a service account
or add a scope to a key without touching an approval. The registry therefore checks each
proxied connector entry's reach on a schedule, in the same pass as drift detection, except a
per-user entry's (below).

- Where the vendor can report what a credential reaches or which scopes it holds, as GitHub
  lists an installation's repositories, the check compares the report with the recorded reach
  and with what the credential permits.
- Where it cannot, the check confirms that a canary resource, kept by the owning team outside
  the reach, is refused. This catches a limit removed, not every resource added. The approval
  states that residual.
- A check never attempts a write. A write that succeeded would be the incident it was looking
  for.
- The registry holds no vendor credential. Each check is a gateway call: the registry is a
  workload principal admitted only to a surface restricted to its own subject, and each check
  is decided, audited and run with the entry's credential from the custodian, like any other
  call. Where reading a vendor's report needs a broader administrative credential, that
  credential is a connector entry of its own, `read`, served only on that surface.
- A mismatch withdraws the entry's tools from every surface, as a changed definition does,
  and alerts the owning team. They return only through a new approval.
- A per-user proxied entry is not checked on a schedule. Its reach is already the whole site
  or workspace, and the registry has no person's grant to call with. Its test, which shows
  that a call to another site or workspace fails, is what holds it.

A withdrawal does not wait for the next snapshot to load from the policy files. It makes a new
snapshot of its own: the snapshot in force with the withdrawn tools removed. That snapshot has
its own revision, naming the base revision and the withdrawal set, and replaces the one in
force atomically, like any other snapshot. The loader's rules are not run again, since a
removal can only narrow what is allowed, so an unrelated change that breaks a loader rule
cannot hold it up. Rows decided after it record its revision, so the revision on a row still
says exactly what was in force. How a withdrawal reaches every gateway replica, and how it
sits with a maximum snapshot age, are Q11's.

### 5. Where each part of the decision is made

| Part | Made by | When | Can it allow? | On the audit record |
| --- | --- | --- | --- | --- |
| Who is calling, and for whom | The identity and delegation verifiers. | Before the decision. | No. | Proved and claimed columns. An identity failure is telemetry with an opaque answer, and no row. A delegation that fails is passed on unverified and denied at check 3, with a row ([decision 0009](0009-audit-completion-receipts-and-recovery.md)). |
| Classification, declaration, credential entry and reach | The person approving the tool, checked by the approval's reviewer. | Approval. | No. They are inputs. | Policy revision. |
| Whether the approvals fit together | The snapshot loader, with the rules above. | When a snapshot loads. | No. A snapshot that breaks a rule is never served. | Policy revision. |
| Which resources the call names, or the reach | The tool's resource adapter, gateway code. | Before the decision. | No. Finding none denies a `declared` tool. | Resources, or the connector entry marked as a reach. |
| Profile, surface, tool, delegation, classification, currency, resource limit, key | The decision function, with the currency check of [decision 0012](0012-what-a-turn-grant-binds.md) and the key check of decision 0009. | Before the row is begun. | Yes. The only place that can. | Decision, reason, sentence. |
| Arguments against the approved schema | The gateway, for proxied tools; the connector's own types, for built-in ones. | After the row is begun, before the vendor. | No. | Outcome `error`, invalid arguments; nothing is forwarded, and a side effect's receipt is `not_performed`. |
| Whether a key was already used | The receipt check (decision 0009). | At begin. | No. It decides about delivery. | An allowed row written complete, `refused` or `duplicate`. |
| Scope known only when running | A built-in connector, for `checks_own_scope` tools. | While running. | No. | Outcome `refused`, with its sentence. |
| Which credential, narrowed how | The credential layer and the custodian, in the approved mode. | While running. | No. | `refused` when no grant exists; `error`, a custodian refusal, when the custodian refuses; the credential identity used. |
| What the credential may do | The vendor. | While running. | No. | Outcome `error`; a vendor refusal where the connector can tell. |
| Result size and duration | The gateway, above any bound of the connector's own. | While and after the tool runs. | No. | `error` for a `read` tool; `unknown` for any other tool (decision 0009). |
| Whether a reach still holds | The registry's scheduled check, run as gateway calls. | Outside the calls it protects. | No. It withdraws. | Its own rows, and the withdrawal. |

Noted on 2026-10-10 ([decision 0014](0014-rollout-safeguards-and-audit-operations.md)): the
credential identity on the row is the configured entry identity, recorded at begin: the entry's
stated mode and principal, never the secret. The gateway records what the entry says, not what
the credential layer reports while the call runs. An entry has one credential and no fallback,
so the two cannot differ until per-user grants arrive in milestone 5, when this is revisited.
The per-server and per-team concurrency caps are a further part that can only refuse: taken
after begin and before the vendor, and recorded as `refused` with a capacity sentence.

The design no longer claims that one function decides everything. It claims that one function
is the only place that can allow a call, that every later part can only refuse or fail, and
that one audit record holds the whole decision for a call. The first holds by construction: a
connector runs only on a call made from an audit guard, a denied call has no guard, and a
compile-fail test shows it. The policy revision on the row identifies the approvals and loader
checks the call relied on.

Every later part takes its limits from that snapshot revision. A built-in connector's own
scope list, such as a team's repositories, comes from the snapshot, not from its own
configuration. The custodian is the exception, deliberately. It runs in its own process and
checks each token request against its own copy of what each team and tool may ask for
(design.md section 9), so that a compromised gateway cannot widen its own requests. That copy
is generated from the same policy files, and each token request carries the revision it was
decided under.

A custodian refusal of an allowed call means the two copies disagree, or the gateway asked
for more than policy allows. A vendor refusal means the gateway's policy and the vendor's
permissions disagree. Each is recorded with its own error kind so it can be counted. How a
vendor refusal is recognized is defined per connector. GitHub answers 404, not 403, for a
private repository the credential cannot see, so the GitHub connector counts a 404 on a
resource inside the caller's limit as a refusal. Where a vendor answers a refusal with an
empty result, as a log search filtered by role does, it cannot be told from no data and is not
counted. A proxied server's refusal is counted only where its error says so.

### 6. Employees

**Reads keep the Q3 rule, now checked by the loader and by check 6.** A shared identity serves
employee reads only for data explicitly approved for those employees. That approval is the
group's resource limit: putting a resource in a group's limit approves it for the group. A
proxied tool on a shared identity reaches nothing outside the caller's limit: its credential
is narrowed to it, or rule 5 refuses the snapshot.

A limit names whole resources, such as a Jira project or a Confluence space. Some systems
restrict content inside them, with Jira issue security levels and Confluence page
restrictions. Approving a project for a group does not approve restricted content in it. A
shared credential that serves employees must be unable to see such content, shown by a
restricted canary inside the reach in its test. Otherwise employees use a per-user grant on
that system, or are not served. The owner accepted this reading of Q3 on 2026-10-07.

**Employees start with `read` only.** The employee profile lists `propose` once, when the first
system qualifies: its per-user grants work (encrypted storage, connection, refresh and
revocation) and durable action receipts exist (decision 0009). A profile is a set of
classifications with no per-system part. Which systems employees may propose in is therefore
decided by which `propose` tools are put on employee surfaces, and rule 9 keeps those on
per-user entries. That a system qualifies rests on the reviewer of the change that adds its
tools. `write` and
`destructive` stay denied in every profile.

**Every employee proposal uses the employee's own per-user grant.** A proposal has an author,
and the vendor should record it as the employee's. Under a shared identity, the vendor checks
the shared identity's permission, so an employee could propose where they cannot act
themselves, under a name that is not theirs. Group limits are too coarse to stand in for each
person's vendor permissions. Rule 9 enforces this.

**There is no fallback.** A tool approved on a per-user entry never runs on another
credential. An employee with no grant is refused, with a sentence telling them to link their
account. Since an entry has one credential and a proxied entry's credential cannot write, an
employee may need two grants for one system: a read-only one for proxied reads and one that
can propose for built-in tools.

A per-user grant is therefore required for every employee proposal, and for an employee read
whose shared credential would reach data not in the group's limit or restricted content
inside it.

**A proposal that changes something existing** (amending a proposal, editing a comment) is
`propose` only if the connector checks that the gateway created it for the same principal:
from the gateway's receipts, or, for a delegating control plane, from its resolver, as in
[decision 0003](0003-otto-keeps-its-control-plane-endpoints.md). Without receipts or such a
resolver, a change to something existing is not `propose`. Decision 0009 goes further: no
`propose` tool is served at all until a receipt store is configured.

**Automation that acts on a proposal.** A tool is `propose` only if nothing it creates takes
effect before a person acts. Automation can break that: a comment that Atlantis or a
comment-triggered workflow reads as a command, a Jira automation rule, a push or pull request
workflow that runs with the repository's secrets on a proposal branch, a workflow file changed
on that branch, or an Atlantis autoplan that runs provider code. Such a tool is `propose` only
if its connector refuses content that would set the automation off, as Otto's GitHub connector
does for Atlantis comment commands, or the automation does not run on the gateway's
proposals. Otherwise it is `write`.

Which automation counts needs its owners and is still open. Until they answer, "otherwise it
is `write`" applies only to automation already named, which today is Atlantis comment
commands. Otto's proposal tools and other built-in `propose` tools stay `propose` under the
position in design.md section 8, that a proposal starting CI is acceptable where those
workflows only build and test. They also refuse changes to CI workflow files and to Atlantis
configuration, as well as command text. A proposal that changes ordinary code or `.tf` files
can still start an Atlantis autoplan, or a pull request workflow that runs with the
repository's secrets. That gap is listed under what stays unguarded.

### 7. Reads that show more than the caller could otherwise see

The 2026-10-04 amendment to decision 0006 deferred a breadth field until the first such tool.
This record settles it: there is no field. The breadth is itself a resource.

A tool that can read across many accounts takes the accounts as a structured argument, and
check 6 checks each named account against the caller's limit. A call that names no accounts
names the breadth resource instead, such as `aws / organization / o-example`, and is allowed
only for teams and groups whose limit lists it. Limits match exactly, so the organization does
not cover a call that names an account. A team opted in to the whole organization lists each
account as well, or calls without naming one. A team whose limit lists only its own accounts
uses the same tool and names them.

Opting in is adding the breadth resource, or accounts, to a team's or group's limit: one
reviewed change to the policy files, revoked by removing it. The amendment also said such a
tool is served only on surfaces whose allowlist is the opted-in teams and groups. That is not
needed. Check 6 refuses a caller without the resource on any surface, and nothing in a
snapshot marks a tool as broad for the loader to check. A surface of its own remains a way to
keep the tool out of other callers' lists.

A broad read with free-form arguments, such as the AWS MCP Server's `call_aws`, is not
exposed. The AWS inventory tool takes fixed parameters (resource type, account, Region, tag),
never a Config query, and its connector builds the query and adds the account filter: the
named accounts, or none when the organization was named. The adapter and the filter read the
same parameters, so neither checks the other. The filter is tested with hostile parameter
values against a fake aggregator in the per-change loop, and against a real one in its reach
test. IAM restricts the role to the inventory query action. That limits what the role can do,
not which accounts it can see.

### 8. Gateway policy and vendor permissions

Both must allow. The gateway decides which caller may use which tool, on which surface, for
which resources, under which classification, with which credential. The vendor decides what
that credential may do, including inside a resource the gateway does not see, such as Jira
issue security levels and Confluence page restrictions. Each can only narrow what the other
allows. The gateway does not copy vendor permissions into its own data, and a vendor
permission never stands in for a gateway rule: a read-only credential does not make a tool
`read`, and a person's admin rights do not permit a `write` tool. The gateway may narrow a
per-user grant below the employee's own permissions. It never lends a broader credential to
get around them.

| Call | Gateway | Vendor | Result |
| --- | --- | --- | --- |
| A payments service reads a file in `example-org/payments-api`, in its team's limit. | Allows. Token narrowed to the team's repositories (`limit`), as Otto's are today. | Allows. | `ok`. |
| The same service reads `example-org/billing-core`. The GitHub App can read it; the team's limit does not list it. | Denies at check 6. | Not asked. | Denied. No token is requested. |
| Any caller calls a merge tool, `write`. The caller administers the repository. | Denies at check 5, in every profile. | Would allow. | Denied, pointing to a proposal. |
| A service's built-in Jira read of an issue in an allowed project, under a security level. | Allows: it sees the project, not the level. | Decides by the team's service account. | Whatever that account may see. The gateway's limit stops at the project. |
| An employee reads the same issue through a shared Jira credential. The project is in the group's limit. | Allows. | Hides it: the shared account holds no security level, as its test showed. | `error`, not found. |
| An engineer reads a private repository in the `engineering` group's limit through a per-user grant. The engineer is not a collaborator. | Allows. | Refuses, answering 404. | `error`, counted as a vendor refusal because the repository is in the limit. Not retried on a shared identity. |
| An engineer with no GitHub grant opens a draft pull request, once employees may propose. | Allows. | Not asked. | `refused` by the credential layer: link your account. |
| Otto amends a pull request its resolver says is not Otto's proposal. | Allows. | Not asked. | `refused` by the connector. |
| The inventory team searches logs through Sumo Logic's server. Its entry's reach is the role filter `sumologic / search-filter / _sourceCategory=inventory/*`, which is in the team's limit. The query names `payments/*`. | Allows. Check 6 sees the reach, not the query. | Returns nothing outside the role, if the "To confirm" test showed the filter applies to MCP searches. | `ok`, empty. The row points to the entry, marked as a reach. |
| The same entry on a surface that admits a team whose limit lacks that resource. | Refuses the snapshot (rule 5). | Not asked. | Never served. |
| A call to a proxied tool carries an argument its approved schema does not declare. | Allows; the argument check refuses. | Not asked. | `error`. Never forwarded. |
| A team that has not opted in asks for AWS inventory across every account. | Denies at check 6: the organization is not in its limit. | Not asked. | Denied. |
| Atlassian's hosted `addOrEditJiraIssueComment`. | Classified `write`: it can edit a comment the gateway did not create, and a proxied server cannot be checked for that. Denied in every profile, and refused at load as a proxied tool that is not `read`. | Not asked. | Never served. |
| `call_aws` on the AWS MCP Server. | Not exposed: it runs any API operation, and its reach is the whole role. | Not asked. | Never served. |
| An Otto turn comments with `github_pr_comment` on a person's pull request in its team's repository. | Allows under the exception in section 9, once it is in force, and only while Otto says the turn is current. Until then denies at check 5. | Allows. | `ok`, with the exception that allowed it on the row. |
| The same tool, with a comment that starts `atlantis apply`. | Allows under the exception. | Not asked. | `refused` by the connector. |

Resource identifiers are literal strings matched exactly. `_sourceCategory=inventory/*` above
is the role's filter as written, not a pattern.

### 9. Otto's comment tools: a recorded exception

On 2026-10-07 the owner accepted a narrow, recorded exception for these tools, the answer Q9
called likely. This record sets its conditions. Otto's `github_pr_comment` comments on any pull
request in the team's repositories, and `jira_comment` on any issue in the configured Jira
projects. Under the comment rule in decision 0006 both are `write`, because they comment on
things the gateway did not create. They stay `write`. Otto's other three writes,
`github_create_pr`, `github_propose_change` and `github_amend_change`, are `propose` and need no
exception. The two comment tools are allowed to Otto's callers only while all of these hold:

- **The profile for Otto's sandboxes only.** No other profile has an exception. The profile for
  Otto's control-plane surface has none, and services and employees are denied both tools. The
  profile for Otto's sandboxes requires currency, so each call is also allowed only while Otto
  says the turn is current ([decision 0012](0012-what-a-turn-grant-binds.md)). The snapshot
  loader refuses a list of excepted tools on any profile that does not require currency, so the
  exception can never sit where calls are not fenced.
- **The tool refuses the commands of the bots named when it is approved.** Today that is
  Atlantis: a comment such as `atlantis apply` is refused, as Otto's `github_pr_comment`
  refuses it now. A command another bot reads, such as `/deploy`, is refused once that bot is
  named. If the owners of CI and Atlantis name more commands (see Still open), they are added
  when the tool is approved again.
- **It reaches only the team's repositories, or the configured Jira projects.** Check 6 and
  the connector hold it to them, as for any built-in tool.
- **Every call is audited as usual,** and the row records the exception that allowed the
  call, in a field of its own. It is not a reason kind, which belongs to a denial.
- **It is listed in the register of exceptions that decision 0010 keeps,** with an owner, as
  every entry there has: this project, and Otto once Otto's owners agree to share it. The
  owner accepted it. Like every entry there, it needs the signature of a named security owner,
  who has not been named yet (see Still open).
- **It comes into force only when both hold:** #12 has built its mechanism, and the security
  owner has signed its register entry. Until then both tools stay denied.
- **It is reviewed on the register's cadence:** every 90 days and before each milestone's
  rollout, so before milestone 4, when it first comes into force. It is also reviewed when
  Otto's cutover (#13) completes. The review keeps it, narrows it or ends it.

Atlassian's hosted `addOrEditJiraIssueComment` gets no exception. It can edit comments other
people wrote, and as a proxied tool it could not be held to the conditions above.

This is not the decision that permits direct writes, which decision 0006 says must replace its
section on them. The core has no way yet to express an exception, and it needs a change to
check 5 itself. Checks stop at the first that denies, and check 5 denies `write` before any
later check runs, so a list checked after it could never allow. Under #12, check 5 denies
`write` and `destructive` unless the tool is named in the calling profile's list of excepted
tools. The profile gains that list, and an allowed decision names the exception that allowed
it, which the audit row records in a field of its own, not as a reason. The property
`a_write_or_destructive_tool_is_never_allowed` is restated as "never allowed, except a tool
named in its profile's exception list", and check 5's comment changes with it.

The list names tools, never a classification, so it cannot permit `write` in general. That is
why it does not reopen the objection in decision 0006 to a per-profile opt-in, that the
company's posture becomes the union of every profile's weakest setting. A setting that permits
a classification permits every tool of that kind, including ones approved later. A name permits
one tool, and adding one takes a decision record and a register entry, as this one does. Every
exception to the company's posture is then in the register, read in one place. The list is
built under #12 with Otto's GitHub and Jira tools, not now. Until it exists and the register
entry is signed, both tools stay denied to Otto's callers, and the conformance cases that use
them stay an expected difference (design.md section 18).

### What each guarantee costs, and what stays unguarded

| Guarantee | Holds against | Rests on the reviewer | Costs |
| --- | --- | --- | --- |
| A proxied call's credential reaches nothing outside its caller's limit. | An agent choosing arguments to get around a check; a server that ignores its arguments. | The recorded reach, the test that showed it, and the vendor honoring a narrowed token. | A vendor credential per distinct limit where the vendor cannot narrow per call, often a service account per team. A dated test per server. Free-text tools need a narrow credential or a built-in connector. |
| Each resource a call names is checked before it runs, and the row records it or the reach. | An agent choosing arguments. | That the structured arguments carry every resource the tool reaches. | An adapter per proxied tool `declared` from its arguments. |
| A proxied tool receives only arguments its approval declared. | A second, undeclared argument naming another target. | That no declared free-text argument or open object can name a resource. | Schema validation in the proxy path. |
| Nothing after the decision function can allow. | Every later part, by construction: a denied call has no guard to run with. | Nothing. | Some refusals come after the row is begun, and the caller learns of them only on calling. |
| A careless declaration fails at load, where the loader can tell. | Approvals that contradict each other or the limits. | Everything the loader only compares: classification, reach, narrowing, what a credential permits. | Nine loader rules and their table cases. |
| A call runs only on the credential its approval names. | Fallback bugs; an operator picking a broader mode. | Nothing. | Employees without a grant cannot use the tool until they link an account. |
| An employee's proposal is theirs and bounded by their own vendor permissions. | A compromised laptop agent proposing where the person could not. | That a system's grants and receipts work before its `propose` tools reach employee surfaces. | Per-user grants and receipts before any employee proposal, and possibly two grants per system. |
| A widened service account withdraws its tools. | A vendor-side change made outside an approval. | That the canary sits outside the reach. | A scheduled check per proxied entry, and a canary where the vendor cannot report reach. |

What stays unguarded: a proxied server misusing its credential within its reach, including
reaching more of its caller's limit than a call named, which the row does not show; a
vendor-side change to a reach between scheduled checks, and any added resource a canary cannot
see; a connector bug that reaches resources the call did not name; a self-built server shared
by several teams carrying one team's data to another in its own state; anything the reviewer
gets wrong in the third column above; Otto's two comment tools, which act on pull requests
and issues the gateway did not create, within the exception in section 9; until the
automation owners answer, a proposal that starts an Atlantis autoplan or a pull request
workflow that runs with the repository's secrets; and, on laptops, other routes to the vendor
(decision 0010).

## Alternatives rejected

- **Trust a proxied server to check its own scope.** It is the simplest option and the only
  one for free-text arguments. But the gateway cannot see or test that check per call, the
  row records `unknown`, the server's behavior can change without its definition changing,
  and a wrong or compromised server reaches everything its credential can.
- **Bound a proxied tool `declared` from its arguments by the union of its callers' limits.**
  One credential could then serve every team. But a server that ignores its arguments, or is
  compromised, could return one team's data to another, and the row would name only what the
  arguments said.
- **Parse free-text query languages in the gateway.** Each language is large and changes on
  the vendor's schedule, and a parser that disagrees with the vendor's in one case is a way
  around the limit. A built-in connector may add a filter where the vendor's language
  guarantees the caller's text cannot widen it, as Otto's GitHub search does. That is a
  `checks_own_scope` tool, tested with hostile queries.
- **A new declaration that leaves a credential-limited tool's resources `unknown`.** It needs
  a change to check 6 and leaves the row unable to say what the call could reach. Naming the
  reach keeps the function unchanged and lets the row point to it.
- **A four-field assurance record on every tool.** Argument validation and output limits
  follow from the kind of connector or are the same for every tool. As per-tool fields they
  would be states that should not be representable.
- **A per-user exposure path with no adapter, as a declaration of its own.** A per-user
  connector is already expressible as a reach of the whole site, listed in the group's limit,
  with the vendor narrowing per person. A separate value would add a check-6 rule for the
  same thing.
- **Employee proposals under a shared or bot identity, with the employee named in the text.**
  Quicker, since no per-user grant is needed. But the vendor shows the shared account as the
  author and applies its permissions, and the record of who asked lives only in free text.
- **Fall back to a shared identity when an employee has no grant.** The effective permission
  becomes the shared identity's, which is what the grant exists to avoid.
- **Let a proxied tool be `propose` on the approver's judgment.** The gateway cannot check
  what the tool changes or refuse command text for a server it does not understand.
- **Mirror vendor permissions in the gateway's limits,** for example by syncing GitHub team
  membership. Two copies drift. Per-user grants put the vendor's own check on the path
  instead.
- **A breadth field on tools and profiles, or a surface of its own for every broad tool.** A
  breadth resource says the same thing with the exact-match limits that exist, and check 6
  enforces it on any surface. Nothing in a snapshot marks a tool as broad, so a surface rule
  could not be checked.
- **Trust a recorded reach once approved.** Vendor administrators change service accounts
  without touching this repository.
- **Check a reach from the registry with its own credentials.** That is a second holder of
  each credential, making vendor calls with no decision and no row, which decision 0003
  rejects.
- **Cut short, in the gateway, a result that is too large.** A result cut short with no flag
  is wrong data that looks right. A connector's flagged truncation is different, and is kept.

## Consequences

- Sections 1 to 8 do not change `ResourceDeclaration`, check 6, or the function's inputs and
  reasons. Section 9 changes check 5 under #12: the profile gains its list of excepted tools, an
  allowed decision names the exception that allowed it, recorded in a column of its own and not
  as a reason, and the property that a `write` or `destructive` tool is never allowed is
  restated to except the tools on that list. The loader refuses that list on a profile that does
  not require currency. The snapshot gains a table of connector entries (kind, credential mode,
  narrowing, reach, what the credential permits, the reach test's date) and, for each `declared`
  tool, its entry and whether its adapter reads the arguments or names the reach. The loader
  gains nine rules, each with a table case and a mutation in `scripts/mutation_check.py`.
- A property joins the decision properties: for any snapshot that loads, every admitted
  team's and group's limit holds the whole reach of every tool on its surfaces that is
  `declared` as the reach, or is proxied with narrowing `none`.
- One constant adapter serves every tool `declared` as the reach. Adapters for proxied tools
  `declared` from the arguments are per-tool gateway code, fuzzed with the other argument
  fuzzing.
- A system with a service account per team has one entry per team, and its tools are approved
  once per entry. A tool name is unique in a snapshot, so the `{system}__{tool}` names of
  design.md section 14 use the entry's name as the system part.
- The audit row gains: whether its resources were named by the call or are a reach, recorded
  by reference to the entry; the credential identity used (the mode and the vendor-side
  principal, never the secret); and an error kind: invalid arguments, an oversized or late
  result from a `read` tool, a custodian refusal or a vendor refusal. `refused` now covers the
  credential layer's refusal as well as the connector's. An oversized or late result from any
  other tool is `unknown`. The five outcomes are stated once, in decision 0009. Otto's
  `gateway_audit` table has none of these columns, so they stay in this gateway's own record
  unless Otto adds them. Whether it gains them is part of the question pull request #30 put
  in Q12, whether that table gains a general column and who adds it. That is its one home.
  Noted on 2026-10-10: [decision 0014](0014-rollout-safeguards-and-audit-operations.md) moves
  that question to the one list of Otto requests (Q18, #21), which is now its one home.
- Built-in `checks_own_scope` tools report the resources they reached when they finish, the
  follow-up the resources column of pull request #30 left. This is required before milestone 4
  brings Otto's code search over.
- A withdrawal makes a snapshot with a revision of its own (section 4), so the snapshot type
  gains a way to be derived from another by removal.
- Before the first policy file lands, the repository gains a `CODEOWNERS` entry for the policy
  files and a branch rule requiring code-owner review. The repository administrator sets both.
  That is what enforces the second reviewer.
- Decision 0006 says a connector's scope refusal is the only decision made outside the
  function. That becomes: the argument check, the connector, the credential layer and the
  custodian may each refuse outside it, and none may allow. Decision 0009 adds the receipt
  check at begin to that list.
- `checks_own_scope` is available only to built-in connectors. Otto's `github_amend_change`
  is `propose` only because Otto's resolver confirms the pull request is Otto's proposal;
  without that answer it is refused, as decision 0003 says.
- Milestone 3 builds sections 1 to 5: schema validation before forwarding, connector entries,
  the loader rules and the scheduled reach check. The mock slice of milestone 2
  ([decision 0008](0008-mock-the-first-slice.md)) does not wait for them. In milestone 3 the
  kind slice is extended to show them: the mock server registered as one entry per team, each
  presenting an identity the mock server limits to that team's project; an undeclared
  argument refused before forwarding; and one entry reaching both projects, served to both
  teams, refused at load.
- The proxied candidates in systems.md (Sumo Logic, MongoDB Atlas, Atlassian) are read-only
  under this record, and each needs its "To confirm" test recorded before exposure. The Sumo
  Logic test must show that the role's search filter applies to the MCP log search. An entry
  that will serve employees adds a restricted canary inside its reach. A Jira comment proposal
  stays built-in.
- The vendor reach tests run in the slow loop, once per proxied entry before exposure and
  again whenever its vendor-side configuration changes. The per-change loop shows an
  undeclared argument never reaching the fake MCP server; a `call`-narrowed token request
  naming exactly the call's resources; a fake vendor whose reach is widened between runs
  causing withdrawal, with later rows carrying the withdrawal's own revision; the AWS account
  filter holding against hostile parameters; and each built-in `propose` tool changing only
  refs, pull requests and comments it created in that call or that its receipts or resolver
  attribute to it, with the fake vendor recording the target of every write.
- Onboarding a proxied server is slower: someone with vendor admin rights must create a
  narrow credential, often one per team, and run the test before any of its tools can be
  exposed. Changes to that credential go through the tool's approval; otherwise the reach
  check withdraws the tool.
- Otto's behavior does not change, except that its proposal tools, when this gateway serves
  them, refuse changes to CI workflow files and Atlantis configuration until the automation
  owners answer. Otto's owners review the declarations for its eighteen tools in this
  repository, and each team's repositories become its resource limit in the snapshot when
  Otto's adapter is built. Nothing is added to `conformance/mutation_check.py`.
- Milestone 5 builds section 6. Section 7 is built with the first breadth tool, AWS
  inventory.
- Milestone 4 (#12) builds the exception mechanism in section 9, with a decision-table case for
  each of Otto's two comment tools, a case showing the same tools denied in every other
  profile, a case showing `addOrEditJiraIssueComment` denied, the restated property, a
  mutation that removes the list check, and a loader case refusing the list on a profile that
  does not require currency. When the exception is in force, the conformance cases that use
  the two tools move out of the expected differences.

## Decided by the owner

On 2026-10-07 the owner accepted the recommendations this record made, with one departure,
on Q9, below. Where a question also needs someone else, the owner's part is decided here and
the rest is under Still open.

- **Every approval has a second reviewer.** An approval of a tool's classification,
  declaration, credential entry or reach test needs a second reviewer, enforced by code owners
  on the policy files and a branch rule (see Consequences). Much of this record rests on that
  reviewer.
- **Data for employees and broad reads is approved by its owner and a security reviewer.**
  Putting a resource in a group's limit, or a breadth resource in a team's, needs the owner of
  the data, such as the cloud platform team for AWS, and a security reviewer.
- **A group's limit approves the resource, not restricted content in it.** That is the
  explicit approval Q3 requires. A shared credential serving employees must be unable to see
  restricted content, such as Jira issues under a security level or restricted Confluence
  pages, shown by a canary in its test. Otherwise employees use per-user grants on that
  system.
- **Every employee proposal uses a per-user grant.** No system is an exception. This tightens
  design.md's "per-user grants where authorship or permissions require them".
- **Employee launch is reads only.** Proposal tools follow one system at a time, each once its
  per-user grant and receipts work: first GitHub draft pull requests, and comments on pull
  requests the gateway created, for engineering; then Jira comments on issues the gateway
  created. An employee may need two grants on one system. That follows from sections 2 and 6
  as accepted: an entry has one credential, and a proxied entry's credential cannot write.
- **A proxied read under an employee's own grant may be exposed with no adapter,** its reach
  being the whole site in the group's limit, so the agent reaches whatever the employee can.
  Reads only.
- **Until the automation owners answer, a `propose` tool refuses changes to CI workflow files
  and Atlantis configuration,** as well as command text, and stays `propose` (section 6). That
  may change Otto's proposal tools.
- **Self-built servers:** one team per server until its owner shows it keeps no state between
  calls. The owner states the backend's permissions in the approval, and rule 4 applies to
  that statement. Self-built servers stay read-only until receipts exist (decision 0009) and a
  later decision says what an owner must show for a server to propose.
- **A reach mismatch withdraws** the entry's tools. It does not only alert.
- **Built-in `checks_own_scope` tools report what they reached before milestone 4,** so the
  rows can say which repositories Otto's code search reached.
- **Policy snapshots are kept as long as the audit rows** they explain, so the declaration and
  reach in force can be read for any row. How long rows are kept is Q12.
- **One record.** Sections 6 and 7 are not split into a record of their own.
- **Q9 is narrowed, not retired.** This is the one departure from the record's
  recommendation, which was to retire Q9 on acceptance. Its remaining parts, under Still open,
  need people other than the owner, and retiring it now would leave them tracked only inside
  this record. Q9 is retired once they are answered.
- **Otto's comment tools get a narrow, recorded exception.** The owner accepted the exception
  Q9 called likely. Its conditions are the ones section 9 sets.

## Still open

These need someone other than the owner, or had no recommendation. The record reads correctly
while they are open: each says what holds until it is answered.

- **Which downstream automation makes a tool `write` rather than `propose`:** Atlantis
  comment commands and autoplan, comment-triggered workflows, push and pull request workflows
  that run with repository secrets on proposal branches, changes to workflow files on those
  branches, and Jira automation rules. This includes the question decision 0006 left open:
  whether a proposal stays `propose` in a repository where a workflow it starts can deploy or
  holds a production credential. Decided by the owners of Atlantis, CI and Jira automation.
  Until then, only Atlantis comment commands make a tool `write`; built-in proposal tools stay
  `propose` with the interim refusals in section 6, and the gap it names stays unguarded.
- **Which AWS accounts are in scope** for broad reads and employees. Decided by the cloud
  platform team, as the data's owner. Until then no AWS account and no breadth resource is in
  any limit, so AWS inventory is served to no one.
- **Who the security reviewer and the security owner are:** the reviewer of data approvals,
  and the named security owner who signs entries in decision 0010's register, including the
  exception in section 9. Decided by the security team. Until then no resource is added to a
  group's limit and no breadth resource to a team's, and the exception's register entry is
  marked as awaiting that signature. The exception is not in force until it is signed, even
  once #12 has built its mechanism.
- **Who the code owners of the policy files are,** and the branch rule that requires their
  review. Set by the repository administrator, with the owner naming the code owners. Until
  then no policy file lands.
- **Whether group limits and broad-read opt-ins expire** and are recertified, and how often.
  No recommendation was made. Decided by the owner with the security team, before
  milestone 5. Until then an approval stands until a reviewed change removes it.
- **Whether a per-user rate limit is a prerequisite** for employee proposals. No
  recommendation was made. Tracked in Q12, for the owner. It is answered before the first
  employee proposal tool is approved.
  Noted on 2026-10-10: [decision 0014](0014-rollout-safeguards-and-audit-operations.md) leaves
  it open for the owner until milestone 5, and tracks it in #15.
- **How often the reach check runs,** which bounds how long a widened service account goes
  unnoticed. No recommendation was made. Tracked in Q11, for the owner. A proxied entry is not
  exposed outside development and test deployments until it is set.
- **Asks of IT and vendor administrators:** who creates and owns the gateway's narrow service
  accounts in Atlassian, Sumo Logic, MongoDB Atlas and AWS; agreement that changes to them go
  through the tool's approval; any administrative credential the reach check needs to read a
  vendor's report; the OAuth applications per-user grants need in GitHub and Atlassian;
  confirmed ownership of the Okta groups that limits name; and how many service accounts are
  acceptable, since one per distinct limit may cost licences or seats. Decided by IT and each
  vendor's administrators. Until then no proxied entry is exposed, since none has a narrow
  credential or a recorded test, and no per-user grant exists.
- **Asks of Otto's owners:** review the declarations for Otto's eighteen tools; agree that each
  team's repositories move from the team manifest into the snapshot's limits; and check Otto's
  proposal tools against the interim automation refusals. Decided by Otto's owners, before
  milestone 4. These go to them in the one list of Otto requests that decision 0012 describes,
  raised by whoever the owner names. Until then this gateway serves none of Otto's tools.
  Whether `gateway_audit` gains columns for resources, the credential identity and the error
  kind is not asked here: it is the question about Otto's audit table in Q12.
  Noted on 2026-10-10: [decision 0014](0014-rollout-safeguards-and-audit-operations.md) moves
  that question into the one list of Otto requests (Q18, #21).
