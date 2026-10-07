# 0010: What stops an agent going around the gateway

Date: 2026-10-06. Status: accepted on 2026-10-07, when the owner accepted the recommendations
made for each question this record raised. Settles Q17.
[Decision 0008](0008-mock-the-first-slice.md) answered it for the first slice in kind; this
record says what that test must show, and covers the other environments. Some questions need a
party other than the owner. They are listed under "Still open", with who decides and what
holds until they do.

## Context

The gateway decides and audits the calls it receives. It cannot decide a call it never sees.
An agent that holds a credential for a target system, or can reach a target system or a
self-built MCP server directly, is governed when it uses the gateway and ungoverned when it
does not. Design section 1 said "the one path" is a property of each environment, and left
to Q17 which environments meet it.

The gateway's rules have the same limit. Under
[decision 0006](0006-what-the-decision-function-sees.md) as amended on 2026-10-04, `write` and
`destructive` tools are denied in every profile, which is how Q4's denial of production
mutation is enforced. Audit rows are to record the resources each call named, a change under
review when this record was accepted. Both describe calls through the gateway and nothing
else. What this record says about the resources on audit rows applies once that column exists.

Q17 said Otto's sandboxes already have default-deny egress. At the pinned Otto commit
`752395a` that is true of a sealed turn only. Under Otto's ADR-0010, a turn whose token
carries a public-egress claim reaches the public internet through one logged proxy. That token
is not the grant this gateway sees. The proxy resolves each name and refuses internal ranges
by address, but its "credential-spend" list names only the model provider and is matched
against the host name in the CONNECT line. Every target system's hosts can be reached through
it, by name or by any name that resolves to them, and public wildcard-DNS services give any
address such a name with no registration.

A sandbox can also reach the EKS Pod Identity endpoint, which a network policy rule opens on
purpose, and is associated with an AWS role that carries no policy, by design. Nobody has
requested the credential since the association was made. Otto's gateway does not use it.

Otto's measurements also decide what counts as evidence. On EKS, network policy enforcement is
a setting on the network plugin, off by default: on Otto's pilot cluster a policy enforced
nothing for sixteen days, and an add-on upgrade switched enforcement off again eighty minutes
after it was fixed. A probe that cannot connect looks the same as a policy that blocks it, and
Otto's sandbox image has no `curl`. kind's default plugin, kindnet, enforces policy from kind
v0.24, but keeps connections opened before a policy applied, and a new pod is outside its
policy for about its first second. `kubectl port-forward` bypasses policy. Node egress on
Otto's pilot cluster left through one NAT address, shared by every workload.

Employees' laptops have no default-deny egress, and employees hold their own vendor sign-ins,
tokens and command-line tools. No vendor-hosted MCP server is known to accept only the
gateway's credential. Device management is out of scope for this project.

## Decision

### Two claims

Each environment that serves agents carries one of two claims, stated in the design.

- **The only path.** From this environment, an agent can act on a target system with Org's
  authority only through the gateway. Reading what a vendor serves to anyone, such as a
  public repository, carries no authority and is outside the claim.
- **The governed path.** The gateway is the route the environment is set up to use, and what
  passes through it is decided and audited. Other routes exist. Each known one is in the
  register below, and nothing in the gateway's records describes them.

An environment has the governed path claim until its evidence for the only path exists and is
current. There is no third claim. An environment that serves no agent carries none.

The only path is defined by authority, not by hosts. A stricter definition, no route to any
host a target system runs, was not taken: it would also refuse hosts that serve only public
content, and cost toolchains more.

### Three controls

The only path holds where all three of these hold for the agents in an environment.

1. **No credential provisioned.** Nothing provisioned to the agent holds or yields a
   credential for a target system: no environment variable, mounted file or projected token;
   no metadata or workload-identity endpoint that returns one; no cloud identity that
   authorizes anything at a target system; and no Kubernetes permission that yields a
   credential or a pod that holds one. Those are: reading secrets; creating pods, or the
   workloads that create them (Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs and
   CronJobs); exec, attach, port-forward or ephemeral containers on pods; requesting
   ServiceAccount tokens; impersonation; bind or escalate on roles; and `nodes/proxy`. AWS is a
   target system.
2. **No route.** The agent reaches target systems and self-built MCP servers only through the
   gateway. Inside Org's network that is network policy. A Kubernetes NetworkPolicy cannot
   name a public host, so for a system on the public internet it means no public egress, or a
   proxy that refuses every host that accepts the system's credential, by resolved address as
   well as by name. That is more than its API and MCP hosts: `github.com` takes a token for a
   git push, an Atlassian site's own host serves the REST API, and AWS's regional and S3
   endpoints take AWS credentials. Each system's hosts and ranges are in a checked-in list
   that records its source, such as GitHub's meta API or the ranges AWS publishes.
3. **Only the gateway accepted.** A self-built server the gateway proxies accepts only the
   gateway's own workload identities: never a source address, and never a valid token from a
   trusted issuer for any other subject. Vendor-hosted servers cannot be held to this. Admin
   controls such as Slack's approval of apps narrow what they accept, so for vendors the only
   path rests on controls 1 and 2. Some vendors can limit one credential to source addresses
   (Slack apps and MongoDB Atlas MCP configurations; Atlassian's allowlist covers the whole
   organization). Limiting the gateway's credential to its egress addresses would be defence
   in depth, worth nothing where those addresses are shared. Whether to do it is for IT and
   the vendors' administrators (see "Still open"). No claim rests on it.

A credential also reaches an agent through what it reads: a token committed to a repository,
pasted into an issue or printed in a job log, which the gateway's own read tools may serve it.
No control on the environment excludes that, so the only path holds against a leaked
credential only as far as control 2 holds. With a credential provisioned, the environment is
one drifted network policy away from an ungoverned path. Controls 1 and 2 are both required.

An environment served by minted short-lived credentials (design section 9) cannot have the
only path claim, because the caller holds the credential by design.

### Evidence

Evidence is dated output from the route check or a test, naming the environment. A statement
is not evidence, and neither is the presence of policy objects. Every check that shows a route
refused also shows, in the same run, that a route that should work does. A check that could
not make an attempt reports "could not probe", never "refused", and a name that does not
resolve is not a refusal at the server's address. Each result is kept in an evidence log
beside the register, with the claim it supports, so the claim that held at any past time can
be read from the log.

A claim lapses to the governed path when a check fails, when its evidence is older than seven
days, or after a change that could open a route: to the network policy, the network plugin or
its settings (add-on upgrades included), credentials or identity bindings, or the registered
self-built servers. Until the route check runs on a schedule, the seven-day age is what catches
a change nobody noticed. Renewing evidence after a change is a step in the environment owner's
change process. For the kind run that owner is this project. For a real cluster it is the
platform owner (see "Still open"); until that owner adds the step, only the seven-day age
catches a change.

### The route check

This repository provides one small program in two parts, each with only the access it needs.
**The operator step** runs outside the workload. It needs `get` and `list` on what it reads,
`create` on `subjectaccessreviews`, and `patch` on `pods/ephemeralcontainers` in the
workload's namespace, to start the probe. It changes nothing else. It picks a running pod of
the workload, and records and checks:

- the network plugin and, where enforcement is a setting, that setting as read from the
  plugin's running agent on the pod's node. It fails if enforcement is off.
- that the pod has no secret volume and no variable from a secret, and that no literal
  variable or mounted ConfigMap holds a string in a known vendor token format.
- by SubjectAccessReview, that the pod's ServiceAccount holds none of control 1's Kubernetes
  permissions, in the workload's, the gateway's or a server's namespace or across the cluster.
- the cloud identity bound to the ServiceAccount, if any, for the owner to check.

**The probe** runs as an ephemeral container in that pod, so it has the pod's network
namespace, ServiceAccount and labels. It needs nothing from the agent's image. Copying a binary
in was not taken: it needs `pods/exec`, and `tar` in the image. The probe sends no credential
for a target system. It reaches the gateway, and fails if it cannot. Then it tries each direct
route on the checked-in list, by name and by address: the hosts that accept a credential for
each target system the gateway holds one for, each registered self-built server, and the
metadata and workload-identity endpoints. Each must be refused.

Where the route is direct, "by address" means the address literal. A proxy can refuse every
literal, as Otto's does, so through a proxy it means a name that resolves to the address: a
public wildcard-DNS name, or a name in a zone the check controls. Where the only way out is a
proxy that needs a token, as for an Otto turn with egress open, the probe presents a token that
carries the egress grant. Without one, every row would be refused for the missing token. A row
through the proxy counts as refused by address only when the proxy's log records that
destination's address as the reason, not a literal, a missing token or a missing grant.

A pass shows that the routes on the list failed, not that no route exists, and the token scan
catches carelessness, not intent. The kind run is the first user. Otto's `make egress-check`
is similar in purpose, but runs its probe through `kubectl exec` with the image's own `node`,
so it needs `pods/exec` and depends on the agent's image. Reused for Otto's sandboxes, it gains
a row for each target system's hosts, by name and by a name that resolves to each address, and
the operator step's checks beside it. Whether its probe moves to an ephemeral container is
Otto's call.

### Per environment

| Environment | Claim | Evidence | Needed before |
| --- | --- | --- | --- |
| First slice, in kind | The only path, to the mock server, once the kind run's evidence is current. | The kind run, below. | The first slice is called done (milestone 2). |
| First slice, Docker Compose | None. It is run by hand, serves no agent, and is never given a real credential. | None. | — |
| Real internal services and scheduled automations | The governed path, until the route check passes in the workload's own namespace. Then the only path. | The route check, run by the environment's owner. | Exposure to real data. A register entry does not stand in for it. |
| Otto sandboxes | The governed path. No Otto turn has the only path while Otto's Go gateway serves any tool through its MCP path. After that, a sealed turn has the only path once its evidence exists and the audit row tells it from a turn with egress open. A turn with egress open keeps the governed path until Otto's proxy refuses every host that accepts a target system's credential, by address as well as by name. | Otto's `make egress-check` from a real sandbox, with a refused row for each such host, by name and by a name that resolves to its address, and for the Pod Identity endpoint, and the operator step's credential checks. | Any Otto turn is said to have the only path. |
| Otto control plane | Not an agent, so no claim. After the cutover stage that moves its vendor actions, it holds no credential for them ([decision 0003](0003-otto-keeps-its-control-plane-endpoints.md)). | The credentials each control-plane component mounts, read from Otto's deploy tree at each re-pin. | That stage. |
| Employees' laptops | The governed path, permanently under this decision. | None for the claim. | Milestone 5. |
| CI runners, externally hosted agents, anything else | Not served, so no claim. None is a planned caller. Adding one needs a row here, and it starts with the governed path. A CI runner always holds a repository token, so it cannot have the only path. | — | — |

**Real internal workloads.** A real workload sees real data through the gateway only after the
route check passes in its own namespace. That narrows the candidates for the first real
workload. A workload that holds a target-system credential for work that is not an agent's
cannot pass control 1. It gives the credential up, or runs its agent in a workload that holds
none, before it onboards. Which clusters real workloads run in, and who runs the check there,
is for platform owners (see "Still open"). Until a check has passed in such a cluster, no real
workload sees real data through the gateway.

**Otto's sandboxes.** Before stage 2 of Otto's cutover, Otto's agents use Otto's Go gateway
and this record makes no claim about them. Stage 2 does not wait for the only path: moving
reads from one gateway to the other opens no route and closes none. Otto's Go gateway is a
second route that acts with Org's authority, decided and audited under Otto's rules, not this
gateway's. While its MCP path serves any tool, writes included, no Otto turn has the only path.

A sealed turn and a turn with egress open share an issuer, a deployment and often a subject, so
Otto is asked to carry the turn's egress setting in the turn grant, which this gateway verifies
and records. It is an additive claim under the two-step rule of decision 0012, on what a turn
grant binds: Otto starts minting it, then this gateway starts requiring it. Otto mints it from
the same setting as the `PublicEgress` claim on its model-broker token, so the two cannot
disagree. A grant without it is read as egress open.

Otto is also asked to remove the sandbox's unused Pod Identity association and the rule that
opens its endpoint. If Otto keeps them, the register holds an entry for the sandbox's AWS
identity, with evidence from outside the sandbox: the role's policies, and a permissions
boundary or service control policy that explicitly denies everything. An explicit deny
overrides any allow in a resource policy. IAM Access Analyzer's external-access findings
cannot show that, because they cover only access from outside the account or organization.

**The kind run.** The gateway calls the mock server with a projected token for the gateway's
ServiceAccount, with the mock server as audience, and the mock server accepts only that
identity. In the slice's one command, in one run:

- Before the network policy is applied, the workload calls the mock server directly, connects,
  and is refused for presenting its own ServiceAccount token. The run fails if this call
  cannot connect. This shows the probe works and the server checks its caller.
- The gateway's call to the same server succeeds.
- The policy is applied. A new pod with the workload's labels and ServiceAccount, started after
  that and given ten seconds to settle, calls the server directly on a new connection and fails
  at the server's address. In the same run it reaches the gateway, and the gateway's call to
  the server still succeeds.
- The operator step's checks pass for the workload, and the report records the kind version
  and the network plugin.

That answers decision 0008's open point about kind's network plugin on every run: a plugin
that does not enforce policy fails it.

**Employees' laptops.** An agent running as an employee can use whatever the employee can: a
command-line tool's login, a personal token, another MCP server on the laptop, and tools the
model provider runs on its own side. That access is granted by vendors and IT, and removing it
is not this project's to do. Limits on clients and sign-in do not close the shell, so they do
not change the claim. Material for employees says "the governed path", never "the only path".
IT security is asked to own the two laptop entries in the register. Until it agrees, this
project owns them. They are accepted, like every entry, by this project's owner with the
security owner's signature. Milestone 5 does not roll out until IT security owns them and they
are accepted.

### Self-built servers at registration

When a proxied server is registered, the registry sends it a `tools/call` naming a tool that
does not exist, which runs nothing, three times: with no credential, with a malformed one, and
with a valid token for the server's audience from a trusted issuer, for a subject outside the
gateway's identities. The first two must be refused with HTTP 401 and a `WWW-Authenticate`
challenge. The third must be refused with 401 or 403. None may return a JSON-RPC result or
error, which would show the call was dispatched. Otherwise the server is not registered. The
registry gets the third token by TokenRequest for a probe ServiceAccount of its own, with the
server as audience. That needs `create` on `serviceaccounts/token` for that one ServiceAccount,
granted by the cluster's owner: this project in kind, and platform owners elsewhere (see
"Still open"). The calls repeat on each drift poll. A server that starts dispatching them is
recorded as open, and its owner and the register's owner are told. Each environment whose
current evidence does not show that server refused has the governed path claim until it is
closed, and the register's owner records which. Its tools stay listed: withdrawing them closes
the governed route and leaves the open one.

A self-built server identifies the gateway by a token for one of the gateway's own workload
identities, with the server as its audience. It accepts only those identities: one for each
deployment, such as the laptop-facing and in-cluster ones, and one for each team service
identity registered for that server. It never accepts a source address or any other subject.
Milestone 2 builds the first, a projected token for the gateway's ServiceAccount with the mock
server as audience. Milestone 3 builds the probe. [systems.md](../systems.md) records both.

### The register

Known routes around the gateway are kept in [route-exceptions.md](../route-exceptions.md),
with the evidence log, and changed only by pull request. Each entry gives the environment, the
route, the control it breaks, what an agent could do with it, why it is accepted, its owner,
who accepted it and when, the next review date, and what would end it. An entry without an
owner or a review date is not accepted. A route that contradicts an environment's claim and is
not in the register is a defect.

**Who accepts an entry.** This project's owner accepts an entry for the company, and a named
security owner signs it. The team that benefits from an entry never accepts it alone. Until
the security team names the security owner, an entry the owner accepts is recorded as awaiting
that signature. This project's owner keeps `route-exceptions.md` and the evidence log.

**Review.** Each entry is reviewed every 90 days, and before each milestone's rollout.

The register also lists the exceptions granted to the gateway's own rules, with who approved
each and its conditions. The first is the exception for Otto's comment tools, granted by
decision 0011.

The first route entries and their owners:

| Route | Environment | Breaks | Owner |
| --- | --- | --- | --- |
| Otto's Go gateway, serving the tools not yet moved, writes included, until its MCP path is retired. It decides and audits under Otto's rules, not this gateway's. | Otto sandboxes | 2 | This project, and Otto once Otto's owners agree |
| Target systems' hosts through Otto's egress proxy, by their own names or any name that resolves to them. | Otto, turns with egress open | 2 | Otto, once Otto's owners agree; this project until then |
| The sandbox's AWS identity, if Otto keeps the Pod Identity association. | Otto sandboxes | 1 | Otto, once Otto's owners agree; this project until then |
| Credentials for Otto's conversation surfaces, such as its Slack app. No sandbox can reach them. | Otto control plane | 1, for a component that is not an agent | Otto, once Otto's owners agree; this project until then |
| The employee's own vendor sign-ins, tokens and command-line tools, and MCP servers configured on the laptop. | Laptops | 1 and 2 | IT security, once it agrees; this project until then |
| Tools the model provider runs on its own side. | Laptops | 2 | IT security, once it agrees; this project until then |
| Vendor-hosted MCP servers accept credentials other than the gateway's. | All | 3 | This project, per vendor |
| `kubectl port-forward` and `exec` reach a pod past network policy. | Every cluster | 2, for anyone holding those permissions | Each cluster's owner: this project for kind |
| A new pod is outside its policy for about its first second; kindnet keeps connections opened before a policy applied. | Every cluster | 2 | Each cluster's owner: this project for kind |

### Decided by the owner on 2026-10-07

The owner accepted the recommendation on each question this record raised:

- **What "the only path" means.** An agent can act on a target system with Org's authority
  only through the gateway. Reading what anyone may read is outside the claim.
- **How long evidence lasts.** Seven days, until the route check runs on a schedule, and it is
  renewed after any change that could open a route. Register entries are reviewed every 90
  days and before each milestone's rollout.
- **Who accepts register entries.** This project's owner, for the company, with a named
  security owner signing. The team that benefits never accepts an entry alone. This project's
  owner keeps `route-exceptions.md` and the evidence log.
- **The write denial where the claim is the governed path.** The company accepts that
  decision 0006's denial of `write` and `destructive`, and Q4 with it, binds only calls
  through this gateway there: on laptops, on Otto's turns with egress open, on Otto's turns
  that use Otto's Go gateway, and for real services before their route check passes.
- **Real workloads.** A real workload passes the route check before it sees real data. A
  register entry does not stand in for it. A workload that holds a target-system credential
  for other work gives it up, or runs its agent in a workload that holds none, before it
  onboards.
- **Stage 2 of Otto's cutover** does not wait for evidence that sealed turns have the only
  path. Otto starts on the governed path. No Otto turn has the only path while Otto's Go
  gateway serves any tool through its MCP path. After that, the claim rises when the evidence
  exists.
- **A self-built server found open on a drift poll** keeps its tools listed. Each environment
  whose evidence does not show that server refused drops to the governed path.
- **How a self-built server identifies the gateway.** By a token for one of the gateway's own
  workload identities, with the server as audience. It accepts only those identities, one per
  deployment and per registered team service identity. Milestone 2 builds the first, for the
  mock server.
- **Decision 0003 and Otto's Slack credential.** 0003's "never holds a vendor credential" is
  scoped to the vendor actions it moves to the gateway. The credential for Otto's Slack app,
  and any other conversation surface, is a register entry. 0003 carries a dated note.
- **CI runners and externally hosted agents.** Neither is a planned caller.

### Still open

These need a party other than the owner. The record holds as written while they are open.

- **Otto's owners:** whether Otto's proxy refuses every host that accepts a target system's
  credential, by resolved address as well as by name; what to do about `github.com` and AWS's
  hosts; whether `make egress-check` gains a refused row for each; whether the sandbox's Pod
  Identity association and its rule go, or stay with evidence from outside the sandbox;
  whether the turn grant carries the turn's egress setting; and whether Otto's owners agree to
  own the register entries for Otto's proxy, the sandbox's AWS identity and Otto's
  conversation surfaces, and to share the one for the Go gateway. None of this has been raised
  with them yet. It goes to them with decision 0012's changes, as one list, raised by whoever
  the owner names for those. Until they decide, every Otto turn has the governed path, this
  project owns those entries, and the entries for Otto's proxy and the sandbox's AWS identity
  are not yet accepted. Acceptance stays with this project's owner, with the security owner's
  signature.
- **IT and each vendor's administrators:** whether to limit the gateway's own credentials to
  its egress addresses, where a vendor can limit one credential. That needs fixed egress
  addresses per deployment, shared with nothing else. Until they decide, the credentials are
  not limited, and no claim rests on it.
- **IT:** whether the zero-trust access layer filters laptop egress; whether to push managed
  client settings that limit which MCP servers a managed client may use; and whether vendor
  administrators limit sign-in to hosted MCP servers, personal tokens and tools the provider
  runs. The laptop claim is the governed path whatever IT decides.
- **IT security:** whether it owns the two laptop entries. Until it agrees, this project owns
  them, and milestone 5 does not roll out.
- **The security team:** naming the security owner who signs register entries. Until it does,
  entries the owner accepts are recorded as awaiting that signature.
- **Platform owners:** which clusters real services and scheduled automations will run in, who
  runs the route check there, who owns each cluster's residual entries (the enforcement
  setting, port-forward and exec permissions, and the window at pod start), making renewal of
  evidence a step in their change process, and granting the registry's probe ServiceAccount
  its token permission there. Until they decide, real workloads have the governed path and see
  no real data through the gateway.
- **IT or security,** when detection of calls around the gateway comes back (below): access to
  vendors' audit logs, and who matches them against the gateway's rows.

### Deferred, and what brings each back

- **Detecting calls that went around the gateway,** by matching vendors' audit logs against
  this gateway's rows for credentials only it holds. The rows cannot yet support it: a tool
  that checks its own scope records unknown resources, Otto's `gateway_audit` table has no
  column for them, and Otto's Go gateway holds vendor credentials until it is retired. Revisit
  when a governed-path environment serves real data, and before milestone 5.
- **Running the route check on a schedule, with alerts.** Revisit with the first real cluster.
- **Anything that narrows the laptop gap:** managed client configuration, vendor limits on
  personal tokens, OAuth apps and sign-in to hosted MCP servers. Revisit when milestone 5 is
  planned, or after an incident in which an agent acted outside the gateway.
- **Exceptions as registry data rather than a file.** Revisit with the registry service
  (milestone 6).

## Alternatives rejected

- **One claim for the whole company,** as the first paragraph of design section 1 reads. It is
  false on laptops, and a claim that is false somewhere is not believed anywhere.
- **Make laptops the only path,** by device management, forced routing of vendor traffic or
  removing employees' own vendor access. Each needs IT, device management is out of scope, and
  employees' access is not this project's to remove. The claim changes only if all three
  controls hold.
- **Rely on credentials alone, or on network policy alone.** Credentials reach agents through
  what they read. Network policy selects by label, and Otto's was off twice without anyone
  seeing it.
- **Refuse only each system's API and MCP hosts, or refuse by host name only.** Other hosts
  take the same credentials, and any public wildcard-DNS name gets past a check on names.
- **Source addresses as "accepts only the gateway".** A workload and the gateway can share one.
- **Probe a self-built server with no credential and a wrong one only.** A server that accepts
  any valid token from a trusted issuer passes both.
- **Show that a sandbox's AWS identity authorizes nothing by calling AWS with it.** That needs
  a route and a credential this record forbids, and misses grants made by resource policies.
- **A connection failure alone as the slice's evidence,** as decision 0008 states it. It
  cannot tell an enforced policy from a probe that never connects, and it says nothing about
  the server's own check.
- **Egress enforcement owned by this project:** its own proxy, sidecars or mutual TLS to every
  server. Otto already runs a proxy, the company network is out of scope, and milestone 2
  needs none of it.
- **The gateway checking each caller's environment on every call.** It sees a token, not a
  network, and a probe result is stale once made.
- **A claim column on every audit row.** It would be copied from a table that is wrong as soon
  as evidence lapses. The row records what identifies the environment, and the dated evidence
  log says which claim held.
- **An exception with no owner or review date.** That is how Otto's namespace came to allow all
  egress with no decision recording it (Otto's ADR-0010).

## Consequences

- Design section 1 and the callers table in section 2 state the claim per environment.
  Invariant 1 points here. Q17 is retired, and its statement about Otto's egress is corrected.
- Where the claim is the governed path, decision 0006's denial of `write` and `destructive`,
  and Q4 with it, describes what an agent may do through the gateway, not what it can do, and
  audit rows show who reached a resource through the gateway, not who reached it. That holds
  on laptops, on Otto's turns with egress open, where git over HTTPS can push, on Otto's turns
  that use Otto's Go gateway, and for real services before their route check passes. The owner accepted this for the company on
  2026-10-07. An incident review reads which claim held from the evidence log.
- Milestone 2 adds one thing to the gateway: its connector presents a projected token for the
  gateway's ServiceAccount, with the mock server as audience. The mock server accepts only that
  identity. The kind run gains the positive controls, the server's own refusal and the
  credential checks, and is the route check's first user.
- Milestone 3 adds the registration and drift probe, and the gateway's identities per team
  service identity.
- The first real workload is narrowed to one that can pass the route check: one with no
  target-system credential, in a cluster whose owner runs the check.
- Otto is asked for four things: its proxy refuses every host that accepts a target system's
  credential, by address as well as by name, which ADR-0010 already says the list should
  cover; `make egress-check` gains a row for each; the Pod Identity association and its rule
  go, or stay with outside evidence; and the turn grant carries the egress setting. The last
  is an additive claim under decision 0012's two-step rule, and belongs in 0012's list of what
  Otto changes, so that Otto gets one list.
- `github.com` and AWS are the hard cases for Otto. Both serve toolchains and accept
  credentials, and AWS shares its addresses with much else. Refusing them breaks fetches;
  allowing them leaves a route. Which to do is Otto's call, recorded in the register.
- If IT and the vendors' administrators limit the gateway's vendor credentials to its egress
  addresses, each deployment needs fixed addresses, changed only after every vendor allowlist
  naming them is updated.
- Milestone 5 ships with the claim "the governed path". It does not roll out until IT
  security owns the laptop entries and they are accepted.
- Decision 0003 says Otto's control plane never holds a vendor credential. Slack is now a
  target system and that control plane holds a Slack app credential. 0003 is scoped to the
  vendor actions it moves, by a dated note, and the Slack credential is a register entry.
- Decision 0008 gets a dated note pointing here. Its body is unchanged. Its kind test relied on
  network policy alone; the mock server now also checks its caller.
