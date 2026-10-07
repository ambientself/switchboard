# Route exceptions and evidence

Date: 2026-10-07. Defined by
[decision 0010](decisions/0010-what-stops-an-agent-going-around-the-gateway.md). Kept by this
project's owner, and changed only by pull request.

This page holds three things:

- **Routes around the gateway** that are known and accepted, each with an owner.
- **Exceptions to the gateway's own rules,** each with who approved it and its conditions.
- **The evidence log:** dated route-check or test output per environment, with the claim each
  result supports.

An environment has "the only path" claim only while its evidence in the log is current and
shows all three controls of decision 0010 holding. Otherwise it has "the governed path". A
route that contradicts an environment's claim and is not listed here is a defect.

## How an entry is accepted

Each entry gives the environment, the route or rule, the control it breaks, what an agent
could do with it, why it is accepted, its owner, who accepted it and when, the next review
date, and what would end it. An entry without an owner or a review date is not accepted. An
exception to the gateway's own rules gives the rule it excepts in place of the route and the
control it breaks, and also the record that granted it and its conditions.

This project's owner accepts an entry for the company, and a named security owner signs it.
The team that benefits from an entry never accepts it alone. The security team has not yet
named the security owner, so entries the owner has accepted are marked as awaiting that
signature. A route exists whether or not its entry is accepted. An exception to a rule is what
lets the gateway allow a call, so it comes into force only once it is accepted and signed.

Every entry is reviewed every 90 days, and before each milestone's rollout.

## Routes around the gateway

The controls are those of decision 0010: 1, no credential provisioned; 2, no route; 3, only
the gateway accepted.

### Otto's Go gateway

- **Environment:** Otto sandboxes.
- **Route:** Otto's Go gateway serves the tools not yet moved to this gateway, writes
  included, with Org's authority.
- **Breaks:** 2. It is a second route, outside this gateway's decision and audit. It decides
  and audits under Otto's rules, and its rows are in Otto's `gateway_audit` table, not this
  gateway's. While its MCP path serves any tool, no Otto turn has the only path, and decision
  0006's denial of `write` and `destructive` does not bind the calls it serves.
- **What an agent could do:** call the tools the Go gateway still serves, writes included.
- **Why accepted:** the cutover is staged
  ([decision 0002](decisions/0002-replace-ottos-mcp-gateway.md)).
- **Owner:** this project, and Otto once Otto's owners agree.
- **Accepted:** by the owner, 2026-10-07. Awaiting the security owner's signature.
- **Next review:** 2027-01-05.
- **Ends when:** the Go gateway's MCP path is retired.

### Target systems' hosts through Otto's egress proxy

- **Environment:** Otto, turns with egress open.
- **Route:** the proxy lets a turn reach any public host whose name is not on its
  credential-spend list, which names only the model provider. That includes every target
  system's hosts, by their own names or by any name that resolves to them.
- **Breaks:** 2.
- **What an agent could do:** use any target-system credential it reads, such as a leaked
  token, directly. Git over HTTPS to `github.com` can push.
- **Why accepted:** turns with egress open need public hosts for toolchain fetches (Otto's
  ADR-0010).
- **Owner:** Otto, once Otto's owners agree. Until then, this project.
- **Accepted:** not yet. Otto's owners decide whether the proxy refuses these hosts, and
  whether they own this entry. Nothing has been raised with them yet. This project's owner
  accepts the entry, with the security owner's signature.
- **Next review:** 2027-01-05.
- **Ends when:** the proxy refuses every host that accepts a target system's credential, by
  resolved address as well as by name, or each hard case (`github.com`, AWS) has an entry of
  its own.

### The sandbox's AWS identity

- **Environment:** Otto sandboxes.
- **Route:** a network policy rule opens the EKS Pod Identity endpoint to the sandbox, which
  is associated with an AWS role that carries no policy. Nobody has requested the credential.
- **Breaks:** 1. AWS is a target system.
- **What an agent could do:** obtain credentials for that role. What they authorize rests on
  the role having no policy, and on no resource policy granting it anything.
- **Why accepted:** not yet decided. Otto is asked to remove the association and its rule.
- **Owner:** Otto, once Otto's owners agree. Until then, this project.
- **Accepted:** not yet. If Otto keeps the association, this entry needs evidence from outside
  the sandbox: the role's policies, and a permissions boundary or service control policy that
  explicitly denies everything. An explicit deny overrides any allow in a resource policy. IAM
  Access Analyzer's external-access findings cannot show that, because they cover only access
  from outside the account or organization.
- **Next review:** 2027-01-05.
- **Ends when:** the association and its rule are removed.

### Credentials for Otto's conversation surfaces

- **Environment:** Otto control plane.
- **Route:** the control plane holds credentials for its own conversation surfaces, such as
  its Slack app, and acts with them outside the gateway.
- **Breaks:** 1, for a component that is not an agent. No sandbox can reach them.
- **What an agent could do:** nothing directly. The control plane can act in Slack without the
  gateway deciding or auditing it.
- **Why accepted:** decision 0003 is scoped to the vendor actions it moves to the gateway
  (noted on 2026-10-07).
- **Owner:** Otto, once Otto's owners agree. Until then, this project.
- **Accepted:** by the owner, 2026-10-07. Awaiting the security owner's signature.
- **Next review:** at each re-pin of Otto, from the credentials each control-plane component
  mounts, and by 2027-01-05.
- **Ends when:** not expected to end.

### The employee's own credentials and MCP servers

- **Environment:** laptops.
- **Route:** the employee's own vendor sign-ins, tokens and command-line tools, and MCP servers
  configured on the laptop.
- **Breaks:** 1 and 2.
- **What an agent could do:** whatever the employee can, with nothing recorded by the gateway.
- **Why accepted:** that access is granted by vendors and IT, and device management is out of
  scope. Employees are told the gateway is "the governed path".
- **Owner:** IT security, once it agrees. Until then, this project.
- **Accepted:** not yet. This project's owner accepts it, with the security owner's signature,
  before milestone 5's rollout. Milestone 5 does not roll out until IT security owns it and it
  is accepted.
- **Next review:** before milestone 5's rollout.
- **Ends when:** not under decision 0010.

### Tools the model provider runs on its own side

- **Environment:** laptops.
- **Route:** tools the model provider runs on its own side, outside the laptop and the
  gateway.
- **Breaks:** 2.
- **What an agent could do:** reach what those tools reach, with nothing recorded by the
  gateway.
- **Why accepted:** they are part of the employee's client and provider account, which IT
  manages.
- **Owner:** IT security, once it agrees. Until then, this project.
- **Accepted:** not yet. This project's owner accepts it, with the security owner's signature,
  before milestone 5's rollout. Milestone 5 does not roll out until IT security owns it and it
  is accepted.
- **Next review:** before milestone 5's rollout.
- **Ends when:** the client or provider account can switch them off, and does.

### Vendor-hosted MCP servers accept other credentials

- **Environment:** all.
- **Route:** a vendor's hosted MCP server accepts credentials other than the gateway's.
- **Breaks:** 3.
- **What an agent could do:** use a vendor's hosted server directly with any credential it
  holds or reads.
- **Why accepted:** a vendor cannot be held to accepting only the gateway's credential. For
  vendors the only path rests on controls 1 and 2.
- **Owner:** this project, per vendor.
- **Accepted:** by the owner, 2026-10-07. Awaiting the security owner's signature.
- **Next review:** 2027-01-05.
- **Ends when:** not expected to end.

### `kubectl port-forward` and `exec`

- **Environment:** every cluster.
- **Route:** `kubectl port-forward` and `exec` reach a pod past network policy.
- **Breaks:** 2, for anyone holding those permissions. The route check shows, by
  SubjectAccessReview, that the workload's own ServiceAccount holds neither `pods/portforward`
  nor `pods/exec`.
- **What an agent could do:** nothing, unless it is given those permissions.
- **Why accepted:** cluster operators need them.
- **Owner:** each cluster's owner. This project for the kind cluster. For real clusters,
  platform owners name the owner.
- **Accepted:** by the owner for the kind cluster, 2026-10-07. Awaiting the security owner's
  signature. Not yet for any other cluster.
- **Next review:** 2027-01-05.
- **Ends when:** not expected to end.

### The window at pod start

- **Environment:** every cluster.
- **Route:** a new pod is outside its network policy for about its first second, and kindnet
  keeps connections opened before a policy applied.
- **Breaks:** 2.
- **What an agent could do:** make a direct call in that window, or over such a connection.
- **Why accepted:** it is how the network plugins behave. The kind run waits ten seconds and
  uses new connections, so its evidence is not affected.
- **Owner:** each cluster's owner. This project for the kind cluster. For real clusters,
  platform owners name the owner.
- **Accepted:** by the owner for the kind cluster, 2026-10-07. Awaiting the security owner's
  signature. Not yet for any other cluster.
- **Next review:** 2027-01-05.
- **Ends when:** not expected to end.

## Exceptions to the gateway's own rules

An exception names tools, never a classification, and adding a tool to one takes a decision
record and an entry here.

### Otto's comment tools

- **Environment:** Otto sandboxes.
- **Tools:** Otto's `github_pr_comment` and `jira_comment`.
- **Rule excepted:** they comment on pull requests and issues the gateway did not create, so
  they are `write`, which [decision 0006](decisions/0006-what-the-decision-function-sees.md)
  denies in every profile. They stay `write`.
- **What an agent could do:** comment on any pull request in its team's repositories, or any
  issue in the configured Jira projects, including ones a person wrote, other than with a
  command of a bot named when the tool was approved. A comment can start CI.
- **Why accepted:** parity with Otto's gateway, which serves both tools to Otto's turns today
  (issue 12).
- **Granted by:** [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md),
  section 9.
- **Owner:** this project, and Otto once Otto's owners agree to share it.
- **Accepted:** by the owner, 2026-10-07. Awaiting the security owner's signature.
- **Conditions:** all of these must hold.
  - The profile for Otto's sandboxes only. The profile for Otto's control-plane surface has no
    exception, and services and employees are denied both tools. The profile for Otto's
    sandboxes requires currency, so each call is also allowed only while Otto says the turn is
    current ([decision 0012](decisions/0012-what-a-turn-grant-binds.md)). The loader refuses
    an exception list on a profile that does not require currency.
  - The tool refuses the commands of the bots named when it is approved. Today that is
    Atlantis. Another bot's commands are refused once that bot is named.
  - It reaches only the team's repositories, or the configured Jira projects. Check 6 and the
    connector hold it to them.
  - Every call is audited as usual, and the row records this exception as what allowed the
    call, in a field of its own.
  - Atlassian's hosted `addOrEditJiraIssueComment` gets no exception.
- **In force:** not yet. It comes into force only when both hold: milestone 4 has built the
  core's way to express an exception (issue 12), and the security owner has signed this entry.
  Until then both tools stay denied to Otto's callers.
- **Next review:** before each milestone's rollout, so before milestone 4, when it would first
  come into force; when Otto's cutover (issue 13) completes; and by 2027-01-05.
- **Ends when:** the review ends it.

## Evidence log

Each result names the environment, the date, the check and its version, what it showed, and
the claim it supports. A result older than seven days, or older than a change that could open
a route, supports no claim.

| Date | Environment | Check | Result | Claim supported |
| --- | --- | --- | --- | --- |

No results yet. The first is the kind run of milestone 2 (issue 14). Until it passes, no
environment has the only path.
