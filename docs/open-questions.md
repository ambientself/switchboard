# Open questions

Q1–Q8, Q14–Q16 and Q19 are settled below, and so is Q10 apart from read auditing. Q9–Q13,
Q17 and Q18 are open; Q10 is narrowed to what compliance requires of read auditing. When
resolved, move their requirements into [design.md](design.md) and remove the open question.
Vendor research remains in [systems.md](systems.md).

## Settled

- **2026-09-30:** The gateway is the one MCP path for Org. Otto is one caller of it.
- **2026-09-30:** Target systems are GitHub, Atlassian, New Relic, Sumo Logic, Akamai, AWS and
  self-built MCP servers. See [systems.md](systems.md).
- **2026-09-30:** Both built-in connectors and proxied servers are needed, because self-built
  servers can only be proxied.
- **2026-09-30 (Q1):** This gateway replaces Otto's Go MCP gateway. Otto will be reconfigured
  to use it after conformance passes; `/repo-config` and model brokering remain Otto
  responsibilities. See [decision 0002](decisions/0002-replace-ottos-mcp-gateway.md).
- **2026-09-30 (Q2):** Employees' laptop agents follow Otto, then internal services and
  scheduled automations. Externally hosted agents are deferred.
- **2026-09-30 (Q3):** Per-user grants are allowed where permissions or authorship require
  them. Shared identities may serve employee reads only for data explicitly approved for
  those employees; otherwise a per-user grant is required before access is enabled.
- **2026-09-30 (Q4):** Enforcement mechanisms are shared, permissions vary by profile, and
  production mutation is denied initially for everyone. Synchronous audit begin and its
  Postgres availability dependency are accepted company-wide.
- **2026-09-30 (Q5):** No client-facing MCP sessions. Upstream session caches are isolated by
  server, credential identity and authorization context; rebuilding them must not silently
  replay writes.
- **2026-09-30 (Q6):** Laptops use private networking or the existing zero-trust access layer,
  through a separate deployment sharing registry and audit storage with the in-cluster one.
- **2026-09-30 (Q7):** GitHub is the built-in parity target; a self-built server establishes
  proxy support. Other vendor choices require research; approving this approach does not
  establish their authentication or transport capabilities.
- **2026-09-30 (Q8):** Conformance lives here, against a pinned `otto` commit. Tests of
  existing Otto behavior are separate from tests of new company-wide behavior.
- **2026-10-01 (Q1, reaffirmed):** Otto still switches to this gateway, after review against
  Otto `752395a`. The work is larger than first scoped; see
  [decision 0002](decisions/0002-replace-ottos-mcp-gateway.md).
- **2026-10-01 (Q14):** Otto keeps its control-plane endpoints and the state behind them, and
  asks this gateway to perform their vendor actions on a surface only Otto's control-plane
  workloads may use. This replaces an answer given earlier the same day that moved the
  endpoints into the gateway. See
  [decision 0003](decisions/0003-otto-keeps-its-control-plane-endpoints.md).
- **2026-10-01 (Q15):** Otto is asked to sign turn grants asymmetrically so this gateway holds
  only a public key, with no shared-secret exception. See
  [decision 0004](decisions/0004-verify-turn-grants-with-a-public-key.md).
- **2026-10-01 (Q16):** The conformance baseline was re-pinned to Otto `752395a`, and is
  re-pinned on a schedule from here, with a freeze of Otto's gateway behavior agreed before
  cutover. See [design.md](design.md), section 18.
- **2026-10-01:** Otto is one piece of the gateway. The core is written for every caller;
  Otto-specific behavior is confined to a profile, a delegation verifier and an extension
  adapter crate, and Otto's parity gates Otto's cutover only. See [design.md](design.md),
  sections 1 and 17.
- **2026-10-01:** Build without a comparison against extending Otto's gateway or adopting an
  existing one. See [decision 0005](decisions/0005-build-without-a-comparison-first.md).
- **2026-10-01:** The milestone order follows the design review: kernel and harness, one
  non-Otto read-only slice, proxy hardening, Otto, employees' agents. See
  [design.md](design.md), section 17.
- **2026-10-01 (part of Q9):** What the decision function sees and returns. See
  [decision 0006](decisions/0006-what-the-decision-function-sees.md).
- **2026-10-01 (part of Q13):** Serve MCP `2026-07-28` and `2025-06-18` on one hand-written
  endpoint; Claude Code is the first client. See
  [decision 0007](decisions/0007-serve-two-mcp-revisions-from-a-hand-written-endpoint.md).
- **2026-10-01 (Q19):** The first slice uses a mock workload and mock server, in kind and
  Docker Compose. See [decision 0008](decisions/0008-mock-the-first-slice.md).
- **2026-10-04 (part of Q9):** Tools are classified `read`, `propose`, `write` or
  `destructive`. `write` and `destructive` are denied in every profile, which is how
  production mutation is denied initially. A delegation's tool list is required. Broad reads
  use the existing surface allowlists and resource limits. On 2026-10-06 the owner decided
  that a comment is `propose` only on something the gateway itself created for review, such
  as its own draft pull request or an issue it opened, and `write` anywhere else. A `propose`
  tool also guards against what would take effect on its own: it refuses a comment a bot would
  read as a command, and forces a pull request it opens to be a draft. See the 2026-10-04
  amendment to
  [decision 0006](decisions/0006-what-the-decision-function-sees.md).
- **2026-10-07 (Q10, apart from read auditing):** Three records: telemetry, audit rows and
  receipts. What begin and finish guarantee. Open rows are found by their deadline and never
  marked. Receipts with per-request, single-use keys and reconciliation that only looks, required
  before the first tool not classified `read` reaches a real system. The gateway never repeats
  a call. Reads stay synchronous on Q4's acceptance until compliance says what it requires. The
  owner accepted the recommendations on 2026-10-07. See
  [decision 0009](decisions/0009-audit-completion-receipts-and-recovery.md). Fencing is in Q18.

## Q9. What does authorization check beyond tool classification?

The current decision function considers classification and profile, with surface allowlists.
It does not fully specify restrictions on the resources named by tool arguments. One read
operation might address any repository, Jira project or AWS account available to its credential.

- **Settled for the core:** what the decision function sees and returns is
  [decision 0006](decisions/0006-what-the-decision-function-sees.md). It sees the resources a
  call names, not its arguments.
- **Recommendation for the rest:** make resource restrictions enforceable for built-in and
  proxied tools.
  If a generic proxy cannot establish the permitted scope, require a constrained server or
  connector before exposing that tool. Keep initial employee writes proposal-shaped; grant
  broader writes only by a later explicit policy decision.
- **Boundary:** the gateway owns agent-access policy; downstream systems still enforce their
  own credential and resource permissions. One gateway decision point does not remove them.
- **Open for the owner: Otto's comment tools.** Otto's `github_pr_comment` and `jira_comment`
  comment on pull requests and issues the gateway did not create, so they are `write` and are
  denied to Otto's callers. So is the hosted Atlassian server's
  `addOrEditJiraIssueComment`, which [systems.md](systems.md) lists to match `jira_comment`.
  That loses parity with Otto's gateway (#12). The conformance suite's cases that use them
  become an expected difference: the tool inventory, the comment case and write count in
  `TestOriginalToolsAndBrokeredCredentials`, three scope and argument cases, and the
  audit-finish and repeated-write tests (design section 18). A narrow, recorded exception is
  the likely answer. Until one is recorded, they stay denied.
- **Open: `propose` refusals inside a proxied server.** A `propose` tool refuses, when it runs,
  what the gateway did not create and what would act on its own. For a built-in tool that
  refusal is gateway code, tested and mutated like any guard. Whether a proxied server's own
  refusal can make its tool `propose`, or such a tool is `write` unless a gateway adapter
  makes the check, is not decided.
- **Open for the owner: proposals that start CI.** CI cannot be refused by what starts it. A
  draft pull request, a push to the gateway's proposal branch and a comment on the gateway's own
  pull request each start the workflows configured for them. That is acceptable where those
  workflows only build and test. Whether a proposal stays `propose` in a repository where such a
  workflow can deploy or holds a production credential is not decided. A comment tool's command refusal covers the bots named when it is
  approved, which today is Atlantis.
- **Blocks:** policy/connector interfaces and employee data-access enforcement, and Otto's
  write cutover for its comment tools.

## Q10. What does compliance require of read auditing?

[Decision 0009](decisions/0009-audit-completion-receipts-and-recovery.md) settles the rest of
Q10. Q4 accepted a synchronous audit write for every call, reads included; nobody has said that
compliance requires it for reads.

- **Until compliance answers:** reads are written synchronously, on Q4's acceptance. A stricter
  or looser requirement, on coverage, immutability or retention, would change part 1 of
  decision 0009.
- **Also open from decision 0009,** each for someone other than the owner. Its "Still open"
  list says what holds meanwhile.
  - Otto's owners: whether Otto's adapter still writes rows for identity failures,
    `initialize` and `ping`; and Otto's key and the grant fields that scope it.
  - Whoever runs logging: where telemetry goes, and the compliance system of record.
  - The security team: whether failed-authentication evidence may be dropped under load, and
    how a person records a resolution.
  - The security team and the storage owners: tamper evidence, and who holds the superuser
    login.
  - Whoever runs Postgres, probably IT: what "committed" means.
  - The audit database's owner: who owns the schema (Q12).
  - Whoever runs the on-call rotation: who is paged, and who settles a receipt by hand.
- **Blocks:** closing #3. Not milestone 2: the interim rule is enough for the first slice.

## Q11. How quickly do policy changes and revocations take effect?

The proxy reads an in-memory snapshot, but the design gives no maximum age or propagation
bound. Drift detection and withdrawal now arrive together, in milestone 3.
A definition hash detects interface changes, not a changed implementation behind the same schema.

- **Recommendation:** use validated, versioned snapshots with atomic replacement and a
  defined maximum age. Deny affected calls when policy freshness cannot be established within
  the agreed bound. Record the policy revision with decisions. Define emergency withdrawal,
  token/group staleness and grant revocation behavior explicitly.
- **Tool approval:** include server identity and routing/credential configuration in the
  approval boundary. Detect drift from the first proxied rollout; define polling and
  propagation bounds, and document the residual interval. Do not claim hash pinning proves
  the downstream implementation is unchanged.
- **Blocks:** the first production proxy deployment and its revocation guarantee.

## Q12. Which operational controls belong before broad rollout?

Limits and isolation of a failing server now arrive in milestone 3, before Otto and
employee access. Explicit identity/audit opt-outs also lack a production deployment restriction.

- **Recommendation:** add request/result size limits, execution deadlines, bounded concurrency,
  per-team/vendor quotas and isolation of failing upstreams with the first real connectors.
  Restrict insecure opt-outs to local development and test deployments. Keep registry API/UI
  work later, driven by onboarding needs.
- **Audit operations:** assign storage/migration ownership, retention, access controls and
  redaction rules before company-wide rollout; avoid storing credentials or unrestricted tool
  payloads. Define availability and latency targets and measure audit overhead against them.
- **Deferred here by decision 0009:** the begin budget, the answer budget and the finish
  deadline (two, two and thirty seconds until then), call deadlines, pool sizes and alert
  thresholds; how long rows, receipts, resolution records and telemetry are kept; and who owns
  the audit and receipt schema, its grants, triggers and migrations. An authentication flood
  no longer writes to the audit store, so the overload question is reduced to begins from
  proved callers.
- **Blocks:** rollout sequencing and production readiness.

## Q13. Which employee clients and access infrastructure are the acceptance targets?

Private access and Okta are chosen directions; the concrete clients, routes and OAuth setup
remain unverified. Publishing discovery metadata alone does not establish interoperability.

- **Recommendation:** choose the first clients and workflows, then test sign-in, client
  registration, gateway-specific token audience, refresh, and the selected private access
  layer together. Preserve required HTTP authentication challenges alongside readable denials.
  Select and pin a supported MCP revision and test initialization, notifications, HTTP
  responses and any supported streaming behavior, even with client sessions disabled.
- **Identity:** select verifiers only from configured trusted issuers; an unverified token
  must never select an arbitrary discovery/JWKS URL. Scope subjects by issuer and subject.
  Avoid promising identical timing across all authentication failure modes; preserve opaque
  failures and verify signatures before subject lookup.
- **References:** [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  and [transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).
- **Blocks:** employee client acceptance tests and deployment setup.

## Q17. What stops an agent going around the gateway?

Central authorization is real only where there is no other route. An agent that holds a vendor
credential, or can reach a vendor or another MCP server directly, is audited when it uses the
gateway and ungoverned when it does not.

- **Recommendation:** for each environment the gateway serves, state the controls and show
  they hold: no vendor credential in the caller, egress that reaches vendors only through the
  gateway, downstream MCP servers that accept only the gateway's identity. Keep a list of
  exceptions. Otto's sandboxes already have default-deny egress; a laptop does not, so for
  employees the honest claim is "the governed path", not "the only path".
- **Blocks:** milestone 2 for its one workload; milestone 5 for employees.

## Q18. What must a turn grant bind?

Otto's grant names a team, a human, an execution, tools, an epoch and an expiry. It does not
name the gateway it is for, and it can be presented again until it expires. It is tied to the
caller only by team: a grant for a team can be presented by any proved workload of that team. Otto signs the
fencing epoch and does not yet enforce it. Any accepted arguments are allowed for a granted
tool.

- **Recommendation:** add the issuer, the gateway and deployment it is for, and a unique
  identifier; keep expiry short. Enforce the epoch. Decide whether a grant may be presented
  more than once: a turn makes many calls, so the likely answer is yes within one turn, with
  the identifier recorded so reuse elsewhere is detectable. Test replay, use against another
  deployment, clock skew, key rotation and emergency revocation.
- **Blocks:** milestone 4. This is a change in Otto, alongside decision 0004.

## Review findings not yet reflected in the design

From the independent review of 2026-10-01. Accepted in principle, not yet designed:

- Overload behavior for the audit store: admission control and bounded pools (Q12). An
  authentication flood no longer reaches the database (decision 0009).
- Freshness and revocation bounds for group claims and team manifests (Q11).
- Identity and audit opt-outs unavailable outside development builds (Q12).
- A table tracing each invariant to its decision and its test. One now exists for audit and
  receipts (design section 18).
