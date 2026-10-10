# Open questions

Q1–Q8, Q11, Q14–Q16 and Q19 are settled below, and so is most of Q9, Q10, Q17 and Q18. Open
are what remains of Q9, which decision 0011 leaves to others; Q10, narrowed to what compliance
requires of read auditing; Q12 and Q13; and what remains of Q17 and Q18, which decisions 0010 and
0012 leave to others. When resolved, move their requirements into [design.md](design.md) and
remove the open question. Vendor research remains in [systems.md](systems.md).

## Settled

- **2026-09-30:** The gateway is the one MCP path for Org. Otto is one caller of it. Noted on
  2026-10-07: scoped by
  [decision 0010](decisions/0010-what-stops-an-agent-going-around-the-gateway.md) to a claim
  per environment, "the only path" or "the governed path".
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
  marked. Receipts with per-request, single-use keys and reconciliation that only looks,
  required before the first tool not classified `read` reaches a real system. The gateway never
  repeats a call. Reads stay synchronous on Q4's acceptance until compliance says what it
  requires. The owner accepted the recommendations on 2026-10-07. See
  [decision 0009](decisions/0009-audit-completion-receipts-and-recovery.md). Fencing is
  [decision 0012](decisions/0012-what-a-turn-grant-binds.md).
- **2026-10-07 (Q17):** Each environment that serves agents carries "the only path" or "the
  governed path". The only path needs three controls, shown by dated evidence from inside the
  environment with a positive control in the same run. The first slice in kind is the only path
  to the mock server once the kind run's evidence is current. Real services and Otto's sandboxes
  start on the governed path, and a real workload passes the route check before it sees real
  data. Laptops stay on the governed path. Known routes around the gateway, with owners, are in
  [route-exceptions.md](route-exceptions.md). What Otto's owners, IT, IT security, the security
  team and platform owners decide is listed in the record and under Q17 below. See
  [decision 0010](decisions/0010-what-stops-an-agent-going-around-the-gateway.md).
- **2026-10-07 (most of Q9):** Every tool's approval says how its resources are found: from
  its arguments, as its credential's tested reach, by a built-in connector at run time, or
  none. Argument validation and output limits are the gateway's. A proxied tool is exposed only
  as a read whose credential reaches nothing outside its callers' limits, and is never trusted
  to check its own scope. Only the decision function can allow a call; everything after it can
  only refuse or fail. Employees start read-only and propose only under their own per-user
  grant, with no fallback. A group's limit approves whole resources, not content restricted
  inside them. Broad reads are opted into by a breadth resource in a limit. Otto's
  `github_pr_comment` and `jira_comment` are allowed to Otto's callers by a narrow, recorded
  exception, once the core can express it (#12); the hosted `addOrEditJiraIssueComment` gets
  none. The owner accepted the record's recommendations. See
  [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md).
- **2026-10-07 (Q18):** A turn grant binds its issuer through the key, the deployments it is for
  (`aud`), a lifetime of at most 15 minutes (`iat`, `exp`), and by stage 3 the sandbox pod. It
  also carries the turn's egress setting, which is recorded. It may be presented again within
  those bounds, and its digest is recorded. Otto's calls of any tool not classified `read` are
  allowed only while Otto says the turn is current, which enforces the epoch and allows revoking
  one turn. Fencing is checked once, before each such call. A failover during the call is not
  stopped. Decision 0009's receipts cover a resend of the same call, and a turn replayed after a
  failover only if Otto's control plane sends a key that stays the same across replays; that
  key, and which grant fields scope it, stay with decision 0009 (its Still open 8). Otto is
  asked to make the changes this needs; none has been agreed with Otto's owners yet, and what
  waits on them is listed in the decision and under Q18 below. See
  [decision 0012](decisions/0012-what-a-turn-grant-binds.md).
- **2026-10-10 (Q11):** Each approval records two hashes: the definition the server serves,
  and the server's binding (identity, address, destination, credential and, with connector
  entries, the reach). Only JSON Schema 2020-12 loads. Each gateway replica runs its own drift
  pass, every 300 s by default, and withdraws a changed tool or a widened reach for itself,
  with a revision naming the withdrawn tools. In milestone 3 a withdrawal lasts until a new
  approval or until that replica restarts, and every one is alerted on. A replica that cannot
  read its registry for 60 s refuses every call. Emergency withdrawal is a registry edit,
  bounded by delivery plus one poll. The drift interval and how long a withdrawal lasts are
  the owner's own answers, given by accepting the record. What platform owners and IT decide
  is under Q17 and Q9. See
  [decision 0013](decisions/0013-registry-freshness-drift-and-withdrawal.md).

## Q9. What does authorization check beyond tool classification?

Settled by [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md),
except the parts below, which need people other than the owner or had no recommendation. The
record says what holds until each is answered. When they are answered, retire Q9.

- **Which downstream automation makes a proposal a direct write:** Atlantis comment commands
  and autoplan, comment-triggered workflows, push and pull request workflows that run with
  repository secrets on proposal branches, changes to workflow files on those branches, and
  Jira automation rules. This includes whether a proposal stays `propose` in a repository
  where a workflow it starts can deploy or holds a production credential. For the owners of
  Atlantis, CI and Jira automation. Until they answer, only Atlantis comment commands make a
  tool `write`, and a `propose` tool also refuses changes to CI workflow files and Atlantis
  configuration, as well as command text. A proposal can still start an Atlantis autoplan or
  a pull request workflow that runs with the repository's secrets.
- **Which AWS accounts are in scope** for broad reads and employees. For the cloud platform
  team. Until then no AWS account is in any limit.
- **Who the security reviewer of data approvals is, and the security owner** who signs
  entries in decision 0010's register, Otto's comment-tool exception among them. For the
  security team. Until then no resource is added to a group's limit and no breadth resource to
  a team's, and the exception's entry awaits that signature.
- **Who the code owners of the policy files are,** and the branch rule requiring their review.
  For the repository administrator, with the owner naming the code owners. Until then no
  policy file lands.
- **Whether group limits and broad-read opt-ins expire** and are recertified, and how often.
  For the owner with the security team, before milestone 5. Until then an approval stands
  until a reviewed change removes it.
- **Asks of IT, vendor administrators and Otto's owners,** listed in the record: narrow service
  accounts and who owns them, OAuth applications for per-user grants, ownership of the Okta
  groups, and the review of Otto's eighteen tool declarations. The asks of Otto's owners go in
  the one list of Otto requests under Q18.
- Whether a per-user rate limit must come before employee proposals is tracked in Q12. How
  often the reach check runs is set by decision 0013. Whether Otto's `gateway_audit` table gains this
  record's audit columns is part of the question about that table in Q12.
- **Blocks:** every policy file, and so milestone 2, until the code owners and the branch rule
  exist; every employee read and any broad read, until the security reviewer is named, since
  no resource enters a group's limit before then; milestone 5's employee proposals; every Otto
  tool at milestone 4, until Otto's owners review the declarations; Otto's two comment tools,
  until the security owner signs the exception's register entry; and Otto's proposal tools,
  if the automation answer asks more of them.

## Q10. What does compliance require of read auditing?

[Decision 0009](decisions/0009-audit-completion-receipts-and-recovery.md) settles the rest of
Q10. Q4 accepted a synchronous audit write for every call, reads included; nobody has said that
compliance requires it for reads.

- **Until compliance answers:** reads are written synchronously, on Q4's acceptance. A stricter
  or looser requirement, on coverage, immutability or retention, would change part 1 of
  decision 0009.
- **Also open from decision 0009,** each for someone other than the owner, alone or with the
  owner. Its "Still open" list says what holds meanwhile.
  - Otto's owners: whether Otto's adapter still writes rows for identity failures,
    `initialize` and `ping`; and Otto's key, the grant fields that scope it, whether it stays
    the same when a turn is replayed, and how read-back treats rows that share a tool-use
    identifier.
  - Whoever runs logging: where telemetry goes, how long it is kept, and the compliance
    system of record.
  - The security team: whether failed-authentication evidence may be dropped under load.
  - The owner with the security team: how a person records a resolution.
  - The security team and the storage owners: tamper evidence for rows and receipts, and who
    holds the superuser login.
  - Whoever runs Postgres, probably IT: what "committed" means.
  - The owner with whoever will own the audit database: who owns the schema (Q12).
  - Whoever runs the on-call rotation: who is paged, and who settles a receipt by hand.
- **Blocks:** closing #3. The first side effect reaching a real system waits for decision
  0009's Still open 9 (who settles by hand) and 10 (how a resolution is recorded); Otto's
  write cutover also waits for its Still open 8 (Otto's key). Not milestone 2: the interim
  rule is enough for the first slice.

## Q12. Which operational controls belong before broad rollout?

Limits and isolation of a failing server now arrive in milestone 3, before Otto and
employee access. Explicit identity/audit opt-outs also lack a production deployment restriction.

- **Recommendation:** add request/result size limits, execution deadlines, bounded concurrency,
  per-team/vendor quotas and isolation of failing upstreams with the first real connectors.
  Restrict insecure opt-outs to local development and test deployments. Keep registry API/UI
  work later, driven by onboarding needs.
- **Before employee proposals:** whether a per-user rate limit must be in place before the
  first employee proposal tool is approved
  ([decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md)). For the
  owner; no recommendation was made. It is answered before that tool is approved. Policy
  snapshots are kept as long as the audit rows they explain, so that retention covers both.
- **Audit operations:** assign storage/migration ownership, retention, access controls and
  redaction rules before company-wide rollout; avoid storing credentials or unrestricted tool
  payloads. Define availability and latency targets and measure audit overhead against them.
  A row's recorded resources alone can reach 147,648 escaped characters, which serialize to
  298,059 bytes as JSON ([design.md](design.md), section 11). Set size limits in the units the
  store counts.
- **Otto's audit table:** Otto's `gateway_audit` table has no column for the resources an
  allowed call names. A denial's or refusal's sentence names the one resource that caused it,
  as prose capped at 1,024 characters. `github_skill_body` records its skill ref, repository
  and commit, but only on an allowed call, on the best-effort finish write. Decide whether the
  table gains a general column, and who adds it.
  [Decision 0002](decisions/0002-replace-ottos-mcp-gateway.md) makes the table's contract a
  compatibility requirement, so adding a column changes it. Otto's rule for this table, stated
  in its migration 0036, is typed columns and not one JSONB bag, so a new column must be
  typed. Otto's writer bounds each text column in bytes.
- **Deferred here by decision 0009:** the begin budget, the answer budget and the finish
  deadline (two, two and thirty seconds until then), call deadlines, pool sizes and alert
  thresholds; how long rows, receipts and resolution records are kept; and who owns the audit
  and receipt schema, its grants, triggers and migrations. How long telemetry is kept is for
  whoever runs logging (decision 0009, Still open 3). An authentication flood no longer
  writes to the audit store, so the overload question is reduced to begins from proved
  callers.
- **Blocks:** rollout sequencing and production readiness.

## Q13. Which employee clients and access infrastructure are the acceptance targets?

Private access and Okta are chosen directions; the concrete clients, routes and OAuth setup
remain unverified. Publishing discovery metadata alone does not establish interoperability.

- **Recommendation:** choose the first clients and workflows, then test sign-in, client
  registration, gateway-specific token audience, refresh, and the selected private access
  layer together. Preserve required HTTP authentication challenges alongside readable denials.
  Select and pin a supported MCP revision and test initialization, notifications, HTTP
  responses and any supported streaming behavior, even with client sessions disabled.
- **Keys for side effects:** a side effect without an idempotency key is denied (decision
  0009). The MCP specification defines no tool-use identifier; Claude Code sends
  `claudecode/toolUseId` in `_meta`. For each target client, check that it sends a tool-use
  identifier or can set the named `_meta` field. One that can do neither cannot propose.
- **Identity:** select verifiers only from configured trusted issuers; an unverified token
  must never select an arbitrary discovery/JWKS URL. Scope subjects by issuer and subject.
  Avoid promising identical timing across all authentication failure modes; preserve opaque
  failures and verify signatures before subject lookup.
- **References:** [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
  and [transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports).
- **Blocks:** employee client acceptance tests and deployment setup.

## Q17. What do others decide about routes around the gateway?

Settled by [decision 0010](decisions/0010-what-stops-an-agent-going-around-the-gateway.md),
except the parts below, which need parties other than the owner. The record says what holds
until each is answered. When they are answered, retire Q17.

- **Otto's owners:** whether Otto's proxy refuses every host that accepts a target system's
  credential, by address as well as by name, and what to do about `github.com` and AWS;
  whether `make egress-check` gains a refused row for each; whether the sandbox's Pod Identity
  association goes; whether the grant carries the turn's egress setting; and whether they own
  or share the register entries for Otto. These go in the one list of Otto requests under Q18.
  Until they answer, every Otto turn has the governed path.
- **IT and vendor administrators:** whether to limit the gateway's credentials to its egress
  addresses; whether the zero-trust access layer filters laptop egress; managed client
  settings; and limits on sign-in to hosted MCP servers, personal tokens and provider-run
  tools.
- **IT security:** whether it owns the two laptop entries in the register. Until it does,
  milestone 5 does not roll out.
- **The security team:** naming the security owner who signs register entries.
- **Platform owners:** which clusters real workloads run in, who runs the route check there,
  who owns each cluster's residual entries, renewal of evidence in their change process, and
  the registry's probe permission. Until then no real workload sees real data.
- **Blocks:** milestone 5's rollout (IT security); real workloads seeing real data (platform
  owners); any Otto turn having the only path (Otto's owners).

## Q18. What do Otto's owners agree for turn grants, and who asks them?

Settled by [decision 0012](decisions/0012-what-a-turn-grant-binds.md), except the parts below.

- **Who raises the Otto requests.** For the owner; the record made no recommendation. Every
  request of Otto's owners from decisions 0009 to 0012 goes to them as one list, raised by
  whoever the owner names: decision 0009's Still open 2 and 8, decision 0010's requests,
  decision 0011's asks of Otto's owners, and decision 0012's changes and questions. Nothing
  has been raised yet, and every item below waits on it.
- **Otto's owners:** agreement to the breaking change before stage 1 and whether Otto's
  schedule fits milestone 4; `pod` in the first change, and whether the harness can read the
  pod's projected token; `egress`; the ceiling and leeway in Otto's minter; the resolver's
  availability target; any blue/green swap or local execution during milestone 4, and the two
  departures from Otto's control-plane document; whether lease-holding control-plane
  components send their epoch; who in Otto may mark a turn revoked; key custody and rotation;
  reading the new row fields back in Otto; minting a renamed deployment first; and the
  audience of the sandbox's identity token for stage 1 copies.
- **The on-call rotation, with whoever runs logging:** how audience and pod failures and the
  lifetime-failure rate reach a person, and the rate that alerts. Until then nothing pages and
  the counts are reviewed at each stage's go/no-go.
- **The security team:** whether a grant-key change needs review beyond the ordinary.
- **Blocks:** milestone 4. Stage 1 waits for Otto's breaking change, and stage 3 for the pod
  binding and the currency answer.

## Review findings not yet reflected in the design

From the independent review of 2026-10-01. Accepted in principle, not yet designed:

- Overload behavior for the audit store: admission control and bounded pools (Q12). An
  authentication flood no longer reaches the database (decision 0009).
- Identity and audit opt-outs unavailable outside development builds (Q12). For turn-grant
  checking this is decided: it can be turned off only in a development build, enforced at boot
  ([decision 0012](decisions/0012-what-a-turn-grant-binds.md)).
- A table tracing each invariant to its decision and its test. One now exists for audit and
  receipts (design section 18).
