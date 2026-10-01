# Open questions

Q1–Q8 and Q14–Q16 are settled below. Q9–Q13 are proposed refinements from the design review,
not yet accepted decisions. When resolved, move their requirements into
[design.md](design.md) and remove the open question. Vendor research remains in [systems.md](systems.md).

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
- **2026-10-01 (Q14):** This gateway serves Otto's control-plane endpoints on a surface only
  Otto's control-plane workloads may use, and is the only holder of the vendor credentials.
  See [decision 0003](decisions/0003-serve-ottos-control-plane-endpoints.md).
- **2026-10-01 (Q15):** Otto is asked to sign turn grants asymmetrically so this gateway holds
  only a public key. See [decision 0004](decisions/0004-verify-turn-grants-with-a-public-key.md).
- **2026-10-01 (Q16):** The conformance baseline was re-pinned to Otto `752395a`, and is
  re-pinned on a schedule from here, with a freeze of Otto's gateway behavior agreed before
  cutover. See [design.md](design.md), section 18.
- **2026-10-01:** Otto is one piece of the gateway. The core is written for every caller;
  Otto-specific behavior is confined to a profile, a delegation verifier and an extension
  crate, and Otto's parity gates Otto's cutover only. See [design.md](design.md), sections 1
  and 17.

## Q9. What does authorization check beyond tool classification?

The current decision function considers classification and profile, with surface allowlists.
It does not fully specify restrictions on the resources named by tool arguments. One read
operation might address any repository, Jira project or AWS account available to its credential.

- **Recommendation:** pass a validated call context to the single decision function: principal,
  surface, approved tool, normalized arguments, target resources/environment, credential scope
  and policy revision. Make resource restrictions enforceable for built-in and proxied tools.
  If a generic proxy cannot establish the permitted scope, require a constrained server or
  connector before exposing that tool. Keep initial employee writes proposal-shaped; grant
  broader writes only by a later explicit policy decision.
- **Boundary:** the gateway owns agent-access policy; downstream systems still enforce their
  own credential and resource permissions. One gateway decision point does not remove them.
- **Blocks:** policy/connector interfaces and employee data-access enforcement.

## Q10. What happens after execution when recording or delivery fails?

The design completes the audit before answering, while Otto's gateway document describes
completion after the answer. An empty outcome can also mean the completion write failed,
not necessarily that the gateway never learned the result. Audit records are not idempotency
receipts, and the design currently omits Otto's planned retry and fencing contract.

- **Recommendation:** retain synchronous audit begin. Attempt finish on an independent,
  bounded deadline; record and alert on completion failure without presenting an executed
  action as safely retryable. Clarify that an empty outcome means no durable outcome exists.
  The fixed audit-unavailable response is the explicit exception to “no answer without a row.”
  Scope the tool audit contract separately from discovery, initialization and malformed requests.
- **Writes:** introduce durable action receipts before enabling real writes. Bind an
  idempotency key to principal, tool and normalized arguments, reject conflicting reuse, and
  distinguish pending, completed and unknown outcomes. An unknown outcome requires downstream
  reconciliation or supported vendor idempotency; a local receipt alone cannot guarantee
  exactly-once execution. Never automatically replay such a write after reconnect or restart.
- **Failover:** specify when Otto's fencing epoch is checked and what it stops; keep this
  separate from MCP session state. Identify implemented behavior versus future Otto promises
  in the conformance baseline.
- **Blocks:** audit behavior and the first real write/cutover readiness criteria.

## Q11. How quickly do policy changes and revocations take effect?

The proxy reads an in-memory snapshot, but the design gives no maximum age or propagation
bound. Tool drift withdrawal appears in milestone 5 while scheduled detection appears in 7.
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

Rate limits and circuit breakers currently wait until milestone 7, after both proxying and
employee access. Explicit identity/audit opt-outs also lack a production deployment restriction.

- **Recommendation:** add request/result size limits, execution deadlines, bounded concurrency,
  per-team/vendor quotas and isolation of failing upstreams with the first real connectors.
  Restrict insecure opt-outs to local development and test deployments. Keep registry API/UI
  work later, driven by onboarding needs.
- **Audit operations:** assign storage/migration ownership, retention, access controls and
  redaction rules before company-wide rollout; avoid storing credentials or unrestricted tool
  payloads. Define availability and latency targets and measure audit overhead against them.
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
