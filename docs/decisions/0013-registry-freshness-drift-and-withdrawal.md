# 0013: Registry freshness, drift and withdrawal

Date: 2026-10-10. Status: proposed, awaiting the owner. Would settle Q11 (#4), and the parts of
#11 that depend on its answers: what an approval fingerprints, a proxied server's identity,
where the gateway may connect, servers that need a session, the registration probe and the
gateway's per-team identities. The recommendations are recorded here under the owner's
standing instruction of 2026-10-10 to take them. Two answers are the owner's own and are
written as recommendations only: how often the drift pass runs (section 5) and how long a
withdrawal lasts (section 7). See For the owner. Written against decisions
[0009](0009-audit-completion-receipts-and-recovery.md) to
[0012](0012-what-a-turn-grant-binds.md) as accepted on 2026-10-07, with 0009's amendment of
2026-10-10, and against the code at the end of milestone 2. Adds dated notes to decisions 0010,
0011 and 0012. Their accepted text is unchanged.

## Context

What milestone 2 built:

- The registry is a checked-in TOML file, mounted from a ConfigMap in kind and from a directory
  in Compose. Each replica reads it at boot and again every `registry.poll_seconds` (2 s in
  the demos). A version that loads replaces the snapshot atomically, from the next request. A
  version that does not load is logged, and the previous snapshot keeps serving. A version
  that changes the policy but keeps its `revision` is refused, and so, until a restart, is one
  that changes a server or a tool's route.
- Every audit row, of kind `call` or `list`, records the revision of the snapshot it was
  decided from.
- Each approval records `definition_sha256`, over the tool's upstream name, title,
  description and input schema. The demo approvals hash hand-written definitions that differ
  from what the mock server serves (#51), so the loader's check shows only that the file
  agrees with itself.
- There is no drift pass, no registration probe and no reach check. `tools/list` answers from
  the approved definitions and never contacts a server.
- A registry change took 0.15 s to 2.03 s to show in Compose, and 33 s to 88 s in kind, where
  kubelet updates the mounted ConfigMap ([first-slice-findings.md](../first-slice-findings.md),
  section 3).
- Issuer keys come from a keys file, read once, or a keys URL, fetched every 300 s by default.
  A refresh that fails keeps the keys in use, with no maximum age. Design section 7 left that
  bound to Q11.
- The gateway presents a projected token for its own ServiceAccount, with the mock server as
  audience. No container in the demos holds a token the Kubernetes API server accepts.

What the records leave to Q11:

- Decision 0011, section 4: how a withdrawal reaches every replica, and how it sits with a
  maximum snapshot age. Its Still open: how often the reach check runs, for the owner, with no
  recommendation. Until that is set, no proxied entry is exposed outside development and test
  deployments.
- Decision 0012: the freshness bound of two revocation levers, removing a team from the
  allowlist of Otto's sandbox surface and withdrawing Otto's surfaces. Until it is set, both
  are taken to need one rollout.
- Decision 0010: the registry sends the registration probe by TokenRequest for a probe
  ServiceAccount of its own. Milestone 3 has no registry workload to send it.
- #4's acceptance criteria: versioning, atomic replacement and a maximum age; the revision on
  every decision; emergency withdrawal and how long it takes to reach every instance; how
  stale group claims and team mappings may be, and how a per-user grant is revoked; how often
  drift is checked; the approval fingerprint; and acceptance scenarios.

This record keeps decision 0011's two assumed failures, an agent that calls anything it can
see with any arguments and a careless approver, and adds a third: a server's owner, or a
vendor's administrator, who changes what sits behind an approval without touching this
repository.

## Decision

### 1. What an approval fingerprints

Each approved tool records two hashes.

- **`definition_sha256`** stays what it is: the SHA-256 of the tool's upstream name, title (when
  there is one), description and input schema, in the canonical JSON the loader already
  writes. The approved definition must be exactly what the server serves. An approval does not
  rewrite a title or a description; a server whose text is unfit is changed by its owner, or not
  approved. This settles #51 as "match what it serves", and the demo approvals are recomputed
  from what the mock server serves.
- **Only JSON Schema 2020-12 loads.** A schema whose `$schema` names another dialect, or that
  uses a form valid only in an earlier draft, is refused at approval and at load. It is never
  converted. The drift pass can then compare the hash of what the server serves with
  `definition_sha256` directly.
- **`binding_sha256`** is new, per tool, in the same canonical JSON. It covers the constant
  dialect `"2020-12"`, and the server's binding: its identity, address and destination class
  (section 3), its credential mode and credential reference, and, once connector entries exist
  (#11), the entry's principal, narrowing, what the credential permits, its reach and the date
  of its reach test.
- **Excluded:** `outputSchema` and `annotations`. The gateway shows neither to callers, and the
  `readOnlyHint` it shows comes from the classification. The probe record (section 9) is not
  hashed either: the drift pass repeats the probe.
- **The loader recomputes both hashes at boot and on every reload.** A registry in which either
  differs from what was recorded is refused, as a definition that no longer matches is refused
  today: at boot the gateway does not start, and on a reload the previous snapshot keeps
  serving. A changed server entry therefore needs its tools approved again, and the reviewer
  sees each one.

A hash shows that the interface and the binding are unchanged. It does not show that the
server's code is unchanged. That stays a risk, carried by the server owner's accountability,
monitoring, and emergency withdrawal (section 8). `binding_sha256` is a tripwire for a careless
edit, not a control on its own: whoever edits a server entry can recompute it. Required review
by the policy files' code owners (#48) is what makes the change a second person's decision.

### 2. A proxied server's identity

A proxied server's identity is the DNS name the connection proves: the host in its address,
verified by the server's certificate for `https`, and accepted as an approved in-cluster
Service name for `http` (section 3). The registry's `identity` must equal the address's host,
and the loader checks it. `serverInfo.name` is only the server's claim about itself. The
connector has no session and never sends `initialize`, so it is neither recorded nor compared.
The demos' identity becomes the Service name: `mock-docs.mock-docs.svc.cluster.local` in kind
and `mock-docs` in Compose.

### 3. Where the gateway connects

- **`https` with a verified certificate for every server,** except an entry with
  `destination = "in_cluster"`, which may use plain `http`. The kind and Compose demos use
  that exception.
- **Trust is named, never ambient.** The deployment file names a CA file for each `https`
  server. No roots are compiled in and none are read from the operating system, as for issuer
  keys under #88.
- **The address is checked when the gateway connects, and the checked address is the one
  connected to,** so a second DNS answer cannot replace it. Redirects are refused.
- **Some addresses are always refused:** loopback, unspecified, link-local (including
  `169.254.169.254`) and multicast. Private and carrier-grade NAT ranges are allowed only for
  `in_cluster` entries.
- **Loopback is allowed only in a development build,** for the tests' local servers. CI checks
  that the release artifact refuses it.

### 4. Servers that need a session

A server that needs an MCP session is refused at registration in milestone 3. The connector
sends no `initialize`, so such a server's tool list cannot be read and approved. The sessions
criterion of #11 is met by three things: the session-less connector; one client and connection
pool per connector entry, which is tested; and a test that a call is never repeated when the
connection breaks after the request was sent, with the HTTP client's retry of cancelled
requests turned off explicitly.

### 5. The drift pass

**Where it runs.** In every gateway replica, as a background task beside the registry reloader.
It reads each proxied entry's tool list with that entry's own credential: a self-built server
accepts only the gateway's identities (decision 0010), so no other workload could read it. In
milestone 3 this pass is the "registry" of decisions 0010 and 0011. There is no registry
workload, withdrawals file or channel between replicas until milestone 6.

**What one pass does, for each proxied entry:**

1. Reads `tools/list` and hashes each approved tool's served definition. A tool whose hash
   differs from `definition_sha256`, or that the server no longer lists, is withdrawn
   (section 6). A tool the server lists that no approval names is not exposed, and is ignored.
2. Sends the three probe calls of section 9 straight to the server.
3. Makes the reach check of decision 0011, section 4, as an audited call through the replica's
   own listener, under the registry's own workload identity (section 10). A mismatch withdraws
   the entry's tools.

**A failed poll is not drift.** A server that cannot be reached, answers with a status other
than 200, answers with something that cannot be parsed, or answers after the entry's call
deadline keeps its tools served. The failure is logged, counted and alerted on. The first pass
runs at boot, before `/readyz` passes, so a restarted replica checks before it serves. A failed
first poll does not hold readiness back.

**How often (for the owner).** The recommendation is every 300 s per proxied entry by default,
set by an optional `[drift]` table in the deployment file, `interval_seconds`, refused below 5
or above 900. The demos set 10. A changed definition or a widened reach can then still be served
for one interval plus one call deadline on each replica, about 305 s at the defaults. Decision
0011 left this question to the owner with no recommendation, so it is not adopted under the
standing instruction. Until the owner answers, decision 0011 keeps every proxied entry to
development and test deployments.

**What every replica sees.** Each replica checks for itself, with nothing passed between them.
A change that lasts at least one interval plus one call deadline is withdrawn on every replica.
A shorter change may be seen by some replicas, or by none.

### 6. Withdrawal in a replica

A withdrawal makes a snapshot of its own, as decision 0011 requires: the snapshot in force
with the withdrawn tools removed. It replaces the snapshot in force atomically. The loader's
rules are not run again, since a removal can only narrow what is allowed.

**Its revision names the withdrawal set literally:** `{base}+withdrawn:{names}`, where `{base}`
is the loaded snapshot's revision and `{names}` are the withdrawn tools' exposed names, sorted
by byte and joined by commas, for example:

```text
demo-3+withdrawn:docs__list_documents,docs__read_document
```

An exposed name is at most 64 characters of ASCII letters, digits, `_` and `-`, so the text
after the last `+withdrawn:` reads back unambiguously, whatever the base revision holds. A row
decided under a withdrawal then says exactly what was in force, with nothing more than the base
snapshot, which decision 0011 keeps as long as the rows. No log is needed to read it.

**The set is capped at 16 tools,** so the part after the base is at most 1,039 bytes. In
milestone 3 the loader refuses a registry that serves more than 16 proxied tools, so no
withdrawal set can pass the cap. Above it, a revision would have to carry a hash of the set,
and the set would then have to be kept as long as the rows that cite it. That store arrives
with the persisted withdrawals of section 7, and the loader's limit is lifted then.

**A standing withdrawal outlives a reload.** It is keyed by the tool's name,
`definition_sha256`, `binding_sha256` and `approved_at`. When a new version of the registry
loads, every standing withdrawal whose key is unchanged is applied to it, and the derived
revision names the new base. A new approval changes `approved_at`, and so clears the
withdrawal. A version that removes the tool drops it.

**Every withdrawal is loud.** The replica logs `tool_withdrawn` at ERROR, naming the tool, its
connector entry, the cause (a changed definition, a tool no longer listed, or a reach mismatch)
and the base and derived revisions. It counts it, and it is alerted on.

### 7. How long a withdrawal lasts (for the owner)

The recommendation is that in milestone 3 a withdrawal lives in each replica's memory. It lasts
until the tool is approved again, or until that replica restarts.

The residual, stated plainly. A restarted replica's first pass withdraws the tool again only if
the server still serves the changed definition, or the reach is still wide. Suppose a server's
definition changes and then changes back. A replica that polled during the change keeps the tool
withdrawn until it is approved again or the replica restarts. A replica that restarts after the
change is undone, and every new replica, serves the tool again with no new approval. For as long
as both kinds of replica run, some serve the tool and some do not. In milestone 3, then,
decision 0011's "They return only through a new approval" and design section 13's "until it is
approved again" hold only on a replica that has not restarted since the withdrawal. Decision
0011 carries a dated note saying so.

What covers it. Every `tool_withdrawn` is logged at ERROR and alerted on, so that a person makes
the withdrawal standing: approves the tool again after review, or removes the tool or its entry
from the registry, which then holds on every replica, restarts included. The alert is what
turns a withdrawal in one replica's memory into a decision that lasts.

Persisting withdrawals, in a table in the audit database read at boot and on each poll, is
deferred to milestone 6, with the registry service. It carries the hashed form of section 6 with
it. The owner may instead ask for it now. That needs a migration, grants for the gateway's role,
a write from every replica and a read at boot, and it brings the audit database into the drift
pass.

### 8. Freshness

**Versioning and replacement.** As built: each version of the registry carries a revision,
loads whole or not at all, and replaces the one in force atomically. Every audit row records
the revision it was decided from, a derived one included.

**Maximum age.** 60 s since the replica last read the registry file successfully, whether or
not that version loaded. It is set by `registry.max_age_seconds` in the deployment file, and is
refused below twice `registry.poll_seconds`. Past it, the replica fails `/readyz` and refuses
`tools/call` and `tools/list` with a fixed sentence saying its policy is stale. Such a request
reaches no decision, so it is telemetry with no audit row, as decision 0009 sorts requests. A
file that reads but does not load keeps the last good policy and is logged. It is not stale.
There is no signed expiry in the snapshot itself until milestone 6.

**The delivery path has a bound of its own,** which the gateway cannot see: from a merged change
to the ConfigMap, and from the ConfigMap to the mounted file. Kubelet's part was measured at up
to 88 s in kind, and is stated as at most 120 s. How long a deployment pipeline takes to apply
the ConfigMap is the pipeline's, and is stated with it.

**Emergency withdrawal** is an edit to the registry: removing the tool from its surfaces, or
removing the tool or its entry. It takes effect on a replica within the delivery bound plus one
`registry.poll_seconds`: in kind, at most 120 s plus one poll once the ConfigMap is applied, and
in Compose, one poll. Restarting
the deployment after applying the ConfigMap bounds it by the rollout instead. The same bound
applies to every lever that is a registry edit, including the two in decision 0012: removing a
team from a surface's allowlist, and withdrawing a surface.

**How stale identity inputs may be:**

- **Group claims** are as fresh as the token that carries them. A user issuer's
  `max_lifetime_seconds` may be at most 3600.
- **A team manifest change** takes one rollout. The manifest is read at boot.
- **Issuer keys** stay in force when a refresh fails. Refusing every token because a refresh
  failed would turn an outage of the issuer's host into an outage of the gateway. Instead each
  issuer's key age is exported as `switchboard_issuer_keys_age_seconds{issuer}`, with the
  issuer label taken from configuration, built with the key refresher's logging (#91). Its
  alert condition, at four refresh intervals, is Q12's (#5).
- **Per-user grants** (milestone 5) are looked up on every call. A grant is revoked by deleting
  it from the gateway's grant store, which drops any access token the gateway holds for it. The
  next call is refused by the credential layer, telling the person to link their account,
  with no snapshot change. A grant revoked at the vendor fails the next call there, as a vendor
  refusal.
- **Residual:** a token for a deleted pod or ServiceAccount is accepted until it expires, since
  verification is offline.

### 9. Registration and the probe

In milestone 3 there is no registry service, so registration is the approval pull request.
Each proxied entry records `probe = { result = "refused", date = ... }`. A new command produces
it: `switchboard probe --config=FILE --server=NAME`. It reads the deployment file and that
server's entry only, and does not apply the loader's probe rule, so an entry can be probed
before it has a record. It sends decision 0010's three calls. The loader refuses a proxied entry
without a record. A probe that could not connect is never recorded as refused.

The drift pass repeats the three calls each interval. A server that dispatches one of them is
logged at ERROR, counted and alerted on, and recorded as open, as decision 0010 says. Its tools
stay listed: withdrawing them would close the governed route and leave the open one.

### 10. Per-team identities, and which containers hold a Kubernetes API token

**Per-team identities.** There is one ServiceAccount per team service identity: `docs-team-a`
and `docs-team-b` now, and later the probe ServiceAccount and the registry's workload identity.
Their tokens come by TokenRequest, under a Role limited by `resourceNames` to those accounts. A
token-writer sidecar in the gateway pod writes each token to a file, using the demo image's
`curl` and `jq`. The gateway reads each file as it reads every credential today, so the gateway
binary gains no API-server client in milestone 3. Compose uses static per-team dummy
credentials. This lands after #60, so that the route check sees grants limited by
`resourceNames`.

**Only the token-writer sidecar holds a token the API server accepts.** It alone mounts a
projected token with the API server's audience, and the cluster CA. The gateway container
mounts none: the pod does not mount its ServiceAccount token automatically, and the projected
tokens the gateway container reads have other audiences, such as the mock server's, which the
API server refuses. No workload mounts one at all. Both containers run as the pod's one
ServiceAccount, so the TokenRequest grants belong to the pod. What keeps the gateway container
from using them is that it holds no token the API server accepts. The demo checks assert it:
in the gateway pod only the token-writer container mounts an API token, and no workload does.

**Fetching the API server's keys (#88) does not give the gateway container a token.** A second
projected token cannot help: every projected token authenticates as the pod's own
ServiceAccount, with its TokenRequest grants. Instead, in kind, the gateway fetches
`/openid/v1/jwks` with no token. This project binds `system:service-account-issuer-discovery` to `system:unauthenticated`
in the kind cluster, which serves the issuer's discovery document and public keys and nothing
else, and the gateway trusts `kube-root-ca.crt` for it. Other clusters publish their issuer's
keys at a URL that needs no token. Where that binding is not wanted, kind keeps its keys file.

### 11. Acceptance scenarios

Each is a test on fakes in the per-change loop, and the kind slice shows the drift ones.

- A registry file that cannot be read for longer than the maximum age: `/readyz` fails, and
  `tools/call` and `tools/list` are refused with the stale-policy sentence and no row.
- Two gateways in one process, each with its own drift pass against one fake server, each
  withdraw a changed definition within one interval plus one deadline, and their rows record
  the derived revision.
- A widened reach, shown by the canary being reached, withdraws the entry's tools.
- Approving the definition the server now serves brings the tool back: a new `approved_at` and
  the new `definition_sha256`, and the next pass leaves it served.
- A server that dispatches a probe call is reported open, and its tools stay listed.
- A restored server and a restarted replica: after a withdrawal, the server serves its approved
  definition again and the replica restarts. The replica serves the tool again, as section 7
  states, and the earlier `tool_withdrawn` line and count exist. With the server still changed,
  the restarted replica withdraws the tool before `/readyz` passes.
- A standing withdrawal survives a reload that leaves its key unchanged, and the derived
  revision names the new base.
- A server entry changed without its tools approved again is refused at boot and at reload.
- A registry serving more than 16 proxied tools is refused.

## Alternatives rejected

- **A separate drift-checker workload writing a withdrawals ConfigMap** (#4's draft). It could
  not read a self-built server's tool list, which accepts only the gateway's identities. It
  adds a second delivery path with kubelet's delay, and a workload with its own credentials.
- **One combined fingerprint over the definition and the binding.** Drift compares only the
  definition with what the server serves. A changed binding is a change in this repository and
  is caught by the loader. Mixing them would make a served definition impossible to compare.
- **Converting draft-07 schemas to 2020-12.** It needs a converter and a third hash, for the
  served schema, to compare against. No server needs it yet.
- **`serverInfo.name` as the identity.** It is the server's own claim, and a session-less
  connector never receives it.
- **Per-audience tokens of the gateway's own ServiceAccount for each team.** Every team would
  present the same subject, so a server could not tell teams apart, and decision 0010 would
  need amending.
- **A TokenRequest client inside the gateway.** It would put a token the API server accepts,
  with the TokenRequest grants, in the process that handles callers' requests.
- **Signed snapshot expiry now.** Nothing signs snapshots yet. The maximum age covers a replica
  that cannot read its file, and the delivery path's bound is stated separately.
- **A hash of the withdrawn names in the revision** (the first draft of this record). A row's
  revision would not say what was in force once the logs mapping the hash were gone.
- **Treating a failed poll as drift.** A server that is down would lose its tools on every
  replica, and one that is slow on purpose could withdraw its own tools.

## Consequences

- **#11 builds:** `binding_sha256` and its recomputation; the identity and destination rules;
  the dialect refusal; the drift pass with its derived revisions and standing withdrawals; the
  probe command and record; the token writer; and the scenarios above. The loader gains these
  rules, each with a case and a mutation in `scripts/mutation_check.py`: both hashes
  recomputed, identity equal to the address's host, the destination rules, a probe record on
  every proxied entry, the dialect, and at most 16 proxied tools.
- **The deployment file gains** an optional `[drift]` table (`interval_seconds`, default 300,
  from 5 to 900) and `registry.max_age_seconds` (default 60, at least twice `poll_seconds`). The
  demos set 10 s for drift. A user issuer's `max_lifetime_seconds` above 3600 is refused.
- **Metrics:** drift polls by result, withdrawals, probe results and reach-check results, per
  proxied server and labelled only by registry names; the policy's age; and each issuer's key
  age. The alert conditions on them are Q12's (#5).
- **The demos change:** approvals are recomputed from what the mock server serves (#51); the
  identity becomes the Service name; the entries are `in_cluster`; and each carries a probe
  record.
- **The demo and deploy registries become policy files** under decision 0011 once approvals
  bind servers: the registries under `deploy/kind`, `deploy/compose` and `deploy/ci`, and the
  registry crate's demo file. Decision 0011 lets no policy file land before the code owners and
  the branch rule requiring their review exist. So #48 (a `CODEOWNERS` entry and a code-owner
  branch rule, set by the owner) must land before the approval-binding work of #11 merges, or
  the owner rules that those files are fixtures, not policy files.
- **Persisted withdrawals** get a home issue in milestone 6, with the hashed revision's store.
- **Q11 is settled,** except what others decide (Still open). Decisions 0010, 0011 and 0012
  carry dated notes. Design sections 7, 8, 13 and 15 change to match.
- **Decision 0012's two levers** take effect within the delivery bound plus one poll, not one
  rollout, and are tested against that.

## For the owner

These are the owner's own answers. The record holds the recommendation for each, and the owner
answers by merging it or by asking for a change.

- **How often the drift pass runs** (section 5): every 300 s by default, configurable from 5 s
  to 900 s, and 10 s in the demos. It also sets how often the reach check runs (decision 0011,
  Still open).
- **How long a withdrawal lasts** (section 7): in each replica's memory in milestone 3, until
  approved again or until that replica restarts, with the residual stated and every withdrawal
  alerted on; persisted in milestone 6.
- **#48 before the approval-binding work** (Consequences), or a ruling that the demo and deploy
  registries are fixtures.

## Still open

- **Platform owners** grant the probe ServiceAccount's TokenRequest permission outside kind
  (Q17). Until then the probe runs only in kind, and no self-built server is registered
  elsewhere.
- **IT and vendor administrators** (decision 0011): the narrow service accounts, and any
  administrative credential the reach check needs to read a vendor's report. Until then no
  proxied entry is exposed, and a vendor report check is not built.
