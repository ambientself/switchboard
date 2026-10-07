# 0012: What a turn grant binds, and what Otto changes for it

Date: 2026-10-06. Status: accepted here; needs changes in Otto. Accepted on 2026-10-07, when
the owner accepted the recommendations (see the end). Settles Q18. Answers what
[decision 0004](0004-verify-turn-grants-with-a-public-key.md) left open, and changes one of its
consequences: the format change is made before stage 1, not with the cutover. Written against
the 2026-10-04 amendment to [decision 0006](0006-what-the-decision-function-sees.md), the
audit record's resource columns (pull request #30, not yet merged), and decisions
[0009](0009-audit-completion-receipts-and-recovery.md),
[0010](0010-what-stops-an-agent-going-around-the-gateway.md) and
[0011](0011-resource-authorization-and-tool-assurance.md), accepted the same day. Amends 0006
again on 2026-10-07. None of the changes in Otto has been agreed with Otto's owners yet.

## Context

Otto's control plane mints one grant per turn. At Otto `752395a` a grant is
`v1.<key id>.<claims>.<MAC>`: an HMAC under a shared secret and a domain prefix, in unpadded
base64url, at most 8192 bytes. The claims are the session, turn, execution, team, acting
human, fencing epoch, expiry, and the turn's tools by Otto's bare names. The control plane
mints it from the AgentExecution just before the turn starts. The expiry is the turn's
deadline, which `-turn-timeout` bounds: 14 minutes by default, and required to be under
`-execution-timeout`, 15 minutes by default. The grant reaches the harness in its MCP
configuration when the turn starts, or at bind on a pre-booted harness (Otto's ADR-0019, on
only in kind), and is sent on every MCP request in `X-Otto-Turn-Grant`. Its claims are
encoded, not encrypted. Anything in the sandbox that can read the harness's configuration can
copy the grant out. No sandbox has a shell today, and Otto relies on that.

The conformance suite shows what Otto's gateway enforces
([otto-baseline.md](../otto-baseline.md)): sixteen kinds of unverifiable grant refused with one
sentence and nothing from the grant recorded, a grant for another team refused naming both
teams, and a tool outside the grant refused. Otto's source shows what the grant leaves open:

- **Which gateway.** Nothing in the grant names its verifier. A public key, unlike a shared
  secret, can be put anywhere without harm to the key, so it will be configured in more places.
  Every verifier that holds it would accept the grant.
- **Which caller.** Any sandbox of the grant's team, until it expires. Otto's sandboxes share
  one ServiceAccount per team, so the proved subject says no more than the proved team. The
  pod's name and UID are in its projected token. Otto's gateway logs them and binds neither.
  Otto tracks this as `otto-d8a9`.
- **How long.** Until expiry. Otto's verifier allows no clock leeway and does not cap the
  lifetime, and the grant carries no issue time.
- **The fencing epoch.** Signed, recorded in `gateway_audit.fencing_epoch`, and compared with
  nothing. Otto's model broker reads a floor from Otto's lease table on each call and refuses a
  superseded control plane's tokens. Its gateway does not. Otto tracks the gap as `otto-k6dy`,
  deferred until a second control plane, a blue/green failover or local execution in
  sandboxes is enabled. Until then Otto runs one control plane per environment.
- **Rotation.** A current and a previous key, the previous retired at an absolute instant. The
  suite does not exercise it.

The staged cutover ([design.md](../design.md), section 17, and issue #13) constrains the
answer. In stage 1 this gateway receives copies of Otto's real read calls. In stage 2 a turn's
reads come here and its writes go to the Go gateway, and the harness holds one grant. Stage 3
moves the writes.

## Decision

A grant binds its issuer, the deployments it is for, a short lifetime and the turn's tools.
It binds the sandbox pod, in Otto's first change if Otto can mint it then, and before stage 3
at the latest. It carries the turn's egress setting, which is recorded. It may be presented any
number of times within those bounds, and every row records which grant it was. A
side-effecting call, a call of any tool not classified `read`, is allowed only while Otto says
the turn is current, which enforces the epoch and lets Otto stop one turn. The grant does not
bind resources.

### What the grant carries

| Claim | Binds | What this gateway checks | Compared with today |
| --- | --- | --- | --- |
| Version, key ID, signature | The issuer: the control plane that holds the private key. | The version is a new one, neither `v1` nor the model broker's `v2`, and is matched before anything else is read. The key ID names a key configured here and not retired. The Ed25519 signature covers the version, key ID and encoded claims under its own domain prefix, and is checked before the claims are decoded. Encoding and verification are strict (below). | Changed. |
| `aud` | The gateway deployments the grant is for, as a list of names. | Includes the deployment that received the call. | New. |
| `iat`, `exp` | When the grant was minted, and the turn's deadline. | `iat` no later than now plus leeway, so it is also the not-before time. `exp` after now minus leeway. `exp − iat` at most 15 minutes. | `iat`, leeway and ceiling new. |
| `team` | The team the turn runs for. | Equal to the proved team (check 3). | Unchanged. |
| `tools` | The tools the turn may call, by Otto's bare names. | Not empty. Mapped to this gateway's names and made the delegation's tool list (check 4). | Mapped. |
| `epoch` | The control plane that drove the turn. | Present. Sent to Otto with each side-effecting call (below). | Enforced, for side-effecting calls. |
| `sid`, `tid`, `eid`, `actor` | The session, turn, execution and acting human. | Present. Recorded, the human in the claimed columns. | Unchanged. |
| `pod` | The UID of the sandbox pod that runs the turn. | Equal to the pod UID in the caller's verified token, once required for the issuer. | New. |
| `egress` | The turn's egress setting: sealed, or open through Otto's proxy (decision 0010). | Covered by the signature, and recorded. No check decides on it. Present, once required for the issuer. | New. |

The leeway is 30 seconds, what Otto's gateway allows on ServiceAccount tokens. The ceiling is
15 minutes, Otto's default `-execution-timeout`, which its turn deadline already has to stay
under. If Otto raises its timeouts past the ceiling, its minter refuses those turns, so the
ceiling is raised here first. Expiry bounds when a call may start, not how long it runs.

**The issuer is the key.** Configuration gives each verifying key one issuer name, and the row
records it. Each Otto environment signs with its own key, so a grant from Otto's QA control
plane does not verify in production.

**The audience is a list,** because until the last stage one grant is presented at two
gateways. During cutover Otto mints the Go gateway's name and the name of this gateway's Otto
deployment; after the last stage, this gateway's name alone. Deployment names become part of
the wire contract, so renaming a deployment needs Otto to mint the new name first.

**The issue time closes a gap the ceiling leaves.** Checking only that expiry is within 15
minutes of now would accept a grant minted to last a year, in its final 15 minutes. The minter
also refuses a longer lifetime itself, so that failure shows in the control plane, not on the
turn.

**The pod is bound by UID.** A pod name can be reused; a UID cannot. Otto has already claimed
the sandbox when it mints: its driver is handed `exec.Status.SandboxRef`, and the controller
reads that Sandbox's UID beside it, without failing the turn when the read fails. The projected
token proves the pod's UID, which is not the Sandbox resource's. What Otto adds is resolving
the claimed sandbox to its pod's UID before minting, and refusing the turn when it cannot. Otto
is asked for `pod` in the first change. If Otto cannot do that, `pod` follows before stage 3 in
the two steps below, and until then a copied grant can be presented for reads by any sandbox of
its team, recorded with the pod that did. The owner accepted that gap for stages 1 and 2. In
stage 3 this gateway makes proposals in the acting human's name, and Otto's rule that a
requester may not approve their own change depends on that name, so the pod is bound before
writes move. The binding stops a copied grant only while the harness cannot also read the pod's
projected token, which Otto has to confirm.

**The egress setting is recorded, not enforced.** A sealed turn and a turn with egress open
share an issuer, a deployment and often a subject, so decision 0010 asks Otto to carry the
setting in the grant, and this gateway verifies and records it. The row then says whether a
turn could have gone around the gateway. Otto is asked for it in the first change. If Otto
cannot, it follows by the two steps below. Until Otto mints it, rows record no egress setting,
and every Otto turn is taken to have the governed path, not the only path, as 0010 says.

**One grant, one string.** Each part must be canonical unpadded base64url, so a grant that
does not re-encode to the same bytes is refused. The signature's S must be canonical, and a
public key of small order is refused when configured. Otherwise one grant could be presented
as many strings, each with its own digest. Otto's Go gateway applies the same rules, so in
stage 2 both gateways accept the same grants.

**One breaking change, then additive claims.** The move to Ed25519 is made once, by Otto's own
procedure: stop admitting turns, drain, roll the control plane, the Go gateway and the sandbox
image together, then resume. It is made before stage 1, so that the shadow comparison verifies
real grants, which means Otto's Go gateway verifies the new format too. After that a claim is
added in two steps: Otto starts minting it, then this gateway starts requiring it. Both
verifiers ignore claims they do not know. This needs no second drain as long as Otto delivers
grants to the harness the same way. Requiring `pod` or `egress` is a setting per issuer in
this gateway's configuration, so turning it on needs no release.

**Failures.** The verifier makes these checks before the decision function, and does not
deny. A grant that fails any of them is passed on as a delegation that is present and
unverified, carrying only which check failed, and check 3 denies it under the single reason
kind [decision 0009](0009-audit-completion-receipts-and-recovery.md) gives an unverified
delegation. One place decides, and a deny row is written. The caller reads Otto's one fixed
sentence for a bad grant. Which check failed is recorded on the row, logged and counted, never
returned, and is not a reason kind. The row holds the proved columns and nothing from the
grant's claims. When the signature verified and a binding failed (audience, lifetime or pod),
the row also records the grant's digest. That is the one exception to 0009's rule that such a
row holds nothing from the grant. A digest is not a claim, and it matches a refused use of a
grant with the rows where the same grant was accepted. Honest sandboxes produce lifetime
failures, from a call just after the deadline or a node whose clock is off, so those are
counted and alerted on by rate. An audience or pod failure comes from a copied grant or a
configuration fault, never from an honest sandbox under a correct configuration, so each one
is investigated. A team mismatch is still named, by check 3, because such a grant verified
and the mismatch is usually a rollout fault. A pod mismatch is not named, because naming it
helps only the copier.

### Presenting a grant more than once

A grant may be presented any number of times before it expires, at a deployment it names, and,
once `pod` is required, only from the pod it names. There is no replay cache.

Each row records the grant's digest, the SHA-256 of the grant as presented, which strict
encoding makes one value per grant. The row also holds the key ID, the verified session, turn,
execution and epoch, and the pod. Across this gateway's deployments that share its audit
store, one query finds a grant used from more than one pod or deployment. (Q6 has the laptop
deployment share the in-cluster one's store; a deployment with a store of its own is queried
separately.) During cutover `aud` also names Otto's Go gateway, which writes to Otto's
`gateway_audit` with no digest. Reuse there is found only by joining on the session and turn,
using the pod Otto's gateway logs. Otto keeps no copy of a grant, by design, so it cannot
compute the digest; it joins on the session and turn, as it does today.

What is left is reuse inside the grant's own pod and lifetime, including after its turn has
ended. For side-effecting calls the currency check below stops it. For reads, expiry bounds
it.

### Currency: the epoch, ended turns and revoked turns

Before deciding a `tools/call` of any tool not classified `read` under the profile for Otto's
sandboxes, the Otto adapter asks Otto's resolver interface
([decision 0003](0003-otto-keeps-its-control-plane-endpoints.md)) one question: is this turn
(session, execution, turn and epoch) current? That covers Otto's three `propose` tools, and
its two `write` comment tools once decision 0011's exception allows them (see Tools and
resources). Otto answers current, superseded (a newer epoch holds the lease), ended, or
revoked. The answer is not cached. No answer within a fixed budget of one second, an error,
an unknown version, or an answer to another question counts as unconfirmed, and the call is
denied, as 0003 requires.

Otto answers from its durable state: the lease row's holder and epoch, compared on the
database's clock as Otto's own fencing does, and the turn's recorded state. A superseded
control plane that is still running must not be able to say its own turns are current. This
gateway cannot tell a right answer from a wrong one, so that is Otto's guarantee, tested in
Otto.

The check is made once, before the call runs. A failover during a side-effecting call does not
stop it, so two control planes driving one session are made unlikely to act twice, not
prevented from it. Decision 0009 states what is left of that window, under "What may be
retried": its receipts cover a resend of the same call, and cover a turn replayed after a
failover only if Otto's control plane sends a key that stays the same across replays, which
is its Still open 8. Until Otto's owners agree such a key, two control planes can propose
twice. Which grant fields scope an idempotency key is also 0009's question, not settled here.

Reads and `tools/list` are not fenced. Otto's model broker already cuts a superseded control
plane's turns off from the model, so their remaining tool calls are ones the sandbox makes
itself. Reads give it nothing the turn did not already have, and end at expiry. Fencing reads
would put Otto's control plane on every read.

This departs from Otto's control-plane document twice, and Otto has to agree. That document
says grant enforcement makes no call to Otto on the ordinary tool path; this makes one on every
side-effecting call. It says the gateway fences a superseded control plane; this fences its
side-effecting calls only.

The same question lets Otto stop one turn at once: it marks the turn revoked, and its next
side-effecting call is denied.

**Control-plane actions are not fenced by this record.** Otto's pull-request receipts, the
control-plane action that writes to GitHub today, are posted by a separate poller after the
turn has completed. It carries no epoch and prevents duplicates by claiming rows in Otto's
database. So the profile for Otto's control-plane surface does not require currency. Whether a
component that acts under the lease should send its epoch, and be asked whether that epoch
holds the lease, is put to Otto.

### Where currency sits in the decision function

The 2026-10-04 amendment kept profiles to a set of classifications, and rejected fields that
mean something only for some tools and profiles. Currency is such a field. It goes in the
function anyway, so that the decision table and its properties cover it. Otherwise the adapter
would deny before the function runs: a second place that decides, which 0006 allows only for
refusals that can never allow, such as a connector's and those decisions 0009 and 0011 add.
Amendments to 0006:

- **The call context** gains the call's currency: current, not current (superseded, ended or
  revoked), unconfirmed, or not asked. The Otto adapter asks only when the snapshot's tool is
  not classified `read` and the profile requires currency. An adapter that fails to ask leaves
  "not asked", which is denied.
- **A profile** gains a setting: a side-effecting call requires a current control plane. The
  profile for Otto's sandboxes sets it.
- **A new check after check 5,** and after the exception step that decision 0011 adds to it,
  before check 6. Under such a profile, a call of a tool not classified `read` is allowed only
  if its currency is current. A `write` tool that no exception names is denied at check 5
  first. The check is skipped for `tools/list`, like check 6.
- **Two new reason kinds,** not current and unconfirmed, each with its sentence. The row
  records which answer Otto gave.
- **The delegation** gains its issuer, digest, key ID and egress setting, and the principal
  gains the pod UID for a Kubernetes workload. The function reads none of these. The audit
  record keeps them.
- **A grant that fails verification** reaches the function as a delegation that is present and
  unverified, carrying only which check failed, and check 3 denies it, as decision 0009 amends
  0006. Its row records which check failed and, when the signature verified, the digest
  (Failures, above).

### Tools and resources

The grant's `tools` become the delegation's tool list, which the 2026-10-04 amendment makes
required. An empty list is refused as an unverifiable grant, as Otto does. While one grant
serves both gateways it carries Otto's names, because the Go gateway compares bare names. The
Otto adapter maps them with the explicit mapping in `conformance/baseline.json` and Otto's
migration configuration ([design.md](../design.md), section 18): reviewed configuration, one
name to one name, tested to be one-to-one. A name with no mapping, or one that maps to a tool
this surface does not serve, is dropped; in stage 2 that drops every write still on the Go
gateway.

A grant only narrows. Check 4 runs before check 5, so a grant that lists a `write` or
`destructive` tool is still denied, naming the classification, unless decision 0011's
exception names that tool for this profile. Of the five write tools Otto serves at `752395a`,
three are `propose`: `github_create_pr`, `github_propose_change` and `github_amend_change`.
Two are `write` under 0006's comment rule: `github_pr_comment` and `jira_comment`. The two are
denied until 0011's exception mechanism is built. From then they are allowed only through it,
and fenced like the three, because the currency check runs after the exception step and
covers every tool not classified `read`. The adapter records all five as `write` in
`gateway_audit`.

The grant does not bind resources. A turn's calls are limited by the team's resource limits
(check 6) and the connectors' own scope checks, as in Otto. Pull request #30 adds the resources
a call named to its row, at most 64. A tool that checks its own scope has no resources before
it runs, and its row says `unknown` only until it reports what it reached when it finishes,
which [decision 0011](0011-resource-authorization-and-tool-assurance.md) requires before
milestone 4. A per-turn resource list would need Otto to know at mint time every repository a
turn may touch, and connectors that narrow by it.

### Keys

One algorithm, Ed25519, which Otto's model broker already uses. The key ID is derived from the
public key, as Otto derives it from the secret today, so a key cannot be filed under the wrong
ID. Keys are deployment configuration, read at boot and changed by a reviewed change and a
rollout, not part of the policy snapshot. The gateway never fetches a key from Otto. Each
issuer has at most two keys: the current one, and a previous one with an absolute end instant,
so a restart does not extend it. The private key is held only by the control plane that mints,
and is not the model broker's key. Rotation: add the new public key here and roll it out; Otto
signs with it; after one lifetime ceiling the old key's end instant passes and it is removed.

The gateway refuses to start if: the profile for Otto's sandboxes has no grant key; a key file
holds private key material; a key is of small order; the same key is configured twice, or
under two issuers; a previous key has no end instant; or a surface under that profile serves a
tool not classified `read` while `pod` is not required for its issuer. The last holds the pod
binding in place once writes move. Surfaces and their tools are snapshot data and change while
the gateway runs, so the last is also checked when a snapshot is loaded: a snapshot that breaks
it is refused, and the running snapshot is kept. The gateway also refuses to start with grant
checking turned off outside a development build. The Rust target of the conformance suite is a
development build, so the suite's cases that start the gateway with grant checking off still
run there.

### Revocation

| Lever | Stops | Takes effect |
| --- | --- | --- |
| Otto marks a turn revoked. | That turn's side-effecting calls. | On its next one. |
| Otto's lease moves to a new epoch. | Side-effecting calls of every turn of the superseded control plane. | On each turn's next one. |
| A team removed from the allowlist of Otto's sandbox surface. | Every call of that team's sandboxes, reads included. | Within the snapshot's freshness bound (Q11). |
| A key removed from configuration. | Every grant it signed, until Otto signs with a key the gateway holds. | One rollout. |
| Otto's surfaces withdrawn. | Every Otto call. | Within the snapshot's freshness bound (Q11). |

None waits for grants to expire. A turn's reads cannot be stopped sooner than its expiry
except by the team, key or surface levers, which stop much more. Until Q11 sets a freshness
bound, the team and surface levers are taken to need one rollout, and are tested against that.

### What Otto changes

In one breaking change, before stage 1:

1. Sign grants with Ed25519 under a new format version and domain prefix, with the key ID
   derived from the public key and a separate key in each environment.
2. Encode grants canonically, and verify them in the Go gateway by the strict rules above.
   Whether the Go gateway also checks `aud` is Otto's choice.
3. Mint `aud`, and `iat` beside `exp`, and refuse to mint a lifetime over the ceiling.
4. Mint `pod`, resolved from the claimed sandbox, and refuse the turn when it cannot be.
   Recommended here, if Otto can do it in this change.
5. Mint `egress`, the turn's egress setting that decision 0010 asks for. Recommended here, if
   Otto can do it in this change.

Before stage 3:

6. Mint `pod`, if it was not in the first change.
7. Answer the currency question on the resolver interface within the budget, from the lease
   row and the turn's recorded state, and record turns as ended or revoked.

At any time, by the two steps above: mint `egress`, if it was not in the first change.

Decision 0003 already asks Otto for the resolver interface and for its control-plane endpoints
to run outside the Go gateway. This adds one question to that interface. None of it has been
raised with Otto yet.

### Tests

The adapter's tests are company-wide behavior, in their own group apart from the baseline, as
Q8 requires, and each guard gets a mutation in `scripts/mutation_check.py`. The groups are
replay, use at another deployment and from another pod, format and forgery (including
non-canonical encodings), clock skew at the leeway and the ceiling, key rotation across a
restart, each boot refusal and the matching refusal at snapshot load, failed grants denied at
check 3, each currency answer against a read, a proposal and, once decision 0011's exception
exists, an excepted `write` tool, revocation, and composition with the tool list. One property
holds throughout: under a profile that requires currency, a call of a tool not classified
`read` is never allowed unless current. Among the mutations: the currency check keyed on
`propose` alone, and the snapshot-load refusal removed. That the answer comes from the lease
row is tested in Otto. The cases go in [design.md](../design.md), section 18, and issue #22.

The conformance suite changes only when it is re-pinned to Otto's new format (#23). Until then
its `mintGrant` signs `v1` HMAC grants, which this gateway never accepts, so the suite cannot
run against the Rust target before the re-pin.

## Alternatives rejected

- **Single-use grants, or a shared replay cache.** A turn makes many calls with one grant.
  Single use needs the control plane on every call. A cache is a shared write on the request
  path, and stops use from another pod no better than binding the pod.
- **An `iss` claim, or a unique-identifier claim.** The key determines the issuer, and an
  `iss` claim could add only a disagreement with it. The digest of a canonical grant
  identifies it without a change in Otto.
- **Binding the ServiceAccount subject.** Otto's sandboxes share one subject per team, so it
  binds no more than the team does.
- **One audience, with each turn routed to one gateway.** Stage 2 splits one turn's calls
  between the two gateways by tool.
- **Two grants per turn, one per gateway.** How stage 2 routes a turn's calls is #13's choice:
  two MCP servers in the harness's configuration, or a proxy in the pod that routes by tool.
  With one grant naming both deployments, either works without knowing about grants. With two,
  whatever routes must also pick the grant, and the stage 1 copies of calls to the Go gateway
  would carry a grant whose audience is not this gateway.
- **Fencing every call against a floor refreshed in the background.** Every Otto call, reads
  included, would fail when the floor went stale, to stop reads by turns that Otto's model
  broker has already cut off from the model.
- **Caching currency answers.** A superseded turn's side-effecting calls would pass for as
  long as the cache lived.
- **Refusing a failed grant in the verifier, before the decision function.** The core writes
  an audit row only from a decision, so that path would leave no row, and it would be a second
  place that decides. Decision 0009 routes it through check 3 instead.
- **Fencing `propose` calls only.** Decision 0011 lets two `write` comment tools through by
  exception. A superseded, ended or revoked turn could then still comment.
- **Reading Otto's lease table directly,** as Otto's model broker does. Decision 0003 says this
  gateway does not read Otto's tables.
- **Asking turn currency for control-plane actions.** Receipts are posted after the turn has
  ended, so every one would be denied.
- **Binding the surface in the grant.** Surface allowlists already admit a sandbox's subject to
  Otto's sandbox surface and nowhere else.
- **JWT.** Header-chosen algorithms and keys are a known class of verifier mistake. Otto's
  format fixes the algorithm by version.
- **Fetching Otto's keys at run time.** Whoever controlled that endpoint could add a key.

## Consequences

- Milestone 4 needs one breaking change in Otto before stage 1, up to two additions before
  stage 3, and `egress` if it was not in the first change. Stage 3 is not ready until the pod
  binding and the currency check are live, alongside the receipts of decision 0009.
- Decision 0004's open paragraph is answered and its requirement stands: Otto's cutover waits
  for the asymmetric signature. Its drain consequence changes: the format change is made
  alone, before stage 1, and Otto's Go gateway verifies the new format.
- Decision 0009 leaves fencing to this record. Which grant fields scope a key stays open in
  0009 (its Still open 8).
- From stage 3, every side-effecting Otto call through this gateway depends on Otto's resolver
  and fails closed when it does not answer. Decision 0003 accepted that for some Otto tools; it
  is now true of Otto's three `propose` tools, and of its two comment tools once decision
  0011's exception allows them. No other caller is affected.
- Decision 0006 is amended as above, with table cases and mutations for each change.
- This gateway's audit record gains the grant digest, issuer, key ID, pod UID, egress setting
  and currency answer. Otto's `gateway_audit` has `session_id`, `turn_id` and `fencing_epoch`
  and no column for these, so they are kept only here unless Otto adds them, as with the
  resources pull request #30 adds.
- The Kubernetes identity verifier exposes the pod UID its token proves.
- Stage 1 copies verify here only if they carry the sandbox's own identity token and grant,
  with that token's audience admitting this gateway. How copies are made is #13.
- Grant checking can be turned off only in a development build, enforced at boot. That settles
  that part of Q12 for this gate. The Rust target of the conformance suite is a development
  build.
- The control plane is still trusted for whom it names. A grant proves that Otto said who the
  turn was for, not that the person acted.
- Verification is offline, so a deleted pod's token and grant verify until they expire or a
  wider lever is used.
- Left for later, and what brings each back: fencing reads, once Otto enables a blue/green
  control-plane swap in production or local execution in sandboxes while this gateway serves
  its reads; resources in the grant, once Otto needs a turn narrowed below its team's
  resources; single use or a replay cache, once Otto mints a grant per call or a write turns up
  that the receipts of decision 0009 do not protect; this gateway's tool names in the grant,
  once the Go gateway's MCP path is retired; facts fixed for the turn, such as skill pins, once
  `github_skill_body` is built (#12), choosing then between a claim and the resolver as 0003
  says.
- Until Otto agrees, the changes in Otto above are requests, and the three "agree with Otto"
  criteria in issue #21 stay open. What this gateway does meanwhile is under Still open, below.

## Decided by the owner

On 2026-10-07 the owner accepted this record's recommendations:

- **The format change comes before stage 1.** Otto is asked to move to Ed25519 in one change,
  alone, before stage 1, and its Go gateway verifies the new format by the same strict rules.
  This replaces decision 0004's plan to make the change with the cutover.
- **`pod` in the first change, if Otto can.** If Otto cannot, stages 1 and 2 may run with
  copied grants usable for reads by any sandbox of the grant's team, recorded with the pod
  that presented them and not refused. `pod` is required before stage 3, and a gate at boot
  and at each snapshot load holds that.
- **The lifetime ceiling is 15 minutes and the leeway 30 seconds.** The ceiling is raised here
  before Otto raises its timeouts past it.
- **The resolver's budget is one second.** No answer within it denies the side-effecting
  call.
- **Reads stay unfenced,** until Otto enables a blue/green control-plane swap in production or
  local execution in sandboxes while this gateway serves its reads.
- **Control-plane actions are not fenced by turn currency.** Duplicate control-plane effects
  stay with Otto's row claims and the receipts of decision 0009, unless Otto's answer below
  changes that.
- **Configuration levers take one rollout** until Q11 sets a freshness bound. Removing a grant
  key, or a team from the allowlist of Otto's sandbox surface, is a reviewed configuration
  change like any other.
- **This gateway names its own deployments,** in its deployment configuration. Renaming a
  deployment that Otto's `aud` names is coordinated with Otto, which mints the new name first.
- **Audience and pod failures are investigated one by one. Lifetime failures alert on a rate.**
- **The digest replaces a unique-identifier claim.** Issue #21 asked for an identifier in the
  grant. The SHA-256 of the canonical grant identifies it with no change in Otto.
- **Grant checking can be turned off only in a development build,** enforced at boot.
- **Stage 1 copies carry the sandbox's own identity token and grant,** with the token's
  audience admitting this gateway. Stage 1 does not start without them.

## Still for the owner

- **Who takes the changes in Otto to Otto's owners.** This record made no recommendation on
  it, so accepting the recommendations did not settle it. Decision 0009 tracks its Otto
  questions under issues #21 and #22. Decision 0010 sends its Otto questions with this record's
  changes, as one list, raised by whoever the owner names. Meanwhile nothing has been raised,
  and the first item below waits on it.

## Still open

These need someone other than the owner. The record holds with them open: each says what
this gateway does meanwhile.

- **Otto's agreement to the changes above, and whether Otto's schedule fits milestone 4.**
  Decided by Otto's owners. Nothing has been raised with them yet. Meanwhile the Otto adapter
  is built and tested against a local grant minter and a fake resolver, Otto's Go gateway
  keeps serving Otto, and stage 1 does not start until Otto's breaking change has been rolled.
- **Whether Otto can mint `pod` in the first change, and whether the harness can read the
  pod's projected token.** Decided by Otto's owners. Meanwhile `pod` is not required, a copied
  grant used for reads is recorded with the pod that presented it, and the gateway refuses to
  start, or to load a snapshot, if Otto's sandbox surface serves a tool not classified `read`
  while `pod` is not required.
- **Whether the grant carries the turn's egress setting, and in which change.** Decided by
  Otto's owners, with decision 0010's other requests. Meanwhile `egress` is not required, rows
  record no egress setting, and every Otto turn is taken to have the governed path, not the
  only path, as 0010 says.
- **The ceiling and leeway in Otto's minter.** Otto's owners agree to mint `iat` and to refuse
  a lifetime over 15 minutes. Meanwhile this gateway applies the ceiling and leeway to every
  grant it verifies.
- **The resolver's availability target, and who is paged when it fails.** The target is
  decided by Otto's owners, and paging by the on-call rotation that will carry it. Meanwhile
  nothing calls the resolver before stage 3. From stage 3 a side-effecting call is denied when
  the resolver does not answer within one second, and reads keep working.
- **Whether Otto plans a blue/green swap in production or local execution in sandboxes during
  milestone 4, and its agreement to the two departures from its control-plane document.**
  Decided by Otto's owners. Meanwhile reads are not fenced. If either is planned, fencing reads
  comes back, as Consequences says.
- **Whether Otto's lease-holding control-plane components send their epoch.** Decided by
  Otto's owners. Meanwhile the profile for Otto's control-plane surface does not require
  currency.
- **Who in Otto may mark a turn revoked.** Decided by Otto's owners. Meanwhile, until Otto
  answers the currency question, a turn is stopped only by the team, key and surface levers
  here, each taking one rollout.
- **Key custody and rotation.** Where Otto's private key is held (a mounted Secret as today, a
  signer like Otto's GitHub App custodian, or KMS or an HSM), whether that needs IT, and the
  rotation schedule are decided by Otto's owners, and by IT if they require it. Whether a
  grant-key change here needs review beyond the ordinary is decided by the security team.
  Meanwhile a grant-key change gets the ordinary review, this gateway holds only public keys,
  read at boot, and rotates by the procedure under Keys.
- **How audience and pod failures and the lifetime-failure rate reach a person.** Whether a
  failure pages or opens a ticket, for whom, and the rate that alerts. Decided by the on-call
  rotation for this gateway, with whoever runs logging. Meanwhile each failure kind is logged
  and counted, and nothing pages. The gateway's maintainers review the audience and pod
  failure counts and the lifetime-failure rate as part of each stage's go/no-go, and
  investigate each audience or pod failure they find.
- **Reading the new fields back in Otto.** Whether Otto adds columns to `gateway_audit` for the
  grant digest, issuer, key ID, pod UID, egress setting and currency answer, or reads them from
  this gateway's record, and whether Otto records each grant's digest at mint. Decided by
  Otto's owners, with audit ownership in Q12. Meanwhile the fields are kept only in this
  gateway's record, and Otto joins on the session and turn.
- **Otto minting a renamed deployment first.** Otto's owners agree to the order. Meanwhile a
  deployment named in Otto's `aud` is not renamed.
- **The audience of the sandbox's identity token for stage 1 copies.** Decided by Otto's
  owners, in the rollout plan for #13. Meanwhile stage 1 does not start.
