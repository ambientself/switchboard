# 0012: What a turn grant binds, and what Otto changes for it

Date: 2026-10-06. Status: proposed. Settles Q18 if accepted and once Otto agrees to the changes
listed below. Answers what [decision 0004](0004-verify-turn-grants-with-a-public-key.md) left
open, and changes one of its consequences: the format change is made before stage 1, not with
the cutover. Written against the 2026-10-04 amendment to
[decision 0006](0006-what-the-decision-function-sees.md) (pull request #29) and the audit
record's resource columns (pull request #30), and amends 0006 again.

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
at the latest. It may be presented any number of times within those bounds, and every row
records which grant it was. A `propose` call is allowed only while Otto says the turn is
current, which enforces the epoch and lets Otto stop one turn. The grant does not bind
resources.

### What the grant carries

| Claim | Binds | What this gateway checks | Compared with today |
| --- | --- | --- | --- |
| Version, key ID, signature | The issuer: the control plane that holds the private key. | The version is a new one, neither `v1` nor the model broker's `v2`, and is matched before anything else is read. The key ID names a key configured here and not retired. The Ed25519 signature covers the version, key ID and encoded claims under its own domain prefix, and is checked before the claims are decoded. Encoding and verification are strict (below). | Changed. |
| `aud` | The gateway deployments the grant is for, as a list of names. | Includes the deployment that received the call. | New. |
| `iat`, `exp` | When the grant was minted, and the turn's deadline. | `iat` no later than now plus leeway, so it is also the not-before time. `exp` after now minus leeway. `exp − iat` at most 15 minutes. | `iat`, leeway and ceiling new. |
| `team` | The team the turn runs for. | Equal to the proved team (check 3). | Unchanged. |
| `tools` | The tools the turn may call, by Otto's bare names. | Not empty. Mapped to this gateway's names and made the delegation's tool list (check 4). | Mapped. |
| `epoch` | The control plane that drove the turn. | Present. Sent to Otto with each `propose` call (below). | Enforced, for proposals. |
| `sid`, `tid`, `eid`, `actor` | The session, turn, execution and acting human. | Present. Recorded, the human in the claimed columns. | Unchanged. |
| `pod` | The UID of the sandbox pod that runs the turn. | Equal to the pod UID in the caller's verified token, once required for the issuer. | New. |

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
the claimed sandbox to its pod's UID before minting, and refusing the turn when it cannot. This
record recommends `pod` in the first change. If Otto cannot do that, `pod` follows before
stage 3 in the two steps below, and until then a copied grant can be presented for reads by
any sandbox of its team, recorded with the pod that did. In stage 3 this gateway makes proposals in
the acting human's name, and Otto's rule that a requester may not approve their own change
depends on that name, so the pod is bound before writes move. The binding stops a copied grant
only while the harness cannot also read the pod's projected token, which Otto has to confirm.

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
grants to the harness the same way. Requiring `pod` is a setting per issuer in this gateway's
configuration, so turning it on needs no release.

**Failures.** Every failure the verifier finds gets Otto's one fixed sentence for a bad grant.
Its kind is logged and counted, never returned, and nothing from a refused grant reaches the
claimed columns. When the signature verified and a binding failed (audience, lifetime or pod),
the row also records the grant's digest and which binding failed, and no claims. Honest
sandboxes produce lifetime failures, from a call just after the deadline or a node whose clock
is off, so those are counted and alerted on by rate. An audience or pod failure comes from a
copied grant or a configuration fault, never from an honest sandbox under a correct
configuration, so each one is investigated. A team mismatch is still named, by check 3, because
it is usually a rollout fault. A pod mismatch is not named, because naming it helps only the
copier.

### Presenting a grant more than once

A grant may be presented any number of times before it expires, at a deployment it names, and,
once `pod` is required, only from the pod it names. There is no replay cache.

Each row records the grant's digest, the SHA-256 of the grant as presented, which strict
encoding makes one value per grant. The row also holds the key ID, the verified session, turn,
execution and epoch, and the pod. Deployments share the audit store (Q6), so one query finds a
grant used from more than one pod or deployment. Otto keeps no copy of a grant, by design, so
it cannot compute the digest; it joins on the session and turn, as it does today.

What is left is reuse inside the grant's own pod and lifetime, including after its turn has
ended. For proposals the currency check below stops it. For reads, expiry bounds it.

### Currency: the epoch, ended turns and revoked turns

Before deciding a `tools/call` of a `propose` tool under the profile for Otto's sandboxes, the
Otto adapter asks Otto's resolver interface
([decision 0003](0003-otto-keeps-its-control-plane-endpoints.md)) one question: is this turn
(session, execution, turn and epoch) current? Otto answers current, superseded (a newer epoch
holds the lease), ended, or revoked. The answer is not cached. No answer within a fixed
budget, proposed at one second, an error, an unknown version, or an answer to another
question counts as unconfirmed, and the call is denied, as 0003 requires.

Otto answers from its durable state: the lease row's holder and epoch, compared on the
database's clock as Otto's own fencing does, and the turn's recorded state. A superseded
control plane that is still running must not be able to say its own turns are current. This
gateway cannot tell a right answer from a wrong one, so that is Otto's guarantee, tested in
Otto.

The check is made once, before the call runs. A failover during a proposal does not stop it,
so two control planes driving one session are made unlikely to propose twice, not prevented
from it. The receipts and idempotency keys in Q10 cover that window.

Reads and `tools/list` are not fenced. Otto's model broker already cuts a superseded control
plane's turns off from the model, so their remaining tool calls are ones the sandbox makes
itself. Reads give it nothing the turn did not already have, and end at expiry. Fencing reads
would put Otto's control plane on every read.

This departs from Otto's control-plane document twice, and Otto has to agree. That document
says grant enforcement makes no call to Otto on the ordinary tool path; this makes one on every
proposal. It says the gateway fences a superseded control plane; this fences its proposals
only.

The same question lets Otto stop one turn at once: it marks the turn revoked, and the next
proposal is denied.

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
would deny before the function runs, a second place that decides, which 0006 allows only for a
connector's refusal. Amendments to 0006:

- **The call context** gains the call's currency: current, not current (superseded, ended or
  revoked), unconfirmed, or not asked. The Otto adapter asks only when the snapshot's tool is
  `propose` and the profile requires currency. An adapter that fails to ask leaves "not
  asked", which is denied.
- **A profile** gains a setting: `propose` requires a current control plane. The profile for
  Otto's sandboxes sets it.
- **A new check between 5 and 6:** under such a profile, a `propose` call is allowed only if
  its currency is current. The check is skipped for `tools/list`, like check 6.
- **Two new reason kinds,** not current and unconfirmed, each with its sentence. The row
  records which answer Otto gave.
- **The delegation** gains its issuer, digest and key ID, and the principal gains the pod UID
  for a Kubernetes workload. The function reads none of these. The audit record keeps them.

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
`destructive` tool is still denied, naming the classification. Every write Otto serves at
`752395a` is `propose` under the amendment, so the currency check covers all of them, and the
adapter records them as `write` in `gateway_audit`.

The grant does not bind resources. A turn's calls are limited by the team's resource limits
(check 6) and the connectors' own scope checks, as in Otto. Each row records the resources its
call named, where the tool could say before it ran; a tool that checks its own scope records
`unknown`, and a row keeps at most 64. A per-turn resource list would need Otto to know at mint
time every repository a turn may touch, and connectors that narrow by it.

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
`propose` tool while `pod` is not required for its issuer. The last holds the pod binding in
place once writes move. If the owner confirms it, it also refuses to start with grant checking
turned off outside a development build.

### Revocation

| Lever | Stops | Takes effect |
| --- | --- | --- |
| Otto marks a turn revoked. | That turn's proposals. | On its next proposal. |
| Otto's lease moves to a new epoch. | Proposals of every turn of the superseded control plane. | On each turn's next proposal. |
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

Before stage 3:

5. Mint `pod`, if it was not in the first change.
6. Answer the currency question on the resolver interface within the budget, from the lease
   row and the turn's recorded state, and record turns as ended or revoked.

Decision 0003 already asks Otto for the resolver interface and for its control-plane endpoints
to run outside the Go gateway. This adds one question to that interface. None of it has been
raised with Otto yet.

### Tests

The adapter's tests are company-wide behavior, in their own group apart from the baseline, as
Q8 requires, and each guard gets a mutation in `scripts/mutation_check.py`. The groups are
replay, use at another deployment and from another pod, format and forgery (including
non-canonical encodings), clock skew at the leeway and the ceiling, key rotation across a
restart, each boot refusal, each currency answer against a read and a proposal, revocation, and
composition with the tool list. One property holds throughout: under a profile that requires
currency, a `propose` call is never allowed unless current. That the answer comes from the
lease row is tested in Otto. The cases go in [design.md](../design.md), section 18, and issue
#22. The conformance suite changes only when it is re-pinned to Otto's new format.

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
- **Caching currency answers.** A superseded turn's proposals would pass for as long as the
  cache lived.
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

- Milestone 4 needs one breaking change in Otto before stage 1, and up to two additions before
  stage 3. Stage 3 is not ready until the pod binding and the currency check are live,
  alongside the receipts from Q10.
- Decision 0004's open paragraph is answered and its requirement stands: Otto's cutover waits
  for the asymmetric signature. Its drain consequence changes: the format change is made
  alone, before stage 1, and Otto's Go gateway verifies the new format.
- From stage 3, every Otto proposal through this gateway depends on Otto's resolver and fails
  closed when it does not answer. Decision 0003 accepted that for some Otto tools; it is now
  true of all of Otto's writes. No other caller is affected.
- Decision 0006 is amended as above, with table cases and mutations for each change.
- This gateway's audit record gains the grant digest, issuer, key ID, pod UID and currency
  answer. Otto's `gateway_audit` has `session_id`, `turn_id` and `fencing_epoch` and no column
  for these, so they are kept only here unless Otto adds them, as with resources.
- The Kubernetes identity verifier exposes the pod UID its token proves.
- Stage 1 copies verify here only if they carry the sandbox's own identity token and grant,
  with that token's audience admitting this gateway. How copies are made is #13.
- If the owner confirms it, grant checking can be turned off only in a development build,
  which settles that part of Q12 for this gate. Otherwise it stays with Q12.
- The control plane is still trusted for whom it names. A grant proves that Otto said who the
  turn was for, not that the person acted.
- Verification is offline, so a deleted pod's token and grant verify until they expire or a
  wider lever is used.
- Left for later, and what brings each back: fencing reads, once Otto enables a blue/green
  control-plane swap in production or local execution in sandboxes while this gateway serves
  its reads; resources in the grant, once Otto needs a turn narrowed below its team's
  resources; single use or a replay cache, once Otto mints a grant per call or a write turns up
  that the receipts in Q10 do not protect; this gateway's tool names in the grant, once the Go
  gateway's MCP path is retired; facts fixed for the turn, such as skill pins, once
  `github_skill_body` is built (#12), choosing then between a claim and the resolver as 0003
  says.
- Until Otto agrees, this record is a proposal, and the three "agree with Otto" criteria in
  issue #21 stay open.

## Needs the owner

- Who takes the Otto change list to Otto's owners, and whether Otto's schedule fits
  milestone 4. Nothing has been raised in Otto yet.
- Whether Otto accepts the breaking change before stage 1, rather than with the cutover as
  decision 0004 had it, which means its Go gateway verifies Ed25519 too.
- Whether Otto can mint `pod` in the first change, and confirms that the harness cannot read
  the pod's projected token. If not in the first change, whether copied grants usable for reads
  within a team, recorded but not refused, are acceptable until stage 3.
- The lifetime ceiling (15 minutes) and leeway (30 seconds), agreed with Otto. The ceiling has
  to grow with Otto's timeouts.
- The resolver's budget (one second) and availability target, and who is paged when it fails.
- Whether reads stay unfenced, and whether Otto plans a blue/green swap in production or local
  execution in sandboxes during milestone 4. Otto's agreement to the two departures from its
  control-plane document.
- Whether control-plane components that act under the lease send their epoch and are fenced,
  or duplicate control-plane effects stay with Otto's row claims and the receipts in Q10.
- Who may revoke a turn in Otto, remove a key here, or remove a team from the allowlist of
  Otto's sandbox surface, and how fast configuration must reach running instances (Q11).
- Where Otto's private key is held, and whether that needs IT or security. Who reviews a key
  change here, and the rotation schedule.
- Who names this gateway's deployments, given that the names are in Otto's grants.
- Whether an audience or pod failure pages someone, and whom, and what rate of lifetime
  failures alerts.
- Whether Otto adds columns to `gateway_audit` for the new fields or reads them from this
  gateway's record, and whether Otto records each grant's digest at mint.
- Whether the digest replaces the unique-identifier claim that issue #21 asks for.
- Whether grant checking is off only in development builds, enforced at boot, or that is left
  to Q12.
- Whether the stage 1 copies (#13) can carry the sandbox's own identity token and grant, with
  that token's audience admitting this gateway.
