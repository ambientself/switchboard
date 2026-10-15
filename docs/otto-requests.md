# What this project asks of Otto's owners

Date: 2026-10-13. This is the one list of everything this project asks of Otto's owners. This
project's owner takes it to them, as the owner said on 2026-10-13. Nothing on it has been raised
with Otto's owners before, and nothing on it has been agreed.

## Switchboard, and the cutover

Switchboard is Org's company-wide MCP gateway, written in Rust in this repository. Every agent
in the company is to reach its tools through it: it proves who is calling, decides whether the
call is allowed, attaches the vendor credential on the server side, and writes an audit row
before it answers. Otto is one of its callers. [Decision 0002][0002] has Switchboard replace
Otto's Go MCP gateway as Otto's MCP path. Otto keeps everything else, listed under
[What Otto keeps](#what-otto-keeps) at the end.

The cutover is made in three stages ([decision 0002][0002-reaffirmed] and issue #13):

1. **Stage 1, alongside and compared.** Otto's Go gateway still serves every call. Switchboard
   receives copies of Otto's real read calls, and its answers and audit rows are compared with
   the Go gateway's. Reads only, because a copied write would act twice.
2. **Stage 2, reads.** A turn's read tools are served by Switchboard. Its writes still go to the
   Go gateway.
3. **Stage 3, writes.** The writes move too. After that the Go gateway's MCP path is retired.

At every stage each tool is served by exactly one gateway, so no call has two paths, and a
rollback switches the active path without leaving both enabled for a tool (#13).

**This is the whole list.** It gathers every request of Otto's owners in this project's decision
records, its design and its open questions. [Decision 0012][0012-owner] said they would reach
Otto's owners as one list rather than piecemeal. A request that is not on this page has not
been made.

Until Otto's owners answer, this project builds and tests its Otto adapter against a local
grant minter and a fake resolver, Otto's Go gateway keeps serving Otto, and stage 1 does not
start until Otto's grant-format change has been rolled out ([decision 0012][0012-open]).

Each request below says what is asked, why, and what Switchboard does until it is answered. It
is marked as a **change**, which is work in Otto, or a **question**, which needs an answer from
Otto's owners. Some are both. Where the sources name no stage for a request, the request says
where it is listed and why.

## Words used here

- **Turn grant:** the signed statement Otto's control plane mints for each turn and the sandbox
  sends on every MCP request in `X-Otto-Turn-Grant`. Today it names the session, turn,
  execution, team, acting human, fencing epoch, expiry and the turn's tools, and is signed with
  a shared secret (an HMAC).
- **Classification:** each tool is `read`, `propose`, `write` or `destructive`. A `propose` tool
  changes only what the gateway itself created, and nothing it creates takes effect until a
  person acts, such as a draft pull request. Switchboard denies `write` and `destructive` tools
  in every profile, except a tool named in a recorded exception ([decision 0011][0011-s9]).
- **Side-effecting call:** a call of any tool not classified `read`.
- **The resolver:** an interface Otto exposes so that Switchboard can ask it facts that only
  Otto knows and that can change during a turn ([decision 0003][0003-decision]). When Otto does
  not answer, Switchboard refuses the call.
- **Currency:** whether Otto says a turn is still current: its control plane still holds the
  lease, and the turn has not ended or been revoked ([decision 0012][0012-currency]).
- **Receipt:** Switchboard's record of a side effect, found by a key the caller sends with each
  request. It is what stops Switchboard making the same side effect twice
  ([decision 0009][0009-key]).
- **Policy snapshot:** the reviewed policy files Switchboard loads: tools, classifications,
  which callers see which tools, and each team's resource limits.
- **Surface and profile:** a surface is the named set of tools one endpoint serves, to the
  callers its allowlist admits. A profile is the policy that applies to one kind of caller,
  such as Otto's sandboxes or Otto's control plane.
- **The only path and the governed path:** the two claims an environment can make about
  routes around the gateway. The only path means an agent can act on a target system with
  Org's authority only through Switchboard. The governed path means Switchboard is the route
  the environment is set up to use, and every other known route is listed in a register,
  [route-exceptions.md](route-exceptions.md), with an owner ([decision 0010][0010-claims]).

## The list at a glance

| # | Request | Kind | Needed before |
| --- | --- | --- | --- |
| 1 | Agree to this list, and say whether Otto's schedule fits | Question | Stage 1 |
| 2 | Sign turn grants with Ed25519, alone, before stage 1 | Change | Stage 1 |
| 3 | Mint `aud` and `iat`, and refuse lifetimes over 15 minutes | Change and question | Stage 1 |
| 4 | Where the signing key is held, and how it rotates | Question | Stage 1 |
| 5 | Stage 1's copies carry the sandbox's own token and grant | Question | Stage 1 |
| 6 | Review the declarations for Otto's eighteen tools | Question | Any Otto tool served |
| 7 | Each team's repositories move into the policy snapshot | Question | Any Otto tool served |
| 8 | Check the proposal tools against the interim automation refusals | Question | Any Otto tool served |
| 9 | Freeze Otto's gateway behavior for an agreed period | Question | Stage 2 |
| 10 | Reconfigure Otto to call Switchboard, stage by stage | Change | Stage 2, and stage 3 |
| 11 | How skill pins reach Switchboard | Change and question | `github_skill_body` is built |
| 12 | Blue/green plans, and two departures from Otto's control-plane document | Question | Stage 2 |
| 13 | Mint `pod`, and say whether the harness can read the pod's token | Change and question | Stage 3 |
| 14 | The resolver interface, with the currency question | Change | Stage 3 |
| 15 | The resolver's availability target | Question | Stage 3 |
| 16 | Otto's idempotency key | Change and question | Stage 3 |
| 17 | Never repeat what may already have happened | Change and question | Stage 3 |
| 18 | Parity differences for side effects | Question | Stage 3 |
| 19 | Control-plane endpoints outside the Go gateway, and their vendor actions | Change | The stage that moves those actions |
| 20 | Parity differences for identity failures, audit outages and open rows | Question | Not blocking |
| 21 | New columns in `gateway_audit` | Question | Not blocking |
| 22 | The egress proxy refuses target systems' hosts | Change and question | Not blocking |
| 23 | `make egress-check` gains rows for those hosts | Change and question | Not blocking |
| 24 | The sandbox's Pod Identity association | Change or question | Not blocking |
| 25 | Mint `egress`, the turn's egress setting | Change | Not blocking |
| 26 | Own or share the register entries for Otto | Question | Not blocking |
| 27 | Whether lease-holding components send their epoch | Question | Not blocking |
| 28 | Who in Otto may mark a turn revoked | Question | Not blocking |
| 29 | Mint a renamed deployment first | Question | Not blocking |

## Before stage 1

### 1. Agree to this list, and say whether Otto's schedule fits

*Question.*

- **Asked:** whether Otto's owners agree to the changes on this page, and whether Otto's
  schedule fits this project's milestone 4, which brings Otto over.
- **Why:** every change here is a request until Otto agrees, and stage 1 cannot start without
  the first of them, request 2 ([decision 0012, Still open][0012-open]).
- **Meanwhile:** the Otto adapter is built and tested against a local grant minter and a fake
  resolver, and Otto's Go gateway keeps serving Otto.

### 2. Sign turn grants with Ed25519, alone, before stage 1

*Change.*

- **Asked:** sign turn grants with an Ed25519 key in place of the shared secret, and have
  Otto's Go gateway verify the new format too. Make the change once, alone, before stage 1.
- **Details:**
  - A new format version that is neither `v1` nor the model broker's `v2`, with its own domain
    prefix.
  - A key ID derived from the public key, and a separate key in each environment, none of them
    the model broker's.
  - Each part encoded as canonical unpadded base64url, and a canonical signature, which the Go
    gateway checks by the same strict rules. Whether it also checks `aud` (request 3) is
    Otto's choice.
  - Otto's own procedure for a breaking grant change: stop admitting turns, drain, roll the
    control plane, the Go gateway and the sandbox image together, and resume. There is no
    interim with the shared secret.
  - The exact format, version `v3`, is in [turn-grant-format.md](turn-grant-format.md): the
    byte layout, the domain prefixes, the key ID's derivation, the claims and their types, the
    strict verification rules and their order, and a worked example to test a minter against.
    It covers request 3's `aud` and `iat` too.
- **Why:** with a shared secret, anything that verifies a grant can also mint one, so a
  company-wide gateway, or whoever compromised it, could write any human's name on any Otto
  action ([decision 0004][0004-decision]). Before stage 1, so that stage 1's comparison
  verifies real grants ([decision 0012, What Otto changes][0012-changes]).
- **Sources:** decision 0004 first had the change made with the cutover. Decision 0012 moved it
  before stage 1 on 2026-10-07, and this list follows 0012.
- **Meanwhile:** Switchboard never accepts a `v1` grant, so the conformance suite cannot run
  against Switchboard until it is re-pinned to the new format. Stage 1 does not start.

### 3. Mint `aud` and `iat`, and refuse lifetimes over 15 minutes

*Change, in the same breaking change as request 2, and a question about the limits.*

- **Asked:** mint `aud`, the gateway deployments the grant is for, and `iat`, the time of
  minting, beside `exp`, and have the minter refuse a lifetime over 15 minutes. Agree the
  limits: a 15-minute ceiling on `exp − iat`, and 30 seconds of clock leeway.
- **Details:**
  - During the cutover `aud` names the Go gateway and Switchboard's Otto deployment; after the
    last stage, Switchboard's alone. Switchboard names its own deployments in its
    configuration.
  - Refusing at the minter makes the failure show in the control plane, not on the turn.
  - Tell this project before Otto raises its turn or execution timeouts past the ceiling, so
    that the ceiling is raised here first.
- **Why:** a public key can be configured anywhere, so the grant must name the gateways it is
  for, and checking only that expiry is within 15 minutes of now would accept a grant minted
  to last a year, in its final 15 minutes
  ([decision 0012, What the grant carries][0012-carries]).
- **Meanwhile:** Switchboard applies the ceiling and the leeway to every grant it verifies.

### 4. Where the signing key is held, and how it rotates

*Question.*

- **Asked:** where Otto's private grant key is held (a mounted Secret as today, a signer like
  Otto's GitHub App custodian, or KMS or an HSM), whether that needs IT, and the rotation
  schedule.
- **Why:** the private key is the issuer. Switchboard holds only public keys, read at boot, and
  never fetches a key from Otto, because whoever controlled that endpoint could add a key
  ([decision 0012, Keys][0012-keys]).
- **When:** the sources name no stage. It is listed here because the key is first used by
  request 2.
- **Meanwhile:** a grant-key change in Switchboard gets the ordinary review. It rotates by
  adding the new public key here and rolling it out; Otto then signs with the new key, and once
  one lifetime ceiling has passed, the old key's end instant passes and it is removed. Whether
  a key change needs more review is for the security team, not Otto.

### 5. Stage 1's copies carry the sandbox's own token and grant

*Question, for the stage 1 rollout plan (#13).*

- **Asked:** the copies of read calls that Switchboard receives in stage 1 carry the sandbox's
  own identity token and turn grant, and the audience of that identity token admits
  Switchboard. Otto's owners decide the token's audience.
- **Why:** a copy verifies here only if it carries the sandbox's own token and grant
  ([decision 0012, Consequences][0012-consequences]).
- **Meanwhile:** stage 1 does not start.

## Before Switchboard serves any of Otto's tools

Decision 0011 asks for these three before milestone 4, and until they are answered Switchboard
serves none of Otto's tools. In stage 1 Switchboard answers copies of Otto's reads, though only
for the comparison: its answers do not reach Otto. That still needs these three, so they come
before stage 1 as well.

### 6. Review the declarations for Otto's eighteen tools

*Question: a review by Otto's owners.*

- **Asked:** review, in this repository, how Switchboard declares each of Otto's eighteen tools:
  its classification, how it finds the resources a call names, and the credential it uses.
  Thirteen are `read`. Of Otto's five writes, `github_create_pr`, `github_propose_change` and
  `github_amend_change` are `propose`. `github_pr_comment` and `jira_comment` comment on things
  the gateway did not create, so they are `write`, allowed only to Otto's sandboxes under a
  narrow recorded exception once it is in force, and only while Otto says the turn is current.
  In `gateway_audit` all five are still recorded as `write`, since its classification column
  has no `propose`.
- **Why:** the declarations are approved by people, and much of what the gateway guarantees
  rests on that review ([decision 0011, Still open][0011-open] and [section 9][0011-s9]).
- **Meanwhile:** Switchboard serves none of Otto's tools.

### 7. Each team's repositories move into the policy snapshot

*Question: agreement.*

- **Asked:** agree that each team's repositories move from Otto's team manifest into
  Switchboard's policy snapshot, as that team's resource limit, when the Otto adapter is built.
- **Why:** every later check takes its limits from the snapshot in force, so a team's
  repositories have to be in it ([decision 0011, Consequences][0011-consequences]).
- **Meanwhile:** Switchboard serves none of Otto's tools.

### 8. Check the proposal tools against the interim automation refusals

*Question: a check by Otto's owners.*

- **Asked:** check that Otto's three proposal tools still serve Otto's users when, as served by
  Switchboard, they refuse changes to CI workflow files and to Atlantis configuration, as well
  as Atlantis command text. These refusals hold until the owners of Atlantis, CI and Jira
  automation say which automation makes a proposal take effect on its own. The same check
  covers one difference already decided: `github_create_pr` always opens a draft, and Otto's
  `CreateReadyPRs` setting is not carried over, because a tool with such a setting is `write`
  ([design.md, section 8](design.md#8-policy)).
- **Why:** a tool is `propose` only if nothing it creates takes effect before a person acts, and
  a workflow or Atlantis change on a proposal branch can
  ([decision 0011, Still open][0011-open]).
- **Meanwhile:** Switchboard serves none of Otto's tools.

## Before stage 2

### 9. Freeze Otto's gateway behavior for an agreed period

*Question.*

- **Asked:** before the cutover, freeze the behavior of Otto's Go gateway for an agreed period.
  Parity is declared against the Otto commit at the start of the freeze, with the conformance
  suite passing against both gateways.
- **Why:** Otto's gateway changes often (fifty-five commits touched it between the first two
  pins), and parity needs a fixed target ([design.md, section 18](design.md#18-testing); #13).
- **When:** the design says only "before cutover". It is listed here because stage 2 is the
  first stage in which Switchboard's answers reach Otto.
- **Meanwhile:** the suite is re-pinned to Otto on a schedule, and the failures at each re-pin
  are the list of what changed in Otto.

### 10. Reconfigure Otto to call Switchboard, stage by stage

*Change.*

- **Asked:** reconfigure Otto to call Switchboard directly: its reads in stage 2, its writes in
  stage 3. How stage 2 splits a turn's calls by tool, two MCP servers in the harness's
  configuration or a proxy in the pod, is chosen in the rollout plan (#13). Endpoint and tool
  name changes are mapped explicitly, one name to one name, in the conformance suite and in
  Otto's migration configuration.
- **Why:** Switchboard replaces Otto's MCP path, and the mappings must not weaken what the
  conformance suite asserts ([decision 0002][0002-decision]; [decision 0012, Tools and
  resources][0012-tools]).
- **Meanwhile:** Otto's Go gateway serves every Otto call.

### 11. How skill pins reach Switchboard

*Change and question: either answer is work in Otto.*

- **Asked:** which skills a turn pinned, and at which commit, is a fact only Otto knows. Agree
  how it reaches Switchboard: as a signed claim in the turn grant, or as a question on the
  resolver (request 14).
- **Why:** a fact fixed for the turn reaches Switchboard in one of those two ways, chosen per
  fact when the tool that needs it is built ([decision 0003][0003-decision];
  [decision 0012, Consequences][0012-consequences]).
- **When:** the sources tie this to building `github_skill_body`, not to a stage. That tool is
  a read, so it moves in stage 2, and it is listed here. Until it is built, Switchboard answers
  no call of it, not even a stage 1 copy.
- **Meanwhile:** nothing is chosen yet, and `github_skill_body` waits on the choice.

### 12. Blue/green plans, and two departures from Otto's control-plane document

*Question.*

- **Asked:** whether Otto plans a blue/green control-plane swap in production, or local
  execution in sandboxes, during milestone 4. Also agree two departures from Otto's
  control-plane document:
  - It says grant enforcement makes no call to Otto on the ordinary tool path. From stage 3,
    Switchboard asks the currency question (request 14) on every side-effecting call.
  - It says the gateway fences a superseded control plane. Switchboard fences only that control
    plane's side-effecting calls, not its reads.
- **Why:** fencing reads would put Otto's control plane on every read, and Otto's model broker
  already cuts a superseded control plane's turns off from the model
  ([decision 0012, Currency][0012-currency]).
- **When:** the sources name no stage. Reads stay unfenced until Otto enables either plan while
  Switchboard serves its reads ([decision 0012, Decided by the owner][0012-decided]), and
  Switchboard serves them from stage 2. So this is listed before stage 2, though the first
  departure takes effect only in stage 3.
- **Meanwhile:** reads are not fenced. If either plan is made, fencing reads comes back.

## Before stage 3

### 13. Mint `pod`, and say whether the harness can read the pod's token

*Change, and a question.*

- **Asked:** mint `pod`, the UID of the sandbox pod that runs the turn. Otto has already claimed
  the sandbox when it mints; what it adds is resolving that sandbox to its pod's UID before
  minting, and refusing the turn when it cannot. This is asked for in the first change
  (request 2) if Otto can do it then, and is required before stage 3. Also say whether the
  harness can read the pod's projected service account token.
- **Why:** without it, any sandbox of the grant's team can present a copied grant until it
  expires. From stage 3 that would make proposals in the acting human's name, and Otto's rule
  that a requester may not approve their own change depends on that name. The binding stops a
  copied grant only while the harness cannot also read the pod's token
  ([decision 0012, What the grant carries][0012-carries]).
- **Meanwhile:** `pod` is not required. A copied grant used for reads is recorded with the pod
  that presented it, a gap the owner accepted for stages 1 and 2. Switchboard refuses to start,
  or to load a snapshot, that would serve a tool not classified `read` to Otto's sandboxes while
  `pod` is not required.

### 14. The resolver interface, with the currency question

*Change.*

- **Asked:** expose a versioned resolver interface that states what Switchboard does when Otto
  does not answer: it refuses the call. Its first question is currency: is this turn (session,
  execution, turn and epoch) current? It also answers whether a pull request is one of Otto's
  own proposals, which `github_amend_change` needs.
- **Details:**
  - Otto answers current, superseded (a newer epoch holds the lease), ended, or revoked, within
    one second.
  - It answers from durable state: the lease row's holder and epoch, compared on the database's
    clock as Otto's own fencing does, and the turn's recorded state. So Otto records turns as
    ended or revoked.
  - A superseded control plane that is still running must not be able to say its own turns are
    current. That is Otto's guarantee, tested in Otto.
  - The proposed wire format is [resolver-interface.md](resolver-interface.md): the request and
    its answer, how an answer echoes its question, how Switchboard authenticates to Otto, the
    one-second budget, and what Switchboard does with no answer. Otto's owners can implement it
    or answer it.
- **Why:** Switchboard does not read Otto's tables ([decision 0003][0003-decision]). The
  currency question enforces the fencing epoch, which today is signed and recorded but compared
  with nothing, and lets Otto stop one turn at once
  ([decision 0012, Currency][0012-currency]).
- **Sources:** issue #13 lists the resolver among Otto's readiness for the cutover without
  naming a stage. Decision 0012, written later, puts the currency answer before stage 3, and
  this list follows it.
- **Meanwhile:** Switchboard is tested against a fake resolver and calls no real one before
  stage 3. From stage 3, a side-effecting call is denied when Otto does not answer, the answer
  is not cached, and reads are not fenced (request 12).

### 15. The resolver's availability target

*Question.*

- **Asked:** the availability target Otto sets for the resolver.
- **Why:** from stage 3 every side-effecting Otto call through Switchboard depends on it and
  fails closed without it ([decision 0012, Still open][0012-open]). Who is paged when it fails
  is for the on-call rotation that will carry it, not for this list.
- **Meanwhile:** nothing calls the resolver before stage 3. From stage 3 a side-effecting call
  is denied when the resolver does not answer within one second, and reads keep working.

### 16. Otto's idempotency key

*Change and question.*

- **Asked:** agree the key sent with each side effect, which lets Switchboard's receipts tell a
  resend from a new call: the carrier Otto's control plane uses for the actions it asks for,
  whether the tool-use identifier Otto's gateway stores today is Otto's key, and which grant
  fields scope a key. The session and the turn are recommended.
- **Details:**
  - The carriers are the caller's tool-use identifier, a named `_meta` field for callers that
    are not models, or a header from a profile that declares its callers set it per request.
  - Also say whether a turn is unique only within an execution, so that the scope needs the
    execution too, and whether the control plane can send a key that stays the same when it
    replays a turn.
  - And say how the control plane's read-back of audit rows by tool-use identifier treats the
    extra rows (a `duplicate`, or a refusal for reuse) that share the original call's
    identifier.
- **Why:** Otto's gateway makes the same comment twice when asked twice, even with the same
  `Idempotency-Key` header. Receipts stop that for a resend of the same call, and cover a turn
  replayed after a failover only if the key survives the replay
  ([decision 0009, The key][0009-key] and [Still open 8][0009-open]).
- **Meanwhile:** Otto's callers make every side effect through Otto's Go gateway. The cutover of
  writes waits for this answer.

### 17. Never repeat what may already have happened

*Change, and a question.*

- **Asked:** Otto's control plane sends a stable key, in the agreed carrier (request 16), for
  every action it asks Switchboard for. It treats both "may already have happened" in an answer
  and an empty outcome on a row it reads back as an instruction not to repeat the action. Agree
  how it learns that such an action was later settled.
- **Why:** a side effect whose outcome is unknown is never presented as safe to repeat, and
  Switchboard never repeats a tool call on its own ([decision 0009, Consequences][0009-cons]).
- **When:** the sources tie this to building the adapter, not to a stage. It is listed here
  because it governs side effects, which move in stage 3.
- **Meanwhile:** writes stay on Otto's Go gateway.

### 18. Parity differences for side effects

*Question: agreement, when the adapter is built.*

- **Asked:** agree these differences from Otto's gateway. `gateway_audit` has no `unknown`, no
  `duplicate` and no deadline, so the adapter writes an empty outcome for `unknown`, never
  `error`, and `ok` for `duplicate`, since the effect exists. A side effect is no longer
  cancelled when the client disconnects. The conformance suite's test that a repeated comment
  is written twice, `TestRepeatedCommentIsWrittenTwice` in this repository, fails on purpose
  once receipts are on for Otto's profile, and moves to the group of expected differences.
- **Why:** these follow from receipts and from never cancelling a side effect midway
  ([decision 0009, Consequences][0009-cons]).
- **When:** the sources say "when the adapter is built", not a stage. It is listed here because
  every difference in it concerns side effects, which move in stage 3.
- **Meanwhile:** writes stay on Otto's Go gateway, so none of these differences reaches Otto.

### 19. Control-plane endpoints outside the Go gateway, and their vendor actions

*Change.*

- **Asked:** keep `/repo-config`, `/pr-receipt` and `/pr-outcome`, and the proposed Jira inbox
  and answer endpoints, running outside Otto's Go gateway. When one needs something done in a
  vendor system, Otto's control plane asks Switchboard, on a surface only named Otto
  control-plane workloads may use. The actions, such as reading a file at a commit, reading a
  pull request's state, and posting or editing a comment on a pull request, are designed with
  Otto when the adapter is built, each classified `read` or `propose`. A comment is `propose`
  only on something the gateway created, such as the pull request carrying Otto's receipt.
- **Why:** Otto's own rule is that a second holder of a vendor credential is a second path
  around the gateway, so Otto's control plane never holds the credential for these actions
  ([decision 0003][0003-decision] and [its consequences][0003-consequences]).
- **When:** the records tie this to the cutover stage that moves the control plane's vendor
  actions, without naming it ([decision 0010, Per environment][0010-env]). It is listed here
  because `/pr-receipt` writes to GitHub, and writes move in stage 3.
- **Meanwhile:** the endpoints stay where they are, with the credential they use today.

## Asked, but not blocking

### 20. Parity differences for identity failures, audit outages and open rows

*Question: an answer, and agreement when the adapter is built.*

- **Asked:** whether Otto's adapter should still write identity failures, `initialize` and
  `ping` into `gateway_audit`, as Otto's gateway does today. Also agree two differences:
  - During an audit outage, a refused identity (HTTP 401) keeps the one opaque identity
    sentence. Otto's gateway replaces it with its audit-failure sentence.
  - Open rows, calls whose outcome the gateway never learned, are found from Switchboard's own
    record, since `gateway_audit` has no deadline column to tell them from calls in flight.
- **Why:** Switchboard records identity failures, `initialize` and `ping` as telemetry, not
  audit rows, so an identity failure writes no row and has no audit failure to report.
  Unverifiable grants and `tools/list` stay audit rows ([decision 0009, Still open 2][0009-open]
  and [Consequences][0009-cons]).
- **When:** the sources say "when the adapter is built", not a stage. Unlike request 18, it is
  listed as not blocking: Switchboard's own record does not depend on the answer, which decides
  only what Otto's adapter also writes to `gateway_audit` and whether Otto accepts the two
  differences. If Otto's owners want it settled before stage 1's comparison, it can move up.
- **Meanwhile:** Switchboard writes no row for them, and these are recorded parity differences.
  They apply to reads as well as writes, so they first show in stage 1's comparison and reach
  Otto from stage 2.

### 21. New columns in `gateway_audit`

*Question.*

- **Asked:** whether `gateway_audit` gains columns for what Switchboard records and the table
  cannot hold, and who adds them: the resources a call names, the credential identity used and
  the error kind; and the grant's digest, issuer, key ID, pod UID, egress setting and currency
  answer. Otto may instead read these from Switchboard's own record. Also say whether Otto
  records each grant's digest when it mints. A new column would be typed and bounded in bytes,
  as Otto's own rules for the table require.
- **Why:** the table's contract is a compatibility requirement, so only Otto's owners can change
  it ([decision 0014, section 10][0014-s10]; [decision 0012, Still open][0012-open];
  [open questions, Otto's audit table][q18]).
  Decision 0011 first put the first three columns in a question about operational controls;
  decision 0014 moved them here.
- **Meanwhile:** these fields are kept only in Switchboard's record, and Otto joins on the
  session and turn.

### 22. The egress proxy refuses target systems' hosts

*Change, and a question.*

- **Asked:** have Otto's egress proxy refuse every host that accepts a target system's
  credential, by resolved address as well as by name, which Otto's own egress record, its
  ADR-0010, already says the list should cover. Decide what to do about `github.com` and AWS,
  which serve toolchains and also accept credentials: refusing them breaks fetches, and
  allowing them leaves a route.
- **Why:** today a turn with egress open can reach every target system's hosts through the
  proxy, by their own names or by any name that resolves to them
  ([decision 0010, Still open][0010-open]; [the register](route-exceptions.md)).
- **Meanwhile:** every Otto turn has the governed path, and the register entry for the proxy is
  held by this project and not yet accepted.

### 23. `make egress-check` gains rows for those hosts

*Change, and a question.*

- **Asked:** add to `make egress-check`, run from a real sandbox, a refused row for each host
  that accepts a target system's credential, by name and by a name that resolves to each
  address, and one for the Pod Identity endpoint, with this project's credential checks run
  beside it from outside the sandbox. Whether its probe moves to an ephemeral
  container, so that it needs neither `pods/exec` nor the agent's image, is Otto's call.
- **Why:** a sealed turn can claim the only path only with dated evidence that each such route
  is refused ([decision 0010, Per environment][0010-env] and [The route check][0010-check]).
- **Meanwhile:** no Otto turn has the only path.

### 24. The sandbox's Pod Identity association

*Change, or a question.*

- **Asked:** remove the sandbox's unused EKS Pod Identity association and the network policy
  rule that opens its endpoint. If Otto keeps them, the register needs evidence from outside
  the sandbox: the role's policies, and a permissions boundary or service control policy that
  explicitly denies everything.
- **Why:** AWS is a target system, and a sandbox that can obtain an AWS credential breaks the
  rule that nothing provisioned to an agent yields one
  ([decision 0010, Per environment][0010-env]).
- **Meanwhile:** the register entry for the sandbox's AWS identity is held by this project and
  not yet accepted.

### 25. Mint `egress`, the turn's egress setting

*Change.*

- **Asked:** mint `egress` in the turn grant: whether the turn is sealed or has egress open
  through Otto's proxy, from the same setting as the `PublicEgress` claim on the model-broker
  token so the two cannot disagree. It is asked for in the first change (request 2) if Otto can
  do it then. Otherwise Otto mints it later, and Switchboard then starts requiring it, with no
  second drain. A grant without it is read as egress open.
- **Why:** a sealed turn and a turn with egress open share an issuer, a deployment and often a
  subject, so only the grant can tell the audit row which it was
  ([decision 0012, What the grant carries][0012-carries]; [decision 0010][0010-env]).
- **Meanwhile:** rows record no egress setting, and every Otto turn has the governed path.

### 26. Own or share the register entries for Otto

*Question.*

- **Asked:** whether Otto's owners own the register entries for Otto's egress proxy, the
  sandbox's AWS identity and the credentials of Otto's conversation surfaces, such as its Slack
  app; and whether they share with this project the entries for Otto's Go gateway while it
  serves tools and for the exception that allows Otto's two comment tools.
- **Why:** every entry needs an owner, and these routes and that exception are Otto's
  ([decision 0010, The register][0010-register]; [decision 0011, section 9][0011-s9]).
- **Meanwhile:** this project owns them. Acceptance stays with this project's owner, with the
  signature of a security owner the security team has yet to name.

### 27. Whether lease-holding components send their epoch

*Question.*

- **Asked:** whether a control-plane component that acts under the lease, such as the poller
  that posts pull-request receipts, should send its epoch with the actions it asks Switchboard
  for, and be asked whether that epoch holds the lease.
- **Why:** turn currency cannot fence those actions, because receipts are posted after the turn
  has ended ([decision 0012, Currency][0012-currency]).
- **Meanwhile:** the profile for Otto's control-plane surface does not require currency, and
  duplicate control-plane effects stay with Otto's row claims and Switchboard's receipts.

### 28. Who in Otto may mark a turn revoked

*Question.*

- **Asked:** who in Otto may mark a turn revoked, so that its next side-effecting call is
  denied.
- **Why:** revocation is the one lever that stops a single turn
  ([decision 0012, Revocation][0012-revocation]).
- **Meanwhile:** until Otto answers the currency question, a turn is stopped only by wider
  levers: removing its team from Otto's sandbox surface or withdrawing Otto's surfaces, which
  take effect within the registry's delivery bound and one poll, or removing a grant key, which
  takes one rollout. Decision 0012 said each lever takes one rollout; decision 0013's later note
  set the bound for the first two, and this list follows it.

### 29. Mint a renamed deployment first

*Question.*

- **Asked:** agree the order for renaming a Switchboard deployment that `aud` names: Otto mints
  the new name first, then Switchboard renames.
- **Why:** deployment names become part of the wire contract once Otto mints them
  ([decision 0012, What the grant carries][0012-carries]).
- **Meanwhile:** a deployment named in Otto's `aud` is not renamed.

## What Otto keeps

The requests above are bounded. Otto keeps:

- **Its model broker,** which is already its own binary and needs nothing from this project
  ([decision 0002][0002-reaffirmed]).
- **Its control-plane endpoints,** `/repo-config`, `/pr-receipt` and `/pr-outcome`, and the
  proposed Jira endpoints, with their orchestration. Switchboard does not host them
  ([decision 0003][0003-decision]).
- **Its tables and state:** the pull-request proposal table, per-turn skill pins, the
  repo-config cache, the team manifest's member table and the lease table. Switchboard does not
  read Otto's tables; it asks the resolver ([decision 0003][0003-decision];
  [decision 0012, Alternatives rejected][0012-alternatives]).
- **`gateway_audit` and its contract.** Switchboard's adapter writes Otto's rows to it as they
  are defined today. Columns are added only if Otto's owners choose (request 21).
- **Its signing key.** Switchboard holds only public keys and never fetches one from Otto.
- **Its egress proxy and sandbox network settings.** This project does not run egress
  enforcement for Otto ([decision 0010, Alternatives rejected][0010-alternatives]).
- **The credentials for its conversation surfaces,** such as its Slack app, recorded in the
  register (request 26).
- **Its own duplicate protection for control-plane actions,** such as the receipt poller's
  row claims ([decision 0012, Currency][0012-currency]).

When Switchboard serves Otto's tools, the differences from today that this project knows of
are the ones named above: the new grant format and its checks (requests 2, 3 and 25); the
differences in requests 6, 8, 18 and 20; and the refusals that requests 13, 14 and 16 add by
stage 3: a grant presented from another pod, a side-effecting call whose turn Otto does not
confirm as current, a side-effecting call sent without a key, and a key reused with a
different tool-use identifier.

[0002]: decisions/0002-replace-ottos-mcp-gateway.md
[0002-decision]: decisions/0002-replace-ottos-mcp-gateway.md#decision
[0002-reaffirmed]: decisions/0002-replace-ottos-mcp-gateway.md#reaffirmed-2026-10-01
[0003-decision]: decisions/0003-otto-keeps-its-control-plane-endpoints.md#decision
[0003-consequences]: decisions/0003-otto-keeps-its-control-plane-endpoints.md#consequences
[0004-decision]: decisions/0004-verify-turn-grants-with-a-public-key.md#decision
[0009-key]: decisions/0009-audit-completion-receipts-and-recovery.md#the-key
[0009-cons]: decisions/0009-audit-completion-receipts-and-recovery.md#consequences
[0009-open]: decisions/0009-audit-completion-receipts-and-recovery.md#still-open
[0010-claims]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#two-claims
[0010-check]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#the-route-check
[0010-env]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#per-environment
[0010-register]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#the-register
[0010-open]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#still-open
[0010-alternatives]: decisions/0010-what-stops-an-agent-going-around-the-gateway.md#alternatives-rejected
[0011-s9]: decisions/0011-resource-authorization-and-tool-assurance.md#9-ottos-comment-tools-a-recorded-exception
[0011-consequences]: decisions/0011-resource-authorization-and-tool-assurance.md#consequences
[0011-open]: decisions/0011-resource-authorization-and-tool-assurance.md#still-open
[0012-carries]: decisions/0012-what-a-turn-grant-binds.md#what-the-grant-carries
[0012-currency]: decisions/0012-what-a-turn-grant-binds.md#currency-the-epoch-ended-turns-and-revoked-turns
[0012-tools]: decisions/0012-what-a-turn-grant-binds.md#tools-and-resources
[0012-keys]: decisions/0012-what-a-turn-grant-binds.md#keys
[0012-revocation]: decisions/0012-what-a-turn-grant-binds.md#revocation
[0012-changes]: decisions/0012-what-a-turn-grant-binds.md#what-otto-changes
[0012-alternatives]: decisions/0012-what-a-turn-grant-binds.md#alternatives-rejected
[0012-consequences]: decisions/0012-what-a-turn-grant-binds.md#consequences
[0012-decided]: decisions/0012-what-a-turn-grant-binds.md#decided-by-the-owner
[0012-owner]: decisions/0012-what-a-turn-grant-binds.md#still-for-the-owner
[0012-open]: decisions/0012-what-a-turn-grant-binds.md#still-open
[0014-s10]: decisions/0014-rollout-safeguards-and-audit-operations.md#10-ottos-audit-table
[q18]: open-questions.md#q18-what-do-ottos-owners-agree-for-turn-grants-and-who-asks-them
