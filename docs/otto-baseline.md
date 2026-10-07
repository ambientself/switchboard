# Observed Otto gateway behavior

Baseline: `ambientself/otto` commit `752395a2d93962ec734f0cc28bbb101c5805f3e8`, re-pinned on
2026-10-01 from `4ad4f69`. The repository was formerly named `agentrunner`, and an older local clone may still sit in a
directory of that name. The exported
commit excludes its working-tree changes. Build toolchain and disposable Postgres image are
pinned in [conformance/baseline.json](../conformance/baseline.json).

The [conformance suite](../conformance/README.md) passes against this binary with the race
detector, real Postgres, locally generated keys, a fake GitHub API and a fake Jira. Everything
in the first table below is asserted by a test. These findings describe Otto's gateway; they
do not settle Q9–Q13 and do not automatically become requirements for the company-wide
gateway. Otto is one caller of that gateway, and this baseline covers only Otto's contract.

## What the suite observes

| Area | Observed behavior | Consequence for Switchboard |
| --- | --- | --- |
| Protocol | Initialization always reports MCP `2025-06-18`, whatever version is requested. No session ID is issued. | A known compatibility point while supported clients are chosen in Q13. |
| Acting context | Every call must carry a signed turn grant in `X-Otto-Turn-Grant`. The five `X-Otto-*` headers are ignored when grants are verified, and are read only when grant checking is explicitly turned off. | The grant is Otto's delegation; other callers need no equivalent. |
| Missing grant | A call with no grant gets its own sentence, naming a control plane that predates grants as the likely cause. | Keep it distinct from a bad grant: it is an operator's rollout problem, not a probe. |
| Bad grant | Sixteen kinds of unverifiable grant all get one fixed sentence: wrong key, forged claims under a genuine signature, expired, no tools, no epoch, wrong version, oversized, a missing field. The audit row records the proved pod and team and nothing from the grant. | Do not record unverified claims as identity, and do not tell the caller which check failed. |
| Grant and pod disagree | A grant minted for a team other than the pod's proved team is refused, naming both teams. | Proved and delegated team must agree. |
| Per-turn tools | A served tool that the turn's grant does not list is refused, with the tool and classification on the row. `tools/list` still returns every served tool under a narrow grant. | The design narrows the list, deliberately. Whether Otto's callers rely on the full list is checked when Otto's adapter is built. |
| Identity failure | HTTP 401, one opaque sentence and a Bearer challenge, for eleven kinds of bad token. If the grant still verifies, the row keeps who the turn was for. | Preserve status, envelope and audit, not only the sentence. |
| Audit scope | `initialize`, `ping` and `tools/list` are audited, as well as `tools/call`. Accepted notifications return 202 with no row. Authenticated malformed JSON returns 400 with no row. | "One row per tool call" understates coverage; "no answer without a row" overstates it. Q10. |
| Scope refusals | A call naming another organization, a repository outside the team's, or a comment Atlantis could read as a command is refused by the connector. The row is `allowed` with outcome `refused`, and `refusal_reason` holds the sentence the caller read. No token is requested. | A refusal is a denial or a `refused` outcome. For proxied tools, [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md) settles it: a proxied tool never checks its own scope. |
| Argument errors | A malformed argument is `allowed` with outcome `error` and no refusal reason. | Keep refusals and errors distinguishable. |
| Tokens | Every token request names the team's repositories and a permission set; the gateway holds several tokens, one per permission set. The caller's own credentials never reach GitHub. | Narrow per call, where the vendor allows. |
| Key custody | The gateway holds no App key. It asks a separate custodian process over a Unix socket, and refuses to start if the old key variables are set. | Adopted for every vendor key in the design. |
| Pull requests | `github_create_pr` opens a draft. | A property of Otto's write shape, tied to Org's Atlantis. |
| Search | The caller's query is parenthesized, the organization qualifier appended, and the advanced search engine requested. | The scoping is in how the request is built. |
| Audit begin failure | Blocks execution and replaces the answer, including a 401, with one fixed sentence. | The stated exception to "no answer without a row". |
| Audit finish | The answer waits for the row to be finished: with a finishing write slowed to 0.3 seconds, the row is complete when the answer arrives. If finishing fails, the answer still succeeds, the write is made once, and the row keeps an empty outcome. | An empty outcome means no outcome was durably recorded. Never retry a write because of it. |
| Disconnect | A client that disconnects during a blocked vendor call still gets an `error` completion row. | Finish on a context separate from the request. |
| Repeated write | The same comment sent twice makes two writes and two rows. | No general deduplication. `github_propose_change` has its own idempotency key, which this suite does not exercise. |
| Tool-use identifier | The caller's `claudecode/toolUseId` is stored on the row. | Otto's control plane joins on it to read decisions back. |
| Identity disabled | Rows say `disabled`, never `failed` or a made-up proof. The fixture still answers. The real connector refuses every call and requests no token, since there is no proved team to scope one to. | Turning identity off must not hand out a live credential. |
| Boot | Refuses to start with identity, grant or audit unconfigured, partly configured, or contradicted by its opt-out flag; on a database login that can write session tables regardless of grants, such as the owner's; or with the connector partly configured. | Every gate is explicit. |
| Tools | Eighteen, with the classifications and required arguments in `baseline.json`. Thirteen read, five write, none destructive. | The served set is pinned by name. |

## What the suite does not cover

These exist in Otto at this commit and are not exercised beyond being listed:

- The behavior of thirteen tools: `github_list_releases`, `github_get_issue`,
  `github_get_checks`, `github_get_job_log`, `github_propose_change`, `github_amend_change`,
  `github_pr_template`, `github_repo_conventions`, `github_skill_body`,
  `declare_unverified_claim` and the three Jira tools.
- The control-plane endpoints `/repo-config`, `/pr-receipt` and `/pr-outcome`. Under
  [decision 0003](decisions/0003-otto-keeps-its-control-plane-endpoints.md) they stay in
  Otto, so the suite will cover the vendor actions they call once those are defined, not the
  endpoints themselves.
- Grant key rotation, the custodian's peer-identity check (Linux only), and the gateway
  waiting for database grants at boot.
- Whether the fencing epoch in the grant is enforced. Otto's code says it is signed and not
  yet enforced; the suite only checks that it is recorded.

Extending coverage is required before Otto's cutover, which is milestone 4 of the design. It
is not needed for the milestones before it.

## Evidence that the tests can fail

`conformance/mutation_check.py` breaks one guard in the pinned gateway at a time and requires
the test named for it to fail. On 2026-10-01 all six were caught: the per-turn tool check,
the grant and pod team comparison, the wait for audit finish, the `refused` outcome, the
draft pull request, and the grant signature check.

The first run did not catch the last one. The "tampered" case had corrupted the claims, so
the grant was refused as malformed whether or not the signature was checked. The case now
swaps in well-formed claims under a genuine signature.

## Changes from the previous pin

Reviewed one by one against Otto's documents; none was accepted only to make a test pass.

| At `4ad4f69` | At `752395a` |
| --- | --- |
| Acting context in five headers; missing header refused by name. | Signed grant; headers read only with grant checking off. |
| Team mismatch sentence named the `X-Otto-Team` header. | Names the grant. |
| A nonnumeric fencing epoch was accepted from a header. | The epoch is a number inside the signed grant, and a grant without one is refused. |
| Connector scope rejections were outcome `error`. | Outcome `refused`, with a reason. |
| Five tools; fixture mode served one. | Eighteen; fixture mode serves two. |
| The gateway read the App key and requested one token. | A custodian holds the key; tokens are requested per permission set and repository list. |
| Search appended the organization qualifier. | Parenthesizes the caller's query first and requests advanced search. |
| Whether `github_create_pr` opened a draft was not checked. | It opens a draft. |
| Schema loaded from one SQL file; the gateway ran as the database owner. | Schema applied by Otto's migrator; the gateway refuses the owner's login and runs as its own role. |
