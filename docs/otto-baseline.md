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
| Audit scope | `initialize`, `ping` and `tools/list` are audited, as well as `tools/call`. Accepted notifications return 202 with no row. Authenticated malformed JSON returns 400 with no row. | Decision 0009. Identity failures, `initialize` and `ping` become telemetry, with no row; `tools/list` and unverifiable grants stay audited. Whether Otto's adapter still writes the first three into `gateway_audit` is for Otto's owners. |
| Scope refusals | A call naming another organization, a repository outside the team's, or a comment Atlantis could read as a command is refused by the connector. The row is `allowed` with outcome `refused`, and `refusal_reason` holds the sentence the caller read. No token is requested. | A refusal is a denial or a `refused` outcome. For proxied tools, [decision 0011](decisions/0011-resource-authorization-and-tool-assurance.md) settles it: a proxied tool never checks its own scope. |
| Argument errors | A malformed argument is `allowed` with outcome `error` and no refusal reason. | Keep refusals and errors distinguishable. |
| Tokens | Every token request names the team's repositories and a permission set; the gateway holds several tokens, one per permission set. The caller's own credentials never reach GitHub. | Narrow per call, where the vendor allows. |
| Key custody | The gateway holds no App key. It asks a separate custodian process over a Unix socket, and refuses to start if the old key variables are set. | Adopted for every vendor key in the design. |
| Pull requests | `github_create_pr` opens a draft. | A property of Otto's write shape, tied to Org's Atlantis. |
| Search | The caller's query is parenthesized, the organization qualifier appended, and the advanced search engine requested. | The scoping is in how the request is built. |
| Audit begin failure | Blocks execution and replaces the answer, including a 401, with one fixed sentence. | The stated exception to "no answer without a row". A 401 keeps the opaque identity sentence here even during an audit outage, since an identity failure writes no row: a recorded parity difference (decision 0009). |
| Audit finish | The answer waits for the row to be finished: with a finishing write slowed to 0.3 seconds, the row is complete when the answer arrives. If finishing fails, the answer still succeeds, the write is made once, and the row keeps an empty outcome. | An empty outcome means no outcome was durably recorded. Never retry a write because of it. Decision 0009's `unknown` reaches `gateway_audit` as an empty outcome, never as `error`, and `duplicate` as `ok`. |
| Disconnect | A client that disconnects during a blocked vendor call still gets an `error` completion row. | Finish on a context separate from the request. Under decision 0009 a read is cancelled and recorded as `error`, as here; a side effect runs to its call deadline, which is a parity difference. |
| Repeated write | The same comment sent twice makes two writes and two rows, on GitHub and on Jira. | No general deduplication. `github_propose_change` has its own idempotency key, below. Once receipts are on for Otto's profile (decision 0009) this is a deliberate divergence, and `TestRepeatedCommentIsWrittenTwice` moves to the group of expected differences, with the divergence recorded. |
| Grant key rotation | The gateway reads its current grant key and, optionally, a previous key with an absolute retirement instant, once, at start. Grants signed by either key verify until that instant and the previous key's are refused from then on, without a restart, with the usual fixed sentence. Rewriting a key file changes nothing until a restart. It refuses to start with a previous key and no instant, an instant that is not RFC3339, the same key twice, or an unreadable previous key. It starts with an instant already past, and with an instant but no previous key, which it ignores. | Decision 0012 replaces this with Ed25519 keys and its own rotation, tested in the new-behavior group. The absolute instant, rather than a window from process start, is worth keeping. |
| Newer GitHub reads | Releases and tags come back as two lists of at most thirty, each said to be cut; release notes are left out. An issue comes with its first twenty comments, oldest first, and a note when more exist; a pull request's number gets a note pointing to `github_get_pr` and nothing else. Checks are read at the pull request's head: thirty check runs, and for a failing run ten annotations and, for a GitHub Actions run, its steps; commit statuses come from the combined status. Each tool asks for its own permission set: contents for releases, metadata for tags, issues and pull requests for an issue, and actions, checks, pull requests and statuses for checks. | The bounds and the "cut" notes are part of the contract a caller sees. |
| Job logs | GitHub answers a log request with a redirect, and the gateway follows it only to its own pinned blob host. A redirect anywhere else is `refused` before any request to that host; a log served without a redirect, or no log, is an `error`. | Pinning the redirect target is a property worth keeping for any vendor that hands out signed URLs. |
| Repository config | The pull request template and `AGENTS.md` come from a per-repository config the gateway loads in the background at the default branch's head, with a read-only token. A call made while it loads is answered at once as pending, with outcome `ok`. `AGENTS.md` is served only when CODEOWNERS gives it an owner, and then quoted inside a frame whose markers carry a token made for that call. | The quoting frame is Otto's defense against instructions in repository files. |
| Proposals | `github_propose_change` makes a branch `otto/<key>` from the default branch's head, one commit whose message is the title, and a draft pull request into the default branch, with the declared unverified claims quoted above the body. Git writes use a contents-write token and the pull request a pull-requests-write token. A record of the proposal is kept in Otto's database. Repeating the call returns the existing proposal (`already_proposed`); other files, or another body while the pull request is open, under the same key is `key_conflict`, with nothing written to the branch; a proposal that changes nothing is an `error`. After a human closes the proposal without merging it, a repeat reports `proposal_declined` with the closed pull request's number and opens no pull request. | A per-call idempotency key with conflict detection is the shape decision 0009's receipts generalize. |
| Amendments | `github_amend_change` needs the App's own login configured. It adds one commit on top of the branch, fast-forwards the branch without force, and rewrites the claims block above the existing description. Git writes use a contents-write token and the pull request edit a token with pull-requests write and contents read. It is refused for a pull request marked ready for review, one whose branch is not under `otto/`, or one with no proposal record; a closed pull request is an `error`, not a refusal. A repeat that would change nothing needs the expected head, and with it reports `no_change`. | The ready-for-review refusal ties amendments to Atlantis planning only drafts. |
| Jira | Every request uses the shared account's basic credentials. Search wraps the caller's JQL as `project in (...) AND (...)`, keeps a trailing `ORDER BY` outside, pages ten by default and at most twenty, and resolves `{me}` to the asker's Atlassian account after checking it exists. An answer that names an issue outside the projects is withheld whole and `refused`. Unbalanced parentheses and functions that depend on the caller, such as `currentUser()`, are refused before any request. An issue's comments with a visibility restriction are withheld and counted; an issue under a security level is `refused` after Jira answers. A comment is posted to the issue's id as paragraphs, with a final line naming Otto, the person and the team. | The project allowlist is a resource scope the core can express; the JQL wrapping is how this connector enforces it. |
| Declarations and skills | `declare_unverified_claim` answers with the claim, served in fixture mode too, and cuts a claim to 1000 bytes and its `wouldBeVerifiedBy` to 200, ending in `...`; it makes no vendor request. `github_skill_body` fails with an `error` unless a skill set was pinned for the turn, and records the requested ref on the row. | A turn's skill set is fixed outside the tool call. |
| Tool-use identifier | The caller's `claudecode/toolUseId` is stored on the row. | Otto's control plane joins on it to read decisions back. |
| Identity disabled | Rows say `disabled`, never `failed` or a made-up proof. The fixture still answers. The real connector refuses every call and requests no token, since there is no proved team to scope one to. | Turning identity off must not hand out a live credential. |
| Boot | Refuses to start with identity, grant or audit unconfigured, partly configured, or contradicted by its opt-out flag; on a database login that can write session tables regardless of grants, such as the owner's; or with the connector partly configured. | Every gate is explicit. |
| Tools | Eighteen, with the classifications and required arguments in `baseline.json`. Thirteen read, five write, none destructive. | The served set is pinned by name. |

## What the suite does not cover

These exist in Otto at this commit and are not exercised:

- A job log's text and the window the gateway cuts from it. The gateway follows GitHub's log
  redirect only to its own pinned blob host, which a local suite cannot stand in for; the
  refusals around it are covered.
- A skill body's text. `github_skill_body` serves only a skill from a set pinned for the turn,
  and nothing a caller can do over the tool interface pins one; the failure without a pin and
  the argument check are covered.
- `github_amend_change`'s `commit_landed_body_failed` state, a commit that lands while the
  body write fails.
- The control-plane endpoints `/repo-config`, `/pr-receipt` and `/pr-outcome`. Under
  [decision 0003](decisions/0003-otto-keeps-its-control-plane-endpoints.md) they stay in
  Otto, so the suite will cover the vendor actions they call once those are defined, not the
  endpoints themselves.
- The custodian's peer-identity check (Linux only), and the gateway waiting for database
  grants at boot.
- Whether the fencing epoch in the grant is enforced. Otto's code says it is signed and not
  yet enforced; the suite only checks that it is recorded.

Rotation of the decision 0012 grant keys and epoch enforcement in this gateway are tested by
the new-behavior group for [decision 0012](decisions/0012-what-a-turn-grant-binds.md)
([design.md](design.md), section 18), not by this suite.

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

On 2026-10-13 thirteen guards were added for the newer tools and grant key rotation, and all
nineteen were caught. They were written from what the gateway says and does over HTTP, without
reading Otto's source, and a guard's text only stays if it matches the pinned source exactly
once. Eight change behavior: the previous key's retirement check, a bound in
`github_get_checks`, where CODEOWNERS is read from, the draft flag and the Atlantis file
refusal in `github_propose_change`, the claim bound, Jira's project restriction and its
reading of comment visibility. Five change a sentence that a test pins, where no line of behavior could
be matched: the boot refusal for a previous key without an instant, the job log redirect
refusal, the unpinned skill failure, the amend commit message and the Jira attribution line.

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
