# Observed Otto gateway behavior

Baseline: `ambientself/otto` commit `4ad4f69ce678f3ebf91d9be5bbcad86ed614bf65`.
The local source checkout is named `agentrunner`. The exported commit excludes its working
tree changes. Build toolchain and disposable Postgres image are pinned in
[conformance/baseline.json](../conformance/baseline.json).

The [conformance suite](../conformance/README.md) passes against this binary with the race
detector, real Postgres, locally generated keys and a fake GitHub API. These findings describe
the existing implementation. They do not settle Q9–Q13 or automatically become requirements
for Switchboard.

## Findings that affect migration

| Observed behavior | Consequence for Switchboard |
| --- | --- |
| Initialization always reports MCP `2025-06-18`, even when a different version is requested. No session ID is issued. | Preserve a known compatibility baseline while selecting supported clients and protocol behavior in Q13. |
| `initialize`, `ping` and `tools/list` are audited, as well as `tools/call`. All require the acting-context headers. | “One row per tool call” understates existing coverage. Decide the precise audit scope in Q10. |
| Accepted notifications return 202 without an audit row. Authenticated malformed JSON returns 400 without a row. Missing-context notifications return 400 with a denial row and no body. | “No answer without an audit row” is not a literal description of every HTTP path. |
| Identity failures return HTTP 401, a fixed opaque sentence and a Bearer challenge. Named tool/policy failures normally return HTTP 200 with a JSON-RPC error. | Preserve status, envelope and audit differences, not just readable denial text. |
| Unknown tools are denied before execution and before vendor token minting. No destructive tools are exposed. | Black-box tests cannot inject a classified destructive tool into the binary; do not claim they test its internal registration guard. |
| Organization and argument checks inside a known connector fail after authorization and audit begin. Those rows are `allowed` with outcome `error`. | A connector rejection is not recorded as a policy denial. Q9 must explicitly decide where resource authorization belongs. |
| An audit-begin failure blocks execution and replaces the normal denial/result with the fixed audit-unavailable sentence. | That failure response is an exception to requiring an audit row before every answer. |
| A failed completion update leaves a successful response and completed vendor action, with a NULL durable outcome. | NULL means no outcome was durably recorded; it does not prove the gateway never learned the result. Q10 must define recovery without suggesting the action is safe to replay. |
| A client disconnect during a blocked vendor request results in an `error` completion row, using an independent completion context. | Preserve completion despite request cancellation. This test does not prove remote writes are undone by disconnecting. |
| Repeating the same comment call, request ID and `Idempotency-Key` produces two writes and two rows. | There is no generic durable action-receipt deduplication in this baseline. New recovery behavior needs its own tests and decision. |
| A nonnumeric fencing-epoch header is accepted and recorded unchanged. | The header is correlation, not enforcement of the control-plane fencing promise. |
| With identity disabled, audit rows explicitly record `disabled`, not `failed` or a fabricated proof. | Keep these states distinguishable. |
| Omitting the connector serves a canned search fixture. Identity's default nonempty audience also makes a bare invocation “half configured.” | Fixture behavior and flag defaults differ from the draft's simplified boot description; migration configuration must be explicit. |

## Compatibility scope

The five tools are search, get file, get pull request, create pull request and comment.
The suite checks classifications, required input fields, output provenance, audit attribution,
organization scoping, bounded results, brokered credentials and observable write effects.
Endpoint/tool-name changes are listed explicitly in the baseline mapping rather than hidden
by changing security assertions.

`/repo-config`, model brokering, human approval flows, minted AWS credentials, employee OAuth,
resource-specific company policy, registry drift and revocation are outside this executable
baseline. Otto retains `/repo-config` and model brokering under decision 0002; separating those
responsibilities still needs rollout work in issue #13.

## Next decisions

Use these findings in Q9 (resource authorization), Q10 (audit, retries and fencing) and Q13
(client/protocol compatibility). Existing-behavior tests should remain separate from tests
for accepted company-wide additions. Record intentional differences before changing a
conformance expectation; current gaps are observations to improve, not guarantees to preserve.
