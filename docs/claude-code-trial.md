# Claude Code against the local gateway

Date: 2026-10-07. What happened when Claude Code, the first real client named in
[decision 0007](decisions/0007-serve-two-mcp-revisions-from-a-hand-written-endpoint.md), was
pointed at `switchboard-dev` in each of its two negotiation modes. This is the record issue #26
asks for.

## Setup

- Claude Code 2.1.289 (macOS build), in print mode (`claude -p`) with Haiku as the model.
- `switchboard-dev` built from the PR #38 branch, after the server's time limits were added.
  Team A's token from its tokens file. Surface `fixture-read`.
- The server was given to Claude Code with `--mcp-config` and `--strict-mcp-config`, as an
  `http` server with an `Authorization: Bearer` header. That is the same entry
  `claude mcp add --transport http ... --header` writes, without changing the user's own
  configuration. `claude mcp add` itself was not run.
- A pass-through logger sat between the two for the two mode runs, so every request and answer
  was recorded. It forwarded the `Host` header unchanged.
- Claude Code chooses its mode with the `MCP_PROTOCOL_NEGOTIATION` environment variable:
  `legacy` runs the `initialize` handshake, and `auto` probes with `server/discover` and falls
  back to `initialize` if the server gives no sign of the newer revision. With the variable
  unset, this build used `auto` for an HTTP server.

Each run asked the model to list the server's tools, read `team-a-notes`, then read
`team-b-notes`, and report what came back.

## What worked

Both modes, and the default run with no logger in between, ended the same way: the tools were
listed, team A's document was read, and team B's was refused with the gateway's sentence,
which reached the model word for word. The gateway wrote an allow row and a deny row for each
run, each carrying the `claudecode/toolUseId` Claude Code put in `_meta`.

**Legacy** (`MCP_PROTOCOL_NEGOTIATION=legacy`):

| Request | Answer |
| --- | --- |
| `initialize` asking for `2025-11-25` | 200, `protocolVersion` `2025-06-18`. Claude Code accepted the lower version and settled in the legacy era. |
| `notifications/initialized`, with `MCP-Protocol-Version: 2025-06-18` | 202 |
| `GET` for an event stream | 405. Claude Code carried on without one. |
| `tools/list` | 200, both read tools |
| `tools/call` `fixture__read` on `team-a-notes` | 200, a result with `isError` false and `structuredContent` |
| `tools/call` `fixture__read` on `team-b-notes` | 200, error `-32001` with the sentence. Claude Code logged it as a protocol error and gave the model the sentence. |

No session ID was asked for or sent, and no `DELETE` followed.

**Auto** (`MCP_PROTOCOL_NEGOTIATION=auto`, and the default):

| Request | Answer |
| --- | --- |
| `server/discover`, with `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method` | 200, `supportedVersions` `["2026-07-28"]`. Claude Code settled in the modern era and sent no `initialize`. |
| `tools/list` | 200, with `resultType`, `ttlMs` and `cacheScope: private` |
| `tools/call`, with `Mcp-Method` and `Mcp-Name: fixture__read` | 200 for `team-a-notes`, error `-32001` for `team-b-notes`, as above |

Every modern request carried the three `_meta` fields and headers that matched its body. No
`subscriptions/listen` was opened, because the gateway advertises no change notifications.

## What did not work

- **No token.** With no `Authorization` header, `server/discover` got 401 with
  `WWW-Authenticate: Bearer realm="switchboard"`. Claude Code took that as a server that needs
  OAuth: it looked for protected-resource and authorization-server metadata under
  `/.well-known/`, tried dynamic client registration at `/register`, got 404 for each, then
  tried again in the legacy era with `initialize` and got the same. It reported the server as
  not connected, with "Dynamic Client Registration rejected (HTTP 404)". The refusal is right;
  the message points a person at OAuth, which this gateway does not offer, rather than at the
  missing token. Signing employees in is open in Q13.
- **A refusal is read as a legacy server.** In `auto`, the 401 to `server/discover` made Claude
  Code fall back to `initialize`. The SDK client in `crates/gateway-dev/tests/rmcp.rs` does
  not do this. It does no harm here, since the fallback is refused too.

## Not tried

- `claude mcp add` itself, and an interactive session.
- A token that expires while Claude Code is connected. The header is a fixed value in Claude
  Code's configuration, so it is expected to fail after an hour with the 401 above.
- The `fixture-all` surface and its `propose` and `write` tools, team B, and the user.
- A browser-based client. The gateway refuses any request that carries an `Origin` header.
