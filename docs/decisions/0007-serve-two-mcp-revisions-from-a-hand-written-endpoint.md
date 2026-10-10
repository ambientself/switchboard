# 0007: Serve two MCP revisions from a hand-written endpoint

Date: 2026-10-01, amended 2026-10-07 (the amendment is at the end). Status: accepted. Settles
the part of Q13 that milestone 1 needs: the MCP revision and the first client. Changes one
consequence of [decision 0001](0001-build-on-axum-not-pingora.md).

## Context

Facts checked against the specification, the Rust SDK and Claude Code's documentation on
2026-10-01:

- The current stable MCP revision is `2026-07-28`. It removes `initialize`, `ping` and
  protocol-level sessions. Every request carries its protocol version, a new `server/discover`
  method reports what a server supports, and each request must carry `MCP-Protocol-Version`,
  `Mcp-Method` and, for a tool call, `Mcp-Name` headers that match its body.
- Revisions up to `2025-11-25` use the `initialize` handshake. Under them a server may issue
  no session ID, and may answer `initialize` with a version of its own choosing.
- Otto's Go gateway answers every `initialize` with `2025-06-18`, issues no session and
  answers in plain JSON.
- Claude Code speaks both eras. Its newer runtime asks a server whether it supports
  `2026-07-28` first. How it behaves when a server supports only the older era was not
  verified.
- The Rust SDK, `rmcp`, supports both eras, but has had three major versions in a month and
  roughly a release a week. Its server transport defaults to issuing sessions and to
  allowing only localhost as a host.
- The surface this gateway needs is small: one POST route, four or five methods, header
  checks, and no streaming for tools that answer once.

## Decision

1. **Serve both eras on one endpoint, without sessions in either.** A request that carries its
   protocol version is served as `2026-07-28`. An `initialize` request selects the older era
   and is answered with `2025-06-18`, as Otto's gateway does. No session ID is issued in
   either. GET and DELETE are refused.
2. **Write the endpoint by hand on `axum`.** JSON-RPC parsing, method dispatch, the header
   checks and the HTTP status codes are this project's code, behind the protocol adapter the
   design already requires.
3. **Use `rmcp` only in tests,** pinned to an exact version, as a client that speaks both
   eras. It is not a dependency of the gateway binary.
4. **Claude Code is the first real client.** The endpoint is tried against it in both of its
   negotiation modes before the HTTP slice is called done.
5. **Policy denials are JSON-RPC errors with code `-32001`** and the denial sentence as the
   message, in both eras. The code is in the range the specification leaves to
   implementations. An unknown tool gets the same code as a tool that is not approved,
   deliberately: a caller should not be able to tell which names exist.
6. **Tool names stay within the design's stricter rule:** 64 characters of letters, digits,
   `_` and `-`. That is inside what the specification recommends, and some clients accept no
   more.

## Why

- A server that supports only the older era risks being misread by a newer client, and one
  that supports only the newer era cannot serve Otto's callers. Serving both removes the
  untested fallback from the path.
- The newer era is stateless by design, which is what this gateway already decided to be.
- Owning the endpoint gives exact control over status codes, authentication challenges and
  error shapes, which the denial contract and Otto's compatibility both depend on. It also
  means a fast-moving SDK cannot change the gateway's behavior in a patch release.

## Consequences

- Decision 0001 said the proxy is built on `axum` with the `rmcp` SDK. It is built on `axum`;
  `rmcp` is a test dependency only.
- This project owns tracking the specification for the methods it serves. The methods are
  few, and each has a test against the SDK's client.
- Not served: resources, prompts, sampling, subscriptions, and requests from server to
  client. A tool that needs input from the user returns a refusal that says so.
- Results under `2026-07-28` carry the fields that revision requires, including the result
  type and, for `tools/list`, how long the list may be cached and for whom. The tool list
  varies by the caller's authorization, which that revision allows, and never by connection.
- Host and origin checks are this project's to implement, and are configured explicitly.
- Open in Q13 and unaffected: employees' clients, sign-in, token audience and private access.

## Amended 2026-10-07: choices made for the HTTP path

The owner made these choices when the HTTP path (#26) was planned. They were first recorded
only in code comments, numbered after that plan's own questions, which clash with the numbers
in [open-questions.md](../open-questions.md). They are recorded here instead.

1. **One code for every refusal, for now.** A policy denial, a connector's scope refusal, an
   audit failure and an identity failure all use `-32001`, in both eras. The sentence tells
   them apart, and an identity failure is also a 401. Giving each kind its own code is a
   change to this decision.
2. **`server/discover` lists only `2026-07-28`.** A client that wants `2025-06-18` starts with
   `initialize`, as that era requires.
3. **A tool that ran and failed is answered with a result, not an error:** `isError: true`,
   with the tool's message as text, so the model sees what went wrong. Its row records the
   outcome `error`. JSON-RPC errors are kept for refusals and for requests the gateway could
   not take.
4. **No client may cache a tool list.** `tools/list` and `server/discover` are answered with a
   `ttlMs` of zero, so a withdrawn tool is gone from the next list.
5. **With identity disabled, nothing is listed and every `tools/call` is refused,** with a
   sentence that says why, and no row is written. Design section 17, under #26, names what
   replaces this: reads served, with rows whose identity is `disabled`.
   Noted on 2026-10-10: [decision 0014](0014-rollout-safeguards-and-audit-operations.md) keeps
   this, and only a development build may disable identity. Nothing replaces it: reads are not
   served with rows whose identity is `disabled`, and #69 is not planned.
