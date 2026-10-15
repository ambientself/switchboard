# The resolver interface, version `v1`

Status: proposed to Otto's owners, not agreed. This is the interface behind
[otto-requests.md](otto-requests.md) request 14, written so that Otto's control plane can
implement it, or answer it, without reading Switchboard's code. Until Otto's owners agree it
([decision 0012](decisions/0012-what-a-turn-grant-binds.md), Still open), Switchboard is built and
tested against a fake resolver and calls no real one. The client that implements it is
`crates/gateway-otto` (`resolver.rs`), and its tests check the example at the end of this page.

## What it is for

Switchboard is Org's MCP gateway, and from stage 3 of the cutover it serves Otto's
side-effecting tools. Some facts a decision depends on are known only to Otto and can change
during a turn. [Decision 0003](decisions/0003-otto-keeps-its-control-plane-endpoints.md) has
Otto expose them through a versioned resolver interface that its control plane serves, and says
what Switchboard does when Otto does not answer: it refuses the call.

The interface has one question so far:

- **Currency** (this page): is this turn current? Its control plane still holds the lease at the
  turn's epoch, and the turn has neither ended nor been revoked
  ([decision 0012, Currency](decisions/0012-what-a-turn-grant-binds.md#currency-the-epoch-ended-turns-and-revoked-turns)).

The next question is whether a pull request is one of Otto's own proposals, which
`github_amend_change` needs. It comes with Otto's GitHub tools (issue #12), as another path
under the same version; it is not specified here. A question added later does not change this
one.

## Asking

Switchboard is configured with the interface's base URL. Each question is one HTTP/1.1 request:

```text
POST {base}/v1/currency
Content-Type: application/json
Accept: application/json
Cache-Control: no-store
Authorization: Bearer <token>
```

`v1` is the interface's version and `currency` the question's name. The body is a JSON object
with exactly these members:

| Member | Type | Value |
| --- | --- | --- |
| `version` | string | Exactly `v1`. |
| `question` | string | Exactly `currency`. |
| `request_id` | string | 32 lowercase hex digits, drawn afresh for every request. |
| `sid` | string | The session, exactly as the turn grant's `sid`. |
| `eid` | string | The execution, exactly as the grant's `eid`. |
| `tid` | string | The turn, exactly as the grant's `tid`. |
| `epoch` | integer | The fencing epoch, exactly as the grant's `epoch`. |

The turn's members use the grant's own claim names ([turn-grant-format.md](turn-grant-format.md)),
and carry the values of a grant Switchboard has verified. Switchboard asks only before a call of
a tool not classified `read`, under the profile for Otto's sandboxes. Reads, `tools/list` and
Otto's control-plane actions are never asked about.

Switchboard asks every time. It keeps no answer, so a turn revoked between two calls is denied
at the second; `Cache-Control: no-store` asks every cache between the two to keep none either.
It may send the same question again on a new connection only when the first was never sent,
such as on a pooled connection that had closed. A question changes nothing in Otto.

## The answer

Otto answers `200` with a JSON object: **the question's own object, every member unchanged, and
one member added, `answer`**:

| `answer` | Meaning |
| --- | --- |
| `current` | The control plane that drove the turn still holds the lease at `epoch`, and the turn has neither ended nor been revoked. |
| `superseded` | A newer epoch holds the lease. |
| `ended` | The turn has ended. |
| `revoked` | The turn was revoked. |

Otto answers from its durable state: the lease row's holder and epoch, compared on the
database's clock as its own fencing does, and the turn's recorded state. A superseded control
plane that is still running must not be able to say its own turns are current. Switchboard
cannot tell a right answer from a wrong one, so that is Otto's guarantee, tested in Otto.

An answer is read in this order:

1. **The status.** Anything but `200` is an error. A redirect is not followed.
2. **The size.** An answer of more than 65536 bytes is refused, from its declared length or as
   it arrives, and is not read in full. An honest answer is far shorter.
3. **The version.** The body must be a JSON object whose `version` is a string. If it is not
   `v1`, the answer is of an unknown version. It is read before anything else in the body,
   since another version may have another shape.
4. **The format.** Exactly the members of the question and `answer`, each once, with the types
   above, and `answer` one of the four values. A member Switchboard does not know is refused:
   anything new comes with a new version.
5. **The echo.** Every member of the question, `request_id` included, must equal what was sent.

Member order and whitespace do not matter. Strings are compared as decoded JSON strings.

### How an answer shows which question it answers

The answer repeats the whole question, so an answer to another question is detected: another
kind of question, another session, execution, turn or epoch. The `request_id` is new for every
request, so an answer to an earlier asking of the same question, such as one a cache kept or a
connection delivered late, is detected too. Otto copies the question; it does not need to
understand `request_id`.

## The budget: one second

Switchboard waits at most **one second** for the whole exchange: reading its token, connecting,
the TLS handshake, the response head and the last byte of the body. The budget is fixed by
decision 0012 and enforced by Switchboard's client, whatever the server does. A turn's
side-effecting call is therefore never held up by the resolver for more than one second.

## When there is no answer

Each of these is **unconfirmed**:

- no whole answer within the budget;
- an error: no connection, a TLS failure, a connection closed before the answer, a status other
  than `200`, or an answer that breaks off;
- an answer of an unknown version;
- an answer to another question, by the echo;
- an answer larger than the cap, or not in the format.

Under the profile for Otto's sandboxes, a side-effecting call is allowed only if the answer is
`current`. Superseded, ended and revoked are denied as not current; unconfirmed is denied as
unconfirmed, as decision 0003 requires. Each of the two reasons has its own sentence, and the
audit row records which answer Otto gave. Reads keep working when the resolver is
down. The resolver's availability target is request 15.

Switchboard counts each answer by result, each failure by kind, and the latency of every
question, timeouts included.

## Authentication

**The gateway to Otto.** Recommended: a projected ServiceAccount token whose audience names the
resolver, sent as `Authorization: Bearer` with every question. Switchboard reads the token from
its file for each question, since the kubelet rotates it in place, and sends it only over TLS.
Otto verifies it as it verifies any ServiceAccount token, against the cluster's keys or with a
TokenReview, and checks the audience and that the subject is Switchboard's ServiceAccount.

The reason: it is how Switchboard already presents itself to the MCP servers it proxies, so it
adds no new kind of credential. Nobody issues, stores or rotates a secret by hand; the token
names Switchboard's workload and expires on its own; and Otto already verifies ServiceAccount
tokens. Mutual TLS would do as well, if Otto prefers it, but needs a client certificate issued
to Switchboard and rotated, which Switchboard's outbound clients do not have yet.

**Otto to the gateway.** The resolver is served over TLS. Switchboard trusts only the CA bundle
its deployment names for the resolver, nothing compiled in and nothing from the system, and
verifies the certificate against the host in the base URL. Its client refuses plain `http`
except to a loopback address, for a local fake: over plain `http` anyone on the path could
answer `current`.

## Versions

A new version is a new path and a new `version` value, such as `POST {base}/v2/currency`.
Switchboard's client asks one version, and moves to a new one in a release of its own. An answer
of another version is unconfirmed, so Otto serves an old version until Switchboard has moved to
the new one.

## Example

A question for the turn in [turn-grant-format.md](turn-grant-format.md)'s example:

<!-- example: question -->
```json
{
  "version": "v1",
  "question": "currency",
  "request_id": "6f1c0b9e2d7a4e58a3b6c9d01f2e3a4b",
  "sid": "session-1",
  "eid": "execution-1",
  "tid": "turn-1",
  "epoch": 7
}
```

Otto's answer, if the turn is current:

<!-- example: answer -->
```json
{
  "version": "v1",
  "question": "currency",
  "request_id": "6f1c0b9e2d7a4e58a3b6c9d01f2e3a4b",
  "sid": "session-1",
  "eid": "execution-1",
  "tid": "turn-1",
  "epoch": 7,
  "answer": "current"
}
```

The same turn after a failover to epoch 8 answers `superseded`. A question naming epoch 8,
answered with `"epoch": 7`, is unconfirmed: it answers another question.
