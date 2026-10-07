# 0004: Verify Otto's turn grants with a public key

Date: 2026-10-01, amended 2026-10-07 by
[decision 0012](0012-what-a-turn-grant-binds.md). Status: accepted here; needs a change in
Otto.

## Context

Otto's control plane mints a signed grant for each turn, naming the session, turn, team,
acting human, fencing epoch, expiry and the tools the turn may call. The gateway verifies it.

Grants are signed with a shared secret, so anything that can verify a grant can also create
one. Otto's code argues this is sound because its gateway is the only verifier and is itself
the authorization point. Otto already moved its model-broker tokens to an asymmetric
signature for the opposite case, a verifier that should not be able to mint.

Once this gateway replaces Otto's, the verifier is a separate, company-wide service. Holding
Otto's signing secret would let it, or anyone who compromised it, write any human's name on
any Otto action.

## Decision

Ask Otto to sign turn grants with an asymmetric key. This gateway holds only the public key.

There is no shared-secret exception. An earlier draft allowed the first cutover to use the
shared secret if the change would delay it. That contradicted the reason for the decision: a
compromised company-wide gateway could forge any Otto action. Otto's cutover waits for the
asymmetric signature.

What a grant binds, whether it may be presented more than once, and enforcement of the
fencing epoch are settled in [decision 0012](0012-what-a-turn-grant-binds.md). The algorithm
is Ed25519, under a format version that is neither `v1` nor the model broker's `v2`.

## Consequences

- The verifier interface in this gateway does not change with the algorithm, so work on
  the Otto adapter can start before Otto's change lands.
- Changing the grant format is a breaking wire change in Otto. Otto's own procedure for the
  last one was to stop admitting turns, drain, roll the control plane, the gateway and the
  sandbox image together, and resume. This record first had the change made with the cutover,
  to avoid doing that twice. Decision 0012 changed that on 2026-10-07: the format change is
  made alone, before stage 1, so the shadow comparison verifies real grants, and Otto's Go
  gateway verifies the new format too. Later claims are added in two steps, Otto minting
  first and this gateway requiring second, with no second drain.
- The same rule applies to any future control plane that delegates to this gateway: it signs
  with a key the gateway cannot use to sign.
- Open in Otto: the request itself has not been raised there yet.
