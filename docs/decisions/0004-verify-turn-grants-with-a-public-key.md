# 0004: Verify Otto's turn grants with a public key

Date: 2026-10-01. Status: accepted here; needs a change in Otto.

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

If that change would delay Otto's cutover, the first cutover may use the shared secret,
recorded as a known gap with a date by which it closes.

## Consequences

- The verifier interface in this gateway does not change with the algorithm, so work on
  milestone 2 can start before Otto's change lands.
- Changing the grant format is a breaking wire change in Otto. Otto's own procedure for the
  last one was to stop admitting turns, drain, roll the control plane, the gateway and the
  sandbox image together, and resume. Combining this change with the cutover avoids doing
  that twice.
- The same rule applies to any future control plane that delegates to this gateway: it signs
  with a key the gateway cannot use to sign.
- Open in Otto: the request itself has not been raised there yet.
