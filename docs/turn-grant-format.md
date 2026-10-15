# The turn-grant format, version `v3`

Status: proposed to Otto's owners, not agreed. This is the exact format behind
[otto-requests.md](otto-requests.md) requests 2 and 3, and the rules of
[decision 0012](decisions/0012-what-a-turn-grant-binds.md), written so that Otto's control plane
can mint grants, and Otto's Go gateway verify them, without reading Switchboard's code. The
verifier that implements it is `crates/gateway-otto`, and its tests check the example at the end
of this page.

A grant is minted by Otto's control plane once per turn and sent by the sandbox on every MCP
request in the `X-Otto-Turn-Grant` header. It is signed with Ed25519. The control plane holds
the private key; each gateway holds only the public key.

Throughout, `||` is concatenation of byte strings, and quoted text is its ASCII bytes.

## The grant

A grant is four parts joined by `.` (0x2E), in this order:

```text
v3.<key id>.<claims>.<signature>
```

| Part | Contents |
| --- | --- |
| Version | The two characters `v3`. Not Otto's `v1` HMAC grants, and not its model broker's `v2` tokens. |
| Key ID | The ID of the public key that verifies the signature (below), encoded. 22 characters. |
| Claims | The claims, a JSON object (below), encoded. |
| Signature | The Ed25519 signature (below), encoded. 86 characters. |

A grant is ASCII, has no whitespace and no line breaks, and is at most 8192 bytes long. Every part
but the version is canonical unpadded base64url.

### Canonical unpadded base64url

The base64url encoding of [RFC 4648, section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5):
the alphabet `A`–`Z`, `a`–`z`, `0`–`9`, `-` and `_`, with these rules:

- No padding: no `=` anywhere.
- No characters outside the alphabet: not `+` or `/`, not whitespace.
- The unused low bits of the last character are zero
  ([RFC 4648, section 3.5](https://www.rfc-editor.org/rfc/rfc4648#section-3.5)). A part whose
  length is 2 more than a multiple of 4 has 4 unused bits; 3 more, 2 unused bits; a multiple of 4,
  none. A length 1 more than a multiple of 4 is never valid.

So each byte string has exactly one encoding, and a grant has exactly one spelling. A verifier
decodes each part and refuses the grant unless re-encoding gives the same characters.

## The key ID

```text
key id = base64url( SHA-256( "otto/gateway-turn-grant/kid/v3" || 0x00 || public key )[0..16] )
```

The public key is the 32-byte encoding of an Ed25519 public key
([RFC 8032, section 5.1.5](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5)). The ID is the
first 16 bytes of the hash, in canonical unpadded base64url: 22 characters. It is derived from the
key, so a key cannot be filed under the wrong ID, and the gateway computes it from the key it is
configured with; nothing configures an ID.

A public key is given to a gateway as a PEM file with one `PUBLIC KEY` block holding an Ed25519
SubjectPublicKeyInfo ([RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)), as
`openssl pkey -pubout` writes it. The gateway refuses a file that holds any private key material,
a key that is not a canonical encoding of a point on the curve, and a key of small order.

## The claims

The claims part encodes a JSON object ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) in
UTF-8. The signature covers the encoded claims exactly as they appear in the grant, so the JSON
need not be in any canonical form: the minter may order members and choose its spacing as it
likes, and nothing re-serializes it after signing.

| Claim | JSON type | Required | Meaning, and what the verifier checks |
| --- | --- | --- | --- |
| `aud` | array of strings | yes | The gateway deployments the grant is for. Must include the name of the deployment that received the call. During cutover it names Otto's Go gateway and Switchboard's Otto deployment. |
| `iat` | integer | yes | When the grant was minted, in seconds since 1970-01-01T00:00:00Z. No later than now plus the leeway. |
| `exp` | integer | yes | The turn's deadline, in seconds since 1970-01-01T00:00:00Z. After now minus the leeway. `exp − iat` at most the ceiling. |
| `team` | string | yes | The team the turn runs for. Not empty. |
| `tools` | array of strings | yes | The tools the turn may call, by Otto's bare names. At least one, and none empty. |
| `epoch` | integer | yes | The fencing epoch of the control plane that drove the turn. At least 1. |
| `sid` | string | yes | The session. Not empty. |
| `tid` | string | yes | The turn. Not empty. |
| `eid` | string | yes | The execution. Not empty. |
| `actor` | string | yes | The acting human. Not empty. Recorded as claimed, not proved. |
| `pod` | string | once required for the issuer | The UID of the sandbox pod that runs the turn, as Kubernetes writes it: a UUID, lowercase, hyphenated (`8-4-4-4-12` hexadecimal digits). Once required, must equal the pod UID in the caller's verified ServiceAccount token. |
| `egress` | string | once required for the issuer | The turn's egress setting: `sealed`, or `open` for egress open through Otto's proxy. No other value. Recorded, not checked against anything. |

More precisely:

- An integer is written as digits only: no sign, fraction or exponent, and at most
  2^63 − 1. `1800000000` is an integer; `1.8e9`, `1800000000.0` and `"1800000000"` are not.
- A claim in the table is never `null`, and never appears twice in one object. `pod` and `egress`
  may be left out until the issuer requires them; when present, they must be valid.
- A member the table does not name is ignored, whatever its value, so a claim can be added later
  without a breaking change: Otto mints it first, and the gateway starts requiring it second.
- `tools` may repeat a name; repeats count once. A name the gateway's mapping does not have is
  dropped, so it permits nothing. It does not fail the grant.
- Nothing requires `exp` to be after `iat`, but a minter must not mint such a grant.

## The signature

```text
signed bytes = "otto/gateway-turn-grant/v3" || 0x00 || "v3" || "." || key id || "." || claims
signature    = Ed25519-Sign(private key, signed bytes)
```

`key id` and `claims` are the second and third parts exactly as they appear in the grant: the
encoded characters, not the decoded bytes. The signature is pure Ed25519 as
[RFC 8032, section 5.1.6](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6) defines it, not
Ed25519ph or Ed25519ctx: the 64 bytes `R || S`, encoded as the fourth part.

Verification is strict. A verifier refuses a signature unless all of these hold:

- it decodes to exactly 64 bytes;
- S, its last 32 bytes read as a little-endian integer, is less than the group order
  ℓ = 2^252 + 27742317777372353535851937790883648493;
- R, its first 32 bytes, decodes to a point that is not of small order;
- the public key is not of small order (the gateway also refuses such a key when configured);
- `[S]B = R + [k]A`, with `k = SHA-512(R || A || signed bytes)` reduced modulo ℓ, checked by
  recomputing R and comparing its encoding (RFC 8032, section 5.1.7, without the cofactor).

Switchboard uses `ed25519-dalek`'s `verify_strict`, and checks S itself before it.

## Verification order

A verifier runs these checks in this order, and the first that fails is the result. Each has a
failure kind, which Switchboard records, logs and counts, and never tells the caller.

| Step | Check | Failure kind |
| --- | --- | --- |
| 1 | The text before the first `.` (or the whole grant, if it has none) is exactly `v3`. Nothing else is read first. | `version` |
| 2 | The grant is at most 8192 bytes, and has exactly four parts. | `malformed` |
| 3 | The key ID is exactly the ID of a configured key. A non-canonical spelling of an ID names no key. | `unknown_key` |
| 4 | That key is not a previous key whose end instant is now or past. | `retired_key` |
| 5 | The signature part, read as base64url but allowing `=` padding and non-zero unused bits (step 7 refuses both), is 64 bytes, and S is less than ℓ. | `encoding` |
| 6 | The signature verifies, strictly, under the key. The claims have not been decoded yet. | `signature` |
| 7 | The signature and claims parts are canonical unpadded base64url. | `encoding` |
| 8 | The claims are a JSON object as the table above requires, including `pod` and `egress` once the issuer requires them. | `malformed` |
| 9 | `aud` includes this deployment. | `wrong_audience` |
| 10 | `iat` ≤ now + 30. | `not_yet_valid` |
| 11 | `exp` > now − 30. | `expired` |
| 12 | `exp − iat` ≤ 900. | `lifetime` |
| 13 | Once the issuer requires `pod`: it equals the caller's proved pod UID. A caller whose token proves no pod fails. | `wrong_pod` |

Now is the gateway's clock in whole seconds since 1970-01-01T00:00:00Z, rounded down. The 30
seconds of leeway is what Otto's gateway allows on ServiceAccount tokens; the 900-second ceiling
is Otto's default execution timeout, and is raised in the gateway before Otto raises its
timeouts past it.

A grant that passes is identified by its digest: the SHA-256 of the grant as presented, all four
parts and the dots, written as 64 lowercase hexadecimal digits. Canonical encoding makes that one
value per grant. A failure at step 7 or later also carries the digest, since the signature
verified; a failure before it carries nothing of the grant. No failure carries anything from the
claims.

A grant may be verified any number of times within these bounds. There is no replay cache.

## Keys and rotation

Each issuer is one Otto environment's control plane, with its own key, which is not the model
broker's. The gateway is configured with each issuer's name, its current public key, at most one
previous public key with an absolute end instant, and whether it requires `pod` and `egress`. The
gateway refuses to start if a key file holds private key material, a key is of small order or not
canonically encoded, the same key is configured twice or under two issuers, or a previous key has
no end instant.

To rotate: add the new public key to the gateway as the current key, with the old one as the
previous key and an end instant at least one ceiling (15 minutes) after Otto will switch; roll it
out; have Otto sign with the new key; once the end instant passes, the old key's grants are
refused without a restart, and a later change removes it.

## What the minter does

- Signs with the issuer's own Ed25519 key, under this format and nothing else.
- Mints `aud`, `iat` and `exp` on every grant, and refuses to mint a grant whose `exp − iat` is
  over 900 seconds, so the failure shows in the control plane, not on the turn.
- Mints `pod` and `egress` when it can (requests 13 and 25), and before the gateway requires them.
- Encodes each part canonically, and signs the encoded parts exactly as they will be sent.

## Example

This example uses the key of RFC 8032, section 7.1, TEST 1, which is published and must never be
used for anything but tests. Its private key (the 32-byte seed) is
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`. Ed25519 signatures are
deterministic, so a minter given that key and the claims below produces exactly this grant.

<!-- example: values -->
```text
public key   d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
key ID       hW155tuyeHx1NSCeNeObWA
deployment   switchboard-otto
now          1800000300
digest       9c5d7cea02d64460dcd18dcd8c7005009891242526710852fd2704586e8f7f5d
```

The public key as a key file holds it:

<!-- example: key file -->
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----
```

The claims, shown indented here. The bytes signed are the compact form, with no spaces or line
breaks, members in this order:

<!-- example: claims -->
```json
{
  "aud": ["otto-gateway", "switchboard-otto"],
  "iat": 1800000000,
  "exp": 1800000600,
  "team": "payments",
  "tools": ["github_get_pr", "github_create_pr"],
  "epoch": 7,
  "sid": "session-1",
  "tid": "turn-1",
  "eid": "execution-1",
  "actor": "requester@example.test",
  "pod": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "egress": "sealed"
}
```

The grant, broken into lines of at most 64 characters here; it has no line breaks:

<!-- example: grant -->
```text
v3.hW155tuyeHx1NSCeNeObWA.
eyJhdWQiOlsib3R0by1nYXRld2F5Iiwic3dpdGNoYm9hcmQtb3R0byJdLCJpYXQi
OjE4MDAwMDAwMDAsImV4cCI6MTgwMDAwMDYwMCwidGVhbSI6InBheW1lbnRzIiwi
dG9vbHMiOlsiZ2l0aHViX2dldF9wciIsImdpdGh1Yl9jcmVhdGVfcHIiXSwiZXBv
Y2giOjcsInNpZCI6InNlc3Npb24tMSIsInRpZCI6InR1cm4tMSIsImVpZCI6ImV4
ZWN1dGlvbi0xIiwiYWN0b3IiOiJyZXF1ZXN0ZXJAZXhhbXBsZS50ZXN0IiwicG9k
IjoiMGY4ZmFkNWItZDljYi00NjlmLWExNjUtNzA4Njc3Mjg5NTBlIiwiZWdyZXNz
Ijoic2VhbGVkIn0.
OTC9obUxY_Dz_NOseI6E_mCExweb4e8XS1O__Tf70luGmR9P1uvFZNAoWH3N1pnA
klsBmYEuxmg7mtBcZ-_JCw
```

It is 512 bytes long. Presented at deployment `switchboard-otto` at the time above, it verifies.
Its claims part has 3 more characters than a multiple of 4, so its last character, `0`, has 2
unused bits, which are zero. `1`, `2` or `3` in its place would decode to the same bytes, but the
signature covers the characters, so that grant fails at step 6. The signature part is not covered
by the signature: its last character, `w`, has 4 unused bits, and any of `x`, `y`, `z`, `0` to
`9`, `-` or `_` in its place decodes to the same signature, which verifies, so that grant is
refused at step 7, with the digest of the grant as presented.

## Compared with `v1`

| | `v1` (Otto today) | `v3` |
| --- | --- | --- |
| Signature | HMAC-SHA256 under a shared secret | Ed25519; the gateway holds only the public key |
| Domain prefix | `otto/gateway-turn-grant/v1` and 0x00 | `otto/gateway-turn-grant/v3` and 0x00 |
| Key ID | hexadecimal, 6 bytes of a hash of the secret | base64url, 16 bytes of a hash of the public key |
| Encoding | unpadded base64url | canonical unpadded base64url, checked |
| New claims | | `aud`, `iat`, and later `pod` and `egress` |
| Lifetime | until `exp`, no leeway | `iat` and `exp` with 30 s of leeway, at most 15 minutes |
