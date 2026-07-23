# JWT, key rotation, and JWKS

## TL;DR + mental model

A **JWT** (JSON Web Token) is a compact, signed piece of text that carries claims — "this user is
`alice`, this token expires at `1700000000`" — that any recipient can read and verify without asking
the issuer. **JWKS** (JSON Web Key Set) is a small JSON document, published at a well-known URL, that
lists the public keys a verifier needs to check those signatures. **Key rotation** is the practice of
periodically retiring an old signing key for a fresh one, without breaking tokens that are already in
flight.

The mental model that ties all three together: a JWT is a **sealed envelope with a wax stamp**.
Anyone can open the envelope and read the letter inside (the claims aren't encrypted, just signed) —
but only someone holding the matching stamp could have sealed it that way. JWKS is the **public
directory of stamps**: "here is what Alice's official stamp currently looks like, so you can check
any envelope that claims to be from her." Key rotation is periodically **switching to a new stamp**
while keeping the old one listed in the directory just long enough that envelopes already sealed with
it still check out.

Everything below unpacks that: why this design exists, exactly how the pieces fit together, runnable
examples, the mistakes people make, and when to reach for something else entirely.

## Why it exists

Before JWT, the common way to keep a user "logged in" across requests was a **server-side session**:
the server generates a random session ID, stores the session data (who the user is, what they can do)
in a database or in-memory store, and hands the client just the ID as a cookie. Every request, the
server looks the ID up. That works, but it means every service that needs to check "who is this?" has
to hit that shared session store — which becomes a bottleneck and a single point of failure once you
have more than one service, and gets awkward across different domains or organizations.

JWT's idea: instead of handing the client an opaque ID and keeping the actual data server-side, put
the data itself (the claims) directly into the token, and **sign** it. Any service that receives the
token can verify the signature and trust the claims inside — no database round-trip, no shared session
store, no coordination needed between services as long as they all trust the same signer. This makes
JWTs a good fit for **stateless, cross-service authentication and authorization**.

Signing, not encrypting, is the key design choice: a JWT proves the claims weren't *tampered with*
and *came from the issuer*, but doesn't hide them from whoever holds the token. That is deliberate —
the "wax stamp," not a locked box.

That signature is only as trustworthy as the key that produced it. If a signing key is ever
compromised, every token it ever signed (until it expires) is forgeable. **Key rotation** exists to
bound that blast radius: rotate keys on a schedule (and immediately on suspected compromise), and an
attacker who steals a key only gets a limited window before it's retired. JWKS exists to make
rotation possible *without breaking anything*: it gives verifiers a way to discover "which public key
should I check this particular token against" even as the answer changes over time.

## How it works

### The token itself

A JWT is three base64url-encoded segments joined by dots: `header.payload.signature`.

- **Header** — a small JSON object naming the signing algorithm (`alg`, e.g. `RS256`) and, critically
  for rotation, which key was used (`kid`, a "key ID").
- **Payload** — the claims. Some are standardized: `iss` (issuer), `sub` (subject — usually the user
  ID), `aud` (audience — who the token is intended for), `exp` (expiry, a Unix timestamp), `iat`
  (issued-at). The rest are whatever the application needs.
- **Signature** — computed over the header and payload, using the algorithm named in `alg` and a
  signing key.

A verifier splits the token on its dots, recomputes the signature over `header.payload` using the key
it believes corresponds to `alg`/`kid`, and compares. If it matches *and* the claims (`exp`, `iss`,
`aud`, …) check out, the token is accepted.

### Symmetric vs. asymmetric signing — why it matters for JWKS

JWTs can be signed two different ways:

- **Symmetric (HMAC, e.g. `HS256`)** — one secret both signs and verifies. Every verifier needs that
  exact secret, which means every verifier is also trusted to *mint* valid tokens. Fine for a single
  service checking its own tokens; unworkable once multiple independent services need to verify
  tokens they didn't issue, because now they all share a secret that can forge tokens.
- **Asymmetric (RSA or ECDSA, e.g. `RS256`, `ES256`)** — a private key signs, a mathematically
  related but distinct public key verifies. The issuer keeps the private key secret; the public key
  can be handed out freely, because knowing it doesn't let you forge a signature.

Asymmetric signing is what makes JWKS *make sense*: because the verification key is public by design,
it's safe to publish it at a well-known HTTP endpoint for anyone to fetch. That's exactly what a JWKS
is.

### JWKS: the public key directory

A **JWKS** is a JSON document shaped like:

```json
{
  "keys": [
    { "kty": "RSA", "kid": "2026-01", "use": "sig", "alg": "RS256", "n": "...", "e": "..." },
    { "kty": "RSA", "kid": "2026-07", "use": "sig", "alg": "RS256", "n": "...", "e": "..." }
  ]
}
```

Each entry is a **JWK** (JSON Web Key) — one public key plus the metadata needed to identify and use
it. `kid` is the field that ties a specific JWT back to a specific entry in this list: the token's
header says `"kid": "2026-07"`, and the verifier looks up that exact entry to know which public key
(and algorithm) to check the signature against.

Issuers conventionally publish this document at a predictable path — commonly
`/.well-known/jwks.json` — so verifiers (and libraries) can find it without out-of-band
configuration. That literal path is convention, not a spec requirement: OpenID Connect Discovery
formalizes key discovery differently — it mandates a *discovery document* at
`/.well-known/openid-configuration`, which itself contains a `jwks_uri` field pointing at wherever the
JWKS actually lives. Verifiers **cache** the fetched JWKS (fetching it on every single token check
would be needlessly slow and puts load on the issuer) and refresh it periodically or when they hit an
unfamiliar `kid`.

### The end-to-end flow

1. Issuer holds a private signing key and publishes the matching public key in its JWKS.
2. Issuer signs a JWT with that private key, stamping the header with the key's `kid`.
3. Client sends the JWT to some service.
4. That service, acting as verifier, fetches (or reads from its cache) the issuer's JWKS.
5. It finds the JWK whose `kid` matches the token header, uses that public key to check the
   signature, and validates the claims (`exp`, `aud`, etc.).
6. If everything checks out, the service trusts the claims — no call back to the issuer needed.

### Key rotation mechanics

Rotation means: introduce a new keypair, retire the old one, without a moment where a still-valid
token fails to verify. The sequence:

1. **Generate** a new keypair, and pick it a new `kid`.
2. **Publish** the new public key into the JWKS *alongside* the old one — the JWKS now lists both.
3. **Switch** the issuer to sign new tokens with the new private key (new tokens now carry the new
   `kid`).
4. **Overlap window**: keep the *old* public key in the JWKS for at least as long as the longest TTL
   any token signed with it might still have. A token signed 2 minutes before rotation with a 15-minute
   `exp` still needs the old key to be verifiable for those remaining 13 minutes.
5. **Retire**: once nothing still-valid could have been signed with the old key, remove it from the
   JWKS. Only now is the old private key safe to destroy.

The overlap window is the entire point: rotate the *signing* key immediately, but keep the *old
verification* key around until every token it could have produced has naturally expired.

## Worked examples

These use [`PyJWT`](https://pyjwt.readthedocs.io/) for encoding/decoding and the
[`cryptography`](https://cryptography.io/) package for RSA keys — install with
`pip install pyjwt cryptography`. The three snippets below build on each other in one continuous
session — run them in order (e.g. paste each into the same REPL or script), since later ones reuse
names (`public_key`, `token`, `verify`, `public_key_to_jwk`) defined earlier.

### 1. Sign and verify a JWT with an RSA keypair

```python
import time
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

token = jwt.encode(
    {"sub": "alice", "iat": int(time.time()), "exp": int(time.time()) + 900},
    private_key,
    algorithm="RS256",
    headers={"kid": "key-1"},
)
print(token)  # header.payload.signature, base64url-encoded

claims = jwt.decode(token, public_key, algorithms=["RS256"])
print(claims)  # {'sub': 'alice', 'iat': ..., 'exp': ...}
```

Note what `jwt.decode` needed: the *public* key and the algorithm — never the private key. That
separation is exactly what lets the public half live in a JWKS anyone can fetch.

### 2. Build a JWKS entry and verify by looking up `kid`

```python
import jwt
from jwt.algorithms import RSAAlgorithm

def public_key_to_jwk(public_key, kid):
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)  # RFC 7517 JWK, as a dict
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return jwk

jwks = {"keys": [public_key_to_jwk(public_key, "key-1")]}

def verify(token, jwks):
    header = jwt.get_unverified_header(token)
    matching = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    signing_key = jwt.PyJWK.from_dict(matching).key
    return jwt.decode(token, signing_key, algorithms=[header["alg"]])

print(verify(token, jwks))
```

This is the core of any JWKS-based verifier: read the `kid` out of the token's header (without
trusting it yet), find the matching public key in the JWKS, *then* verify.

### 3. Simulate a rotation window

```python
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

def new_signer(kid):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key(), kid

old_priv, old_pub, old_kid = new_signer("2026-01")
new_priv, new_pub, new_kid = new_signer("2026-07")

# JWKS during the overlap window lists BOTH keys.
jwks = {"keys": [
    public_key_to_jwk(old_pub, old_kid),
    public_key_to_jwk(new_pub, new_kid),
]}

def sign(private_key, kid):
    now = int(time.time())
    return jwt.encode(
        {"sub": "alice", "iat": now, "exp": now + 900},
        private_key, algorithm="RS256", headers={"kid": kid},
    )

old_token = sign(old_priv, old_kid)     # issued just before rotation
new_token = sign(new_priv, new_kid)     # issued just after rotation

# Both still verify — that's the whole point of the overlap window.
assert verify(old_token, jwks)["sub"] == "alice"
assert verify(new_token, jwks)["sub"] == "alice"
```

Only after every token signed with `old_kid` has passed its `exp` is it safe to drop that entry from
`jwks["keys"]`.

## Common pitfalls & gotchas

- **Algorithm-confusion attacks.** If a verifier isn't pinned to an expected algorithm, an attacker
  can present an `HS256`-signed token whose "secret" is actually the issuer's known *public* RSA key —
  several real-world libraries were tricked into accepting this as valid HMAC (first widely disclosed
  by Tim McLean in 2015, and now a named risk in [RFC 8725, the JWT security BCP](https://www.rfc-editor.org/rfc/rfc8725)).
  Always pass an explicit `algorithms=[...]` allow-list to `decode`, never derive it from the token's
  own `alg` header — PyJWT's docs call this out directly. Never accept `alg: none`.
- **Rotating faster than your longest token TTL.** If access tokens live for 15 minutes and you retire
  the old JWKS entry after 5, every token issued in the last 10 minutes suddenly fails verification.
  The overlap window must be at least as long as the longest-lived token that key could have signed.
- **Skipping the overlap window entirely.** Swapping the JWKS to only the new key at the same instant
  you switch signers guarantees a burst of failed verifications for any token still in flight.
- **Not caching the JWKS.** Fetching it on every single verification is slow and needlessly loads the
  issuer; but caching forever is just as broken, because a verifier with a stale cache won't know
  about a newly rotated key. Cache with a sensible TTL, and refresh early when an unrecognized `kid`
  shows up.
- **No handling for an unknown `kid`.** If a verifier can't find the `kid` in its cached JWKS, it
  should refresh the JWKS once (in case rotation just happened) before giving up — not silently
  reject, and not fall back to some other key.
- **Treating a JWT like a session you can revoke.** Because verification doesn't call back to the
  issuer, there's no cheap way to invalidate one specific already-issued JWT before it expires. Design
  around this (short TTLs, a separate revocation/deny-list if you truly need it) rather than assuming
  you can "log a token out."

## When to use / when not to

JWTs signed with asymmetric keys and verified via JWKS are a good fit when:

- Multiple independent services need to verify tokens without a shared secret or a call back to the
  issuer (microservices, third-party API consumers, federated identity).
- Tokens are short-lived, so the "can't revoke early" tradeoff is acceptable.

Reach for something else when:

- You need to revoke access **immediately** (ban a user right now, kill a compromised session) —
  server-side sessions or a checked-on-every-use opaque token give you a single place to flip
  "revoked," which a self-contained signed JWT does not.
- It's a single service verifying its own tokens with no one else involved — a symmetric HMAC secret
  (or even just a server-side session) is simpler and there's no rotation-across-many-verifiers
  problem to solve.
- The token needs to carry a large amount of data — JWTs are sent on every request, and every byte in
  them is bandwidth; an opaque reference to server-side state scales better here.
- **Refresh tokens** specifically are commonly issued as opaque, server-side-tracked tokens (not
  JWTs) precisely because they're long-lived and revocability matters more for them than for short-lived
  access tokens.

## Quick reference

| Concept | Meaning |
|---|---|
| JWT structure | `header.payload.signature`, each segment base64url-encoded |
| `alg` (header) | Signing algorithm, e.g. `RS256`, `ES256`, `HS256` |
| `kid` (header) | Which key (from the JWKS) signed this token |
| `iss` | Issuer |
| `sub` | Subject — the entity the token is about (usually a user ID) |
| `aud` | Audience — intended recipient(s) |
| `exp` / `iat` | Expiry / issued-at, Unix timestamps |
| JWK | One public key + metadata (`kty`, `kid`, `use`, `alg`, `n`/`e` for RSA) |
| JWKS | `{"keys": [...]}` — a set of JWKs, published for verifiers to fetch |
| Well-known path | Conventionally `/.well-known/jwks.json` |

**Rotation checklist:**

1. Generate new keypair + new `kid`.
2. Add the new public key to the JWKS (old key stays too).
3. Switch the signer to the new private key.
4. Wait out the old key's overlap window (≥ longest token TTL it could have signed).
5. Remove the old key from the JWKS; only then destroy the old private key.

## Sources

- [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7517 — JSON Web Key (JWK) and JWK Set](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [PyJWT documentation](https://pyjwt.readthedocs.io/)
- [`cryptography` package documentation](https://cryptography.io/)
- [PortSwigger — JWT attacks: algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
