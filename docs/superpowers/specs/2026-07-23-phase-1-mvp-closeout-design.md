# Phase 1 MVP Closeout — Design

## 1. Context

Phase 1 (per `docs/design/iam-base-service.md`) is functionally complete on `main`: register/login
(slice 1), refresh/logout with reuse detection (slice 2), and code-first OpenAPI docs (Huma). Build,
`go test ./...`, `gofmt -l .`, and `golangci-lint run` are all clean, and the stack has been
live-verified end to end via docker-compose.

An audit for "what's left to close this phase and start using it" surfaced several deferred items.
One — `IPRateLimiter`'s unbounded map growth — turned out to already be fixed (TTL-based eviction
landed in a later commit than the ledger note describes) and needs no further work. Three real gaps
remain, and this spec covers all three:

1. No signing-key rotation story — the JWT issuer supports exactly one key; rotating it today means
   redeploying and instantly invalidating every outstanding token.
2. No way for docker-compose (or any future orchestrator) to tell if the `identity` service itself is
   up, and the stack doesn't restart itself after a crash or host reboot.
3. No README — nothing documents how to generate keys, configure, or run the service.

Explicitly out of scope (deferred, not forgotten): API contract documentation beyond the existing
`/docs`/`/openapi.json`, a consumer integration walkthrough, and digest-pinning base images.

## 2. Multi-key JWT signing (rotation support)

**Current state:** `config.JWTPrivateKeyPath` + `config.JWTKeyID` load exactly one RSA private key.
`RSAIssuer` signs every token with it and `JWKS()` publishes exactly that one public key.

**Target shape:**

- Config replaces the single-file settings with a **directory of PEM files**, one per key, filename
  = key ID (e.g. `keys/1.pem`, `keys/2.pem`). New env vars: `JWT_KEYS_DIR` (directory path) and
  `JWT_ACTIVE_KEY_ID` (which file signs new tokens). `config.Load()` fails fast if `JWT_ACTIVE_KEY_ID`
  has no matching file in the directory.
- `jwt.LoadRSAPrivateKeys(dir string) (map[string]*rsa.PrivateKey, error)` replaces
  `LoadRSAPrivateKey`, reading every `*.pem` file in `dir` into a `kid -> key` map. Kid is the
  filename without its `.pem` extension.
- `RSAIssuer` holds the full key map plus `activeKeyID`:
  - `Issue()` signs only with `keys[activeKeyID]`, unchanged claim shape/TTL behaviour otherwise.
  - `JWKS()` now emits one entry per key in the map, not just the active one, so tokens signed under
    a since-retired key still verify against the published set.
- **Rotation runbook** (documented in the README): generate a new PEM into the keys directory, flip
  `JWT_ACTIVE_KEY_ID` to it, redeploy — JWKS now serves both keys. Once the refresh-token TTL has
  fully elapsed (nothing signed under the old key can still be presented), delete the old PEM and
  redeploy again to retire it from JWKS.
- No scheduler, no automated key generation — rotation stays a deliberate, manual operator action,
  consistent with the design doc's "solo maintainer, one deploy unit" constraint.

**Testing:** `LoadRSAPrivateKeys` — multiple files, missing directory, malformed PEM. `RSAIssuer`:
`JWKS()` returns one entry per loaded key; `Issue()` always signs with the active key regardless of
map iteration order. Composition root: fails fast when `JWT_ACTIVE_KEY_ID` isn't present in the
loaded key map.

## 3. Health-check endpoint + restart policy

- Add `GET /healthz`, a plain `net/http` handler mounted directly on the chi mux — not a Huma
  operation, so it carries no schema, isn't rate-limited, and doesn't appear in the public OpenAPI
  surface. Pure liveness: returns `200 OK` whenever the process can handle a request; no DB ping.
- Wire it into `deployments/docker-compose.yml`'s `identity` service via a `healthcheck:` block using
  `wget` (already available in the `alpine` base image), matching the existing Postgres healthcheck
  style.
- Add `restart: unless-stopped` to both the `postgres` and `identity` services.

**Testing:** a handler test asserting `GET /healthz` returns 200 with no dependencies wired up.

## 4. README.md (run & deploy only)

Scope is deliberately narrow — how to run and deploy this instance, not the API contract (already
served live at `/docs`) and not a consumer integration guide (no consumer exists yet). Sections, in
order:

1. One paragraph on what the service is, pointing to `docs/design/iam-base-service.md` for the full
   rationale.
2. Prerequisites (Docker, Docker Compose).
3. Generating signing keys: `openssl genrsa -traditional` output into
   `deployments/keys/<kid>.pem`, reflecting the multi-key layout from §2.
4. Environment variable reference table covering every `config.Config` field, marking which are
   required vs. defaulted (updated for `JWT_KEYS_DIR`/`JWT_ACTIVE_KEY_ID` replacing the old
   single-key vars).
5. Running via `docker compose up` — migrations run automatically on boot (existing composition-root
   behaviour, unchanged).
6. One line pointing at `/docs` for the live API reference.

## 5. What doesn't change

- No change to the register/login/refresh/logout domain logic, HTTP contract, or error format.
- No change to rate limiting (already fixed).
- `CLAUDE.md` is stale (describes the repo as empty) — worth a follow-up fix, but tracked separately
  since it's pure documentation hygiene, not part of this closeout's scope.

## 6. Risks / open questions

- Changing `JWT_PRIVATE_KEY_PATH`/`JWT_KEY_ID` to `JWT_KEYS_DIR`/`JWT_ACTIVE_KEY_ID` is a breaking
  config change. Acceptable pre-production with a solo operator; `docker-compose.yml` and any local
  `.env` need updating in the same change.
- `/healthz` liveness-only means the container can report healthy while its DB connection is down.
  Accepted for phase 1 — no orchestrator currently depends on readiness semantics.
