# IAM Base Service — Design

## 1. Problem & context

`iam-base` is a standalone Authentication & Identity Management service, meant to be reused across
all of the author's other projects as the one place that owns user identity. Phase 1 scope: email +
password registration/login, JWT access + refresh tokens. Consuming projects never store credentials
themselves — they call this service to authenticate, then verify the access tokens it issues on their
own.

Constraints that shaped this design: solo maintainer, one team, one deploy unit; low expected traffic
initially; self-hosted (Docker, not a managed cloud IAM product); Go, matching this repo's existing
harness (`CLAUDE.md`).

## 2. Domain & ubiquitous language

- **Account** — a registered identity (email + credential). Not called "User" so the model has room
  for future non-human principals (service accounts) without a rename.
- **Credential** — the account's password hash, hashing algorithm, and algorithm version (so future
  re-hashing on login can upgrade the algorithm without a migration).
- **RefreshTokenFamily** — the chain of refresh tokens produced by successive rotations for one
  login session. Reusing a superseded member of the family signals theft and revokes the whole family.
- **AccessToken** — a short-lived, signed JWT asserting the account's identity to consuming services.
- **JWKS** — the published set of public keys consuming services fetch to verify access tokens
  themselves, without calling back into this service.

## 3. Subdomain map

Relative to the author's other projects, **Identity/Auth is a generic subdomain** — a solved problem,
not a differentiator (see `bounded-contexts`). That argues for a lean, proven-pattern implementation
over heavy bespoke modelling. It does not argue against correctness: this service is a trust anchor
for everything else, so its few real invariants (credential handling, refresh-token rotation) are
still worth enforcing deliberately. There is exactly one subdomain here — **Identity** — classified
generic-but-security-critical; no second subdomain competes for attention within this repo.

## 4. Recommended architecture — and why

**Single-module hexagonal service, tactical DDD only on the two aggregates with real invariants.**
One Go module (one bounded context: Identity), internally layered `domain` / `app` / `infra`, three
layers deep, dependencies pointing inward. Not a modular monolith of several bounded contexts — there
is only one context here, so splitting further would be ceremony with no payoff.

**Why:** email uniqueness, password hashing, and — the one piece of real state-machine logic —
refresh-token rotation with reuse detection are genuine invariants that need one enforced home; a
thin CRUD/script design risks that logic scattering across handlers, the failure mode this service can
least afford since every other project will trust it. But it's a generic subdomain with one team and
one deploy unit, so a full multi-module monolith (published interfaces, integration events between
internal modules) buys isolation nothing here needs yet.

**Alternatives considered:**
1. **Thin CRUD/script** (a `users` table + handlers, no aggregates) — ruled out: rotation/reuse
   detection and credential handling need one enforced home, not logic spread across handlers.
2. **Full modular monolith** (separate `accounts`/`sessions` modules with published interfaces) —
   ruled out for phase 1: the "contexts" are tightly coupled (no auth without an account) and there's
   one team; revisit only if this grows into multi-tenant/OAuth2 with per-client scopes.
3. **Chosen: single hexagonal module, tactical DDD on `Account` and `RefreshTokenFamily` only.**

## 5. Module / bounded-context breakdown

One module, one bounded context: **`identity`**. It owns all its own data (accounts, credentials,
refresh tokens) — no other module or service reads those tables directly; everything else integrates
through the HTTP API and JWKS (see §8).

```
cmd/server/                    — composition root: config load, wire adapters, start HTTP server
internal/identity/
  domain/                      — Account, Credential, RefreshTokenFamily, value objects, domain errors
  app/
    command/                  — RegisterAccount, Authenticate, RotateRefreshToken, RevokeSession
    query/                    — GetJWKS (read port + DTO; bypasses the domain)
    ports.go                  — AccountRepository, RefreshTokenRepository, PasswordHasher,
                                 TokenIssuer, Clock (all interfaces; no concrete types)
  infra/
    httpapi/                  — REST handlers, routing, middleware, JWKS response
    postgres/                 — repository implementations (pgx + sqlc), migrations
    jwt/                      — TokenIssuer implementation (golang-jwt), signing-key management
    passwordhash/             — PasswordHasher implementation (argon2id)
deployments/
  Dockerfile
  docker-compose.yml           — service + postgres
```

## 6. Layers & CQRS per module

- **`domain`** — pure, no DB/clock/HTTP. `Account` and `RefreshTokenFamily` aggregates enforce their
  invariants; ports (`AccountRepository`, `RefreshTokenRepository`) are declared here, implemented in
  `infra`.
- **`app` command side** — `RegisterAccount`, `Authenticate` (login), `RotateRefreshToken` (refresh),
  `RevokeSession` (logout): load/create the aggregate through its port, invoke domain behaviour,
  persist, done in one transaction per aggregate.
- **`app` query side** — `GetJWKS` returns the current public key set as a DTO; it's a pass-through
  over infra key storage, not a domain read, so it skips the domain entirely.
- **`infra`** — driven adapters (Postgres repositories, JWT issuer, password hasher) and driving
  adapters (HTTP handlers dispatching to command/query handlers). One datastore (Postgres); no event
  sourcing, no separate read store.

## 7. Domain-model sketch

- **`Account`** (aggregate root) — `AccountID`, `Email` (value object: validated, normalized,
  unique), `Credential` (value object: hash + algo + version), `Status` (active/disabled). Invariant:
  email uniqueness enforced by a DB unique constraint, surfaced up as a domain error
  (`ErrEmailAlreadyRegistered`), not a 500.
- **`RefreshTokenFamily`** (aggregate) — `FamilyID`, `AccountID`, current token hash, generation
  counter, expiry. Invariant: `Rotate()` consumes the current token and advances the generation in the
  same family; presenting a token from an earlier generation raises `ErrTokenReuseDetected` and
  revokes the entire family (theft signal) — this is the one real state machine in the service.
- **`AccessToken`** (value, not persisted) — short-lived signed JWT, `sub` = AccountID, standard
  claims; verified by consumers via JWKS. No domain rules beyond expiry and claim shape.
- Everything else (JWKS serving, health checks) is plain infrastructure — no aggregates needed.
- No cross-aggregate transactions: registering creates one `Account`; logging in reads one `Account`
  and creates one `RefreshTokenFamily` in its own save — never both in one commit.

## 8. Integration / context map

Consuming projects are the only neighbour. The integration pattern is **open-host service /
published language**: a stable, versioned REST contract (`/v1/auth/*`) plus a standard JWKS endpoint
(`/.well-known/jwks.json`), so any consumer in any language can integrate without a bespoke
integration per project. Consumers never see this service's internal model — they only see issued
JWTs (standard claims) and the public keys to verify them.

## 9. Cross-cutting

- **API contract** — REST/JSON, resource-oriented under `/v1/auth/*`
  (`register`, `login`, `refresh`, `logout`) plus `/.well-known/jwks.json`; governed by `api-design`.
- **Persistence** — Postgres via `pgx`/`sqlc`, one aggregate per transaction, migrations via a
  standard tool (e.g. `golang-migrate`); governed by `data-access-patterns` and `safe-schema-changes`.
- **Config/secrets** — JWT signing keys, DB DSN, token TTLs from environment (12-factor), validated at
  startup; governed by `config-and-secrets`. No secrets committed to the repo.
- **Resilience** — DB calls carry a context deadline; graceful shutdown drains in-flight requests;
  governed by `resilience-and-timeouts`.
- **Recommended libraries** — `golang-jwt/jwt/v5` (JWT signing/verification, JWKS-friendly),
  `alexedwards/argon2id` (password hashing), `jackc/pgx` + `sqlc` (Postgres access),
  standard `net/http` + `go-chi/chi` (routing).
- **Testing** — exercise the HTTP API boundary against a real Postgres (e.g. via testcontainers), not
  mocked; governed by `backend-testing`/`tdd`.

## 10. Build order (the slices)

Two vertically-sliced, independently shippable PRs (per `divide-and-conquer`):

1. **Slice 1 — Register & login (walking skeleton).** `Account` domain + Postgres migration/repo +
   `argon2id` hashing + `POST /v1/auth/register`, `POST /v1/auth/login` issuing an access-token-only
   JWT + `GET /.well-known/jwks.json` + Dockerfile/docker-compose + env-based config. Proves the whole
   seam end to end: a consumer can register, log in, and verify the token itself. This is the
   foundation the second slice extends.
2. **Slice 2 — Refresh & logout.** `RefreshTokenFamily` aggregate + refresh-token table +
   `POST /v1/auth/refresh` (rotate, single-use, reuse detection) + `POST /v1/auth/logout` (revoke a
   family). Extends slice 1's login response to also return a refresh token.

Each slice is a candidate for its own `/revai:feature` run, with its own full Ship gate (tests, review,
PR) — no shortcutting between them. Phase-2 work (email verification, password reset, per-client
scopes) is explicitly out of scope for this design; revisit as a separate design increment once phase
1 is running.

## 11. Open questions & risks

- Exact signing algorithm: RS256 vs ES256, and how the private signing key is generated/stored/rotated
  (a mounted secret vs. a KMS is overkill for phase 1, but the rotation story should be decided before
  slice 1 ships).
- Access token TTL and refresh token TTL defaults (common starting point: minutes for access, days for
  refresh — to be fixed as a config default in slice 1).
- Login brute-force protection (rate limiting / lockout) — deferred as a concern, not forgotten;
  should land no later than slice 1 given this is a public-facing credential endpoint.
- Whether `Account` needs anything beyond email/credential/status for phase 1 (e.g. `created_at` only,
  or more) — kept minimal unless a concrete need appears.
