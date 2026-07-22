# Slice 2 — Refresh & Logout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add refresh-token rotation with reuse detection and session logout to iam-base, extending
slice 1's login response to also return a refresh token.

**Architecture:** One new aggregate, `RefreshTokenFamily`, in the existing single `identity` bounded
context (no new module). Same three-layer hexagonal shape as slice 1: a pure `domain` aggregate, two
new `app/command` handlers (`RotateRefreshToken`, `RevokeSession`) plus an extension of the existing
`Login` handler, and `infra` adapters (a new Postgres table/repo, a new opaque-token-generator
adapter, two new HTTP handlers). No new query side, no new module, no cross-aggregate transactions —
login reads one `Account` and separately saves one new `RefreshTokenFamily`, never both in one commit.

**Tech Stack:** Go 1.26, `jackc/pgx/v5` (Postgres), `golang-migrate/migrate/v4` (migrations), stdlib
`crypto/rand` + `crypto/sha256` for the refresh-token secret (no new dependency), `go-chi/chi/v5`
(routing), `testcontainers-go/modules/postgres` (repo tests against a real Postgres).

## Global Constraints

- Module/bounded context: single `identity` context — everything lives under `internal/{domain,app,infra}`,
  no new top-level module or per-context folder (see `docs/design/iam-base-service.md` §5).
- Layers touched: `domain` (new aggregate + port), `app` command-side only (no new query — see
  `hexagonal-architecture`), `infra` (Postgres, HTTP, a new token-generator adapter, config,
  composition root).
- In-scope revai skills: `domain-modeling` (the aggregate and its invariants), `data-access-patterns` +
  `safe-schema-changes` (new table + migration), `api-design` (two new `/v1/auth/*` endpoints),
  `error-handling-and-logging` (the manual-collapse error style below), `resilience-and-timeouts`
  (context deadlines on the new DB calls — inherited for free since every method takes `ctx` and the
  existing `pgxpool.Pool`/`http.Server` already carry request-scoped deadlines; no new timeout wiring
  needed).
- No cross-aggregate transactions: `Login`'s `Account` lookup and its new `RefreshTokenFamily` save
  are two separate repository calls, never combined in one DB transaction (design doc §7).
- Refresh tokens are opaque random strings, never JWTs — `jwt.RSAIssuer` is not touched.
- This is the last remaining slice for iam-base's phase 1 (design doc §10). No further slice is
  backlogged after this one; phase 2 (email verification, password reset, OAuth2 scopes) is a
  separate future design increment, out of scope here.
- Run `gofmt -w` on every file a task touches as part of that task's commit step, before `git add` —
  several steps below add entries to existing `var (...)` blocks (e.g. `domain/errors.go`) without
  hand-computing gofmt's exact column alignment; `gofmt -w` fixes that automatically so Task 14's
  final `gofmt -l .` gate has nothing left to flag.

## Named Decisions (resolved during Plan — flag any of these you want changed)

1. **Refresh/logout error style mirrors `LoginHandler`, not `RegisterAccountHandler`.** Every failure
   mode on `/v1/auth/refresh` (unknown family, expired, malformed, reused token) collapses into one
   generic `app.ErrInvalidRefreshToken` (401) — an attacker must not be able to distinguish "expired"
   from "reused" from "never existed" (same OWASP-style rationale as `LoginHandler`'s
   `ErrInvalidCredentials`). `/v1/auth/logout` is idempotent: revoking an already-revoked, malformed,
   or unknown family still returns success, since logout's only job is "make sure this session is not
   valid," which is already true in all of those cases.
2. **Refresh-token secret: stdlib `crypto/rand` (32 random bytes, base64url-encoded) + stdlib
   `crypto/sha256`, stored as the hash — no new dependency.** A refresh token is a high-entropy random
   secret, not a human password, so it needs neither salting nor a slow/adaptive hash (argon2id) —
   only protection against DB-dump replay, which a fast cryptographic hash already gives.
3. **The existing per-IP rate limiter (`IPRateLimiter`) is extended to cover `/v1/auth/refresh` and
   `/v1/auth/logout`.** Both are public-facing, credential-adjacent endpoints (refresh accepts a
   bearer secret) — design doc §11 flags rate limiting as a concern for "every public-facing
   credential endpoint," and slice 1 already scoped the limiter to register/login only.
4. **The opaque refresh token's wire format is `<familyID>.<secret>`** (family ID, then a literal
   `.`, then the base64url secret) so refresh/logout can look up the family in O(1) without a
   secondary index, and so `Rotate`'s hash-mismatch case can be attributed to a specific family
   (needed for reuse detection / family-wide revocation) rather than being an untraceable guess.

---

## File Structure

```
internal/domain/
  family_id.go                 — new: FamilyID value object
  family_id_test.go            — new
  refresh_token_family.go      — new: RefreshTokenFamily aggregate
  refresh_token_family_test.go — new
  errors.go                    — modify: 5 new domain errors
  events.go                    — modify: 3 new domain events
  repository.go                — modify: new RefreshTokenRepository port

internal/app/
  ports.go                     — modify: IDGenerator.NewFamilyID, new RefreshTokenGenerator port
  errors.go                    — modify: app.ErrInvalidRefreshToken
  command/
    login.go                   — modify: LoginHandler issues a RefreshTokenFamily too
    login_test.go               — modify
    refresh_fakes_test.go      — new: fakeRefreshTokenRepo, fakeTokenGenerator, fakeClock
    refresh_token.go            — new: parseRefreshToken/formatRefreshToken helpers
    refresh.go                  — new: RotateRefreshTokenHandler
    refresh_test.go             — new
    logout.go                   — new: RevokeSessionHandler
    logout_test.go              — new

internal/infra/
  idgen/
    idgen.go                   — modify: UUIDGenerator.NewFamilyID
    idgen_test.go               — new
  refreshtoken/
    generator.go                — new package: SHA256Generator adapter
    generator_test.go
  postgres/
    migrations/
      000002_create_refresh_token_families.up.sql   — new
      000002_create_refresh_token_families.down.sql — new
    refresh_token_repo.go        — new
    refresh_token_repo_test.go   — new
  httpapi/
    refresh_handler.go           — new
    refresh_handler_test.go      — new
    logout_handler.go            — new
    logout_handler_test.go       — new
    router.go                    — modify: add refresh/logout routes
  config/
    config.go                    — modify: RefreshTokenTTL
    config_test.go                — modify
  composition/
    composition.go                — modify: wire the new repo/adapter/handlers

deployments/
  docker-compose.yml              — modify: REFRESH_TOKEN_TTL env var
```

---

### Task 1: `FamilyID` value object

**Files:**
- Create: `internal/domain/family_id.go`
- Test: `internal/domain/family_id_test.go`

**Interfaces:**
- Produces: `domain.FamilyID` (struct), `domain.NewFamilyID(raw string) (FamilyID, error)`,
  `(FamilyID) String() string`, `(FamilyID) Equals(other FamilyID) bool`,
  `domain.ErrInvalidFamilyID` (error var).

- [ ] **Step 1: Write the failing test**

```go
// internal/domain/family_id_test.go
package domain

import "testing"

func TestNewFamilyID(t *testing.T) {
	id, err := NewFamilyID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("NewFamilyID() error = %v, want nil", err)
	}
	if id.String() != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("String() = %q, want the raw value", id.String())
	}
}

func TestNewFamilyID_RejectsEmpty(t *testing.T) {
	if _, err := NewFamilyID(""); err == nil {
		t.Error("NewFamilyID(\"\") error = nil, want error")
	}
}

func TestFamilyID_Equals(t *testing.T) {
	a, _ := NewFamilyID("same")
	b, _ := NewFamilyID("same")
	c, _ := NewFamilyID("different")

	if !a.Equals(b) {
		t.Error("Equals() = false for equal IDs, want true")
	}
	if a.Equals(c) {
		t.Error("Equals() = true for different IDs, want false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domain/... -run TestNewFamilyID -v`
Expected: FAIL — `undefined: NewFamilyID`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/domain/family_id.go
package domain

// FamilyID identifies a RefreshTokenFamily. The raw value is produced by an
// infra-provided app.IDGenerator adapter; domain only validates and holds it.
type FamilyID struct {
	value string
}

var _ ValueObject[FamilyID] = FamilyID{}

func NewFamilyID(raw string) (FamilyID, error) {
	if raw == "" {
		return FamilyID{}, ErrInvalidFamilyID
	}
	return FamilyID{value: raw}, nil
}

func (id FamilyID) String() string {
	return id.value
}

func (id FamilyID) Equals(other FamilyID) bool {
	return id.value == other.value
}
```

Also add the new error this depends on:

```go
// internal/domain/errors.go — add to the existing var (...) block
ErrInvalidFamilyID = errors.New("invalid family id")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domain/... -run 'TestNewFamilyID|TestFamilyID_Equals' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/family_id.go internal/domain/family_id_test.go internal/domain/errors.go
git commit -m "feat(domain): add FamilyID value object"
```

---

### Task 2: `RefreshTokenFamily` aggregate

**Files:**
- Create: `internal/domain/refresh_token_family.go`
- Test: `internal/domain/refresh_token_family_test.go`
- Modify: `internal/domain/errors.go` (4 more errors)
- Modify: `internal/domain/events.go` (3 new events)
- Modify: `internal/domain/repository.go` (new `RefreshTokenRepository` port)

**Interfaces:**
- Consumes: `FamilyID` (Task 1), `AccountID`, `AggregateRoot[ID]`/`Entity[ID]` (existing).
- Produces: `domain.RefreshTokenFamily` (aggregate), `domain.IssueFamily(id FamilyID, accountID
  AccountID, tokenHash string, expiresAt time.Time) (*RefreshTokenFamily, error)`,
  `domain.ReconstituteRefreshTokenFamily(id FamilyID, accountID AccountID, tokenHash string,
  generation int, expiresAt time.Time, revoked bool) *RefreshTokenFamily`,
  `(*RefreshTokenFamily) AccountID() AccountID`, `(*RefreshTokenFamily) CurrentTokenHash() string`,
  `(*RefreshTokenFamily) Generation() int`, `(*RefreshTokenFamily) ExpiresAt() time.Time`,
  `(*RefreshTokenFamily) Revoked() bool`,
  `(*RefreshTokenFamily) Rotate(now time.Time, presentedHash, newHash string, newExpiresAt
  time.Time) error`, `(*RefreshTokenFamily) Revoke() error`,
  `domain.RefreshTokenRepository` (port: `Save`, `FindByID`),
  errors `domain.ErrTokenReuseDetected`, `domain.ErrRefreshTokenExpired`,
  `domain.ErrRefreshTokenFamilyAlreadyRevoked`, `domain.ErrRefreshTokenFamilyNotFound`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/domain/refresh_token_family_test.go
package domain

import (
	"errors"
	"testing"
	"time"
)

func newTestFamily(t *testing.T) *RefreshTokenFamily {
	t.Helper()
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")
	family, err := IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("IssueFamily() error = %v, want nil", err)
	}
	return family
}

func TestIssueFamily(t *testing.T) {
	family := newTestFamily(t)

	if family.Generation() != 1 {
		t.Errorf("Generation() = %d, want 1", family.Generation())
	}
	if family.CurrentTokenHash() != "hash-gen-1" {
		t.Errorf("CurrentTokenHash() = %q, want %q", family.CurrentTokenHash(), "hash-gen-1")
	}
	if family.Revoked() {
		t.Error("a newly issued family must not be revoked")
	}
}

func TestIssueFamily_RecordsRefreshTokenFamilyIssuedEvent(t *testing.T) {
	family := newTestFamily(t)

	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	issued, ok := events[0].(RefreshTokenFamilyIssued)
	if !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyIssued", events[0])
	}
	if issued.FamilyID != family.ID() {
		t.Errorf("RefreshTokenFamilyIssued.FamilyID = %v, want %v", issued.FamilyID, family.ID())
	}
}

func TestReconstituteRefreshTokenFamily_DoesNotRecordEvent(t *testing.T) {
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")

	family := ReconstituteRefreshTokenFamily(id, accountID, "hash-gen-2", 2, time.Now().Add(time.Hour), false)

	if family.Generation() != 2 || family.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("ReconstituteRefreshTokenFamily() = %+v, want generation=2 hash=hash-gen-2", family)
	}
	if events := family.RecordedEvents(); len(events) != 0 {
		t.Errorf("ReconstituteRefreshTokenFamily() recorded %d events, want 0 — reconstitution is not a new fact", len(events))
	}
}

func TestRefreshTokenFamily_Rotate_Success(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()
	now := time.Now()
	newExpiresAt := now.Add(24 * time.Hour)

	if err := family.Rotate(now, "hash-gen-1", "hash-gen-2", newExpiresAt); err != nil {
		t.Fatalf("Rotate() error = %v, want nil", err)
	}
	if family.Generation() != 2 {
		t.Errorf("Generation() = %d, want 2", family.Generation())
	}
	if family.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("CurrentTokenHash() = %q, want %q", family.CurrentTokenHash(), "hash-gen-2")
	}
	if !family.ExpiresAt().Equal(newExpiresAt) {
		t.Errorf("ExpiresAt() = %v, want %v", family.ExpiresAt(), newExpiresAt)
	}

	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRotated); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRotated", events[0])
	}
}

func TestRefreshTokenFamily_Rotate_WrongHash_RevokesAndReportsReuse(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()
	now := time.Now()

	err := family.Rotate(now, "wrong-hash", "hash-gen-2", now.Add(24*time.Hour))
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() error = %v, want ErrTokenReuseDetected", err)
	}
	if !family.Revoked() {
		t.Error("Rotate() with a mismatched hash must revoke the whole family")
	}
	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRevoked); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRevoked", events[0])
	}
}

func TestRefreshTokenFamily_Rotate_AlreadyRevoked_ReportsReuse(t *testing.T) {
	family := newTestFamily(t)
	if err := family.Revoke(); err != nil {
		t.Fatalf("fixture Revoke: %v", err)
	}
	now := time.Now()

	err := family.Rotate(now, "hash-gen-1", "hash-gen-2", now.Add(24*time.Hour))
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() on an already-revoked family error = %v, want ErrTokenReuseDetected", err)
	}
}

func TestRefreshTokenFamily_Rotate_Expired(t *testing.T) {
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")
	family, err := IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("IssueFamily() error = %v, want nil", err)
	}

	err = family.Rotate(time.Now(), "hash-gen-1", "hash-gen-2", time.Now().Add(24*time.Hour))
	if !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("Rotate() on an expired family error = %v, want ErrRefreshTokenExpired", err)
	}
}

func TestRefreshTokenFamily_Revoke(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()

	if err := family.Revoke(); err != nil {
		t.Fatalf("Revoke() error = %v, want nil", err)
	}
	if !family.Revoked() {
		t.Error("Revoke() must mark the family revoked")
	}
	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRevoked); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRevoked", events[0])
	}
}

func TestRefreshTokenFamily_Revoke_RejectsAlreadyRevoked(t *testing.T) {
	family := newTestFamily(t)
	if err := family.Revoke(); err != nil {
		t.Fatalf("Revoke() error = %v, want nil", err)
	}

	if err := family.Revoke(); !errors.Is(err, ErrRefreshTokenFamilyAlreadyRevoked) {
		t.Errorf("Revoke() on an already-revoked family = %v, want ErrRefreshTokenFamilyAlreadyRevoked", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/domain/... -run 'RefreshTokenFamily' -v`
Expected: FAIL — `undefined: IssueFamily` (and the other undefined symbols)

- [ ] **Step 3: Write minimal implementation**

Add to `internal/domain/errors.go`'s existing `var (...)` block:

```go
ErrTokenReuseDetected             = errors.New("refresh token reuse detected")
ErrRefreshTokenExpired             = errors.New("refresh token expired")
ErrRefreshTokenFamilyAlreadyRevoked = errors.New("refresh token family already revoked")
ErrRefreshTokenFamilyNotFound       = errors.New("refresh token family not found")
```

Add to `internal/domain/events.go`:

```go
const (
	eventNameRefreshTokenFamilyIssued  = "identity.refresh_token_family_issued"
	eventNameRefreshTokenFamilyRotated = "identity.refresh_token_family_rotated"
	eventNameRefreshTokenFamilyRevoked = "identity.refresh_token_family_revoked"
)

var _ Event = RefreshTokenFamilyIssued{}

// RefreshTokenFamilyIssued is raised when a new RefreshTokenFamily is created (on login).
type RefreshTokenFamilyIssued struct {
	FamilyID  FamilyID
	AccountID AccountID
}

func (e RefreshTokenFamilyIssued) EventName() string {
	return eventNameRefreshTokenFamilyIssued
}

var _ Event = RefreshTokenFamilyRotated{}

// RefreshTokenFamilyRotated is raised when a family's refresh token is rotated.
type RefreshTokenFamilyRotated struct {
	FamilyID FamilyID
}

func (e RefreshTokenFamilyRotated) EventName() string {
	return eventNameRefreshTokenFamilyRotated
}

var _ Event = RefreshTokenFamilyRevoked{}

// RefreshTokenFamilyRevoked is raised when a family is revoked, either explicitly
// (logout) or defensively (a reused/superseded token was presented).
type RefreshTokenFamilyRevoked struct {
	FamilyID FamilyID
}

func (e RefreshTokenFamilyRevoked) EventName() string {
	return eventNameRefreshTokenFamilyRevoked
}
```

Add to `internal/domain/repository.go`:

```go
// RefreshTokenRepository is the write-repository port for the RefreshTokenFamily
// aggregate. The domain declares it; infra/postgres provides the adapter.
type RefreshTokenRepository interface {
	Save(ctx context.Context, family *RefreshTokenFamily) error
	FindByID(ctx context.Context, id FamilyID) (*RefreshTokenFamily, error)
}
```

Create `internal/domain/refresh_token_family.go`:

```go
package domain

import "time"

// RefreshTokenFamily is the chain of refresh tokens produced by successive
// rotations for one login session. Reusing a superseded member of the family
// signals theft and revokes the whole family.
type RefreshTokenFamily struct {
	AggregateRoot[FamilyID]
	accountID        AccountID
	currentTokenHash string
	generation       int
	expiresAt        time.Time
	revoked          bool
}

// IssueFamily creates a brand-new RefreshTokenFamily at generation 1, e.g. on login.
func IssueFamily(id FamilyID, accountID AccountID, tokenHash string, expiresAt time.Time) (*RefreshTokenFamily, error) {
	family := &RefreshTokenFamily{
		AggregateRoot:    NewAggregateRoot(id),
		accountID:        accountID,
		currentTokenHash: tokenHash,
		generation:       1,
		expiresAt:        expiresAt,
	}
	family.RecordEvent(RefreshTokenFamilyIssued{FamilyID: id, AccountID: accountID})
	return family, nil
}

// ReconstituteRefreshTokenFamily rebuilds a RefreshTokenFamily already known to
// exist — loaded from storage, not newly issued — so it does not raise
// RefreshTokenFamilyIssued. Repository-only caller.
func ReconstituteRefreshTokenFamily(id FamilyID, accountID AccountID, tokenHash string, generation int, expiresAt time.Time, revoked bool) *RefreshTokenFamily {
	return &RefreshTokenFamily{
		AggregateRoot:    NewAggregateRoot(id),
		accountID:        accountID,
		currentTokenHash: tokenHash,
		generation:       generation,
		expiresAt:        expiresAt,
		revoked:          revoked,
	}
}

func (f *RefreshTokenFamily) AccountID() AccountID {
	return f.accountID
}

func (f *RefreshTokenFamily) CurrentTokenHash() string {
	return f.currentTokenHash
}

func (f *RefreshTokenFamily) Generation() int {
	return f.generation
}

func (f *RefreshTokenFamily) ExpiresAt() time.Time {
	return f.expiresAt
}

func (f *RefreshTokenFamily) Revoked() bool {
	return f.revoked
}

// Rotate consumes the current token and advances the family to a new
// generation. now and newExpiresAt are supplied by the caller (app.Clock) so
// the domain stays clock-free. presentedHash not matching the family's
// current hash means either an already-superseded token or a forged one —
// either way it is treated as theft: the whole family is revoked and
// ErrTokenReuseDetected is returned instead of rotating.
func (f *RefreshTokenFamily) Rotate(now time.Time, presentedHash, newHash string, newExpiresAt time.Time) error {
	if f.revoked {
		return ErrTokenReuseDetected
	}
	if now.After(f.expiresAt) {
		return ErrRefreshTokenExpired
	}
	if presentedHash != f.currentTokenHash {
		f.revoked = true
		f.RecordEvent(RefreshTokenFamilyRevoked{FamilyID: f.ID()})
		return ErrTokenReuseDetected
	}
	f.currentTokenHash = newHash
	f.generation++
	f.expiresAt = newExpiresAt
	f.RecordEvent(RefreshTokenFamilyRotated{FamilyID: f.ID()})
	return nil
}

// Revoke ends the family outright (logout). Revoking an already-revoked
// family is rejected — callers to whom that must be a no-op (idempotent
// logout) check for ErrRefreshTokenFamilyAlreadyRevoked themselves.
func (f *RefreshTokenFamily) Revoke() error {
	if f.revoked {
		return ErrRefreshTokenFamilyAlreadyRevoked
	}
	f.revoked = true
	f.RecordEvent(RefreshTokenFamilyRevoked{FamilyID: f.ID()})
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/domain/... -run 'RefreshTokenFamily' -v`
Expected: PASS (all 9 test functions)

- [ ] **Step 5: Commit**

```bash
git add internal/domain/refresh_token_family.go internal/domain/refresh_token_family_test.go \
        internal/domain/errors.go internal/domain/events.go internal/domain/repository.go
git commit -m "feat(domain): add RefreshTokenFamily aggregate with rotation and reuse detection"
```

---

### Task 3: App-layer ports — `IDGenerator.NewFamilyID`, `RefreshTokenGenerator`

**Files:**
- Modify: `internal/app/ports.go`
- Modify: `internal/app/errors.go`
- Modify: `internal/infra/idgen/idgen.go`
- Test: `internal/infra/idgen/idgen_test.go`

**Interfaces:**
- Consumes: `domain.FamilyID` (Task 1).
- Produces: `app.IDGenerator.NewFamilyID() (domain.FamilyID, error)`,
  `app.RefreshTokenGenerator` interface (`Generate() (raw, hash string, err error)`,
  `Hash(raw string) string`), `app.ErrInvalidRefreshToken`, `idgen.UUIDGenerator.NewFamilyID()`.

- [ ] **Step 1: Write the failing test**

```go
// internal/infra/idgen/idgen_test.go
package idgen

import "testing"

func TestUUIDGenerator_NewFamilyID(t *testing.T) {
	gen := UUIDGenerator{}

	id, err := gen.NewFamilyID()
	if err != nil {
		t.Fatalf("NewFamilyID() error = %v, want nil", err)
	}
	if id.String() == "" {
		t.Error("NewFamilyID() returned an empty FamilyID")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/infra/idgen/... -v`
Expected: FAIL — `gen.NewFamilyID undefined`

- [ ] **Step 3: Write minimal implementation**

Modify `internal/app/ports.go`:

```go
type IDGenerator interface {
	NewAccountID() (domain.AccountID, error)
	NewFamilyID() (domain.FamilyID, error)
}

// RefreshTokenGenerator issues opaque refresh-token secrets and hashes them
// for storage/comparison. The raw secret is returned to the caller once and
// is never persisted — only its hash is stored, so a leaked database dump
// does not expose usable refresh tokens.
type RefreshTokenGenerator interface {
	Generate() (raw string, hash string, err error)
	Hash(raw string) string
}
```

Modify `internal/app/errors.go` — add below `ErrInvalidCredentials`:

```go
// ErrInvalidRefreshToken is returned by RotateRefreshTokenHandler for any
// refresh failure that must be indistinguishable from any other (unknown
// family, expired, malformed, reused token) so the response never leaks
// which reason it was.
var ErrInvalidRefreshToken = NewError(KindUnauthorized, "invalid_refresh_token", errors.New("invalid refresh token"))
```

Modify `internal/infra/idgen/idgen.go`:

```go
package idgen

import (
	"github.com/google/uuid"

	"github.com/AymanKastali/iam-base/internal/domain"
)

// UUIDGenerator is the app.IDGenerator adapter backed by google/uuid.
type UUIDGenerator struct{}

func (UUIDGenerator) NewAccountID() (domain.AccountID, error) {
	return domain.NewAccountID(uuid.NewString())
}

func (UUIDGenerator) NewFamilyID() (domain.FamilyID, error) {
	return domain.NewFamilyID(uuid.NewString())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/infra/idgen/... -v && go build ./...`
Expected: PASS, and the build succeeds (confirms `UUIDGenerator` still satisfies `app.IDGenerator`
now that the interface grew a method).

- [ ] **Step 5: Commit**

```bash
git add internal/app/ports.go internal/app/errors.go internal/infra/idgen/idgen.go internal/infra/idgen/idgen_test.go
git commit -m "feat(app): add IDGenerator.NewFamilyID and RefreshTokenGenerator ports"
```

---

### Task 4: `refreshtoken.SHA256Generator` infra adapter

**Files:**
- Create: `internal/infra/refreshtoken/generator.go`
- Test: `internal/infra/refreshtoken/generator_test.go`

**Interfaces:**
- Consumes: `app.RefreshTokenGenerator` (Task 3, as the interface this satisfies).
- Produces: `refreshtoken.SHA256Generator{}` implementing `Generate() (string, string, error)`
  and `Hash(raw string) string`.

- [ ] **Step 1: Write the failing test**

```go
// internal/infra/refreshtoken/generator_test.go
package refreshtoken

import "testing"

func TestSHA256Generator_Generate(t *testing.T) {
	gen := SHA256Generator{}

	raw, hash, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	if raw == "" || hash == "" {
		t.Fatalf("Generate() = (%q, %q), want two non-empty strings", raw, hash)
	}
	if raw == hash {
		t.Error("Generate() raw secret and its hash must differ")
	}
	if got := gen.Hash(raw); got != hash {
		t.Errorf("Hash(raw) = %q, want %q (must match the hash Generate() returned for the same raw)", got, hash)
	}
}

func TestSHA256Generator_Generate_ProducesDistinctSecrets(t *testing.T) {
	gen := SHA256Generator{}

	raw1, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	raw2, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	if raw1 == raw2 {
		t.Error("Generate() produced the same secret twice — not using enough randomness")
	}
}

func TestSHA256Generator_Hash_Deterministic(t *testing.T) {
	gen := SHA256Generator{}

	if gen.Hash("same-input") != gen.Hash("same-input") {
		t.Error("Hash() must be deterministic for the same input")
	}
	if gen.Hash("a") == gen.Hash("b") {
		t.Error("Hash() must differ for different inputs")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/infra/refreshtoken/... -v`
Expected: FAIL — `undefined: SHA256Generator`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/infra/refreshtoken/generator.go

// Package refreshtoken provides the infra adapter for app.RefreshTokenGenerator:
// a high-entropy opaque secret, hashed with SHA-256 for storage. A refresh
// token is a random secret rather than a human password, so it needs no
// salting or slow/adaptive hash — only protection against a leaked DB dump
// yielding directly-usable tokens, which a fast cryptographic hash provides.
package refreshtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const secretBytes = 32

type SHA256Generator struct{}

func (SHA256Generator) Generate() (raw string, hash string, err error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashSecret(raw), nil
}

func (SHA256Generator) Hash(raw string) string {
	return hashSecret(raw)
}

func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/infra/refreshtoken/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/refreshtoken/generator.go internal/infra/refreshtoken/generator_test.go
git commit -m "feat(infra): add SHA-256 opaque refresh-token generator adapter"
```

---

### Task 5: Extend `LoginHandler` to issue a refresh token

**Files:**
- Modify: `internal/app/command/login.go`
- Modify: `internal/app/command/login_test.go`
- Create: `internal/app/command/refresh_fakes_test.go`

**Interfaces:**
- Consumes: `domain.RefreshTokenRepository`, `domain.IssueFamily` (Task 2); `app.RefreshTokenGenerator`,
  `app.IDGenerator.NewFamilyID`, `app.Clock` (Task 3).
- Produces: `command.LoginResult{AccessToken string; ExpiresAt time.Time; RefreshToken string}`
  (adds the `RefreshToken` field), `command.LoginHandler` gains `RefreshRepo`, `TokenGen`, `IDGen`,
  `Clock`, `RefreshTokenTTL` fields. Test doubles `fakeRefreshTokenRepo`, `fakeTokenGenerator`,
  `fakeClock` (reused by Tasks 6 and 7).

- [ ] **Step 1: Write the failing test**

Create `internal/app/command/refresh_fakes_test.go` (shared fakes for this and later command tests):

```go
// internal/app/command/refresh_fakes_test.go
package command

import (
	"context"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type fakeRefreshTokenRepo struct {
	families map[string]*domain.RefreshTokenFamily
	saveErr  error
	findErr  error
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{families: map[string]*domain.RefreshTokenFamily{}}
}

func (r *fakeRefreshTokenRepo) Save(ctx context.Context, family *domain.RefreshTokenFamily) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.families[family.ID().String()] = family
	return nil
}

func (r *fakeRefreshTokenRepo) FindByID(ctx context.Context, id domain.FamilyID) (*domain.RefreshTokenFamily, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	family, ok := r.families[id.String()]
	if !ok {
		return nil, domain.ErrRefreshTokenFamilyNotFound
	}
	return family, nil
}

// fakeTokenGenerator returns deterministic secret/hash pairs so tests can
// assert on their exact values instead of just non-emptiness.
type fakeTokenGenerator struct {
	nextSecret string
	nextHash   string
}

func (f fakeTokenGenerator) Generate() (string, string, error) {
	return f.nextSecret, f.nextHash, nil
}

func (f fakeTokenGenerator) Hash(raw string) string {
	return "hash:" + raw
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}
```

First, add a `NewFamilyID` method to the existing `fakeIDGenerator` in `register_test.go` so it
satisfies the now-larger `app.IDGenerator` interface:

```go
// internal/app/command/register_test.go — add next to the existing NewAccountID method
func (fakeIDGenerator) NewFamilyID() (domain.FamilyID, error) {
	return domain.NewFamilyID("fake-family-id")
}
```

Then modify `internal/app/command/login_test.go` — update every `LoginHandler{...}` literal in the
file to also set the new fields, and extend the success test:

```go
func TestLoginHandler_Handle_Success(t *testing.T) {
	repo := newFakeAccountRepo()
	registerFixture(t, repo, "a@b.com", sampleCredential)
	expiresAt := time.Now().Add(15 * time.Minute)
	refreshRepo := newFakeRefreshTokenRepo()
	h := LoginHandler{
		Repo:            repo,
		Hasher:          fakeHasher{},
		Issuer:          fakeIssuer{token: "signed-jwt", expiresAt: expiresAt},
		RefreshRepo:     refreshRepo,
		TokenGen:        fakeTokenGenerator{nextSecret: "raw-secret", nextHash: "hash-1"},
		IDGen:           fakeIDGenerator{},
		Clock:           fakeClock{now: time.Now()},
		RefreshTokenTTL: 24 * time.Hour,
	}

	result, err := h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: sampleCredential})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if result.AccessToken != "signed-jwt" || !result.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Handle() = %+v, want token=signed-jwt expiresAt=%v", result, expiresAt)
	}
	wantRefreshToken := "fake-family-id.raw-secret" // fakeIDGenerator.NewFamilyID() returns "fake-family-id"
	if result.RefreshToken != wantRefreshToken {
		t.Errorf("Handle() RefreshToken = %q, want %q", result.RefreshToken, wantRefreshToken)
	}
	if len(refreshRepo.families) != 1 {
		t.Errorf("RefreshRepo has %d families, want 1", len(refreshRepo.families))
	}
}
```

Also update every other `LoginHandler{...}` literal in `login_test.go` (the disabled-account,
wrong-password, repository-failure, unknown-email, and both timing-padding tests) to add:
`RefreshRepo: newFakeRefreshTokenRepo(), TokenGen: fakeTokenGenerator{nextSecret: "s", nextHash: "h"},
IDGen: fakeIDGenerator{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: 24 * time.Hour,` —
these tests all fail before reaching refresh-token issuance, so the values themselves don't matter,
only that the struct compiles.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/app/command/... -v`
Expected: FAIL to compile — `unknown field RefreshRepo in struct literal` (until Step 3), then once
that's fixed, `result.RefreshToken` assertions fail because `login.go` doesn't set it yet.

- [ ] **Step 3: Write minimal implementation**

Modify `internal/app/command/login.go`:

```go
package command

import (
	"context"
	"errors"
	"time"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// ErrInvalidCredentials is command's alias for app.ErrInvalidCredentials, so
// callers in this package don't need to import app just to reference it.
var ErrInvalidCredentials = app.ErrInvalidCredentials

type LoginCommand struct {
	Email    string
	Password string
}

type LoginResult struct {
	AccessToken  string
	ExpiresAt    time.Time
	RefreshToken string
}

type LoginHandler struct {
	Repo            domain.AccountRepository
	Hasher          app.PasswordHasher
	Issuer          app.TokenIssuer
	RefreshRepo     domain.RefreshTokenRepository
	TokenGen        app.RefreshTokenGenerator
	IDGen           app.IDGenerator
	Clock           app.Clock
	RefreshTokenTTL time.Duration
}

func (h LoginHandler) Handle(ctx context.Context, cmd LoginCommand) (LoginResult, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	account, err := h.Repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrAccountNotFound) {
			h.padTimingCost(cmd.Password)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	if err := account.Login(); err != nil {
		h.padTimingCost(cmd.Password)
		return LoginResult{}, ErrInvalidCredentials
	}
	ok, err := h.Hasher.Verify(account.Credential(), cmd.Password)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		return LoginResult{}, ErrInvalidCredentials
	}

	token, expiresAt, err := h.Issuer.Issue(ctx, account.ID())
	if err != nil {
		return LoginResult{}, err
	}

	// Login reads one Account above and, here, separately saves one new
	// RefreshTokenFamily — two independent saves, never one transaction
	// (design doc §7: no cross-aggregate transactions).
	refreshToken, err := h.issueRefreshFamily(ctx, account.ID())
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{AccessToken: token, ExpiresAt: expiresAt, RefreshToken: refreshToken}, nil
}

func (h LoginHandler) issueRefreshFamily(ctx context.Context, accountID domain.AccountID) (string, error) {
	familyID, err := h.IDGen.NewFamilyID()
	if err != nil {
		return "", err
	}
	secret, hash, err := h.TokenGen.Generate()
	if err != nil {
		return "", err
	}
	expiresAt := h.Clock.Now().Add(h.RefreshTokenTTL)
	family, err := domain.IssueFamily(familyID, accountID, hash, expiresAt)
	if err != nil {
		return "", err
	}
	if err := h.RefreshRepo.Save(ctx, family); err != nil {
		return "", err
	}
	return formatRefreshToken(familyID, secret), nil
}

// padTimingCost runs a throwaway password hash so the unknown-email and
// disabled-account paths cost roughly the same as a real credential
// verification — otherwise their faster response time would leak account
// existence/status to an attacker even though the returned error doesn't.
func (h LoginHandler) padTimingCost(password string) {
	_, _ = h.Hasher.Hash(password)
}
```

Create `internal/app/command/refresh_token.go` (introduced here since `login.go` above already
needs `formatRefreshToken`; `parseRefreshToken` is added now too since both live together and
Task 6 needs it):

```go
// internal/app/command/refresh_token.go
package command

import (
	"errors"
	"strings"

	"github.com/AymanKastali/iam-base/internal/domain"
)

const refreshTokenSeparator = "."

var errMalformedRefreshToken = errors.New("malformed refresh token")

// formatRefreshToken builds the opaque wire-format refresh token: the family
// ID (so refresh/logout can look the family up directly) followed by the
// random secret, joined by refreshTokenSeparator.
func formatRefreshToken(familyID domain.FamilyID, secret string) string {
	return familyID.String() + refreshTokenSeparator + secret
}

// parseRefreshToken splits a wire-format refresh token back into its family
// ID and secret. A missing separator or an empty half is malformed.
func parseRefreshToken(raw string) (domain.FamilyID, string, error) {
	idPart, secret, found := strings.Cut(raw, refreshTokenSeparator)
	if !found || idPart == "" || secret == "" {
		return domain.FamilyID{}, "", errMalformedRefreshToken
	}
	familyID, err := domain.NewFamilyID(idPart)
	if err != nil {
		return domain.FamilyID{}, "", errMalformedRefreshToken
	}
	return familyID, secret, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/app/command/... -v`
Expected: PASS (all existing + new login tests)

- [ ] **Step 5: Commit**

```bash
git add internal/app/command/login.go internal/app/command/login_test.go \
        internal/app/command/refresh_fakes_test.go internal/app/command/refresh_token.go \
        internal/app/command/register_test.go
git commit -m "feat(app): Login issues a RefreshTokenFamily and returns a refresh token"
```

---

### Task 6: `RotateRefreshTokenHandler` (refresh)

**Files:**
- Create: `internal/app/command/refresh.go`
- Test: `internal/app/command/refresh_test.go`

**Interfaces:**
- Consumes: `domain.RefreshTokenRepository`, `(*domain.RefreshTokenFamily).Rotate` (Task 2);
  `app.RefreshTokenGenerator`, `app.Clock` (Task 3); `parseRefreshToken`/`formatRefreshToken`,
  `fakeRefreshTokenRepo`/`fakeTokenGenerator`/`fakeClock`/`fakeIssuer` (Task 5).
- Produces: `command.RotateRefreshTokenCommand{RefreshToken string}`,
  `command.RefreshResult{AccessToken string; AccessTokenExpiresAt time.Time; RefreshToken string}`,
  `command.RotateRefreshTokenHandler{Repo, TokenGen, Issuer, Clock, RefreshTokenTTL}`,
  `command.ErrInvalidRefreshToken` (alias for `app.ErrInvalidRefreshToken`).

- [ ] **Step 1: Write the failing tests**

```go
// internal/app/command/refresh_test.go
package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func issueTestFamily(t *testing.T, repo *fakeRefreshTokenRepo, hash string, expiresAt time.Time) domain.FamilyID {
	t.Helper()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, err := domain.IssueFamily(familyID, accountID, hash, expiresAt)
	if err != nil {
		t.Fatalf("fixture IssueFamily: %v", err)
	}
	if err := repo.Save(context.Background(), family); err != nil {
		t.Fatalf("fixture Save: %v", err)
	}
	return familyID
}

func TestRotateRefreshTokenHandler_Handle_Success(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:old-secret", now.Add(time.Hour))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{token: "signed-jwt", expiresAt: now.Add(15 * time.Minute)},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	result, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".old-secret"})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if result.AccessToken != "signed-jwt" {
		t.Errorf("Handle() AccessToken = %q, want signed-jwt", result.AccessToken)
	}
	wantRefreshToken := familyID.String() + ".new-secret"
	if result.RefreshToken != wantRefreshToken {
		t.Errorf("Handle() RefreshToken = %q, want %q", result.RefreshToken, wantRefreshToken)
	}

	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if stored.Generation() != 2 {
		t.Errorf("stored family Generation() = %d, want 2", stored.Generation())
	}
}

func TestRotateRefreshTokenHandler_Handle_MalformedToken(t *testing.T) {
	h := RotateRefreshTokenHandler{Repo: newFakeRefreshTokenRepo(), TokenGen: fakeTokenGenerator{}, Issuer: fakeIssuer{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: time.Hour}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: "not-a-valid-token"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRotateRefreshTokenHandler_Handle_UnknownFamily(t *testing.T) {
	h := RotateRefreshTokenHandler{Repo: newFakeRefreshTokenRepo(), TokenGen: fakeTokenGenerator{}, Issuer: fakeIssuer{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: time.Hour}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: "unknown-family.some-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRotateRefreshTokenHandler_Handle_ReusedToken_RevokesFamily(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:current-secret", now.Add(time.Hour))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{token: "signed-jwt", expiresAt: now.Add(15 * time.Minute)},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".an-old-superseded-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}

	stored, findErr := repo.FindByID(context.Background(), familyID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v, want nil", findErr)
	}
	if !stored.Revoked() {
		t.Error("a reused token must revoke the whole family, even though the handler returns a generic error")
	}
}

func TestRotateRefreshTokenHandler_Handle_ExpiredToken(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:old-secret", now.Add(-time.Minute))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".old-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/app/command/... -run RotateRefreshTokenHandler -v`
Expected: FAIL — `undefined: RotateRefreshTokenHandler`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/app/command/refresh.go
package command

import (
	"context"
	"time"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// ErrInvalidRefreshToken is command's alias for app.ErrInvalidRefreshToken.
var ErrInvalidRefreshToken = app.ErrInvalidRefreshToken

type RotateRefreshTokenCommand struct {
	RefreshToken string
}

type RefreshResult struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
	RefreshToken         string
}

type RotateRefreshTokenHandler struct {
	Repo            domain.RefreshTokenRepository
	TokenGen        app.RefreshTokenGenerator
	Issuer          app.TokenIssuer
	Clock           app.Clock
	RefreshTokenTTL time.Duration
}

func (h RotateRefreshTokenHandler) Handle(ctx context.Context, cmd RotateRefreshTokenCommand) (RefreshResult, error) {
	familyID, secret, err := parseRefreshToken(cmd.RefreshToken)
	if err != nil {
		return RefreshResult{}, ErrInvalidRefreshToken
	}

	family, err := h.Repo.FindByID(ctx, familyID)
	if err != nil {
		return RefreshResult{}, ErrInvalidRefreshToken
	}

	newSecret, newHash, err := h.TokenGen.Generate()
	if err != nil {
		return RefreshResult{}, err
	}

	now := h.Clock.Now()
	presentedHash := h.TokenGen.Hash(secret)
	rotateErr := family.Rotate(now, presentedHash, newHash, now.Add(h.RefreshTokenTTL))
	// Save unconditionally: on the reuse path Rotate has already marked the
	// family revoked, and that revocation must persist even though Handle
	// goes on to return a generic error.
	if saveErr := h.Repo.Save(ctx, family); saveErr != nil {
		return RefreshResult{}, saveErr
	}
	if rotateErr != nil {
		return RefreshResult{}, ErrInvalidRefreshToken
	}

	accessToken, expiresAt, err := h.Issuer.Issue(ctx, family.AccountID())
	if err != nil {
		return RefreshResult{}, err
	}

	return RefreshResult{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: expiresAt,
		RefreshToken:         formatRefreshToken(familyID, newSecret),
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/app/command/... -run RotateRefreshTokenHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/app/command/refresh.go internal/app/command/refresh_test.go
git commit -m "feat(app): add RotateRefreshTokenHandler with reuse detection"
```

---

### Task 7: `RevokeSessionHandler` (logout)

**Files:**
- Create: `internal/app/command/logout.go`
- Test: `internal/app/command/logout_test.go`

**Interfaces:**
- Consumes: `domain.RefreshTokenRepository`, `(*domain.RefreshTokenFamily).Revoke` (Task 2);
  `parseRefreshToken`, `fakeRefreshTokenRepo` (Task 5).
- Produces: `command.RevokeSessionCommand{RefreshToken string}`,
  `command.RevokeSessionHandler{Repo domain.RefreshTokenRepository}`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/app/command/logout_test.go
package command

import (
	"context"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func TestRevokeSessionHandler_Handle_Success(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	h := RevokeSessionHandler{Repo: repo}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}

	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("Handle() must revoke the family")
	}
}

func TestRevokeSessionHandler_Handle_AlreadyRevoked_IsIdempotent(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	h := RevokeSessionHandler{Repo: repo}
	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Fatalf("fixture Handle: %v", err)
	}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Errorf("Handle() on an already-revoked family error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_UnknownFamily_IsIdempotent(t *testing.T) {
	h := RevokeSessionHandler{Repo: newFakeRefreshTokenRepo()}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: "unknown-family.some-secret"}); err != nil {
		t.Errorf("Handle() for an unknown family error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_MalformedToken_IsIdempotent(t *testing.T) {
	h := RevokeSessionHandler{Repo: newFakeRefreshTokenRepo()}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: "not-a-valid-token"}); err != nil {
		t.Errorf("Handle() for a malformed token error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_RepositoryFailure_Propagates(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	repo.saveErr = domain.ErrRefreshTokenFamilyNotFound // any non-nil save error stands in for a DB failure
	h := RevokeSessionHandler{Repo: repo}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err == nil {
		t.Error("Handle() must propagate a genuine repository save failure, not swallow it")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/app/command/... -run RevokeSessionHandler -v`
Expected: FAIL — `undefined: RevokeSessionHandler`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/app/command/logout.go
package command

import (
	"context"
	"errors"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type RevokeSessionCommand struct {
	RefreshToken string
}

type RevokeSessionHandler struct {
	Repo domain.RefreshTokenRepository
}

// Handle revokes the family the presented refresh token belongs to. It is
// idempotent by design: a malformed token, an unknown family, or a family
// that's already revoked all return nil — logout's only job is "make sure
// this session is not valid," which is already true in all three cases, and
// treating them as errors would let a client distinguish an unknown family
// from a known-but-already-revoked one.
func (h RevokeSessionHandler) Handle(ctx context.Context, cmd RevokeSessionCommand) error {
	familyID, _, err := parseRefreshToken(cmd.RefreshToken)
	if err != nil {
		return nil
	}

	family, err := h.Repo.FindByID(ctx, familyID)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenFamilyNotFound) {
			return nil
		}
		return err
	}

	if err := family.Revoke(); err != nil {
		if errors.Is(err, domain.ErrRefreshTokenFamilyAlreadyRevoked) {
			return nil
		}
		return err
	}

	return h.Repo.Save(ctx, family)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/app/command/... -run RevokeSessionHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/app/command/logout.go internal/app/command/logout_test.go
git commit -m "feat(app): add RevokeSessionHandler for idempotent logout"
```

---

### Task 8: Postgres `refresh_token_families` table and repository

**Files:**
- Create: `internal/infra/postgres/migrations/000002_create_refresh_token_families.up.sql`
- Create: `internal/infra/postgres/migrations/000002_create_refresh_token_families.down.sql`
- Create: `internal/infra/postgres/refresh_token_repo.go`
- Test: `internal/infra/postgres/refresh_token_repo_test.go`

**Interfaces:**
- Consumes: `domain.RefreshTokenRepository` (port to satisfy), `domain.IssueFamily`,
  `domain.ReconstituteRefreshTokenFamily`, `domain.ErrRefreshTokenFamilyNotFound` (Task 2).
- Produces: `postgres.NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository`,
  `(*RefreshTokenRepository) Save(ctx, *domain.RefreshTokenFamily) error`,
  `(*RefreshTokenRepository) FindByID(ctx, domain.FamilyID) (*domain.RefreshTokenFamily, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/infra/postgres/refresh_token_repo_test.go
package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func newTestRefreshTokenRepo(t *testing.T, accountRepo *AccountRepository) *RefreshTokenRepository {
	t.Helper()
	return &RefreshTokenRepository{pool: accountRepo.pool}
}

func newTestFamily(t *testing.T, accountID domain.AccountID) *domain.RefreshTokenFamily {
	t.Helper()
	id, err := domain.NewFamilyID(uuid.NewString())
	if err != nil {
		t.Fatalf("NewFamilyID: %v", err)
	}
	family, err := domain.IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(time.Hour).Truncate(time.Microsecond))
	if err != nil {
		t.Fatalf("IssueFamily: %v", err)
	}
	return family
}

func TestRefreshTokenRepository_SaveAndFindByID(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	ctx := context.Background()
	account := newTestAccount(t, "refresh-owner@b.com")
	if err := accountRepo.Save(ctx, account); err != nil {
		t.Fatalf("fixture Save account: %v", err)
	}
	family := newTestFamily(t, account.ID())

	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	found, err := repo.FindByID(ctx, family.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if found.AccountID() != family.AccountID() {
		t.Errorf("FindByID().AccountID() = %v, want %v", found.AccountID(), family.AccountID())
	}
	if found.CurrentTokenHash() != family.CurrentTokenHash() {
		t.Errorf("FindByID().CurrentTokenHash() = %q, want %q", found.CurrentTokenHash(), family.CurrentTokenHash())
	}
	if found.Generation() != family.Generation() {
		t.Errorf("FindByID().Generation() = %d, want %d", found.Generation(), family.Generation())
	}
	if found.Revoked() {
		t.Error("FindByID() must not report a freshly-issued family as revoked")
	}
	if events := found.RecordedEvents(); len(events) != 0 {
		t.Errorf("FindByID() recorded %d events, want 0 — loading is not a new fact", len(events))
	}
}

func TestRefreshTokenRepository_Save_UpsertsRotation(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	ctx := context.Background()
	account := newTestAccount(t, "rotator@b.com")
	if err := accountRepo.Save(ctx, account); err != nil {
		t.Fatalf("fixture Save account: %v", err)
	}
	family := newTestFamily(t, account.ID())
	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("initial Save() error = %v, want nil", err)
	}

	if err := family.Rotate(time.Now(), "hash-gen-1", "hash-gen-2", time.Now().Add(2*time.Hour).Truncate(time.Microsecond)); err != nil {
		t.Fatalf("fixture Rotate: %v", err)
	}
	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("rotation Save() error = %v, want nil", err)
	}

	found, err := repo.FindByID(ctx, family.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if found.Generation() != 2 || found.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("FindByID() after rotation = generation=%d hash=%q, want generation=2 hash=hash-gen-2", found.Generation(), found.CurrentTokenHash())
	}
}

func TestRefreshTokenRepository_FindByID_NotFound(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	missingID, _ := domain.NewFamilyID(uuid.NewString())

	_, err := repo.FindByID(context.Background(), missingID)
	if !errors.Is(err, domain.ErrRefreshTokenFamilyNotFound) {
		t.Fatalf("FindByID() error = %v, want ErrRefreshTokenFamilyNotFound", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/postgres/... -run RefreshTokenRepository -v`
Expected: FAIL — `undefined: RefreshTokenRepository` (and no `000002` migration exists yet)

- [ ] **Step 3: Write minimal implementation**

Create `internal/infra/postgres/migrations/000002_create_refresh_token_families.up.sql`:

```sql
CREATE TABLE refresh_token_families (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    current_token_hash TEXT NOT NULL,
    generation INT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Create `internal/infra/postgres/migrations/000002_create_refresh_token_families.down.sql`:

```sql
DROP TABLE refresh_token_families;
```

Create `internal/infra/postgres/refresh_token_repo.go`:

```go
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

// Save upserts the family: an INSERT for a newly-issued family (Login), or an
// UPDATE-via-ON-CONFLICT for an existing one (Rotate, Revoke) — one method
// covers both since domain.RefreshTokenRepository declares only Save, not a
// separate Create/Update pair.
func (r *RefreshTokenRepository) Save(ctx context.Context, family *domain.RefreshTokenFamily) error {
	const q = `
		INSERT INTO refresh_token_families (id, account_id, current_token_hash, generation, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			current_token_hash = EXCLUDED.current_token_hash,
			generation = EXCLUDED.generation,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked
	`
	_, err := r.pool.Exec(ctx, q,
		family.ID().String(),
		family.AccountID().String(),
		family.CurrentTokenHash(),
		family.Generation(),
		family.ExpiresAt(),
		family.Revoked(),
	)
	return err
}

func (r *RefreshTokenRepository) FindByID(ctx context.Context, id domain.FamilyID) (*domain.RefreshTokenFamily, error) {
	const q = `
		SELECT account_id, current_token_hash, generation, expires_at, revoked
		FROM refresh_token_families
		WHERE id = $1
	`
	var (
		accountIDRaw string
		tokenHash    string
		generation   int
		expiresAt    time.Time
		revoked      bool
	)
	err := r.pool.QueryRow(ctx, q, id.String()).Scan(&accountIDRaw, &tokenHash, &generation, &expiresAt, &revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrRefreshTokenFamilyNotFound
		}
		return nil, err
	}

	accountID, err := domain.NewAccountID(accountIDRaw)
	if err != nil {
		return nil, err
	}
	return domain.ReconstituteRefreshTokenFamily(id, accountID, tokenHash, generation, expiresAt, revoked), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/infra/postgres/... -run RefreshTokenRepository -v`
Expected: PASS (spins up a real `postgres:16-alpine` testcontainer; requires Docker running locally)

- [ ] **Step 5: Commit**

```bash
git add internal/infra/postgres/migrations/000002_create_refresh_token_families.up.sql \
        internal/infra/postgres/migrations/000002_create_refresh_token_families.down.sql \
        internal/infra/postgres/refresh_token_repo.go internal/infra/postgres/refresh_token_repo_test.go
git commit -m "feat(infra): add refresh_token_families table and Postgres repository"
```

---

### Task 9: HTTP `RefreshHandler`

**Files:**
- Create: `internal/infra/httpapi/refresh_handler.go`
- Test: `internal/infra/httpapi/refresh_handler_test.go`

**Interfaces:**
- Consumes: `command.RotateRefreshTokenHandler`, `command.RotateRefreshTokenCommand`,
  `command.ErrInvalidRefreshToken` (Task 6); `decodeJSON`/`writeJSON`/`writeError`/`respondError`,
  `stubAccountRepo`-style stub conventions (existing).
- Produces: `httpapi.RefreshHandler{Handler command.RotateRefreshTokenHandler}`, its `ServeHTTP`,
  and package-shared test stubs `stubRefreshTokenRepo`, `stubTokenGenerator`, `stubClock` (reused
  by Task 10).

- [ ] **Step 1: Write the failing tests**

```go
// internal/infra/httpapi/refresh_handler_test.go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type stubRefreshTokenRepo struct {
	families map[string]*domain.RefreshTokenFamily
}

func newStubRefreshTokenRepo() *stubRefreshTokenRepo {
	return &stubRefreshTokenRepo{families: map[string]*domain.RefreshTokenFamily{}}
}

func (r *stubRefreshTokenRepo) Save(ctx context.Context, family *domain.RefreshTokenFamily) error {
	r.families[family.ID().String()] = family
	return nil
}

func (r *stubRefreshTokenRepo) FindByID(ctx context.Context, id domain.FamilyID) (*domain.RefreshTokenFamily, error) {
	family, ok := r.families[id.String()]
	if !ok {
		return nil, domain.ErrRefreshTokenFamilyNotFound
	}
	return family, nil
}

type stubTokenGenerator struct {
	nextSecret string
	nextHash   string
}

func (g stubTokenGenerator) Generate() (string, string, error) {
	return g.nextSecret, g.nextHash, nil
}

func (stubTokenGenerator) Hash(raw string) string {
	return "hash:" + raw
}

type stubClock struct {
	now time.Time
}

func (c stubClock) Now() time.Time {
	return c.now
}

func TestRefreshHandler_ServeHTTP_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	now := time.Now()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:old-secret", now.Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	h := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        stubTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          stubIssuer{},
		Clock:           stubClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}}

	body, _ := json.Marshal(map[string]string{"refresh_token": "family-1.old-secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["refresh_token"] != "family-1.new-secret" {
		t.Errorf("refresh_token = %v, want family-1.new-secret", resp["refresh_token"])
	}
}

func TestRefreshHandler_ServeHTTP_InvalidRefreshToken(t *testing.T) {
	h := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: newStubRefreshTokenRepo(), TokenGen: stubTokenGenerator{}, Issuer: stubIssuer{}, Clock: stubClock{now: time.Now()}, RefreshTokenTTL: time.Hour,
	}}

	body, _ := json.Marshal(map[string]string{"refresh_token": "unknown-family.secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRefreshHandler_ServeHTTP_BodyTooLarge(t *testing.T) {
	h := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: newStubRefreshTokenRepo(), TokenGen: stubTokenGenerator{}, Issuer: stubIssuer{}, Clock: stubClock{now: time.Now()}, RefreshTokenTTL: time.Hour,
	}}

	oversizedToken := strings.Repeat("a", maxRequestBodyBytes)
	body, _ := json.Marshal(map[string]string{"refresh_token": oversizedToken})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/httpapi/... -run TestRefreshHandler -v`
Expected: FAIL — `undefined: RefreshHandler`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/infra/httpapi/refresh_handler.go
package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RefreshHandler struct {
	Handler command.RotateRefreshTokenHandler
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
}

func (h RefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	result, err := h.Handler.Handle(r.Context(), command.RotateRefreshTokenCommand{RefreshToken: req.RefreshToken})
	if err != nil {
		respondError(w, "refresh", err)
		return
	}

	writeJSON(w, http.StatusOK, refreshResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.AccessTokenExpiresAt.Format(http.TimeFormat),
		RefreshToken: result.RefreshToken,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/infra/httpapi/... -run TestRefreshHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/refresh_handler.go internal/infra/httpapi/refresh_handler_test.go
git commit -m "feat(infra): add HTTP handler for POST /v1/auth/refresh"
```

---

### Task 10: HTTP `LogoutHandler`

**Files:**
- Create: `internal/infra/httpapi/logout_handler.go`
- Test: `internal/infra/httpapi/logout_handler_test.go`

**Interfaces:**
- Consumes: `command.RevokeSessionHandler`, `command.RevokeSessionCommand` (Task 7);
  `stubRefreshTokenRepo` (Task 9).
- Produces: `httpapi.LogoutHandler{Handler command.RevokeSessionHandler}`, its `ServeHTTP`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/infra/httpapi/logout_handler_test.go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

func TestLogoutHandler_ServeHTTP_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:secret", time.Now().Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: repo}}
	body, _ := json.Marshal(map[string]string{"refresh_token": "family-1.secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("logout must revoke the family")
	}
}

func TestLogoutHandler_ServeHTTP_UnknownFamily_StillNoContent(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}
	body, _ := json.Marshal(map[string]string{"refresh_token": "unknown-family.secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (logout is idempotent)", rec.Code)
	}
}

func TestLogoutHandler_ServeHTTP_BodyTooLarge(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}

	oversizedToken := strings.Repeat("a", maxRequestBodyBytes)
	body, _ := json.Marshal(map[string]string{"refresh_token": oversizedToken})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/httpapi/... -run TestLogoutHandler -v`
Expected: FAIL — `undefined: LogoutHandler`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/infra/httpapi/logout_handler.go
package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LogoutHandler struct {
	Handler command.RevokeSessionHandler
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	if err := h.Handler.Handle(r.Context(), command.RevokeSessionCommand{RefreshToken: req.RefreshToken}); err != nil {
		respondError(w, "logout", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/infra/httpapi/... -run TestLogoutHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/logout_handler.go internal/infra/httpapi/logout_handler_test.go
git commit -m "feat(infra): add HTTP handler for POST /v1/auth/logout"
```

---

### Task 11: Wire `/v1/auth/refresh` and `/v1/auth/logout` into the router

**Files:**
- Modify: `internal/infra/httpapi/router.go`

**Interfaces:**
- Consumes: `httpapi.RefreshHandler` (Task 9), `httpapi.LogoutHandler` (Task 10), existing
  `IPRateLimiter`.
- Produces: `httpapi.NewRouter(register, login, refresh, logout, jwks http.Handler, limiter
  *IPRateLimiter) *chi.Mux` (signature changes — `refresh, logout` added, `jwks` moved after them).

There's no dedicated `router_test.go` in this codebase (routing is exercised indirectly through
each handler's own tests plus the end-to-end smoke test in Task 14), so this task has no red/green
test cycle of its own — verify it by building and by the fact that Tasks 9/10's handler tests
already cover `RefreshHandler`/`LogoutHandler` behavior; this task only wires them to paths.

- [ ] **Step 1: Modify `router.go`**

```go
// internal/infra/httpapi/router.go
package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter(register, login, refresh, logout, jwks http.Handler, limiter *IPRateLimiter) *chi.Mux {
	r := chi.NewRouter()
	r.Method(http.MethodPost, "/v1/auth/register", limiter.Middleware(register))
	r.Method(http.MethodPost, "/v1/auth/login", limiter.Middleware(login))
	r.Method(http.MethodPost, "/v1/auth/refresh", limiter.Middleware(refresh))
	r.Method(http.MethodPost, "/v1/auth/logout", limiter.Middleware(logout))
	r.Method(http.MethodGet, "/.well-known/jwks.json", jwks)
	return r
}
```

- [ ] **Step 2: Confirm the build fails until Task 13 updates the only caller**

Run: `go build ./...`
Expected: FAIL — `internal/infra/composition/composition.go:63: not enough arguments in call to
httpapi.NewRouter` (composition.go still calls the old 4-argument signature; Task 13 fixes this).
This is expected — the two tasks are split for reviewability, not because the code compiles in
between.

- [ ] **Step 3: Commit**

```bash
git add internal/infra/httpapi/router.go
git commit -m "feat(infra): wire refresh/logout routes into the router"
```

---

### Task 12: `REFRESH_TOKEN_TTL` config

**Files:**
- Modify: `internal/infra/config/config.go`
- Modify: `internal/infra/config/config_test.go`

**Interfaces:**
- Produces: `config.Config.RefreshTokenTTL time.Duration` field, defaulting to 30 days
  (`720h`, expressed as `30 * 24 * time.Hour` since `time.ParseDuration` has no day unit),
  overridable via the `REFRESH_TOKEN_TTL` env var (same format as `ACCESS_TOKEN_TTL`, e.g. `"720h"`).

- [ ] **Step 1: Write the failing test**

Add to `internal/infra/config/config_test.go`:

```go
func TestLoad_Defaults_IncludesRefreshTokenTTL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "/etc/iam/private.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 720h (30 days)", cfg.RefreshTokenTTL)
	}
}

func TestLoad_RefreshTokenTTL_Override(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "/etc/iam/private.pem")
	t.Setenv("REFRESH_TOKEN_TTL", "1h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.RefreshTokenTTL != time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 1h", cfg.RefreshTokenTTL)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/infra/config/... -v`
Expected: FAIL — `cfg.RefreshTokenTTL undefined`

- [ ] **Step 3: Write minimal implementation**

Modify `internal/infra/config/config.go`:

```go
type Config struct {
	Port              string
	DatabaseURL       string
	JWTPrivateKeyPath string
	JWTKeyID          string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	RateLimitRPS      float64
	RateLimitBurst    int
}

func Load() (Config, error) {
	cfg := Config{
		Port:              getEnv("PORT", "8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTPrivateKeyPath: os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTKeyID:          getEnv("JWT_KEY_ID", "1"),
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   30 * 24 * time.Hour,
		RateLimitRPS:      5,
		RateLimitBurst:    10,
	}

	if ttl := os.Getenv("ACCESS_TOKEN_TTL"); ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ACCESS_TOKEN_TTL: %w", err)
		}
		cfg.AccessTokenTTL = d
	}
	if ttl := os.Getenv("REFRESH_TOKEN_TTL"); ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("invalid REFRESH_TOKEN_TTL: %w", err)
		}
		cfg.RefreshTokenTTL = d
	}
	if rps := os.Getenv("RATE_LIMIT_RPS"); rps != "" {
		v, err := strconv.ParseFloat(rps, 64)
		if err != nil {
			return Config{}, fmt.Errorf("invalid RATE_LIMIT_RPS: %w", err)
		}
		cfg.RateLimitRPS = v
	}
	if burst := os.Getenv("RATE_LIMIT_BURST"); burst != "" {
		v, err := strconv.Atoi(burst)
		if err != nil {
			return Config{}, fmt.Errorf("invalid RATE_LIMIT_BURST: %w", err)
		}
		cfg.RateLimitBurst = v
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.JWTPrivateKeyPath == "" {
		return Config{}, errors.New("JWT_PRIVATE_KEY_PATH is required")
	}
	return cfg, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/infra/config/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/config/config.go internal/infra/config/config_test.go
git commit -m "feat(config): add REFRESH_TOKEN_TTL, defaulting to 30 days"
```

---

### Task 13: Wire everything in the composition root

**Files:**
- Modify: `internal/infra/composition/composition.go`

**Interfaces:**
- Consumes: everything produced by Tasks 1–12.
- Produces: a fully-wired `Application` whose router serves refresh/logout alongside
  register/login/jwks.

There's no `composition_test.go` in this codebase — the composition root is verified by the fact
that it's the only caller of every constructor changed in this plan, so `go build ./...` fails
loudly if anything is wired wrong, and by the end-to-end smoke test in Task 14.

- [ ] **Step 1: Modify `composition.go`**

```go
// internal/infra/composition/composition.go
package composition

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
	"github.com/AymanKastali/iam-base/internal/infra/config"
	"github.com/AymanKastali/iam-base/internal/infra/httpapi"
	"github.com/AymanKastali/iam-base/internal/infra/idgen"
	"github.com/AymanKastali/iam-base/internal/infra/jwt"
	"github.com/AymanKastali/iam-base/internal/infra/passwordhash"
	"github.com/AymanKastali/iam-base/internal/infra/postgres"
	"github.com/AymanKastali/iam-base/internal/infra/refreshtoken"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Application bundles what cmd/server needs to serve requests and shut
// down cleanly.
type Application struct {
	Router http.Handler
	Pool   *pgxpool.Pool
}

// Build runs pending migrations and wires every dependency the identity
// module needs, from the Postgres pool up through the HTTP router.
func Build(ctx context.Context, cfg config.Config) (*Application, error) {
	if err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		return nil, err
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.LoadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		pool.Close()
		return nil, err
	}

	repo := postgres.NewAccountRepository(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer := jwt.NewRSAIssuer(privateKey, cfg.JWTKeyID, cfg.AccessTokenTTL, systemClock{})
	tokenGen := refreshtoken.SHA256Generator{}
	idGen := idgen.UUIDGenerator{}
	clock := systemClock{}

	registerHandler := httpapi.RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: hasher, Policy: domain.MinLengthPasswordPolicy{}, IDGen: idGen}}
	loginHandler := httpapi.LoginHandler{Handler: command.LoginHandler{
		Repo: repo, Hasher: hasher, Issuer: issuer,
		RefreshRepo: refreshTokenRepo, TokenGen: tokenGen, IDGen: idGen,
		Clock: clock, RefreshTokenTTL: cfg.RefreshTokenTTL,
	}}
	refreshHandler := httpapi.RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: refreshTokenRepo, TokenGen: tokenGen, Issuer: issuer,
		Clock: clock, RefreshTokenTTL: cfg.RefreshTokenTTL,
	}}
	logoutHandler := httpapi.LogoutHandler{Handler: command.RevokeSessionHandler{Repo: refreshTokenRepo}}
	jwksHandler := httpapi.JWKSHandler{Handler: query.GetJWKSHandler{Port: issuer}}
	limiter := httpapi.NewIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	router := httpapi.NewRouter(registerHandler, loginHandler, refreshHandler, logoutHandler, jwksHandler, limiter)

	return &Application{Router: router, Pool: pool}, nil
}
```

- [ ] **Step 2: Verify the build succeeds**

Run: `go build ./...`
Expected: succeeds (this is the fix for Task 11's expected build failure)

- [ ] **Step 3: Run the full test suite**

Run: `go test ./...`
Expected: PASS across every package (requires Docker running locally for the `postgres` package's
testcontainer-based tests)

- [ ] **Step 4: Commit**

```bash
git add internal/infra/composition/composition.go
git commit -m "feat: wire refresh/logout handlers into the composition root"
```

---

### Task 14: Manual smoke test, deployment config, and final verification

**Files:**
- Modify: `deployments/docker-compose.yml`

This task can't be meaningfully TDD'd — it's an end-to-end manual check against the real running
stack, mirroring slice 1's own smoke-test steps.

- [ ] **Step 1: Add `REFRESH_TOKEN_TTL` to the compose file**

Modify `deployments/docker-compose.yml`'s `identity` service `environment` block:

```yaml
    environment:
      PORT: "8080"
      DATABASE_URL: "postgres://iam:iam@postgres:5432/iam?sslmode=disable"
      JWT_PRIVATE_KEY_PATH: "/etc/iam/private.pem"
      JWT_KEY_ID: "1"
      ACCESS_TOKEN_TTL: "15m"
      REFRESH_TOKEN_TTL: "720h"
      RATE_LIMIT_RPS: "5"
      RATE_LIMIT_BURST: "10"
```

- [ ] **Step 2: Run the stack**

Run (reuses the signing key generated for slice 1's smoke test, if it still exists under
`deployments/keys/`; otherwise regenerate it first with the `-traditional` `openssl genrsa` command
from that plan):

```bash
docker compose -f deployments/docker-compose.yml up --build -d
```
Expected: both containers healthy — `docker compose -f deployments/docker-compose.yml ps` shows
`identity` and `postgres` running.

- [ ] **Step 3: Smoke-test register → login → refresh → logout → refresh-after-logout**

```bash
curl -s -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"slice2@test.com","password":"secret123"}'
```
Expected: HTTP 201.

```bash
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"slice2@test.com","password":"secret123"}')
echo "$LOGIN_RESPONSE"
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
```
Expected: HTTP 200 body now includes a non-empty `refresh_token` alongside `access_token`.

```bash
curl -s -X POST http://localhost:8080/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```
Expected: HTTP 200 with a new `access_token` and a new `refresh_token` (different from the one sent).

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```
Expected: `401` — the old refresh token was consumed by the previous step's rotation; presenting it
again is reuse of a superseded token.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/v1/auth/logout \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```
Expected: `204` — logout is idempotent, so this succeeds even though the token above was already
revoked by the reuse-detection step.

- [ ] **Step 4: Tear down**

```bash
docker compose -f deployments/docker-compose.yml down
```

- [ ] **Step 5: Full verification and commit**

```bash
go build ./...
go test ./...
golangci-lint run
gofmt -l .
```
Expected: build succeeds, all tests pass, no lint findings, `gofmt -l .` prints nothing.

```bash
git add deployments/docker-compose.yml
git commit -m "feat(deploy): add REFRESH_TOKEN_TTL to docker-compose"
```

---

## Self-Review Notes

- **Spec coverage:** `RefreshTokenFamily` aggregate with `Rotate`/reuse-detection (Task 2),
  refresh-token table + repo (Task 8), `POST /v1/auth/refresh` (Tasks 6, 9), `POST /v1/auth/logout`
  (Tasks 7, 10), login response extended with a refresh token (Task 5). All four items from design
  doc §10's Slice 2 description are covered. The design doc's "no cross-aggregate transactions"
  constraint (§7) is satisfied structurally: `LoginHandler.Handle` calls `h.Repo.FindByEmail` and
  then, in a separate step, `h.issueRefreshFamily` which calls `h.RefreshRepo.Save` — two
  independent repository calls, no shared transaction.
- **Type consistency:** `domain.FamilyID` flows unchanged from `IssueFamily`/`Reconstitute...` →
  `RefreshTokenRepository` → command handlers → the `<familyID>.<secret>` wire format → HTTP
  responses. `app.RefreshTokenGenerator`'s `Generate()`/`Hash()` signatures match between
  `ports.go`, the `fake`/`stub` test doubles, and `refreshtoken.SHA256Generator`. `LoginHandler`,
  `RotateRefreshTokenHandler`, and `RevokeSessionHandler` all depend on `domain.RefreshTokenRepository`
  with identical `Save`/`FindByID` signatures throughout.
- **No placeholders:** every step above shows complete, real code — no `TODO`s, no "add appropriate
  handling," no code elided as "similar to Task N." The one intentional cross-task dependency called
  out explicitly is Task 11's router-signature change temporarily breaking the build until Task 13's
  composition-root update — flagged in Task 11's own verification step so it isn't mistaken for a
  mistake.
- **Test-double naming convention preserved:** `internal/app/command` tests use the `fake*` prefix
  (`fakeRefreshTokenRepo`, `fakeTokenGenerator`, `fakeClock`, matching existing `fakeAccountRepo`/
  `fakeHasher`/`fakeIDGenerator`); `internal/infra/httpapi` tests use the `stub*` prefix
  (`stubRefreshTokenRepo`, `stubTokenGenerator`, `stubClock`, matching existing `stubAccountRepo`/
  `stubHasher`/`stubIDGenerator`).

---

## Backlog (after this plan)

None — this is the last slice of iam-base's phase 1 per `docs/design/iam-base-service.md` §10.
Phase 2 (email verification, password reset, per-client OAuth2 scopes) is a separate future design
increment; revisit via `/revai:design` once phase 1 is running in production, not via a direct
`/revai:prepare` off this plan.
