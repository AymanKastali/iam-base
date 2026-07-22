# Code-First OpenAPI Docs with Huma Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the identity service's API self-documenting by generating its OpenAPI 3.1 spec directly from the Go handler code (code-first) using Huma v2, with an interactive docs UI visible at `/docs`.

**Architecture:** Keep the existing `go-chi/chi` router as the underlying mux (already a direct dependency) and wrap it with Huma's `humachi` adapter. Convert the five existing `http.Handler` structs in `internal/infra/httpapi` into Huma operations — each keeps its existing app-layer command/query call unchanged, but its transport method becomes `Handle(ctx context.Context, input *XInput) (*XOutput, error)` instead of `ServeHTTP`, with typed `Input`/`Output` structs replacing manual JSON decode/encode. `composition.Build` and `cmd/server/main.go` need **no changes** — `Application.Router` is already typed `http.Handler`, and the handler struct variables passed into `httpapi.NewRouter(...)` keep their exact current types.

**Tech Stack:** `github.com/danielgtaylor/huma/v2` v2.39.0 (verified via a local spike — see Global Constraints), its `adapters/humachi` sub-package, existing `github.com/go-chi/chi/v5` v5.3.1.

## Global Constraints

- Go 1.26, module `github.com/AymanKastali/iam-base`. Add `github.com/danielgtaylor/huma/v2 v2.39.0` as a **direct** dependency; run `go mod tidy` after adding the import so `go.sum` picks up its transitive deps (`fxamacker/cbor`, `x448/float16`, etc).
- **Error format decision (user-approved):** switch all 4 POST endpoints from the old custom `{"error":{"code":"...","message":"..."}}` envelope to Huma's native RFC 9457 `application/problem+json` format (`{"title","status","detail","errors"}`). This is a deliberate, approved breaking change to the wire contract — do not try to preserve the old envelope.
- **Docs UI decision (user-approved):** use Huma's default renderer (Stoplight Elements) at `/docs` — do not set `config.DocsRenderer`.
- Disable Huma's automatic `$schema` link injection on success response bodies via `config.CreateHooks = nil` in `NewRouter`, so the existing success-response JSON shapes (`{"access_token":...}`, `{"id":...}`, etc.) stay byte-for-byte unchanged — only error responses change shape.
- Every fact below (exact status codes, field names, config knobs) was verified against real `huma/v2 v2.39.0` code run in a throwaway spike, not from memory — see the per-task notes for what each verified.
- Do not touch `internal/infra/composition/composition.go` or `cmd/server/main.go` — verified no change is needed there.
- `internal/infra/httpapi/response.go` (the old `decodeJSON`/`writeJSON`/`writeError`/`errorResponse` helpers) becomes fully dead once every handler is converted and must be deleted, not left unused.
- The existing 64KB body cap (`maxRequestBodyBytes = 1 << 16`) must be preserved exactly via Huma's `Operation.MaxBodyBytes` field (Huma's own default is 1MB) — verified that exceeding it returns **413**, not the old 400.

---

### Task 1: Add the Huma dependency and rewrite error mapping for RFC 9457

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `internal/infra/httpapi/errors.go`
- Create: `internal/infra/httpapi/errors_test.go`

**Interfaces:**
- Produces: `mapAppError(action string, err error) error` — a new function alongside the existing `respondError`. Returns a `huma.StatusError` (which satisfies `error`) instead of writing directly to an `http.ResponseWriter`. Every Huma-converted handler task (3-7) calls this.
- Keeps: `respondError(w http.ResponseWriter, action string, err error)` and the full `kindedError` interface (`Kind()` + `Code()`) **unchanged, still present** — handlers not yet converted (everything until Task 7 finishes) still call it, and it still depends on `writeError` in `response.go`. Task 8 removes `respondError` and trims `kindedError` down to just `Kind()` once no handler calls it anymore and `response.go` is deleted. Do NOT delete `respondError` in this task — doing so breaks the build, since Tasks 3-7 haven't converted their handlers yet.
- Produces: `statusForKind(k app.Kind) int` — unchanged signature/behavior, kept as-is.

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/danielgtaylor/huma/v2@v2.39.0`
Expected: `go.mod` gains a `require github.com/danielgtaylor/huma/v2 v2.39.0` line.

- [ ] **Step 2: Write the failing test**

Create `internal/infra/httpapi/errors_test.go`:

```go
package httpapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app"
)

func TestMapAppError_KindedError(t *testing.T) {
	cases := []struct {
		name       string
		kind       app.Kind
		wantStatus int
	}{
		{"validation", app.KindValidation, http.StatusUnprocessableEntity},
		{"conflict", app.KindConflict, http.StatusConflict},
		{"unauthorized", app.KindUnauthorized, http.StatusUnauthorized},
		{"not_found", app.KindNotFound, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := app.NewError(c.kind, "some_code", errors.New("boom"))

			mapped := mapAppError("test", err)

			statusErr, ok := mapped.(huma.StatusError)
			if !ok {
				t.Fatalf("mapAppError() = %v, want a huma.StatusError", mapped)
			}
			if statusErr.GetStatus() != c.wantStatus {
				t.Errorf("status = %d, want %d", statusErr.GetStatus(), c.wantStatus)
			}
			if statusErr.Error() != "boom" {
				t.Errorf("message = %q, want %q", statusErr.Error(), "boom")
			}
		})
	}
}

func TestMapAppError_UnclassifiedError_Returns500(t *testing.T) {
	mapped := mapAppError("test", errors.New("boom"))

	statusErr, ok := mapped.(huma.StatusError)
	if !ok {
		t.Fatalf("mapAppError() = %v, want a huma.StatusError", mapped)
	}
	if statusErr.GetStatus() != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", statusErr.GetStatus())
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestMapAppError -v`
Expected: FAIL — `mapAppError` is undefined (compile error).

- [ ] **Step 4: Replace `errors.go`**

Replace the full contents of `internal/infra/httpapi/errors.go` with (this **adds** `mapAppError` alongside the existing `respondError` — it does not remove anything; `respondError` still backs the not-yet-converted handlers until Task 8):

```go
package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app"
)

// kindedError is implemented by any app-layer error that carries a Kind and
// a machine-readable Code (see app.Error). Handlers never name individual
// errors — they just call respondError or mapAppError.
type kindedError interface {
	error
	Kind() app.Kind
	Code() string
}

// respondError classifies err via kindedError and writes the matching
// response; anything that doesn't implement it is logged and returned as a
// generic 500. Used by handlers not yet converted to Huma operations. Once
// every handler calls mapAppError instead (Tasks 3-7 complete), Task 8
// deletes this function together with response.go.
func respondError(w http.ResponseWriter, action string, err error) {
	if ke, ok := errors.AsType[kindedError](err); ok {
		writeError(w, statusForKind(ke.Kind()), ke.Code(), ke.Error())
		return
	}
	log.Printf("%s: unexpected error: %v", action, err)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

// mapAppError classifies err via kindedError and returns the matching
// huma.StatusError; anything that doesn't implement it is logged and mapped
// to a generic 500. This is what every Huma-converted handler (Tasks 3-7)
// calls instead of respondError.
func mapAppError(action string, err error) error {
	if ke, ok := errors.AsType[kindedError](err); ok {
		return huma.NewError(statusForKind(ke.Kind()), ke.Error())
	}
	log.Printf("%s: unexpected error: %v", action, err)
	return huma.NewError(http.StatusInternalServerError, "internal error")
}

func statusForKind(k app.Kind) int {
	switch k {
	case app.KindValidation:
		// A business rule rejected the submitted data itself (e.g. password
		// policy, email format) — the payload is well-formed but semantically
		// invalid.
		return http.StatusUnprocessableEntity
	case app.KindConflict:
		// The data is valid but conflicts with existing state (e.g. email
		// already registered) — RFC 9110's 409, not 422.
		return http.StatusConflict
	case app.KindUnauthorized:
		return http.StatusUnauthorized
	case app.KindNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestMapAppError -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/infra/httpapi/errors.go internal/infra/httpapi/errors_test.go
git commit -m "feat(httpapi): add huma dependency and RFC 9457 error mapping"
```

---

### Task 2: Extract `IPRateLimiter.Allow` and add a Huma-native middleware adapter

**Files:**
- Modify: `internal/infra/httpapi/ratelimit.go`
- Modify: `internal/infra/httpapi/ratelimit_test.go`

**Interfaces:**
- Produces: `func (l *IPRateLimiter) Allow(remoteAddr string) bool` — the IP-extraction + token-bucket check, now the single place both the old-style and Huma middleware call.
- Produces: `func (l *IPRateLimiter) HumaMiddleware(api huma.API) func(huma.Context, func(huma.Context))` — a factory returning a Huma middleware function. Consumed by Task 8's `router.go`.
- Removes: `func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler` — dead once `router.go` (Task 8) no longer wraps raw `http.Handler`s. Removed in this task since its only test coverage is being rewritten now; `router.go` still compiles independently until Task 8 because Go doesn't require call sites to exist yet within the same task.

**Verified facts used below** (via local Huma v2.39.0 spike):
- `huma.Context` has a `RemoteAddr() string` method that returns the exact same `"ip:port"` string as `http.Request.RemoteAddr` — no need for `humachi.Unwrap`.
- `huma.WriteErr(api huma.API, ctx huma.Context, status int, msg string, errs ...error) error` writes the error response and matches the RFC 9457 shape from Task 1.
- Middleware signature is exactly `func(ctx huma.Context, next func(huma.Context))`.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/ratelimit_test.go`:

```go
package httpapi

import (
	"testing"
	"time"
)

func TestIPRateLimiter_Allow(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1) // 1 request burst, refills slowly

	if !limiter.Allow("1.2.3.4:5555") {
		t.Fatal("first Allow() = false, want true")
	}
	if limiter.Allow("1.2.3.4:5555") {
		t.Fatal("second Allow() = true, want false (burst exhausted)")
	}
}

func TestIPRateLimiter_Allow_IsolatesByIP(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)

	if !limiter.Allow("1.2.3.4:5555") {
		t.Fatal("IP A first Allow() = false, want true")
	}
	if limiter.Allow("1.2.3.4:5555") {
		t.Fatal("IP A second Allow() = true, want false")
	}
	if !limiter.Allow("5.6.7.8:9999") {
		t.Fatal("IP B first Allow() = false, want true — must not be throttled by IP A's limiter")
	}
}

func TestIPRateLimiter_Allow_HandlesAddrWithoutPort(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)

	if !limiter.Allow("not-a-host-port") {
		t.Fatal("first Allow() = false, want true")
	}
	if limiter.Allow("not-a-host-port") {
		t.Fatal("second Allow() = true, want false")
	}
}

func TestIPRateLimiter_EvictStale(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)
	limiter.limiterFor("1.2.3.4")
	limiter.limiterFor("5.6.7.8")

	now := time.Now()
	limiter.mu.Lock()
	limiter.limiters["1.2.3.4"].lastSeen = now.Add(-2 * staleEntryTTL)
	limiter.mu.Unlock()

	limiter.evictStale(now)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, ok := limiter.limiters["1.2.3.4"]; ok {
		t.Error("evictStale() did not remove the stale entry for 1.2.3.4")
	}
	if _, ok := limiter.limiters["5.6.7.8"]; !ok {
		t.Error("evictStale() incorrectly removed the fresh entry for 5.6.7.8")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestIPRateLimiter -v`
Expected: FAIL — `limiter.Allow` is undefined (compile error); the old `TestIPRateLimiter_Middleware*` tests are gone so no old failures apply.

- [ ] **Step 3: Replace `ratelimit.go`**

Replace the full contents of `internal/infra/httpapi/ratelimit.go`:

```go
package httpapi

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/time/rate"
)

// staleEntryTTL and evictionInterval bound IPRateLimiter's memory: without
// them, a limiter entry is created per distinct source IP and never removed,
// letting an attacker who can mint many source addresses (trivial over IPv6)
// grow the map without limit.
const (
	staleEntryTTL    = 10 * time.Minute
	evictionInterval = time.Minute
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	rps      rate.Limit
	burst    int
}

func NewIPRateLimiter(rps float64, burst int) *IPRateLimiter {
	l := &IPRateLimiter{
		limiters: make(map[string]*limiterEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go l.evictStaleLoop()
	return l
}

func (l *IPRateLimiter) evictStaleLoop() {
	ticker := time.NewTicker(evictionInterval)
	defer ticker.Stop()
	for range ticker.C {
		l.evictStale(time.Now())
	}
}

func (l *IPRateLimiter) evictStale(now time.Time) {
	cutoff := now.Add(-staleEntryTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}

func (l *IPRateLimiter) limiterFor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.limiters[ip]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// Allow reports whether a request from remoteAddr (an "ip:port" string, as
// found on http.Request.RemoteAddr and huma.Context.RemoteAddr()) may
// proceed.
func (l *IPRateLimiter) Allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return l.limiterFor(host).Allow()
}

// HumaMiddleware adapts Allow into a Huma operation middleware, writing a 429
// via the shared RFC 9457 error format (huma.WriteErr) when the caller's IP
// has exceeded its budget.
func (l *IPRateLimiter) HumaMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if !l.Allow(ctx.RemoteAddr()) {
			_ = huma.WriteErr(api, ctx, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(ctx)
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestIPRateLimiter -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/ratelimit.go internal/infra/httpapi/ratelimit_test.go
git commit -m "refactor(httpapi): extract IPRateLimiter.Allow and add a Huma middleware adapter"
```

---

### Task 3: Convert the JWKS handler to a Huma operation

**Files:**
- Modify: `internal/infra/httpapi/jwks_handler.go`
- Modify: `internal/infra/httpapi/jwks_handler_test.go`

**Interfaces:**
- Consumes: `query.GetJWKSHandler.Handle(ctx) (query.JWKSDocument, error)` (unchanged, from `internal/app/query/jwks.go`).
- Produces: `type JWKSInput struct{}`, `type JWKSOutput struct{ Body query.JWKSDocument }`, `func (h JWKSHandler) Handle(ctx context.Context, input *JWKSInput) (*JWKSOutput, error)`. Consumed by Task 8's `router.go`.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/jwks_handler_test.go`:

```go
package httpapi

import (
	"context"
	"testing"

	"github.com/AymanKastali/iam-base/internal/app/query"
)

type stubJWKSPort struct{ doc query.JWKSDocument }

func (s stubJWKSPort) JWKS() query.JWKSDocument { return s.doc }

func TestJWKSHandler_Handle(t *testing.T) {
	doc := query.JWKSDocument{Keys: []query.JWKSKey{{Kty: "RSA", Kid: "1", Alg: "RS256", Use: "sig", N: "n", E: "e"}}}
	h := JWKSHandler{Handler: query.GetJWKSHandler{Port: stubJWKSPort{doc: doc}}}

	out, err := h.Handle(context.Background(), &JWKSInput{})

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if len(out.Body.Keys) != 1 || out.Body.Keys[0].Kid != "1" {
		t.Errorf("Body = %+v, want the JWKS document unchanged", out.Body)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestJWKSHandler -v`
Expected: FAIL — `JWKSInput`/`JWKSOutput` undefined (compile error).

- [ ] **Step 3: Replace `jwks_handler.go`**

Replace the full contents of `internal/infra/httpapi/jwks_handler.go`:

```go
package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/query"
)

type JWKSHandler struct {
	Handler query.GetJWKSHandler
}

type JWKSInput struct{}

type JWKSOutput struct {
	Body query.JWKSDocument
}

func (h JWKSHandler) Handle(ctx context.Context, input *JWKSInput) (*JWKSOutput, error) {
	doc, err := h.Handler.Handle(ctx)
	if err != nil {
		return nil, mapAppError("jwks", err)
	}
	return &JWKSOutput{Body: doc}, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestJWKSHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/jwks_handler.go internal/infra/httpapi/jwks_handler_test.go
git commit -m "feat(httpapi): convert JWKS handler to a Huma operation"
```

---

### Task 4: Convert the register handler to a Huma operation

**Files:**
- Modify: `internal/infra/httpapi/register_handler.go`
- Modify: `internal/infra/httpapi/register_handler_test.go`

**Interfaces:**
- Consumes: `command.RegisterAccountHandler.Handle(ctx, command.RegisterAccountCommand{Email, Password string}) (domain.AccountID, error)` (unchanged).
- Produces: `type RegisterInput struct{ Body struct{ Email, Password string } }`, `type RegisterOutput struct{ Body struct{ ID string } }`, `func (h RegisterHandler) Handle(ctx context.Context, input *RegisterInput) (*RegisterOutput, error)`. Consumed by Task 8's `router.go`.
- Note: the `BodyTooLarge` scenario moves to Task 8's `router_test.go` — Huma enforces `MaxBodyBytes` in the transport adapter, before `Handle` is ever called, so it cannot be exercised by calling `Handle` directly.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/register_handler_test.go`:

```go
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// sampleCredential is a fixture value, not a secret — named so it never reads
// like a hardcoded credential in a struct literal or JSON body.
const sampleCredential = "secret123"

type stubAccountRepo struct {
	saved   *domain.Account
	saveErr error
}

func (r *stubAccountRepo) Save(ctx context.Context, a *domain.Account) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.saved = a
	return nil
}

func (r *stubAccountRepo) FindByEmail(ctx context.Context, e domain.Email) (*domain.Account, error) {
	if r.saved != nil && r.saved.Email() == e {
		return r.saved, nil
	}
	return nil, domain.ErrAccountNotFound
}

type stubHasher struct{}

func (stubHasher) Hash(password string) (domain.Credential, error) {
	return domain.NewCredential("hashed:"+password, "argon2id", 1)
}

func (stubHasher) Verify(c domain.Credential, password string) (bool, error) {
	return c.Hash() == "hashed:"+password, nil
}

type stubIDGenerator struct{}

func (stubIDGenerator) NewAccountID() (domain.AccountID, error) {
	return domain.NewAccountID("stub-account-id")
}

func (stubIDGenerator) NewFamilyID() (domain.FamilyID, error) {
	return domain.NewFamilyID("stub-family-id")
}

func newRegisterInput(email, password string) *RegisterInput {
	input := &RegisterInput{}
	input.Body.Email = email
	input.Body.Password = password
	return input
}

func TestRegisterHandler_Handle_Success(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	out, err := h.Handle(context.Background(), newRegisterInput("a@b.com", sampleCredential))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if out.Body.ID == "" {
		t.Error("Body.ID is empty, want the new account's ID")
	}
}

func TestRegisterHandler_Handle_DuplicateEmail(t *testing.T) {
	repo := &stubAccountRepo{saveErr: domain.ErrEmailAlreadyRegistered}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	_, err := h.Handle(context.Background(), newRegisterInput("a@b.com", sampleCredential))

	assertStatus(t, err, http.StatusConflict)
}

func TestRegisterHandler_Handle_InvalidEmail(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	_, err := h.Handle(context.Background(), newRegisterInput("not-an-email", sampleCredential))

	assertStatus(t, err, http.StatusUnprocessableEntity)
}

func TestRegisterHandler_Handle_PasswordTooShort(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	_, err := h.Handle(context.Background(), newRegisterInput("a@b.com", "short"))

	assertStatus(t, err, http.StatusUnprocessableEntity)
}

func TestRegisterHandler_Handle_UnexpectedError(t *testing.T) {
	repo := &stubAccountRepo{saveErr: errors.New("boom")}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	_, err := h.Handle(context.Background(), newRegisterInput("a@b.com", sampleCredential))

	assertStatus(t, err, http.StatusInternalServerError)
}

// assertStatus fails the test unless err is a huma.StatusError with the
// given status. Shared by every converted handler's test file.
func assertStatus(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want a huma.StatusError")
	}
	statusErr, ok := err.(huma.StatusError)
	if !ok {
		t.Fatalf("error = %v (%T), want a huma.StatusError", err, err)
	}
	if statusErr.GetStatus() != want {
		t.Errorf("status = %d, want %d", statusErr.GetStatus(), want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestRegisterHandler -v`
Expected: FAIL — `RegisterInput`/`RegisterOutput` undefined (compile error).

- [ ] **Step 3: Replace `register_handler.go`**

Replace the full contents of `internal/infra/httpapi/register_handler.go`:

```go
package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RegisterHandler struct {
	Handler command.RegisterAccountHandler
}

type RegisterInput struct {
	Body struct {
		Email    string `json:"email" required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

type RegisterOutput struct {
	Body struct {
		ID string `json:"id"`
	}
}

func (h RegisterHandler) Handle(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	id, err := h.Handler.Handle(ctx, command.RegisterAccountCommand{Email: input.Body.Email, Password: input.Body.Password})
	if err != nil {
		return nil, mapAppError("register", err)
	}
	out := &RegisterOutput{}
	out.Body.ID = id.String()
	return out, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestRegisterHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/register_handler.go internal/infra/httpapi/register_handler_test.go
git commit -m "feat(httpapi): convert register handler to a Huma operation"
```

---

### Task 5: Convert the login handler to a Huma operation

**Files:**
- Modify: `internal/infra/httpapi/login_handler.go`
- Modify: `internal/infra/httpapi/login_handler_test.go`

**Interfaces:**
- Consumes: `command.LoginHandler.Handle(ctx, command.LoginCommand{Email, Password string}) (command.LoginResult{AccessToken, ExpiresAt time.Time, RefreshToken string}, error)` (unchanged). Consumes `assertStatus` from Task 4.
- Produces: `type LoginInput struct{ Body struct{ Email, Password string } }`, `type LoginOutput struct{ Body struct{ AccessToken, TokenType, ExpiresAt, RefreshToken string } }`, `func (h LoginHandler) Handle(ctx context.Context, input *LoginInput) (*LoginOutput, error)`. Consumed by Task 8's `router.go`.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/login_handler_test.go`:

```go
package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type stubIssuer struct{}

func (stubIssuer) Issue(ctx context.Context, id domain.AccountID) (string, time.Time, error) {
	return "signed-jwt", time.Now().Add(15 * time.Minute), nil
}

func newLoginInput(email, password string) *LoginInput {
	input := &LoginInput{}
	input.Body.Email = email
	input.Body.Password = password
	return input
}

func TestLoginHandler_Handle_Success(t *testing.T) {
	repo := &stubAccountRepo{}
	registerHandler := command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}
	if _, err := registerHandler.Handle(context.Background(), command.RegisterAccountCommand{Email: "a@b.com", Password: sampleCredential}); err != nil {
		t.Fatalf("fixture register: %v", err)
	}

	h := LoginHandler{Handler: command.LoginHandler{
		Repo:            repo,
		Hasher:          stubHasher{},
		Issuer:          stubIssuer{},
		RefreshRepo:     newStubRefreshTokenRepo(),
		TokenGen:        stubTokenGenerator{nextSecret: "s", nextHash: "h"},
		IDGen:           stubIDGenerator{},
		Clock:           stubClock{now: time.Now()},
		RefreshTokenTTL: 24 * time.Hour,
	}}

	out, err := h.Handle(context.Background(), newLoginInput("a@b.com", sampleCredential))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if out.Body.AccessToken != "signed-jwt" {
		t.Errorf("AccessToken = %v, want signed-jwt", out.Body.AccessToken)
	}
	if out.Body.RefreshToken == "" {
		t.Error("RefreshToken missing from login response")
	}
}

func TestLoginHandler_Handle_InvalidCredentials(t *testing.T) {
	repo := &stubAccountRepo{}
	h := LoginHandler{Handler: command.LoginHandler{
		Repo:            repo,
		Hasher:          stubHasher{},
		Issuer:          stubIssuer{},
		RefreshRepo:     newStubRefreshTokenRepo(),
		TokenGen:        stubTokenGenerator{nextSecret: "s", nextHash: "h"},
		IDGen:           stubIDGenerator{},
		Clock:           stubClock{now: time.Now()},
		RefreshTokenTTL: 24 * time.Hour,
	}}

	_, err := h.Handle(context.Background(), newLoginInput("missing@b.com", sampleCredential))

	assertStatus(t, err, http.StatusUnauthorized)
}

func TestLoginHandler_Handle_DisabledAccount(t *testing.T) {
	repo := &stubAccountRepo{}
	registerHandler := command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}
	if _, err := registerHandler.Handle(context.Background(), command.RegisterAccountCommand{Email: "a@b.com", Password: sampleCredential}); err != nil {
		t.Fatalf("fixture register: %v", err)
	}
	if err := repo.saved.Disable(); err != nil {
		t.Fatalf("fixture Disable: %v", err)
	}

	h := LoginHandler{Handler: command.LoginHandler{
		Repo:            repo,
		Hasher:          stubHasher{},
		Issuer:          stubIssuer{},
		RefreshRepo:     newStubRefreshTokenRepo(),
		TokenGen:        stubTokenGenerator{nextSecret: "s", nextHash: "h"},
		IDGen:           stubIDGenerator{},
		Clock:           stubClock{now: time.Now()},
		RefreshTokenTTL: 24 * time.Hour,
	}}

	_, err := h.Handle(context.Background(), newLoginInput("a@b.com", sampleCredential))

	assertStatus(t, err, http.StatusUnauthorized)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestLoginHandler -v`
Expected: FAIL — `LoginInput`/`LoginOutput` undefined (compile error).

- [ ] **Step 3: Replace `login_handler.go`**

Replace the full contents of `internal/infra/httpapi/login_handler.go`:

```go
package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LoginHandler struct {
	Handler command.LoginHandler
}

type LoginInput struct {
	Body struct {
		Email    string `json:"email" required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

type LoginOutput struct {
	Body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresAt    string `json:"expires_at"`
		RefreshToken string `json:"refresh_token"`
	}
}

func (h LoginHandler) Handle(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	result, err := h.Handler.Handle(ctx, command.LoginCommand{Email: input.Body.Email, Password: input.Body.Password})
	if err != nil {
		return nil, mapAppError("login", err)
	}
	out := &LoginOutput{}
	out.Body.AccessToken = result.AccessToken
	out.Body.TokenType = "Bearer"
	out.Body.ExpiresAt = result.ExpiresAt.Format(http.TimeFormat)
	out.Body.RefreshToken = result.RefreshToken
	return out, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestLoginHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/login_handler.go internal/infra/httpapi/login_handler_test.go
git commit -m "feat(httpapi): convert login handler to a Huma operation"
```

---

### Task 6: Convert the refresh handler to a Huma operation

**Files:**
- Modify: `internal/infra/httpapi/refresh_handler.go`
- Modify: `internal/infra/httpapi/refresh_handler_test.go`

**Interfaces:**
- Consumes: `command.RotateRefreshTokenHandler.Handle(ctx, command.RotateRefreshTokenCommand{RefreshToken string}) (command.RefreshResult{AccessToken, RefreshToken string, AccessTokenExpiresAt time.Time}, error)` (unchanged). Consumes `assertStatus` from Task 4, `stubIssuer` from Task 5.
- Produces: `type RefreshInput struct{ Body struct{ RefreshToken string } }`, `type RefreshOutput struct{ Body struct{ AccessToken, TokenType, ExpiresAt, RefreshToken string } }`, `func (h RefreshHandler) Handle(ctx context.Context, input *RefreshInput) (*RefreshOutput, error)`. Consumed by Task 8's `router.go`.
- Also keeps producing (unchanged, still needed by Tasks 5/7/8's tests): `stubRefreshTokenRepo`/`newStubRefreshTokenRepo()`, `stubTokenGenerator`, `stubClock`.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/refresh_handler_test.go`:

```go
// internal/infra/httpapi/refresh_handler_test.go
package httpapi

import (
	"context"
	"net/http"
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

func newRefreshInput(refreshToken string) *RefreshInput {
	input := &RefreshInput{}
	input.Body.RefreshToken = refreshToken
	return input
}

func TestRefreshHandler_Handle_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	now := time.Now()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:old-secret", now.Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	newSecretValue := "new-secret"
	h := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: repo,
		TokenGen: stubTokenGenerator{
			nextSecret: newSecretValue,
			nextHash:   "hash:" + newSecretValue,
		},
		Issuer:          stubIssuer{},
		Clock:           stubClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}}

	out, err := h.Handle(context.Background(), newRefreshInput("family-1.old-secret"))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if out.Body.RefreshToken != "family-1.new-secret" {
		t.Errorf("RefreshToken = %v, want family-1.new-secret", out.Body.RefreshToken)
	}
}

func TestRefreshHandler_Handle_InvalidRefreshToken(t *testing.T) {
	h := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: newStubRefreshTokenRepo(), TokenGen: stubTokenGenerator{}, Issuer: stubIssuer{}, Clock: stubClock{now: time.Now()}, RefreshTokenTTL: time.Hour,
	}}

	_, err := h.Handle(context.Background(), newRefreshInput("unknown-family.secret"))

	assertStatus(t, err, http.StatusUnauthorized)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestRefreshHandler -v`
Expected: FAIL — `RefreshInput`/`RefreshOutput` undefined (compile error).

- [ ] **Step 3: Replace `refresh_handler.go`**

Replace the full contents of `internal/infra/httpapi/refresh_handler.go`:

```go
// internal/infra/httpapi/refresh_handler.go
package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RefreshHandler struct {
	Handler command.RotateRefreshTokenHandler
}

type RefreshInput struct {
	Body struct {
		RefreshToken string `json:"refresh_token" required:"true"`
	}
}

type RefreshOutput struct {
	Body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresAt    string `json:"expires_at"`
		RefreshToken string `json:"refresh_token"`
	}
}

func (h RefreshHandler) Handle(ctx context.Context, input *RefreshInput) (*RefreshOutput, error) {
	result, err := h.Handler.Handle(ctx, command.RotateRefreshTokenCommand{RefreshToken: input.Body.RefreshToken})
	if err != nil {
		return nil, mapAppError("refresh", err)
	}
	out := &RefreshOutput{}
	out.Body.AccessToken = result.AccessToken
	out.Body.TokenType = "Bearer"
	out.Body.ExpiresAt = result.AccessTokenExpiresAt.Format(http.TimeFormat)
	out.Body.RefreshToken = result.RefreshToken
	return out, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestRefreshHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/refresh_handler.go internal/infra/httpapi/refresh_handler_test.go
git commit -m "feat(httpapi): convert refresh handler to a Huma operation"
```

---

### Task 7: Convert the logout handler to a Huma operation

**Files:**
- Modify: `internal/infra/httpapi/logout_handler.go`
- Modify: `internal/infra/httpapi/logout_handler_test.go`

**Interfaces:**
- Consumes: `command.RevokeSessionHandler.Handle(ctx, command.RevokeSessionCommand{RefreshToken string}) error` (unchanged). Consumes `newStubRefreshTokenRepo()` from Task 6.
- Produces: `type LogoutInput struct{ Body struct{ RefreshToken string } }`, `type LogoutOutput struct{}` (no `Body` field — an empty response), `func (h LogoutHandler) Handle(ctx context.Context, input *LogoutInput) (*LogoutOutput, error)`. Consumed by Task 8's `router.go`.

- [ ] **Step 1: Write the failing test**

Replace the full contents of `internal/infra/httpapi/logout_handler_test.go`:

```go
// internal/infra/httpapi/logout_handler_test.go
package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

func newLogoutInput(refreshToken string) *LogoutInput {
	input := &LogoutInput{}
	input.Body.RefreshToken = refreshToken
	return input
}

func TestLogoutHandler_Handle_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:secret", time.Now().Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: repo}}

	_, err := h.Handle(context.Background(), newLogoutInput("family-1.secret"))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("logout must revoke the family")
	}
}

func TestLogoutHandler_Handle_UnknownFamily_StillSucceeds(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}

	_, err := h.Handle(context.Background(), newLogoutInput("unknown-family.secret"))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil (logout is idempotent)", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestLogoutHandler -v`
Expected: FAIL — `LogoutInput`/`LogoutOutput` undefined (compile error).

- [ ] **Step 3: Replace `logout_handler.go`**

Replace the full contents of `internal/infra/httpapi/logout_handler.go`:

```go
// internal/infra/httpapi/logout_handler.go
package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LogoutHandler struct {
	Handler command.RevokeSessionHandler
}

type LogoutInput struct {
	Body struct {
		RefreshToken string `json:"refresh_token" required:"true"`
	}
}

type LogoutOutput struct{}

func (h LogoutHandler) Handle(ctx context.Context, input *LogoutInput) (*LogoutOutput, error) {
	if err := h.Handler.Handle(ctx, command.RevokeSessionCommand{RefreshToken: input.Body.RefreshToken}); err != nil {
		return nil, mapAppError("logout", err)
	}
	return &LogoutOutput{}, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestLogoutHandler -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/infra/httpapi/logout_handler.go internal/infra/httpapi/logout_handler_test.go
git commit -m "feat(httpapi): convert logout handler to a Huma operation"
```

---

### Task 8: Wire the Huma-backed router, remove the dead JSON helpers, add wiring-level tests

**Files:**
- Modify: `internal/infra/httpapi/router.go`
- Modify: `internal/infra/httpapi/errors.go`
- Delete: `internal/infra/httpapi/response.go`
- Create: `internal/infra/httpapi/router_test.go`

**Interfaces:**
- Consumes: `RegisterHandler.Handle`, `LoginHandler.Handle`, `RefreshHandler.Handle`, `LogoutHandler.Handle`, `JWKSHandler.Handle` (Tasks 3–7), `IPRateLimiter.HumaMiddleware` (Task 2).
- Produces: `func NewRouter(register RegisterHandler, login LoginHandler, refresh RefreshHandler, logout LogoutHandler, jwks JWKSHandler, limiter *IPRateLimiter) http.Handler` — same call signature/argument order `composition.Build` already uses, so **no change needed there**. Also produces the package-level `const maxRequestBodyBytes = 1 << 16` (moved here from the deleted `response.go`), consumed by every `Operation.MaxBodyBytes` field above and by this task's own test.

**Verified facts used below** (via local Huma v2.39.0 spike):
- `humachi.New(mux, config)` returns a `huma.API` bound to the given `*chi.Mux`; `huma.Register(api, op, handler)` registers routes directly on it.
- An `Operation` with `DefaultStatus: http.StatusCreated` and an Output struct with only a `Body` field (no `Status` field) returns 201 — do **not** add a `Status int` field to an Output struct unless you intend to set it explicitly in every code path; an unset `Status` field makes Huma call `WriteHeader(0)` and panic.
- An Output struct with **no fields at all** (`type LogoutOutput struct{}`) combined with `DefaultStatus: http.StatusNoContent` produces a real 204 with an empty body.
- `config.CreateHooks = nil` removes the `$schema` property Huma otherwise injects into success bodies, keeping `{"id":"..."}`-style bodies unchanged.
- Default paths under `huma.DefaultConfig`: `/openapi.json`, `/openapi.yaml` (spec), `/docs` (Stoplight Elements UI).
- `Operation.MaxBodyBytes` (per-operation, overrides Huma's 1MB default) triggers a **413** (`Request Entity Too Large`) when exceeded — not the old 400.

- [ ] **Step 1: Write the failing tests**

Create `internal/infra/httpapi/router_test.go`:

```go
package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
)

func newTestRouter(limiter *IPRateLimiter) http.Handler {
	repo := &stubAccountRepo{}
	refreshRepo := newStubRefreshTokenRepo()

	register := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}
	login := LoginHandler{Handler: command.LoginHandler{
		Repo: repo, Hasher: stubHasher{}, Issuer: stubIssuer{},
		RefreshRepo: refreshRepo, TokenGen: stubTokenGenerator{nextSecret: "s", nextHash: "h"},
		IDGen: stubIDGenerator{}, Clock: stubClock{now: time.Now()}, RefreshTokenTTL: time.Hour,
	}}
	refresh := RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: refreshRepo, TokenGen: stubTokenGenerator{nextSecret: "s", nextHash: "h"}, Issuer: stubIssuer{}, Clock: stubClock{now: time.Now()}, RefreshTokenTTL: time.Hour,
	}}
	logout := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: refreshRepo}}
	jwks := JWKSHandler{Handler: query.GetJWKSHandler{Port: stubJWKSPort{doc: query.JWKSDocument{Keys: []query.JWKSKey{{Kty: "RSA", Kid: "1"}}}}}}

	return NewRouter(register, login, refresh, logout, jwks, limiter)
}

func TestNewRouter_RateLimitsAuthEndpoints(t *testing.T) {
	router := newTestRouter(NewIPRateLimiter(1, 1))
	body := []byte(`{"email":"a@b.com","password":"secret123"}`)

	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	req1.RemoteAddr = "1.2.3.4:5555"
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code == http.StatusTooManyRequests {
		t.Fatalf("first request status = 429, want it to be let through")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	req2.RemoteAddr = "1.2.3.4:5555"
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429, body = %s", rec2.Code, rec2.Body.String())
	}
}

func TestNewRouter_RejectsOversizedBody(t *testing.T) {
	router := newTestRouter(NewIPRateLimiter(1000, 1000))

	oversizedPassword := strings.Repeat("a", maxRequestBodyBytes)
	body := []byte(`{"email":"a@b.com","password":"` + oversizedPassword + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body = %s", rec.Code, rec.Body.String())
	}
}

func TestNewRouter_ServesOpenAPIAndDocs(t *testing.T) {
	router := newTestRouter(NewIPRateLimiter(1000, 1000))

	for _, path := range []string{"/openapi.json", "/docs"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rec.Code)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/infra/httpapi/... -run TestNewRouter -v`
Expected: FAIL — `NewRouter`'s current signature takes `http.Handler` params and returns `*chi.Mux`; passing concrete handler structs is a compile error until Step 3.

- [ ] **Step 3: Replace `router.go`**

Replace the full contents of `internal/infra/httpapi/router.go`:

```go
package httpapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// maxRequestBodyBytes caps request bodies on public, unauthenticated
// endpoints so a large or slow-drip body can't exhaust server memory.
const maxRequestBodyBytes = 1 << 16 // 64KB

func NewRouter(register RegisterHandler, login LoginHandler, refresh RefreshHandler, logout LogoutHandler, jwks JWKSHandler, limiter *IPRateLimiter) http.Handler {
	mux := chi.NewMux()

	config := huma.DefaultConfig("iam-base", "1.0.0")
	config.CreateHooks = nil // keep success response bodies free of Huma's injected "$schema" field
	api := humachi.New(mux, config)

	rateLimited := huma.Middlewares{limiter.HumaMiddleware(api)}

	huma.Register(api, huma.Operation{
		OperationID:   "register",
		Method:        http.MethodPost,
		Path:          "/v1/auth/register",
		Summary:       "Register a new account",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxRequestBodyBytes,
		Errors:        []int{http.StatusConflict, http.StatusUnprocessableEntity},
		Middlewares:   rateLimited,
	}, register.Handle)

	huma.Register(api, huma.Operation{
		OperationID:  "login",
		Method:       http.MethodPost,
		Path:         "/v1/auth/login",
		Summary:      "Exchange credentials for an access and refresh token",
		Tags:         []string{"Auth"},
		MaxBodyBytes: maxRequestBodyBytes,
		Errors:       []int{http.StatusUnauthorized},
		Middlewares:  rateLimited,
	}, login.Handle)

	huma.Register(api, huma.Operation{
		OperationID:  "refresh",
		Method:       http.MethodPost,
		Path:         "/v1/auth/refresh",
		Summary:      "Rotate a refresh token for a new access/refresh token pair",
		Tags:         []string{"Auth"},
		MaxBodyBytes: maxRequestBodyBytes,
		Errors:       []int{http.StatusUnauthorized},
		Middlewares:  rateLimited,
	}, refresh.Handle)

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodPost,
		Path:          "/v1/auth/logout",
		Summary:       "Revoke a refresh token session",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusNoContent,
		MaxBodyBytes:  maxRequestBodyBytes,
		Middlewares:   rateLimited,
	}, logout.Handle)

	huma.Register(api, huma.Operation{
		OperationID: "get-jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "Fetch the JSON Web Key Set used to verify access tokens",
		Tags:        []string{"Auth"},
	}, jwks.Handle)

	return mux
}
```

- [ ] **Step 4: Trim `errors.go` and delete `response.go`**

By this point (Tasks 3–7 done), no handler calls `respondError` anymore — it and `response.go`'s `writeError`/`writeJSON`/`decodeJSON`/`errorResponse`/`errorBody` are now dead. Remove them together, since `respondError` depends on `writeError`.

Replace the full contents of `internal/infra/httpapi/errors.go` (drops `respondError` and shrinks `kindedError` back down to just `Kind()`, since `mapAppError` never calls `Code()`):

```go
package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app"
)

// kindedError is implemented by any app-layer error that carries a Kind (see
// app.Error). Handlers never name individual errors — they just call
// mapAppError.
type kindedError interface {
	error
	Kind() app.Kind
}

// mapAppError classifies err via kindedError and returns the matching
// huma.StatusError; anything that doesn't implement it is logged and mapped
// to a generic 500. This is the single place that knows how app errors
// become wire responses — handlers only decide when to call it.
func mapAppError(action string, err error) error {
	if ke, ok := errors.AsType[kindedError](err); ok {
		return huma.NewError(statusForKind(ke.Kind()), ke.Error())
	}
	log.Printf("%s: unexpected error: %v", action, err)
	return huma.NewError(http.StatusInternalServerError, "internal error")
}

func statusForKind(k app.Kind) int {
	switch k {
	case app.KindValidation:
		return http.StatusUnprocessableEntity
	case app.KindConflict:
		return http.StatusConflict
	case app.KindUnauthorized:
		return http.StatusUnauthorized
	case app.KindNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
```

Run: `git rm internal/infra/httpapi/response.go`
Expected: `decodeJSON`, `writeJSON`, `writeError`, `errorResponse`, `errorBody` are gone — nothing references them anymore after this step.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/infra/httpapi/... -v`
Expected: PASS — every test in the package, including all of Tasks 1–8's. (Task 1's `errors_test.go` still passes unchanged — it only ever tested `mapAppError`, never `respondError`.)

- [ ] **Step 6: Run the full test suite and static checks**

Run: `go build ./...`
Expected: builds cleanly (confirms `composition.go`/`main.go` needed no changes).

Run: `go test ./...`
Expected: PASS across the whole module.

Run: `gofmt -l .`
Expected: no output (nothing unformatted).

Run: `golangci-lint run`
Expected: no findings.

- [ ] **Step 7: Commit**

```bash
git add internal/infra/httpapi/router.go internal/infra/httpapi/router_test.go internal/infra/httpapi/errors.go
git rm internal/infra/httpapi/response.go
git commit -m "feat(httpapi): wire a Huma-backed router exposing OpenAPI docs at /docs"
```

---

### Task 9: End-to-end smoke test via Docker Compose

**Files:** none (verification only).

- [ ] **Step 1: Build and start the stack**

Run: `docker compose -f deployments/docker-compose.yml up -d --build`
Expected: both `identity` and `postgres` containers report `Up`/healthy.

- [ ] **Step 2: Confirm the docs UI and spec are reachable**

Run: `curl -sf -o /dev/null -w "%{http_code}\n" http://localhost:8080/docs`
Expected: `200`

Run: `curl -sf http://localhost:8080/openapi.json | head -c 200`
Expected: valid JSON starting with `{"$schema"...` or `{"openapi":"3.1...`, listing the 5 registered operations.

- [ ] **Step 3: Confirm a real request still works end-to-end**

Run: `curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/v1/auth/register -H "Content-Type: application/json" -d '{"email":"smoke@example.com","password":"secret123"}'`
Expected: `201`

- [ ] **Step 4: Tear down**

Run: `docker compose -f deployments/docker-compose.yml down`
Expected: containers and network removed cleanly.
