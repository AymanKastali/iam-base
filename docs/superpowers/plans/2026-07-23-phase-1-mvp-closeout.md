# Phase 1 MVP Closeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close out phase 1 of iam-base: JWT signing supports multiple keys (rotation without downtime), the service exposes a liveness endpoint and restarts itself under docker-compose, and a README documents how to run and deploy it.

**Architecture:** Three independent, additive changes over the existing hexagonal layout (`domain`/`app`/`infra`): (1) `infra/jwt` and `infra/config` grow from one signing key to a `kid -> key` map, wired through the existing `infra/composition` root; (2) a plain `net/http` handler mounted directly on the existing chi mux, bypassing Huma since it needs no schema or rate limiting; (3) `deployments/docker-compose.yml` hardening plus a new root-level `README.md`.

**Tech Stack:** Go 1.26, `golang-jwt/jwt/v5`, `go-chi/chi/v5`, Docker Compose. No new dependencies.

## Global Constraints

- Design source of truth: `docs/superpowers/specs/2026-07-23-phase-1-mvp-closeout-design.md`.
- Signing keys are PKCS1-encoded RSA PEM (`openssl genrsa -traditional`) — unchanged from phase 1.
- Renaming `JWT_PRIVATE_KEY_PATH`/`JWT_KEY_ID` to `JWT_KEYS_DIR`/`JWT_ACTIVE_KEY_ID` is a breaking config change, acceptable pre-production with a solo operator; every reference (`config.go`, `composition.go`, `docker-compose.yml`, tests) must move together in this plan.
- `/healthz` is liveness-only (no DB ping), not a Huma operation, not rate-limited, and does not appear in the OpenAPI surface.
- No automated key rotation or scheduler — rotation is a documented manual runbook only.
- README scope is run & deploy only: no API contract duplication (already live at `/docs`), no consumer integration guide.
- No change to register/login/refresh/logout domain logic, HTTP contract, or error format.

---

### Task 1: `jwt.LoadRSAPrivateKeys` — load a directory of keys

**Files:**
- Modify: `internal/infra/jwt/keyload.go` (replaces the single-file `LoadRSAPrivateKey`)
- Test: `internal/infra/jwt/keyload_test.go` (replaces the existing tests for the old function)

**Interfaces:**
- Produces: `func LoadRSAPrivateKeys(dir string) (map[string]*rsa.PrivateKey, error)` — reads every `*.pem` file in `dir`; the map key (`kid`) is the filename without its `.pem` extension (e.g. `1.pem` -> `"1"`). Returns an error if `dir` doesn't exist, if no `*.pem` files are found, or if any file isn't valid PKCS1 PEM.

- [ ] **Step 1: Write the failing tests**

Replace the full contents of `internal/infra/jwt/keyload_test.go` with:

```go
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeKeyFile(t *testing.T, dir, name string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

func encodeKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestLoadRSAPrivateKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	dir := t.TempDir()
	writeKeyFile(t, dir, "1.pem", encodeKey(key1))
	writeKeyFile(t, dir, "2.pem", encodeKey(key2))
	writeKeyFile(t, dir, "ignored.txt", []byte("not a key"))

	keys, err := LoadRSAPrivateKeys(dir)
	if err != nil {
		t.Fatalf("LoadRSAPrivateKeys() error = %v, want nil", err)
	}
	if len(keys) != 2 {
		t.Fatalf("LoadRSAPrivateKeys() returned %d keys, want 2", len(keys))
	}
	if got, ok := keys["1"]; !ok || !got.Equal(key1) {
		t.Error(`LoadRSAPrivateKeys()["1"] does not match key1`)
	}
	if got, ok := keys["2"]; !ok || !got.Equal(key2) {
		t.Error(`LoadRSAPrivateKeys()["2"] does not match key2`)
	}
}

func TestLoadRSAPrivateKeys_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	writeKeyFile(t, dir, "bad.pem", []byte("not a pem file"))

	if _, err := LoadRSAPrivateKeys(dir); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error for invalid PEM")
	}
}

func TestLoadRSAPrivateKeys_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	if _, err := LoadRSAPrivateKeys(missing); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error for a missing directory")
	}
}

func TestLoadRSAPrivateKeys_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadRSAPrivateKeys(dir); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error when no *.pem files are present")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/infra/jwt/... -run TestLoadRSAPrivateKeys -v`
Expected: FAIL — `undefined: LoadRSAPrivateKeys` (the old file still only defines `LoadRSAPrivateKey`).

- [ ] **Step 3: Replace `internal/infra/jwt/keyload.go`**

```go
package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadRSAPrivateKeys reads every "*.pem" file in dir into a kid -> key map,
// where kid is the filename without its extension (e.g. "1.pem" -> "1").
// Loading more than one key lets RSAIssuer publish a retired key in JWKS
// long enough for tokens signed under it to finish expiring after rotation.
func LoadRSAPrivateKeys(dir string) (map[string]*rsa.PrivateKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PrivateKey)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		kid := strings.TrimSuffix(entry.Name(), ".pem")
		key, err := loadRSAPrivateKey(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("load key %q: %w", entry.Name(), err)
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no *.pem key files found in %q", dir)
	}
	return keys, nil
}

// loadRSAPrivateKey reads a single PKCS1 PEM-encoded RSA private key from path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM in JWT private key file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/infra/jwt/... -run TestLoadRSAPrivateKeys -v`
Expected: PASS (all 4 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/infra/jwt/keyload.go internal/infra/jwt/keyload_test.go
git commit -m "feat(jwt): load a directory of signing keys instead of a single file"
```

---

### Task 2: `RSAIssuer` — sign with the active key, publish all keys

**Files:**
- Modify: `internal/infra/jwt/issuer.go`
- Test: `internal/infra/jwt/issuer_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 directly (builds its own `map[string]*rsa.PrivateKey` in-line for tests); at runtime, `composition.go` (Task 4) will pass it the map `LoadRSAPrivateKeys` returns.
- Produces: `func NewRSAIssuer(keys map[string]*rsa.PrivateKey, activeKeyID string, ttl time.Duration, clock app.Clock) (*RSAIssuer, error)` — returns an error if `activeKeyID` has no entry in `keys`. `(*RSAIssuer).Issue` and `(*RSAIssuer).JWKS` keep their existing signatures; `JWKS()` now returns one `query.JWKSKey` per entry in `keys`, not just the active one.

- [ ] **Step 1: Write the failing tests**

Replace the full contents of `internal/infra/jwt/issuer_test.go` with:

```go
package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestRSAIssuer_IssueAndVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "1", 15*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	accountID, err := domain.NewAccountID("acc-1")
	if err != nil {
		t.Fatalf("NewAccountID: %v", err)
	}
	token, expiresAt, err := issuer.Issue(context.Background(), accountID)
	if err != nil {
		t.Fatalf("Issue() error = %v, want nil", err)
	}
	if !expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("expiresAt = %v, want %v", expiresAt, now.Add(15*time.Minute))
	}

	parsed, err := jwtlib.Parse(token, func(tok *jwtlib.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}), jwtlib.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsed.Valid {
		t.Fatalf("Parse() error = %v, valid = %v", err, parsed.Valid)
	}
	claims := parsed.Claims.(jwtlib.MapClaims)
	if claims["sub"] != "acc-1" {
		t.Errorf("sub claim = %v, want acc-1", claims["sub"])
	}
}

func TestRSAIssuer_JWKS_PublishesActiveKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "1", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	doc := issuer.JWKS()
	if len(doc.Keys) != 1 {
		t.Fatalf("JWKS().Keys = %d keys, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Kid != "1" || k.N == "" || k.E == "" {
		t.Errorf("JWKS key = %+v, want RSA/RS256/1 with non-empty n, e", k)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.Cmp(priv.N) != 0 {
		t.Error("JWKS n does not match the issuer's actual public key modulus")
	}
	if e.Int64() != int64(priv.E) {
		t.Errorf("JWKS e = %v, want %v", e.Int64(), priv.E)
	}
}

func TestRSAIssuer_JWKS_PublishesRetiredKeyAlongsideActive(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": oldKey, "2": newKey}, "2", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	doc := issuer.JWKS()
	if len(doc.Keys) != 2 {
		t.Fatalf("JWKS().Keys = %d keys, want 2", len(doc.Keys))
	}

	kids := map[string]bool{}
	for _, k := range doc.Keys {
		kids[k.Kid] = true
	}
	if !kids["1"] || !kids["2"] {
		t.Errorf("JWKS().Keys kids = %v, want both %q and %q present", kids, "1", "2")
	}
}

func TestRSAIssuer_Issue_AlwaysSignsWithActiveKey(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	activeKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": oldKey, "2": activeKey}, "2", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	accountID, _ := domain.NewAccountID("acc-1")
	token, _, err := issuer.Issue(context.Background(), accountID)
	if err != nil {
		t.Fatalf("Issue() error = %v, want nil", err)
	}

	parsed, err := jwtlib.Parse(token, func(tok *jwtlib.Token) (interface{}, error) {
		if tok.Header["kid"] != "2" {
			t.Errorf("token kid = %v, want %q", tok.Header["kid"], "2")
		}
		return &activeKey.PublicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("Parse() error = %v, valid = %v", err, parsed.Valid)
	}
}

func TestNewRSAIssuer_ActiveKeyIDNotFound(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	if _, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "does-not-exist", 15*time.Minute, fixedClock{now: time.Now()}); err == nil {
		t.Error("NewRSAIssuer() error = nil, want error for an active key id absent from keys")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/infra/jwt/... -run TestRSAIssuer -v`
Expected: FAIL to compile — `NewRSAIssuer` still takes `(*rsa.PrivateKey, string, time.Duration, app.Clock)` and returns one value, not `(*RSAIssuer, error)`.

- [ ] **Step 3: Replace `internal/infra/jwt/issuer.go`**

```go
package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type RSAIssuer struct {
	keys        map[string]*rsa.PrivateKey
	activeKeyID string
	ttl         time.Duration
	clock       app.Clock
}

// NewRSAIssuer builds an issuer that signs new tokens with keys[activeKeyID]
// and publishes every key in keys via JWKS, so tokens signed under a
// since-retired key still verify until that key is removed from keys.
func NewRSAIssuer(keys map[string]*rsa.PrivateKey, activeKeyID string, ttl time.Duration, clock app.Clock) (*RSAIssuer, error) {
	if _, ok := keys[activeKeyID]; !ok {
		return nil, fmt.Errorf("active key id %q not found among loaded keys", activeKeyID)
	}
	return &RSAIssuer{keys: keys, activeKeyID: activeKeyID, ttl: ttl, clock: clock}, nil
}

func (i *RSAIssuer) Issue(ctx context.Context, accountID domain.AccountID) (string, time.Time, error) {
	now := i.clock.Now()
	expiresAt := now.Add(i.ttl)

	claims := jwtlib.MapClaims{
		"sub": accountID.String(),
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = i.activeKeyID

	signed, err := token.SignedString(i.keys[i.activeKeyID])
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (i *RSAIssuer) JWKS() query.JWKSDocument {
	doc := query.JWKSDocument{Keys: make([]query.JWKSKey, 0, len(i.keys))}
	for kid, key := range i.keys {
		pub := key.PublicKey
		doc.Keys = append(doc.Keys, query.JWKSKey{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return doc
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/infra/jwt/... -v`
Expected: PASS (all tests in the package, including Task 1's).

- [ ] **Step 5: Commit**

```bash
git add internal/infra/jwt/issuer.go internal/infra/jwt/issuer_test.go
git commit -m "feat(jwt): RSAIssuer signs with the active key, publishes all keys via JWKS"
```

---

### Task 3: `config` — replace single-key settings with a keys directory

**Files:**
- Modify: `internal/infra/config/config.go`
- Test: `internal/infra/config/config_test.go`

**Interfaces:**
- Produces: `Config.JWTKeysDir string` (required, from `JWT_KEYS_DIR`) and `Config.JWTActiveKeyID string` (defaults to `"1"`, from `JWT_ACTIVE_KEY_ID`), replacing `Config.JWTPrivateKeyPath` and `Config.JWTKeyID`. Every other `Config` field is unchanged.

- [ ] **Step 1: Write the failing tests**

Replace the full contents of `internal/infra/config/config_test.go` with:

```go
package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 15m", cfg.AccessTokenTTL)
	}
	if cfg.JWTActiveKeyID != "1" {
		t.Errorf("JWTActiveKeyID = %q, want %q", cfg.JWTActiveKeyID, "1")
	}
	if cfg.RateLimitRPS != 5 || cfg.RateLimitBurst != 10 {
		t.Errorf("rate limit = %v/%v, want 5/10", cfg.RateLimitRPS, cfg.RateLimitBurst)
	}
}

func TestLoad_JWTActiveKeyID_Override(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")
	t.Setenv("JWT_ACTIVE_KEY_ID", "2")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.JWTActiveKeyID != "2" {
		t.Errorf("JWTActiveKeyID = %q, want %q", cfg.JWTActiveKeyID, "2")
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_KEYS_DIR", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for missing DATABASE_URL/JWT_KEYS_DIR")
	}
}

func TestLoad_Defaults_IncludesRefreshTokenTTL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")

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
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")
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

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/infra/config/... -v`
Expected: FAIL to compile — `cfg.JWTActiveKeyID` is undefined (the struct still has `JWTKeyID`/`JWTPrivateKeyPath`).

- [ ] **Step 3: Replace `internal/infra/config/config.go`**

```go
// Package config loads the identity service's configuration from the
// environment, failing fast when a required value is missing or invalid.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port            string
	DatabaseURL     string
	JWTKeysDir      string
	JWTActiveKeyID  string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	RateLimitRPS    float64
	RateLimitBurst  int
}

func Load() (Config, error) {
	cfg := Config{
		Port:            getEnv("PORT", "8080"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		JWTKeysDir:      os.Getenv("JWT_KEYS_DIR"),
		JWTActiveKeyID:  getEnv("JWT_ACTIVE_KEY_ID", "1"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		RateLimitRPS:    5,
		RateLimitBurst:  10,
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
	if cfg.JWTKeysDir == "" {
		return Config{}, errors.New("JWT_KEYS_DIR is required")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/infra/config/... -v`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/infra/config/config.go internal/infra/config/config_test.go
git commit -m "feat(config): replace single JWT key path/id with a keys directory + active key id"
```

---

### Task 4: Wire the keys directory through the composition root

**Files:**
- Modify: `internal/infra/composition/composition.go`

**Interfaces:**
- Consumes: `jwt.LoadRSAPrivateKeys` (Task 1), `jwt.NewRSAIssuer` (Task 2, now `(*RSAIssuer, error)`), `config.Config.JWTKeysDir`/`JWTActiveKeyID` (Task 3).
- Produces: no change to `composition.Build`'s own signature (`func Build(ctx context.Context, cfg config.Config) (*Application, error)`) or to `Application{Router, Pool}`.

There is no `composition_test.go` in the repo — this task's correctness is proven by the full test suite (unchanged) plus `go build ./...`, not a new test file.

- [ ] **Step 1: Update the key-loading and issuer-construction lines in `internal/infra/composition/composition.go`**

Replace:

```go
	privateKey, err := jwt.LoadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		pool.Close()
		return nil, err
	}

	repo := postgres.NewAccountRepository(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer := jwt.NewRSAIssuer(privateKey, cfg.JWTKeyID, cfg.AccessTokenTTL, systemClock{})
```

with:

```go
	keys, err := jwt.LoadRSAPrivateKeys(cfg.JWTKeysDir)
	if err != nil {
		pool.Close()
		return nil, err
	}

	repo := postgres.NewAccountRepository(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer, err := jwt.NewRSAIssuer(keys, cfg.JWTActiveKeyID, cfg.AccessTokenTTL, systemClock{})
	if err != nil {
		pool.Close()
		return nil, err
	}
```

Everything else in the file (imports, the rest of `Build`) is unchanged — `jwt` is already imported.

- [ ] **Step 2: Confirm the module builds and the full suite still passes**

Run: `go build ./...`
Expected: no output, exit 0.

Run: `go test ./...`
Expected: PASS across every package.

- [ ] **Step 3: Commit**

```bash
git add internal/infra/composition/composition.go
git commit -m "feat(composition): wire the multi-key JWT loader and issuer"
```

---

### Task 5: `GET /healthz` liveness endpoint

**Files:**
- Create: `internal/infra/httpapi/healthz_handler.go`
- Test: `internal/infra/httpapi/healthz_handler_test.go`
- Modify: `internal/infra/httpapi/router.go`
- Modify: `internal/infra/httpapi/router_test.go`

**Interfaces:**
- Produces: `func HealthzHandler(w http.ResponseWriter, r *http.Request)` — a plain `net/http.HandlerFunc`-compatible function, mounted directly on the chi mux in `NewRouter`, not registered as a Huma operation.

- [ ] **Step 1: Write the failing handler test**

Create `internal/infra/httpapi/healthz_handler_test.go`:

```go
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	HealthzHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestHealthzHandler -v`
Expected: FAIL to compile — `undefined: HealthzHandler`.

- [ ] **Step 3: Create `internal/infra/httpapi/healthz_handler.go`**

```go
package httpapi

import "net/http"

// HealthzHandler reports liveness for container/orchestrator health checks:
// a 200 means the process can serve a request at all, not that its database
// connection is healthy. It is intentionally not a Huma operation — no
// schema, no rate limiting, and it stays out of the public OpenAPI surface.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/infra/httpapi/... -run TestHealthzHandler -v`
Expected: PASS.

- [ ] **Step 5: Write the failing router-level test**

Append to `internal/infra/httpapi/router_test.go`:

```go
func TestNewRouter_ServesHealthz(t *testing.T) {
	router := newTestRouter(NewIPRateLimiter(1000, 1000))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", rec.Code)
	}
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `go test ./internal/infra/httpapi/... -run TestNewRouter_ServesHealthz -v`
Expected: FAIL — 404, since `/healthz` isn't wired into `NewRouter` yet.

- [ ] **Step 7: Wire `/healthz` into `NewRouter` in `internal/infra/httpapi/router.go`**

Immediately after `mux := chi.NewMux()`, add:

```go
	mux.Get("/healthz", HealthzHandler)
```

So the top of `NewRouter` reads:

```go
func NewRouter(register RegisterHandler, login LoginHandler, refresh RefreshHandler, logout LogoutHandler, jwks JWKSHandler, limiter *IPRateLimiter) http.Handler {
	mux := chi.NewMux()
	mux.Get("/healthz", HealthzHandler)

	config := huma.DefaultConfig("iam-base", "1.0.0")
```

- [ ] **Step 8: Run both tests to verify they pass**

Run: `go test ./internal/infra/httpapi/... -v`
Expected: PASS across the whole package.

- [ ] **Step 9: Commit**

```bash
git add internal/infra/httpapi/healthz_handler.go internal/infra/httpapi/healthz_handler_test.go internal/infra/httpapi/router.go internal/infra/httpapi/router_test.go
git commit -m "feat(httpapi): add GET /healthz liveness endpoint"
```

---

### Task 6: docker-compose hardening — new env vars, healthcheck, restart policy

**Files:**
- Modify: `deployments/docker-compose.yml`

**Interfaces:**
- Consumes: `JWT_KEYS_DIR`/`JWT_ACTIVE_KEY_ID` (Task 3), `GET /healthz` (Task 5).

This is deploy configuration, not Go code — there is no automated test. Correctness is verified with a manual smoke test in Step 3.

- [ ] **Step 1: Replace the full contents of `deployments/docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: iam
      POSTGRES_PASSWORD: iam
      POSTGRES_DB: iam
    volumes:
      - iam_pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iam"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  identity:
    build:
      context: ..
      dockerfile: deployments/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      PORT: "8080"
      DATABASE_URL: "postgres://iam:iam@postgres:5432/iam?sslmode=disable"
      JWT_KEYS_DIR: "/etc/iam"
      JWT_ACTIVE_KEY_ID: "1"
      ACCESS_TOKEN_TTL: "15m"
      REFRESH_TOKEN_TTL: "720h"
      RATE_LIMIT_RPS: "5"
      RATE_LIMIT_BURST: "10"
    volumes:
      - ./keys:/etc/iam:ro
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8080/healthz"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  iam_pg_data:
```

- [ ] **Step 2: Move the local dev key into the new layout**

The existing local `deployments/keys/private.pem` (gitignored, not tracked) must be renamed to match `JWT_ACTIVE_KEY_ID=1`:

```bash
mv deployments/keys/private.pem deployments/keys/1.pem
```

If this file doesn't exist in your checkout, generate one instead (see Task 7's README key-generation command).

- [ ] **Step 3: Manual smoke test**

Run:

```bash
cd deployments
docker compose up --build -d
docker compose ps
```

Expected: both `postgres` and `identity` show `healthy` in the `STATUS` column within ~30s (`identity`'s `/healthz` check needs `wget`, which ships by default in the `alpine:3.20` base image via BusyBox — if the healthcheck instead shows `unhealthy`, run `docker compose exec identity wget --spider -q http://localhost:8080/healthz; echo $?` to confirm `wget` is present before debugging further).

Then confirm the full auth flow still works:

```bash
curl -i -X POST http://localhost:8080/v1/auth/register -H 'content-type: application/json' -d '{"email":"smoke@test.com","password":"secret123"}'
curl -i -X POST http://localhost:8080/v1/auth/login -H 'content-type: application/json' -d '{"email":"smoke@test.com","password":"secret123"}'
curl -s http://localhost:8080/.well-known/jwks.json
```

Expected: `201`, then `200` with an access + refresh token, then a JWKS document with exactly one key (`kid: "1"`).

```bash
cd deployments
docker compose down
```

- [ ] **Step 4: Commit**

```bash
git add deployments/docker-compose.yml
git commit -m "feat(deploy): add /healthz healthcheck, restart policy, and new JWT key env vars"
```

---

### Task 7: README.md

**Files:**
- Create: `README.md` (repo root)

**Interfaces:**
- Consumes: env var names from Task 3, key file layout from Task 1, rotation runbook from Task 2's design, `/healthz` from Task 5.

No test — documentation only.

- [ ] **Step 1: Create `README.md`**

```markdown
# iam-base

Standalone Authentication & Identity Management service: email + password
registration/login, JWT access + refresh tokens, and a JWKS endpoint so
consuming services can verify tokens themselves. See
`docs/design/iam-base-service.md` for the full design rationale.

## Prerequisites

- Docker and Docker Compose

## Generating signing keys

The service signs access tokens with an RSA private key, and can hold more
than one at a time (see "Rotating the signing key" below). Each key lives
in its own PEM file inside a keys directory, named `<key-id>.pem`:

\`\`\`bash
mkdir -p deployments/keys
openssl genrsa -traditional -out deployments/keys/1.pem 2048
\`\`\`

`-traditional` is required: the service expects PKCS1-encoded keys, and
recent OpenSSL versions default to PKCS8.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | no | `8080` | HTTP port the server listens on |
| `DATABASE_URL` | yes | — | Postgres connection string |
| `JWT_KEYS_DIR` | yes | — | Directory of `<key-id>.pem` RSA private keys |
| `JWT_ACTIVE_KEY_ID` | no | `1` | Which key in `JWT_KEYS_DIR` signs new tokens |
| `ACCESS_TOKEN_TTL` | no | `15m` | Access token lifetime (Go duration syntax) |
| `REFRESH_TOKEN_TTL` | no | `720h` | Refresh token lifetime (Go duration syntax) |
| `RATE_LIMIT_RPS` | no | `5` | Requests per second allowed per client IP |
| `RATE_LIMIT_BURST` | no | `10` | Burst size allowed per client IP |

## Running

\`\`\`bash
cd deployments
docker compose up --build
\`\`\`

This builds the image, starts Postgres, runs pending migrations
automatically on boot, and starts the identity service on `:8080`.

## Rotating the signing key

1. Generate a new key into the same directory, e.g.
   `openssl genrsa -traditional -out deployments/keys/2.pem 2048`.
2. Set `JWT_ACTIVE_KEY_ID=2` and redeploy. `/.well-known/jwks.json` now
   publishes both keys, so tokens already issued under key `1` still verify.
3. Once `REFRESH_TOKEN_TTL` has fully elapsed since the last token was
   issued under key `1` (so nothing signed under it can still be
   presented), delete `deployments/keys/1.pem` and redeploy again to
   retire it from the published JWKS.

## API reference

The service exposes live, code-first OpenAPI docs once running:

- Swagger UI: `http://localhost:8080/docs`
- OpenAPI spec: `http://localhost:8080/openapi.json`
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README covering key generation, config, and running the service"
```
