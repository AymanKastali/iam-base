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
