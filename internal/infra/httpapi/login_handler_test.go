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

type stubIssuer struct{}

func (stubIssuer) Issue(ctx context.Context, id domain.AccountID) (string, time.Time, error) {
	return "signed-jwt", time.Now().Add(15 * time.Minute), nil
}

func TestLoginHandler_ServeHTTP_Success(t *testing.T) {
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
	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["access_token"] != "signed-jwt" {
		t.Errorf("access_token = %v, want signed-jwt", resp["access_token"])
	}
	if resp["refresh_token"] == "" || resp["refresh_token"] == nil {
		t.Error("refresh_token missing from login response")
	}
}

func TestLoginHandler_ServeHTTP_InvalidCredentials(t *testing.T) {
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

	body, _ := json.Marshal(map[string]string{"email": "missing@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLoginHandler_ServeHTTP_BodyTooLarge(t *testing.T) {
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

	oversizedPassword := strings.Repeat("a", maxRequestBodyBytes)
	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": oversizedPassword})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestLoginHandler_ServeHTTP_DisabledAccount(t *testing.T) {
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
	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
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
