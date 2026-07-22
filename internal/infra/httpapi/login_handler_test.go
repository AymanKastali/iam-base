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

func newLoginHandler(repo *stubAccountRepo) LoginHandler {
	return LoginHandler{Handler: command.LoginHandler{
		Repo:            repo,
		Hasher:          stubHasher{},
		Issuer:          stubIssuer{},
		RefreshRepo:     newStubRefreshTokenRepo(),
		TokenGen:        stubTokenGenerator{nextSecret: "s", nextHash: "h"},
		IDGen:           stubIDGenerator{},
		Clock:           stubClock{now: time.Now()},
		RefreshTokenTTL: 24 * time.Hour,
	}}
}

func TestLoginHandler_Handle_Success(t *testing.T) {
	repo := &stubAccountRepo{}
	registerHandler := command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}
	if _, err := registerHandler.Handle(context.Background(), command.RegisterAccountCommand{Email: "a@b.com", Password: sampleCredential}); err != nil {
		t.Fatalf("fixture register: %v", err)
	}

	h := newLoginHandler(repo)

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
	h := newLoginHandler(repo)

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

	h := newLoginHandler(repo)

	_, err := h.Handle(context.Background(), newLoginInput("a@b.com", sampleCredential))

	assertStatus(t, err, http.StatusUnauthorized)
}
