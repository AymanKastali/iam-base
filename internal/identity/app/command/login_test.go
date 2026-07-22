// internal/identity/app/command/login_test.go
package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

type fakeIssuer struct {
	token     string
	expiresAt time.Time
	err       error
}

func (f fakeIssuer) Issue(ctx context.Context, id domain.AccountID) (string, time.Time, error) {
	if f.err != nil {
		return "", time.Time{}, f.err
	}
	return f.token, f.expiresAt, nil
}

func registerFixture(t *testing.T, repo *fakeAccountRepo, email, password string) {
	t.Helper()
	h := RegisterAccountHandler{Repo: repo, Hasher: fakeHasher{}}
	if _, err := h.Handle(context.Background(), RegisterAccountCommand{Email: email, Password: password}); err != nil {
		t.Fatalf("fixture register: %v", err)
	}
}

func TestLoginHandler_Handle_Success(t *testing.T) {
	repo := newFakeAccountRepo()
	registerFixture(t, repo, "a@b.com", sampleCredential)
	expiresAt := time.Now().Add(15 * time.Minute)
	h := LoginHandler{Repo: repo, Hasher: fakeHasher{}, Issuer: fakeIssuer{token: "signed-jwt", expiresAt: expiresAt}}

	result, err := h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: sampleCredential})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if result.AccessToken != "signed-jwt" || !result.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Handle() = %+v, want token=signed-jwt expiresAt=%v", result, expiresAt)
	}
}

func TestLoginHandler_Handle_DisabledAccount(t *testing.T) {
	repo := newFakeAccountRepo()
	registerFixture(t, repo, "a@b.com", sampleCredential)
	email, _ := domain.NewEmail("a@b.com")
	account, err := repo.FindByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("fixture FindByEmail: %v", err)
	}
	if err := account.Disable(); err != nil {
		t.Fatalf("fixture Disable: %v", err)
	}
	h := LoginHandler{Repo: repo, Hasher: fakeHasher{}, Issuer: fakeIssuer{}}

	_, err = h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: sampleCredential})
	if !errors.Is(err, domain.ErrAccountDisabled) {
		t.Fatalf("Handle() error = %v, want ErrAccountDisabled", err)
	}
}

func TestLoginHandler_Handle_WrongPassword(t *testing.T) {
	repo := newFakeAccountRepo()
	registerFixture(t, repo, "a@b.com", sampleCredential)
	h := LoginHandler{Repo: repo, Hasher: fakeHasher{}, Issuer: fakeIssuer{}}

	_, err := h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: "wrong"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Handle() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginHandler_Handle_UnknownEmail(t *testing.T) {
	repo := newFakeAccountRepo()
	h := LoginHandler{Repo: repo, Hasher: fakeHasher{}, Issuer: fakeIssuer{}}

	_, err := h.Handle(context.Background(), LoginCommand{Email: "missing@b.com", Password: sampleCredential})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Handle() error = %v, want ErrInvalidCredentials (must not leak account existence)", err)
	}
}
