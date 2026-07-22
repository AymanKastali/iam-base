// internal/app/command/login_test.go
package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
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

func TestLoginHandler_Handle_RepositoryFailure_Propagates(t *testing.T) {
	repoErr := errors.New("connection refused")
	repo := &fakeAccountRepo{lookupErr: repoErr}
	h := LoginHandler{Repo: repo, Hasher: fakeHasher{}, Issuer: fakeIssuer{}}

	_, err := h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: sampleCredential})
	if !errors.Is(err, repoErr) {
		t.Fatalf("Handle() error = %v, want repository error to propagate (not be masked as ErrInvalidCredentials)", err)
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

// spyHasher counts Hash() calls so tests can confirm the unknown-email and
// disabled-account paths pay the same hashing cost as a real verification —
// otherwise their faster response time would leak account existence/status.
type spyHasher struct {
	fakeHasher
	hashCalls int
}

func (s *spyHasher) Hash(password string) (domain.Credential, error) {
	s.hashCalls++
	return s.fakeHasher.Hash(password)
}

func TestLoginHandler_Handle_UnknownEmail_PadsTimingCost(t *testing.T) {
	repo := newFakeAccountRepo()
	spy := &spyHasher{}
	h := LoginHandler{Repo: repo, Hasher: spy, Issuer: fakeIssuer{}}

	if _, err := h.Handle(context.Background(), LoginCommand{Email: "missing@b.com", Password: sampleCredential}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Handle() error = %v, want ErrInvalidCredentials", err)
	}
	if spy.hashCalls != 1 {
		t.Errorf("Hasher.Hash() call count = %d, want 1 (timing-cost padding)", spy.hashCalls)
	}
}

func TestLoginHandler_Handle_DisabledAccount_PadsTimingCost(t *testing.T) {
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

	spy := &spyHasher{}
	h := LoginHandler{Repo: repo, Hasher: spy, Issuer: fakeIssuer{}}

	if _, err := h.Handle(context.Background(), LoginCommand{Email: "a@b.com", Password: sampleCredential}); !errors.Is(err, domain.ErrAccountDisabled) {
		t.Fatalf("Handle() error = %v, want ErrAccountDisabled", err)
	}
	if spy.hashCalls != 1 {
		t.Errorf("Hasher.Hash() call count = %d, want 1 (timing-cost padding)", spy.hashCalls)
	}
}
