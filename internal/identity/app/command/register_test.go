// internal/identity/app/command/register_test.go
package command

import (
	"context"
	"errors"
	"testing"

	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

// sampleCredential is a fixture value, not a secret — kept as a named constant
// (rather than inline in struct literals) so it reads clearly as test data.
const sampleCredential = "secret123"

type fakeAccountRepo struct {
	accounts  map[string]*domain.Account
	saveErr   error
	lookupErr error
}

func newFakeAccountRepo() *fakeAccountRepo {
	return &fakeAccountRepo{accounts: map[string]*domain.Account{}}
}

func (r *fakeAccountRepo) Save(ctx context.Context, a *domain.Account) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.accounts[a.Email().String()] = a
	return nil
}

func (r *fakeAccountRepo) FindByEmail(ctx context.Context, e domain.Email) (*domain.Account, error) {
	if r.lookupErr != nil {
		return nil, r.lookupErr
	}
	a, ok := r.accounts[e.String()]
	if !ok {
		return nil, domain.ErrAccountNotFound
	}
	return a, nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(password string) (domain.Credential, error) {
	return domain.NewCredential("hashed:"+password, "argon2id", 1)
}

func (fakeHasher) Verify(c domain.Credential, password string) (bool, error) {
	return c.Hash() == "hashed:"+password, nil
}

func TestRegisterAccountHandler_Handle(t *testing.T) {
	repo := newFakeAccountRepo()
	h := RegisterAccountHandler{Repo: repo, Hasher: fakeHasher{}}

	id, err := h.Handle(context.Background(), RegisterAccountCommand{Email: "a@b.com", Password: sampleCredential})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if id.String() == "" {
		t.Error("Handle() returned empty AccountID")
	}

	stored, err := repo.FindByEmail(context.Background(), mustEmail(t, "a@b.com"))
	if err != nil {
		t.Fatalf("FindByEmail() error = %v, want nil", err)
	}
	if stored.Credential().Hash() != "hashed:"+sampleCredential {
		t.Errorf("stored credential hash = %q, want %q", stored.Credential().Hash(), "hashed:"+sampleCredential)
	}
}

func TestRegisterAccountHandler_Handle_InvalidEmail(t *testing.T) {
	h := RegisterAccountHandler{Repo: newFakeAccountRepo(), Hasher: fakeHasher{}}

	_, err := h.Handle(context.Background(), RegisterAccountCommand{Email: "not-an-email", Password: sampleCredential})
	if !errors.Is(err, domain.ErrInvalidEmail) {
		t.Fatalf("Handle() error = %v, want ErrInvalidEmail", err)
	}
}

func TestRegisterAccountHandler_Handle_PasswordTooShort(t *testing.T) {
	h := RegisterAccountHandler{Repo: newFakeAccountRepo(), Hasher: fakeHasher{}}

	_, err := h.Handle(context.Background(), RegisterAccountCommand{Email: "a@b.com", Password: "short"})
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Handle() error = %v, want ErrPasswordTooShort", err)
	}
}

func TestRegisterAccountHandler_Handle_DuplicateEmail(t *testing.T) {
	repo := newFakeAccountRepo()
	repo.saveErr = domain.ErrEmailAlreadyRegistered
	h := RegisterAccountHandler{Repo: repo, Hasher: fakeHasher{}}

	_, err := h.Handle(context.Background(), RegisterAccountCommand{Email: "a@b.com", Password: sampleCredential})
	if !errors.Is(err, domain.ErrEmailAlreadyRegistered) {
		t.Fatalf("Handle() error = %v, want ErrEmailAlreadyRegistered", err)
	}
}

func mustEmail(t *testing.T, raw string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(raw)
	if err != nil {
		t.Fatalf("NewEmail(%q): %v", raw, err)
	}
	return e
}
