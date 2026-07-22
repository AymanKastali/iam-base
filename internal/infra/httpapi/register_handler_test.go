package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestRegisterHandler_ServeHTTP_Success(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterHandler_ServeHTTP_DuplicateEmail(t *testing.T) {
	repo := &stubAccountRepo{saveErr: domain.ErrEmailAlreadyRegistered}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestRegisterHandler_ServeHTTP_InvalidEmail(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	body, _ := json.Marshal(map[string]string{"email": "not-an-email", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
}

func TestRegisterHandler_ServeHTTP_PasswordTooShort(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": "short"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterHandler_ServeHTTP_BodyTooLarge(t *testing.T) {
	repo := &stubAccountRepo{}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	oversizedPassword := strings.Repeat("a", maxRequestBodyBytes)
	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": oversizedPassword})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterHandler_ServeHTTP_UnexpectedError(t *testing.T) {
	repo := &stubAccountRepo{saveErr: errors.New("boom")}
	h := RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: stubHasher{}, Policy: domain.MinLengthPasswordPolicy{}, IDGen: stubIDGenerator{}}}

	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": sampleCredential})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
