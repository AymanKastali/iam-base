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
