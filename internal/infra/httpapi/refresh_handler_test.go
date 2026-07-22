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
