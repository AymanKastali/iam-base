// internal/app/command/refresh_test.go
package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func issueTestFamily(t *testing.T, repo *fakeRefreshTokenRepo, hash string, expiresAt time.Time) domain.FamilyID {
	t.Helper()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, err := domain.IssueFamily(familyID, accountID, hash, expiresAt)
	if err != nil {
		t.Fatalf("fixture IssueFamily: %v", err)
	}
	if err := repo.Save(context.Background(), family); err != nil {
		t.Fatalf("fixture Save: %v", err)
	}
	return familyID
}

func TestRotateRefreshTokenHandler_Handle_Success(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:old-secret", now.Add(time.Hour))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{token: "signed-jwt", expiresAt: now.Add(15 * time.Minute)},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	result, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".old-secret"})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if result.AccessToken != "signed-jwt" {
		t.Errorf("Handle() AccessToken = %q, want signed-jwt", result.AccessToken)
	}
	wantRefreshToken := familyID.String() + ".new-secret"
	if result.RefreshToken != wantRefreshToken {
		t.Errorf("Handle() RefreshToken = %q, want %q", result.RefreshToken, wantRefreshToken)
	}

	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if stored.Generation() != 2 {
		t.Errorf("stored family Generation() = %d, want 2", stored.Generation())
	}
}

func TestRotateRefreshTokenHandler_Handle_MalformedToken(t *testing.T) {
	h := RotateRefreshTokenHandler{Repo: newFakeRefreshTokenRepo(), TokenGen: fakeTokenGenerator{}, Issuer: fakeIssuer{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: time.Hour}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: "not-a-valid-token"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRotateRefreshTokenHandler_Handle_RepositoryFailure_Propagates(t *testing.T) {
	repoErr := errors.New("connection refused")
	repo := &fakeRefreshTokenRepo{findErr: repoErr}
	h := RotateRefreshTokenHandler{Repo: repo, TokenGen: fakeTokenGenerator{}, Issuer: fakeIssuer{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: time.Hour}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: "family-1.some-secret"})
	if !errors.Is(err, repoErr) {
		t.Fatalf("Handle() error = %v, want repository error to propagate (not be masked as ErrInvalidRefreshToken)", err)
	}
}

func TestRotateRefreshTokenHandler_Handle_UnknownFamily(t *testing.T) {
	h := RotateRefreshTokenHandler{Repo: newFakeRefreshTokenRepo(), TokenGen: fakeTokenGenerator{}, Issuer: fakeIssuer{}, Clock: fakeClock{now: time.Now()}, RefreshTokenTTL: time.Hour}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: "unknown-family.some-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRotateRefreshTokenHandler_Handle_ReusedToken_RevokesFamily(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:current-secret", now.Add(time.Hour))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{token: "signed-jwt", expiresAt: now.Add(15 * time.Minute)},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".an-old-superseded-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}

	stored, findErr := repo.FindByID(context.Background(), familyID)
	if findErr != nil {
		t.Fatalf("FindByID() error = %v, want nil", findErr)
	}
	if !stored.Revoked() {
		t.Error("a reused token must revoke the whole family, even though the handler returns a generic error")
	}
}

func TestRotateRefreshTokenHandler_Handle_ExpiredToken(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	now := time.Now()
	familyID := issueTestFamily(t, repo, "hash:old-secret", now.Add(-time.Minute))
	h := RotateRefreshTokenHandler{
		Repo:            repo,
		TokenGen:        fakeTokenGenerator{nextSecret: "new-secret", nextHash: "hash:new-secret"},
		Issuer:          fakeIssuer{},
		Clock:           fakeClock{now: now},
		RefreshTokenTTL: 24 * time.Hour,
	}

	_, err := h.Handle(context.Background(), RotateRefreshTokenCommand{RefreshToken: familyID.String() + ".old-secret"})
	if !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("Handle() error = %v, want ErrInvalidRefreshToken", err)
	}
}
