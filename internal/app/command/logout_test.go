// internal/app/command/logout_test.go
package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func TestRevokeSessionHandler_Handle_Success(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	h := RevokeSessionHandler{Repo: repo}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}

	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("Handle() must revoke the family")
	}
}

func TestRevokeSessionHandler_Handle_AlreadyRevoked_IsIdempotent(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	h := RevokeSessionHandler{Repo: repo}
	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Fatalf("fixture Handle: %v", err)
	}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err != nil {
		t.Errorf("Handle() on an already-revoked family error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_UnknownFamily_IsIdempotent(t *testing.T) {
	h := RevokeSessionHandler{Repo: newFakeRefreshTokenRepo()}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: "unknown-family.some-secret"}); err != nil {
		t.Errorf("Handle() for an unknown family error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_MalformedToken_IsIdempotent(t *testing.T) {
	h := RevokeSessionHandler{Repo: newFakeRefreshTokenRepo()}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: "not-a-valid-token"}); err != nil {
		t.Errorf("Handle() for a malformed token error = %v, want nil (logout is idempotent)", err)
	}
}

func TestRevokeSessionHandler_Handle_RepositoryFailure_Propagates(t *testing.T) {
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	repo.saveErr = domain.ErrRefreshTokenFamilyNotFound // any non-nil save error stands in for a DB failure
	h := RevokeSessionHandler{Repo: repo}

	if err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"}); err == nil {
		t.Error("Handle() must propagate a genuine repository save failure, not swallow it")
	}
}

func TestRevokeSessionHandler_Handle_FindByIDFailure_Propagates(t *testing.T) {
	repoErr := errors.New("connection refused")
	repo := newFakeRefreshTokenRepo()
	familyID := issueTestFamily(t, repo, "hash:secret", time.Now().Add(time.Hour))
	repo.findErr = repoErr
	h := RevokeSessionHandler{Repo: repo}

	err := h.Handle(context.Background(), RevokeSessionCommand{RefreshToken: familyID.String() + ".secret"})
	if !errors.Is(err, repoErr) {
		t.Fatalf("Handle() error = %v, want repository error to propagate (not be swallowed as nil like the not-found case)", err)
	}
}
