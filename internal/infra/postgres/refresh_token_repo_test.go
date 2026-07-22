package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/AymanKastali/iam-base/internal/domain"
)

func newTestRefreshTokenRepo(t *testing.T, accountRepo *AccountRepository) *RefreshTokenRepository {
	t.Helper()
	return &RefreshTokenRepository{pool: accountRepo.pool}
}

func newTestFamily(t *testing.T, accountID domain.AccountID) *domain.RefreshTokenFamily {
	t.Helper()
	id, err := domain.NewFamilyID(uuid.NewString())
	if err != nil {
		t.Fatalf("NewFamilyID: %v", err)
	}
	family, err := domain.IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(time.Hour).Truncate(time.Microsecond))
	if err != nil {
		t.Fatalf("IssueFamily: %v", err)
	}
	return family
}

func TestRefreshTokenRepository_SaveAndFindByID(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	ctx := context.Background()
	account := newTestAccount(t, "refresh-owner@b.com")
	if err := accountRepo.Save(ctx, account); err != nil {
		t.Fatalf("fixture Save account: %v", err)
	}
	family := newTestFamily(t, account.ID())

	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	found, err := repo.FindByID(ctx, family.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if found.AccountID() != family.AccountID() {
		t.Errorf("FindByID().AccountID() = %v, want %v", found.AccountID(), family.AccountID())
	}
	if found.CurrentTokenHash() != family.CurrentTokenHash() {
		t.Errorf("FindByID().CurrentTokenHash() = %q, want %q", found.CurrentTokenHash(), family.CurrentTokenHash())
	}
	if found.Generation() != family.Generation() {
		t.Errorf("FindByID().Generation() = %d, want %d", found.Generation(), family.Generation())
	}
	if found.Revoked() {
		t.Error("FindByID() must not report a freshly-issued family as revoked")
	}
	if events := found.RecordedEvents(); len(events) != 0 {
		t.Errorf("FindByID() recorded %d events, want 0 — loading is not a new fact", len(events))
	}
}

func TestRefreshTokenRepository_Save_UpsertsRotation(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	ctx := context.Background()
	account := newTestAccount(t, "rotator@b.com")
	if err := accountRepo.Save(ctx, account); err != nil {
		t.Fatalf("fixture Save account: %v", err)
	}
	family := newTestFamily(t, account.ID())
	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("initial Save() error = %v, want nil", err)
	}

	if err := family.Rotate(time.Now(), "hash-gen-1", "hash-gen-2", time.Now().Add(2*time.Hour).Truncate(time.Microsecond)); err != nil {
		t.Fatalf("fixture Rotate: %v", err)
	}
	if err := repo.Save(ctx, family); err != nil {
		t.Fatalf("rotation Save() error = %v, want nil", err)
	}

	found, err := repo.FindByID(ctx, family.ID())
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if found.Generation() != 2 || found.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("FindByID() after rotation = generation=%d hash=%q, want generation=2 hash=hash-gen-2", found.Generation(), found.CurrentTokenHash())
	}
}

func TestRefreshTokenRepository_FindByID_NotFound(t *testing.T) {
	accountRepo := newTestRepo(t)
	repo := newTestRefreshTokenRepo(t, accountRepo)
	missingID, _ := domain.NewFamilyID(uuid.NewString())

	_, err := repo.FindByID(context.Background(), missingID)
	if !errors.Is(err, domain.ErrRefreshTokenFamilyNotFound) {
		t.Fatalf("FindByID() error = %v, want ErrRefreshTokenFamilyNotFound", err)
	}
}
