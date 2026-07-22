package domain

import (
	"errors"
	"testing"
	"time"
)

func newTestFamily(t *testing.T) *RefreshTokenFamily {
	t.Helper()
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")
	family, err := IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("IssueFamily() error = %v, want nil", err)
	}
	return family
}

func TestIssueFamily(t *testing.T) {
	family := newTestFamily(t)

	if family.Generation() != 1 {
		t.Errorf("Generation() = %d, want 1", family.Generation())
	}
	if family.CurrentTokenHash() != "hash-gen-1" {
		t.Errorf("CurrentTokenHash() = %q, want %q", family.CurrentTokenHash(), "hash-gen-1")
	}
	if family.Revoked() {
		t.Error("a newly issued family must not be revoked")
	}
}

func TestIssueFamily_RecordsRefreshTokenFamilyIssuedEvent(t *testing.T) {
	family := newTestFamily(t)

	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	issued, ok := events[0].(RefreshTokenFamilyIssued)
	if !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyIssued", events[0])
	}
	if issued.FamilyID != family.ID() {
		t.Errorf("RefreshTokenFamilyIssued.FamilyID = %v, want %v", issued.FamilyID, family.ID())
	}
}

func TestReconstituteRefreshTokenFamily_DoesNotRecordEvent(t *testing.T) {
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")

	family := ReconstituteRefreshTokenFamily(id, accountID, "hash-gen-2", 2, time.Now().Add(time.Hour), false)

	if family.Generation() != 2 || family.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("ReconstituteRefreshTokenFamily() = %+v, want generation=2 hash=hash-gen-2", family)
	}
	if events := family.RecordedEvents(); len(events) != 0 {
		t.Errorf("ReconstituteRefreshTokenFamily() recorded %d events, want 0 — reconstitution is not a new fact", len(events))
	}
}

func TestRefreshTokenFamily_Rotate_Success(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()
	now := time.Now()
	newExpiresAt := now.Add(24 * time.Hour)

	if err := family.Rotate(now, "hash-gen-1", "hash-gen-2", newExpiresAt); err != nil {
		t.Fatalf("Rotate() error = %v, want nil", err)
	}
	if family.Generation() != 2 {
		t.Errorf("Generation() = %d, want 2", family.Generation())
	}
	if family.CurrentTokenHash() != "hash-gen-2" {
		t.Errorf("CurrentTokenHash() = %q, want %q", family.CurrentTokenHash(), "hash-gen-2")
	}
	if !family.ExpiresAt().Equal(newExpiresAt) {
		t.Errorf("ExpiresAt() = %v, want %v", family.ExpiresAt(), newExpiresAt)
	}

	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRotated); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRotated", events[0])
	}
}

func TestRefreshTokenFamily_Rotate_WrongHash_RevokesAndReportsReuse(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()
	now := time.Now()

	err := family.Rotate(now, "wrong-hash", "hash-gen-2", now.Add(24*time.Hour))
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() error = %v, want ErrTokenReuseDetected", err)
	}
	if !family.Revoked() {
		t.Error("Rotate() with a mismatched hash must revoke the whole family")
	}
	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRevoked); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRevoked", events[0])
	}
}

func TestRefreshTokenFamily_Rotate_AlreadyRevoked_ReportsReuse(t *testing.T) {
	family := newTestFamily(t)
	if err := family.Revoke(); err != nil {
		t.Fatalf("fixture Revoke: %v", err)
	}
	now := time.Now()

	err := family.Rotate(now, "hash-gen-1", "hash-gen-2", now.Add(24*time.Hour))
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() on an already-revoked family error = %v, want ErrTokenReuseDetected", err)
	}
}

func TestRefreshTokenFamily_Rotate_AlreadyRevoked_RecordsNoEvent(t *testing.T) {
	family := newTestFamily(t)
	if err := family.Revoke(); err != nil {
		t.Fatalf("fixture Revoke: %v", err)
	}
	family.DrainEvents()
	now := time.Now()

	if err := family.Rotate(now, "hash-gen-1", "hash-gen-2", now.Add(24*time.Hour)); !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() on an already-revoked family error = %v, want ErrTokenReuseDetected", err)
	}
	if events := family.RecordedEvents(); len(events) != 0 {
		t.Errorf("RecordedEvents() = %d events, want 0 — the already-revoked early return must not record a second RefreshTokenFamilyRevoked event", len(events))
	}
}

func TestRefreshTokenFamily_Rotate_RevokedAndExpired_RevokedWins(t *testing.T) {
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")
	family, err := IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("IssueFamily() error = %v, want nil", err)
	}
	if err := family.Revoke(); err != nil {
		t.Fatalf("fixture Revoke: %v", err)
	}
	now := time.Now()

	err = family.Rotate(now, "hash-gen-1", "hash-gen-2", now.Add(24*time.Hour))
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("Rotate() on a revoked-and-expired family error = %v, want ErrTokenReuseDetected (the revoked check must win over the expiry check)", err)
	}
}

func TestRefreshTokenFamily_Rotate_Expired(t *testing.T) {
	id, _ := NewFamilyID("11111111-1111-1111-1111-111111111111")
	accountID, _ := NewAccountID("22222222-2222-2222-2222-222222222222")
	family, err := IssueFamily(id, accountID, "hash-gen-1", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("IssueFamily() error = %v, want nil", err)
	}

	err = family.Rotate(time.Now(), "hash-gen-1", "hash-gen-2", time.Now().Add(24*time.Hour))
	if !errors.Is(err, ErrRefreshTokenExpired) {
		t.Fatalf("Rotate() on an expired family error = %v, want ErrRefreshTokenExpired", err)
	}
}

func TestRefreshTokenFamily_Revoke(t *testing.T) {
	family := newTestFamily(t)
	family.DrainEvents()

	if err := family.Revoke(); err != nil {
		t.Fatalf("Revoke() error = %v, want nil", err)
	}
	if !family.Revoked() {
		t.Error("Revoke() must mark the family revoked")
	}
	events := family.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	if _, ok := events[0].(RefreshTokenFamilyRevoked); !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want RefreshTokenFamilyRevoked", events[0])
	}
}

func TestRefreshTokenFamily_Revoke_RejectsAlreadyRevoked(t *testing.T) {
	family := newTestFamily(t)
	if err := family.Revoke(); err != nil {
		t.Fatalf("Revoke() error = %v, want nil", err)
	}

	if err := family.Revoke(); !errors.Is(err, ErrRefreshTokenFamilyAlreadyRevoked) {
		t.Errorf("Revoke() on an already-revoked family = %v, want ErrRefreshTokenFamilyAlreadyRevoked", err)
	}
}
