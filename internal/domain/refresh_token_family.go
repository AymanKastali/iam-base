package domain

import "time"

// RefreshTokenFamily is the chain of refresh tokens produced by successive
// rotations for one login session. Reusing a superseded member of the family
// signals theft and revokes the whole family.
type RefreshTokenFamily struct {
	AggregateRoot[FamilyID]
	accountID        AccountID
	currentTokenHash string
	generation       int
	expiresAt        time.Time
	revoked          bool
}

// IssueFamily creates a brand-new RefreshTokenFamily at generation 1, e.g. on login.
func IssueFamily(id FamilyID, accountID AccountID, tokenHash string, expiresAt time.Time) (*RefreshTokenFamily, error) {
	family := &RefreshTokenFamily{
		AggregateRoot:    NewAggregateRoot(id),
		accountID:        accountID,
		currentTokenHash: tokenHash,
		generation:       1,
		expiresAt:        expiresAt,
	}
	family.RecordEvent(RefreshTokenFamilyIssued{FamilyID: id, AccountID: accountID})
	return family, nil
}

// ReconstituteRefreshTokenFamily rebuilds a RefreshTokenFamily already known to
// exist — loaded from storage, not newly issued — so it does not raise
// RefreshTokenFamilyIssued. Repository-only caller.
func ReconstituteRefreshTokenFamily(id FamilyID, accountID AccountID, tokenHash string, generation int, expiresAt time.Time, revoked bool) *RefreshTokenFamily {
	return &RefreshTokenFamily{
		AggregateRoot:    NewAggregateRoot(id),
		accountID:        accountID,
		currentTokenHash: tokenHash,
		generation:       generation,
		expiresAt:        expiresAt,
		revoked:          revoked,
	}
}

func (f *RefreshTokenFamily) AccountID() AccountID {
	return f.accountID
}

func (f *RefreshTokenFamily) CurrentTokenHash() string {
	return f.currentTokenHash
}

func (f *RefreshTokenFamily) Generation() int {
	return f.generation
}

func (f *RefreshTokenFamily) ExpiresAt() time.Time {
	return f.expiresAt
}

func (f *RefreshTokenFamily) Revoked() bool {
	return f.revoked
}

// Rotate consumes the current token and advances the family to a new
// generation. now and newExpiresAt are supplied by the caller (app.Clock) so
// the domain stays clock-free. presentedHash not matching the family's
// current hash means either an already-superseded token or a forged one —
// either way it is treated as theft: the whole family is revoked and
// ErrTokenReuseDetected is returned instead of rotating.
func (f *RefreshTokenFamily) Rotate(now time.Time, presentedHash, newHash string, newExpiresAt time.Time) error {
	if f.revoked {
		return ErrTokenReuseDetected
	}
	if now.After(f.expiresAt) {
		return ErrRefreshTokenExpired
	}
	if presentedHash != f.currentTokenHash {
		f.revoked = true
		f.RecordEvent(RefreshTokenFamilyRevoked{FamilyID: f.ID()})
		return ErrTokenReuseDetected
	}
	f.currentTokenHash = newHash
	f.generation++
	f.expiresAt = newExpiresAt
	f.RecordEvent(RefreshTokenFamilyRotated{FamilyID: f.ID()})
	return nil
}

// Revoke ends the family outright (logout). Revoking an already-revoked
// family is rejected — callers to whom that must be a no-op (idempotent
// logout) check for ErrRefreshTokenFamilyAlreadyRevoked themselves.
func (f *RefreshTokenFamily) Revoke() error {
	if f.revoked {
		return ErrRefreshTokenFamilyAlreadyRevoked
	}
	f.revoked = true
	f.RecordEvent(RefreshTokenFamilyRevoked{FamilyID: f.ID()})
	return nil
}
