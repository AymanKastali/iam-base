package app

import (
	"context"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type PasswordHasher interface {
	Hash(password string) (domain.Credential, error)
	Verify(credential domain.Credential, password string) (bool, error)
}

type TokenIssuer interface {
	Issue(ctx context.Context, accountID domain.AccountID) (accessToken string, expiresAt time.Time, err error)
}

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewAccountID() (domain.AccountID, error)
	NewFamilyID() (domain.FamilyID, error)
}

// RefreshTokenGenerator issues opaque refresh-token secrets and hashes them
// for storage/comparison. The raw secret is returned to the caller once and
// is never persisted — only its hash is stored, so a leaked database dump
// does not expose usable refresh tokens.
type RefreshTokenGenerator interface {
	Generate() (raw string, hash string, err error)
	Hash(raw string) string
}
