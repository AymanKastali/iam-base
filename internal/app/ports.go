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
