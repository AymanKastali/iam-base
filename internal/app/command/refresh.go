// internal/app/command/refresh.go
package command

import (
	"context"
	"errors"
	"time"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// ErrInvalidRefreshToken is command's alias for app.ErrInvalidRefreshToken.
var ErrInvalidRefreshToken = app.ErrInvalidRefreshToken

type RotateRefreshTokenCommand struct {
	RefreshToken string
}

type RefreshResult struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
	RefreshToken         string
}

type RotateRefreshTokenHandler struct {
	Repo            domain.RefreshTokenRepository
	TokenGen        app.RefreshTokenGenerator
	Issuer          app.TokenIssuer
	Clock           app.Clock
	RefreshTokenTTL time.Duration
}

func (h RotateRefreshTokenHandler) Handle(ctx context.Context, cmd RotateRefreshTokenCommand) (RefreshResult, error) {
	familyID, secret, err := parseRefreshToken(cmd.RefreshToken)
	if err != nil {
		return RefreshResult{}, ErrInvalidRefreshToken
	}

	family, err := h.Repo.FindByID(ctx, familyID)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenFamilyNotFound) {
			return RefreshResult{}, ErrInvalidRefreshToken
		}
		return RefreshResult{}, err
	}

	newSecret, newHash, err := h.TokenGen.Generate()
	if err != nil {
		return RefreshResult{}, err
	}

	now := h.Clock.Now()
	presentedHash := h.TokenGen.Hash(secret)
	rotateErr := family.Rotate(now, presentedHash, newHash, now.Add(h.RefreshTokenTTL))
	// Save unconditionally: on the reuse path Rotate has already marked the
	// family revoked, and that revocation must persist even though Handle
	// goes on to return a generic error.
	if saveErr := h.Repo.Save(ctx, family); saveErr != nil {
		return RefreshResult{}, saveErr
	}
	if rotateErr != nil {
		return RefreshResult{}, ErrInvalidRefreshToken
	}

	accessToken, expiresAt, err := h.Issuer.Issue(ctx, family.AccountID())
	if err != nil {
		return RefreshResult{}, err
	}

	return RefreshResult{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: expiresAt,
		RefreshToken:         formatRefreshToken(familyID, newSecret),
	}, nil
}
