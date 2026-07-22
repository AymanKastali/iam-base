// internal/app/command/logout.go
package command

import (
	"context"
	"errors"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type RevokeSessionCommand struct {
	RefreshToken string
}

type RevokeSessionHandler struct {
	Repo domain.RefreshTokenRepository
}

// Handle revokes the family the presented refresh token belongs to. It is
// idempotent by design: a malformed token, an unknown family, or a family
// that's already revoked all return nil — logout's only job is "make sure
// this session is not valid," which is already true in all three cases, and
// treating them as errors would let a client distinguish an unknown family
// from a known-but-already-revoked one.
func (h RevokeSessionHandler) Handle(ctx context.Context, cmd RevokeSessionCommand) error {
	familyID, _, err := parseRefreshToken(cmd.RefreshToken)
	if err != nil {
		return nil
	}

	family, err := h.Repo.FindByID(ctx, familyID)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenFamilyNotFound) {
			return nil
		}
		return err
	}

	if err := family.Revoke(); err != nil {
		if errors.Is(err, domain.ErrRefreshTokenFamilyAlreadyRevoked) {
			return nil
		}
		return err
	}

	return h.Repo.Save(ctx, family)
}
