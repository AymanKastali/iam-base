// internal/app/command/refresh_token.go
package command

import (
	"errors"
	"strings"

	"github.com/AymanKastali/iam-base/internal/domain"
)

const refreshTokenSeparator = "."

var errMalformedRefreshToken = errors.New("malformed refresh token")

// formatRefreshToken builds the opaque wire-format refresh token: the family
// ID (so refresh/logout can look the family up directly) followed by the
// random secret, joined by refreshTokenSeparator.
func formatRefreshToken(familyID domain.FamilyID, secret string) string {
	return familyID.String() + refreshTokenSeparator + secret
}

// parseRefreshToken splits a wire-format refresh token back into its family
// ID and secret. A missing separator or an empty half is malformed.
func parseRefreshToken(raw string) (domain.FamilyID, string, error) {
	idPart, secret, found := strings.Cut(raw, refreshTokenSeparator)
	if !found || idPart == "" || secret == "" {
		return domain.FamilyID{}, "", errMalformedRefreshToken
	}
	familyID, err := domain.NewFamilyID(idPart)
	if err != nil {
		return domain.FamilyID{}, "", errMalformedRefreshToken
	}
	return familyID, secret, nil
}
