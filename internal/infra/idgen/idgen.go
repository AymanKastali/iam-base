package idgen

import (
	"github.com/google/uuid"

	"github.com/AymanKastali/iam-base/internal/domain"
)

// UUIDGenerator is the app.IDGenerator adapter backed by google/uuid.
type UUIDGenerator struct{}

func (UUIDGenerator) NewAccountID() (domain.AccountID, error) {
	return domain.NewAccountID(uuid.NewString())
}
