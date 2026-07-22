// internal/app/command/refresh_fakes_test.go
package command

import (
	"context"
	"time"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type fakeRefreshTokenRepo struct {
	families map[string]*domain.RefreshTokenFamily
	saveErr  error
	findErr  error
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{families: map[string]*domain.RefreshTokenFamily{}}
}

func (r *fakeRefreshTokenRepo) Save(ctx context.Context, family *domain.RefreshTokenFamily) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.families[family.ID().String()] = family
	return nil
}

func (r *fakeRefreshTokenRepo) FindByID(ctx context.Context, id domain.FamilyID) (*domain.RefreshTokenFamily, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	family, ok := r.families[id.String()]
	if !ok {
		return nil, domain.ErrRefreshTokenFamilyNotFound
	}
	return family, nil
}

// fakeTokenGenerator returns deterministic secret/hash pairs so tests can
// assert on their exact values instead of just non-emptiness.
type fakeTokenGenerator struct {
	nextSecret string
	nextHash   string
}

func (f fakeTokenGenerator) Generate() (string, string, error) {
	return f.nextSecret, f.nextHash, nil
}

func (f fakeTokenGenerator) Hash(raw string) string {
	return "hash:" + raw
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}
