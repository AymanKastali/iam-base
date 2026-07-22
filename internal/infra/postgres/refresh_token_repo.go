package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AymanKastali/iam-base/internal/domain"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

// Save upserts the family: an INSERT for a newly-issued family (Login), or an
// UPDATE-via-ON-CONFLICT for an existing one (Rotate, Revoke) — one method
// covers both since domain.RefreshTokenRepository declares only Save, not a
// separate Create/Update pair.
func (r *RefreshTokenRepository) Save(ctx context.Context, family *domain.RefreshTokenFamily) error {
	const q = `
		INSERT INTO refresh_token_families (id, account_id, current_token_hash, generation, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			current_token_hash = EXCLUDED.current_token_hash,
			generation = EXCLUDED.generation,
			expires_at = EXCLUDED.expires_at,
			revoked = EXCLUDED.revoked
	`
	_, err := r.pool.Exec(ctx, q,
		family.ID().String(),
		family.AccountID().String(),
		family.CurrentTokenHash(),
		family.Generation(),
		family.ExpiresAt(),
		family.Revoked(),
	)
	return err
}

func (r *RefreshTokenRepository) FindByID(ctx context.Context, id domain.FamilyID) (*domain.RefreshTokenFamily, error) {
	const q = `
		SELECT account_id, current_token_hash, generation, expires_at, revoked
		FROM refresh_token_families
		WHERE id = $1
	`
	var (
		accountIDRaw string
		tokenHash    string
		generation   int
		expiresAt    time.Time
		revoked      bool
	)
	err := r.pool.QueryRow(ctx, q, id.String()).Scan(&accountIDRaw, &tokenHash, &generation, &expiresAt, &revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrRefreshTokenFamilyNotFound
		}
		return nil, err
	}

	accountID, err := domain.NewAccountID(accountIDRaw)
	if err != nil {
		return nil, err
	}
	return domain.ReconstituteRefreshTokenFamily(id, accountID, tokenHash, generation, expiresAt, revoked), nil
}
