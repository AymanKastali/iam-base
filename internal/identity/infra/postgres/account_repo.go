package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

type AccountRepository struct {
	pool *pgxpool.Pool
}

func NewAccountRepository(pool *pgxpool.Pool) *AccountRepository {
	return &AccountRepository{pool: pool}
}

func (r *AccountRepository) Save(ctx context.Context, account *domain.Account) error {
	const q = `
		INSERT INTO accounts (id, email, credential_hash, credential_algo, credential_version, status)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.pool.Exec(ctx, q,
		account.ID().String(),
		account.Email().String(),
		account.Credential().Hash(),
		account.Credential().Algo(),
		account.Credential().Version(),
		account.Status().String(),
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrEmailAlreadyRegistered
		}
		return err
	}
	return nil
}

func (r *AccountRepository) FindByEmail(ctx context.Context, email domain.Email) (*domain.Account, error) {
	const q = `
		SELECT id, email, credential_hash, credential_algo, credential_version, status
		FROM accounts WHERE email = $1
	`
	var (
		id, emailStr, hash, algo, status string
		version                          int
	)
	err := r.pool.QueryRow(ctx, q, email.String()).Scan(&id, &emailStr, &hash, &algo, &version, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrAccountNotFound
		}
		return nil, err
	}

	e, err := domain.NewEmail(emailStr)
	if err != nil {
		return nil, err
	}
	cred, err := domain.NewCredential(hash, algo, version)
	if err != nil {
		return nil, err
	}
	accountID, err := domain.NewAccountID(id)
	if err != nil {
		return nil, err
	}
	accountStatus, err := domain.ParseAccountStatus(status)
	if err != nil {
		return nil, err
	}
	return domain.Reconstitute(accountID, e, cred, accountStatus), nil
}
