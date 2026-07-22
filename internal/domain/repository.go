package domain

import "context"

// AccountRepository is the write-repository port for the Account aggregate.
// The domain declares it; infra/postgres provides the adapter.
type AccountRepository interface {
	Save(ctx context.Context, account *Account) error
	FindByEmail(ctx context.Context, email Email) (*Account, error)
}
