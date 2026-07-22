package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

func newTestRepo(t *testing.T) *AccountRepository {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("iam_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	if err := Migrate(dsn, "file://migrations"); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	return &AccountRepository{pool: pool}
}

func newTestAccount(t *testing.T, email string) *domain.Account {
	t.Helper()
	e, err := domain.NewEmail(email)
	if err != nil {
		t.Fatalf("NewEmail: %v", err)
	}
	c, err := domain.NewCredential("hash", "argon2id", 1)
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	id, err := domain.NewAccountID(uuid.NewString())
	if err != nil {
		t.Fatalf("NewAccountID: %v", err)
	}
	acc, err := domain.Register(id, e, c)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return acc
}

func TestAccountRepository_SaveAndFindByEmail(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	acc := newTestAccount(t, "a@b.com")

	if err := repo.Save(ctx, acc); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	found, err := repo.FindByEmail(ctx, acc.Email())
	if err != nil {
		t.Fatalf("FindByEmail() error = %v, want nil", err)
	}
	if found.ID() != acc.ID() {
		t.Errorf("FindByEmail().ID() = %v, want %v", found.ID(), acc.ID())
	}
	if found.Status() != acc.Status() || !found.IsActive() {
		t.Errorf("FindByEmail().Status() = %v, want %v (active)", found.Status(), acc.Status())
	}
}

func TestAccountRepository_FindByEmail_PreservesDisabledStatus(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	acc := newTestAccount(t, "disabled@b.com")
	if err := acc.Disable(); err != nil {
		t.Fatalf("fixture Disable: %v", err)
	}

	if err := repo.Save(ctx, acc); err != nil {
		t.Fatalf("Save() error = %v, want nil", err)
	}

	found, err := repo.FindByEmail(ctx, acc.Email())
	if err != nil {
		t.Fatalf("FindByEmail() error = %v, want nil", err)
	}
	if found.Status() != domain.StatusDisabled || found.IsActive() {
		t.Errorf("FindByEmail().Status() = %v, want StatusDisabled — a disabled account must not silently reactivate on load", found.Status())
	}
	if events := found.RecordedEvents(); len(events) != 0 {
		t.Errorf("FindByEmail() recorded %d events, want 0 — loading is not a new registration", len(events))
	}
}

func TestAccountRepository_Save_DuplicateEmail(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	acc1 := newTestAccount(t, "dup@b.com")
	acc2 := newTestAccount(t, "dup@b.com")

	if err := repo.Save(ctx, acc1); err != nil {
		t.Fatalf("Save() first account error = %v, want nil", err)
	}
	err := repo.Save(ctx, acc2)
	if !errors.Is(err, domain.ErrEmailAlreadyRegistered) {
		t.Fatalf("Save() duplicate error = %v, want ErrEmailAlreadyRegistered", err)
	}
}

func TestAccountRepository_FindByEmail_NotFound(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	email, _ := domain.NewEmail("missing@b.com")

	_, err := repo.FindByEmail(ctx, email)
	if !errors.Is(err, domain.ErrAccountNotFound) {
		t.Fatalf("FindByEmail() error = %v, want ErrAccountNotFound", err)
	}
}
