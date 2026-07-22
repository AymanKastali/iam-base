package postgres

import (
	"embed"
	"errors"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate runs all pending migrations against databaseURL, tolerating the
// case where none are pending. Migrations are embedded in the binary rather
// than read from a path relative to the process's working directory, so
// this works the same regardless of where or how the binary is deployed.
func Migrate(databaseURL string) error {
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithSourceInstance("iofs", sourceDriver, toPgx5DSN(databaseURL))
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// toPgx5DSN rewrites a postgres:// or postgresql:// DSN to the pgx5://
// scheme golang-migrate's pgx/v5 driver registers under.
func toPgx5DSN(databaseURL string) string {
	return "pgx5://" + strings.TrimPrefix(strings.TrimPrefix(databaseURL, "postgres://"), "postgresql://")
}
