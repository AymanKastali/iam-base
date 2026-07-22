package postgres

import (
	"errors"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Migrate runs all pending migrations found at sourceURL against
// databaseURL, tolerating the case where none are pending.
func Migrate(databaseURL, sourceURL string) error {
	m, err := migrate.New(sourceURL, toPgx5DSN(databaseURL))
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
