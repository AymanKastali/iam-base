package postgres

import "testing"

func TestToPgx5DSN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"postgres scheme", "postgres://user:pass@host:5432/db", "pgx5://user:pass@host:5432/db"},
		{"postgresql scheme", "postgresql://user:pass@host:5432/db", "pgx5://user:pass@host:5432/db"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toPgx5DSN(tt.in); got != tt.want {
				t.Errorf("toPgx5DSN(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
