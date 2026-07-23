package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 15m", cfg.AccessTokenTTL)
	}
	if cfg.JWTActiveKeyID != "1" {
		t.Errorf("JWTActiveKeyID = %q, want %q", cfg.JWTActiveKeyID, "1")
	}
	if cfg.RateLimitRPS != 5 || cfg.RateLimitBurst != 10 {
		t.Errorf("rate limit = %v/%v, want 5/10", cfg.RateLimitRPS, cfg.RateLimitBurst)
	}
}

func TestLoad_JWTActiveKeyID_Override(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")
	t.Setenv("JWT_ACTIVE_KEY_ID", "2")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.JWTActiveKeyID != "2" {
		t.Errorf("JWTActiveKeyID = %q, want %q", cfg.JWTActiveKeyID, "2")
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_KEYS_DIR", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for missing DATABASE_URL/JWT_KEYS_DIR")
	}
}

func TestLoad_Defaults_IncludesRefreshTokenTTL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 720h (30 days)", cfg.RefreshTokenTTL)
	}
}

func TestLoad_RefreshTokenTTL_Override(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_KEYS_DIR", "/etc/iam")
	t.Setenv("REFRESH_TOKEN_TTL", "1h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if cfg.RefreshTokenTTL != time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 1h", cfg.RefreshTokenTTL)
	}
}
