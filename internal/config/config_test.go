package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam?sslmode=disable")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "/etc/iam/private.pem")

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
	if cfg.JWTKeyID != "1" {
		t.Errorf("JWTKeyID = %q, want %q", cfg.JWTKeyID, "1")
	}
	if cfg.RateLimitRPS != 5 || cfg.RateLimitBurst != 10 {
		t.Errorf("rate limit = %v/%v, want 5/10", cfg.RateLimitRPS, cfg.RateLimitBurst)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for missing DATABASE_URL/JWT_PRIVATE_KEY_PATH")
	}
}
