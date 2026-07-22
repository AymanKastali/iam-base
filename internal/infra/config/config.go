// Package config loads the identity service's configuration from the
// environment, failing fast when a required value is missing or invalid.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port              string
	DatabaseURL       string
	JWTPrivateKeyPath string
	JWTKeyID          string
	AccessTokenTTL    time.Duration
	RateLimitRPS      float64
	RateLimitBurst    int
}

func Load() (Config, error) {
	cfg := Config{
		Port:              getEnv("PORT", "8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		JWTPrivateKeyPath: os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTKeyID:          getEnv("JWT_KEY_ID", "1"),
		AccessTokenTTL:    15 * time.Minute,
		RateLimitRPS:      5,
		RateLimitBurst:    10,
	}

	if ttl := os.Getenv("ACCESS_TOKEN_TTL"); ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ACCESS_TOKEN_TTL: %w", err)
		}
		cfg.AccessTokenTTL = d
	}
	if rps := os.Getenv("RATE_LIMIT_RPS"); rps != "" {
		v, err := strconv.ParseFloat(rps, 64)
		if err != nil {
			return Config{}, fmt.Errorf("invalid RATE_LIMIT_RPS: %w", err)
		}
		cfg.RateLimitRPS = v
	}
	if burst := os.Getenv("RATE_LIMIT_BURST"); burst != "" {
		v, err := strconv.Atoi(burst)
		if err != nil {
			return Config{}, fmt.Errorf("invalid RATE_LIMIT_BURST: %w", err)
		}
		cfg.RateLimitBurst = v
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.JWTPrivateKeyPath == "" {
		return Config{}, errors.New("JWT_PRIVATE_KEY_PATH is required")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
