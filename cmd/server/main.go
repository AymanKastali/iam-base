// cmd/server/main.go
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AymanKastali/iam-base/internal/identity/app/command"
	"github.com/AymanKastali/iam-base/internal/identity/app/query"
	"github.com/AymanKastali/iam-base/internal/identity/infra/httpapi"
	"github.com/AymanKastali/iam-base/internal/identity/infra/jwt"
	"github.com/AymanKastali/iam-base/internal/identity/infra/passwordhash"
	"github.com/AymanKastali/iam-base/internal/identity/infra/postgres"
	"github.com/AymanKastali/iam-base/internal/infra/config"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := runMigrations(cfg.DatabaseURL); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	privateKey, err := loadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		log.Fatalf("load JWT private key: %v", err)
	}

	repo := postgres.NewAccountRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer := jwt.NewRSAIssuer(privateKey, cfg.JWTKeyID, cfg.AccessTokenTTL, systemClock{})

	registerHandler := httpapi.RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: hasher}}
	loginHandler := httpapi.LoginHandler{Handler: command.LoginHandler{Repo: repo, Hasher: hasher, Issuer: issuer}}
	jwksHandler := httpapi.JWKSHandler{Handler: query.GetJWKSHandler{Port: issuer}}
	limiter := httpapi.NewIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	router := httpapi.NewRouter(registerHandler, loginHandler, jwksHandler, limiter)

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func runMigrations(databaseURL string) error {
	// Relative to the process's working directory — must run from the repo
	// root (or a container WORKDIR laid out the same way; see the
	// Dockerfile's COPY destinations for the migrations directory).
	m, err := migrate.New("file://internal/identity/infra/postgres/migrations", databaseURL)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM in JWT private key file")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
