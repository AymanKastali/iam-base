// Package composition is the application's composition root: it wires
// config into concrete adapters and use-case handlers, returning the
// fully-assembled HTTP application. cmd/server calls Build and constructs
// nothing itself.
package composition

import (
	"context"
	"net/http"
	"time"

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

// Application bundles what cmd/server needs to serve requests and shut
// down cleanly.
type Application struct {
	Router http.Handler
	Pool   *pgxpool.Pool
}

// Build runs pending migrations and wires every dependency the identity
// module needs, from the Postgres pool up through the HTTP router.
func Build(ctx context.Context, cfg config.Config) (*Application, error) {
	if err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		return nil, err
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.LoadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		pool.Close()
		return nil, err
	}

	repo := postgres.NewAccountRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer := jwt.NewRSAIssuer(privateKey, cfg.JWTKeyID, cfg.AccessTokenTTL, systemClock{})

	registerHandler := httpapi.RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: hasher}}
	loginHandler := httpapi.LoginHandler{Handler: command.LoginHandler{Repo: repo, Hasher: hasher, Issuer: issuer}}
	jwksHandler := httpapi.JWKSHandler{Handler: query.GetJWKSHandler{Port: issuer}}
	limiter := httpapi.NewIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	router := httpapi.NewRouter(registerHandler, loginHandler, jwksHandler, limiter)

	return &Application{Router: router, Pool: pool}, nil
}
