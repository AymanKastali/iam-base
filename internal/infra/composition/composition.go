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

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
	"github.com/AymanKastali/iam-base/internal/infra/config"
	"github.com/AymanKastali/iam-base/internal/infra/httpapi"
	"github.com/AymanKastali/iam-base/internal/infra/idgen"
	"github.com/AymanKastali/iam-base/internal/infra/jwt"
	"github.com/AymanKastali/iam-base/internal/infra/passwordhash"
	"github.com/AymanKastali/iam-base/internal/infra/postgres"
	"github.com/AymanKastali/iam-base/internal/infra/refreshtoken"
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

	keys, err := jwt.LoadRSAPrivateKeys(cfg.JWTKeysDir)
	if err != nil {
		pool.Close()
		return nil, err
	}

	repo := postgres.NewAccountRepository(pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool)
	hasher := passwordhash.Argon2IDHasher{}
	issuer, err := jwt.NewRSAIssuer(keys, cfg.JWTActiveKeyID, cfg.AccessTokenTTL, systemClock{})
	if err != nil {
		pool.Close()
		return nil, err
	}
	tokenGen := refreshtoken.SHA256Generator{}
	idGen := idgen.UUIDGenerator{}
	clock := systemClock{}

	registerHandler := httpapi.RegisterHandler{Handler: command.RegisterAccountHandler{Repo: repo, Hasher: hasher, Policy: domain.MinLengthPasswordPolicy{}, IDGen: idGen}}
	loginHandler := httpapi.LoginHandler{Handler: command.LoginHandler{
		Repo: repo, Hasher: hasher, Issuer: issuer,
		RefreshRepo: refreshTokenRepo, TokenGen: tokenGen, IDGen: idGen,
		Clock: clock, RefreshTokenTTL: cfg.RefreshTokenTTL,
	}}
	refreshHandler := httpapi.RefreshHandler{Handler: command.RotateRefreshTokenHandler{
		Repo: refreshTokenRepo, TokenGen: tokenGen, Issuer: issuer,
		Clock: clock, RefreshTokenTTL: cfg.RefreshTokenTTL,
	}}
	logoutHandler := httpapi.LogoutHandler{Handler: command.RevokeSessionHandler{Repo: refreshTokenRepo}}
	jwksHandler := httpapi.JWKSHandler{Handler: query.GetJWKSHandler{Port: issuer}}
	limiter := httpapi.NewIPRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	router := httpapi.NewRouter(registerHandler, loginHandler, refreshHandler, logoutHandler, jwksHandler, limiter)

	return &Application{Router: router, Pool: pool}, nil
}
