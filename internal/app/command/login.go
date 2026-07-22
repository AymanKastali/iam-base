package command

import (
	"context"
	"errors"
	"time"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// ErrInvalidCredentials is command's alias for app.ErrInvalidCredentials, so
// callers in this package don't need to import app just to reference it.
var ErrInvalidCredentials = app.ErrInvalidCredentials

type LoginCommand struct {
	Email    string
	Password string
}

type LoginResult struct {
	AccessToken string
	ExpiresAt   time.Time
}

type LoginHandler struct {
	Repo   domain.AccountRepository
	Hasher app.PasswordHasher
	Issuer app.TokenIssuer
}

func (h LoginHandler) Handle(ctx context.Context, cmd LoginCommand) (LoginResult, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	account, err := h.Repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrAccountNotFound) {
			h.padTimingCost(cmd.Password)
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	if err := account.Login(); err != nil {
		h.padTimingCost(cmd.Password)
		return LoginResult{}, ErrInvalidCredentials
	}
	ok, err := h.Hasher.Verify(account.Credential(), cmd.Password)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		return LoginResult{}, ErrInvalidCredentials
	}
	token, expiresAt, err := h.Issuer.Issue(ctx, account.ID())
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{AccessToken: token, ExpiresAt: expiresAt}, nil
}

// padTimingCost runs a throwaway password hash so the unknown-email and
// disabled-account paths cost roughly the same as a real credential
// verification — otherwise their faster response time would leak account
// existence/status to an attacker even though the returned error doesn't.
func (h LoginHandler) padTimingCost(password string) {
	_, _ = h.Hasher.Hash(password)
}
