package command

import (
	"context"
	"errors"
	"time"

	"github.com/AymanKastali/iam-base/internal/identity/app"
	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

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
		return LoginResult{}, ErrInvalidCredentials
	}
	if err := account.Login(); err != nil {
		return LoginResult{}, err
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
