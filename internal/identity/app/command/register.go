package command

import (
	"context"

	"github.com/google/uuid"

	"github.com/AymanKastali/iam-base/internal/identity/app"
	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

type RegisterAccountCommand struct {
	Email    string
	Password string
}

type RegisterAccountHandler struct {
	Repo   domain.AccountRepository
	Hasher app.PasswordHasher
}

func (h RegisterAccountHandler) Handle(ctx context.Context, cmd RegisterAccountCommand) (domain.AccountID, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return domain.AccountID{}, err
	}
	credential, err := h.Hasher.Hash(cmd.Password)
	if err != nil {
		return domain.AccountID{}, err
	}
	id, err := domain.NewAccountID(uuid.NewString())
	if err != nil {
		return domain.AccountID{}, err
	}
	account, err := domain.Register(id, email, credential)
	if err != nil {
		return domain.AccountID{}, err
	}
	if err := h.Repo.Save(ctx, account); err != nil {
		return domain.AccountID{}, err
	}
	return account.ID(), nil
}
