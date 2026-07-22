// Package command holds the identity module's write-side (CQRS command)
// use cases: RegisterAccount and Login orchestrate the domain and its ports,
// never touching persistence or infrastructure directly.
package command

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type RegisterAccountCommand struct {
	Email    string
	Password string
}

type RegisterAccountHandler struct {
	Repo   domain.AccountRepository
	Hasher app.PasswordHasher
	Policy domain.PasswordPolicy
	IDGen  app.IDGenerator
}

func (h RegisterAccountHandler) Handle(ctx context.Context, cmd RegisterAccountCommand) (_ domain.AccountID, err error) {
	defer func() { err = app.Classify(err) }()

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return domain.AccountID{}, err
	}
	if err := h.Policy.Validate(cmd.Password); err != nil {
		return domain.AccountID{}, err
	}
	credential, err := h.Hasher.Hash(cmd.Password)
	if err != nil {
		return domain.AccountID{}, err
	}
	id, err := h.IDGen.NewAccountID()
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
