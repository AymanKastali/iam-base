package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RegisterHandler struct {
	Handler command.RegisterAccountHandler
}

type RegisterInput struct {
	Body struct {
		Email    string `json:"email" required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

type RegisterOutput struct {
	Body struct {
		ID string `json:"id"`
	}
}

func (h RegisterHandler) Handle(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	id, err := h.Handler.Handle(ctx, command.RegisterAccountCommand{Email: input.Body.Email, Password: input.Body.Password})
	if err != nil {
		return nil, mapAppError("register", err)
	}
	out := &RegisterOutput{}
	out.Body.ID = id.String()
	return out, nil
}
