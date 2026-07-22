// internal/infra/httpapi/logout_handler.go
package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LogoutHandler struct {
	Handler command.RevokeSessionHandler
}

type LogoutInput struct {
	Body struct {
		RefreshToken string `json:"refresh_token" required:"true"`
	}
}

type LogoutOutput struct{}

func (h LogoutHandler) Handle(ctx context.Context, input *LogoutInput) (*LogoutOutput, error) {
	if err := h.Handler.Handle(ctx, command.RevokeSessionCommand{RefreshToken: input.Body.RefreshToken}); err != nil {
		return nil, mapAppError("logout", err)
	}
	return &LogoutOutput{}, nil
}
