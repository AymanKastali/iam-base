// internal/infra/httpapi/refresh_handler.go
package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RefreshHandler struct {
	Handler command.RotateRefreshTokenHandler
}

type RefreshInput struct {
	Body struct {
		RefreshToken string `json:"refresh_token" required:"true"`
	}
}

type RefreshOutput struct {
	Body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresAt    string `json:"expires_at"`
		RefreshToken string `json:"refresh_token"`
	}
}

func (h RefreshHandler) Handle(ctx context.Context, input *RefreshInput) (*RefreshOutput, error) {
	result, err := h.Handler.Handle(ctx, command.RotateRefreshTokenCommand{RefreshToken: input.Body.RefreshToken})
	if err != nil {
		return nil, mapAppError("refresh", err)
	}
	out := &RefreshOutput{}
	out.Body.AccessToken = result.AccessToken
	out.Body.TokenType = "Bearer"
	out.Body.ExpiresAt = result.AccessTokenExpiresAt.Format(http.TimeFormat)
	out.Body.RefreshToken = result.RefreshToken
	return out, nil
}
