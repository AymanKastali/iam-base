package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LoginHandler struct {
	Handler command.LoginHandler
}

type LoginInput struct {
	Body struct {
		Email    string `json:"email" required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

type LoginOutput struct {
	Body struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresAt    string `json:"expires_at"`
		RefreshToken string `json:"refresh_token"`
	}
}

func (h LoginHandler) Handle(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	result, err := h.Handler.Handle(ctx, command.LoginCommand{Email: input.Body.Email, Password: input.Body.Password})
	if err != nil {
		return nil, mapAppError("login", err)
	}
	out := &LoginOutput{}
	out.Body.AccessToken = result.AccessToken
	out.Body.TokenType = "Bearer"
	out.Body.ExpiresAt = result.ExpiresAt.Format(http.TimeFormat)
	out.Body.RefreshToken = result.RefreshToken
	return out, nil
}
