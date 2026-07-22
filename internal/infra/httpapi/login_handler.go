package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LoginHandler struct {
	Handler command.LoginHandler
}

// LoginInput deliberately carries no `required`/`format` validation tags,
// and `omitempty` so Huma doesn't infer them as required either (verified: a
// non-pointer field without `omitempty` defaults to required in Huma's
// generated schema regardless of an explicit `required` tag). Every
// malformed or missing credential must reach LoginHandler.Handle, not be
// rejected upfront, so it returns the same ErrInvalidCredentials with the
// same timing padding regardless of why the login failed — see
// app.ErrInvalidCredentials.
type LoginInput struct {
	Body struct {
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
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
