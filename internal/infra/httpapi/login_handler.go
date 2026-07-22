package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LoginHandler struct {
	Handler command.LoginHandler
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
}

func (h LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	result, err := h.Handler.Handle(r.Context(), command.LoginCommand{Email: req.Email, Password: req.Password})
	if err != nil {
		respondError(w, "login", err)
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.ExpiresAt.Format(http.TimeFormat),
		RefreshToken: result.RefreshToken,
	})
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
