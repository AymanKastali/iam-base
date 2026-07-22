package httpapi

import (
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
