package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/identity/app/command"
	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

type LoginHandler struct {
	Handler command.LoginHandler
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   string `json:"expires_at"`
}

func (h LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	result, err := h.Handler.Handle(r.Context(), command.LoginCommand{Email: req.Email, Password: req.Password})
	if err != nil {
		switch {
		case errors.Is(err, command.ErrInvalidCredentials), errors.Is(err, domain.ErrAccountDisabled):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		default:
			log.Printf("login: unexpected error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   result.ExpiresAt.Format(http.TimeFormat),
	})
}
