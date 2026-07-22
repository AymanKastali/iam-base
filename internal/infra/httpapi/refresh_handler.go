// internal/infra/httpapi/refresh_handler.go
package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RefreshHandler struct {
	Handler command.RotateRefreshTokenHandler
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
}

func (h RefreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	result, err := h.Handler.Handle(r.Context(), command.RotateRefreshTokenCommand{RefreshToken: req.RefreshToken})
	if err != nil {
		respondError(w, "refresh", err)
		return
	}

	writeJSON(w, http.StatusOK, refreshResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresAt:    result.AccessTokenExpiresAt.Format(http.TimeFormat),
		RefreshToken: result.RefreshToken,
	})
}
