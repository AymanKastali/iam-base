// internal/infra/httpapi/logout_handler.go
package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type LogoutHandler struct {
	Handler command.RevokeSessionHandler
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	if err := h.Handler.Handle(r.Context(), command.RevokeSessionCommand{RefreshToken: req.RefreshToken}); err != nil {
		respondError(w, "logout", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
