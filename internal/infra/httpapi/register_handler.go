package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
)

type RegisterHandler struct {
	Handler command.RegisterAccountHandler
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	id, err := h.Handler.Handle(r.Context(), command.RegisterAccountCommand{Email: req.Email, Password: req.Password})
	if err != nil {
		respondError(w, "register", err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}
