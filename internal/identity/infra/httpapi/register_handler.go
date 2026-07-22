package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/identity/app/command"
	"github.com/AymanKastali/iam-base/internal/identity/domain"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	id, err := h.Handler.Handle(r.Context(), command.RegisterAccountCommand{Email: req.Email, Password: req.Password})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrEmailAlreadyRegistered):
			writeError(w, http.StatusConflict, "email already registered")
		case errors.Is(err, domain.ErrInvalidEmail):
			writeError(w, http.StatusBadRequest, "invalid email")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
