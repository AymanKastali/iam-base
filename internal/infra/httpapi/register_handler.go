package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

// maxRequestBodyBytes caps request bodies on public, unauthenticated
// endpoints so a large or slow-drip body can't exhaust server memory.
const maxRequestBodyBytes = 1 << 16 // 64KB

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
		switch {
		case errors.Is(err, domain.ErrEmailAlreadyRegistered):
			writeError(w, http.StatusConflict, "email_already_registered", "email already registered")
		case errors.Is(err, domain.ErrInvalidEmail):
			writeError(w, http.StatusBadRequest, "invalid_email", "invalid email")
		case errors.Is(err, command.ErrPasswordTooShort):
			writeError(w, http.StatusBadRequest, "password_too_short", "password must be at least 8 characters")
		default:
			log.Printf("register: unexpected error: %v", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id.String()})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: errorBody{Code: code, Message: message}})
}
