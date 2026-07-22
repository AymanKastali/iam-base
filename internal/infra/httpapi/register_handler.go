package httpapi

import (
	"context"
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

type RegisterInput struct {
	Body struct {
		Email    string `json:"email" required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

type RegisterOutput struct {
	Body struct {
		ID string `json:"id"`
	}
}

func (h RegisterHandler) Handle(ctx context.Context, input *RegisterInput) (*RegisterOutput, error) {
	id, err := h.Handler.Handle(ctx, command.RegisterAccountCommand{Email: input.Body.Email, Password: input.Body.Password})
	if err != nil {
		return nil, mapAppError("register", err)
	}
	out := &RegisterOutput{}
	out.Body.ID = id.String()
	return out, nil
}
