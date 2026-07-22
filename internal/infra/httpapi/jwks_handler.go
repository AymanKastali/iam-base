package httpapi

import (
	"context"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/app/query"
)

type JWKSHandler struct {
	Handler query.GetJWKSHandler
}

func (h JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc, err := h.Handler.Handle(r.Context())
	if err != nil {
		respondError(w, "jwks", err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

type JWKSInput struct{}

type JWKSOutput struct {
	Body query.JWKSDocument
}

func (h JWKSHandler) Handle(ctx context.Context, input *JWKSInput) (*JWKSOutput, error) {
	doc, err := h.Handler.Handle(ctx)
	if err != nil {
		return nil, mapAppError("jwks", err)
	}
	return &JWKSOutput{Body: doc}, nil
}
