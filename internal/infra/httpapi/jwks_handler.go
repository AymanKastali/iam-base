package httpapi

import (
	"context"

	"github.com/AymanKastali/iam-base/internal/app/query"
)

type JWKSHandler struct {
	Handler query.GetJWKSHandler
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
