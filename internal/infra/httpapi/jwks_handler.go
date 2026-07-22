package httpapi

import (
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
