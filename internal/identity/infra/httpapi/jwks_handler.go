package httpapi

import (
	"log"
	"net/http"

	"github.com/AymanKastali/iam-base/internal/identity/app/query"
)

type JWKSHandler struct {
	Handler query.GetJWKSHandler
}

func (h JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc, err := h.Handler.Handle(r.Context())
	if err != nil {
		log.Printf("jwks: unexpected error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}
