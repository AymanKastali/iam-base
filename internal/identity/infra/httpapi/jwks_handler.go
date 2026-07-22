package httpapi

import (
	"net/http"

	"github.com/AymanKastali/iam-base/internal/identity/app/query"
)

type JWKSHandler struct {
	Handler query.GetJWKSHandler
}

func (h JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	doc, err := h.Handler.Handle(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}
