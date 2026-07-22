package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app"
)

// kindedError is implemented by any app-layer error that carries a Kind and
// a machine-readable Code (see app.Error). Handlers never name individual
// errors — they just call respondError or mapAppError.
type kindedError interface {
	error
	Kind() app.Kind
	Code() string
}

// respondError classifies err via kindedError and writes the matching
// response; anything that doesn't implement it is logged and returned as a
// generic 500. Used by handlers not yet converted to Huma operations. Once
// every handler calls mapAppError instead (Tasks 3-7 complete), Task 8
// deletes this function together with response.go.
func respondError(w http.ResponseWriter, action string, err error) {
	if ke, ok := errors.AsType[kindedError](err); ok {
		writeError(w, statusForKind(ke.Kind()), ke.Code(), ke.Error())
		return
	}
	log.Printf("%s: unexpected error: %v", action, err)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}

// mapAppError classifies err via kindedError and returns the matching
// huma.StatusError; anything that doesn't implement it is logged and mapped
// to a generic 500. This is what every Huma-converted handler (Tasks 3-7)
// calls instead of respondError.
func mapAppError(action string, err error) error {
	if ke, ok := errors.AsType[kindedError](err); ok {
		return huma.NewError(statusForKind(ke.Kind()), ke.Error())
	}
	log.Printf("%s: unexpected error: %v", action, err)
	return huma.NewError(http.StatusInternalServerError, "internal error")
}

func statusForKind(k app.Kind) int {
	switch k {
	case app.KindValidation:
		// A business rule rejected the submitted data itself (e.g. password
		// policy, email format) — the payload is well-formed but semantically
		// invalid.
		return http.StatusUnprocessableEntity
	case app.KindConflict:
		// The data is valid but conflicts with existing state (e.g. email
		// already registered) — RFC 9110's 409, not 422.
		return http.StatusConflict
	case app.KindUnauthorized:
		return http.StatusUnauthorized
	case app.KindNotFound:
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
