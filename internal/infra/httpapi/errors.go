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
// errors — they just call mapAppError.
type kindedError interface {
	error
	Kind() app.Kind
	Code() string
}

// mapAppError classifies err via kindedError and returns the matching
// huma.StatusError; anything that doesn't implement it is logged and mapped
// to a generic 500. This is the single place that knows how app errors
// become wire responses — handlers only decide when to call it.
//
// ke.Code() (e.g. "invalid_email", "email_already_registered") is carried
// through as ErrorModel.Type — RFC 9457's slot for a stable, machine-readable
// problem identifier, distinct from Detail's free-text message — so API
// consumers can distinguish error causes without parsing English prose.
func mapAppError(action string, err error) error {
	if ke, ok := errors.AsType[kindedError](err); ok {
		status := statusForKind(ke.Kind())
		return &huma.ErrorModel{
			Type:   ke.Code(),
			Title:  http.StatusText(status),
			Status: status,
			Detail: ke.Error(),
		}
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
