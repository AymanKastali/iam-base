package app

import (
	"errors"

	"github.com/AymanKastali/iam-base/internal/domain"
)

// Kind classifies an Error into a small, transport-agnostic category so any
// transport (HTTP, gRPC, ...) can map it to an appropriate response without
// needing to know about every individual error the app layer returns.
type Kind int

const (
	KindInternal Kind = iota // zero value: unclassified, treated as an internal error
	KindValidation
	KindConflict
	KindNotFound
	KindUnauthorized
)

// Error is a categorized application error: a Kind for transport mapping, a
// stable machine-readable Code, and the cause it was translated from — its
// message is the cause's message, so there's only one place text is authored.
type Error struct {
	kind  Kind
	code  string
	cause error
}

func NewError(kind Kind, code string, cause error) *Error {
	return &Error{kind: kind, code: code, cause: cause}
}

func (e *Error) Error() string { return e.cause.Error() }
func (e *Error) Kind() Kind    { return e.kind }
func (e *Error) Code() string  { return e.code }
func (e *Error) Unwrap() error { return e.cause }

// ErrInvalidCredentials is returned by LoginHandler for any login failure
// that must be indistinguishable from a wrong password (unknown email,
// wrong password, disabled account) so the response never leaks account
// existence or status.
var ErrInvalidCredentials = NewError(KindUnauthorized, "invalid_credentials", errors.New("invalid credentials"))

// Classify translates a raw domain error into a categorized *Error, so
// command handlers never need to know the HTTP-facing shape of their own
// errors — they just defer a Classify call once, at the top of Handle. Any
// error it doesn't recognize is returned unchanged (infra then treats it as
// an unclassified/internal error).
func Classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrInvalidEmail):
		return NewError(KindValidation, "invalid_email", err)
	case errors.Is(err, domain.ErrPasswordTooShort):
		return NewError(KindValidation, "password_too_short", err)
	case errors.Is(err, domain.ErrEmailAlreadyRegistered):
		return NewError(KindConflict, "email_already_registered", err)
	default:
		return err
	}
}
