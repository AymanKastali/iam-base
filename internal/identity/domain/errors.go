package domain

import "errors"

var (
	ErrInvalidEmail           = errors.New("invalid email")
	ErrInvalidCredential      = errors.New("invalid credential")
	ErrEmailAlreadyRegistered = errors.New("email already registered")
	ErrAccountNotFound        = errors.New("account not found")
	ErrAccountDisabled        = errors.New("account disabled")
)
