package domain

import "errors"

var (
	ErrInvalidEmail           = errors.New("invalid email")
	ErrInvalidCredential      = errors.New("invalid credential")
	ErrPasswordTooShort       = errors.New("password must be at least 8 characters")
	ErrEmailAlreadyRegistered = errors.New("email already registered")
	ErrAccountNotFound        = errors.New("account not found")
	ErrAccountDisabled        = errors.New("account disabled")
	ErrInvalidAccountID       = errors.New("invalid account id")
	ErrAccountAlreadyDisabled = errors.New("account already disabled")
	ErrAccountAlreadyActive   = errors.New("account already active")
	ErrInvalidAccountStatus   = errors.New("invalid account status")
	ErrInvalidFamilyID        = errors.New("invalid family id")
)
