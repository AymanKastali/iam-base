package domain

// DomainError represents an error originating from the domain layer.
type DomainError struct {
	message string
}

func (e *DomainError) Error() string {
	return e.message
}

// NewDomainError creates a new domain error with the given message.
func NewDomainError(message string) *DomainError {
	return &DomainError{message: message}
}

var (
	ErrInvalidEmail           = NewDomainError("invalid email")
	ErrInvalidCredential      = NewDomainError("invalid credential")
	ErrEmailAlreadyRegistered = NewDomainError("email already registered")
	ErrAccountNotFound        = NewDomainError("account not found")
	ErrAccountDisabled        = NewDomainError("account disabled")
)
