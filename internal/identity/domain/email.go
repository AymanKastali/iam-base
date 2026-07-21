package domain

import (
	"strings"
)

type Email struct {
	value string
}

var _ ValueObject[Email] = Email{}

func NewEmail(raw string) (Email, error) {
	normalized, err := normalizeEmail(raw)
	if err != nil {
		return Email{}, err
	}
	if err := validateEmailFormat(normalized); err != nil {
		return Email{}, err
	}
	return Email{value: normalized}, nil
}

func (e Email) String() string {
	return e.value
}

func (e Email) Equals(other Email) bool {
	return e.value == other.value
}

// normalizeEmail trims whitespace and converts to lowercase.
func normalizeEmail(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(trimmed), nil
}

// validateEmailFormat checks for proper email structure: user@domain.tld
func validateEmailFormat(email string) error {
	at := strings.IndexByte(email, '@')
	if !hasValidLocalPart(email, at) {
		return ErrInvalidEmail
	}
	if !hasValidDomain(email, at) {
		return ErrInvalidEmail
	}
	return nil
}

// hasValidLocalPart checks the part before @.
func hasValidLocalPart(email string, atIdx int) bool {
	return atIdx > 0
}

// hasValidDomain checks the part after @ has at least one dot.
func hasValidDomain(email string, atIdx int) bool {
	if atIdx == -1 || atIdx >= len(email)-1 {
		return false
	}
	domainPart := email[atIdx+1:]
	// Check for multiple @ symbols in domain part
	if strings.ContainsAny(domainPart, "@") {
		return false
	}
	// Domain must contain at least one dot
	return strings.Contains(domainPart, ".")
}
