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

// validateEmailFormat checks for proper email structure: user@domain.tld —
// a non-empty local part, a single @, and a domain containing a dot.
func validateEmailFormat(email string) error {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at >= len(email)-1 {
		return ErrInvalidEmail
	}
	domainPart := email[at+1:]
	if strings.Contains(domainPart, "@") || !strings.Contains(domainPart, ".") {
		return ErrInvalidEmail
	}
	return nil
}
