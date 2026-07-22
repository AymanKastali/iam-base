package domain

const minPasswordLength = 8

// PasswordPolicy determines whether a raw password satisfies the domain's
// password-strength rules. Declared and implemented in domain — unlike
// AccountRepository, this needs no external adapter.
type PasswordPolicy interface {
	Validate(password string) error
}

// MinLengthPasswordPolicy is the domain's default PasswordPolicy.
type MinLengthPasswordPolicy struct{}

func (MinLengthPasswordPolicy) Validate(password string) error {
	if len(password) < minPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}
