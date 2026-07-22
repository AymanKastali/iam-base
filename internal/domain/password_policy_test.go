package domain

import (
	"errors"
	"testing"
)

func TestMinLengthPasswordPolicy_Validate(t *testing.T) {
	policy := MinLengthPasswordPolicy{}

	if err := policy.Validate("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Validate(%q) error = %v, want ErrPasswordTooShort", "short", err)
	}
	if err := policy.Validate("12345678"); err != nil {
		t.Errorf("Validate(%q) error = %v, want nil", "12345678", err)
	}
	if err := policy.Validate("123456789"); err != nil {
		t.Errorf("Validate(%q) error = %v, want nil", "123456789", err)
	}
}
