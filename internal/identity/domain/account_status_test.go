package domain

import "testing"

func TestAccountStatus_String(t *testing.T) {
	if got := StatusActive.String(); got != "active" {
		t.Errorf("StatusActive.String() = %q, want %q", got, "active")
	}
	if got := StatusDisabled.String(); got != "disabled" {
		t.Errorf("StatusDisabled.String() = %q, want %q", got, "disabled")
	}
}
