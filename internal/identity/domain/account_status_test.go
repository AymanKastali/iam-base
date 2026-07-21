package domain

import (
	"errors"
	"testing"
)

func TestAccountStatus_String(t *testing.T) {
	if got := StatusActive.String(); got != "active" {
		t.Errorf("StatusActive.String() = %q, want %q", got, "active")
	}
	if got := StatusDisabled.String(); got != "disabled" {
		t.Errorf("StatusDisabled.String() = %q, want %q", got, "disabled")
	}
}

func TestParseAccountStatus(t *testing.T) {
	got, err := ParseAccountStatus("active")
	if err != nil || got != StatusActive {
		t.Errorf("ParseAccountStatus(%q) = %v, %v, want StatusActive, nil", "active", got, err)
	}

	got, err = ParseAccountStatus("disabled")
	if err != nil || got != StatusDisabled {
		t.Errorf("ParseAccountStatus(%q) = %v, %v, want StatusDisabled, nil", "disabled", got, err)
	}
}

func TestParseAccountStatus_RejectsUnrecognizedValue(t *testing.T) {
	if _, err := ParseAccountStatus("archived"); !errors.Is(err, ErrInvalidAccountStatus) {
		t.Errorf("ParseAccountStatus(%q) error = %v, want ErrInvalidAccountStatus", "archived", err)
	}
}

func TestAccountStatus_StringAndParse_RoundTrip(t *testing.T) {
	for _, s := range []AccountStatus{StatusActive, StatusDisabled} {
		got, err := ParseAccountStatus(s.String())
		if err != nil || got != s {
			t.Errorf("ParseAccountStatus(%q.String()) = %v, %v, want %v, nil", s, got, err, s)
		}
	}
}
