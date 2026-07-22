package domain

import "testing"

func TestNewAccountID(t *testing.T) {
	id, err := NewAccountID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("NewAccountID() error = %v, want nil", err)
	}
	if id.String() != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("String() = %q, want the raw value", id.String())
	}
}

func TestNewAccountID_RejectsEmpty(t *testing.T) {
	if _, err := NewAccountID(""); err == nil {
		t.Error("NewAccountID(\"\") error = nil, want error")
	}
}

func TestAccountID_Equals(t *testing.T) {
	a, _ := NewAccountID("same")
	b, _ := NewAccountID("same")
	c, _ := NewAccountID("different")

	if !a.Equals(b) {
		t.Error("Equals() = false for equal IDs, want true")
	}
	if a.Equals(c) {
		t.Error("Equals() = true for different IDs, want false")
	}
}
