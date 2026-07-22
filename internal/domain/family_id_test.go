package domain

import "testing"

func TestNewFamilyID(t *testing.T) {
	id, err := NewFamilyID("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("NewFamilyID() error = %v, want nil", err)
	}
	if id.String() != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("String() = %q, want the raw value", id.String())
	}
}

func TestNewFamilyID_RejectsEmpty(t *testing.T) {
	if _, err := NewFamilyID(""); err == nil {
		t.Error("NewFamilyID(\"\") error = nil, want error")
	}
}

func TestFamilyID_Equals(t *testing.T) {
	a, _ := NewFamilyID("same")
	b, _ := NewFamilyID("same")
	c, _ := NewFamilyID("different")

	if !a.Equals(b) {
		t.Error("Equals() = false for equal IDs, want true")
	}
	if a.Equals(c) {
		t.Error("Equals() = true for different IDs, want false")
	}
}
