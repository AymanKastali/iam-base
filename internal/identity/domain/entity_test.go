package domain

import "testing"

func TestEntity_Equals(t *testing.T) {
	a := NewEntity("same")
	b := NewEntity("same")
	c := NewEntity("different")

	if !a.Equals(b) {
		t.Error("Equals() = false for equal IDs, want true")
	}
	if a.Equals(c) {
		t.Error("Equals() = true for different IDs, want false")
	}
	if a.ID() != "same" {
		t.Errorf("ID() = %q, want %q", a.ID(), "same")
	}
}
