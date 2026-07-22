package idgen

import "testing"

func TestUUIDGenerator_NewFamilyID(t *testing.T) {
	gen := UUIDGenerator{}

	id, err := gen.NewFamilyID()
	if err != nil {
		t.Fatalf("NewFamilyID() error = %v, want nil", err)
	}
	if id.String() == "" {
		t.Error("NewFamilyID() returned an empty FamilyID")
	}
}
