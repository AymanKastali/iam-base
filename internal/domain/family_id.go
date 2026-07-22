package domain

// FamilyID identifies a RefreshTokenFamily. The raw value is produced by an
// infra-provided app.IDGenerator adapter; domain only validates and holds it.
type FamilyID struct {
	value string
}

var _ ValueObject[FamilyID] = FamilyID{}

func NewFamilyID(raw string) (FamilyID, error) {
	if raw == "" {
		return FamilyID{}, ErrInvalidFamilyID
	}
	return FamilyID{value: raw}, nil
}

func (id FamilyID) String() string {
	return id.value
}

func (id FamilyID) Equals(other FamilyID) bool {
	return id.value == other.value
}
