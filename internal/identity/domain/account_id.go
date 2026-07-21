package domain

// AccountID is the Account aggregate's identity — an opaque, non-empty
// value. The app layer generates the raw value (e.g. a UUID); domain only
// validates and holds it, exactly like Email or Credential.
type AccountID struct {
	value string
}

var _ ValueObject[AccountID] = AccountID{}

func NewAccountID(raw string) (AccountID, error) {
	if raw == "" {
		return AccountID{}, ErrInvalidAccountID
	}
	return AccountID{value: raw}, nil
}

func (id AccountID) String() string {
	return id.value
}

func (id AccountID) Equals(other AccountID) bool {
	return id.value == other.value
}
