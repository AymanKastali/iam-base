package domain

type AccountStatus int

const (
	StatusActive AccountStatus = iota
	StatusDisabled
)

func (s AccountStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// ParseAccountStatus parses AccountStatus.String()'s output back into an
// AccountStatus — the repository adapter's counterpart for rehydrating a
// persisted account.
func ParseAccountStatus(raw string) (AccountStatus, error) {
	switch raw {
	case "active":
		return StatusActive, nil
	case "disabled":
		return StatusDisabled, nil
	default:
		return 0, ErrInvalidAccountStatus
	}
}
