package domain

type AccountStatus int

const (
	StatusActive AccountStatus = iota
	StatusDisabled
)

func (s AccountStatus) String() string {
	if s == StatusDisabled {
		return "disabled"
	}
	return "active"
}
