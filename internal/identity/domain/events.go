package domain

const eventNameAccountRegistered = "identity.account_registered"

var _ Event = AccountRegistered{}

// AccountRegistered is raised when a new Account is created.
type AccountRegistered struct {
	AccountID AccountID
}

func (e AccountRegistered) EventName() string {
	return eventNameAccountRegistered
}
