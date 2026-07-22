package domain

const (
	eventNameAccountRegistered = "identity.account_registered"
	eventNameAccountDisabled   = "identity.account_disabled"
	eventNameAccountActivated  = "identity.account_activated"
)

var _ Event = AccountRegistered{}

// AccountRegistered is raised when a new Account is created.
type AccountRegistered struct {
	AccountID AccountID
}

func (e AccountRegistered) EventName() string {
	return eventNameAccountRegistered
}

var _ Event = AccountDisabled{}

// AccountDisabled is raised when an Account transitions to disabled.
type AccountDisabled struct {
	AccountID AccountID
}

func (e AccountDisabled) EventName() string {
	return eventNameAccountDisabled
}

var _ Event = AccountActivated{}

// AccountActivated is raised when a disabled Account is reactivated.
type AccountActivated struct {
	AccountID AccountID
}

func (e AccountActivated) EventName() string {
	return eventNameAccountActivated
}
