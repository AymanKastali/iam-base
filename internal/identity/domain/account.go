// Package domain holds the Identity bounded context's pure business logic —
// the Account aggregate, its value objects, and the domain errors and
// repository ports it needs. No DB, clock, or HTTP belongs here.
package domain

type Account struct {
	AggregateRoot[AccountID]
	email      Email
	credential Credential
	status     AccountStatus
}

func NewAccount(id AccountID, email Email, credential Credential) (*Account, error) {
	account := &Account{
		AggregateRoot: NewAggregateRoot(id),
		email:         email,
		credential:    credential,
		status:        StatusActive,
	}
	account.RecordEvent(AccountRegistered{AccountID: id})
	return account, nil
}

func (a *Account) Email() Email           { return a.email }
func (a *Account) Credential() Credential { return a.credential }
func (a *Account) Status() AccountStatus  { return a.status }
func (a *Account) IsActive() bool         { return a.status == StatusActive }

// Disable marks the account disabled — a disabled account can no longer
// authenticate (see EnsureActive).
func (a *Account) Disable() {
	a.status = StatusDisabled
}

// Activate marks the account active again.
func (a *Account) Activate() {
	a.status = StatusActive
}

// EnsureActive enforces the login-eligibility invariant: a disabled account
// cannot authenticate. Callers check this instead of inspecting IsActive
// themselves, so the rule lives on the aggregate, not the caller.
func (a *Account) EnsureActive() error {
	if !a.IsActive() {
		return ErrAccountDisabled
	}
	return nil
}
