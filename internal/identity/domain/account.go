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
