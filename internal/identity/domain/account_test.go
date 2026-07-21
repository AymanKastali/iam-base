package domain

import (
	"errors"
	"testing"
)

func TestNewAccount(t *testing.T) {
	email, _ := NewEmail("a@b.com")
	cred, _ := NewCredential("hash", "argon2id", 1)
	id, _ := NewAccountID("11111111-1111-1111-1111-111111111111")

	acc, err := NewAccount(id, email, cred)
	if err != nil {
		t.Fatalf("NewAccount() error = %v, want nil", err)
	}
	if acc.ID() != id {
		t.Errorf("ID() = %v, want %v", acc.ID(), id)
	}
	if acc.Email() != email {
		t.Errorf("Email() = %v, want %v", acc.Email(), email)
	}
	if acc.Status() != StatusActive || !acc.IsActive() {
		t.Error("new account must be active")
	}
}

func TestNewAccount_RecordsAccountRegisteredEvent(t *testing.T) {
	email, _ := NewEmail("a@b.com")
	cred, _ := NewCredential("hash", "argon2id", 1)
	id, _ := NewAccountID("11111111-1111-1111-1111-111111111111")

	acc, err := NewAccount(id, email, cred)
	if err != nil {
		t.Fatalf("NewAccount() error = %v, want nil", err)
	}

	events := acc.RecordedEvents()
	if len(events) != 1 {
		t.Fatalf("RecordedEvents() = %d events, want 1", len(events))
	}
	registered, ok := events[0].(AccountRegistered)
	if !ok {
		t.Fatalf("RecordedEvents()[0] = %T, want AccountRegistered", events[0])
	}
	if registered.AccountID != id {
		t.Errorf("AccountRegistered.AccountID = %v, want %v", registered.AccountID, id)
	}
}

func newTestAccount(t *testing.T) *Account {
	t.Helper()
	email, _ := NewEmail("a@b.com")
	cred, _ := NewCredential("hash", "argon2id", 1)
	id, _ := NewAccountID("11111111-1111-1111-1111-111111111111")

	acc, err := NewAccount(id, email, cred)
	if err != nil {
		t.Fatalf("NewAccount() error = %v, want nil", err)
	}
	return acc
}

func TestAccount_DisableAndActivate(t *testing.T) {
	acc := newTestAccount(t)

	acc.Disable()
	if acc.Status() != StatusDisabled || acc.IsActive() {
		t.Error("Disable() must set status to StatusDisabled")
	}

	acc.Activate()
	if acc.Status() != StatusActive || !acc.IsActive() {
		t.Error("Activate() must set status back to StatusActive")
	}
}

func TestAccount_EnsureActive(t *testing.T) {
	acc := newTestAccount(t)

	if err := acc.EnsureActive(); err != nil {
		t.Errorf("EnsureActive() on a new account = %v, want nil", err)
	}

	acc.Disable()
	if err := acc.EnsureActive(); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("EnsureActive() on a disabled account = %v, want ErrAccountDisabled", err)
	}
}
