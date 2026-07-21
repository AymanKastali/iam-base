package domain

import "testing"

func TestNewCredential(t *testing.T) {
	c, err := NewCredential("hash", "argon2id", 1)
	if err != nil {
		t.Fatalf("NewCredential() error = %v, want nil", err)
	}
	if c.Hash() != "hash" || c.Algo() != "argon2id" || c.Version() != 1 {
		t.Errorf("got %+v, want hash=hash algo=argon2id version=1", c)
	}

	if _, err := NewCredential("", "argon2id", 1); err == nil {
		t.Error("NewCredential() with empty hash: error = nil, want error")
	}
	if _, err := NewCredential("hash", "", 1); err == nil {
		t.Error("NewCredential() with empty algo: error = nil, want error")
	}
}
