package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeKeyFile(t *testing.T, dir, name string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

func encodeKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestLoadRSAPrivateKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	dir := t.TempDir()
	writeKeyFile(t, dir, "1.pem", encodeKey(key1))
	writeKeyFile(t, dir, "2.pem", encodeKey(key2))
	writeKeyFile(t, dir, "ignored.txt", []byte("not a key"))

	keys, err := LoadRSAPrivateKeys(dir)
	if err != nil {
		t.Fatalf("LoadRSAPrivateKeys() error = %v, want nil", err)
	}
	if len(keys) != 2 {
		t.Fatalf("LoadRSAPrivateKeys() returned %d keys, want 2", len(keys))
	}
	if got, ok := keys["1"]; !ok || !got.Equal(key1) {
		t.Error(`LoadRSAPrivateKeys()["1"] does not match key1`)
	}
	if got, ok := keys["2"]; !ok || !got.Equal(key2) {
		t.Error(`LoadRSAPrivateKeys()["2"] does not match key2`)
	}
}

func TestLoadRSAPrivateKeys_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	writeKeyFile(t, dir, "bad.pem", []byte("not a pem file"))

	if _, err := LoadRSAPrivateKeys(dir); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error for invalid PEM")
	}
}

func TestLoadRSAPrivateKeys_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	if _, err := LoadRSAPrivateKeys(missing); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error for a missing directory")
	}
}

func TestLoadRSAPrivateKeys_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadRSAPrivateKeys(dir); err == nil {
		t.Error("LoadRSAPrivateKeys() error = nil, want error when no *.pem files are present")
	}
}
