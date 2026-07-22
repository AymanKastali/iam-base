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

func writeKeyFile(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func TestLoadRSAPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	path := writeKeyFile(t, "key.pem", pemBytes)

	got, err := LoadRSAPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadRSAPrivateKey() error = %v, want nil", err)
	}
	if !got.Equal(key) {
		t.Error("LoadRSAPrivateKey() returned a key that doesn't match the one written")
	}
}

func TestLoadRSAPrivateKey_InvalidPEM(t *testing.T) {
	path := writeKeyFile(t, "bad.pem", []byte("not a pem file"))

	if _, err := LoadRSAPrivateKey(path); err == nil {
		t.Error("LoadRSAPrivateKey() error = nil, want error for invalid PEM")
	}
}

func TestLoadRSAPrivateKey_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")

	if _, err := LoadRSAPrivateKey(missing); err == nil {
		t.Error("LoadRSAPrivateKey() error = nil, want error for a missing file")
	}
}
