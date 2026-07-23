package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadRSAPrivateKeys reads every "*.pem" file in dir into a kid -> key map,
// where kid is the filename without its extension (e.g. "1.pem" -> "1").
// Loading more than one key lets RSAIssuer publish a retired key in JWKS
// long enough for tokens signed under it to finish expiring after rotation.
func LoadRSAPrivateKeys(dir string) (map[string]*rsa.PrivateKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PrivateKey)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		kid := strings.TrimSuffix(entry.Name(), ".pem")
		key, err := loadRSAPrivateKey(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("load key %q: %w", entry.Name(), err)
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no *.pem key files found in %q", dir)
	}
	return keys, nil
}

// loadRSAPrivateKey reads a single PKCS1 PEM-encoded RSA private key from path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM in JWT private key file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
