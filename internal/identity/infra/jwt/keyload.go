package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadRSAPrivateKey reads a PKCS1 PEM-encoded RSA private key from path.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
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
