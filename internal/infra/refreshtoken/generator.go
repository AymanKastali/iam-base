// Package refreshtoken provides the infra adapter for app.RefreshTokenGenerator:
// a high-entropy opaque secret, hashed with SHA-256 for storage. A refresh
// token is a random secret rather than a human password, so it needs no
// salting or slow/adaptive hash — only protection against a leaked DB dump
// yielding directly-usable tokens, which a fast cryptographic hash provides.
package refreshtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const secretBytes = 32

type SHA256Generator struct{}

func (SHA256Generator) Generate() (raw string, hash string, err error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashSecret(raw), nil
}

func (SHA256Generator) Hash(raw string) string {
	return hashSecret(raw)
}

func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
