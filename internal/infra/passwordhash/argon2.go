// Package passwordhash provides the argon2id adapter for app.PasswordHasher.
package passwordhash

import (
	"github.com/alexedwards/argon2id"

	"github.com/AymanKastali/iam-base/internal/domain"
)

const algName = "argon2id"
const credentialVersion = 1

type Argon2IDHasher struct{}

func (Argon2IDHasher) Hash(password string) (domain.Credential, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return domain.Credential{}, err
	}
	return domain.NewCredential(hash, algName, credentialVersion)
}

func (Argon2IDHasher) Verify(credential domain.Credential, password string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, credential.Hash())
}
