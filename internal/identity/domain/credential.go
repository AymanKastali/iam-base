package domain

type Credential struct {
	hash    string
	alg     string
	version int
}

func NewCredential(hash, alg string, version int) (Credential, error) {
	if err := validateCredentialHash(hash); err != nil {
		return Credential{}, err
	}
	if err := validateCredentialAlg(alg); err != nil {
		return Credential{}, err
	}
	if err := validateCredentialVersion(version); err != nil {
		return Credential{}, err
	}
	return Credential{hash: hash, alg: alg, version: version}, nil
}

func (c Credential) Hash() string  { return c.hash }
func (c Credential) Algo() string  { return c.alg }
func (c Credential) Version() int  { return c.version }

// validateCredentialHash checks that hash is not empty.
func validateCredentialHash(hash string) error {
	if hash == "" {
		return ErrInvalidCredential
	}
	return nil
}

// validateCredentialAlg checks that alg is not empty.
func validateCredentialAlg(alg string) error {
	if alg == "" {
		return ErrInvalidCredential
	}
	return nil
}

// validateCredentialVersion checks that version is at least 1.
func validateCredentialVersion(version int) error {
	if version < 1 {
		return ErrInvalidCredential
	}
	return nil
}
