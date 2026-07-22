package passwordhash

import "testing"

func TestArgon2IDHasher_HashAndVerify(t *testing.T) {
	h := Argon2IDHasher{}

	cred, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}
	if cred.Alg() != "argon2id" {
		t.Errorf("Alg() = %q, want argon2id", cred.Alg())
	}

	ok, err := h.Verify(cred, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("Verify() = %v, %v, want true, nil", ok, err)
	}

	ok, err = h.Verify(cred, "wrong password")
	if err != nil || ok {
		t.Fatalf("Verify() with wrong password = %v, %v, want false, nil", ok, err)
	}
}
