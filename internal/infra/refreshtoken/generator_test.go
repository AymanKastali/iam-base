// internal/infra/refreshtoken/generator_test.go
package refreshtoken

import "testing"

func TestSHA256Generator_Generate(t *testing.T) {
	gen := SHA256Generator{}

	raw, hash, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	if raw == "" || hash == "" {
		t.Fatalf("Generate() = (%q, %q), want two non-empty strings", raw, hash)
	}
	if raw == hash {
		t.Error("Generate() raw secret and its hash must differ")
	}
	if got := gen.Hash(raw); got != hash {
		t.Errorf("Hash(raw) = %q, want %q (must match the hash Generate() returned for the same raw)", got, hash)
	}
}

func TestSHA256Generator_Generate_ProducesDistinctSecrets(t *testing.T) {
	gen := SHA256Generator{}

	raw1, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	raw2, _, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}
	if raw1 == raw2 {
		t.Error("Generate() produced the same secret twice — not using enough randomness")
	}
}

func TestSHA256Generator_Hash_Deterministic(t *testing.T) {
	gen := SHA256Generator{}

	first := gen.Hash("same-input")
	second := gen.Hash("same-input")
	if first != second {
		t.Error("Hash() must be deterministic for the same input")
	}
	if gen.Hash("a") == gen.Hash("b") {
		t.Error("Hash() must differ for different inputs")
	}
}
