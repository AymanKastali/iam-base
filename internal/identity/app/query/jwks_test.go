package query

import (
	"context"
	"testing"
)

type fakeJWKSPort struct{ doc JWKSDocument }

func (f fakeJWKSPort) JWKS() JWKSDocument { return f.doc }

func TestGetJWKSHandler_Handle(t *testing.T) {
	want := JWKSDocument{Keys: []JWKSKey{{Kty: "RSA", Use: "sig", Kid: "1", Alg: "RS256", N: "n", E: "e"}}}
	h := GetJWKSHandler{Port: fakeJWKSPort{doc: want}}

	got, err := h.Handle(context.Background())
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].Kid != "1" {
		t.Errorf("Handle() = %+v, want %+v", got, want)
	}
}
