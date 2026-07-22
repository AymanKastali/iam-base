package httpapi

import (
	"context"
	"testing"

	"github.com/AymanKastali/iam-base/internal/app/query"
)

type stubJWKSPort struct{ doc query.JWKSDocument }

func (s stubJWKSPort) JWKS() query.JWKSDocument { return s.doc }

func TestJWKSHandler_Handle(t *testing.T) {
	doc := query.JWKSDocument{Keys: []query.JWKSKey{{Kty: "RSA", Kid: "1", Alg: "RS256", Use: "sig", N: "n", E: "e"}}}
	h := JWKSHandler{Handler: query.GetJWKSHandler{Port: stubJWKSPort{doc: doc}}}

	out, err := h.Handle(context.Background(), &JWKSInput{})

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	if len(out.Body.Keys) != 1 || out.Body.Keys[0].Kid != "1" {
		t.Errorf("Body = %+v, want the JWKS document unchanged", out.Body)
	}
}
