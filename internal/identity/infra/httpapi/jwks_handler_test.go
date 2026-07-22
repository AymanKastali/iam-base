package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AymanKastali/iam-base/internal/identity/app/query"
)

type stubJWKSPort struct{ doc query.JWKSDocument }

func (s stubJWKSPort) JWKS() query.JWKSDocument { return s.doc }

func TestJWKSHandler_ServeHTTP(t *testing.T) {
	doc := query.JWKSDocument{Keys: []query.JWKSKey{{Kty: "RSA", Kid: "1", Alg: "RS256", Use: "sig", N: "n", E: "e"}}}
	h := JWKSHandler{Handler: query.GetJWKSHandler{Port: stubJWKSPort{doc: doc}}}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	_ = context.Background()
}
