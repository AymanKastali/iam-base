package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/AymanKastali/iam-base/internal/identity/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestRSAIssuer_IssueAndVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issuer := NewRSAIssuer(priv, "1", 15*time.Minute, fixedClock{now: now})

	accountID, err := domain.NewAccountID("acc-1")
	if err != nil {
		t.Fatalf("NewAccountID: %v", err)
	}
	token, expiresAt, err := issuer.Issue(context.Background(), accountID)
	if err != nil {
		t.Fatalf("Issue() error = %v, want nil", err)
	}
	if !expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("expiresAt = %v, want %v", expiresAt, now.Add(15*time.Minute))
	}

	parsed, err := jwtlib.Parse(token, func(tok *jwtlib.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}), jwtlib.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsed.Valid {
		t.Fatalf("Parse() error = %v, valid = %v", err, parsed.Valid)
	}
	claims := parsed.Claims.(jwtlib.MapClaims)
	if claims["sub"] != "acc-1" {
		t.Errorf("sub claim = %v, want acc-1", claims["sub"])
	}
}

func TestRSAIssuer_JWKS(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := NewRSAIssuer(priv, "1", 15*time.Minute, fixedClock{now: time.Now()})

	doc := issuer.JWKS()
	if len(doc.Keys) != 1 {
		t.Fatalf("JWKS().Keys = %d keys, want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Kid != "1" || k.N == "" || k.E == "" {
		t.Errorf("JWKS key = %+v, want RSA/RS256/1 with non-empty n, e", k)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.Cmp(priv.N) != 0 {
		t.Error("JWKS n does not match the issuer's actual public key modulus")
	}
	if e.Int64() != int64(priv.E) {
		t.Errorf("JWKS e = %v, want %v", e.Int64(), priv.E)
	}
}
