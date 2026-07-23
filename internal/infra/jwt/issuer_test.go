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

	"github.com/AymanKastali/iam-base/internal/domain"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestRSAIssuer_IssueAndVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "1", 15*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

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

func TestRSAIssuer_JWKS_PublishesActiveKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "1", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

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

func TestRSAIssuer_JWKS_PublishesRetiredKeyAlongsideActive(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": oldKey, "2": newKey}, "2", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	doc := issuer.JWKS()
	if len(doc.Keys) != 2 {
		t.Fatalf("JWKS().Keys = %d keys, want 2", len(doc.Keys))
	}

	kids := map[string]bool{}
	for _, k := range doc.Keys {
		kids[k.Kid] = true
	}
	if !kids["1"] || !kids["2"] {
		t.Errorf("JWKS().Keys kids = %v, want both %q and %q present", kids, "1", "2")
	}
}

func TestRSAIssuer_Issue_AlwaysSignsWithActiveKey(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	activeKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": oldKey, "2": activeKey}, "2", 15*time.Minute, fixedClock{now: time.Now()})
	if err != nil {
		t.Fatalf("NewRSAIssuer() error = %v, want nil", err)
	}

	accountID, _ := domain.NewAccountID("acc-1")
	token, _, err := issuer.Issue(context.Background(), accountID)
	if err != nil {
		t.Fatalf("Issue() error = %v, want nil", err)
	}

	parsed, err := jwtlib.Parse(token, func(tok *jwtlib.Token) (interface{}, error) {
		if tok.Header["kid"] != "2" {
			t.Errorf("token kid = %v, want %q", tok.Header["kid"], "2")
		}
		return &activeKey.PublicKey, nil
	}, jwtlib.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("Parse() error = %v, valid = %v", err, parsed.Valid)
	}
}

func TestNewRSAIssuer_ActiveKeyIDNotFound(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	if _, err := NewRSAIssuer(map[string]*rsa.PrivateKey{"1": priv}, "does-not-exist", 15*time.Minute, fixedClock{now: time.Now()}); err == nil {
		t.Error("NewRSAIssuer() error = nil, want error for an active key id absent from keys")
	}
}
