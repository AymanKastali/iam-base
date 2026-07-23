package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type RSAIssuer struct {
	keys        map[string]*rsa.PrivateKey
	activeKeyID string
	ttl         time.Duration
	clock       app.Clock
}

// NewRSAIssuer builds an issuer that signs new tokens with keys[activeKeyID]
// and publishes every key in keys via JWKS, so tokens signed under a
// since-retired key still verify until that key is removed from keys.
func NewRSAIssuer(keys map[string]*rsa.PrivateKey, activeKeyID string, ttl time.Duration, clock app.Clock) (*RSAIssuer, error) {
	if _, ok := keys[activeKeyID]; !ok {
		return nil, fmt.Errorf("active key id %q not found among loaded keys", activeKeyID)
	}
	return &RSAIssuer{keys: keys, activeKeyID: activeKeyID, ttl: ttl, clock: clock}, nil
}

func (i *RSAIssuer) Issue(ctx context.Context, accountID domain.AccountID) (string, time.Time, error) {
	now := i.clock.Now()
	expiresAt := now.Add(i.ttl)

	claims := jwtlib.MapClaims{
		"sub": accountID.String(),
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = i.activeKeyID

	signed, err := token.SignedString(i.keys[i.activeKeyID])
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (i *RSAIssuer) JWKS() query.JWKSDocument {
	doc := query.JWKSDocument{Keys: make([]query.JWKSKey, 0, len(i.keys))}
	for kid, key := range i.keys {
		pub := key.PublicKey
		doc.Keys = append(doc.Keys, query.JWKSKey{
			Kty: "RSA",
			Use: "sig",
			Kid: kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return doc
}
