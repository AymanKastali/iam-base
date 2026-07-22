package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/AymanKastali/iam-base/internal/app"
	"github.com/AymanKastali/iam-base/internal/app/query"
	"github.com/AymanKastali/iam-base/internal/domain"
)

type RSAIssuer struct {
	privateKey *rsa.PrivateKey
	keyID      string
	ttl        time.Duration
	clock      app.Clock
}

func NewRSAIssuer(privateKey *rsa.PrivateKey, keyID string, ttl time.Duration, clock app.Clock) *RSAIssuer {
	return &RSAIssuer{privateKey: privateKey, keyID: keyID, ttl: ttl, clock: clock}
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
	token.Header["kid"] = i.keyID

	signed, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (i *RSAIssuer) JWKS() query.JWKSDocument {
	pub := i.privateKey.PublicKey
	return query.JWKSDocument{
		Keys: []query.JWKSKey{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: i.keyID,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
