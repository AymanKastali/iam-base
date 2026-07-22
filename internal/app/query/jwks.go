package query

import "context"

type JWKSKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSDocument struct {
	Keys []JWKSKey `json:"keys"`
}

type JWKSPort interface {
	JWKS() JWKSDocument
}

type GetJWKSHandler struct {
	Port JWKSPort
}

func (h GetJWKSHandler) Handle(ctx context.Context) (JWKSDocument, error) {
	return h.Port.JWKS(), nil
}
