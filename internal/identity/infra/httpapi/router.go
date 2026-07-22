package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter(register, login, jwks http.Handler, limiter *IPRateLimiter) *chi.Mux {
	r := chi.NewRouter()
	r.Method(http.MethodPost, "/v1/auth/register", limiter.Middleware(register))
	r.Method(http.MethodPost, "/v1/auth/login", limiter.Middleware(login))
	r.Method(http.MethodGet, "/.well-known/jwks.json", jwks)
	return r
}
