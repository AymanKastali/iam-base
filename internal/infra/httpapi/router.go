package httpapi

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// maxRequestBodyBytes caps request bodies on public, unauthenticated
// endpoints so a large or slow-drip body can't exhaust server memory.
const maxRequestBodyBytes = 1 << 16 // 64KB

func NewRouter(register RegisterHandler, login LoginHandler, refresh RefreshHandler, logout LogoutHandler, jwks JWKSHandler, limiter *IPRateLimiter) http.Handler {
	mux := chi.NewMux()

	config := huma.DefaultConfig("iam-base", "1.0.0")
	config.CreateHooks = nil // keep success response bodies free of Huma's injected "$schema" field
	api := humachi.New(mux, config)

	rateLimited := huma.Middlewares{limiter.HumaMiddleware(api)}

	huma.Register(api, huma.Operation{
		OperationID:   "register",
		Method:        http.MethodPost,
		Path:          "/v1/auth/register",
		Summary:       "Register a new account",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxRequestBodyBytes,
		Errors:        []int{http.StatusConflict, http.StatusUnprocessableEntity},
		Middlewares:   rateLimited,
	}, register.Handle)

	huma.Register(api, huma.Operation{
		OperationID:  "login",
		Method:       http.MethodPost,
		Path:         "/v1/auth/login",
		Summary:      "Exchange credentials for an access and refresh token",
		Tags:         []string{"Auth"},
		MaxBodyBytes: maxRequestBodyBytes,
		Errors:       []int{http.StatusUnauthorized},
		Middlewares:  rateLimited,
	}, login.Handle)

	huma.Register(api, huma.Operation{
		OperationID:  "refresh",
		Method:       http.MethodPost,
		Path:         "/v1/auth/refresh",
		Summary:      "Rotate a refresh token for a new access/refresh token pair",
		Tags:         []string{"Auth"},
		MaxBodyBytes: maxRequestBodyBytes,
		Errors:       []int{http.StatusUnauthorized},
		Middlewares:  rateLimited,
	}, refresh.Handle)

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodPost,
		Path:          "/v1/auth/logout",
		Summary:       "Revoke a refresh token session",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusNoContent,
		MaxBodyBytes:  maxRequestBodyBytes,
		Middlewares:   rateLimited,
	}, logout.Handle)

	huma.Register(api, huma.Operation{
		OperationID: "get-jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "Fetch the JSON Web Key Set used to verify access tokens",
		Tags:        []string{"Auth"},
	}, jwks.Handle)

	return mux
}
