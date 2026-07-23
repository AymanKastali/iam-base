package httpapi

import "net/http"

// HealthzHandler reports liveness for container/orchestrator health checks:
// a 200 means the process can serve a request at all, not that its database
// connection is healthy. It is intentionally not a Huma operation — no
// schema, no rate limiting, and it stays out of the public OpenAPI surface.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
