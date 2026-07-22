package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiter_Middleware(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1) // 1 request burst, refills slowly
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(next)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:5555"

	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rec2.Code)
	}
}

func TestIPRateLimiter_Middleware_IsolatesByIP(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(next)

	reqA := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	reqA.RemoteAddr = "1.2.3.4:5555"
	reqB := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	reqB.RemoteAddr = "5.6.7.8:9999"

	recA1 := httptest.NewRecorder()
	handler.ServeHTTP(recA1, reqA)
	if recA1.Code != http.StatusOK {
		t.Fatalf("IP A first request status = %d, want 200", recA1.Code)
	}

	recA2 := httptest.NewRecorder()
	handler.ServeHTTP(recA2, reqA)
	if recA2.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A second request status = %d, want 429", recA2.Code)
	}

	recB1 := httptest.NewRecorder()
	handler.ServeHTTP(recB1, reqB)
	if recB1.Code != http.StatusOK {
		t.Fatalf("IP B first request status = %d, want 200 — must not be throttled by IP A's limiter", recB1.Code)
	}
}

func TestIPRateLimiter_Allow(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1) // 1 request burst, refills slowly

	if !limiter.Allow("1.2.3.4:5555") {
		t.Fatal("first Allow() = false, want true")
	}
	if limiter.Allow("1.2.3.4:5555") {
		t.Fatal("second Allow() = true, want false (burst exhausted)")
	}
}

func TestIPRateLimiter_Allow_IsolatesByIP(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)

	if !limiter.Allow("1.2.3.4:5555") {
		t.Fatal("IP A first Allow() = false, want true")
	}
	if limiter.Allow("1.2.3.4:5555") {
		t.Fatal("IP A second Allow() = true, want false")
	}
	if !limiter.Allow("5.6.7.8:9999") {
		t.Fatal("IP B first Allow() = false, want true — must not be throttled by IP A's limiter")
	}
}

func TestIPRateLimiter_Allow_HandlesAddrWithoutPort(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)

	if !limiter.Allow("not-a-host-port") {
		t.Fatal("first Allow() = false, want true")
	}
	if limiter.Allow("not-a-host-port") {
		t.Fatal("second Allow() = true, want false")
	}
}

func TestIPRateLimiter_EvictStale(t *testing.T) {
	limiter := NewIPRateLimiter(1, 1)
	limiter.limiterFor("1.2.3.4")
	limiter.limiterFor("5.6.7.8")

	now := time.Now()
	limiter.mu.Lock()
	limiter.limiters["1.2.3.4"].lastSeen = now.Add(-2 * staleEntryTTL)
	limiter.mu.Unlock()

	limiter.evictStale(now)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, ok := limiter.limiters["1.2.3.4"]; ok {
		t.Error("evictStale() did not remove the stale entry for 1.2.3.4")
	}
	if _, ok := limiter.limiters["5.6.7.8"]; !ok {
		t.Error("evictStale() incorrectly removed the fresh entry for 5.6.7.8")
	}
}
