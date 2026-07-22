package httpapi

import (
	"testing"
	"time"
)

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
