package httpapi

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// staleEntryTTL and evictionInterval bound IPRateLimiter's memory: without
// them, a limiter entry is created per distinct source IP and never removed,
// letting an attacker who can mint many source addresses (trivial over IPv6)
// grow the map without limit.
const (
	staleEntryTTL    = 10 * time.Minute
	evictionInterval = time.Minute
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	rps      rate.Limit
	burst    int
}

func NewIPRateLimiter(rps float64, burst int) *IPRateLimiter {
	l := &IPRateLimiter{
		limiters: make(map[string]*limiterEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go l.evictStaleLoop()
	return l
}

func (l *IPRateLimiter) evictStaleLoop() {
	ticker := time.NewTicker(evictionInterval)
	defer ticker.Stop()
	for range ticker.C {
		l.evictStale(time.Now())
	}
}

func (l *IPRateLimiter) evictStale(now time.Time) {
	cutoff := now.Add(-staleEntryTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, ip)
		}
	}
}

func (l *IPRateLimiter) limiterFor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.limiters[ip]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !l.limiterFor(host).Allow() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
