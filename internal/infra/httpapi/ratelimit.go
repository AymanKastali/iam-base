package httpapi

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
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

// Allow reports whether a request from remoteAddr (an "ip:port" string, as
// found on http.Request.RemoteAddr and huma.Context.RemoteAddr()) may
// proceed.
func (l *IPRateLimiter) Allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return l.limiterFor(host).Allow()
}

// HumaMiddleware adapts Allow into a Huma operation middleware, writing a 429
// via the shared RFC 9457 error format (huma.WriteErr) when the caller's IP
// has exceeded its budget.
func (l *IPRateLimiter) HumaMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if !l.Allow(ctx.RemoteAddr()) {
			_ = huma.WriteErr(api, ctx, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(ctx)
	}
}
