// Package slowloris atténue les attaques Slowloris / Slow POST (FR-23) en
// bornant le nombre de requêtes concurrentes par IP. Les timeouts d'en-têtes et
// de lecture du corps sont appliqués au niveau du http.Server (configurables).
package slowloris

import (
	"net/http"
	"sync"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

// Limiter borne le nombre de requêtes simultanées par IP client.
type Limiter struct {
	max    int
	mu     sync.Mutex
	counts map[string]int
}

func New(maxPerIP int) *Limiter {
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	return &Limiter{max: maxPerIP, counts: make(map[string]int)}
}

func (l *Limiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := cloudflare.RealIP(r)
		if !l.acquire(ip) {
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-WAF-Reason", "too_many_connections")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		defer l.release(ip)
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] >= l.max {
		return false
	}
	l.counts[ip]++
	return true
}

func (l *Limiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] <= 1 {
		delete(l.counts, ip)
		return
	}
	l.counts[ip]--
}
