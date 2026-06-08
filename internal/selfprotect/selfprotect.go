// Package selfprotect protège les endpoints sensibles du WAF lui-même (FR-30) :
// flood de POST /waf/verify et brute-force sur l'API d'administration. Il repose
// sur un compteur par IP à fenêtre fixe.
package selfprotect

import (
	"net/http"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

// Window compte les occurrences par IP sur une fenêtre glissante simple.
type Window struct {
	max    int
	window time.Duration
	mu     sync.Mutex
	counts map[string]*counter
	now    func() time.Time
}

type counter struct {
	count   int
	resetAt time.Time
}

func NewWindow(max int, window time.Duration) *Window {
	if max < 1 {
		max = 1
	}
	return &Window{max: max, window: window, counts: make(map[string]*counter), now: time.Now}
}

// Record incrémente le compteur de l'IP (réinitialisé si la fenêtre est écoulée)
// et retourne le compte courant.
func (w *Window) Record(ip string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	c, ok := w.counts[ip]
	if !ok || now.After(c.resetAt) {
		c = &counter{resetAt: now.Add(w.window)}
		w.counts[ip] = c
	}
	c.count++
	return c.count
}

// Count retourne le compte courant de l'IP (0 si fenêtre écoulée).
func (w *Window) Count(ip string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	c, ok := w.counts[ip]
	if !ok || w.now().After(c.resetAt) {
		return 0
	}
	return c.count
}

// Limited retourne true si l'IP a atteint la limite.
func (w *Window) Limited(ip string) bool {
	return w.Count(ip) >= w.max
}

// PathGuard limite le débit d'un chemin précis par IP (ex : POST /waf/verify).
func PathGuard(path string, window *Window) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == path {
				ip := cloudflare.RealIP(r)
				if window.Record(ip) > window.max {
					w.Header().Set("Retry-After", "10")
					w.Header().Set("X-WAF-Reason", "self_protect_flood")
					http.Error(w, "too many requests", http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
