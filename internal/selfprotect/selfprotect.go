// Package selfprotect protège les endpoints sensibles du WAF lui-même (FR-30) :
// flood de POST /waf/verify et brute-force sur l'API d'administration. Il repose
// sur un compteur par IP à fenêtre fixe.
package selfprotect

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/ipkey"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/ttlcache"
	"github.com/gaetandev/waf/internal/wafheader"
)

// maxTrackedIPs borne le nombre d'IP comptées simultanément. Il faudrait
// autant d'IP distinctes dans une même fenêtre pour évincer un compteur actif.
const maxTrackedIPs = 100000

// Window compte les occurrences par IP sur une fenêtre fixe.
//
// Les compteurs vivent dans un cache borné et expirent avec leur fenêtre. Une
// map nue les portait auparavant : chaque IP ayant touché /waf/verify (ou
// échoué une fois sur l'API admin) y restait pour toujours.
type Window struct {
	max    int
	window time.Duration
	counts *ttlcache.Cache[string, counter]
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
	w := &Window{max: max, window: window, now: time.Now}
	w.counts = ttlcache.New[string, counter](maxTrackedIPs, window).WithClock(func() time.Time { return w.now() })
	return w
}

// Record incrémente le compteur de l'IP (réinitialisé si la fenêtre est écoulée)
// et retourne le compte courant.
func (w *Window) Record(ip string) int {
	now := w.now()
	return w.counts.Update(ip, func(c counter, found bool) counter {
		if !found || now.After(c.resetAt) {
			c = counter{resetAt: now.Add(w.window)}
		}
		c.count++
		return c
	}).count
}

// Count retourne le compte courant de l'IP (0 si fenêtre écoulée).
func (w *Window) Count(ip string) int {
	c, ok := w.counts.Get(ip)
	if !ok || w.now().After(c.resetAt) {
		return 0
	}
	return c.count
}

// RetryAfter rend le délai, en secondes entières arrondies au-dessus (au moins
// 1), avant la réinitialisation du compteur de l'IP.
func (w *Window) RetryAfter(ip string) int {
	c, ok := w.counts.Get(ip)
	if !ok {
		return 1
	}
	remaining := c.resetAt.Sub(w.now())
	return max(1, int((remaining+time.Second-1)/time.Second))
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
				// Compté par client : une IPv6 par son /64 (ipkey).
				ip := ipkey.Subject(cloudflare.RealIP(r))
				if window.Record(ip) > window.max {
					w.Header().Set("Retry-After", strconv.Itoa(window.RetryAfter(ip)))
					w.Header().Set(wafheader.Action, wafheader.ActionRateLimit)
					w.Header().Set(wafheader.Reason, "self_protect_flood")
					http.Error(w, "too many requests", http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
