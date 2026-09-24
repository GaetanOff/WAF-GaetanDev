// Package slowloris atténue les attaques Slowloris / Slow POST (FR-23) en
// bornant le nombre de requêtes concurrentes par IP. Les timeouts d'en-têtes et
// de lecture du corps sont appliqués au niveau du http.Server (configurables).
package slowloris

import (
	"hash/maphash"
	"net/http"
	"sync"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

// shardCount répartit les compteurs sur autant de verrous. Un verrou unique,
// pris deux fois par requête (entrée et sortie), sérialisait tout le trafic
// sur un serveur multi-cœurs.
const shardCount = 64

// Limiter borne le nombre de requêtes simultanées par IP client.
type Limiter struct {
	max    int
	seed   maphash.Seed
	shards [shardCount]shard
}

type shard struct {
	mu     sync.Mutex
	counts map[string]int
}

func New(maxPerIP int) *Limiter {
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	limiter := &Limiter{max: maxPerIP, seed: maphash.MakeSeed()}
	for i := range limiter.shards {
		limiter.shards[i].counts = make(map[string]int)
	}
	return limiter
}

func (l *Limiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := cloudflare.RealIP(r)
		if !l.acquire(ip) {
			w.Header().Set("Retry-After", "10")
			w.Header().Set("X-WAF-Action", "RATE_LIMIT")
			w.Header().Set("X-WAF-Reason", "too_many_connections_per_ip")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		defer l.release(ip)
		next.ServeHTTP(w, r)
	})
}

// shardFor retourne le shard d'une IP : toutes ses requêtes partagent un même
// compteur, donc la borne par IP reste exacte.
func (l *Limiter) shardFor(ip string) *shard {
	return &l.shards[maphash.String(l.seed, ip)%shardCount]
}

func (l *Limiter) acquire(ip string) bool {
	s := l.shardFor(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts[ip] >= l.max {
		return false
	}
	s.counts[ip]++
	return true
}

func (l *Limiter) release(ip string) {
	s := l.shardFor(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts[ip] <= 1 {
		delete(s.counts, ip)
		return
	}
	s.counts[ip]--
}
