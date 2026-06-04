package ratelimit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	defaultBucketTTL = time.Hour
)

type Middleware struct {
	store    storage.Store
	scores   *trust.ScoreManager
	rate     float64
	capacity float64
	now      func() time.Time
}

func New(store storage.Store, scores *trust.ScoreManager, cfg config.Config) (*Middleware, error) {
	return &Middleware{
		store:    store,
		scores:   scores,
		rate:     cfg.RateLimit.RequestsPerSecond,
		capacity: float64(cfg.RateLimit.Burst),
		now:      time.Now,
	}, nil
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		now := m.now()
		ip := cloudflare.RealIP(r)
		ipHash := trust.HashIP(ip)
		bucket := m.loadBucket(ipHash, now)
		allowed, retryAfter := bucket.TryConsume(now)
		m.store.SetBucket(ipHash, toStorageBucket(bucket.Snapshot(now, defaultBucketTTL, ipHash)))

		if !allowed {
			visitor := m.scores.Apply(ip, r.Host, trust.DeltaRateLimit)
			if m.scores.State(visitor.Score) == trust.StateBlocked {
				w.Header().Set("X-WAF-Action", "BLOCK")
				w.Header().Set("X-WAF-Reason", "score_below_block_threshold")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Retry-After", strconv.Itoa(maxInt(1, int(retryAfter.Seconds()))))
			w.Header().Set("X-WAF-Action", "RATE_LIMIT")
			w.Header().Set("X-WAF-Reason", "rate_limit_exceeded")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) loadBucket(ipHash string, now time.Time) *TokenBucket {
	if existing, ok := m.store.GetBucket(ipHash); ok {
		return BucketFromSnapshot(BucketSnapshot{
			IPHash:     existing.IPHash,
			Tokens:     existing.Tokens,
			LastRefill: existing.LastRefill,
			Rate:       existing.Rate,
			Capacity:   existing.Capacity,
			ExpiresAt:  existing.ExpiresAt,
		})
	}

	return NewTokenBucket(m.rate, m.capacity, now)
}

func toStorageBucket(snapshot BucketSnapshot) storage.RateBucket {
	return storage.RateBucket{
		IPHash:     snapshot.IPHash,
		Tokens:     snapshot.Tokens,
		LastRefill: snapshot.LastRefill,
		Rate:       snapshot.Rate,
		Capacity:   snapshot.Capacity,
		ExpiresAt:  snapshot.ExpiresAt,
	}
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
