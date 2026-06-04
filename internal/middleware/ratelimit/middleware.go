package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
)

const (
	defaultBucketTTL = time.Hour
	rateLimitDelta   = -10
)

type Middleware struct {
	store        storage.Store
	rate         float64
	capacity     float64
	initialScore int
	scoreTTL     time.Duration
	now          func() time.Time
}

func New(store storage.Store, cfg config.Config) (*Middleware, error) {
	scoreTTL, err := time.ParseDuration(cfg.Trust.ScoreTTL)
	if err != nil {
		return nil, err
	}

	return &Middleware{
		store:        store,
		rate:         cfg.RateLimit.RequestsPerSecond,
		capacity:     float64(cfg.RateLimit.Burst),
		initialScore: cfg.Trust.InitialScore,
		scoreTTL:     scoreTTL,
		now:          time.Now,
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
		ipHash := hashIP(ip)
		bucket := m.loadBucket(ipHash, now)
		allowed, retryAfter := bucket.TryConsume(now)
		m.store.SetBucket(ipHash, toStorageBucket(bucket.Snapshot(now, defaultBucketTTL, ipHash)))

		if !allowed {
			m.applyScoreDelta(ipHash, r.Host, now)
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

func (m *Middleware) applyScoreDelta(ipHash string, domain string, now time.Time) {
	visitor, ok := m.store.GetVisitor(ipHash)
	if !ok {
		visitor = &storage.VisitorState{
			IPHash:    ipHash,
			Domain:    domain,
			Score:     m.initialScore,
			FirstSeen: now,
		}
	}
	visitor.Score = clamp(visitor.Score+rateLimitDelta, 0, 100)
	visitor.LastSeen = now
	visitor.ExpiresAt = now.Add(m.scoreTTL)
	visitor.ViolationCount++
	m.store.SetVisitor(ipHash, *visitor)
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

func hashIP(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])[:16]
}

func clamp(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
