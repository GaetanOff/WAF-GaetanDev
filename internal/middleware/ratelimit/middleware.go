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

	headerGlobalPressure = "X-WAF-Global-Pressure"

	pressureNormal   = "normal"
	pressureElevated = "elevated"
	pressureHigh     = "high"
	pressureCritical = "critical"
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

		// FR-08 v2 : sous pression globale anti-DDoS, le débit autorisé des
		// visiteurs non dignes de confiance est resserré (mitigation réversible,
		// THROTTLE). Les visiteurs TRUSTED (challenge réussi, navigation stable)
		// conservent leur débit nominal. La pression normale n'a aucun effet.
		effectiveRate, effectiveCapacity := m.rate, m.capacity
		if factor := m.pressureFactor(r, ip); factor < 1 {
			effectiveRate *= factor
			effectiveCapacity *= factor
		}

		bucket := m.loadBucket(ipHash, effectiveRate, effectiveCapacity, now)
		allowed, retryAfter := bucket.TryConsume(now)
		snapshot := bucket.Snapshot(now, defaultBucketTTL, ipHash)
		snapshot.ExpiresAt = time.Now().Add(defaultBucketTTL)
		m.store.SetBucket(ipHash, toStorageBucket(snapshot))

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

		// Requête autorisée : publie une contribution `rate` proportionnelle à la
		// déplétion du bucket (pression de débit) pour le moteur de risque. Le 429
		// volumétrique ci-dessus reste indépendant (cf. Articulation FR-35).
		if contribution := rateContribution(snapshot.Tokens, effectiveCapacity); contribution > 0 {
			r.Header.Set("X-WAF-Risk-rate", strconv.Itoa(maxInt(contribution, existingRateContribution(r))))
		}

		next.ServeHTTP(w, r)
	})
}

// loadBucket reconstruit le token bucket avec le débit/capacité EFFECTIFS du
// moment (recalculés à chaque requête depuis la config × le facteur de pression),
// jamais depuis les valeurs persistées. Seuls les jetons et l'instant de refill
// sont repris du store : ainsi un resserrement sous pression est réversible dès
// que la pression retombe, sans figer un débit réduit dans le stockage.
func (m *Middleware) loadBucket(ipHash string, rate float64, capacity float64, now time.Time) *TokenBucket {
	if existing, ok := m.store.GetBucket(ipHash); ok {
		tokens := existing.Tokens
		if tokens > capacity {
			// La capacité effective a baissé (pression) : on rogne les jetons
			// accumulés au plafond courant — c'est la mitigation immédiate.
			tokens = capacity
		}
		return BucketFromSnapshot(BucketSnapshot{
			IPHash:     existing.IPHash,
			Tokens:     tokens,
			LastRefill: existing.LastRefill,
			Rate:       rate,
			Capacity:   capacity,
			ExpiresAt:  existing.ExpiresAt,
		})
	}

	return NewTokenBucket(rate, capacity, now)
}

// pressureFactor retourne le multiplicateur appliqué au débit/capacité du bucket
// selon la pression globale courante. Retourne 1 (aucun effet) quand la pression
// est normale/absente ou que le visiteur est digne de confiance (TRUSTED).
func (m *Middleware) pressureFactor(r *http.Request, ip string) float64 {
	level := r.Header.Get(headerGlobalPressure)
	if level == "" || level == pressureNormal {
		return 1
	}
	if m.isTrusted(ip, r.Host) {
		return 1
	}
	switch level {
	case pressureCritical:
		return 0.25
	case pressureHigh:
		return 0.5
	case pressureElevated:
		return 0.8
	default:
		return 1
	}
}

// isTrusted indique si le visiteur a prouvé sa fiabilité (challenge réussi ou
// navigation stable) et doit être épargné par le resserrement de pression.
func (m *Middleware) isTrusted(ip string, host string) bool {
	visitor := m.scores.Get(ip, host)
	return m.scores.State(visitor.Score) == trust.StateTrusted
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

func existingRateContribution(r *http.Request) int {
	value, err := strconv.Atoi(r.Header.Get("X-WAF-Risk-rate"))
	if err != nil {
		return 0
	}
	return value
}

// rateContribution mappe la déplétion du bucket (0 = plein, 1 = vide) vers une
// contribution de risque [0..100] pour la famille `rate`.
func rateContribution(tokens float64, capacity float64) int {
	if capacity <= 0 {
		return 0
	}
	depletion := 1 - tokens/capacity
	contribution := int(depletion * 100)
	if contribution < 0 {
		return 0
	}
	if contribution > 100 {
		return 100
	}
	return contribution
}
