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

	// Suffixes de clé de stockage des fenêtres supplémentaires (FR-03). La
	// fenêtre seconde garde la clé nue (ipHash) : son état persisté reste
	// compatible avec les déploiements antérieurs à la mise en place des fenêtres.
	minuteKeySuffix = ":m"
	hourKeySuffix   = ":h"

	headerGlobalPressure = "X-WAF-Global-Pressure"

	pressureNormal   = "normal"
	pressureElevated = "elevated"
	pressureHigh     = "high"
	pressureCritical = "critical"

	reasonRateLimitExceeded       = "rate_limit_exceeded"
	reasonRateLimitExceededMinute = "rate_limit_exceeded_minute"
	reasonRateLimitExceededHour   = "rate_limit_exceeded_hour"
	// ReasonPressureThrottle identifie un 429 imputable au seul resserrement de
	// pression globale (FR-08) : la requête aurait été admise au débit nominal.
	// Ces refus sont neutres — ni pénalité de score, ni violation de
	// circuit-breaker (consommé par le middleware anti-DDoS).
	ReasonPressureThrottle = "rate_limit_pressure"
)

// window décrit une fenêtre de limitation (FR-03). Chacune a son propre Token
// Bucket par IP : le débit de recharge vaut la limite divisée par la durée de la
// fenêtre, la capacité vaut la limite elle-même. La fenêtre seconde est la seule
// dont la capacité est découplée du débit (`burst`), parce qu'elle borne la
// rafale ; les fenêtres minute et heure bornent le débit soutenu.
type window struct {
	keySuffix string
	reason    string
	rate      float64
	capacity  float64
	// ttl borne la durée de vie de l'état persisté. Il vaut la durée de la
	// fenêtre : après une inactivité de cette durée, le bucket se serait de
	// toute façon rechargé entièrement — l'expiration et la recharge complète
	// sont alors le même état, et l'entrée cesse d'occuper le store.
	ttl time.Duration
}

type Middleware struct {
	store   storage.Store
	scores  *trust.ScoreManager
	windows []window
	now     func() time.Time
}

func New(store storage.Store, scores *trust.ScoreManager, cfg config.Config) (*Middleware, error) {
	return &Middleware{
		store:   store,
		scores:  scores,
		windows: buildWindows(cfg.RateLimit),
		now:     time.Now,
	}, nil
}

// buildWindows construit les fenêtres actives. Une limite à 0 désactive sa
// fenêtre (FR-03) ; la fenêtre seconde est toujours présente — `rate_limit`
// n'est monté que si `enabled`, et sa validation impose des bornes >= 1.
func buildWindows(cfg config.RateLimit) []window {
	windows := []window{{
		reason:   reasonRateLimitExceeded,
		rate:     cfg.RequestsPerSecond,
		capacity: float64(cfg.Burst),
		ttl:      defaultBucketTTL,
	}}
	if cfg.RequestsPerMinute > 0 {
		windows = append(windows, window{
			keySuffix: minuteKeySuffix,
			reason:    reasonRateLimitExceededMinute,
			rate:      float64(cfg.RequestsPerMinute) / time.Minute.Seconds(),
			capacity:  float64(cfg.RequestsPerMinute),
			ttl:       time.Minute,
		})
	}
	if cfg.RequestsPerHour > 0 {
		windows = append(windows, window{
			keySuffix: hourKeySuffix,
			reason:    reasonRateLimitExceededHour,
			rate:      float64(cfg.RequestsPerHour) / time.Hour.Seconds(),
			capacity:  float64(cfg.RequestsPerHour),
			ttl:       time.Hour,
		})
	}
	return windows
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

		// FR-08 v2.1 : sous pression globale anti-DDoS, seul le DÉBIT DE REFILL
		// des visiteurs non dignes de confiance est resserré — la capacité de
		// burst reste nominale, pour qu'un chargement de page unique (rafale de
		// sous-requêtes) passe toujours : c'est le débit soutenu qui distingue
		// un bot, pas le burst initial. Les visiteurs TRUSTED (challenge réussi,
		// navigation stable) conservent leur débit nominal. Le facteur s'applique
		// aux trois fenêtres : resserrer la seconde en laissant filer l'heure
		// laisserait passer le débit soutenu, précisément ce que la pression
		// cherche à contenir.
		factor := 1.0
		pressured := false
		if f := m.pressureFactor(r, ip); f < 1 {
			factor = f
			pressured = true
		}

		// Les fenêtres sont d'abord RECHARGÉES sans prélèvement : le jeton n'est
		// consommé que si toutes l'autorisent (FR-03).
		windows := m.evaluate(ipHash, factor, now)
		allowed, retryAfter, reason := verdict(windows)
		snapshots := m.settle(windows, allowed, now)

		if !allowed {
			if pressured && m.nominalWouldAllow(windows, now) {
				// 429 imputable au seul throttle de pression : neutre (FR-08).
				// Pas de pénalité de score ni de violation de circuit-breaker,
				// sinon le WAF punit des humains pour les 429 qu'il a lui-même
				// provoqués (boucle de rétroaction auto-infligée).
				w.Header().Set("Retry-After", strconv.Itoa(maxInt(1, int(retryAfter.Seconds()))))
				w.Header().Set("X-WAF-Action", "RATE_LIMIT")
				w.Header().Set("X-WAF-Reason", ReasonPressureThrottle)
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			visitor := m.scores.PenalizeRateLimit(ip, r.Host)
			if m.scores.State(visitor.Score) == trust.StateBlocked {
				w.Header().Set("X-WAF-Action", "BLOCK")
				w.Header().Set("X-WAF-Reason", "score_below_block_threshold")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Retry-After", strconv.Itoa(maxInt(1, int(retryAfter.Seconds()))))
			w.Header().Set("X-WAF-Action", "RATE_LIMIT")
			w.Header().Set("X-WAF-Reason", reason)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}

		// Requête autorisée : publie une contribution `rate` proportionnelle à la
		// déplétion du bucket (pression de débit) pour le moteur de risque. Le 429
		// volumétrique ci-dessus reste indépendant (cf. Articulation FR-35).
		if contribution := rateContribution(snapshots[0].Tokens, windows[0].window.capacity); contribution > 0 {
			r.Header.Set("X-WAF-Risk-rate", strconv.Itoa(maxInt(contribution, existingRateContribution(r))))
		}

		next.ServeHTTP(w, r)
	})
}

// evaluation porte l'état d'une fenêtre pour la requête courante : le bucket
// rechargé, l'état persisté d'où il vient (nécessaire au rejeu nominal) et le
// verdict de la fenêtre.
type evaluation struct {
	window      window
	key         string
	bucket      *TokenBucket
	existing    *storage.RateBucket
	hasExisting bool
	allowed     bool
	retryAfter  time.Duration
}

// evaluate charge et recharge chaque fenêtre active, sans rien prélever ni
// persister.
func (m *Middleware) evaluate(ipHash string, factor float64, now time.Time) []evaluation {
	evaluations := make([]evaluation, 0, len(m.windows))
	for _, w := range m.windows {
		key := ipHash + w.keySuffix
		existing, hasExisting := m.store.GetBucket(key)
		bucket := m.loadBucket(existing, hasExisting, w.rate*factor, w.capacity, now)
		allowed, retryAfter := bucket.Refill(now)
		evaluations = append(evaluations, evaluation{
			window:      w,
			key:         key,
			bucket:      bucket,
			existing:    existing,
			hasExisting: hasExisting,
			allowed:     allowed,
			retryAfter:  retryAfter,
		})
	}
	return evaluations
}

// verdict agrège les fenêtres : la requête passe si toutes l'autorisent, sinon
// c'est la fenêtre au délai de réouverture le plus long qui décide du
// `Retry-After` et de la raison journalisée — annoncer le délai d'une fenêtre
// plus courte inviterait le client à réessayer pour rien.
func verdict(evaluations []evaluation) (bool, time.Duration, string) {
	allowed := true
	retryAfter := time.Duration(0)
	reason := reasonRateLimitExceeded
	for _, e := range evaluations {
		if e.allowed {
			continue
		}
		allowed = false
		if e.retryAfter >= retryAfter {
			retryAfter = e.retryAfter
			reason = e.window.reason
		}
	}
	return allowed, retryAfter, reason
}

// settle prélève le jeton de chaque fenêtre quand la requête est admise, puis
// persiste l'état des fenêtres. Sur refus, seule la RECHARGE est persistée :
// l'horodatage doit avancer, mais aucun jeton n'est prélevé — ni dans la fenêtre
// qui refuse, ni dans les autres (FR-03). Sans cette séparation, un client buté
// sur sa limite horaire verrait aussi son burst à la seconde vidé, et
// repartirait avec un bucket vide à la réouverture de la fenêtre.
func (m *Middleware) settle(evaluations []evaluation, allowed bool, now time.Time) []BucketSnapshot {
	snapshots := make([]BucketSnapshot, 0, len(evaluations))
	for _, e := range evaluations {
		if allowed {
			e.bucket.Consume()
		}
		snapshot := e.bucket.Snapshot(now, e.window.ttl, e.key)
		// L'échéance est posée sur l'horloge réelle : c'est celle que le store
		// interroge pour expirer l'entrée, même quand le middleware tourne sur
		// une horloge injectée (tests).
		snapshot.ExpiresAt = time.Now().Add(e.window.ttl)
		m.store.SetBucket(e.key, toStorageBucket(snapshot))
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// loadBucket reconstruit le token bucket avec le débit de refill EFFECTIF du
// moment (recalculé à chaque requête depuis la config × le facteur de pression),
// jamais depuis les valeurs persistées. Seuls les jetons et l'instant de refill
// sont repris du store : ainsi un resserrement sous pression est réversible dès
// que la pression retombe, sans figer un débit réduit dans le stockage.
func (m *Middleware) loadBucket(existing *storage.RateBucket, hasExisting bool, rate float64, capacity float64, now time.Time) *TokenBucket {
	if hasExisting {
		tokens := existing.Tokens
		if tokens > capacity {
			// La capacité configurée a baissé depuis la persistance : rogne les
			// jetons accumulés au plafond courant.
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

// nominalWouldAllow rejoue la requête refusée sur le bucket persisté avec le
// débit de refill NOMINAL (sans facteur de pression), sans rien persister. Si
// elle aurait été admise, le 429 courant est imputable au seul resserrement de
// pression et doit rester neutre (FR-08). Approximation assumée : seul le
// dernier intervalle de refill est rejoué au débit nominal ; un abuseur soutenu
// reste largement au-dessus du nominal et échoue aussi ce rejeu.
func (m *Middleware) nominalWouldAllow(evaluations []evaluation, now time.Time) bool {
	for _, e := range evaluations {
		if e.allowed {
			continue // cette fenêtre passe déjà au débit resserré
		}
		if !e.hasExisting {
			continue // fenêtre neuve : elle part pleine, elle ne peut pas refuser
		}
		tokens := e.existing.Tokens
		if tokens > e.window.capacity {
			tokens = e.window.capacity
		}
		nominal := BucketFromSnapshot(BucketSnapshot{
			IPHash:     e.existing.IPHash,
			Tokens:     tokens,
			LastRefill: e.existing.LastRefill,
			Rate:       e.window.rate,
			Capacity:   e.window.capacity,
			ExpiresAt:  e.existing.ExpiresAt,
		})
		if allowed, _ := nominal.Refill(now); !allowed {
			return false // le refus tient aussi au débit nominal : 429 imputable au client
		}
	}
	return true
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
