package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
)

const (
	StateTrusted    = "TRUSTED"
	StateMonitored  = "MONITORED"
	StateChallenged = "CHALLENGED"
	StateBlocked    = "BLOCKED"

	DeltaChallengePassed = 25
	DeltaNavigation      = 1
	DeltaRateLimit       = -10
	DeltaChallengeFailed = -20
	DeltaHoneypot        = -50

	// CriticalScore : sous ce score, un visiteur est « très dangereux » et son
	// score est partagé avec les autres nœuds (FR-20).
	CriticalScore = 5

	// RateLimitPenaltyWindow borne DeltaRateLimit à une application par fenêtre
	// (FR-05) : les sous-requêtes refusées d'un même chargement de page comptent
	// pour UNE pénalité, pas une par 429.
	RateLimitPenaltyWindow = 10 * time.Second
)

type ScoreManager struct {
	store              storage.Store
	initialScore       int
	challengeThreshold atomic.Int64 // modifiable à chaud (SetThresholds)
	blockThreshold     atomic.Int64
	scoreTTL           time.Duration
	onCritical         func(storage.VisitorState)
	now                func() time.Time
}

// WithCriticalObserver est notifié quand un score passe sous CriticalScore
// (propagation cluster, FR-20).
func (m *ScoreManager) WithCriticalObserver(observer func(storage.VisitorState)) {
	m.onCritical = observer
}

func (m *ScoreManager) notifyCritical(before int, visitor storage.VisitorState) {
	if m.onCritical != nil && before >= CriticalScore && visitor.Score < CriticalScore {
		m.onCritical(visitor)
	}
}

func NewScoreManager(store storage.Store, cfg config.Config) (*ScoreManager, error) {
	scoreTTL, err := time.ParseDuration(cfg.Trust.ScoreTTL)
	if err != nil {
		return nil, err
	}

	manager := &ScoreManager{
		store:        store,
		initialScore: cfg.Trust.InitialScore,
		scoreTTL:     scoreTTL,
		now:          time.Now,
	}
	manager.SetThresholds(cfg.Trust.ChallengeThreshold, cfg.Trust.BlockThreshold)
	return manager, nil
}

// SetThresholds applique à chaud les seuils de challenge et de blocage
// (PATCH /waf/admin/config). La cohérence (block < challenge) est validée par
// config.Validate en amont.
func (m *ScoreManager) SetThresholds(challengeThreshold int, blockThreshold int) {
	m.challengeThreshold.Store(int64(challengeThreshold))
	m.blockThreshold.Store(int64(blockThreshold))
}

func (m *ScoreManager) Get(ip string, domain string) storage.VisitorState {
	now := m.now()
	ipHash := HashIP(ip)
	if visitor, ok := m.store.GetVisitor(ipHash); ok {
		if !visitor.ExpiresAt.IsZero() && !visitor.ExpiresAt.After(now) {
			m.store.DeleteVisitor(ipHash)
			return m.create(ipHash, domain, now)
		}
		visitor.LastSeen = now
		visitor.ExpiresAt = now.Add(m.scoreTTL)
		m.store.SetVisitor(ipHash, *visitor)
		return *visitor
	}

	return m.create(ipHash, domain, now)
}

func (m *ScoreManager) create(ipHash string, domain string, now time.Time) storage.VisitorState {
	visitor := storage.VisitorState{
		IPHash:    ipHash,
		Domain:    domain,
		Score:     m.initialScore,
		FirstSeen: now,
		LastSeen:  now,
		ExpiresAt: now.Add(m.scoreTTL),
	}
	m.store.SetVisitor(ipHash, visitor)
	return visitor
}

func (m *ScoreManager) Set(ip string, domain string, score int) storage.VisitorState {
	now := m.now()
	ipHash := HashIP(ip)
	visitor := storage.VisitorState{
		IPHash:    ipHash,
		Domain:    domain,
		Score:     clamp(score, 0, 100),
		FirstSeen: now,
		LastSeen:  now,
		ExpiresAt: now.Add(m.scoreTTL),
	}
	m.store.SetVisitor(ipHash, visitor)
	return visitor
}

func (m *ScoreManager) Apply(ip string, domain string, delta int) storage.VisitorState {
	visitor := m.Get(ip, domain)
	before := visitor.Score
	visitor.Score = clamp(visitor.Score+delta, 0, 100)
	visitor.LastSeen = m.now()
	visitor.ExpiresAt = visitor.LastSeen.Add(m.scoreTTL)
	m.store.SetVisitor(visitor.IPHash, visitor)
	m.notifyCritical(before, visitor)
	return visitor
}

// PenalizeRateLimit applique DeltaRateLimit au plus une fois par
// RateLimitPenaltyWindow (FR-05). Les refus supplémentaires dans la fenêtre
// retournent l'état courant sans nouvelle pénalité.
func (m *ScoreManager) PenalizeRateLimit(ip string, domain string) storage.VisitorState {
	visitor := m.Get(ip, domain)
	now := m.now()
	if visitor.LastRateLimitPenalty != nil && now.Sub(*visitor.LastRateLimitPenalty) < RateLimitPenaltyWindow {
		return visitor
	}
	before := visitor.Score
	visitor.Score = clamp(visitor.Score+DeltaRateLimit, 0, 100)
	visitor.LastSeen = now
	visitor.ExpiresAt = now.Add(m.scoreTTL)
	visitor.LastRateLimitPenalty = &now
	m.store.SetVisitor(visitor.IPHash, visitor)
	m.notifyCritical(before, visitor)
	return visitor
}

func (m *ScoreManager) State(score int) string {
	if int64(score) <= m.blockThreshold.Load() {
		return StateBlocked
	}
	if int64(score) < m.challengeThreshold.Load() {
		return StateChallenged
	}
	if score >= 70 {
		return StateTrusted
	}
	return StateMonitored
}

func (m *ScoreManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		visitor := m.Get(cloudflare.RealIP(r), r.Host)
		state := m.State(visitor.Score)
		r.Header.Set("X-WAF-Score", strconv.Itoa(visitor.Score))
		r.Header.Set("X-WAF-State", state)

		if state == StateBlocked {
			w.Header().Set("X-WAF-Action", "BLOCK")
			if r.Header.Get("X-WAF-Reason") == "" {
				w.Header().Set("X-WAF-Reason", "score_below_block_threshold")
			} else {
				w.Header().Set("X-WAF-Reason", r.Header.Get("X-WAF-Reason"))
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if state == StateChallenged {
			r.Header.Set("X-WAF-Action", "CHALLENGE")
			if r.Header.Get("X-WAF-Reason") == "" {
				r.Header.Set("X-WAF-Reason", "score_below_challenge_threshold")
			}
		}

		next.ServeHTTP(w, r)
	})
}

func HashIP(ip string) string {
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
