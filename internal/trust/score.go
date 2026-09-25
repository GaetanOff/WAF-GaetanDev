package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/maphash"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/wafheader"
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

	// maxTouchInterval borne la fréquence à laquelle Get réécrit un visiteur
	// connu pour faire glisser son TTL. Réécrire à CHAQUE lecture coûtait, par
	// requête, un SET Redis synchrone et le verrou global du store mémoire pour
	// chacun des appels à Get du pipeline. Le TTL glisse donc par pas : un
	// visiteur actif expire au plus maxTouchInterval plus tôt qu'à la seconde
	// près, ce qui est sans effet pratique pour un score_ttl d'une heure.
	maxTouchInterval = 30 * time.Second

	// headerDeterministicTrigger porte un signal déterministe publié par un
	// détecteur (threat intel critique, JA3 blacklisté ; FR-35).
	headerDeterministicTrigger = wafheader.DeterministicTrigger
)

// deterministicTriggers sont les signaux qui bloquent seuls, sans
// corroboration (requirements-detection FR-35) — l'énumération de
// risk-assessment.schema.json.
var deterministicTriggers = map[string]bool{
	"blacklist":             true,
	"honeypot":              true,
	"ja3_blacklist":         true,
	"threat_intel_critical": true,
	"circuit_breaker":       true,
}

type ScoreManager struct {
	store              storage.Store
	initialScore       int
	challengeThreshold atomic.Int64 // modifiable à chaud (SetThresholds)
	blockThreshold     atomic.Int64
	scoreTTL           time.Duration
	touchInterval      time.Duration
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
		store:         store,
		initialScore:  cfg.Trust.InitialScore,
		scoreTTL:      scoreTTL,
		touchInterval: min(maxTouchInterval, scoreTTL/4),
		now:           time.Now,
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

// Get retourne l'état du visiteur, en le créant s'il est inconnu ou expiré, et
// fait glisser son TTL. La réécriture du TTL n'a lieu qu'une fois par
// touchInterval : les lectures suivantes ne coûtent qu'un GetVisitor.
func (m *ScoreManager) Get(ip string, domain string) storage.VisitorState {
	now := m.now()
	ipHash := HashIP(ip)
	if visitor, ok := m.store.GetVisitor(ipHash); ok {
		if isExpired(*visitor, now) {
			m.store.DeleteVisitor(ipHash)
			return m.create(ipHash, domain, now)
		}
		if now.Sub(visitor.LastSeen) >= m.touchInterval {
			visitor.LastSeen = now
			visitor.ExpiresAt = now.Add(m.scoreTTL)
			m.store.SetVisitor(ipHash, *visitor)
		}
		return *visitor
	}

	return m.create(ipHash, domain, now)
}

// Peek retourne l'état du visiteur SANS rien écrire : ni création, ni
// glissement du TTL. Un visiteur inconnu ou expiré est rendu à son score
// initial, tel que Get le créerait. Réservé aux observateurs (journal,
// métriques, lectures de décision) : seul le middleware de décision doit
// payer l'écriture.
func (m *ScoreManager) Peek(ip string, domain string) storage.VisitorState {
	now := m.now()
	ipHash := HashIP(ip)
	if visitor, ok := m.store.GetVisitor(ipHash); ok && !isExpired(*visitor, now) {
		return *visitor
	}
	return m.initialVisitor(ipHash, domain, now)
}

func isExpired(visitor storage.VisitorState, now time.Time) bool {
	return !visitor.ExpiresAt.IsZero() && !visitor.ExpiresAt.After(now)
}

func (m *ScoreManager) create(ipHash string, domain string, now time.Time) storage.VisitorState {
	visitor := m.initialVisitor(ipHash, domain, now)
	m.store.SetVisitor(ipHash, visitor)
	return visitor
}

func (m *ScoreManager) initialVisitor(ipHash string, domain string, now time.Time) storage.VisitorState {
	return storage.VisitorState{
		IPHash:    ipHash,
		Domain:    domain,
		Score:     m.initialScore,
		FirstSeen: now,
		LastSeen:  now,
		ExpiresAt: now.Add(m.scoreTTL),
	}
}

// TTL retourne la durée de vie d'un score sans activité (trust.score_ttl).
func (m *ScoreManager) TTL() time.Duration {
	return m.scoreTTL
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
		if r.Header.Get(wafheader.Action) == wafheader.ActionPass {
			next.ServeHTTP(w, r)
			return
		}

		// Sans moteur de risque, ce middleware est le seul à décider : ignorer le
		// déclencheur laissait passer, sans blocage ni challenge, une IP classée
		// critique par AbuseIPDB ou un JA3 explicitement blacklisté.
		if trigger := r.Header.Get(headerDeterministicTrigger); deterministicTriggers[trigger] {
			blockDeterministic(w, r, trigger)
			return
		}

		visitor := m.Get(cloudflare.RealIP(r), r.Host)
		state := m.State(visitor.Score)
		r.Header.Set(wafheader.Score, strconv.Itoa(visitor.Score))
		r.Header.Set(wafheader.State, state)

		if state == StateBlocked {
			w.Header().Set(wafheader.Action, wafheader.ActionBlock)
			if r.Header.Get(wafheader.Reason) == "" {
				w.Header().Set(wafheader.Reason, "score_below_block_threshold")
			} else {
				w.Header().Set(wafheader.Reason, r.Header.Get(wafheader.Reason))
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if state == StateChallenged {
			r.Header.Set(wafheader.Action, wafheader.ActionChallenge)
			if r.Header.Get(wafheader.Reason) == "" {
				r.Header.Set(wafheader.Reason, "score_below_challenge_threshold")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// blockDeterministic refuse la requête en 403 sur un déclencheur déterministe,
// avec la raison posée par le détecteur (ex. ja3_blacklisted).
func blockDeterministic(w http.ResponseWriter, r *http.Request, trigger string) {
	reason := r.Header.Get(wafheader.Reason)
	if reason == "" {
		reason = "deterministic_" + trigger
	}
	w.Header().Set(headerDeterministicTrigger, trigger)
	w.Header().Set(wafheader.Action, wafheader.ActionBlock)
	w.Header().Set(wafheader.Reason, reason)
	http.Error(w, "forbidden", http.StatusForbidden)
}

// ipHashBytes est la part du SHA-256 conservée : 8 octets, 16 caractères hex.
const ipHashBytes = 8

// hashCacheSlots est la taille du cache de HashIP (puissance de deux).
const hashCacheSlots = 1 << 14

// ipHash est une entrée du cache de HashIP.
type ipHash struct {
	ip   string
	hash string
}

var (
	hashCache [hashCacheSlots]atomic.Pointer[ipHash]
	hashSeed  = maphash.MakeSeed()
)

// HashIP est appelé six à dix fois par requête pour la même IP (rate limit,
// trust, journal, métriques, moteur de risque, détecteurs) : un SHA-256 et une
// allocation à chaque fois. Un cache à correspondance directe, sans verrou,
// retient le dernier hash calculé par emplacement : le premier appel d'une
// requête le calcule, les suivants le relisent. Deux IP qui se disputent un
// emplacement se l'arrachent sans erreur possible — l'IP est comparée avant de
// rendre le hash. N'encoder que les octets conservés, au lieu des 64
// caractères tronqués ensuite, produit la même clé.
func HashIP(ip string) string {
	slot := &hashCache[maphash.String(hashSeed, ip)&(hashCacheSlots-1)]
	if cached := slot.Load(); cached != nil && cached.ip == ip {
		return cached.hash
	}
	sum := sha256.Sum256([]byte(ip))
	hash := hex.EncodeToString(sum[:ipHashBytes])
	// Clone : ip peut être une sous-chaîne d'un en-tête ou de RemoteAddr, que
	// l'entrée retiendrait sinon en mémoire.
	slot.Store(&ipHash{ip: strings.Clone(ip), hash: hash})
	return hash
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
