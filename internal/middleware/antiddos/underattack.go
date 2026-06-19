package antiddos

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// DefaultMaxTrackedDomains borne le nombre de domaines suivis par le compteur de
// pression par domaine (éviction LRU) quand scope = per_domain.
const DefaultMaxTrackedDomains = 1024

// pressureRank classe les niveaux pour comparer trigger/exit (FR-39).
func pressureRank(level PressureLevel) int {
	switch level {
	case PressureElevated:
		return 1
	case PressureHigh:
		return 2
	case PressureCritical:
		return 3
	default: // PressureNormal et inconnu
		return 0
	}
}

// UnderAttackConfig paramètre le mode « sous attaque » (FR-39, ADR-018).
type UnderAttackConfig struct {
	Enabled         bool
	PerDomain       bool // scope = per_domain (sinon global)
	TriggerPressure PressureLevel
	ExitPressure    PressureLevel
	Cooldown        time.Duration
	Shadow          bool
	MaxDomains      int

	// Paramètres du compteur de pression sous-jacent (réutilise GlobalRateDetector).
	Threshold int
	Window    time.Duration
	Pressure  PressureConfig
}

// Decision est le verdict du détecteur pour une requête.
type Decision struct {
	Pressure    PressureLevel
	UnderAttack bool // état du scope (journalisé même en shadow)
	Enforce     bool // UnderAttack && !shadow → le challenge doit être forcé
}

// scopeState porte, pour un scope (domaine ou clé globale), son compteur de
// pression et l'état de la machine à hystérésis du mode sous attaque.
type scopeState struct {
	detector   *GlobalRateDetector
	active     bool
	belowSince time.Time // depuis quand la pression est <= exit (0 = jamais, en mode actif)
}

// UnderAttackDetector calcule la pression par scope et pilote l'entrée/sortie du
// mode sous attaque avec hystérésis. Le nombre de scopes (domaines) est borné par
// éviction LRU. Sûr pour un usage concurrent.
type UnderAttackDetector struct {
	cfg UnderAttackConfig

	mu     sync.Mutex
	states map[string]*list.Element // scopeKey -> élément LRU (Value = *lruItem)
	lru    *list.List               // front = plus récemment utilisé
	now    func() time.Time

	// onTransition est appelé hors verrou à chaque changement d'état (entrée/sortie).
	onTransition func(scope string, active bool)
}

type lruItem struct {
	key   string
	state *scopeState
}

// NewUnderAttackDetector construit le détecteur à partir de la config normalisée.
func NewUnderAttackDetector(cfg UnderAttackConfig) *UnderAttackDetector {
	if cfg.MaxDomains < 1 {
		cfg.MaxDomains = DefaultMaxTrackedDomains
	}
	if cfg.Threshold < 1 {
		cfg.Threshold = DefaultGlobalRequestsPerSecond
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultGlobalWindow
	}
	if pressureRank(cfg.TriggerPressure) == 0 {
		cfg.TriggerPressure = PressureHigh
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	cfg.Pressure = normalizePressureConfig(cfg.Pressure)
	return &UnderAttackDetector{
		cfg:    cfg,
		states: make(map[string]*list.Element),
		lru:    list.New(),
		now:    time.Now,
	}
}

// WithTransitionObserver enregistre un observateur appelé à chaque entrée/sortie du
// mode sous attaque (pour l'alerting FR-29). Appelé hors verrou.
func (d *UnderAttackDetector) WithTransitionObserver(fn func(scope string, active bool)) *UnderAttackDetector {
	d.onTransition = fn
	return d
}

// Observe enregistre une requête sur le domaine donné et retourne la décision.
func (d *UnderAttackDetector) Observe(domain string) Decision {
	key := d.scopeKey(domain)

	d.mu.Lock()
	state := d.getOrCreateLocked(key)
	pressure := state.detector.RecordAndPressure()
	prevActive := state.active
	active := d.evaluateLocked(state, pressure)
	d.mu.Unlock()

	if active != prevActive && d.onTransition != nil {
		d.onTransition(key, active)
	}

	return Decision{
		Pressure:    pressure,
		UnderAttack: active,
		Enforce:     active && !d.cfg.Shadow,
	}
}

// evaluateLocked applique la machine à hystérésis. Appelée sous verrou.
func (d *UnderAttackDetector) evaluateLocked(state *scopeState, pressure PressureLevel) bool {
	now := d.now()
	rank := pressureRank(pressure)
	triggerRank := pressureRank(d.cfg.TriggerPressure)
	exitRank := pressureRank(d.cfg.ExitPressure)

	if !state.active {
		if rank >= triggerRank {
			state.active = true
			state.belowSince = time.Time{}
		}
		return state.active
	}

	// Déjà actif : on ne sort que sous exit_pressure maintenu pendant cooldown.
	if rank > exitRank {
		state.belowSince = time.Time{} // toujours sous tension → on réarme le timer
		return true
	}
	if state.belowSince.IsZero() {
		state.belowSince = now
		return true
	}
	if now.Sub(state.belowSince) >= d.cfg.Cooldown {
		state.active = false
		state.belowSince = time.Time{}
		return false
	}
	return true
}

func (d *UnderAttackDetector) scopeKey(domain string) string {
	if !d.cfg.PerDomain {
		return "*"
	}
	host := domain
	if i := strings.IndexByte(host, ':'); i >= 0 { // retire le port éventuel
		host = host[:i]
	}
	return strings.ToLower(host)
}

// getOrCreateLocked retourne l'état du scope, en créant l'entrée (et en évinçant le
// LRU le moins récent au-delà de MaxDomains) si nécessaire. Appelée sous verrou.
func (d *UnderAttackDetector) getOrCreateLocked(key string) *scopeState {
	if elem, ok := d.states[key]; ok {
		d.lru.MoveToFront(elem)
		return elem.Value.(*lruItem).state
	}

	detector := NewGlobalRateDetector(d.cfg.Threshold, d.cfg.Window, d.cfg.Pressure)
	detector.now = d.now // horloge partagée (tests déterministes)
	state := &scopeState{detector: detector}
	elem := d.lru.PushFront(&lruItem{key: key, state: state})
	d.states[key] = elem

	for d.lru.Len() > d.cfg.MaxDomains {
		oldest := d.lru.Back()
		if oldest == nil {
			break
		}
		d.lru.Remove(oldest)
		delete(d.states, oldest.Value.(*lruItem).key)
	}
	return state
}
