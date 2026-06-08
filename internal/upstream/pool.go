// Package upstream gère un pool de serveurs d'origine avec health checks actifs
// et stratégies de load balancing (FR-25, FR-26, ADR-012). Un upstream marqué
// non sain est exclu de la sélection ; si tous les primaires sont down, les
// upstreams de secours (backup) prennent le relais.
package upstream

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
)

// Stratégies de sélection.
const (
	StrategyRoundRobin = "round_robin"
	StrategyLeastConn  = "least_conn"
	StrategyIPHash     = "ip_hash"
	StrategyWeighted   = "weighted"
)

// Upstream représente un serveur d'origine.
type Upstream struct {
	Address string
	Weight  int
	Backup  bool

	healthy  atomic.Bool
	inflight atomic.Int64
}

func (u *Upstream) Healthy() bool     { return u.healthy.Load() }
func (u *Upstream) SetHealthy(v bool) { u.healthy.Store(v) }
func (u *Upstream) Acquire()          { u.inflight.Add(1) }
func (u *Upstream) Release()          { u.inflight.Add(-1) }
func (u *Upstream) Inflight() int64   { return u.inflight.Load() }

// Pool sélectionne un upstream sain selon la stratégie configurée.
type Pool struct {
	strategy  string
	upstreams []*Upstream
	mu        sync.Mutex
	counter   uint64
}

func NewPool(strategy string, upstreams []*Upstream) *Pool {
	if strategy == "" {
		strategy = StrategyRoundRobin
	}
	for _, u := range upstreams {
		u.SetHealthy(true) // sain jusqu'à preuve du contraire
		if u.Weight <= 0 {
			u.Weight = 1
		}
	}
	return &Pool{strategy: strategy, upstreams: upstreams}
}

// Upstreams retourne tous les upstreams (pour le health checker).
func (p *Pool) Upstreams() []*Upstream { return p.upstreams }

// Pick choisit un upstream sain. Préfère les primaires ; bascule sur les backups
// si aucun primaire n'est sain. Retourne (nil, false) si tout est down.
func (p *Pool) Pick(key string) (*Upstream, bool) {
	if u, ok := p.pick(key, false); ok {
		return u, true
	}
	return p.pick(key, true) // fallback backups
}

func (p *Pool) pick(key string, backup bool) (*Upstream, bool) {
	candidates := make([]*Upstream, 0, len(p.upstreams))
	for _, u := range p.upstreams {
		if u.Backup == backup && u.Healthy() {
			candidates = append(candidates, u)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}

	switch p.strategy {
	case StrategyIPHash:
		return candidates[hashKey(key)%uint32(len(candidates))], true
	case StrategyLeastConn:
		return leastConn(candidates), true
	case StrategyWeighted:
		return p.weighted(candidates), true
	default: // round_robin
		p.mu.Lock()
		idx := p.counter % uint64(len(candidates))
		p.counter++
		p.mu.Unlock()
		return candidates[idx], true
	}
}

func leastConn(candidates []*Upstream) *Upstream {
	best := candidates[0]
	for _, u := range candidates[1:] {
		if u.Inflight() < best.Inflight() {
			best = u
		}
	}
	return best
}

func (p *Pool) weighted(candidates []*Upstream) *Upstream {
	total := 0
	for _, u := range candidates {
		total += u.Weight
	}
	if total <= 0 {
		return candidates[0]
	}
	p.mu.Lock()
	point := int(p.counter % uint64(total))
	p.counter++
	p.mu.Unlock()
	for _, u := range candidates {
		point -= u.Weight
		if point < 0 {
			return u
		}
	}
	return candidates[len(candidates)-1]
}

func hashKey(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32()
}
