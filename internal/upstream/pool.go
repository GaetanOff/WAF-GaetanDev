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

// pick sélectionne parmi les candidats (membres sains du groupe primaire ou
// backup) sans matérialiser leur liste : une tranche de candidats était
// allouée sur le tas à chaque requête proxifiée. Deux parcours de
// p.upstreams — compter, puis désigner le n-ième — suffisent.
func (p *Pool) pick(key string, backup bool) (*Upstream, bool) {
	count, totalWeight := 0, 0
	for _, u := range p.upstreams {
		if isCandidate(u, backup) {
			count++
			totalWeight += u.Weight
		}
	}
	if count == 0 {
		return nil, false
	}

	switch p.strategy {
	case StrategyIPHash:
		return p.nthCandidate(backup, int(hashKey(key)%uint32(count))), true
	case StrategyLeastConn:
		return p.leastConn(backup), true
	case StrategyWeighted:
		return p.weighted(backup, totalWeight), true
	default: // round_robin
		return p.nthCandidate(backup, int(p.next()%uint64(count))), true
	}
}

func isCandidate(u *Upstream, backup bool) bool {
	return u.Backup == backup && u.Healthy()
}

// next retourne puis avance le compteur de rotation.
func (p *Pool) next() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.counter
	p.counter++
	return current
}

// nthCandidate retourne le n-ième candidat. Un membre qui change d'état entre
// le comptage et ce parcours peut décaler l'index : le dernier candidat vu,
// ou à défaut le premier membre du groupe, est alors retenu.
func (p *Pool) nthCandidate(backup bool, n int) *Upstream {
	var last *Upstream
	for _, u := range p.upstreams {
		if !isCandidate(u, backup) {
			continue
		}
		if n == 0 {
			return u
		}
		n--
		last = u
	}
	if last != nil {
		return last
	}
	return p.firstOfGroup(backup)
}

func (p *Pool) leastConn(backup bool) *Upstream {
	var best *Upstream
	for _, u := range p.upstreams {
		if isCandidate(u, backup) && (best == nil || u.Inflight() < best.Inflight()) {
			best = u
		}
	}
	if best == nil {
		return p.firstOfGroup(backup)
	}
	return best
}

func (p *Pool) weighted(backup bool, total int) *Upstream {
	if total <= 0 {
		return p.nthCandidate(backup, 0)
	}
	point := int(p.next() % uint64(total))
	for _, u := range p.upstreams {
		if !isCandidate(u, backup) {
			continue
		}
		point -= u.Weight
		if point < 0 {
			return u
		}
	}
	return p.nthCandidate(backup, 0)
}

// firstOfGroup est le repli d'une course entre comptage et sélection : tous
// les candidats sont devenus non sains entre-temps.
func (p *Pool) firstOfGroup(backup bool) *Upstream {
	for _, u := range p.upstreams {
		if u.Backup == backup {
			return u
		}
	}
	return p.upstreams[0]
}

func hashKey(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32()
}
