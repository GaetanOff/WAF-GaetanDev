// Package threatintel évalue la réputation IP (FR-13) à partir de feeds locaux
// (CIDR malveillants, nœuds de sortie Tor, plages datacenter) et d'une source
// HTTP optionnelle (type AbuseIPDB). Les lookups sont mis en cache avec TTL et
// résolus de façon asynchrone et non bloquante (NFR-08).
package threatintel

import (
	"net"
	"sync"
	"time"
)

// Level classe la réputation d'une IP, du plus bénin au plus dangereux.
type Level int

const (
	LevelClean Level = iota
	LevelSuspect
	LevelMalicious
	LevelCritical
)

// Verdict est le résultat d'évaluation pour une IP.
type Verdict struct {
	Level  Level
	Reason string
}

// Source fournit un verdict pour une IP (feed local, API externe, ...).
type Source interface {
	Lookup(ip net.IP) Verdict
}

// Checker agrège des sources et met en cache les verdicts avec TTL. Les misses
// déclenchent une résolution asynchrone afin de ne jamais bloquer la requête.
type Checker struct {
	sources []Source
	ttl     time.Duration

	mu       sync.RWMutex
	cache    map[string]cachedVerdict
	inflight map[string]struct{}
	now      func() time.Time
}

type cachedVerdict struct {
	verdict   Verdict
	expiresAt time.Time
}

func NewChecker(ttl time.Duration, sources ...Source) *Checker {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Checker{
		sources:  sources,
		ttl:      ttl,
		cache:    make(map[string]cachedVerdict),
		inflight: make(map[string]struct{}),
		now:      time.Now,
	}
}

// Verdict retourne le verdict caché pour l'IP. Sur miss, il retourne LevelClean
// immédiatement et déclenche une résolution asynchrone (NFR-08 : non bloquant).
func (c *Checker) Verdict(ip string) Verdict {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Verdict{Level: LevelClean}
	}

	c.mu.RLock()
	entry, ok := c.cache[ip]
	c.mu.RUnlock()
	if ok && entry.expiresAt.After(c.now()) {
		return entry.verdict
	}

	c.triggerAsync(ip, parsed)
	return Verdict{Level: LevelClean}
}

func (c *Checker) triggerAsync(ip string, parsed net.IP) {
	c.mu.Lock()
	if _, busy := c.inflight[ip]; busy {
		c.mu.Unlock()
		return
	}
	c.inflight[ip] = struct{}{}
	c.mu.Unlock()

	go func() {
		verdict := c.evaluate(parsed)
		c.mu.Lock()
		c.cache[ip] = cachedVerdict{verdict: verdict, expiresAt: c.now().Add(c.ttl)}
		delete(c.inflight, ip)
		c.mu.Unlock()
	}()
}

// resolveSync évalue et met en cache le verdict de façon synchrone (utilisé par
// les tests et pour préchauffer le cache).
func (c *Checker) resolveSync(ip string) Verdict {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Verdict{Level: LevelClean}
	}
	verdict := c.evaluate(parsed)
	c.mu.Lock()
	c.cache[ip] = cachedVerdict{verdict: verdict, expiresAt: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return verdict
}

// evaluate interroge toutes les sources et retourne le verdict le plus sévère.
func (c *Checker) evaluate(ip net.IP) Verdict {
	worst := Verdict{Level: LevelClean}
	for _, source := range c.sources {
		if v := source.Lookup(ip); v.Level > worst.Level {
			worst = v
		}
	}
	return worst
}

// StaticSource est un feed local : des plages CIDR associées à un niveau et une
// raison (blocklist, Tor exit nodes, ASN datacenter exprimés en CIDR).
type StaticSource struct {
	entries []staticEntry
}

type staticEntry struct {
	network *net.IPNet
	level   Level
	reason  string
}

func NewStaticSource() *StaticSource {
	return &StaticSource{}
}

// Add enregistre une plage CIDR avec son niveau et sa raison. Une entrée
// invalide est ignorée silencieusement (le feed reste opérationnel).
func (s *StaticSource) Add(cidr string, level Level, reason string) *StaticSource {
	if _, network, err := net.ParseCIDR(cidr); err == nil {
		s.entries = append(s.entries, staticEntry{network: network, level: level, reason: reason})
	}
	return s
}

func (s *StaticSource) Lookup(ip net.IP) Verdict {
	worst := Verdict{Level: LevelClean}
	for _, entry := range s.entries {
		if entry.network.Contains(ip) && entry.level > worst.Level {
			worst = Verdict{Level: entry.level, Reason: entry.reason}
		}
	}
	return worst
}
