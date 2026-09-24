// Package threatintel évalue la réputation IP (FR-13) à partir de feeds locaux
// (CIDR malveillants, nœuds de sortie Tor, plages datacenter) et d'une source
// HTTP optionnelle (type AbuseIPDB). Les lookups sont mis en cache avec TTL et
// résolus de façon asynchrone et non bloquante (NFR-08).
package threatintel

import (
	"net"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/ttlcache"
)

const (
	// maxCachedVerdicts borne le cache de réputation.
	maxCachedVerdicts = 100000
	// lookupWorkers borne les résolutions simultanées (requêtes vers les
	// sources, dont l'API HTTP) ; lookupQueueSize borne celles en attente.
	lookupWorkers   = 16
	lookupQueueSize = 1024
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
//
// Le cache est borné (maxCachedVerdicts, LRU) et ses entrées expirent. C'était
// une map dont les verdicts périmés n'étaient remplacés qu'à la relecture de la
// même IP : chaque IP vue une fois y restait pour toujours.
//
// Les misses sont résolus par un pool fixe de lookupWorkers goroutines. Une
// goroutine était lancée par miss : 20 000 IP neuves par seconde, c'étaient
// 20 000 goroutines concurrentes interrogeant AbuseIPDB.
type Checker struct {
	sources []Source
	ttl     time.Duration
	cache   *ttlcache.Cache[string, Verdict]
	lookups chan lookup

	mu       sync.Mutex
	inflight map[string]struct{}
}

type lookup struct {
	ip     string
	parsed net.IP
}

func NewChecker(ttl time.Duration, sources ...Source) *Checker {
	if ttl <= 0 {
		ttl = time.Hour
	}
	checker := &Checker{
		sources:  sources,
		ttl:      ttl,
		cache:    ttlcache.New[string, Verdict](maxCachedVerdicts, ttl),
		lookups:  make(chan lookup, lookupQueueSize),
		inflight: make(map[string]struct{}),
	}
	for range lookupWorkers {
		go checker.worker()
	}
	return checker
}

// Close arrête les workers de résolution.
func (c *Checker) Close() {
	close(c.lookups)
}

func (c *Checker) worker() {
	for job := range c.lookups {
		c.cache.Set(job.ip, c.evaluate(job.parsed))
		c.mu.Lock()
		delete(c.inflight, job.ip)
		c.mu.Unlock()
	}
}

// Verdict retourne le verdict caché pour l'IP. Sur miss, il retourne LevelClean
// immédiatement et déclenche une résolution asynchrone (NFR-08 : non bloquant).
func (c *Checker) Verdict(ip string) Verdict {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Verdict{Level: LevelClean}
	}

	if verdict, ok := c.cache.Get(ip); ok {
		return verdict
	}

	c.triggerAsync(ip, parsed)
	return Verdict{Level: LevelClean}
}

// triggerAsync remet la résolution au pool sans bloquer. File pleine : la
// résolution est abandonnée, l'IP sera retentée à sa prochaine requête
// (NFR-08 : un miss n'attend jamais).
func (c *Checker) triggerAsync(ip string, parsed net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, busy := c.inflight[ip]; busy {
		return
	}
	select {
	case c.lookups <- lookup{ip: ip, parsed: parsed}:
		c.inflight[ip] = struct{}{}
	default:
	}
}

// resolveSync évalue et met en cache le verdict de façon synchrone (utilisé par
// les tests et pour préchauffer le cache).
func (c *Checker) resolveSync(ip string) Verdict {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Verdict{Level: LevelClean}
	}
	verdict := c.evaluate(parsed)
	c.cache.Set(ip, verdict)
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
