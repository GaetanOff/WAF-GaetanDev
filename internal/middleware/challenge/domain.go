package challenge

import (
	"strings"
	"sync/atomic"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
)

// domainGate résout, pour l'hôte d'une requête, si le challenge JS doit être
// servi (FR-06). `domains[].challenge_enabled` est une surcharge à trois états
// de `challenge.enabled` :
//
//	nil   -> le domaine hérite du réglage global
//	false -> jamais de challenge sur ce domaine, y compris sous le mode « sous
//	         attaque » (FR-39) : c'est une décision explicite de l'opérateur
//	         (typiquement une API dont les clients ne peuvent pas exécuter de JS),
//	         elle prime sur l'escalade automatique
//	true  -> challenge servi même si `challenge.enabled` vaut false globalement
//
// La correspondance d'hôte suit les règles du routage `domains[]` : casse
// ignorée, port retiré, exacte ou wildcard `*.example.com` (qui couvre aussi
// l'apex `example.com`), première entrée correspondante gagnante.
type domainGate struct {
	// global est partagé par les copies du Middleware (type valeur) et
	// modifiable à chaud (challenge.enabled, PATCH /waf/admin/config).
	global    *atomic.Bool
	overrides []domainOverride
}

type domainOverride struct {
	host     string // hôte normalisé, wildcard sans le préfixe "*."
	wildcard bool
	enabled  bool
}

func newDomainGate(cfg config.Config) domainGate {
	gate := domainGate{global: new(atomic.Bool)}
	gate.global.Store(cfg.Challenge.Enabled)
	for _, domain := range cfg.Domains {
		if domain.ChallengeEnabled == nil {
			continue // clé absente : le domaine hérite du global
		}
		host := hostname.Normalize(domain.Host)
		wildcard := strings.HasPrefix(host, "*.")
		gate.overrides = append(gate.overrides, domainOverride{
			host:     strings.TrimPrefix(host, "*."),
			wildcard: wildcard,
			enabled:  *domain.ChallengeEnabled,
		})
	}
	return gate
}

func (g domainGate) enabledFor(host string) bool {
	requestHost := hostname.Normalize(host)
	for _, override := range g.overrides {
		if override.matches(requestHost) {
			return override.enabled
		}
	}
	return g.global.Load()
}

// anyEnabled indique si au moins un hôte peut recevoir un challenge : le global
// est actif, ou un domaine l'active explicitement alors que le global est éteint.
func (g domainGate) anyEnabled() bool {
	if g.global.Load() {
		return true
	}
	for _, override := range g.overrides {
		if override.enabled {
			return true
		}
	}
	return false
}

func (o domainOverride) matches(host string) bool {
	if o.wildcard {
		return host == o.host || strings.HasSuffix(host, "."+o.host)
	}
	return host == o.host
}
