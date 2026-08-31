package challenge

import (
	"net"
	"strings"

	"github.com/gaetandev/waf/internal/config"
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
	global    bool
	overrides []domainOverride
}

type domainOverride struct {
	host     string // hôte normalisé, wildcard sans le préfixe "*."
	wildcard bool
	enabled  bool
}

func newDomainGate(cfg config.Config) domainGate {
	gate := domainGate{global: cfg.Challenge.Enabled}
	for _, domain := range cfg.Domains {
		if domain.ChallengeEnabled == nil {
			continue // clé absente : le domaine hérite du global
		}
		host := normalizeHost(domain.Host)
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
	requestHost := normalizeHost(host)
	for _, override := range g.overrides {
		if override.matches(requestHost) {
			return override.enabled
		}
	}
	return g.global
}

// anyEnabled indique si au moins un hôte peut recevoir un challenge : le global
// est actif, ou un domaine l'active explicitement alors que le global est éteint.
func (g domainGate) anyEnabled() bool {
	if g.global {
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

// normalizeHost met l'hôte en minuscules et retire le port éventuel. Un Host
// IPv6 littéral ("[::1]:8443") est géré par net.SplitHostPort.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return hostname
	}
	return host
}

// Enabled indique si le middleware de challenge doit être monté dans la chaîne :
// soit `challenge.enabled` est vrai, soit au moins un `domains[]` l'active
// explicitement alors que le global est éteint (FR-06).
func Enabled(cfg config.Config) bool {
	return newDomainGate(cfg).anyEnabled()
}
