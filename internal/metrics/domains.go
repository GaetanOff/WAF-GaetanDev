package metrics

import (
	"strings"

	"github.com/gaetandev/waf/internal/hostname"
)

// undeclaredDomain est le label domain de tout hôte absent de domains[]. Le
// label reprenait r.Host : sans server.strict_host, chaque Host inventé par un
// client créait une série Prometheus, conservée jusqu'à l'arrêt du processus —
// une croissance mémoire pilotée par l'attaquant.
const undeclaredDomain = "_undeclared"

// globalScope est la portée du mode « sous attaque » quand il n'est pas suivi
// par domaine (antiddos.UnderAttackDetector).
const globalScope = "*"

// domainLabels borne le label domain aux entrées de domains[] : un hôte exact
// est rendu tel quel, un hôte couvert par un wildcard rend le wildcard, tout
// autre hôte rend undeclaredDomain. Même correspondance que le routage : casse
// ignorée, port retiré, wildcard couvrant l'apex, exact avant wildcard.
type domainLabels struct {
	exact     map[string]struct{}
	wildcards []string // domaine couvert, sans le préfixe "*."
}

func newDomainLabels(hosts []string) domainLabels {
	labels := domainLabels{exact: make(map[string]struct{}, len(hosts))}
	for _, host := range hosts {
		host = hostname.Normalize(host)
		if suffix, ok := strings.CutPrefix(host, "*."); ok {
			labels.wildcards = append(labels.wildcards, suffix)
			continue
		}
		labels.exact[host] = struct{}{}
	}
	return labels
}

func (l domainLabels) label(host string) string {
	host = hostname.Normalize(host)
	if _, ok := l.exact[host]; ok {
		return host
	}
	for _, suffix := range l.wildcards {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return "*." + suffix
		}
	}
	return undeclaredDomain
}
