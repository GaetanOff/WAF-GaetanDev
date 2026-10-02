package hostname

import "strings"

// Undeclared désigne tout hôte absent de domains[]. Un label ou une clé qui
// reprenait le Host reçu tel quel croissait au gré des Host inventés par les
// clients (séries Prometheus, clés de déduplication des alertes).
const Undeclared = "_undeclared"

// Declared borne un hôte aux entrées de domains[] : un hôte exact est rendu
// tel quel, un hôte couvert par un wildcard rend le wildcard, tout autre hôte
// rend Undeclared. Même correspondance que le routage : casse ignorée, port
// retiré, wildcard couvrant l'apex, exact avant wildcard.
type Declared struct {
	exact     map[string]struct{}
	wildcards []string // domaine couvert, sans le préfixe "*."
}

func NewDeclared(hosts []string) Declared {
	declared := Declared{exact: make(map[string]struct{}, len(hosts))}
	for _, host := range hosts {
		host = Normalize(host)
		if suffix, ok := strings.CutPrefix(host, "*."); ok {
			declared.wildcards = append(declared.wildcards, suffix)
			continue
		}
		declared.exact[host] = struct{}{}
	}
	return declared
}

// Label rend l'entrée de domains[] qui couvre host, ou Undeclared.
func (d Declared) Label(host string) string {
	host = Normalize(host)
	if _, ok := d.exact[host]; ok {
		return host
	}
	for _, suffix := range d.wildcards {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return "*." + suffix
		}
	}
	return Undeclared
}
