package proxy

import (
	"net/http"
	"strings"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
	"github.com/gaetandev/waf/internal/wafheader"
)

// healthPath reste servi quel que soit le Host : les sondes de conteneur et
// de load balancer appellent le WAF par son IP (ADR-020, conséquences).
const healthPath = "/waf/health"

// StrictHost refuse en 400 toute requête dont le Host ne correspond à aucune
// entrée domains[] (server.strict_host, ADR-020 option 1C).
//
// Sans cette garde, un Host non listé est routé vers upstream.address et hérite
// de la politique GLOBALE : si cet upstream est la même origine qu'un domaine
// durci (challenge_enabled: true), le durcissement se contourne en changeant
// l'en-tête. La correspondance est celle du routage (casse ignorée, port
// retiré, wildcard couvrant l'apex) : un hôte accepté ici est exactement un
// hôte que resolveProxy attribue à une entrée domains[].
func StrictHost(domains []config.DomainConfig, next http.Handler) http.Handler {
	routes := make([]domainRoute, 0, len(domains))
	for _, domain := range domains {
		host := strings.ToLower(domain.Host)
		wildcard := strings.HasPrefix(host, "*.")
		routes = append(routes, domainRoute{host: strings.TrimPrefix(host, "*."), wildcard: wildcard})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath || declared(routes, hostname.Normalize(r.Host)) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set(wafheader.Action, wafheader.ActionBlock)
		w.Header().Set(wafheader.Reason, "host_not_declared")
		http.Error(w, "bad request", http.StatusBadRequest)
	})
}

func declared(routes []domainRoute, host string) bool {
	for _, route := range routes {
		if route.matches(host) {
			return true
		}
	}
	return false
}
