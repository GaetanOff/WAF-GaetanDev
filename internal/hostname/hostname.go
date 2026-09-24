// Package hostname normalise l'hôte d'une requête HTTP. Toute décision ou
// signature liée à un hôte (routage domains[], surcharge de challenge, tokens
// et cookies de challenge, token d'origine) doit porter sur la même forme :
// "Example.com", "example.com:443" et "example.com" désignent un seul domaine.
package hostname

import (
	"net"
	"strings"
)

// Normalize met l'hôte en minuscules et retire le port éventuel. Un Host IPv6
// littéral ("[::1]:8443") est géré par net.SplitHostPort.
func Normalize(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	// SplitHostPort alloue une erreur quand il n'y a pas de port : le cas
	// courant (Host sans port) l'évite.
	if strings.IndexByte(host, ':') >= 0 {
		if hostname, _, err := net.SplitHostPort(host); err == nil {
			return hostname
		}
	}
	return host
}
