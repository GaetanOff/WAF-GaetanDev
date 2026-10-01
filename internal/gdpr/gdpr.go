// Package gdpr fournit les primitives de conformité RGPD (FR-28, ADR-013) :
// anonymisation des adresses IP (troncature /24 IPv4, /48 IPv6) pour les logs.
// La rétention est assurée par le TTL du store (purge) ; l'effacement par
// l'endpoint admin dédié.
package gdpr

import "net/netip"

// Préfixes conservés par AnonymizeIP (FR-28).
const (
	ipv4KeptBits = 24
	ipv6KeptBits = 48
)

// AnonymizeIP tronque une IP : IPv4 → /24 (dernier octet à 0), IPv6 → /48
// (80 bits de poids faible à 0). Retourne la valeur inchangée si non parsable.
func AnonymizeIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	// Une IPv4 mappée se tronque comme une IPv4 ; la zone (fe80::1%eth0) est
	// retirée — net.ParseIP la refusait et l'adresse était journalisée entière.
	addr = addr.Unmap().WithZone("")
	bits := ipv6KeptBits
	if addr.Is4() {
		bits = ipv4KeptBits
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ip
	}
	return prefix.Addr().String()
}
