// Package gdpr fournit les primitives de conformité RGPD (FR-28, ADR-013) :
// anonymisation des adresses IP (troncature /24 IPv4, /48 IPv6) pour les logs.
// La rétention est assurée par le TTL du store (purge) ; l'effacement par
// l'endpoint admin dédié.
package gdpr

import "net"

// AnonymizeIP tronque une IP : IPv4 → /24 (dernier octet à 0), IPv6 → /48
// (96 bits de poids faible à 0). Retourne la valeur inchangée si non parsable.
func AnonymizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		masked := v4.Mask(net.CIDRMask(24, 32))
		return masked.String()
	}
	masked := parsed.Mask(net.CIDRMask(48, 128))
	return masked.String()
}
