// Package ipkey dérive l'identité d'un client des contrôles par IP (rate limit,
// trust score, circuit-breaker, slowloris…). Une adresse IPv4 est son propre
// client ; une adresse IPv6 est ramenée à son préfixe /64, la plus petite
// allocation d'un abonné : compter par adresse complète donnait 2⁶⁴ identités
// à quiconque dispose d'un /64, et chaque contrôle par IP se contournait en
// changeant d'adresse.
package ipkey

import "net/netip"

// IPv6PrefixBits est la longueur du préfixe qui identifie un client IPv6.
const IPv6PrefixBits = 64

// Subject retourne l'identité client de ip : l'IPv4 elle-même (une IPv4
// mappée « ::ffff:a.b.c.d » est démappée), le préfixe /64 d'une IPv6 (zone
// retirée). Une valeur non parsable est rendue telle quelle.
func Subject(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr.Is4() {
		return ip
	}
	if addr.Is4In6() {
		return addr.Unmap().String()
	}
	prefix, err := addr.WithZone("").Prefix(IPv6PrefixBits)
	if err != nil {
		return ip
	}
	return prefix.String()
}
