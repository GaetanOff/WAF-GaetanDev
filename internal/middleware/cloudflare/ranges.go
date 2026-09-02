package cloudflare

import (
	"net/netip"
	"sync/atomic"
)

// builtinRanges est la liste compilée dans le binaire, relevée sur les listes
// officielles Cloudflare le 2026-06-04 :
// https://www.cloudflare.com/ips-v4 et https://www.cloudflare.com/ips-v6
//
// Elle sert de valeur initiale ET de repli permanent : le rafraîchissement
// automatique (FR-02, cloudflare.auto_update_ranges) ne la remplace que par une
// liste complète et validée. Un échec de récupération laisse donc toujours une
// liste sûre en vigueur — jamais de liste vide.
var builtinRanges = parsePrefixes([]string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
})

// activeRanges porte la liste en vigueur ; nil signifie « liste compilée ».
// Le remplacement est atomique parce que IsCloudflareIP est sur le chemin de
// requête : un lecteur voit soit l'ancienne liste, soit la nouvelle, jamais un
// état intermédiaire, et sans verrou à prendre par requête.
var activeRanges atomic.Pointer[[]netip.Prefix]

// Ranges retourne les plages en vigueur.
func Ranges() []netip.Prefix {
	if current := activeRanges.Load(); current != nil {
		return *current
	}
	return builtinRanges
}

// BuiltinRanges retourne la liste compilée dans le binaire.
func BuiltinRanges() []netip.Prefix {
	return builtinRanges
}

// setRanges installe une liste récupérée. Réservé à l'updater : la validation
// est faite en amont (validateFetchedRanges), poser la liste ici est
// inconditionnel.
func setRanges(prefixes []netip.Prefix) {
	snapshot := make([]netip.Prefix, len(prefixes))
	copy(snapshot, prefixes)
	activeRanges.Store(&snapshot)
}

// resetRanges revient à la liste compilée.
func resetRanges() {
	activeRanges.Store(nil)
}

func parsePrefixes(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
