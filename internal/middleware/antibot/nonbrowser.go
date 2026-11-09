package antibot

import (
	"path"
	"slices"
	"strings"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
)

// nonBrowserPaths résout, pour l'hôte et le chemin d'une requête, l'exemption
// des signaux « client non navigateur » déclarée par domains[].non_browser_paths
// (FR-41, ADR-023).
//
// L'entrée domains[] est choisie comme par le routage : casse ignorée, port
// retiré, exacte ou wildcard `*.example.com` (qui couvre aussi l'apex),
// première entrée correspondante gagnante. Toutes les entrées sont retenues,
// même sans la clé : une entrée exacte sans liste ne doit pas laisser un
// wildcard placé après lui prêter la sienne (aucun héritage).
type nonBrowserPaths struct {
	entries []nonBrowserEntry
}

type nonBrowserEntry struct {
	// label est le host configuré, normalisé : label de métrique borné par
	// domains[], jamais l'hôte brut de la requête.
	label    string
	host     string // hôte normalisé, wildcard sans le préfixe "*."
	wildcard bool
	patterns []string
}

func newNonBrowserPaths(domains []config.DomainConfig) nonBrowserPaths {
	declared := slices.ContainsFunc(domains, func(domain config.DomainConfig) bool {
		return len(domain.NonBrowserPaths) > 0
	})
	if !declared {
		return nonBrowserPaths{} // aucune exemption : rien à résoudre par requête
	}
	set := nonBrowserPaths{entries: make([]nonBrowserEntry, 0, len(domains))}
	for _, domain := range domains {
		label := hostname.Normalize(domain.Host)
		host, wildcard := strings.CutPrefix(label, "*.")
		set.entries = append(set.entries, nonBrowserEntry{
			label:    label,
			host:     host,
			wildcard: wildcard,
			patterns: slices.Clone(domain.NonBrowserPaths),
		})
	}
	return set
}

// exempt rend le label de l'entrée domains[] qui exempte requestPath sur host.
func (s nonBrowserPaths) exempt(host, requestPath string) (string, bool) {
	if len(s.entries) == 0 {
		return "", false
	}
	entry, ok := s.resolve(hostname.Normalize(host))
	if !ok || !entry.covers(requestPath) {
		return "", false
	}
	return entry.label, true
}

func (s nonBrowserPaths) resolve(host string) (nonBrowserEntry, bool) {
	for _, entry := range s.entries {
		if entry.matches(host) {
			return entry, true
		}
	}
	return nonBrowserEntry{}, false
}

func (e nonBrowserEntry) matches(host string) bool {
	if e.wildcard {
		return host == e.host || strings.HasSuffix(host, "."+e.host)
	}
	return host == e.host
}

// covers : un motif terminé par "/" couvre ses sous-chemins, un autre motif
// son seul chemin. Fail-closed : un chemin non canonique n'est jamais couvert —
// "/v1/../admin" ne doit pas hériter de l'exemption de "/v1/".
func (e nonBrowserEntry) covers(requestPath string) bool {
	if len(e.patterns) == 0 || !isCanonicalPath(requestPath) {
		return false
	}
	for _, pattern := range e.patterns {
		if strings.HasSuffix(pattern, "/") {
			if strings.HasPrefix(requestPath, pattern) {
				return true
			}
		} else if requestPath == pattern {
			return true
		}
	}
	return false
}

// isCanonicalPath : le chemin est absolu et égal à son path.Clean, "/" final
// préservé — ni segment "." ou "..", ni "//".
func isCanonicalPath(requestPath string) bool {
	if !strings.HasPrefix(requestPath, "/") {
		return false
	}
	cleaned := path.Clean(requestPath)
	if strings.HasSuffix(requestPath, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned == requestPath
}
