// Package staticassets court-circuite le challenge, le trust et les détecteurs
// pour les ressources statiques (FR-24). Sans ce bypass, le CSS/JS chargé par la
// page de challenge elle-même serait challengé → deadlock de bootstrap.
//
// Le bypass pose X-WAF-Action=PASS avec X-WAF-Reason=static_asset (honoré par
// challenge/trust/antibot/risk). La blacklist (middleware access) reste
// appliquée : un asset depuis une IP blacklistée est toujours bloqué. Le rate
// limit aussi : il reconnaît la raison Reason et compte l'asset, faute de quoi
// n'importe quel chemin en .css inondait l'origine sans aucune borne.
package staticassets

import (
	"net/http"
	"strings"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/wafheader"
)

// Reason est la raison posée sur les requêtes d'assets (wafheader).
const Reason = wafheader.ReasonStaticAsset

// Bypass marque les requêtes d'assets statiques en PASS : par extension, par
// préfixe de répertoire ou par chemin exact (FR-24).
type Bypass struct {
	enabled    bool
	extensions []string
	prefixes   []string
	exactPaths map[string]struct{}
	// onAsset compte la requête d'asset (waf_asset_requests_total).
	onAsset func(host string)
}

func New(cfg config.StaticAssets) Bypass {
	exts := make([]string, 0, len(cfg.Extensions))
	for _, e := range cfg.Extensions {
		exts = append(exts, strings.ToLower(e))
	}
	exactPaths := make(map[string]struct{}, len(cfg.ExactPaths))
	for _, path := range cfg.ExactPaths {
		exactPaths[path] = struct{}{}
	}
	return Bypass{enabled: cfg.Enabled, extensions: exts, prefixes: cfg.PathPrefixes, exactPaths: exactPaths}
}

// WithCounter branche le comptage des requêtes d'assets bypassées.
func (b Bypass) WithCounter(onAsset func(host string)) Bypass {
	b.onAsset = onAsset
	return b
}

func (b Bypass) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.enabled && b.isAsset(r.URL.Path) {
			r.Header.Set(wafheader.Action, wafheader.ActionPass)
			r.Header.Set(wafheader.Reason, Reason)
			if b.onAsset != nil {
				b.onAsset(r.Host)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isAsset : l'extension est comparée sans tenir compte de la casse, comme
// avant ; préfixes et chemins exacts le sont à la casse près — un chemin
// d'URL y est sensible, et en cas de doute un chemin n'est pas un asset.
func (b Bypass) isAsset(path string) bool {
	if _, ok := b.exactPaths[path]; ok {
		return true
	}
	for _, prefix := range b.prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	lower := strings.ToLower(path)
	for _, ext := range b.extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
