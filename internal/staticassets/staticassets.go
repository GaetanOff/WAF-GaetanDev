// Package staticassets dispense les ressources statiques du challenge proactif
// et des décisions heuristiques (FR-24) : trust score, anti-bot, intégrité,
// score du moteur de risque.
//
// Seuls GET et HEAD sont éligibles : « POST /login.css » n'est pas un asset.
//
// Le bypass pose X-WAF-Action=PASS avec X-WAF-Reason=static_asset. Ce PASS
// n'est pas celui de la whitelist IP (wafheader.IsFullPass) : la blacklist,
// le géo-blocage, les règles, la threat intel, la blacklist JA3, le ban
// honeypot, le rate limit, le comptage de pression anti-DDoS, le
// circuit-breaker et le challenge sous attaque (FR-39) s'appliquent aux
// assets. Honoré par toute la chaîne, il laissait « GET /x.js?r=<aléa> »
// contourner la défense contre un flood L7 distribué.
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
		if b.enabled && isReadMethod(r.Method) && b.isAsset(r.URL.Path) {
			r.Header.Set(wafheader.Action, wafheader.ActionPass)
			r.Header.Set(wafheader.Reason, Reason)
			if b.onAsset != nil {
				b.onAsset(r.Host)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isReadMethod : une écriture (POST, PUT, PATCH, DELETE) n'est jamais une
// lecture d'asset, quel que soit son chemin (FR-24).
func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
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
