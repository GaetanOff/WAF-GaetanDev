// Package staticassets court-circuite le challenge, le trust et les détecteurs
// pour les ressources statiques (FR-24). Sans ce bypass, le CSS/JS chargé par la
// page de challenge elle-même serait challengé → deadlock de bootstrap.
//
// Le bypass pose X-WAF-Action=PASS (honoré par challenge/rate/antibot/risk).
// La blacklist (middleware access) reste appliquée : un asset depuis une IP
// blacklistée est toujours bloqué.
package staticassets

import (
	"net/http"
	"strings"

	"github.com/gaetandev/waf/internal/config"
)

// Bypass marque les requêtes d'assets statiques en PASS.
type Bypass struct {
	enabled    bool
	extensions []string
}

func New(cfg config.StaticAssets) Bypass {
	exts := make([]string, 0, len(cfg.Extensions))
	for _, e := range cfg.Extensions {
		exts = append(exts, strings.ToLower(e))
	}
	return Bypass{enabled: cfg.Enabled, extensions: exts}
}

func (b Bypass) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.enabled && b.isAsset(r.URL.Path) {
			r.Header.Set("X-WAF-Action", "PASS")
			r.Header.Set("X-WAF-Reason", "static_asset")
		}
		next.ServeHTTP(w, r)
	})
}

func (b Bypass) isAsset(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range b.extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
