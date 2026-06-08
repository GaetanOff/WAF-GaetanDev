// Package geo applique des règles géographiques (FR-16) à partir du header
// CF-IPCountry fourni par Cloudflare. Sans ce header (déploiement hors
// Cloudflare), les règles sont ignorées gracieusement.
package geo

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gaetandev/waf/internal/config"
)

const (
	headerCountry       = "CF-IPCountry"
	headerRiskGeo       = "X-WAF-Risk-geo"
	headerAction        = "X-WAF-Action"
	headerReason        = "X-WAF-Reason"
	defaultChallengeGeo = 60
)

// Rules compile les listes de pays en ensembles pour une évaluation O(1).
type Rules struct {
	enabled          bool
	allowed          map[string]struct{}
	blocked          map[string]struct{}
	challenge        map[string]struct{}
	challengeContrib int
}

func NewRules(cfg config.Geo) Rules {
	contrib := cfg.ChallengeContribution
	if contrib <= 0 {
		contrib = defaultChallengeGeo
	}
	return Rules{
		enabled:          cfg.Enabled,
		allowed:          toSet(cfg.AllowedCountries),
		blocked:          toSet(cfg.BlockedCountries),
		challenge:        toSet(cfg.ChallengeCountries),
		challengeContrib: contrib,
	}
}

func (r Rules) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.enabled || req.Header.Get(headerAction) == "PASS" {
			next.ServeHTTP(w, req)
			return
		}

		country := strings.ToUpper(strings.TrimSpace(req.Header.Get(headerCountry)))
		if country == "" {
			// Pas de header CF-IPCountry → règles géo ignorées (FR-16).
			next.ServeHTTP(w, req)
			return
		}

		// Mode whitelist : seuls les pays autorisés passent.
		if len(r.allowed) > 0 {
			if _, ok := r.allowed[country]; !ok {
				block(w, "geo_country_not_allowed")
				return
			}
		}
		if _, ok := r.blocked[country]; ok {
			block(w, "geo_country_blocked")
			return
		}
		if _, ok := r.challenge[country]; ok {
			req.Header.Set(headerRiskGeo, strconv.Itoa(r.challengeContrib))
			if req.Header.Get(headerReason) == "" {
				req.Header.Set(headerReason, "geo_country_challenge")
			}
		}

		next.ServeHTTP(w, req)
	})
}

func block(w http.ResponseWriter, reason string) {
	w.Header().Set(headerAction, "BLOCK")
	w.Header().Set(headerReason, reason)
	http.Error(w, "forbidden", http.StatusForbidden)
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[strings.ToUpper(strings.TrimSpace(v))] = struct{}{}
	}
	return set
}
