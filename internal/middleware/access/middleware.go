package access

import (
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

// HeaderUserAgentWhitelisted marque une requête dont le User-Agent correspond
// à whitelist_user_agents. Seul le challenge JS proactif l'honore : le reste de
// la chaîne (blacklist, anti-DDoS, rate limit, moteur de risque et sa
// vérification reverse-DNS des crawlers) s'applique. En-tête interne : le
// middleware ingress supprime tout X-WAF-* fourni par le client.
const HeaderUserAgentWhitelisted = "X-WAF-UA-Whitelisted"

func WhitelistMiddleware(rules *RuleSet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := rules.IsWhitelisted(cloudflare.RealIP(r)); ok {
			r.Header.Set("X-WAF-Action", "PASS")
			r.Header.Set("X-WAF-Reason", reason)
			next.ServeHTTP(w, r)
			return
		}
		markWhitelistedUserAgent(rules, r)
		next.ServeHTTP(w, r)
	})
}

func BlacklistMiddleware(rules *RuleSet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := rules.IsBlacklisted(cloudflare.RealIP(r)); ok {
			// Signal déterministe (FR-35) : annoncé pour l'observabilité tout en
			// conservant le blocage immédiat.
			w.Header().Set("X-WAF-Deterministic-Trigger", "blacklist")
			w.Header().Set("X-WAF-Action", "BLOCK")
			w.Header().Set("X-WAF-Reason", reason)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware applique la whitelist IP (bypass total), puis la blacklist, puis
// marque les User-Agents whitelistés.
//
// La whitelist User-Agent posait auparavant X-WAF-Action=PASS, comme la
// whitelist IP : « User-Agent: Googlebot » contournait alors toutes les
// protections, y compris la vérification reverse-DNS de
// risk_engine.verified_bots, court-circuitée par le PASS.
func Middleware(rules *RuleSet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := rules.IsWhitelisted(cloudflare.RealIP(r)); ok {
			r.Header.Set("X-WAF-Action", "PASS")
			r.Header.Set("X-WAF-Reason", reason)
			next.ServeHTTP(w, r)
			return
		}
		BlacklistMiddleware(rules, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			markWhitelistedUserAgent(rules, r)
			next.ServeHTTP(w, r)
		})).ServeHTTP(w, r)
	})
}

func markWhitelistedUserAgent(rules *RuleSet, r *http.Request) {
	if rules.MatchesUserAgent(r.UserAgent()) {
		r.Header.Set(HeaderUserAgentWhitelisted, "true")
	}
}
