package access

import (
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

func WhitelistMiddleware(rules *RuleSet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := rules.IsWhitelisted(cloudflare.RealIP(r), r.UserAgent()); ok {
			r.Header.Set("X-WAF-Action", "PASS")
			r.Header.Set("X-WAF-Reason", reason)
			next.ServeHTTP(w, r)
			return
		}
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

func Middleware(rules *RuleSet, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, reason := rules.IsWhitelisted(cloudflare.RealIP(r), r.UserAgent()); ok {
			r.Header.Set("X-WAF-Action", "PASS")
			r.Header.Set("X-WAF-Reason", reason)
			next.ServeHTTP(w, r)
			return
		}
		BlacklistMiddleware(rules, next).ServeHTTP(w, r)
	})
}
