package rules

import (
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

// Middleware évalue le jeu de règles et applique les actions de la première
// règle qui matche. Les actions block/tarpit sont terminales (court-circuit).
type Middleware struct {
	rules  *RuleSet
	scores *trust.ScoreManager
}

func NewMiddleware(rules *RuleSet, scores *trust.ScoreManager) Middleware {
	return Middleware{rules: rules, scores: scores}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		for _, action := range m.rules.Match(r) {
			switch action.Type {
			case "block":
				w.Header().Set("X-WAF-Action", "BLOCK")
				w.Header().Set("X-WAF-Reason", reasonOr(action.Value, "rule_block"))
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			case "tarpit":
				r.Header.Set("X-WAF-Action", "TARPIT")
				r.Header.Set("X-WAF-Reason", reasonOr(action.Value, "rule_tarpit"))
			case "score_delta":
				if m.scores != nil {
					m.scores.Apply(cloudflare.RealIP(r), r.Host, action.Delta)
				}
			case "add_header":
				if action.Header != "" {
					w.Header().Set(action.Header, action.Value)
				}
			case "log":
				if r.Header.Get("X-WAF-Reason") == "" {
					r.Header.Set("X-WAF-Reason", reasonOr(action.Value, "rule_log"))
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func reasonOr(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
