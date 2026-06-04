package antibot

import (
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

type Middleware struct {
	rules  Rules
	scores *trust.ScoreManager
}

func New(rules Rules, scores *trust.ScoreManager) Middleware {
	return Middleware{rules: rules, scores: scores}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		decision := m.rules.Evaluate(r)
		if decision.Delta == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		var visitorScore int
		if decision.Block {
			visitor := m.scores.Set(ip, r.Host, 0)
			visitorScore = visitor.Score
		} else {
			visitor := m.scores.Apply(ip, r.Host, decision.Delta)
			visitorScore = visitor.Score
		}

		r.Header.Set("X-WAF-Reason", decision.Reason)
		if decision.Block || m.scores.State(visitorScore) == trust.StateBlocked {
			action := "BLOCK"
			if decision.Reason == ReasonHoneypot {
				action = "HONEYPOT"
			}
			w.Header().Set("X-WAF-Action", action)
			w.Header().Set("X-WAF-Reason", decision.Reason)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
