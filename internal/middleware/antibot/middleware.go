package antibot

import (
	"net/http"
	"strconv"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	// headerRiskFingerprint publie une contribution de la famille `fingerprint`
	// consommée par le moteur de risque (requirements-detection FR-33).
	headerRiskFingerprint = "X-WAF-Risk-fingerprint"
	// headerDeterministicTrigger signale un déclencheur déterministe au moteur de
	// risque / au logger (requirements-detection FR-35).
	headerDeterministicTrigger = "X-WAF-Deterministic-Trigger"
)

type Middleware struct {
	rules  Rules
	scores *trust.ScoreManager
	shadow bool
}

// New construit le middleware anti-bot. shadow (= risk_engine.shadow_mode) active
// le mode calibration : les blocages heuristiques sont observés sans être appliqués
// (le honeypot, déterministe, reste bloquant) afin de ne pas casser le trafic
// API/serveur légitime non-navigateur.
func New(rules Rules, scores *trust.ScoreManager, shadow bool) Middleware {
	return Middleware{rules: rules, scores: scores, shadow: shadow}
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
			isHoneypot := decision.Reason == ReasonHoneypot
			action := "BLOCK"
			if isHoneypot {
				action = "HONEYPOT"
				// Le honeypot est un signal déterministe (FR-35) : on l'annonce
				// pour l'observabilité tout en conservant le blocage immédiat.
				w.Header().Set(headerDeterministicTrigger, "honeypot")
			}
			// Calibration (shadow_mode) : on observe les blocages heuristiques sans
			// les appliquer (sinon le trafic API/serveur légitime — client OAuth
			// non-navigateur, en-têtes navigateur absents — serait bloqué). Le
			// honeypot reste bloquant car déterministe et sans faux positif.
			if m.shadow && !isHoneypot {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("X-WAF-Action", action)
			w.Header().Set("X-WAF-Reason", decision.Reason)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Signal heuristique non bloquant : publie une contribution `fingerprint`
		// (delta négatif → contribution de risque positive) pour le moteur de
		// risque. Seul, ce signal ne peut pas bloquer (corroboration FR-35).
		if decision.Delta < 0 {
			r.Header.Set(headerRiskFingerprint, strconv.Itoa(-decision.Delta))
		}

		next.ServeHTTP(w, r)
	})
}
