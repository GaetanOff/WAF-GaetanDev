package antibot

import (
	"net/http"
	"strconv"

	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/wafheader"
)

const (
	// headerRiskFingerprint publie une contribution de la famille `fingerprint`
	// consommée par le moteur de risque (requirements-detection FR-33).
	headerRiskFingerprint = wafheader.RiskFingerprint
	// headerDeterministicTrigger signale un déclencheur déterministe au moteur de
	// risque / au logger (requirements-detection FR-35).
	headerDeterministicTrigger = wafheader.DeterministicTrigger
)

type Middleware struct {
	rules  Rules
	scores *trust.ScoreManager
	shadow bool
	// onNonBrowserExempt compte une exemption FR-41 effective, par host
	// configuré de l'entrée domains[] (nil : pas de comptage).
	onNonBrowserExempt func(domain string)
}

// New construit le middleware anti-bot. shadow (= risk_engine.shadow_mode) active
// le mode calibration : les blocages heuristiques sont observés sans être appliqués
// (le honeypot, déterministe, reste bloquant) afin de ne pas casser le trafic
// API/serveur légitime non-navigateur.
func New(rules Rules, scores *trust.ScoreManager, shadow bool) Middleware {
	return Middleware{rules: rules, scores: scores, shadow: shadow}
}

// WithNonBrowserExemptCounter branche le comptage des exemptions de
// domains[].non_browser_paths (FR-41, waf_antibot_non_browser_exempt_total).
func (m Middleware) WithNonBrowserExemptCounter(onExempt func(domain string)) Middleware {
	m.onNonBrowserExempt = onExempt
	return m
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(wafheader.Action) == wafheader.ActionPass {
			next.ServeHTTP(w, r)
			return
		}

		decision := m.exemptNonBrowserClients(r, m.rules.Evaluate(r))
		if decision.Delta == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		var visitorScore int
		switch {
		case decision.Reason == ReasonHoneypot:
			visitorScore = m.scores.BanHoneypot(ip, r.Host).Score
		case decision.Block:
			visitor := m.scores.Set(ip, r.Host, 0)
			visitorScore = visitor.Score
		default:
			visitor := m.scores.Apply(ip, r.Host, decision.Delta)
			visitorScore = visitor.Score
		}

		r.Header.Set(wafheader.Reason, decision.Reason)
		if decision.Block || m.scores.State(visitorScore) == trust.StateBlocked {
			isHoneypot := decision.Reason == ReasonHoneypot
			action := wafheader.ActionBlock
			if isHoneypot {
				action = wafheader.ActionHoneypot
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
			w.Header().Set(wafheader.Action, action)
			w.Header().Set(wafheader.Reason, decision.Reason)
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

// isNonBrowserSignal désigne les heuristiques qui ne prouvent qu'une chose :
// le client n'est pas un navigateur interactif. Un User-Agent de
// whitelist_user_agents les déclare justement comme tel — un crawler n'envoie
// ni Accept-Language ni les autres en-têtes d'un navigateur. Sans cette
// exemption, chaque requête de Googlebot coûtait 5 points : sous le seuil de
// blocage en huit requêtes, avant que la vérification reverse-DNS du moteur de
// risque ait pu le reconnaître. L'exemption n'ouvre aucun contournement : ces
// en-têtes se forgent aussi aisément que le User-Agent, et un faux crawler
// reste démasqué par risk_engine.verified_bots. Honeypot, outils
// d'automatisation et navigateurs headless restent évalués.
func isNonBrowserSignal(reason string) bool {
	return reason == ReasonMissingHeader || reason == ReasonSuspiciousUA
}

// isNonBrowserPathSignal étend isNonBrowserSignal au User-Agent vide, pour les
// seuls chemins de domains[].non_browser_paths (FR-41) : un client HTTP
// serveur à serveur n'en envoie pas toujours. La whitelist UA n'en hérite pas :
// elle exempte un client qui se déclare par son User-Agent, et un User-Agent
// vide ne déclare rien.
func isNonBrowserPathSignal(reason string) bool {
	return isNonBrowserSignal(reason) || reason == ReasonMissingUA
}

// exemptNonBrowserClients lève les signaux « client non navigateur » d'un
// client déclaré comme tel : User-Agent de whitelist_user_agents, ou chemin de
// domains[].non_browser_paths (FR-41). Honeypot, automatisation et headless ne
// sont jamais levés.
func (m Middleware) exemptNonBrowserClients(r *http.Request, decision Decision) Decision {
	if isNonBrowserSignal(decision.Reason) && r.Header.Get(access.HeaderUserAgentWhitelisted) == "true" {
		return Decision{}
	}
	if !isNonBrowserPathSignal(decision.Reason) {
		return decision
	}
	domain, exempt := m.rules.nonBrowser.exempt(r.Host, r.URL.Path)
	if !exempt {
		return decision
	}
	if m.onNonBrowserExempt != nil {
		m.onNonBrowserExempt(domain)
	}
	return Decision{}
}
