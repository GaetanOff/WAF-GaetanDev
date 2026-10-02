package threatintel

import (
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/wafheader"
)

const (
	headerDeterministicTrigger = wafheader.DeterministicTrigger
	headerReason               = wafheader.Reason

	triggerThreatIntelCritical = "threat_intel_critical"

	// Plafonds de trust score appliqués selon la sévérité (idempotents : on
	// abaisse le score à au plus la valeur, jamais on ne le remonte).
	ceilingMalicious = 20
	ceilingSuspect   = 35
)

// Middleware applique le verdict de réputation au moteur de risque : verdict
// critique → trigger déterministe (BLOCK via le moteur, FR-35) ; sinon plafond
// du trust score (la famille `reputation` du moteur s'en trouve renforcée).
type Middleware struct {
	checker *Checker
	scores  *trust.ScoreManager
}

func NewMiddleware(checker *Checker, scores *trust.ScoreManager) Middleware {
	return Middleware{checker: checker, scores: scores}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// La réputation s'applique aux assets statiques (FR-24).
		if wafheader.IsFullPass(r.Header) {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		verdict := m.checker.Verdict(ip)
		switch verdict.Level {
		case LevelCritical:
			r.Header.Set(headerDeterministicTrigger, triggerThreatIntelCritical)
			if r.Header.Get(headerReason) == "" {
				r.Header.Set(headerReason, reasonOr(verdict, triggerThreatIntelCritical))
			}
		case LevelMalicious:
			m.applyCeiling(ip, r.Host, ceilingMalicious)
			setReason(r, reasonOr(verdict, "threat_intel_malicious"))
		case LevelSuspect:
			m.applyCeiling(ip, r.Host, ceilingSuspect)
			setReason(r, reasonOr(verdict, "threat_intel_suspect"))
		}

		next.ServeHTTP(w, r)
	})
}

// applyCeiling abaisse le trust score du visiteur à au plus ceiling (idempotent).
func (m Middleware) applyCeiling(ip string, domain string, ceiling int) {
	if m.scores == nil {
		return
	}
	if current := m.scores.Peek(ip, domain).Score; current > ceiling {
		m.scores.Set(ip, domain, ceiling)
	}
}

func reasonOr(verdict Verdict, fallback string) string {
	if verdict.Reason != "" {
		return verdict.Reason
	}
	return fallback
}

// setReason publie la raison de la réputation, sauf sur un asset statique :
// remplacer sa raison static_asset en ferait un PASS de whitelist IP, que les
// middlewares suivants honorent sans réserve (FR-24).
func setReason(r *http.Request, reason string) {
	if wafheader.IsAssetPass(r.Header) {
		return
	}
	r.Header.Set(headerReason, reason)
}
