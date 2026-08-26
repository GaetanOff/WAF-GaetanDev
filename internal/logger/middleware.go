package logger

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/gaetandev/waf/internal/alert"
	"github.com/gaetandev/waf/internal/gdpr"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/upstreamtime"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func (l Logger) Middleware(scores *trust.ScoreManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewV4().String()
		startedAt := l.now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		w.Header().Set(requestIDHeader, requestID)

		// Chronomètre upstream : le proxy y cumule le temps passé à parler à
		// l'origine, pour isoler waf_latency_ms (temps WAF) de latency_ms (total).
		ctx, upstreamRec := upstreamtime.WithRecorder(r.Context())
		r = withRequestID(r.WithContext(ctx), requestID)
		next.ServeHTTP(recorder, r)

		elapsed := l.now().Sub(startedAt).Seconds() * 1000
		wafLatency := elapsed - upstreamRec.Total().Seconds()*1000
		if wafLatency < 0 {
			wafLatency = 0
		}
		event := l.securityEvent(r, recorder, scores, requestID, startedAt, elapsed, wafLatency)
		l.WriteSecurityEvent(event)
		if l.Alerter != nil && isAlertable(event.Action) {
			l.Alerter.Notify(alert.Event{
				Trigger:    alertTrigger(event.Action),
				Domain:     event.Domain,
				Reason:     event.Reason,
				IP:         event.IP,
				Path:       event.Path,
				Method:     event.Method,
				Action:     event.Action,
				RequestID:  event.RequestID,
				Country:    valueOrEmpty(event.CFCountry),
				TrustScore: event.TrustScore,
			})
		}
	})
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// isAlertable indique si une action mérite une alerte webhook (FR-29).
func isAlertable(action string) bool {
	switch action {
	case ActionBlock, ActionCircuitBreak, ActionHoneypot:
		return true
	default:
		return false
	}
}

func alertTrigger(action string) string {
	switch action {
	case ActionCircuitBreak:
		return "circuit_breaker"
	case ActionHoneypot:
		return "honeypot"
	default:
		return "block"
	}
}

func RequestID(r *http.Request) string {
	if value, ok := r.Context().Value(requestIDContextKey{}).(string); ok {
		return value
	}
	return ""
}

func withRequestID(r *http.Request, requestID string) *http.Request {
	ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
	return r.WithContext(ctx)
}

func (l Logger) securityEvent(r *http.Request, recorder *statusRecorder, scores *trust.ScoreManager, requestID string, startedAt time.Time, elapsedMS float64, wafLatencyMS float64) SecurityEvent {
	ip := cloudflare.RealIP(r)
	trustScore := currentTrustScore(r, scores, ip)
	action := normalizedAction(r, recorder)
	loggedIP := ip
	if l.AnonymizeIP {
		loggedIP = gdpr.AnonymizeIP(ip)
	}
	return SecurityEvent{
		Timestamp:      startedAt.UTC().Format(time.RFC3339Nano),
		RequestID:      requestID,
		IP:             loggedIP,
		IPHash:         trust.HashIP(ip),
		Domain:         r.Host,
		Method:         r.Method,
		Path:           r.URL.Path,
		UserAgent:      r.UserAgent(),
		Action:         action,
		Reason:         reason(r, recorder),
		TrustScore:     trustScore,
		ScoreDelta:     scoreDelta(r),
		RiskScore:      riskScore(r),
		RiskDecision:   r.Header.Get("X-WAF-Risk-Decision"),
		RiskConfidence: riskConfidence(r),
		ShadowMode:     r.Header.Get("X-WAF-Risk-Shadow-Mode") == "true",
		GlobalPressure: globalPressure(r),
		UnderAttack:    r.Header.Get("X-WAF-Under-Attack") == "true",
		LatencyMS:      elapsedMS,
		WAFLatencyMS:   wafLatencyMS,
		UpstreamStatus: upstreamStatus(action, recorder.statusCode),
		CFRay:          cfRay(r),
		CFCountry:      cfCountry(r),
	}
}

func globalPressure(r *http.Request) string {
	if value := r.Header.Get("X-WAF-Global-Pressure"); value != "" {
		return value
	}
	return "normal"
}

func scoreDelta(r *http.Request) int {
	if value := r.Header.Get("X-WAF-Score-Delta"); value != "" {
		scoreDelta, err := strconv.Atoi(value)
		if err == nil {
			return scoreDelta
		}
	}
	return 0
}

func riskScore(r *http.Request) int {
	if value := r.Header.Get("X-WAF-Risk-Score"); value != "" {
		score, err := strconv.Atoi(value)
		if err == nil {
			return score
		}
	}
	return 0
}

func riskConfidence(r *http.Request) float64 {
	if value := r.Header.Get("X-WAF-Risk-Confidence"); value != "" {
		confidence, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return confidence
		}
	}
	return 0
}

func currentTrustScore(r *http.Request, scores *trust.ScoreManager, ip string) int {
	if value := r.Header.Get("X-WAF-Score"); value != "" {
		score, err := strconv.Atoi(value)
		if err == nil {
			return score
		}
	}
	if scores == nil {
		return 0
	}
	return scores.Get(ip, r.Host).Score
}

// normalizedAction dérive l'action depuis l'en-tête X-WAF-Action. Toutes les
// vraies décisions du WAF (access, antibot, ratelimit, circuit-breaker, rules,
// trust, risk) posent cet en-tête. En son absence, l'action est PASS : le statut
// observé vient alors de l'UPSTREAM (ex: 502 origine down, 403/404 applicatif)
// et ne doit PAS être compté comme un blocage WAF — sinon faux BLOCK dans les
// métriques/logs et fausses alertes webhook à chaque hoquet d'origine.
func normalizedAction(r *http.Request, recorder *statusRecorder) string {
	action := recorder.Header().Get("X-WAF-Action")
	if action == "" {
		action = r.Header.Get("X-WAF-Action")
	}
	switch action {
	case ActionPass, ActionChallenge, ActionBlock, ActionRateLimit, ActionCircuitBreak, ActionHoneypot:
		return action
	default:
		return ActionPass
	}
}

func reason(r *http.Request, recorder *statusRecorder) string {
	if value := recorder.Header().Get("X-WAF-Reason"); value != "" {
		return value
	}
	return r.Header.Get("X-WAF-Reason")
}

func upstreamStatus(action string, statusCode int) *int {
	if action != ActionPass {
		return nil
	}
	return &statusCode
}

// maxCFRayLen plafonne la longueur d'un identifiant CF-Ray journalisé. Un ray
// Cloudflare réel fait ~20 caractères (16 hexadécimaux + "-" + code datacenter) ;
// la borne empêche un client joignant l'origine hors Cloudflare de forger une
// valeur démesurée dans le journal d'audit.
const maxCFRayLen = 32

// cfRay lit et assainit l'en-tête CF-Ray (identifiant de corrélation Cloudflare),
// contrôlable par un client atteignant directement l'origine (hors Cloudflare).
// Le nom d'en-tête est un littéral constant : c'est ce qui lève l'alerte
// clear-text-logging (CWE-312), CodeQL ne reconnaissant pas comme sûre une lecture
// d'en-tête au nom variable. Le filtrage (alphanumériques ASCII + tiret, longueur
// bornée) est une défense en profondeur contre l'injection de caractères de
// contrôle chez les consommateurs de logs non-JSON (CWE-117).
func cfRay(r *http.Request) *string {
	return sanitizedToken(r.Header.Get("CF-Ray"), maxCFRayLen)
}

// cfCountry lit et assainit l'en-tête CF-IPCountry. Seul un code de 2 lettres
// majuscules (ISO 3166-1 alpha-2 et "XX" — inconnu) ou la valeur spéciale
// Cloudflare "T1" (Tor) est accepté ; toute autre valeur est ignorée (nil)
// plutôt que journalisée telle quelle.
func cfCountry(r *http.Request) *string {
	country := strings.ToUpper(strings.TrimSpace(r.Header.Get("CF-IPCountry")))
	if !isCountryCode(country) {
		return nil
	}
	return &country
}

// sanitizedToken ne conserve que les caractères alphanumériques ASCII et le tiret,
// dans la limite de maxLen. Retourne nil si la valeur est vide ou ne contient
// aucun caractère autorisé.
func sanitizedToken(value string, maxLen int) *string {
	if value == "" {
		return nil
	}
	var b strings.Builder
	for _, c := range value {
		if b.Len() >= maxLen {
			break
		}
		if isTokenRune(c) {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	out := b.String()
	return &out
}

// isTokenRune autorise les caractères d'un identifiant opaque sûr à journaliser.
func isTokenRune(c rune) bool {
	return c == '-' ||
		(c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z')
}

// isCountryCode valide un code pays CF-IPCountry : 2 lettres majuscules ASCII
// (codes ISO 3166-1 alpha-2 et "XX" inconnu) ou la valeur spéciale "T1" (Tor).
func isCountryCode(s string) bool {
	if s == "T1" {
		return true
	}
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
