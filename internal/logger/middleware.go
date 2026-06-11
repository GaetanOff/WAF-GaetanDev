package logger

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/alert"
	"github.com/gaetandev/waf/internal/gdpr"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/google/uuid"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func (l Logger) Middleware(scores *trust.ScoreManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()
		startedAt := l.now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		w.Header().Set(requestIDHeader, requestID)

		r = withRequestID(r, requestID)
		next.ServeHTTP(recorder, r)

		elapsed := l.now().Sub(startedAt).Seconds() * 1000
		event := l.securityEvent(r, recorder, scores, requestID, startedAt, elapsed)
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

func (l Logger) securityEvent(r *http.Request, recorder *statusRecorder, scores *trust.ScoreManager, requestID string, startedAt time.Time, elapsedMS float64) SecurityEvent {
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
		LatencyMS:      elapsedMS,
		WAFLatencyMS:   elapsedMS,
		UpstreamStatus: upstreamStatus(action, recorder.statusCode),
		CFRay:          optionalHeader(r, "CF-Ray"),
		CFCountry:      optionalHeader(r, "CF-IPCountry"),
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

func optionalHeader(r *http.Request, name string) *string {
	value := r.Header.Get(name)
	if value == "" {
		return nil
	}
	return &value
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
