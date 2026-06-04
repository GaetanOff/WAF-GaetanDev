package logger

import (
	"context"
	"net/http"
	"strconv"
	"time"

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
		l.WriteSecurityEvent(l.securityEvent(r, recorder, scores, requestID, startedAt, elapsed))
	})
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
	return SecurityEvent{
		Timestamp:      startedAt.UTC().Format(time.RFC3339Nano),
		RequestID:      requestID,
		IP:             ip,
		IPHash:         trust.HashIP(ip),
		Domain:         r.Host,
		Method:         r.Method,
		Path:           r.URL.Path,
		UserAgent:      r.UserAgent(),
		Action:         action,
		Reason:         reason(r, recorder),
		TrustScore:     trustScore,
		LatencyMS:      elapsedMS,
		WAFLatencyMS:   elapsedMS,
		UpstreamStatus: upstreamStatus(action, recorder.statusCode),
		CFRay:          optionalHeader(r, "CF-Ray"),
		CFCountry:      optionalHeader(r, "CF-IPCountry"),
	}
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

func normalizedAction(r *http.Request, recorder *statusRecorder) string {
	action := recorder.Header().Get("X-WAF-Action")
	if action == "" {
		action = r.Header.Get("X-WAF-Action")
	}
	if action == "" {
		action = actionFromStatus(recorder.statusCode)
	}
	switch action {
	case ActionPass, ActionChallenge, ActionBlock, ActionRateLimit, ActionCircuitBreak, ActionHoneypot:
		return action
	case "DEGRADED":
		return ActionBlock
	default:
		return ActionPass
	}
}

func actionFromStatus(statusCode int) string {
	switch {
	case statusCode == http.StatusTooManyRequests:
		return ActionRateLimit
	case statusCode == http.StatusForbidden || statusCode >= http.StatusInternalServerError:
		return ActionBlock
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
