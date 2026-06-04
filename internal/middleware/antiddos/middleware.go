package antiddos

import (
	"log/slog"
	"net/http"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

type Middleware struct {
	breaker CircuitBreaker
}

func New(breaker CircuitBreaker) Middleware {
	return Middleware{breaker: breaker}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		if m.breaker.IsOpen(ip) {
			slog.Warn("waf security event", "ip", ip, "domain", r.Host, "path", r.URL.Path, "action", "CIRCUIT_BREAK", "reason", "circuit_breaker_open")
			w.Header().Set("X-WAF-Action", "CIRCUIT_BREAK")
			w.Header().Set("X-WAF-Reason", "circuit_breaker_open")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if isViolation(recorder) {
			m.breaker.RecordViolation(ip)
			return
		}
		m.breaker.Reset(ip)
	})
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
	if r.statusCode == http.StatusOK {
		r.statusCode = http.StatusOK
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func isViolation(recorder *statusRecorder) bool {
	action := recorder.Header().Get("X-WAF-Action")
	return action == "RATE_LIMIT" || recorder.statusCode == http.StatusTooManyRequests
}
