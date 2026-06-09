package antiddos

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
)

type Middleware struct {
	enabled           bool
	breaker           CircuitBreaker
	global            *GlobalRateDetector
	onPressure        func(PressureLevel)
	retryAfterSeconds int
}

func New(breaker CircuitBreaker, global *GlobalRateDetector, retryAfterSeconds int) Middleware {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = DefaultRetryAfterSeconds
	}
	return Middleware{
		enabled:           true,
		breaker:           breaker,
		global:            global,
		retryAfterSeconds: retryAfterSeconds,
	}
}

func (m Middleware) WithPressureObserver(observer func(PressureLevel)) Middleware {
	m.onPressure = observer
	return m
}

func NewFromConfig(store storage.Store, cfg config.Config) (Middleware, error) {
	window, err := time.ParseDuration(cfg.AntiDDoS.GlobalWindow)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse antiddos.global_window: %w", err)
	}
	middleware := New(
		NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration),
		NewGlobalRateDetector(cfg.AntiDDoS.GlobalRequestsPerSecond, window, PressureConfig{
			ElevatedMultiplier: cfg.AntiDDoS.PressureLevels.ElevatedMultiplier,
			HighMultiplier:     cfg.AntiDDoS.PressureLevels.HighMultiplier,
			CriticalMultiplier: cfg.AntiDDoS.PressureLevels.CriticalMultiplier,
		}),
		cfg.AntiDDoS.RetryAfterSeconds,
	)
	middleware.enabled = cfg.AntiDDoS.Enabled
	return middleware, nil
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		if m.breaker.IsOpen(ip) {
			// Signal déterministe (FR-35) : annoncé pour l'observabilité tout en
			// conservant le blocage immédiat.
			w.Header().Set("X-WAF-Deterministic-Trigger", "circuit_breaker")
			w.Header().Set("X-WAF-Action", "CIRCUIT_BREAK")
			w.Header().Set("X-WAF-Reason", "circuit_breaker_open")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		pressure := m.recordPressure()
		r.Header.Set("X-WAF-Global-Pressure", string(pressure))
		if contribution := pressureContribution(pressure); contribution > 0 {
			r.Header.Set("X-WAF-Risk-rate", strconv.Itoa(contribution))
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

func (m Middleware) recordPressure() PressureLevel {
	if m.global == nil {
		return PressureNormal
	}
	pressure := m.global.RecordAndPressure()
	if m.onPressure != nil {
		m.onPressure(pressure)
	}
	return pressure
}

func pressureContribution(pressure PressureLevel) int {
	switch pressure {
	case PressureElevated:
		return 35
	case PressureHigh:
		return 60
	case PressureCritical:
		return 80
	default:
		return 0
	}
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
