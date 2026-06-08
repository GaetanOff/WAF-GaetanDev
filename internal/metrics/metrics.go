package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	actionPass         = "PASS"
	actionChallenge    = "CHALLENGE"
	actionBlock        = "BLOCK"
	actionRateLimit    = "RATE_LIMIT"
	actionCircuitBreak = "CIRCUIT_BREAK"
	actionHoneypot     = "HONEYPOT"
)

type Metrics struct {
	registry        *prometheus.Registry
	requests        *prometheus.CounterVec
	blocked         *prometheus.CounterVec
	challenged      *prometheus.CounterVec
	duration        *prometheus.HistogramVec
	decisions       *prometheus.CounterVec
	challengeFP     prometheus.Counter
	hardBlocks      *prometheus.CounterVec
	verifiedBots    *prometheus.CounterVec
	activeVisitors  prometheus.Gauge
	visitorsByState *prometheus.GaugeVec
	mu              sync.Mutex
	visitors        map[string]string
	now             func() time.Time
}

func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		registry: registry,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total WAF requests by action and domain.",
		}, []string{"action", "domain"}),
		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_blocked_total",
			Help: "Total WAF blocked requests by domain and reason.",
		}, []string{"domain", "reason"}),
		challenged: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_challenged_total",
			Help: "Total WAF challenged requests by domain and reason.",
		}, []string{"domain", "reason"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_duration_seconds",
			Help:    "WAF request duration in seconds by action.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"action"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_decisions_total",
			Help: "Risk engine decisions by mitigation tier.",
		}, []string{"tier"}),
		challengeFP: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_challenge_pass_after_flag_total",
			Help: "Challenges passed after a previous risk flag, proxying probable false positives.",
		}),
		hardBlocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_hard_blocks_total",
			Help: "Risk engine hard blocks split by corroboration mode.",
		}, []string{"corroborated"}),
		verifiedBots: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_verified_bot_total",
			Help: "Verified crawler decisions by bot name.",
		}, []string{"bot"}),
		activeVisitors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_active_visitors",
			Help: "Number of active visitors seen by this WAF process.",
		}),
		visitorsByState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_visitors_by_state",
			Help: "Number of active visitors by trust state.",
		}, []string{"state"}),
		visitors: make(map[string]string),
		now:      time.Now,
	}
	registry.MustRegister(m.requests, m.blocked, m.challenged, m.duration, m.decisions, m.challengeFP, m.hardBlocks, m.verifiedBots, m.activeVisitors, m.visitorsByState)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Middleware(scores *trust.ScoreManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := m.now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(recorder, r)

		action := normalizedAction(r, recorder)
		reason := wafReason(r, recorder)
		m.requests.WithLabelValues(action, r.Host).Inc()
		m.duration.WithLabelValues(action).Observe(m.now().Sub(startedAt).Seconds())
		if action == actionChallenge {
			m.challenged.WithLabelValues(r.Host, reason).Inc()
		}
		if isBlockedAction(action) {
			m.blocked.WithLabelValues(r.Host, reason).Inc()
		}
		m.observeRisk(r, recorder)
		m.observeVisitor(r, scores)
	})
}

func (m *Metrics) observeRisk(r *http.Request, recorder *statusRecorder) {
	decision := headerValue(r, recorder, "X-WAF-Risk-Decision")
	if decision != "" {
		m.decisions.WithLabelValues(decision).Inc()
	}
	if headerValue(r, recorder, "X-WAF-Challenge-Pass-After-Flag") == "true" {
		m.challengeFP.Inc()
	}
	if decision == actionBlock {
		corroborated := headerValue(r, recorder, "X-WAF-Risk-Corroborated")
		if corroborated != "true" {
			corroborated = "false"
		}
		m.hardBlocks.WithLabelValues(corroborated).Inc()
	}
	if bot := headerValue(r, recorder, "X-WAF-Risk-Verified-Bot"); bot != "" {
		m.verifiedBots.WithLabelValues(bot).Inc()
	}
}

func (m *Metrics) observeVisitor(r *http.Request, scores *trust.ScoreManager) {
	if scores == nil {
		return
	}
	ip := cloudflare.RealIP(r)
	visitor := scores.Get(ip, r.Host)
	state := scores.State(visitor.Score)
	m.mu.Lock()
	defer m.mu.Unlock()

	m.visitors[visitor.IPHash] = state
	counts := map[string]int{
		trust.StateTrusted:    0,
		trust.StateMonitored:  0,
		trust.StateChallenged: 0,
		trust.StateBlocked:    0,
	}
	for _, visitorState := range m.visitors {
		counts[visitorState]++
	}
	m.activeVisitors.Set(float64(len(m.visitors)))
	for stateName, count := range counts {
		m.visitorsByState.WithLabelValues(stateName).Set(float64(count))
	}
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
	case actionPass, actionChallenge, actionBlock, actionRateLimit, actionCircuitBreak, actionHoneypot:
		return action
	case "DEGRADED":
		return actionBlock
	default:
		return actionPass
	}
}

func actionFromStatus(statusCode int) string {
	switch {
	case statusCode == http.StatusTooManyRequests:
		return actionRateLimit
	case statusCode == http.StatusForbidden || statusCode >= http.StatusInternalServerError:
		return actionBlock
	default:
		return actionPass
	}
}

func wafReason(r *http.Request, recorder *statusRecorder) string {
	if value := recorder.Header().Get("X-WAF-Reason"); value != "" {
		return value
	}
	if value := r.Header.Get("X-WAF-Reason"); value != "" {
		return value
	}
	return "none"
}

func headerValue(r *http.Request, recorder *statusRecorder, name string) string {
	if value := recorder.Header().Get(name); value != "" {
		return value
	}
	return r.Header.Get(name)
}

func isBlockedAction(action string) bool {
	return action == actionBlock || action == actionCircuitBreak || action == actionHoneypot
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
